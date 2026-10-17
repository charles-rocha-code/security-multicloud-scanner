# auditor_k8s_authenticated.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False

from graph_model import GraphCollector, GraphEdge, GraphNode
from kubeconfig_guard import validate_kubeconfig_file
from ssrf_guard import assert_server_not_ssrf_target
from auditor_k8s import _is_system_namespace, group_pods_by_workload, replicas_note, verify_cluster_access
from engine_risk import scan_content_for_secrets

# Sujeitos que, se vinculados a uma ClusterRole perigosa, representam ponto
# de entrada exposto de verdade — qualquer requisição não autenticada ou
# qualquer usuário autenticado (mesmo sem identidade específica) cai aqui.
EXPOSED_SUBJECT_NAMES = {"system:unauthenticated", "system:authenticated"}


SENSITIVE_KEY_PATTERNS = (
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "access_key", "private_key", "credential", "auth",
)

# ClusterRoles nativas do Kubernetes que legitimamente concedem '*'/'*' --
# hoje só cluster-admin bate nisso de verdade (admin/edit/view são escopadas
# por apiGroup, não têm resources=["*"] literal). Continua entrando no grafo
# (dangerous_roles) porque o Mapa de Grafo de Ataque precisa dela pra mostrar
# "existe alvo de alto valor, mas nenhum caminho sem credencial leva até ele"
# -- só não vira um finding CRITICAL solto, que é ruído (é assim que
# cluster-admin existe em todo cluster Kubernetes, não uma misconfiguração).
_NATIVE_WILDCARD_CLUSTERROLES = {"cluster-admin"}

# ClusterRoleBindings nativas que concedem acesso mínimo (só /healthz,
# /version) a system:unauthenticated/system:authenticated -- shipped por
# padrão em todo cluster Kubernetes desde ~1.14, não é acesso anônimo real.
_BENIGN_ANONYMOUS_BINDINGS = {"system:public-info-viewer"}


class K8sAuthenticatedAuditor(GraphCollector):
    """
    Auditor Kubernetes COM credenciais (kubeconfig):
      - Lista workloads (Pods/Deployments) e checa SecurityContext
      - Verifica RBAC (ClusterRoles com permissões '*')
      - Procura Secrets / ConfigMaps com dados sensíveis
      - Verifica exposição de rede (Services LoadBalancer/NodePort)
      - Checagens de control-plane (best-effort)

    Mesma metodologia do S3AuthenticatedAuditor: cada problema vira um
    'finding' com severity, e o payload final passa pelo mesmo
    pipeline de relatório.
    """

    def __init__(
        self,
        kubeconfig_path: Optional[str] = None,
        context: Optional[str] = None,
        in_cluster: bool = False,
        namespace: Optional[str] = None,
        max_resources: int = 1000,
        timeout: int = 30,
    ):
        if not K8S_AVAILABLE:
            raise ImportError(
                "Pacote 'kubernetes' não instalado. "
                "Rode: pip install kubernetes>=29.0.0"
            )

        GraphCollector.__init__(self)
        self.namespace = namespace
        self.max_resources = max_resources
        self.timeout = timeout

        try:
            if in_cluster:
                config.load_incluster_config()
            elif kubeconfig_path:
                # Antes do load: load_kube_config roda o plugin users[].user.exec
                # do arquivo -- ver kubeconfig_guard.py.
                validate_kubeconfig_file(kubeconfig_path)
                config.load_kube_config(config_file=kubeconfig_path, context=context)
            else:
                config.load_kube_config(context=context)
        except Exception as e:
            raise ValueError(f"Erro ao carregar configuração k8s: {e}")

        assert_server_not_ssrf_target(client.Configuration.get_default_copy().host)

        self.core = client.CoreV1Api()
        self.apps = client.AppsV1Api()
        self.rbac = client.RbacAuthorizationV1Api()
        self.networking = client.NetworkingV1Api()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _finding(
        severity: str,
        category: str,
        resource_type: str,
        resource_name: str,
        namespace: Optional[str],
        reason: str,
        recommendation: str,
    ) -> Dict[str, Any]:
        key = f"{namespace or 'cluster'}/{resource_type}/{resource_name}"
        return {
            "key": key,
            "name": resource_name,
            "size": 0,
            "severity": severity,
            "reason": reason,
            "category": category,
            "resource_type": resource_type,
            "resource_name": resource_name,
            "namespace": namespace or "-",
            "recommendation": recommendation,
        }

    def _list_namespaces(self) -> List[str]:
        if self.namespace:
            return [self.namespace]
        try:
            ns = self.core.list_namespace(_request_timeout=self.timeout)
            return [n.metadata.name for n in ns.items]
        except ApiException as e:
            raise Exception(f"Erro ao listar namespaces: {e}")

    def _get_cluster_info(self) -> Dict[str, Any]:
        try:
            version_api = client.VersionApi()
            v = version_api.get_code(_request_timeout=self.timeout)
            return {"server_version": f"{v.major}.{v.minor}", "platform": v.platform}
        except Exception:
            return {"server_version": "-", "platform": "-"}

    # ------------------------------------------------------------------
    # Checagens
    # ------------------------------------------------------------------

    def _check_workload_security(self, namespaces: List[str]) -> List[Dict[str, Any]]:
        """Privileged, hostNetwork, runAsRoot, sem resource limits.

        Em namespace de sistema (kube-system etc.), esses padrões são como o
        próprio control plane/CNI funciona (etcd, kube-apiserver, kindnet,
        kube-proxy) -- reportar isso como CRITICAL/HIGH genérico é ruído que
        afoga achado real de workload de usuário. Severidade cai pra LOW
        nesses namespaces, sem deixar de reportar (visibilidade continua,
        só não grita alarme falso)."""
        findings: List[Dict[str, Any]] = []

        def finding(default_severity, category, resource_type, resource_name, namespace, reason, recommendation):
            if _is_system_namespace(namespace):
                default_severity = "LOW"
                reason = f"{reason} -- namespace de sistema ({namespace}), esperado em control plane/CNI"
            return self._finding(default_severity, category, resource_type, resource_name, namespace, reason, recommendation)

        for ns in namespaces:
            try:
                pods = self.core.list_namespaced_pod(ns, _request_timeout=self.timeout)
            except ApiException:
                continue

            # Uma checagem por workload, não por réplica: as réplicas de um
            # DaemonSet/Deployment têm o mesmo spec (ver group_pods_by_workload).
            for pod, kind, name, n_pods in group_pods_by_workload(pods.items):
                spec = pod.spec
                reps = replicas_note(n_pods)

                if spec.host_network:
                    findings.append(finding(
                        "HIGH", "Workload Security", kind, name, ns,
                        f"Pod com hostNetwork=true (compartilha rede do nó){reps}",
                        "Remover hostNetwork salvo necessidade técnica justificada.",
                    ))
                if spec.host_pid:
                    findings.append(finding(
                        "HIGH", "Workload Security", kind, name, ns,
                        f"Pod com hostPID=true (vê processos do nó){reps}",
                        "Remover hostPID.",
                    ))
                if spec.host_ipc:
                    findings.append(finding(
                        "HIGH", "Workload Security", kind, name, ns,
                        f"Pod com hostIPC=true{reps}",
                        "Remover hostIPC.",
                    ))

                for c in spec.containers or []:
                    sc = c.security_context
                    if sc:
                        if sc.privileged:
                            findings.append(finding(
                                "CRITICAL", "Workload Security", "Container",
                                f"{name}/{c.name}", ns,
                                f"Container rodando como privileged{reps}",
                                "Remover privileged=true; usar capabilities específicas se necessário.",
                            ))
                        if sc.run_as_user == 0 or (sc.run_as_user is None and sc.run_as_non_root is not True):
                            findings.append(finding(
                                "HIGH", "Workload Security", "Container",
                                f"{name}/{c.name}", ns,
                                f"Container pode estar rodando como root{reps}",
                                "Definir runAsNonRoot=true e runAsUser >= 1000.",
                            ))

                    if not c.resources or not c.resources.limits:
                        findings.append(finding(
                            "MEDIUM", "Workload Security", "Container",
                            f"{name}/{c.name}", ns,
                            f"Container sem resources.limits (CPU/memory){reps}",
                            "Definir limits para evitar noisy neighbor/DoS.",
                        ))

        return findings

    def _check_rbac(self) -> List[Dict[str, Any]]:
        """ClusterRoles com wildcard '*', bindings perigosos."""
        findings: List[Dict[str, Any]] = []
        try:
            roles = self.rbac.list_cluster_role(_request_timeout=self.timeout)
        except ApiException as e:
            return [self._finding("LOW", "RBAC", "ClusterRole", "-", None,
                                  f"Não foi possível listar ClusterRoles: {e.reason}",
                                  "Verifique permissões da conta de auditoria.")]

        dangerous_roles: set = set()
        for role in roles.items:
            for rule in role.rules or []:
                verbs = rule.verbs or []
                resources = rule.resources or []
                if "*" in verbs and "*" in resources:
                    # Continua em dangerous_roles (o grafo abaixo precisa
                    # dela pra mostrar "existe alvo de alto valor, nenhum
                    # caminho sem credencial chega nele") -- só não vira
                    # finding solto se for uma role nativa do Kubernetes
                    # (cluster-admin existe em todo cluster, não é
                    # misconfiguração de ninguém).
                    dangerous_roles.add(role.metadata.name)
                    if role.metadata.name not in _NATIVE_WILDCARD_CLUSTERROLES:
                        findings.append(self._finding(
                            "CRITICAL", "RBAC", "ClusterRole", role.metadata.name, None,
                            "ClusterRole concede '*' verbs em '*' resources",
                            "Aplicar princípio do menor privilégio; remover wildcards.",
                        ))

        # Grafo: quem está vinculado (bound) às roles perigosas encontradas
        # acima. Dado novo em relação aos outros clouds — list_cluster_role
        # já era chamado, mas list_cluster_role_binding não, porque o check
        # original só olhava a permissão da role, não quem pode usá-la.
        if dangerous_roles:
            try:
                bindings = self.rbac.list_cluster_role_binding(_request_timeout=self.timeout)
            except ApiException:
                bindings = None
            if bindings:
                for binding in bindings.items:
                    role_ref = binding.role_ref.name if binding.role_ref else None
                    if role_ref not in dangerous_roles:
                        continue
                    role_id = f"clusterrole/{role_ref}"
                    self.add_node(GraphNode(
                        id=role_id, type="k8s_clusterrole", provider="KUBERNETES",
                        label=role_ref, high_value=True,
                    ))
                    for subject in binding.subjects or []:
                        subj_name = subject.name or "unknown"
                        subj_id = f"{subject.kind}/{subj_name}"
                        self.add_node(GraphNode(
                            id=subj_id, type="k8s_subject", provider="KUBERNETES", label=subj_name,
                            exposed=(subj_name in EXPOSED_SUBJECT_NAMES),
                        ))
                        self.add_edge(GraphEdge(subj_id, role_id, "has_permission"))

        return findings

    def _check_namespaced_rbac(self, namespaces: List[str]) -> List[Dict[str, Any]]:
        """Roles (namespaced) com wildcard '*', bindings perigosos -- mesma
        lógica do _check_rbac, mas pra Role/RoleBinding escopados a um
        namespace, que list_cluster_role/list_cluster_role_binding nunca
        enxergam. Um Role com '*'/'*' escopado a um namespace concede o
        mesmo acesso irrestrito que um ClusterRole wildcard, só que
        limitado àquele namespace -- igualmente CRITICAL."""
        findings: List[Dict[str, Any]] = []

        for ns in namespaces:
            try:
                roles = self.rbac.list_namespaced_role(ns, _request_timeout=self.timeout)
            except ApiException:
                continue

            dangerous_roles: set = set()
            for role in roles.items:
                for rule in role.rules or []:
                    verbs = rule.verbs or []
                    resources = rule.resources or []
                    if "*" in verbs and "*" in resources:
                        dangerous_roles.add(role.metadata.name)
                        findings.append(self._finding(
                            "CRITICAL", "RBAC", "Role", role.metadata.name, ns,
                            "Role concede '*' verbs em '*' resources neste namespace",
                            "Aplicar princípio do menor privilégio; remover wildcards.",
                        ))

            if not dangerous_roles:
                continue

            try:
                bindings = self.rbac.list_namespaced_role_binding(ns, _request_timeout=self.timeout)
            except ApiException:
                continue

            for binding in bindings.items:
                role_ref = binding.role_ref.name if binding.role_ref else None
                if role_ref not in dangerous_roles:
                    continue
                role_id = f"role/{ns}/{role_ref}"
                self.add_node(GraphNode(
                    id=role_id, type="k8s_role", provider="KUBERNETES",
                    label=f"{role_ref} ({ns})", high_value=True,
                ))
                for subject in binding.subjects or []:
                    subj_name = subject.name or "unknown"
                    subj_id = f"{subject.kind}/{subj_name}"
                    self.add_node(GraphNode(
                        id=subj_id, type="k8s_subject", provider="KUBERNETES", label=subj_name,
                        exposed=(subj_name in EXPOSED_SUBJECT_NAMES),
                    ))
                    self.add_edge(GraphEdge(subj_id, role_id, "has_permission"))

        return findings

    def _check_secrets_configmaps(self, namespaces: List[str]) -> List[Dict[str, Any]]:
        """ConfigMaps com chaves sensíveis, Secrets usados como env var."""
        findings: List[Dict[str, Any]] = []

        for ns in namespaces:
            try:
                cms = self.core.list_namespaced_config_map(ns, _request_timeout=self.timeout)
            except ApiException:
                continue

            for cm in cms.items:
                for key, value in (cm.data or {}).items():
                    if any(p in key.lower() for p in SENSITIVE_KEY_PATTERNS):
                        findings.append(self._finding(
                            "CRITICAL", "Secrets", "ConfigMap", cm.metadata.name, ns,
                            f"ConfigMap contém chave sensível '{key}' em plaintext",
                            "Migrar para Secret (ainda melhor: External Secrets + Vault/KMS).",
                        ))
                        continue
                    # Mesmo motor de scan de conteúdo usado nos auditores de
                    # storage (engine_risk.py) -- sem isso, uma chave com
                    # nome inofensivo (ex. "app-config") mas valor contendo
                    # uma AKIA... embutida passava invisível, enquanto o
                    # mesmo conteúdo num arquivo do S3 já era detectado.
                    # include_entropy_fallback=False: validado contra um
                    # cluster kind real, o fallback de entropia sozinho
                    # (sem isso) marcava kube-root-ca.crt (certificado PEM)
                    # e ConfigMap de regra do Prometheus/kubelet (JSON
                    # grande) como "possível segredo" -- 100% falso-positivo,
                    # zero dos padrões precisos (AWS/PEM/JWT/api_key) bateu
                    # nesse cluster. Mantém os padrões precisos, só desliga
                    # o fallback ruidoso pra esse tipo de dado.
                    content_match = scan_content_for_secrets(value or "", include_entropy_fallback=False)
                    if content_match:
                        sev, reason = content_match
                        findings.append(self._finding(
                            sev, "Secrets", "ConfigMap", cm.metadata.name, ns,
                            f"ConfigMap chave '{key}': {reason}",
                            "Migrar para Secret (ainda melhor: External Secrets + Vault/KMS).",
                        ))

            try:
                pods = self.core.list_namespaced_pod(ns, _request_timeout=self.timeout)
            except ApiException:
                continue

            for pod, kind, name, n_pods in group_pods_by_workload(pods.items):
                for c in pod.spec.containers or []:
                    # Um finding por Secret por container, listando as env vars
                    # -- antes era um por env var, e o mesmo Secret exposto em 2
                    # variáveis virava 2 findings idênticos (mesma key e motivo).
                    secret_vars: Dict[str, List[str]] = {}
                    for ev in c.env or []:
                        if ev.value_from and ev.value_from.secret_key_ref:
                            secret_vars.setdefault(ev.value_from.secret_key_ref.name, []).append(ev.name)
                    for secret_name, env_names in secret_vars.items():
                        findings.append(self._finding(
                            "MEDIUM", "Secrets", "Container",
                            f"{name}/{c.name}", ns,
                            f"Secret '{secret_name}' montado como env var "
                            f"({', '.join(sorted(env_names))}){replicas_note(n_pods)}",
                            "Preferir volume mount (env vars vazam em logs/inspeção).",
                        ))

        return findings

    def _check_network_exposure(self, namespaces: List[str]) -> List[Dict[str, Any]]:
        """Services LoadBalancer/NodePort, namespaces sem NetworkPolicy (ou com
        NetworkPolicy que existe mas equivale a allow-all)."""
        findings: List[Dict[str, Any]] = []

        for ns in namespaces:
            try:
                svcs = self.core.list_namespaced_service(ns, _request_timeout=self.timeout)
            except ApiException:
                continue

            for svc in svcs.items:
                if svc.spec.type in ("LoadBalancer", "NodePort"):
                    findings.append(self._finding(
                        "MEDIUM", "Network", "Service", svc.metadata.name, ns,
                        f"Service tipo {svc.spec.type} expõe serviço externamente",
                        "Validar necessidade; preferir Ingress com TLS e WAF.",
                    ))

            try:
                policies = self.networking.list_namespaced_network_policy(ns, _request_timeout=self.timeout)
                if not policies.items:
                    findings.append(self._finding(
                        "HIGH", "Network", "Namespace", ns, ns,
                        "Namespace sem NetworkPolicy (tráfego pod-a-pod liberado)",
                        "Aplicar default-deny e regras de allowlist.",
                    ))
                else:
                    for policy in policies.items:
                        ingress_rules = policy.spec.ingress or []
                        allow_all_rule = any(not (rule._from or []) for rule in ingress_rules)
                        if allow_all_rule:
                            findings.append(self._finding(
                                "HIGH", "Network", "NetworkPolicy", policy.metadata.name, ns,
                                "NetworkPolicy presente mas com regra de ingress sem "
                                "'from' -- equivale a allow-all, não restringe origem",
                                "Definir 'from' (podSelector/namespaceSelector) em vez "
                                "de regra vazia.",
                            ))
            except ApiException:
                pass

        return findings

    def _check_anonymous_auth(self) -> List[Dict[str, Any]]:
        """Best-effort: verifica acesso anônimo ao API server."""
        findings: List[Dict[str, Any]] = []
        try:
            sars = self.rbac.list_cluster_role_binding(_request_timeout=self.timeout)
            for crb in sars.items:
                role_ref_name = crb.role_ref.name if crb.role_ref else None
                if (
                    crb.metadata.name in _BENIGN_ANONYMOUS_BINDINGS
                    and role_ref_name in _BENIGN_ANONYMOUS_BINDINGS
                ):
                    # system:public-info-viewer só expõe /healthz e /version
                    # -- shipped por padrão em todo cluster desde ~1.14, não
                    # é acesso anônimo real. Checa nome do binding E
                    # role_ref: sem isso, alguém reapontando esse binding
                    # pra cluster-admin (mantendo o mesmo nome) passaria
                    # despercebido -- exatamente o CRITICAL que este check
                    # existe pra pegar. Um binding novo com nome diferente
                    # continua sendo pego abaixo.
                    continue
                for s in crb.subjects or []:
                    if s.name == "system:anonymous" or s.name == "system:unauthenticated":
                        findings.append(self._finding(
                            "CRITICAL", "API Server", "ClusterRoleBinding",
                            crb.metadata.name, None,
                            f"Binding concede permissões a {s.name}",
                            "Remover binding; desabilitar --anonymous-auth no kube-apiserver.",
                        ))
        except ApiException:
            pass
        return findings

    # ------------------------------------------------------------------
    # Orquestração
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        # Credencial recusada/cluster fora do ar vira exceção aqui, não um
        # resultado "limpo" -- ver K8sAccessError em auditor_k8s.py.
        verify_cluster_access(self.core, self.timeout)

        errors: List[str] = []
        findings: List[Dict[str, Any]] = []

        try:
            namespaces = self._list_namespaces()
        except Exception as e:
            errors.append(str(e))
            namespaces = []

        cluster_info = self._get_cluster_info()

        # Ordem importa: _check_workload_security gera uma finding MEDIUM por
        # container sem resources.limits -- escala com o total de containers
        # do cluster e é, de longe, o check mais "barulhento" dos cinco. Se
        # ele rodasse primeiro num cluster grande, sozinho poderia estourar
        # max_resources e cortar o loop antes de RBAC/anonymous-auth (os dois
        # que geram CRITICAL de verdade) sequer rodarem. Roda por último de
        # propósito: os checks de alto sinal e baixo volume vêm primeiro, e
        # se algum corte acontecer, é garantido que é só nele.
        for check in (
            self._check_rbac,
            lambda: self._check_namespaced_rbac(namespaces),
            self._check_anonymous_auth,
            lambda: self._check_secrets_configmaps(namespaces),
            lambda: self._check_network_exposure(namespaces),
            lambda: self._check_workload_security(namespaces),
        ):
            try:
                findings.extend(check())
                if len(findings) >= self.max_resources:
                    findings = findings[: self.max_resources]
                    break
            except Exception as e:
                errors.append(f"{check.__name__ if hasattr(check, '__name__') else 'check'}: {e}")

        severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            severity_distribution[f["severity"]] = severity_distribution.get(f["severity"], 0) + 1

        critical_high = severity_distribution["CRITICAL"] * 25 + severity_distribution["HIGH"] * 10
        risk_score = min(100, critical_high + severity_distribution["MEDIUM"] * 3 + severity_distribution["LOW"])

        recommendations = sorted({f["recommendation"] for f in findings})

        return {
            "provider": "KUBERNETES",
            "cluster": cluster_info.get("server_version", "-"),
            "platform": cluster_info.get("platform", "-"),
            "namespace_filter": self.namespace or "-",
            "summary": {
                "namespaces_scanned": len(namespaces),
                "findings_total": len(findings),
            },
            "files": findings,
            "severity_distribution": severity_distribution,
            "risk_score": risk_score,
            "recommendations": recommendations,
            "errors": errors,
            "graph": self.graph_output(),
        }
