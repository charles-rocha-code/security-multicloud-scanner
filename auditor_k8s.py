"""
auditor_k8s.py - Auditor de segurança de storage em clusters Kubernetes.

Analisa:
- PersistentVolumes (PVs) e PersistentVolumeClaims (PVCs) expostos
- StorageClasses inseguros
- Secrets com credenciais de storage (AWS, GCS, Azure)
- ConfigMaps com dados sensíveis de storage
- Pods com volumes hostPath
- Namespaces com permissões excessivas em storage
"""

from __future__ import annotations

import io
import yaml
from datetime import datetime
from typing import Any, Dict, List, Optional

from kubernetes import client, config as k8s_config
from kubernetes.client.rest import ApiException

from cve_mapping import enrich_finding
from kubeconfig_guard import validate_user_kubeconfig
from ssrf_guard import assert_server_not_ssrf_target


SENSITIVE_PATTERNS = [
    "aws_access_key", "aws_secret", "aws_key", "s3_key",
    "storage_account", "azure_key", "azure_connection",
    "google_credentials", "service_account", "gcs_key",
    "password", "passwd", "token", "secret", "credential",
]


class K8sAccessError(Exception):
    """O cluster recusou a credencial (401) ou não respondeu. Levantada antes de
    qualquer check: sem isso, os checks engoliam o erro um a um e o scan saía
    "com sucesso" com risk_score baixo e quase nenhum finding -- um falso
    negativo indistinguível de cluster limpo (o 401 ficava só em 'errors',
    que o dashboard não mostra)."""


def verify_cluster_access(core: "client.CoreV1Api", timeout: int = 30) -> None:
    """Confirma que a credencial é aceita e o API server responde. 403 passa:
    credencial válida com RBAC mais restrito (ex.: escopo de namespace) é um
    uso legítimo -- os checks que não tiverem permissão reportam isso."""
    try:
        core.list_namespace(limit=1, _request_timeout=timeout)
    except ApiException as e:
        if e.status == 401:
            raise K8sAccessError(
                "o cluster recusou a credencial do kubeconfig (401 Unauthorized) -- "
                "token expirado ou inválido; gere um novo kubeconfig da ServiceAccount"
            ) from None
        if e.status == 403:
            return
        raise K8sAccessError(f"o API server respondeu {e.status} {e.reason}") from None
    except Exception as e:
        raise K8sAccessError(f"o API server do cluster não respondeu ({e.__class__.__name__})") from None


def _is_sensitive(key: str) -> bool:
    k = key.lower()
    return any(p in k for p in SENSITIVE_PATTERNS)


# Namespaces reservados do próprio Kubernetes (kube-node-lease/kube-public
# nunca têm workload; kube-system concentra o control plane e CNI). hostPath
# nesses namespaces é como o cluster funciona (etcd, kube-apiserver, kindnet,
# kube-proxy montando certs/socket/lib-modules do nó) -- não é a mesma coisa
# que um workload de usuário optando por hostPath, então não deveria disparar
# a mesma severidade. Sem essa distinção, todo cluster kind/kubeadm gera uma
# dezena de CRITICAL genéricos que afogam achados de usuário reais.
_SYSTEM_NAMESPACES = {"kube-system", "kube-node-lease", "kube-public"}


def _is_system_namespace(ns: str) -> bool:
    return ns in _SYSTEM_NAMESPACES


# Só controllers cujas réplicas compartilham o mesmo spec. Static pods do
# control plane (etcd, kube-apiserver, scheduler...) têm o *Node* como dono --
# agrupar por ele juntava pods diferentes num só e escondia os hostPaths dos
# demais (pego comparando o scan antes/depois no cluster kind).
_REPLICA_CONTROLLERS = {"DaemonSet", "ReplicaSet", "StatefulSet", "Job", "ReplicationController"}


def _pod_workload(pod) -> tuple:
    """(kind, nome) do workload dono do pod. Pod de Deployment pertence a um
    ReplicaSet "<deployment>-<pod-template-hash>": tira o hash para chegar no
    Deployment. Pod sem controller de réplicas é o próprio workload."""
    meta = pod.metadata
    owners = getattr(meta, "owner_references", None) or []
    owner = next((o for o in owners if getattr(o, "controller", False)), owners[0] if owners else None)
    if owner is None or owner.kind not in _REPLICA_CONTROLLERS:
        return "Pod", getattr(meta, "name", None) or "-"
    if owner.kind == "ReplicaSet":
        tmpl_hash = (getattr(meta, "labels", None) or {}).get("pod-template-hash")
        if tmpl_hash and owner.name.endswith(f"-{tmpl_hash}"):
            return "Deployment", owner.name[: -len(tmpl_hash) - 1]
    return owner.kind, owner.name


def group_pods_by_workload(pods) -> list:
    """Uma entrada por workload: [(pod_representante, kind, nome, n_pods)].
    Réplicas de um mesmo DaemonSet/Deployment/StatefulSet compartilham o mesmo
    spec -- checar cada réplica só multiplicava o mesmo achado (ex.: 3 réplicas
    do node-exporter = 3x cada hostPath). O namespace entra na chave porque
    workloads de mesmo nome em namespaces diferentes são coisas diferentes."""
    groups: Dict[tuple, list] = {}
    for pod in pods or []:
        kind, name = _pod_workload(pod)
        groups.setdefault((getattr(pod.metadata, "namespace", None), kind, name), []).append(pod)
    return [(members[0], kind, name, len(members)) for (_, kind, name), members in groups.items()]


def replicas_note(n_pods: int) -> str:
    return f" ({n_pods} pods)" if n_pods > 1 else ""


_CLUSTER_SCOPED_KINDS = {"PV", "StorageClass"}
_NAMESPACED_KEY_KINDS = {"Pod", "PVC", "Secret", "ConfigMap", "DaemonSet", "Deployment",
                         "StatefulSet", "ReplicaSet", "Job", "CronJob"}


def finding_namespace(f: Dict[str, Any]) -> str:
    """Namespace de um finding K8s, venha de qual auditor vier. Os dois
    auditores usam formatos de chave diferentes ('<Kind>/<ns>/...' no de
    storage, '<ns>/<Tipo>/...' no autenticado), e o relatório pegava sempre o
    1º segmento -- mostrando 'Pod'/'Secret'/'PV' como namespace."""
    ns = f.get("namespace")
    if ns and ns != "-":
        return ns
    parts = (f.get("key") or "").split("/")
    if ns == "-" or (parts and parts[0] in _CLUSTER_SCOPED_KINDS) or (parts and parts[0] == "cluster"):
        return "cluster"
    if len(parts) > 1 and parts[0] in _NAMESPACED_KEY_KINDS:
        return parts[1]
    return parts[0] if parts and parts[0] else "-"


def _classify_severity(reason: str) -> str:
    reason_lower = reason.lower()
    if any(w in reason_lower for w in ["public", "exposed", "secret", "credential", "token", "key"]):
        return "CRITICAL"
    if any(w in reason_lower for w in ["hostpath", "readwritemany", "retain", "insecure"]):
        return "HIGH"
    if any(w in reason_lower for w in ["configmap", "storageclas", "annotation"]):
        return "MEDIUM"
    return "LOW"


class K8sStorageAuditor:
    """Auditor de storage Kubernetes a partir de um kubeconfig YAML."""

    def __init__(self, kubeconfig_yaml: str, max_objects: int = 1000):
        self.kubeconfig_yaml = kubeconfig_yaml
        self.max_objects = max_objects
        self._api_client: Optional[client.ApiClient] = None

    def _load_config(self) -> client.ApiClient:
        # Antes do loader: load_and_set roda o plugin users[].user.exec do
        # kubeconfig -- sem isso, kubeconfig do usuário executava comando aqui.
        cfg_dict = validate_user_kubeconfig(self.kubeconfig_yaml)
        loader = k8s_config.kube_config.KubeConfigLoader(config_dict=cfg_dict)
        cfg = client.Configuration()
        loader.load_and_set(cfg)
        assert_server_not_ssrf_target(cfg.host)  # bloqueia antes do 1º request real
        return client.ApiClient(configuration=cfg)

    def _safe(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ApiException:
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _check_pvs(self, core: client.CoreV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(core.list_persistent_volume)
        if not resp:
            return findings

        for pv in (resp.items or []):
            name = pv.metadata.name or "-"
            spec = pv.spec or client.V1PersistentVolumeSpec()

            # ReclaimPolicy Retain mantém dados após deleção do PVC
            if getattr(spec, "persistent_volume_reclaim_policy", "") == "Retain":
                findings.append({
                    "key": f"PV/{name}",
                    "size": 0,
                    "severity": "HIGH",
                    "reason": "ReclaimPolicy=Retain: dados persistem após deleção do PVC",
                })

            # AccessMode ReadWriteMany expõe volume a múltiplos nós
            modes = getattr(spec, "access_modes", []) or []
            if "ReadWriteMany" in modes:
                findings.append({
                    "key": f"PV/{name}",
                    "size": 0,
                    "severity": "HIGH",
                    "reason": "AccessMode=ReadWriteMany: volume acessível por múltiplos nós simultaneamente",
                })

            # hostPath aponta para diretório do host
            if getattr(spec, "host_path", None):
                findings.append({
                    "key": f"PV/{name}",
                    "size": 0,
                    "severity": "CRITICAL",
                    "reason": f"hostPath={spec.host_path.path}: volume monta diretório do nó host",
                })

        return findings

    def _check_pvcs(self, core: client.CoreV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(core.list_persistent_volume_claim_for_all_namespaces)
        if not resp:
            return findings

        for pvc in (resp.items or []):
            name = pvc.metadata.name or "-"
            ns = pvc.metadata.namespace or "default"
            spec = pvc.spec or client.V1PersistentVolumeClaimSpec()
            modes = getattr(spec, "access_modes", []) or []

            if "ReadWriteMany" in modes:
                findings.append({
                    "key": f"PVC/{ns}/{name}",
                    "size": 0,
                    "severity": "HIGH",
                    "reason": "AccessMode=ReadWriteMany: PVC compartilhado entre múltiplos pods",
                })

        return findings

    def _check_secrets(self, core: client.CoreV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(core.list_secret_for_all_namespaces)
        if not resp:
            return findings

        for secret in (resp.items or []):
            name = secret.metadata.name or "-"
            ns = secret.metadata.namespace or "default"
            data = secret.data or {}

            for key in data:
                if _is_sensitive(key):
                    findings.append({
                        "key": f"Secret/{ns}/{name}[{key}]",
                        "size": len(data[key]) if data[key] else 0,
                        "severity": "CRITICAL",
                        "reason": f"Secret contém chave sensível de storage: '{key}'",
                    })
                    break  # um achado por secret é suficiente

        return findings

    def _check_configmaps(self, core: client.CoreV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(core.list_config_map_for_all_namespaces)
        if not resp:
            return findings

        for cm in (resp.items or []):
            name = cm.metadata.name or "-"
            ns = cm.metadata.namespace or "default"
            if ns in ("kube-system", "kube-public"):
                continue
            data = cm.data or {}

            for key in data:
                if _is_sensitive(key):
                    findings.append({
                        "key": f"ConfigMap/{ns}/{name}[{key}]",
                        "size": len(data[key]) if data[key] else 0,
                        "severity": "MEDIUM",
                        "reason": f"ConfigMap expõe dado sensível em texto plano: '{key}'",
                    })
                    break

        return findings

    def _check_storage_classes(self, storage: client.StorageV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(storage.list_storage_class)
        if not resp:
            return findings

        for sc in (resp.items or []):
            name = sc.metadata.name or "-"
            reclaim = getattr(sc, "reclaim_policy", "") or ""

            if reclaim == "Retain":
                findings.append({
                    "key": f"StorageClass/{name}",
                    "size": 0,
                    "severity": "MEDIUM",
                    "reason": "StorageClass reclaimPolicy=Retain: dados persistem após deleção",
                })

            params = getattr(sc, "parameters", {}) or {}
            for k, v in params.items():
                if _is_sensitive(k):
                    findings.append({
                        "key": f"StorageClass/{name}[{k}]",
                        "size": 0,
                        "severity": "HIGH",
                        "reason": f"StorageClass contém parâmetro sensível: '{k}'",
                    })
                    break

        return findings

    def _check_hostpath_pods(self, core: client.CoreV1Api) -> List[Dict]:
        findings = []
        resp = self._safe(core.list_pod_for_all_namespaces)
        if not resp:
            return findings

        for pod, kind, name, n_pods in group_pods_by_workload(resp.items):
            ns = pod.metadata.namespace or "default"
            spec = pod.spec or client.V1PodSpec(containers=[])
            volumes = getattr(spec, "volumes", []) or []
            reps = replicas_note(n_pods)

            for vol in volumes:
                if getattr(vol, "host_path", None):
                    if _is_system_namespace(ns):
                        findings.append({
                            "key": f"{kind}/{ns}/{name}/volume:{vol.name}",
                            "namespace": ns,
                            "size": 0,
                            "severity": "LOW",
                            "reason": (
                                f"{kind} monta hostPath={vol.host_path.path} em namespace de sistema "
                                f"({ns}){reps}: esperado em componentes de control plane/CNI, não é um "
                                f"achado de configuração de usuário"
                            ),
                        })
                    else:
                        findings.append({
                            "key": f"{kind}/{ns}/{name}/volume:{vol.name}",
                            "namespace": ns,
                            "size": 0,
                            "severity": "CRITICAL",
                            "reason": f"{kind} monta hostPath={vol.host_path.path}{reps}: acesso direto ao sistema de arquivos do host",
                        })

        return findings

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        try:
            api_client = self._load_config()
        except Exception as e:
            return {
                "provider": "KUBERNETES",
                "bucket": "cluster",
                "region": "-",
                "public_access": False,
                "public_listing": False,
                "summary": {"objects_scanned": 0, "total_size_bytes": 0},
                "files": [],
                "errors": [f"Falha ao carregar kubeconfig: {e}"],
                "risk_score": 0,
                "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "recommendations": ["Verifique se o kubeconfig está correto e o cluster está acessível."],
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

        core = client.CoreV1Api(api_client)
        storage_api = client.StorageV1Api(api_client)
        verify_cluster_access(core)

        findings: List[Dict] = []
        errors: List[str] = []

        for check_fn, args in [
            (self._check_pvs, (core,)),
            (self._check_pvcs, (core,)),
            (self._check_secrets, (core,)),
            (self._check_configmaps, (core,)),
            (self._check_storage_classes, (storage_api,)),
            (self._check_hostpath_pods, (core,)),
        ]:
            try:
                findings.extend(check_fn(*args))
            except Exception as e:
                errors.append(f"{check_fn.__name__}: {e}")

        findings = findings[: self.max_objects]

        for f in findings:
            f.setdefault("category", "Storage")
            f.setdefault("namespace", finding_namespace(f))
            enrich_finding(f, "KUBERNETES")

        dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            if sev == "CRITICAL":
                dist["critical"] += 1
            elif sev == "HIGH":
                dist["high"] += 1
            elif sev == "MEDIUM":
                dist["medium"] += 1
            else:
                dist["low"] += 1

        total = len(findings)
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_score = total * 4 if total else 1
        raw = sum(dist[k] * weights[k] for k in dist)
        risk_score = min(100, int((raw / max_score) * 100)) if total else 0

        # Cluster server para exibir como "bucket"; nome do cluster e usuário
        # do contexto ativo pra exibir como "region"/"account" na barra
        # superior -- k8s não tem esses conceitos, mas são o equivalente
        # mais próximo (cluster = onde, user do contexto = quem conecta).
        cluster_server = "-"
        cluster_name = "-"
        account_identity = "-"
        try:
            cfg_dict = yaml.safe_load(self.kubeconfig_yaml)
            clusters = cfg_dict.get("clusters", [])
            if clusters:
                cluster_server = clusters[0].get("cluster", {}).get("server", "-")
                cluster_name = clusters[0].get("name", "-")

            current_context = cfg_dict.get("current-context")
            for ctx in cfg_dict.get("contexts", []):
                if ctx.get("name") == current_context:
                    account_identity = ctx.get("context", {}).get("user", "-")
                    break
        except Exception:
            pass

        recs = []
        if dist["critical"] > 0:
            recs.append("Remova ou rotacione credenciais de storage expostas em Secrets imediatamente.")
        if dist["high"] > 0:
            recs.append("Revise PersistentVolumes com hostPath e ReclaimPolicy=Retain.")
        if dist["medium"] > 0:
            recs.append("Mova dados sensíveis de ConfigMaps para Secrets ou Vault.")
        recs.append("Use RBAC restritivo para acesso a PVs, PVCs e Secrets de storage.")
        recs.append("Habilite auditoria do Kubernetes API Server para operações em Secrets e PVs.")

        return {
            "provider": "KUBERNETES",
            "bucket": cluster_server,
            "region": cluster_name,
            "account_id": account_identity,
            "public_access": dist["critical"] > 0,
            "public_listing": False,
            "summary": {
                "objects_scanned": total,
                "total_size_bytes": sum(f.get("size", 0) for f in findings),
            },
            "files": findings,
            "errors": errors,
            "risk_score": risk_score,
            "severity_distribution": dist,
            "recommendations": recs,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
