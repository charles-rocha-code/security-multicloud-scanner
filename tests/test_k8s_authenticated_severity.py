"""
auditor_k8s_authenticated.py marcava CRITICAL genérico pra três padrões que
existem em todo cluster Kubernetes por padrão, não por misconfiguração de
usuário: hostNetwork/root/sem-limits em pods de kube-system, a ClusterRole
nativa cluster-admin (wildcard '*'/'*' é a própria definição dela), e o
binding padrão system:public-info-viewer (só expõe /healthz e /version pra
system:unauthenticated). Isso inflava o risk_score e afogava achado real de
usuário em ruído -- validado num scan real contra um cluster kind.

cluster-admin precisa continuar entrando no grafo de ataque (dangerous_roles)
mesmo sem gerar finding -- é o que sustenta o Mapa de Grafo de Ataque
mostrando "alvo de alto valor existe, nenhum caminho leva até ele".
"""
from types import SimpleNamespace

from auditor_k8s_authenticated import K8sAuthenticatedAuditor
from graph_model import GraphCollector


def _make_auditor():
    obj = K8sAuthenticatedAuditor.__new__(K8sAuthenticatedAuditor)
    GraphCollector.__init__(obj)
    obj.timeout = 30
    obj.namespace = None
    obj.max_resources = 1000
    return obj


def _fake_pod(namespace, name, host_network=False, privileged=False, run_as_user=0, has_limits=True):
    sc = SimpleNamespace(privileged=privileged, run_as_user=run_as_user, run_as_non_root=None)
    resources = SimpleNamespace(limits={"cpu": "100m"} if has_limits else None)
    container = SimpleNamespace(name="main", security_context=sc, resources=resources)
    spec = SimpleNamespace(host_network=host_network, host_pid=False, host_ipc=False, containers=[container])
    metadata = SimpleNamespace(name=name)
    return SimpleNamespace(metadata=metadata, spec=spec)


def test_workload_security_em_kube_system_e_low():
    auditor = _make_auditor()
    auditor.core = SimpleNamespace(
        list_namespaced_pod=lambda ns, **kw: SimpleNamespace(
            items=[_fake_pod("kube-system", "etcd", host_network=True, privileged=True, run_as_user=0, has_limits=False)]
        )
    )

    findings = auditor._check_workload_security(["kube-system"])

    assert len(findings) > 0
    assert all(f["severity"] == "LOW" for f in findings)
    assert all("namespace de sistema" in f["reason"] for f in findings)


def test_workload_security_em_namespace_de_usuario_mantem_severidade_real():
    auditor = _make_auditor()
    auditor.core = SimpleNamespace(
        list_namespaced_pod=lambda ns, **kw: SimpleNamespace(
            items=[_fake_pod("default", "privileged-pod", host_network=True, privileged=True, run_as_user=0, has_limits=False)]
        )
    )

    findings = auditor._check_workload_security(["default"])
    by_reason = {f["reason"].split(" -- ")[0].split(" (")[0]: f["severity"] for f in findings}

    severities = {f["severity"] for f in findings}
    assert "CRITICAL" in severities  # privileged
    assert "HIGH" in severities      # hostNetwork / root
    assert "MEDIUM" in severities    # sem limits


def _fake_clusterrole(name, verbs=("*",), resources=("*",)):
    rule = SimpleNamespace(verbs=list(verbs), resources=list(resources))
    return SimpleNamespace(metadata=SimpleNamespace(name=name), rules=[rule])


def test_cluster_admin_nao_gera_finding_mas_entra_no_grafo():
    auditor = _make_auditor()
    auditor.rbac = SimpleNamespace(
        list_cluster_role=lambda **kw: SimpleNamespace(items=[_fake_clusterrole("cluster-admin")]),
        list_cluster_role_binding=lambda **kw: SimpleNamespace(items=[]),
    )

    findings = auditor._check_rbac()

    assert findings == []
    graph = auditor.graph_output()
    node_ids = [n["id"] for n in graph["nodes"]]
    assert "clusterrole/cluster-admin" not in node_ids  # sem binding, nada pra desenhar ainda


def test_role_custom_com_wildcard_continua_critical():
    auditor = _make_auditor()
    auditor.rbac = SimpleNamespace(
        list_cluster_role=lambda **kw: SimpleNamespace(items=[_fake_clusterrole("dangerous-wildcard-role")]),
        list_cluster_role_binding=lambda **kw: SimpleNamespace(items=[]),
    )

    findings = auditor._check_rbac()

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["resource_name"] == "dangerous-wildcard-role"


def test_cluster_admin_com_binding_aparece_no_grafo_sem_finding():
    auditor = _make_auditor()
    binding = SimpleNamespace(
        metadata=SimpleNamespace(name="cluster-admin"),
        role_ref=SimpleNamespace(name="cluster-admin"),
        subjects=[SimpleNamespace(kind="Group", name="system:masters")],
    )
    auditor.rbac = SimpleNamespace(
        list_cluster_role=lambda **kw: SimpleNamespace(items=[_fake_clusterrole("cluster-admin")]),
        list_cluster_role_binding=lambda **kw: SimpleNamespace(items=[binding]),
    )

    findings = auditor._check_rbac()

    assert findings == []
    graph = auditor.graph_output()
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "clusterrole/cluster-admin" in node_ids


def _fake_crb(name, subject_names):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name),
        subjects=[SimpleNamespace(name=n) for n in subject_names],
    )


def test_public_info_viewer_nao_e_reportado():
    auditor = _make_auditor()
    auditor.rbac = SimpleNamespace(
        list_cluster_role_binding=lambda **kw: SimpleNamespace(items=[
            _fake_crb("system:public-info-viewer", ["system:authenticated", "system:unauthenticated"]),
        ])
    )

    findings = auditor._check_anonymous_auth()

    assert findings == []


def test_binding_novo_para_anonymous_continua_reportado():
    auditor = _make_auditor()
    auditor.rbac = SimpleNamespace(
        list_cluster_role_binding=lambda **kw: SimpleNamespace(items=[
            _fake_crb("um-binding-perigoso-qualquer", ["system:anonymous"]),
        ])
    )

    findings = auditor._check_anonymous_auth()

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
