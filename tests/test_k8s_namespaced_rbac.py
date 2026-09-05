"""
_check_rbac só auditava ClusterRole/ClusterRoleBinding -- um Role
namespaced com '*'/'*' (ex.: acesso irrestrito a secrets de um namespace)
era invisível pro scanner. Ver docs/dspm-kspm-roadmap.md, Fase K1.
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


def _fake_role(name, verbs=("*",), resources=("*",)):
    rule = SimpleNamespace(verbs=list(verbs), resources=list(resources))
    return SimpleNamespace(metadata=SimpleNamespace(name=name), rules=[rule])


def _fake_role_binding(name, role_ref, subject_names):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name),
        role_ref=SimpleNamespace(name=role_ref),
        subjects=[SimpleNamespace(kind="ServiceAccount", name=n) for n in subject_names],
    )


def test_role_namespaced_com_wildcard_gera_critical():
    auditor = _make_auditor()
    auditor.rbac = SimpleNamespace(
        list_namespaced_role=lambda ns, **kw: SimpleNamespace(items=[_fake_role("god-mode")]),
        list_namespaced_role_binding=lambda ns, **kw: SimpleNamespace(items=[]),
    )

    findings = auditor._check_namespaced_rbac(["default"])

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["resource_type"] == "Role"
    assert findings[0]["namespace"] == "default"


def test_role_namespaced_restritiva_nao_gera_finding():
    auditor = _make_auditor()
    auditor.rbac = SimpleNamespace(
        list_namespaced_role=lambda ns, **kw: SimpleNamespace(
            items=[_fake_role("reader", verbs=("get", "list"), resources=("pods",))]
        ),
        list_namespaced_role_binding=lambda ns, **kw: SimpleNamespace(items=[]),
    )

    findings = auditor._check_namespaced_rbac(["default"])

    assert findings == []


def test_role_perigosa_com_binding_entra_no_grafo():
    auditor = _make_auditor()
    auditor.rbac = SimpleNamespace(
        list_namespaced_role=lambda ns, **kw: SimpleNamespace(items=[_fake_role("god-mode")]),
        list_namespaced_role_binding=lambda ns, **kw: SimpleNamespace(
            items=[_fake_role_binding("bind-god-mode", "god-mode", ["default-sa"])]
        ),
    )

    findings = auditor._check_namespaced_rbac(["default"])

    assert len(findings) == 1
    graph = auditor.graph_output()
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "role/default/god-mode" in node_ids


def test_namespace_sem_permissao_para_listar_role_nao_quebra_scan():
    from kubernetes.client.rest import ApiException

    auditor = _make_auditor()

    def _raise(ns, **kw):
        raise ApiException(status=403, reason="Forbidden")

    auditor.rbac = SimpleNamespace(
        list_namespaced_role=_raise,
        list_namespaced_role_binding=_raise,
    )

    findings = auditor._check_namespaced_rbac(["default"])

    assert findings == []
