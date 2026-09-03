"""
_check_network_exposure só verificava se existia algum objeto NetworkPolicy
no namespace, sem olhar o conteúdo -- uma policy com regra de ingress sem
'from' casa qualquer origem (equivale a allow-all) e passava como
"protegido". Ver docs/cwpp-roadmap.md, Fase 2.
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
    obj.core = SimpleNamespace(
        list_namespaced_service=lambda ns, **kw: SimpleNamespace(items=[])
    )
    return obj


def _fake_policy(name, ingress_rules):
    spec = SimpleNamespace(ingress=ingress_rules)
    return SimpleNamespace(metadata=SimpleNamespace(name=name), spec=spec)


def test_networkpolicy_com_ingress_sem_from_gera_finding_high():
    auditor = _make_auditor()
    allow_all_rule = SimpleNamespace(_from=None)
    auditor.networking = SimpleNamespace(
        list_namespaced_network_policy=lambda ns, **kw: SimpleNamespace(
            items=[_fake_policy("fake-deny-all", [allow_all_rule])]
        )
    )

    findings = auditor._check_network_exposure(["default"])

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource_type"] == "NetworkPolicy"
    assert "allow-all" in findings[0]["reason"]


def test_networkpolicy_restritiva_de_verdade_nao_gera_finding():
    auditor = _make_auditor()
    restrictive_rule = SimpleNamespace(
        _from=[SimpleNamespace(pod_selector=SimpleNamespace(match_labels={"app": "frontend"}))]
    )
    auditor.networking = SimpleNamespace(
        list_namespaced_network_policy=lambda ns, **kw: SimpleNamespace(
            items=[_fake_policy("real-policy", [restrictive_rule])]
        )
    )

    findings = auditor._check_network_exposure(["default"])

    assert findings == []


def test_namespace_sem_networkpolicy_mantem_comportamento_atual():
    auditor = _make_auditor()
    auditor.networking = SimpleNamespace(
        list_namespaced_network_policy=lambda ns, **kw: SimpleNamespace(items=[])
    )

    findings = auditor._check_network_exposure(["default"])

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource_type"] == "Namespace"
