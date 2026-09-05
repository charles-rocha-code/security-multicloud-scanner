"""
_check_secrets_configmaps só olhava o NOME da chave de um ConfigMap
('password', 'secret', 'token'...) -- uma chave com nome inofensivo
('app-config') mas valor contendo um segredo real embutido (chave AWS,
chave privada, JWT) passava invisível, mesmo o mesmo conteúdo já sendo
detectado nos auditores de storage (engine_risk.py). Ver
docs/dspm-kspm-roadmap.md, Fase D2.
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
        list_namespaced_pod=lambda ns, **kw: SimpleNamespace(items=[])
    )
    return obj


def _fake_configmap(name, data):
    return SimpleNamespace(metadata=SimpleNamespace(name=name), data=data)


def test_chave_com_nome_sensivel_continua_critical_sem_scan_de_conteudo():
    auditor = _make_auditor()
    auditor.core.list_namespaced_config_map = lambda ns, **kw: SimpleNamespace(
        items=[_fake_configmap("cfg", {"password": "qualquer-coisa"})]
    )

    findings = auditor._check_secrets_configmaps(["default"])

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert "chave sensível" in findings[0]["reason"]


def test_chave_com_nome_inofensivo_mas_valor_com_chave_aws_e_detectada():
    auditor = _make_auditor()
    auditor.core.list_namespaced_config_map = lambda ns, **kw: SimpleNamespace(
        items=[_fake_configmap("app-config", {"settings": "AKIAABCDEFGHIJKLMNOP"})]  # nosemgrep: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value -- chave falsa, fixture de teste
    )

    findings = auditor._check_secrets_configmaps(["default"])

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert "chave 'settings'" in findings[0]["reason"]


def test_chave_com_valor_comum_nao_gera_finding():
    auditor = _make_auditor()
    auditor.core.list_namespaced_config_map = lambda ns, **kw: SimpleNamespace(
        items=[_fake_configmap("app-config", {"log_level": "debug"})]
    )

    findings = auditor._check_secrets_configmaps(["default"])

    assert findings == []


def test_ca_cert_legitimo_nao_gera_falso_positivo_de_entropia():
    # Achado num scan real contra um cluster kind (docs/dspm-kspm-roadmap.md):
    # kube-root-ca.crt (certificado PEM público, existe em todo namespace por
    # padrão do próprio Kubernetes) batia no fallback de "alta entropia" --
    # 100% falso-positivo, zero relação com segredo de usuário.
    auditor = _make_auditor()
    fake_pem = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDXTCCAkWgAwIBAgIJAqGZ8f9K3vN2wR7tY1sB6dF3hJ0cA5eGXk9mZq2Lp8vN\n"
        "-----END CERTIFICATE-----\n"
    )
    auditor.core.list_namespaced_config_map = lambda ns, **kw: SimpleNamespace(
        items=[_fake_configmap("kube-root-ca.crt", {"ca.crt": fake_pem})]
    )

    findings = auditor._check_secrets_configmaps(["default"])

    assert findings == []
