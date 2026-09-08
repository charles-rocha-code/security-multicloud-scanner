"""
POST /ai/ask-tools (openspec/changes/add-ai-ask-tool-calling/) — cobre os
requirements de specs/ai-tool-calling/spec.md que dizem respeito ao
endpoint em si: autenticação exigida, campo `kubeconfig` opcional com
fallback pro kubeconfig local, e rate limit próprio (não o de /ai/ask).

`ai_tools.ask_with_tools` é sempre mockado aqui -- este arquivo testa o
contrato HTTP do endpoint, não o loop de tool-use (isso é
tests/test_ai_tools.py). Nenhum teste bate na Anthropic API real.
"""
import logging

import pytest
from fastapi.testclient import TestClient

import api_with_mfa
from auth_mfa import require_mfa

TEST_EMAIL = "ask-tools-test@example.com"


@pytest.fixture(autouse=True, scope="module")
def _restore_scanner_logger_propagation():
    """Importar api_with_mfa roda setup_logging() (logging_setup.py) a nível
    de módulo, que seta logging.getLogger('scanner').propagate = False --
    efeito colateral global no processo, não só neste arquivo. Sem desfazer
    isso, qualquer teste depois deste arquivo que use caplog num logger
    'scanner.*' (ex.: tests/test_auth_local_backend.py) para de capturar
    registro nenhum, porque eles não sobem mais até o root logger que o
    caplog escuta. Não é bug introduzido por este change -- é um efeito
    colateral pré-existente de setup_logging(), só nunca disparado antes
    porque nenhum teste da suíte importava api_with_mfa."""
    yield
    logging.getLogger("scanner").propagate = True


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    # O limiter é um singleton em memória (Redis indisponível localmente) --
    # sem reset, requisições de um teste contam pra cota do próximo.
    api_with_mfa.limiter.reset()
    yield


@pytest.fixture
def client():
    return TestClient(api_with_mfa.app)


@pytest.fixture
def authenticated():
    """Sobrepõe require_mfa (sessão MFA válida) e garante um scan salvo,
    sem depender de login/cookie real nem de DynamoDB. LAST_SCAN_BY_EMAIL é
    um _ScanCache customizado (só __setitem__/get, sem __delitem__) -- não dá
    pra usar monkeypatch.setitem nele, por isso o set/cleanup é manual."""
    api_with_mfa.app.dependency_overrides[require_mfa] = lambda: {"email": TEST_EMAIL}
    api_with_mfa.LAST_SCAN_BY_EMAIL[TEST_EMAIL] = {"result": {"provider": "kubernetes"}}
    yield
    api_with_mfa.app.dependency_overrides.pop(require_mfa, None)
    api_with_mfa.LAST_SCAN_BY_EMAIL._mem.pop(TEST_EMAIL, None)


def test_sem_sessao_mfa_retorna_401(client):
    resp = client.post("/ai/ask-tools", json={"question": "algum ClusterRole com '*' agora?"})
    assert resp.status_code == 401


def test_sem_scan_salvo_retorna_404(client, monkeypatch):
    api_with_mfa.app.dependency_overrides[require_mfa] = lambda: {"email": "sem-scan@example.com"}
    try:
        resp = client.post("/ai/ask-tools", json={"question": "x"})
        assert resp.status_code == 404
    finally:
        api_with_mfa.app.dependency_overrides.pop(require_mfa, None)


def test_sem_kubeconfig_no_body_cai_pro_default_local(client, authenticated, monkeypatch):
    captured = {}

    def _fake_ask_with_tools(question, scan, history=None, kubeconfig_yaml=None):
        captured["kubeconfig_yaml"] = kubeconfig_yaml
        return "ok"

    monkeypatch.setattr(api_with_mfa.ai_tools, "ask_with_tools", _fake_ask_with_tools)

    resp = client.post("/ai/ask-tools", json={"question": "algo sobre o cluster", "use_history": False})

    assert resp.status_code == 200
    assert captured["kubeconfig_yaml"] is None  # endpoint não resolve o default -- ai_tools resolve


def test_kubeconfig_enviado_no_body_e_repassado(client, authenticated, monkeypatch):
    captured = {}

    def _fake_ask_with_tools(question, scan, history=None, kubeconfig_yaml=None):
        captured["kubeconfig_yaml"] = kubeconfig_yaml
        return "ok"

    monkeypatch.setattr(api_with_mfa.ai_tools, "ask_with_tools", _fake_ask_with_tools)

    resp = client.post(
        "/ai/ask-tools",
        json={"question": "algo sobre o cluster", "use_history": False, "kubeconfig": "conteudo-yaml-fake"},
    )

    assert resp.status_code == 200
    assert captured["kubeconfig_yaml"] == "conteudo-yaml-fake"


def test_rate_limit_proprio_nao_e_o_de_ai_ask(client, authenticated, monkeypatch):
    monkeypatch.setattr(api_with_mfa.ai_tools, "ask_with_tools", lambda *a, **kw: "ok")

    statuses = [
        client.post("/ai/ask-tools", json={"question": "x", "use_history": False}).status_code
        for _ in range(6)
    ]

    assert statuses[:5] == [200, 200, 200, 200, 200]
    assert statuses[5] == 429
