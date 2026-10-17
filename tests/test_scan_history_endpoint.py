"""
`provider` vira segmento de caminho no histórico de scans
(openspec/changes/fix-security-history-kubeconfig-timeout/, spec scan-history):
a borda HTTP tem que recusar com 422 qualquer valor que não seja um
identificador simples, antes de chegar em scan_history. Sessão MFA mockada
via dependency_overrides, mesmo padrão de tests/test_ai_ask_tools_endpoint.py.
"""
import logging

import pytest
from fastapi.testclient import TestClient

import api_with_mfa
import scan_history
from auth_mfa import require_mfa

EMAIL_A = "history-a@example.com"
EMAIL_B = "history-b@example.com"


@pytest.fixture(autouse=True, scope="module")
def _restore_scanner_logger_propagation():
    # Ver o mesmo fixture em tests/test_ai_ask_tools_endpoint.py.
    yield
    logging.getLogger("scanner").propagate = True


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    api_with_mfa.limiter.reset()
    yield


@pytest.fixture
def client():
    return TestClient(api_with_mfa.app)


@pytest.fixture
def historico(tmp_path, monkeypatch):
    """Dois usuários com um scan cada, num local_data/ temporário, e o
    usuário A autenticado."""
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setattr(scan_history, "DATA_DIR", tmp_path)
    monkeypatch.setattr(scan_history, "LOCAL_DIR", tmp_path / scan_history.PREFIX)
    scan_history.save_scan(EMAIL_A, "k8s", {"risk_score": 1})
    scan_history.save_scan(EMAIL_B, "k8s", {"risk_score": 2})
    api_with_mfa.app.dependency_overrides[require_mfa] = lambda: {"email": EMAIL_A}
    yield
    api_with_mfa.app.dependency_overrides.pop(require_mfa, None)


def test_history_provider_valido_lista_so_os_scans_do_usuario(client, historico):
    resp = client.get("/scan/history", params={"provider": "k8s"})

    assert resp.status_code == 200
    scans = resp.json()["scans"]
    assert len(scans) == 1
    assert scan_history._email_safe(EMAIL_A) in scans[0]["key"]


def test_history_provider_em_maiusculas_continua_aceito(client, historico):
    resp = client.get("/scan/history", params={"provider": "K8S"})

    assert resp.status_code == 200
    assert resp.json()["total"] == 1


@pytest.mark.parametrize("provider", [
    f"../{scan_history._email_safe(EMAIL_B)}",
    "../../",
    "k8s/../../x",
    "a" * 33,
])
def test_history_provider_com_traversal_responde_422(client, historico, provider):
    resp = client.get("/scan/history", params={"provider": provider})

    assert resp.status_code == 422
    assert scan_history._email_safe(EMAIL_B) not in resp.text.replace(provider, "")


def test_history_sem_provider_nao_cruza_usuarios(client, historico):
    resp = client.get("/scan/history")

    assert resp.status_code == 200
    keys = [s["key"] for s in resp.json()["scans"]]
    assert len(keys) == 1
    assert all(scan_history._email_safe(EMAIL_B) not in k for k in keys)


@pytest.mark.parametrize("rota", ["/ai/ask", "/ai/ask-tools"])
def test_ai_com_provider_traversal_responde_422_antes_do_modelo(client, historico, monkeypatch, rota):
    chamado = {"modelo": False}

    def _nao_deveria_chamar(*a, **k):
        chamado["modelo"] = True
        return "x"

    monkeypatch.setattr(api_with_mfa.ai_analyzer, "ask", _nao_deveria_chamar, raising=False)
    if getattr(api_with_mfa, "ai_tools", None) is not None:
        monkeypatch.setattr(api_with_mfa.ai_tools, "ask_with_tools", _nao_deveria_chamar)

    resp = client.post(rota, json={
        "question": "resuma",
        "provider": f"../{scan_history._email_safe(EMAIL_B)}",
    })

    assert resp.status_code == 422
    assert chamado["modelo"] is False
