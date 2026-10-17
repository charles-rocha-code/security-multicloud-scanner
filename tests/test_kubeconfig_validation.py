"""
kubeconfig enviado pelo usuário não pode executar comando no scanner
(openspec/changes/fix-security-history-kubeconfig-timeout/, spec
k8s-kubeconfig-validation). Os testes de sentinela provam o ponto que
importa: o comando do plugin `exec` NÃO roda -- não só que um erro sobe.
"""
import pytest
import yaml

from kubeconfig_guard import validate_kubeconfig_file, validate_user_kubeconfig


def _kubeconfig(user: dict, server: str = "https://10.0.0.1:6443") -> str:
    return yaml.safe_dump({
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "c", "cluster": {"server": server, "insecure-skip-tls-verify": True}}],
        "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "u"}}],
        "current-context": "ctx",
        "users": [{"name": "u", "user": user}],
    })


def _exec_kubeconfig(sentinel_path) -> str:
    return _kubeconfig({"exec": {
        "apiVersion": "client.authentication.k8s.io/v1beta1",
        "command": "sh",
        "args": ["-c", f"touch {sentinel_path}; echo '{{}}'"],
    }})


# --- validador puro --------------------------------------------------------

def test_token_aceito():
    cfg = validate_user_kubeconfig(_kubeconfig({"token": "abc"}))
    assert cfg["users"][0]["user"]["token"] == "abc"


def test_client_cert_aceito():
    validate_user_kubeconfig(_kubeconfig({
        "client-certificate-data": "Y2VydA==", "client-key-data": "a2V5",
    }))


def test_exec_recusado(tmp_path):
    with pytest.raises(ValueError, match="exec"):
        validate_user_kubeconfig(_exec_kubeconfig(tmp_path / "pwned"))


def test_auth_provider_recusado():
    with pytest.raises(ValueError, match="auth-provider"):
        validate_user_kubeconfig(_kubeconfig({"auth-provider": {"name": "oidc", "config": {}}}))


@pytest.mark.parametrize("texto", [
    "::: não é yaml",          # YAML válido ({'::': ...}), mas sem clusters
    "clusters: [\n",           # YAML quebrado
    "apenas uma string",
    "- lista\n- de itens",
    "clusters: []",
])
def test_yaml_invalido_ou_nao_mapeamento_recusado(texto):
    with pytest.raises(ValueError, match="kubeconfig inválido"):
        validate_user_kubeconfig(texto)


def test_validate_kubeconfig_file(tmp_path):
    p = tmp_path / "kc.yaml"
    p.write_text(_exec_kubeconfig(tmp_path / "pwned"))
    with pytest.raises(ValueError, match="exec"):
        validate_kubeconfig_file(str(p))


# --- auditores: o comando do plugin exec NÃO pode rodar -------------------
# Antes deste change, os dois casos abaixo criavam o arquivo-sentinela
# (reproduzido manualmente): o load do kubeconfig executava o plugin.

def test_storage_auditor_nao_executa_plugin_exec(tmp_path):
    from auditor_k8s import K8sStorageAuditor
    sentinel = tmp_path / "pwned_storage"

    with pytest.raises(ValueError, match="exec"):
        K8sStorageAuditor(kubeconfig_yaml=_exec_kubeconfig(sentinel))._load_config()

    assert not sentinel.exists()


def test_authenticated_auditor_nao_executa_plugin_exec(tmp_path):
    from auditor_k8s_authenticated import K8sAuthenticatedAuditor
    sentinel = tmp_path / "pwned_auth"
    kc = tmp_path / "kc.yaml"
    kc.write_text(_exec_kubeconfig(sentinel))

    with pytest.raises(ValueError, match="exec"):
        K8sAuthenticatedAuditor(kubeconfig_path=str(kc))

    assert not sentinel.exists()


# --- borda HTTP: 422 antes de qualquer auditor ou modelo ------------------

@pytest.fixture
def api_client(monkeypatch):
    import logging
    from fastapi.testclient import TestClient
    import api_with_mfa
    from auth_mfa import require_mfa

    email = "kubeconfig-test@example.com"
    api_with_mfa.limiter.reset()
    api_with_mfa.app.dependency_overrides[require_mfa] = lambda: {"email": email}
    api_with_mfa.LAST_SCAN_BY_EMAIL[email] = {"result": {"provider": "kubernetes"}}
    yield api_with_mfa, TestClient(api_with_mfa.app)
    api_with_mfa.app.dependency_overrides.pop(require_mfa, None)
    api_with_mfa.LAST_SCAN_BY_EMAIL._mem.pop(email, None)
    logging.getLogger("scanner").propagate = True


def test_scan_k8s_com_exec_responde_422_e_nao_executa(api_client, tmp_path, monkeypatch):
    api, client = api_client
    sentinel = tmp_path / "pwned_endpoint"
    monkeypatch.setattr(api, "_run_full_k8s_scan", lambda *a, **k: pytest.fail("auditor não deveria rodar"))

    resp = client.post("/scan/k8s", json={"kubeconfig": _exec_kubeconfig(sentinel)})

    assert resp.status_code == 422
    assert "exec" in resp.text
    assert not sentinel.exists()


def test_scan_k8s_com_yaml_invalido_responde_422_nao_500(api_client):
    _, client = api_client

    resp = client.post("/scan/k8s", json={"kubeconfig": "::: não é yaml"})

    assert resp.status_code == 422
    assert "kubeconfig inválido" in resp.text


def test_ai_ask_tools_com_exec_responde_422_antes_do_modelo(api_client, tmp_path, monkeypatch):
    api, client = api_client
    sentinel = tmp_path / "pwned_tools"
    monkeypatch.setattr(api.ai_tools, "ask_with_tools", lambda *a, **k: pytest.fail("modelo não deveria ser chamado"))

    resp = client.post("/ai/ask-tools", json={"question": "audite", "kubeconfig": _exec_kubeconfig(sentinel)})

    assert resp.status_code == 422
    assert "exec" in resp.text
    assert not sentinel.exists()


def test_kubeconfig_recusado_nao_vai_pro_log(api_client, caplog):
    import logging
    _, client = api_client
    logging.getLogger("scanner").propagate = True
    segredo = "TOKEN-QUE-NAO-PODE-IR-PRO-LOG"
    kc = _kubeconfig({"token": segredo, "exec": {"command": "true"}})

    with caplog.at_level(logging.ERROR, logger="scanner"):
        resp = client.post("/scan/k8s", json={"kubeconfig": kc})

    assert resp.status_code == 422
    assert "422 em POST /scan/k8s" in caplog.text
    assert segredo not in caplog.text


def test_scan_k8s_com_token_passa_pela_validacao(api_client, monkeypatch):
    api, client = api_client
    chamado = {}
    monkeypatch.setattr(api, "_run_full_k8s_scan", lambda kc, mx: chamado.setdefault("ok", {"provider": "KUBERNETES", "files": []}))
    monkeypatch.setattr(api, "save_scan", lambda *a, **k: "", raising=False)

    resp = client.post("/scan/k8s", json={"kubeconfig": _kubeconfig({"token": "abc"})})

    assert "ok" in chamado
    assert resp.status_code != 422
