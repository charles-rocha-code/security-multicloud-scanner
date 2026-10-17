"""
Credencial recusada (401) ou cluster fora do ar não pode virar um scan
"limpo". Antes, cada check engolia o erro, o resultado saía com
risk_score baixo e um único finding LOW, e o 401 ficava só em 'errors'
(que o dashboard não mostra) -- reproduzido contra o cluster kind local
com o token vencido do kubeconfig de piloto.
"""
import logging

import pytest
from kubernetes.client.rest import ApiException

from auditor_k8s import K8sAccessError, verify_cluster_access


class _Core:
    def __init__(self, exc=None):
        self.exc = exc

    def list_namespace(self, **kwargs):
        if self.exc:
            raise self.exc
        return object()


def _api_exc(status, reason="x"):
    e = ApiException(status=status, reason=reason)
    return e


def test_credencial_aceita_passa():
    verify_cluster_access(_Core())


def test_401_levanta_k8saccesserror():
    with pytest.raises(K8sAccessError, match="401"):
        verify_cluster_access(_Core(_api_exc(401, "Unauthorized")))


def test_403_passa_rbac_restrito_e_uso_legitimo():
    verify_cluster_access(_Core(_api_exc(403, "Forbidden")))


def test_outro_status_levanta():
    with pytest.raises(K8sAccessError, match="500"):
        verify_cluster_access(_Core(_api_exc(500, "Internal Server Error")))


def test_cluster_fora_do_ar_levanta():
    with pytest.raises(K8sAccessError, match="não respondeu"):
        verify_cluster_access(_Core(ConnectionRefusedError("refused")))


def test_authenticated_auditor_run_levanta_em_401(monkeypatch):
    from auditor_k8s_authenticated import K8sAuthenticatedAuditor

    auditor = K8sAuthenticatedAuditor.__new__(K8sAuthenticatedAuditor)
    auditor.core = _Core(_api_exc(401, "Unauthorized"))
    auditor.timeout = 1

    with pytest.raises(K8sAccessError):
        auditor.run()


def test_scan_k8s_com_credencial_recusada_responde_400_e_nao_salva(monkeypatch):
    from fastapi.testclient import TestClient
    import api_with_mfa
    from auth_mfa import require_mfa

    email = "cluster-access@example.com"
    salvos = []

    def _recusa(*a, **k):
        raise K8sAccessError("o cluster recusou a credencial do kubeconfig (401 Unauthorized)")

    monkeypatch.setattr(api_with_mfa, "_run_full_k8s_scan", _recusa)
    monkeypatch.setattr(api_with_mfa, "save_scan", lambda *a, **k: salvos.append(a), raising=False)
    api_with_mfa.limiter.reset()
    api_with_mfa.app.dependency_overrides[require_mfa] = lambda: {"email": email}
    try:
        kc = "clusters:\n- name: c\n  cluster: {server: 'https://10.0.0.1:6443'}\nusers:\n- name: u\n  user: {token: abc}\n"
        resp = TestClient(api_with_mfa.app).post("/scan/k8s", json={"kubeconfig": kc})
    finally:
        api_with_mfa.app.dependency_overrides.pop(require_mfa, None)
        logging.getLogger("scanner").propagate = True

    assert resp.status_code == 400
    assert "401" in resp.json()["detail"]
    assert salvos == []
