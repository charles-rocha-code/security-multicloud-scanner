"""
Transforma em regressão permanente a validação que fizemos manualmente ao
vivo (contra as classes reais de auditor, e depois em produção via SSM)
quando corrigimos o gap de SSRF aberto pelas exceções de WAF em /scan/k8s
e /generate-report. Sem isso, o teste "passou uma vez" não protege contra
alguém remover a checagem sem querer num refactor futuro.

Loopback só é liberado quando STORAGE_BACKEND é EXPLICITAMENTE "local" -- em
qualquer outro valor, inclusive a variável não definida (ambiente novo, ou
deploy mal configurado), o bloqueio de loopback fica ativo por padrão
(fail-safe: risco de SSRF contra host de produção atrás do WAF não pode
depender de alguém lembrar de setar STORAGE_BACKEND=aws em todo caminho de
deploy possível). Link-local/metadados continuam bloqueados sempre, em
qualquer backend.

Usa só IPs literais (nunca hostname a resolver de verdade) -- não pode
depender de rede/DNS disponível no runner do CI.
"""
import pytest

from ssrf_guard import assert_server_not_ssrf_target


@pytest.mark.parametrize("url", [
    "https://169.254.169.254/latest/meta-data/",   # metadados AWS/Azure
    "https://[fe80::1]:6443",                        # link-local IPv6
])
@pytest.mark.parametrize("backend", ["local", "aws"])
def test_bloqueia_link_local_e_metadados_em_qualquer_backend(url, backend, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", backend)
    with pytest.raises(ValueError):
        assert_server_not_ssrf_target(url)


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:6443",   # loopback IPv4
    "https://[::1]:6443",       # loopback IPv6
])
def test_bloqueia_loopback_em_producao(url, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "aws")
    with pytest.raises(ValueError):
        assert_server_not_ssrf_target(url)


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:6443",
    "https://[::1]:6443",
])
def test_permite_loopback_em_modo_local(url, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    assert assert_server_not_ssrf_target(url) is None


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:6443",
    "https://[::1]:6443",
])
def test_bloqueia_loopback_quando_storage_backend_nao_esta_definido(url, monkeypatch):
    # Achado do code review: se ninguem setar STORAGE_BACKEND (ambiente
    # novo, deploy que esqueceu a variavel), o bloqueio de loopback nao
    # pode ficar liberado por omissao -- so "local" explicito libera.
    monkeypatch.delenv("STORAGE_BACKEND", raising=False)
    with pytest.raises(ValueError):
        assert_server_not_ssrf_target(url)


def test_bloqueia_localhost_via_resolucao_dns_em_producao(monkeypatch):
    # "localhost" resolve pra 127.0.0.1 -- prova que a checagem resolve o
    # hostname pra IP antes de comparar, não confia só na string literal
    monkeypatch.setenv("STORAGE_BACKEND", "aws")
    with pytest.raises(ValueError):
        assert_server_not_ssrf_target("https://localhost:6443")


def test_permite_ip_privado_nao_link_local():
    # Cluster K8s privado (10.x/172.16.x/192.168.x) é caso de uso real
    # desta ferramenta -- a guarda não pode bloquear isso, só
    # loopback (em produção)/link-local/metadados
    assert assert_server_not_ssrf_target("https://10.0.1.50:6443") is None


def test_url_sem_hostname_e_rejeitada():
    with pytest.raises(ValueError):
        assert_server_not_ssrf_target("nao-e-uma-url")
