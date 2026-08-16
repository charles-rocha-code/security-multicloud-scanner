"""
Transforma em regressão permanente a validação que fizemos manualmente ao
vivo (contra as classes reais de auditor, e depois em produção via SSM)
quando corrigimos o gap de SSRF aberto pelas exceções de WAF em /scan/k8s
e /generate-report. Sem isso, o teste "passou uma vez" não protege contra
alguém remover a checagem sem querer num refactor futuro.

Usa só IPs literais (nunca hostname a resolver de verdade) -- não pode
depender de rede/DNS disponível no runner do CI.
"""
import pytest

from ssrf_guard import assert_server_not_ssrf_target


@pytest.mark.parametrize("url", [
    "https://169.254.169.254/latest/meta-data/",   # metadados AWS/Azure
    "https://127.0.0.1:6443",                        # loopback IPv4
    "https://[::1]:6443",                             # loopback IPv6
    "https://[fe80::1]:6443",                         # link-local IPv6
])
def test_bloqueia_alvos_de_ssrf(url):
    with pytest.raises(ValueError):
        assert_server_not_ssrf_target(url)


def test_bloqueia_localhost_via_resolucao_dns():
    # "localhost" resolve pra 127.0.0.1 -- prova que a checagem resolve o
    # hostname pra IP antes de comparar, não confia só na string literal
    with pytest.raises(ValueError):
        assert_server_not_ssrf_target("https://localhost:6443")


def test_permite_ip_privado_nao_link_local():
    # Cluster K8s privado (10.x/172.16.x/192.168.x) é caso de uso real
    # desta ferramenta -- a guarda não pode bloquear isso, só
    # loopback/link-local/metadados
    assert_server_not_ssrf_target("https://10.0.1.50:6443") is None


def test_url_sem_hostname_e_rejeitada():
    with pytest.raises(ValueError):
        assert_server_not_ssrf_target("nao-e-uma-url")
