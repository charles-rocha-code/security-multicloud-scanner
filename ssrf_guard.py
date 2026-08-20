"""Bloqueia URL de servidor apontando pra loopback/link-local/metadados de
nuvem, antes de qualquer request real. Existe porque as exceções de WAF em
/scan/k8s e /generate-report (EC2MetaDataSSRF_BODY, GenericRFI_BODY) tiraram
a proteção de borda pra esse padrão especificamente nessas rotas -- essa
checagem é a defesa real que sobrou, não decoração.

Bloqueia link-local (inclui 169.254.169.254, metadados de AWS/Azure/GCP)
sempre, em qualquer backend -- risco de metadados do host é independente de
onde a app roda. NÃO bloqueia faixa privada geral (10.x/172.16.x/192.168.x)
porque cluster K8s privado legítimo é um caso de uso real desta ferramenta.

Loopback só é bloqueado em STORAGE_BACKEND=aws (produção): lá, permitir
'server: 127.0.0.1' seria SSRF contra o próprio host de produção atrás do
WAF. Em STORAGE_BACKEND=local (padrão sem AWS) quem roda o scan é o mesmo
dono da máquina e do cluster (ex.: kind, que só publica a API em loopback) --
o risco que esse bloqueio existe pra evitar não se aplica nesse cenário.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

_ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local -- cobre 169.254.169.254
    ipaddress.ip_network("fe80::/10"),        # link-local IPv6
]

_LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback IPv4
    ipaddress.ip_network("::1/128"),          # loopback IPv6
]


def assert_server_not_ssrf_target(server_url: str) -> None:
    host = urlparse(server_url).hostname
    if not host:
        raise ValueError("kubeconfig com 'server:' inválido ou ausente")

    try:
        # Resolve pra IP antes de checar -- não confia só na string do host,
        # senão um hostname que resolve pra 169.254.169.254 passaria batido.
        addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        raise ValueError(f"Não foi possível resolver o endereço do cluster: {host}")

    blocked_networks = list(_ALWAYS_BLOCKED_NETWORKS)
    if os.environ.get("STORAGE_BACKEND", "local") == "aws":
        blocked_networks += _LOOPBACK_NETWORKS

    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if any(ip in net for net in blocked_networks):
            raise ValueError(
                f"Endereço do cluster ({host} -> {ip}) aponta para loopback/"
                f"link-local/metadados de nuvem -- recusado por segurança."
            )
