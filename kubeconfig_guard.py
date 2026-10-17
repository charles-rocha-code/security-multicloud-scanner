"""Recusa kubeconfig que faria a biblioteca do Kubernetes executar código no
host do scanner. `config.load_kube_config` e `KubeConfigLoader.load_and_set`
rodam o plugin `users[].user.exec` (e os `auth-provider` com refresh) durante
o próprio load -- antes de assert_server_not_ssrf_target e antes de qualquer
request ao cluster. Com kubeconfig vindo do usuário (/scan/k8s,
/ai/ask-tools), isso era execução remota de comando no servidor.

Denylist (exec, auth-provider) em vez de allowlist de chaves: cobre
exatamente os dois mecanismos que executam código, sem quebrar campos
legítimos e raros de `user` (impersonate, as-groups...). Token, tokenFile,
certificado de cliente e usuário/senha continuam aceitos -- é o que o
kubeconfig de ServiceAccount do script de onboarding usa.

Chamado na borda HTTP (validators dos modelos Pydantic -> 422) e de novo
nos auditores, antes do load: um caminho novo que esqueça a borda não
reabre o problema.
"""
from __future__ import annotations

from typing import Any, Dict

import yaml

FORBIDDEN_USER_KEYS = ("exec", "auth-provider")


def validate_user_kubeconfig(kubeconfig_yaml: str) -> Dict[str, Any]:
    """Faz o parse do kubeconfig e devolve o dict. Levanta ValueError se não
    for YAML de mapeamento ou se algum usuário declarar exec/auth-provider."""
    try:
        cfg = yaml.safe_load(kubeconfig_yaml)
    except yaml.YAMLError as e:
        raise ValueError(f"kubeconfig inválido: não é YAML válido ({e.__class__.__name__})")
    if not isinstance(cfg, dict):
        raise ValueError("kubeconfig inválido: esperado um mapeamento YAML (clusters/contexts/users)")
    clusters = cfg.get("clusters")
    if not isinstance(clusters, list) or not clusters:
        raise ValueError("kubeconfig inválido: 'clusters' ausente ou vazio")

    users = cfg.get("users") or []
    if not isinstance(users, list):
        raise ValueError("kubeconfig inválido: 'users' deve ser uma lista")

    for entry in users:
        user = (entry or {}).get("user") if isinstance(entry, dict) else None
        if not isinstance(user, dict):
            continue
        found = [k for k in FORBIDDEN_USER_KEYS if k in user]
        if found:
            name = entry.get("name", "?")
            raise ValueError(
                f"kubeconfig recusado: o usuário '{name}' usa {', '.join(found)}, "
                "que executa comando no servidor do scanner. Use um kubeconfig de "
                "ServiceAccount com token (ou certificado de cliente)."
            )
    return cfg


def validate_kubeconfig_file(path: str) -> Dict[str, Any]:
    """Mesma validação, lendo o kubeconfig de um arquivo."""
    with open(path, encoding="utf-8") as fh:
        return validate_user_kubeconfig(fh.read())
