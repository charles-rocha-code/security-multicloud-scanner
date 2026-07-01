"""
waf_agent.py — Gerencia WAF: bloqueia IPs automaticamente, desbloqueia com aprovação.
"""
from __future__ import annotations

from .approval import create_token
from .notifier import notify_action_executed, notify_action_pending, notify_incident, Severity
from .tools.aws import get_error_logs, get_ip_set, get_waf_rules, update_ip_set

BLOCKED_IP_SET_NAME = "security-scanner-production-waf-blocked-ips"
BLOCKED_IP_SET_ID   = "175ba253-6665-48b9-b4c3-d8a54cdaebc4"
TRUSTED_IP_SET_NAME = "security-scanner-production-waf-trusted-ips"
TRUSTED_IP_SET_ID   = "12065527-8c83-411a-b8c1-9f4f4187e005"
RATE_THRESHOLD      = 500  # requisições suspeitas para auto-block


def status() -> dict:
    """Retorna estado atual do WAF — regras, IPs bloqueados e confiáveis."""
    rules   = get_waf_rules()
    blocked = get_ip_set(BLOCKED_IP_SET_NAME, BLOCKED_IP_SET_ID)
    trusted = get_ip_set(TRUSTED_IP_SET_NAME, TRUSTED_IP_SET_ID)
    return {"rules": rules, "blocked_ips": blocked["addresses"], "trusted_ips": trusted["addresses"]}


def block_ip(ip: str, reason: str = "Manual") -> dict:
    """Bloqueia um IP. Executa automaticamente (sem aprovação)."""
    cidr = ip if "/" in ip else f"{ip}/32"
    data = get_ip_set(BLOCKED_IP_SET_NAME, BLOCKED_IP_SET_ID)

    if cidr in data["addresses"]:
        return {"status": "skipped", "reason": f"{cidr} já está bloqueado"}

    new_list = data["addresses"] + [cidr]
    update_ip_set(BLOCKED_IP_SET_NAME, BLOCKED_IP_SET_ID, new_list, data["lock_token"])

    notify_action_executed(
        agent="WAFAgent",
        action=f"IP bloqueado: {cidr}",
        result=f"Motivo: {reason}\nTotal de IPs bloqueados: {len(new_list)}",
    )
    print(f"[WAFAgent] IP bloqueado: {cidr} — {reason}")
    return {"status": "executed", "ip": cidr, "total_blocked": len(new_list)}


def unblock_ip(ip: str) -> dict:
    """Desbloqueia IP. Sempre exige aprovação humana."""
    cidr = ip if "/" in ip else f"{ip}/32"

    # Fix 4: verifica se o IP está realmente bloqueado antes de criar token
    data = get_ip_set(BLOCKED_IP_SET_NAME, BLOCKED_IP_SET_ID)
    if cidr not in data["addresses"]:
        return {"status": "skipped", "reason": f"{cidr} não está na lista de bloqueados"}

    token = create_token(
        action_command=f"waf unblock-execute {cidr}",
        description=f"Remover {cidr} do IP Set de bloqueados no WAF",
    )
    notify_action_pending(
        agent="WAFAgent",
        token=token,
        proposed_action=f"Desbloquear IP: remover {cidr} do WAF",
        context=f"IP {cidr} está atualmente bloqueado no WAF.\n"
                f"Confirme se o desbloqueio é intencional.",
    )
    return {"status": "pending_approval", "token": token, "ip": cidr}


def execute_unblock(ip: str) -> dict:
    """Executa desbloqueio após aprovação humana."""
    cidr = ip if "/" in ip else f"{ip}/32"
    data = get_ip_set(BLOCKED_IP_SET_NAME, BLOCKED_IP_SET_ID)
    new_list = [a for a in data["addresses"] if a != cidr]
    update_ip_set(BLOCKED_IP_SET_NAME, BLOCKED_IP_SET_ID, new_list, data["lock_token"])
    notify_action_executed(
        agent="WAFAgent",
        action=f"IP desbloqueado: {cidr}",
        result=f"Total de IPs bloqueados agora: {len(new_list)}",
    )
    return {"status": "executed", "ip": cidr}


def _is_private_ip(ip: str) -> bool:
    """Retorna True para IPs reservados/internos que nunca devem ser bloqueados no WAF."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local    # 169.254.x.x — IMDS da EC2
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return True  # formato inválido → não bloquear


def scan_logs_for_attacks(minutes: int = 30) -> dict:
    """
    Analisa logs em busca de padrões de ataque.
    Bloqueia automaticamente IPs públicos com volume suspeito.
    IPs privados/internos são ignorados (Fix 1).
    """
    from collections import Counter
    import re

    errors = get_error_logs(minutes=minutes)
    if not errors:
        return {"status": "clean", "blocked": []}

    ip_pattern = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    ip_counts  = Counter()
    for e in errors:
        for ip in ip_pattern.findall(e.get("message", "")):
            if not _is_private_ip(ip):          # Fix 1: ignora IPs internos
                ip_counts[ip] += 1

    blocked = []
    for ip, count in ip_counts.items():
        if count >= RATE_THRESHOLD:
            result = block_ip(ip, reason=f"Rate automático: {count} erros em {minutes} min")
            # Fix 2: block_ip() já envia notify_action_executed — sem segundo email aqui
            if result["status"] == "executed":
                blocked.append(ip)

    return {"status": "scanned", "errors_found": len(errors), "ips_blocked": blocked}
