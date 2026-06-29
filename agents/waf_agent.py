"""
waf_agent.py — Gerencia WAF: bloqueia IPs automaticamente, desbloqueia com aprovação.
"""
from __future__ import annotations

import uuid

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
    cidr      = ip if "/" in ip else f"{ip}/32"
    action_id = str(uuid.uuid4())[:8]

    notify_action_pending(
        agent="WAFAgent",
        action_id=action_id,
        proposed_action=f"Remover {cidr} do IP Set de bloqueados",
        context=f"IP {cidr} está atualmente bloqueado no WAF.\n"
                f"Confirme se o desbloqueio é intencional.",
    )
    return {"status": "pending_approval", "action_id": action_id, "ip": cidr}


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


def scan_logs_for_attacks(minutes: int = 30) -> dict:
    """
    Analisa logs em busca de padrões de ataque.
    Bloqueia automaticamente IPs com volume suspeito.
    """
    from collections import Counter
    import re

    errors = get_error_logs(minutes=minutes)
    if not errors:
        return {"status": "clean", "blocked": []}

    # Extrai IPs dos logs (padrão: IP no início da mensagem ou após "client:")
    ip_pattern = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    ip_counts  = Counter()
    for e in errors:
        for ip in ip_pattern.findall(e.get("message", "")):
            ip_counts[ip] += 1

    blocked = []
    for ip, count in ip_counts.items():
        if count >= RATE_THRESHOLD:
            result = block_ip(ip, reason=f"Rate automático: {count} erros em {minutes} min")
            if result["status"] == "executed":
                blocked.append(ip)
                notify_incident(
                    agent="WAFAgent",
                    description=f"IP {ip} bloqueado automaticamente.\n"
                                f"Motivo: {count} erros nos últimos {minutes} minutos.",
                    severity=Severity.HIGH,
                )

    return {"status": "scanned", "errors_found": len(errors), "ips_blocked": blocked}
