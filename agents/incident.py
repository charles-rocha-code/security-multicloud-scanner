"""
incident.py — Diagnostica incidentes e coordena a resposta entre agentes.
"""
from __future__ import annotations

from .notifier import notify_incident, Severity
from .tools.aws import get_alarms_in_alarm, get_cpu_average, get_target_health, describe_asg
from . import scaler, waf_agent

ASG_MAIN      = "security-scanner-asg"
TG_MAIN       = "security-scanner-tg"
CPU_THRESHOLD = 80.0


def respond(watchdog_findings: list[dict]) -> dict:
    """
    Recebe os findings do WatchdogAgent e decide a resposta.
    Ações automáticas: scale up +1, block IP por ataque.
    Ações com aprovação: scale down, deploy, unblock.
    """
    if not watchdog_findings:
        return {"status": "ok", "actions": []}

    actions = []
    types   = {f["type"] for f in watchdog_findings}

    # CPU alta → scale up automático
    if "cpu" in types:
        cpu = get_cpu_average(ASG_MAIN)
        asg = describe_asg(ASG_MAIN)
        notify_incident(
            agent="IncidentAgent",
            description=f"CPU alta detectada ({cpu}%). Iniciando scale up automático.\n"
                        f"ASG atual: Desired={asg.get('desired')}, Max={asg.get('max')}",
            severity=Severity.HIGH,
        )
        result = scaler.scale_up(auto=True)
        actions.append({"type": "scale_up", "result": result})

    # Instância unhealthy → verifica logs para possível ataque
    if "unhealthy" in types or "alarm" in types:
        notify_incident(
            agent="IncidentAgent",
            description="Instâncias unhealthy ou alarme ativo detectado.\n"
                        "Analisando logs em busca de padrão de ataque...",
            severity=Severity.HIGH,
        )
        waf_result = waf_agent.scan_logs_for_attacks(minutes=30)
        actions.append({"type": "waf_scan", "result": waf_result})

        # Se não houver ataque, verifica se é problema de capacidade
        if not waf_result.get("ips_blocked"):
            health = get_target_health(TG_MAIN)
            healthy_count = sum(1 for t in health if t["state"] == "healthy")
            if healthy_count < 2:
                result = scaler.scale_up(auto=True)
                actions.append({"type": "scale_up_recovery", "result": result})

    # Muitos erros nos logs → scan de ataque WAF
    if "logs" in types:
        waf_result = waf_agent.scan_logs_for_attacks(minutes=30)
        actions.append({"type": "waf_scan_logs", "result": waf_result})

    print(f"[IncidentAgent] Respondeu ao incidente com {len(actions)} ação(ões)")
    return {"status": "responded", "actions": actions}


def diagnose() -> dict:
    """Diagnóstico completo do ambiente sem tomar ações."""
    cpu     = get_cpu_average(ASG_MAIN)
    health  = get_target_health(TG_MAIN)
    alarms  = get_alarms_in_alarm()
    asg     = describe_asg(ASG_MAIN)

    healthy   = [t for t in health if t["state"] == "healthy"]
    unhealthy = [t for t in health if t["state"] != "healthy"]

    return {
        "cpu_avg":          cpu,
        "healthy_targets":  len(healthy),
        "unhealthy_targets": len(unhealthy),
        "active_alarms":    len(alarms),
        "asg_desired":      asg.get("desired"),
        "asg_instances":    len(asg.get("instances", [])),
        "severity":         "CRITICAL" if unhealthy or alarms else ("HIGH" if cpu > CPU_THRESHOLD else "OK"),
    }
