"""
watchdog.py — Monitora saúde do ambiente e dispara alertas.
Não toma ações — apenas detecta e notifica.
"""
from __future__ import annotations

from .notifier import notify_incident, Severity
from .tools.aws import (
    get_alarms_in_alarm, get_cpu_average, describe_asg,
    get_target_health, get_error_logs,
)

ASG_MAIN  = "security-scanner-asg"
TG_MAIN   = "security-scanner-tg"
CPU_THRESHOLD = 80.0
MIN_HEALTHY   = 1


def run() -> dict:
    """
    Executa checagem completa do ambiente.
    Retorna dict com achados e dispara notificações se necessário.
    """
    findings = []

    # 1. Alarmes CloudWatch ativos
    alarms = get_alarms_in_alarm()
    if alarms:
        names = ", ".join(a["name"] for a in alarms)
        findings.append({"type": "alarm", "severity": "HIGH", "detail": f"Alarmes ativos: {names}"})
        notify_incident(
            agent="WatchdogAgent",
            description=f"Alarmes CloudWatch em estado ALARM:\n" +
                        "\n".join(f"  • {a['name']}: {a['reason']}" for a in alarms),
            severity=Severity.HIGH,
        )

    # 2. CPU do ASG principal
    cpu = get_cpu_average(ASG_MAIN)
    if cpu >= CPU_THRESHOLD:
        findings.append({"type": "cpu", "severity": "HIGH", "detail": f"CPU média: {cpu}%"})
        notify_incident(
            agent="WatchdogAgent",
            description=f"CPU média do ASG {ASG_MAIN}: {cpu}% (threshold: {CPU_THRESHOLD}%)\n"
                        f"Considere escalar o ambiente.",
            severity=Severity.HIGH,
        )

    # 3. Instâncias unhealthy no Target Group
    health = get_target_health(TG_MAIN)
    unhealthy = [t for t in health if t["state"] != "healthy"]
    if unhealthy:
        detail = "\n".join(f"  • {t['id']}: {t['state']} ({t['reason']})" for t in unhealthy)
        findings.append({"type": "unhealthy", "severity": "CRITICAL", "detail": detail})
        notify_incident(
            agent="WatchdogAgent",
            description=f"{len(unhealthy)} instância(s) unhealthy no Target Group {TG_MAIN}:\n{detail}",
            severity=Severity.CRITICAL,
        )

    # 4. ASG com menos instâncias que o mínimo esperado
    asg = describe_asg(ASG_MAIN)
    healthy_count = sum(1 for i in asg.get("instances", []) if i["health"] == "Healthy")
    if healthy_count < MIN_HEALTHY:
        findings.append({"type": "asg", "severity": "CRITICAL",
                         "detail": f"Apenas {healthy_count} instância(s) healthy no ASG"})
        notify_incident(
            agent="WatchdogAgent",
            description=f"ASG {ASG_MAIN} com apenas {healthy_count} instância(s) healthy.\n"
                        f"Desired: {asg.get('desired')}, Min: {asg.get('min')}",
            severity=Severity.CRITICAL,
        )

    # 5. Erros recentes nos logs
    errors = get_error_logs(minutes=30)
    if len(errors) > 10:
        findings.append({"type": "logs", "severity": "HIGH",
                         "detail": f"{len(errors)} erros nos últimos 30 minutos"})
        notify_incident(
            agent="WatchdogAgent",
            description=f"{len(errors)} erros detectados nos logs nos últimos 30 minutos.\n"
                        f"Primeiros erros:\n" +
                        "\n".join(f"  • {e['message'][:120]}" for e in errors[:5]),
            severity=Severity.HIGH,
        )

    status = "ok" if not findings else "anomaly"
    print(f"[WatchdogAgent] Status: {status} — {len(findings)} achado(s)")
    return {"status": status, "findings": findings, "cpu": cpu, "healthy_instances": healthy_count}
