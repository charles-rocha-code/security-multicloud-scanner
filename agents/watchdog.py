"""
watchdog.py — Monitora saúde do ambiente e dispara alertas.
Não toma ações — apenas detecta e notifica.
Todas as verificações são executadas em paralelo (ThreadPoolExecutor).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .notifier import notify_incident, Severity
from .tools.aws import (
    get_alarms_in_alarm, get_cpu_average, describe_asg,
    get_target_health, get_error_logs,
)

ASG_MAIN      = "security-scanner-asg"
TG_MAIN       = "security-scanner-tg"
CPU_THRESHOLD = 80.0
MIN_HEALTHY   = 1


def _check_alarms() -> dict:
    alarms = get_alarms_in_alarm()
    if not alarms:
        return {}
    names = ", ".join(a["name"] for a in alarms)
    notify_incident(
        agent="WatchdogAgent",
        description="Alarmes CloudWatch em estado ALARM:\n" +
                    "\n".join(f"  • {a['name']}: {a['reason']}" for a in alarms),
        severity=Severity.HIGH,
    )
    return {"type": "alarm", "severity": "HIGH", "detail": f"Alarmes ativos: {names}"}


def _check_cpu() -> tuple[float, dict | None]:
    cpu = get_cpu_average(ASG_MAIN)
    if cpu < CPU_THRESHOLD:
        return cpu, None
    notify_incident(
        agent="WatchdogAgent",
        description=f"CPU média do ASG {ASG_MAIN}: {cpu}% (threshold: {CPU_THRESHOLD}%)\n"
                    f"Considere escalar o ambiente.",
        severity=Severity.HIGH,
    )
    return cpu, {"type": "cpu", "severity": "HIGH", "detail": f"CPU média: {cpu}%"}


def _check_target_health() -> dict | None:
    health   = get_target_health(TG_MAIN)
    unhealthy = [t for t in health if t["state"] != "healthy"]
    if not unhealthy:
        return None
    detail = "\n".join(f"  • {t['id']}: {t['state']} ({t['reason']})" for t in unhealthy)
    notify_incident(
        agent="WatchdogAgent",
        description=f"{len(unhealthy)} instância(s) unhealthy no Target Group {TG_MAIN}:\n{detail}",
        severity=Severity.CRITICAL,
    )
    return {"type": "unhealthy", "severity": "CRITICAL", "detail": detail}


def _check_asg() -> tuple[int, dict | None]:
    asg           = describe_asg(ASG_MAIN)
    healthy_count = sum(1 for i in asg.get("instances", []) if i["health"] == "Healthy")
    if healthy_count >= MIN_HEALTHY:
        return healthy_count, None
    notify_incident(
        agent="WatchdogAgent",
        description=f"ASG {ASG_MAIN} com apenas {healthy_count} instância(s) healthy.\n"
                    f"Desired: {asg.get('desired')}, Min: {asg.get('min')}",
        severity=Severity.CRITICAL,
    )
    return healthy_count, {
        "type": "asg", "severity": "CRITICAL",
        "detail": f"Apenas {healthy_count} instância(s) healthy no ASG",
    }


def _check_logs() -> dict | None:
    errors = get_error_logs(minutes=30, max_events=500)
    if len(errors) <= 10:
        return None
    notify_incident(
        agent="WatchdogAgent",
        description=f"{len(errors)} erros detectados nos logs nos últimos 30 minutos.\n"
                    "Primeiros erros:\n" +
                    "\n".join(f"  • {e['message'][:120]}" for e in errors[:5]),
        severity=Severity.HIGH,
    )
    return {"type": "logs", "severity": "HIGH",
            "detail": f"{len(errors)} erros nos últimos 30 minutos"}


def run() -> dict:
    """
    Executa todas as verificações em paralelo e agrega os resultados.
    Retorna dict com achados e dispara notificações se necessário.
    """
    findings: list[dict]  = []
    cpu:      float       = 0.0
    healthy:  int         = 0

    checks = {
        "alarms": _check_alarms,
        "cpu":    _check_cpu,
        "health": _check_target_health,
        "asg":    _check_asg,
        "logs":   _check_logs,
    }

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(fn): name for name, fn in checks.items()}
        for future in as_completed(futures):
            name   = futures[future]
            result = future.result()

            if name == "cpu":
                cpu, finding = result
                if finding:
                    findings.append(finding)
            elif name == "asg":
                healthy, finding = result
                if finding:
                    findings.append(finding)
            elif result:
                findings.append(result)

    status = "ok" if not findings else "anomaly"
    print(f"[WatchdogAgent] Status: {status} — {len(findings)} achado(s)")
    return {"status": status, "findings": findings, "cpu": cpu, "healthy_instances": healthy}
