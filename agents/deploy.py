"""
deploy.py — Gerencia blue-green deploy. Sempre exige aprovação humana.
"""
from __future__ import annotations

from .approval import create_token
from .notifier import notify_action_executed, notify_action_pending, notify_incident, Severity
from .tools.aws import (
    describe_asg, get_target_health, get_tg_arn,
    switch_listener, update_asg_size,
    ASG_MAIN, ASG_GREEN, TG_MAIN, TG_GREEN,
)


def status() -> dict:
    """Retorna estado atual dos dois slots (blue e green)."""
    main_asg   = describe_asg(ASG_MAIN)
    green_asg  = describe_asg(ASG_GREEN)
    main_health  = get_target_health(TG_MAIN)
    green_health = get_target_health(TG_GREEN)

    return {
        "blue":  {"asg": main_asg,  "health": main_health},
        "green": {"asg": green_asg, "health": green_health},
    }


def promote() -> dict:
    """
    Solicita aprovação para promover slot green para produção.
    Verifica saúde do green antes de pedir aprovação.
    """
    green_health = get_target_health(TG_GREEN)
    healthy = [t for t in green_health if t["state"] == "healthy"]

    if not green_health:
        notify_incident(
            agent="DeployAgent",
            description="Promoção do green solicitada mas não há instâncias no Target Group green.",
            severity=Severity.HIGH,
        )
        return {"status": "error", "reason": "Target Group green sem instâncias"}

    if len(healthy) < len(green_health):
        unhealthy_ids = [t["id"] for t in green_health if t["state"] != "healthy"]
        notify_incident(
            agent="DeployAgent",
            description=f"Instâncias unhealthy no green: {unhealthy_ids}. Promoção bloqueada.",
            severity=Severity.HIGH,
        )
        return {"status": "error", "reason": f"Green tem instâncias unhealthy: {unhealthy_ids}"}

    token = create_token(
        action_command="deploy promote-execute",
        description=f"Promover slot green para produção ({len(healthy)} instâncias healthy)",
    )
    notify_action_pending(
        agent="DeployAgent",
        token=token,
        proposed_action=f"Redirecionar tráfego HTTPS → slot green ({TG_GREEN})",
        context=f"Slot green: {len(healthy)}/{len(green_health)} instâncias healthy\n"
                f"Esta ação muda o tráfego de produção do blue para o green.",
    )
    return {"status": "pending_approval", "token": token, "green_healthy": len(healthy)}


def execute_promote() -> dict:
    """Executa a promoção após aprovação humana."""
    switch_listener(TG_GREEN)
    notify_action_executed(
        agent="DeployAgent",
        action="Listener HTTPS redirecionado para Target Group green",
        result="Tráfego de produção agora servido pelo slot green.",
    )
    print("[DeployAgent] Promoção green executada")
    return {"status": "executed", "active_slot": "green"}


def rollback() -> dict:
    """Solicita aprovação para rollback para o slot blue (main)."""
    token = create_token(
        action_command="deploy rollback-execute",
        description="Rollback: restaurar tráfego para slot blue e zerar ASG green",
    )
    notify_action_pending(
        agent="DeployAgent",
        token=token,
        proposed_action=f"Rollback: tráfego → slot blue ({TG_MAIN}) + zerar ASG green",
        context="Esta ação faz rollback do tráfego para o slot blue e desliga as instâncias green.",
    )
    return {"status": "pending_approval", "token": token}


def execute_rollback() -> dict:
    """Executa rollback após aprovação humana."""
    switch_listener(TG_MAIN)
    update_asg_size(ASG_GREEN, min_size=0, max_size=4, desired=0)
    notify_action_executed(
        agent="DeployAgent",
        action="Rollback: listener voltou para blue, ASG green zerado",
        result="Tráfego de produção restaurado para o slot blue.",
    )
    print("[DeployAgent] Rollback executado")
    return {"status": "executed", "active_slot": "blue"}
