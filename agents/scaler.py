"""
scaler.py — Gerencia capacidade do ASG principal.
Scale up +1 é automático. Scale down e > +1 exigem aprovação.
"""
from __future__ import annotations

from .approval import create_token
from .notifier import notify_action_executed, notify_action_pending, Severity
from .tools.aws import describe_asg, set_desired_capacity

ASG_MAIN = "security-scanner-asg"
MIN_CAP  = 2
MAX_CAP  = 4


def scale_up(auto: bool = True) -> dict:
    """Aumenta capacidade em +1. Se auto=True, executa sem aprovação."""
    asg = describe_asg(ASG_MAIN)
    current = asg.get("desired", MIN_CAP)

    if current >= MAX_CAP:
        msg = f"ASG já está no máximo ({MAX_CAP} instâncias). Nenhuma ação tomada."
        print(f"[ScalerAgent] {msg}")
        return {"status": "skipped", "reason": msg}

    new_desired = current + 1

    if not auto:
        token = create_token(
            action_command=f"scale {new_desired}",
            description=f"Escalar ASG de {current} → {new_desired} instâncias",
        )
        notify_action_pending(
            agent="ScalerAgent",
            token=token,
            proposed_action=f"Aumentar capacidade: {current} → {new_desired} instâncias ({ASG_MAIN})",
            context=f"Estado atual: Desired={current}, Min={MIN_CAP}, Max={MAX_CAP}\n"
                    f"Ação proposta: aumentar de {current} para {new_desired} instâncias.",
        )
        return {"status": "pending_approval", "token": token, "proposed_desired": new_desired}

    set_desired_capacity(ASG_MAIN, new_desired)
    notify_action_executed(
        agent="ScalerAgent",
        action=f"Scale up: {current} → {new_desired} instâncias",
        result=f"ASG {ASG_MAIN} agora com Desired={new_desired}. Aguarde ~3-5 min para instância ficar InService.",
    )
    print(f"[ScalerAgent] Scale up executado: {current} → {new_desired}")
    return {"status": "executed", "previous": current, "new": new_desired}


def scale_down() -> dict:
    """Reduz capacidade em -1. Sempre exige aprovação."""
    asg = describe_asg(ASG_MAIN)
    current = asg.get("desired", MIN_CAP)

    if current <= MIN_CAP:
        msg = f"ASG já está no mínimo ({MIN_CAP} instâncias). Nenhuma ação tomada."
        print(f"[ScalerAgent] {msg}")
        return {"status": "skipped", "reason": msg}

    new_desired = current - 1
    token = create_token(
        action_command=f"scale {new_desired}",
        description=f"Reduzir ASG de {current} → {new_desired} instâncias",
    )
    notify_action_pending(
        agent="ScalerAgent",
        token=token,
        proposed_action=f"Reduzir capacidade: {current} → {new_desired} instâncias ({ASG_MAIN})",
        context=f"Estado atual: Desired={current}, Min={MIN_CAP}, Max={MAX_CAP}\n"
                f"Ação proposta: reduzir de {current} para {new_desired} instâncias.",
    )
    return {"status": "pending_approval", "token": token, "proposed_desired": new_desired}


def set_capacity(desired: int) -> dict:
    """Define capacidade exata. Sempre exige aprovação."""
    if desired < MIN_CAP or desired > MAX_CAP:
        return {"status": "error", "reason": f"Desired {desired} fora dos limites ({MIN_CAP}-{MAX_CAP})"}

    asg     = describe_asg(ASG_MAIN)
    current = asg.get("desired", MIN_CAP)
    token = create_token(
        action_command=f"scale {desired}",
        description=f"Definir capacidade do ASG para {desired} instâncias",
    )
    notify_action_pending(
        agent="ScalerAgent",
        token=token,
        proposed_action=f"Definir capacidade: {current} → {desired} instâncias ({ASG_MAIN})",
        context=f"Estado atual: Desired={current}\nAção proposta: definir Desired={desired}",
    )
    return {"status": "pending_approval", "token": token, "proposed_desired": desired}


def status() -> dict:
    """Retorna estado atual do ASG sem fazer nenhuma alteração."""
    return describe_asg(ASG_MAIN)
