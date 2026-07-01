"""
lambda_handler.py — Entry point AWS Lambda para os agentes de infraestrutura.
Suporta dois tipos de evento:
  - EventBridge (watchdog/drift): campo "command" no evento
  - Lambda Function URL (aprovação): GET /approve?token=... ou /reject?token=...
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, "/var/task")

from agents import watchdog, incident, drift as drift_agent
from agents.approval import validate_and_consume
from agents.notifier import notify_action_executed, notify_incident, Severity


def _html_response(status_code: int, title: str, message: str, color: str = "#1976d2") -> dict:
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><title>{title}</title></head>
<body style="font-family:Arial,sans-serif;max-width:520px;margin:60px auto;padding:24px;">
  <div style="border-left:5px solid {color};padding:16px 24px;background:#fafafa;border-radius:6px;">
    <h2 style="margin:0 0 8px;color:{color};">{title}</h2>
    <p style="margin:0;color:#444;">{message}</p>
  </div>
  <p style="margin-top:24px;font-size:12px;color:#999;">
    security-scanner · agentes de infraestrutura AWS
  </p>
</body>
</html>"""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": html,
    }


def _handle_approval(event: dict) -> dict:
    """Processa cliques nos botões de aprovação/rejeição do email."""
    path  = event.get("rawPath", "") or event.get("requestContext", {}).get("http", {}).get("path", "")
    qs    = event.get("queryStringParameters") or {}
    token = qs.get("token", "").strip()

    if not token:
        return _html_response(400, "❌ Link inválido", "Token ausente ou malformado.", "#c62828")

    if path.startswith("/reject"):
        # Consome o token sem executar a ação
        action = validate_and_consume(token)
        if action is None:
            return _html_response(
                410, "⚠️ Link expirado",
                "Este link já foi utilizado ou expirou (validade: 24h).", "#f57c00"
            )
        notify_incident(
            agent="ApprovalGate",
            description=f"Ação REJEITADA pelo administrador.\nAção cancelada: {action}",
            severity=Severity.INFO,
        )
        return _html_response(200, "✅ Ação rejeitada", f"A ação foi cancelada com sucesso.<br><br><code>{action}</code>", "#2e7d32")

    if path.startswith("/approve"):
        action = validate_and_consume(token)
        if action is None:
            return _html_response(
                410, "⚠️ Link expirado",
                "Este link já foi utilizado ou expirou (validade: 24h).", "#f57c00"
            )

        # Executa a ação via orchestrator
        try:
            from agents.orchestrator import run as orchestrator_run
            parts  = action.split(" ", 1)
            cmd    = parts[0]
            arg    = parts[1] if len(parts) > 1 else ""
            result = orchestrator_run(cmd, arg)

            notify_action_executed(
                agent="ApprovalGate",
                action=action,
                result=json.dumps(result, ensure_ascii=False, default=str),
            )
            return _html_response(
                200,
                "✅ Ação aprovada e executada",
                f"Ação: <code>{action}</code><br><br>"
                f"Resultado: <pre style='background:#f5f5f5;padding:8px;border-radius:4px;'>"
                f"{json.dumps(result, indent=2, ensure_ascii=False, default=str)}</pre>",
                "#2e7d32",
            )
        except Exception as exc:
            print(f"[ApprovalGate] Erro ao executar ação '{action}': {exc}")
            return _html_response(
                500, "❌ Erro ao executar",
                f"A ação foi aprovada mas falhou durante a execução.<br><br>"
                f"<code>{action}</code><br><br>Erro: {exc}", "#c62828"
            )

    return _html_response(400, "❌ Rota desconhecida", f"Caminho não reconhecido: {path}", "#c62828")


def handler(event: dict, context) -> dict:
    """
    Roteamento principal:
      - Evento com 'requestContext.http' → Lambda Function URL (aprovação)
      - Evento com 'command'             → EventBridge (watchdog/drift)
    """
    # Lambda Function URL envia requestContext com http.method
    if event.get("requestContext", {}).get("http"):
        return _handle_approval(event)

    command = event.get("command", "watchdog")
    print(f"[Lambda] Executando: {command}")

    if command == "watchdog":
        result = watchdog.run()
        if result["status"] == "anomaly":
            incident.respond(result["findings"])
        return {"statusCode": 200, "body": json.dumps(result, default=str)}

    if command == "drift":
        result = drift_agent.run()
        return {"statusCode": 200, "body": json.dumps(result, default=str)}

    return {"statusCode": 400, "body": f"Comando desconhecido: {command}"}
