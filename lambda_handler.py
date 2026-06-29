"""
lambda_handler.py — Entry point AWS Lambda para os agentes de infraestrutura.
Acionado pelo EventBridge a cada 15 minutos (watchdog) e diariamente (drift).
"""
from __future__ import annotations

import json
import os
import sys

# Garante que o pacote agents/ é encontrado no Lambda
sys.path.insert(0, "/var/task")

from agents import watchdog, incident, drift as drift_agent


def handler(event: dict, context) -> dict:
    """
    event["command"]: "watchdog" | "drift"
    EventBridge injeta o command via Input do target.
    """
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
