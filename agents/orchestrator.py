"""
orchestrator.py — Ponto de entrada único para todos os agentes de infraestrutura.
Uso: python -m agents.orchestrator [watchdog|incident|scale|deploy|waf|drift]
"""
from __future__ import annotations

import sys


def run(command: str = "watchdog", arg: str = "") -> dict:
    command = command.lower().strip()

    if command == "watchdog":
        from . import watchdog, incident
        result = watchdog.run()
        if result["status"] == "anomaly":
            incident.respond(result["findings"])
        return result

    if command == "incident":
        from . import incident
        return incident.diagnose()

    if command == "scale":
        from . import scaler
        if arg == "up":
            return scaler.scale_up(auto=False)
        if arg == "down":
            return scaler.scale_down()
        if arg.isdigit():
            return scaler.set_capacity(int(arg))
        return scaler.status()

    if command == "deploy":
        from . import deploy
        if arg == "promote":
            return deploy.promote()
        if arg == "rollback":
            return deploy.rollback()
        if arg == "promote-execute":
            return deploy.execute_promote()
        if arg == "rollback-execute":
            return deploy.execute_rollback()
        return deploy.status()

    if command == "waf":
        from . import waf_agent
        if arg.startswith("block "):
            return waf_agent.block_ip(arg.split(" ", 1)[1], reason="Manual via orchestrator")
        if arg.startswith("unblock-execute "):
            return waf_agent.execute_unblock(arg.split(" ", 1)[1])
        if arg.startswith("unblock "):
            return waf_agent.unblock_ip(arg.split(" ", 1)[1])
        if arg == "scan":
            return waf_agent.scan_logs_for_attacks()
        return waf_agent.status()

    if command == "drift":
        from . import drift
        return drift.run()

    return {"error": f"Comando desconhecido: {command}"}


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "watchdog"
    arg = sys.argv[2] if len(sys.argv) > 2 else ""
    import json, sys as _sys
    result = run(cmd, arg)
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
