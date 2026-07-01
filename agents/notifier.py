"""
notifier.py — Notificações por email via AWS SES para os agentes de infraestrutura.
Remetente: alertas@oisolucoes.app.br
Destinatário: charles.rocha@oi.net.br
"""
from __future__ import annotations

import os
from datetime import datetime
from enum import Enum

import boto3

SES_REGION        = os.getenv("SES_REGION", "us-east-1")
SES_FROM          = os.getenv("SES_FROM", "alertas@oisolucoes.app.br")
ALERT_TO          = os.getenv("ALERT_EMAIL", "charles.rocha@oi.net.br")
ENVIRONMENT       = os.getenv("ENVIRONMENT", "security-scanner [us-east-2]")
APPROVAL_BASE_URL = os.getenv("APPROVAL_BASE_URL", "").rstrip("/")


class Severity(str, Enum):
    CRITICAL = "CRÍTICO"
    HIGH     = "ALTO"
    INFO     = "INFO"


SEVERITY_COLOR = {
    Severity.CRITICAL: "#d32f2f",
    Severity.HIGH:     "#f57c00",
    Severity.INFO:     "#1976d2",
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🚨",
    Severity.HIGH:     "⚠️",
    Severity.INFO:     "ℹ️",
}


def send_alert(
    subject: str,
    body: str,
    severity: Severity = Severity.HIGH,
    token: str | None = None,
    proposed_action: str | None = None,
) -> bool:
    """Envia alerta de infraestrutura via AWS SES."""
    emoji   = SEVERITY_EMOJI[severity]
    color   = SEVERITY_COLOR[severity]
    now_brt = datetime.utcnow().strftime("%d/%m/%Y %H:%M") + " BRT"

    approval_section = ""
    if token and proposed_action:
        if APPROVAL_BASE_URL:
            approve_url = f"{APPROVAL_BASE_URL}/approve?token={token}"
            reject_url  = f"{APPROVAL_BASE_URL}/reject?token={token}"
            approval_section = f"""
        <div style="margin-top:24px; padding:20px; background:#fff8e1;
                    border:1px solid #ffe082; border-radius:8px;">
            <p style="margin:0 0 12px; font-weight:bold; color:#e65100; font-size:15px;">
                ⏳ Aprovação necessária
            </p>
            <p style="margin:0 0 8px; font-size:13px; color:#555;">Ação proposta:</p>
            <p style="margin:0 0 20px; font-family:monospace; background:#fff;
                      padding:10px; border-radius:4px; font-size:13px;
                      border-left:3px solid #f57c00;">{proposed_action}</p>
            <table style="border-collapse:separate; border-spacing:12px 0;">
              <tr>
                <td>
                  <a href="{approve_url}"
                     style="display:inline-block; padding:12px 28px; background:#2e7d32;
                            color:#fff; text-decoration:none; border-radius:6px;
                            font-weight:bold; font-size:15px;">
                    ✅ APROVAR
                  </a>
                </td>
                <td>
                  <a href="{reject_url}"
                     style="display:inline-block; padding:12px 28px; background:#c62828;
                            color:#fff; text-decoration:none; border-radius:6px;
                            font-weight:bold; font-size:15px;">
                    ❌ REJEITAR
                  </a>
                </td>
              </tr>
            </table>
            <p style="margin:16px 0 0; font-size:11px; color:#999;">
                Link expira em 24h · uso único · não responda este email
            </p>
        </div>
        """
        else:
            approval_section = f"""
        <div style="margin-top:24px; padding:16px; background:#fff8e1;
                    border:1px solid #ffe082; border-radius:6px;">
            <p style="margin:0 0 8px; font-weight:bold; color:#e65100;">⏳ Aprovação necessária</p>
            <p style="margin:0 0 8px; font-size:13px; color:#555;">Ação proposta:</p>
            <p style="margin:0 0 16px; font-family:monospace; background:#fff;
                      padding:8px; border-radius:4px;">{proposed_action}</p>
            <p style="margin:0 0 4px; font-size:12px; color:#666;">
                APPROVAL_BASE_URL não configurada — aprovação via CLI:
            </p>
            <p style="margin:0; font-family:monospace; background:#263238; color:#80cbc4;
                      padding:8px; border-radius:4px; font-size:12px;">
                Token: {token}
            </p>
        </div>
        """

    html = f"""
    <html>
    <body style="font-family:Arial,sans-serif; max-width:600px; margin:0 auto; padding:20px;">
        <div style="border-left:4px solid {color}; padding-left:16px; margin-bottom:24px;">
            <h2 style="margin:0; color:{color};">{emoji} {severity.value} — {ENVIRONMENT}</h2>
            <p style="margin:4px 0 0; color:#666; font-size:13px;">{now_brt}</p>
        </div>
        <div style="background:#fafafa; border-radius:6px; padding:16px; margin-bottom:16px;">
            <pre style="margin:0; white-space:pre-wrap; font-family:Arial,sans-serif;
                        font-size:14px; color:#333;">{body}</pre>
        </div>
        {approval_section}
        <hr style="border:none; border-top:1px solid #eee; margin:24px 0;">
        <p style="color:#999; font-size:11px; margin:0;">
            Enviado automaticamente pelos agentes de infraestrutura AWS via Amazon SES.
        </p>
    </body>
    </html>
    """

    try:
        client = boto3.client("sesv2", region_name=SES_REGION)
        client.send_email(
            FromEmailAddress=SES_FROM,
            ReplyToAddresses=[ALERT_TO],
            Destination={"ToAddresses": [ALERT_TO]},
            Content={
                "Simple": {
                    "Subject": {"Data": f"{emoji} [{severity.value}] {subject}", "Charset": "UTF-8"},
                    "Body":    {"Html": {"Data": html, "Charset": "UTF-8"}},
                }
            },
        )
        print(f"[NOTIFIER] Alerta enviado para {ALERT_TO}: {subject}")
        return True
    except Exception as exc:
        print(f"[NOTIFIER] Falha ao enviar via SES: {exc}")
        return False


def notify_incident(agent: str, description: str, severity: Severity = Severity.HIGH) -> bool:
    return send_alert(
        subject=f"{agent} detectou anomalia",
        body=description,
        severity=severity,
    )


def notify_action_pending(
    agent: str,
    token: str,
    proposed_action: str,
    context: str,
) -> bool:
    return send_alert(
        subject=f"{agent} aguarda aprovação",
        body=context,
        severity=Severity.HIGH,
        token=token,
        proposed_action=proposed_action,
    )


def notify_action_executed(agent: str, action: str, result: str) -> bool:
    return send_alert(
        subject=f"{agent} executou ação",
        body=f"Ação executada:\n{action}\n\nResultado:\n{result}",
        severity=Severity.INFO,
    )
