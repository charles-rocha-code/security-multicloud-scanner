"""
notifier.py — Notificações por email (Microsoft 365) para os agentes de infraestrutura.
"""
from __future__ import annotations

import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
ALERT_TO  = os.getenv("ALERT_EMAIL", SMTP_USER)

ENVIRONMENT = os.getenv("ENVIRONMENT", "security-scanner [us-east-2]")


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
    action_id: str | None = None,
    proposed_action: str | None = None,
) -> bool:
    """
    Envia alerta de infraestrutura por email Microsoft 365.
    Inclui botão de aprovação se action_id for fornecido.
    """
    if not SMTP_USER or not SMTP_PASS:
        print(f"[NOTIFIER] SMTP não configurado — alerta não enviado: {subject}")
        return False

    emoji   = SEVERITY_EMOJI[severity]
    color   = SEVERITY_COLOR[severity]
    now_brt = datetime.utcnow().strftime("%d/%m/%Y %H:%M") + " BRT"

    approval_section = ""
    if action_id and proposed_action:
        approval_section = f"""
        <div style="margin-top:24px; padding:16px; background:#f5f5f5; border-radius:6px;">
            <p style="margin:0 0 12px; font-weight:bold;">Ação proposta pelo agente:</p>
            <p style="margin:0 0 16px; font-family:monospace; background:#fff;
                      padding:8px; border-radius:4px;">{proposed_action}</p>
            <p style="margin:0; font-size:12px; color:#666;">
                Para aprovar ou rejeitar, responda este email com:<br>
                <strong>APROVAR {action_id}</strong> ou <strong>REJEITAR {action_id}</strong>
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
            Enviado automaticamente pelos agentes de infraestrutura AWS.
        </p>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"{emoji} [{severity.value}] {subject}"
    msg["From"]    = SMTP_FROM
    msg["To"]      = ALERT_TO
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [ALERT_TO], msg.as_string())
        print(f"[NOTIFIER] Alerta enviado para {ALERT_TO}: {subject}")
        return True
    except Exception as exc:
        print(f"[NOTIFIER] Falha ao enviar email: {exc}")
        return False


def notify_incident(agent: str, description: str, severity: Severity = Severity.HIGH) -> bool:
    return send_alert(
        subject=f"{agent} detectou anomalia",
        body=description,
        severity=severity,
    )


def notify_action_pending(
    agent: str,
    action_id: str,
    proposed_action: str,
    context: str,
) -> bool:
    return send_alert(
        subject=f"{agent} aguarda aprovação",
        body=context,
        severity=Severity.HIGH,
        action_id=action_id,
        proposed_action=proposed_action,
    )


def notify_action_executed(agent: str, action: str, result: str) -> bool:
    return send_alert(
        subject=f"{agent} executou ação",
        body=f"Ação executada:\n{action}\n\nResultado:\n{result}",
        severity=Severity.INFO,
    )
