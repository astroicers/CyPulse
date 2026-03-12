from __future__ import annotations
import os
import smtplib
from abc import ABC, abstractmethod
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import structlog
import requests

logger = structlog.get_logger()


class Notifier(ABC):
    @abstractmethod
    def send(self, message: str, severity: str = "info") -> bool:
        ...


class SlackNotifier(Notifier):
    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")

    def send(self, message: str, severity: str = "info") -> bool:
        if not self.webhook_url:
            logger.warning("slack_no_webhook")
            return False
        emoji = {"critical": ":red_circle:", "high": ":orange_circle:", "info": ":blue_circle:"}.get(severity, ":white_circle:")
        try:
            resp = requests.post(
                self.webhook_url,
                json={"text": f"{emoji} *[CyPulse]* {message}"},
                timeout=10,
            )
            return resp.status_code == 200
        except Exception as e:
            logger.error("slack_send_failed", error=str(e))
            return False


class EmailNotifier(Notifier):
    def __init__(self):
        self.smtp_host = os.environ.get("EMAIL_SMTP_HOST", "")
        self.smtp_port = int(os.environ.get("EMAIL_SMTP_PORT", "587"))
        self.smtp_user = os.environ.get("EMAIL_SMTP_USER", "")
        self.smtp_pass = os.environ.get("EMAIL_SMTP_PASS", "")
        self.from_addr = os.environ.get("EMAIL_FROM", "")
        self.to_addrs = [a.strip() for a in os.environ.get("EMAIL_TO", "").split(",") if a.strip()]

    def send(self, message: str, severity: str = "info") -> bool:
        if not all([self.smtp_host, self.from_addr, self.to_addrs]):
            logger.warning("email_not_configured")
            return False
        try:
            msg = MIMEMultipart()
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_addrs)
            msg["Subject"] = f"[CyPulse] {severity.upper()} Alert"
            msg.attach(MIMEText(message, "plain", "utf-8"))
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                if self.smtp_user:
                    server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            return True
        except Exception as e:
            logger.error("email_send_failed", error=str(e))
            return False


class LineNotifier(Notifier):
    def __init__(self, token: str | None = None):
        self.token = token or os.environ.get("LINE_NOTIFY_TOKEN", "")

    def send(self, message: str, severity: str = "info") -> bool:
        if not self.token:
            logger.warning("line_no_token")
            return False
        try:
            resp = requests.post(
                "https://notify-api.line.me/api/notify",
                headers={"Authorization": f"Bearer {self.token}"},
                data={"message": f"\n[CyPulse] {message}"},
                timeout=10,
            )
            return resp.status_code == 200
        except Exception as e:
            logger.error("line_send_failed", error=str(e))
            return False


def send_alerts(alerts: list[str], config: dict) -> None:
    """Send alerts via all configured channels."""
    notifiers: list[Notifier] = []
    if os.environ.get("SLACK_WEBHOOK_URL"):
        notifiers.append(SlackNotifier())
    if os.environ.get("EMAIL_SMTP_HOST"):
        notifiers.append(EmailNotifier())
    if os.environ.get("LINE_NOTIFY_TOKEN"):
        notifiers.append(LineNotifier())

    for alert in alerts:
        severity = "high" if "critical" in alert.lower() or "high" in alert.lower() else "info"
        for notifier in notifiers:
            notifier.send(alert, severity)
