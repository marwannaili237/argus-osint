"""Email notifier using aiosmtplib."""
import logging
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from argus.config import settings
from argus.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class EmailNotifier(BaseNotifier):
    name = "email"

    def __init__(self):
        self.enabled = bool(settings.SMTP_HOST and settings.SMTP_USER)

    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        if not self.enabled:
            return False
        recipients = kwargs.get("recipients", [settings.SMTP_USER])
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Argus OSINT] {title}"
        msg["From"] = settings.SMTP_USER
        msg["To"] = ", ".join(recipients)
        html = f"""<html><body style="font-family: Arial, sans-serif;"><div style="padding: 20px; background: #f5f5f5; border-radius: 8px;"><h2 style="color: #333;">{title}</h2><p style="color: #555;">{message}</p><p style="color: #999; font-size: 12px;">Severity: {severity}</p></div></body></html>"""
        msg.attach(MIMEText(html, "html"))
        try:
            await aiosmtplib.send(msg, hostname=settings.SMTP_HOST, port=settings.SMTP_PORT, username=settings.SMTP_USER, password=settings.SMTP_PASSWORD, use_tls=True)
            return True
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return False

    async def test_connection(self) -> bool:
        return await self.send("Test", "Argus OSINT test notification", "info")
