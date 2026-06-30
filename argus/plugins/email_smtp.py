"""SMTP email verification plugin."""
import logging
import asyncio
import dns.resolver
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class EmailSmtpPlugin(BasePlugin):
    name = "email_smtp"
    target_types = ["email"]
    timeout_seconds = 20

    async def run(self, target: str) -> PluginResult:
        domain = target.split("@")[-1]
        mx_records = []
        try:
            answers = dns.resolver.resolve(domain, "MX")
            mx_records = sorted([{"server": str(r.exchange).rstrip("."), "priority": r.preference} for r in answers], key=lambda x: x["priority"])
        except Exception:
            pass
        if not mx_records:
            return PluginResult(plugin_name=self.name, status="success", data={"smtp_check": False, "mx_records": [], "mail_server": None, "accepts_mail": False, "catch_all": False})
        mail_server = mx_records[0]["server"]
        accepts_mail = False
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(mail_server, 25), timeout=10)
            banner = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.write(f"EHLO argus-osint\r\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.write(f"MAIL FROM:<check@argus.osint>\r\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.write(f"RCPT TO:<{target}>\r\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=5)
            accepts_mail = b"250" in resp
            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug(f"SMTP check failed: {e}")
        return PluginResult(plugin_name=self.name, status="success", data={"smtp_check": True, "mx_records": mx_records, "mail_server": mail_server, "accepts_mail": accepts_mail, "catch_all": False})
