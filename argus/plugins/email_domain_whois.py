"""Email domain WHOIS lookup plugin."""
import logging
import subprocess
import json
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)


class EmailDomainWhoisPlugin(BasePlugin):
    name = "email_domain_whois"
    target_types = ["email"]
    timeout_seconds = 30

    async def run(self, target: str) -> PluginResult:
        domain = target.split("@")[-1]
        try:
            proc = await asyncio.create_subprocess_exec("whois", domain, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=25)
            import asyncio as aio
            output = stdout.decode("utf-8", errors="replace")
            registrar = ""
            creation_date = ""
            expiry_date = ""
            name_servers = []
            for line in output.splitlines():
                line = line.strip()
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if "registrar" in key and not registrar:
                    registrar = val
                elif "creation" in key or "registered" in key:
                    creation_date = val
                elif "expir" in key or "registry expiry" in key:
                    expiry_date = val
                elif "name server" in key or "nserver" in key:
                    name_servers.append(val)
            return PluginResult(plugin_name=self.name, status="success", data={"domain": domain, "registrar": registrar, "creation_date": creation_date, "expiry_date": expiry_date, "name_servers": name_servers[:10], "raw_length": len(output)})
        except Exception as e:
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))


import asyncio
