"""IP allowlist middleware."""
import ipaddress
import logging
from argus.config import settings

logger = logging.getLogger(__name__)


def _parse_allowlist() -> list:
    if not settings.IP_ALLOWLIST:
        return []
    entries = []
    for entry in settings.IP_ALLOWLIST.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                entries.append(ipaddress.ip_network(entry, strict=False))
            else:
                entries.append(ipaddress.ip_address(entry))
        except ValueError:
            logger.warning(f"Invalid IP allowlist entry: {entry}")
    return entries


_allowlist_cache: list | None = None


def check_ip_allowlist(ip: str) -> bool:
    """Check if IP is allowed. Returns True if allowlist is empty (disabled) or IP matches."""
    global _allowlist_cache
    if _allowlist_cache is None:
        _allowlist_cache = _parse_allowlist()
    if not _allowlist_cache:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        for entry in _allowlist_cache:
            if isinstance(entry, ipaddress.ip_network):
                if addr in entry:
                    return True
            elif addr == entry:
                return True
        return False
    except ValueError:
        logger.warning(f"Invalid IP to check: {ip}")
        return False


def reset_allowlist_cache():
    global _allowlist_cache
    _allowlist_cache = None
