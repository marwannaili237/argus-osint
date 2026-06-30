"""Progress display utilities for bot."""


def create_progress_bar(current: int, total: int, width: int = 10) -> str:
    if total == 0:
        return "[----------] 0%"
    ratio = min(current / max(total, 1), 1.0)
    filled = int(width * ratio)
    bar = "[" + "#" * filled + "-" * (width - filled) + "]"
    return f"{bar} {int(ratio * 100)}%"


def get_threat_emoji(level: str) -> str:
    mapping = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM", "low": "🟢 LOW", "info": "🔵 INFO"}
    return mapping.get(level.lower(), "⚪ UNKNOWN")


def format_plugin_status(status: str) -> str:
    mapping = {"success": "✅", "error": "❌", "timeout": "⏰", "cached": "💾"}
    return mapping.get(status, "❓")


def format_scan_summary(results: list) -> str:
    if not results:
        return "No results."
    success = sum(1 for r in results if r.get("status") == "success")
    error = sum(1 for r in results if r.get("status") == "error")
    timeout = sum(1 for r in results if r.get("status") == "timeout")
    cached = sum(1 for r in results if r.get("status") == "cached")
    lines = [f"Total: {len(results)} | ✅ {success} ❌ {error} ⏰ {timeout} 💾 {cached}"]
    for r in results:
        icon = format_plugin_status(r.get("status", ""))
        t_sec = r.get("execution_time", 0)
        name = r.get("plugin_name", "unknown")
        lines.append(f"  {icon} {name} ({t_sec:.2f}s)")
    return "\n".join(lines)
