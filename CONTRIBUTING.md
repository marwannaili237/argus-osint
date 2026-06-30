# Contributing to Argus OSINT

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

1. **Fork & Clone** the repository
2. **Install dependencies**: `pip install -r requirements.txt`
3. **Configure**: Copy `.env.example` to `.env` and fill in API keys
4. **Database**: Tables are auto-created on startup via SQLAlchemy

## Project Structure

```
argus-osint/
├── argus/
│   ├── api/          # FastAPI route modules
│   ├── bot/          # Telegram bot (aiogram 3)
│   ├── models/       # SQLAlchemy 2 models
│   ├── notifiers/    # Alert integrations
│   ├── plugins/      # OSINT plugins (42 total)
│   ├── security/     # RBAC, TOTP, encryption
│   └── static/       # Dashboard HTML
├── tests/           # 146 test functions
├── alembic/         # Database migrations
├── helm-chart/      # Kubernetes Helm chart
├── scripts/         # Backup, log rotation
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Creating a New Plugin

1. Create a file in `argus/plugins/` (e.g., `my_plugin.py`)
2. Inherit from `BasePlugin` from `argus.plugins.runner`
3. Set `name`, `target_types`, `timeout_seconds`
4. Implement `async def run(self, target: str) -> PluginResult`
5. Import in `argus/plugins/runner.py` auto-register list

Example:

```python
from argus.plugins.runner import BasePlugin, PluginResult

class MyPlugin(BasePlugin):
    name = "my_plugin"
    target_types = ["domain"]
    timeout_seconds = 15

    async def run(self, target: str) -> PluginResult:
        # Your OSINT logic here
        return PluginResult(
            plugin_name=self.name,
            status="success",
            data={"key": "value"},
        )
```

## Adding a Notifier

1. Create a file in `argus/notifiers/` inheriting `BaseNotifier`
2. Implement `send()` and `test_connection()` methods
3. Register in startup checks

## Code Style

- Python 3.11+ with type hints everywhere
- async/await throughout
- Use `logging.getLogger(__name__)` for logging
- Follow existing patterns in the codebase

## Pull Request Process

1. Create a feature branch
2. Write tests for your changes
3. Ensure all existing tests pass: `pytest tests/`
4. Submit PR with a clear description

## Reporting Issues

Use GitHub Issues with the appropriate labels: `bug`, `enhancement`, `plugin`, `integration`.