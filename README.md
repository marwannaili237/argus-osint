# Argus OSINT — Open Source Intelligence Platform

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11-blue?logo=python&logoColor=white" alt="Python 3.11">
  <img src="https://img.shields.io/badge/FastAPI-0.104-orange?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/aiogram-3.4-blue?logo=telegram&logoColor=white" alt="aiogram 3">
  <img src="https://img.shields.io/badge/SQLAlchemy%202-blue?logo=sqlalchemy&logoColor=white" alt="SQLAlchemy">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT">
</p>

Argus OSINT is a comprehensive open-source intelligence platform that automates target reconnaissance across domains, IPs, emails, usernames, URLs, and more. It features 42 OSINT plugins, a Telegram bot, multi-channel alerting, and an interactive web dashboard.

## Features

- **42 OSINT Plugins** — Email enrichment (FullContact, Hunter, Clearbit, Gravatar, SMTP), social media discovery (Sherlock scanning 30+ sites, Reddit, Twitter, Instagram, Telegram, Discord), network analysis (traceroute, ASN, CDN/WAF, zone transfer, IPv6, DNS monitoring, certificate pinning, banner grabbing), web OSINT (crawler, Wayback Machine archive, broken links, JS analysis, document metadata, connected sites, version fingerprinting), AI analysis (classification, correlation, IOC extraction, threat scoring, NL query parsing, sentiment analysis, report generation)
- **Interactive Dashboard** — D3.js network graph, Leaflet geolocation map, Chart.js analytics, dark/light theme toggle, PDF/CSV export
- **Telegram Bot** — i18n (English, French, Arabic, Spanish), inline queries, progress bars, pagination, autocomplete, custom keyboards
- **10 Notification Channels** — Slack, Discord, Email, TheHive, Mattermost, Microsoft Teams, PagerDuty, Jira, OpenCTI, ELK
- **Security** — RBAC (admin/analyst/viewer/auditor), JWT auth, API key management with rate limiting, TOTP 2FA, Fernet encryption, IP allowlist, PII redaction
- **REST API** — 30+ endpoints with JWT and API key authentication, target CRUD, investigation management, plugin registry, dashboard analytics

## Quick Start

```bash
git clone https://github.com/marwannaili237/argus-osint.git
cd argus-osint
cp .env.example .env  # Configure your API keys
pip install -r requirements.txt
python -m uvicorn argus.main:app --host 0.0.0.0 --port 8000
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/health/ready` | Readiness probe |
| POST | `/targets/` | Create target |
| GET | `/targets/` | List targets |
| POST | `/targets/{id}/scan` | Run all plugins |
| GET | `/plugins/` | List all plugins |
| POST | `/api-keys/` | Generate API key |

## Configuration

Set environment variables or use a `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `BOT_TOKEN` | Telegram bot token | — |
| `SHODAN_API_KEY` | Shodan API key | — |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | — |
| `DATABASE_URL` | Database connection string | sqlite+aiosqlite:///./data/argus.db |
| `SECRET_KEY` | JWT signing key | auto-generated |
| `ENCRYPTION_KEY` | Fernet encryption key | auto-generated |

## License

MIT