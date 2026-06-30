# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2025-06-30

### Added
- **42 OSINT Plugins** across 6 categories:
  - Email (11): FullContact, Hunter, Clearbit, Header Analysis, Gravatar, SMTP, Forwarding, Domain WHOIS, Reputation, Thread, To-Phone
  - Social (6): Sherlock (30+ sites), Telegram, Reddit, Twitter/X, Instagram, Discord
  - Network (8): Traceroute, ASN, CDN/WAF Detection, Zone Transfer, IPv6, DNS Monitor, Cert Pinning, Version Fingerprinting
  - Web OSINT (7): Crawler, Wayback Archive, Broken Links, JS Analyzer, Doc Metadata, Connected Sites, Version Fingerprint
  - AI (7): Classifier, Correlation, IOC Extraction, Threat Scoring, NL Query Parser, Sentiment Analysis, Report Generator
  - Existing (8): DNS History, Website Screenshot, Favicon Hash, IP Geolocation, Honeypot Detector, Darkweb, Security Headers, CAPTCHA Detector, Reverse Image
- **Dashboard** with D3.js network graph, Leaflet geo map, Chart.js charts, dark/light toggle, PDF/CSV export, comparison view
- **10 Notification Integrations**: Slack, Discord, Email, TheHive, Mattermost, Microsoft Teams, PagerDuty, Jira, OpenCTI, ELK/ELK
- **Security Module**: RBAC (4 roles, 10+ permissions), PII Redaction, TOTP 2FA, Fernet Encryption, IP Allowlist
- **Telegram Bot**: i18n (en/fr/ar/es), inline queries, progress display, pagination, autocomplete, custom keyboards
- **API**: 7 router modules with 30+ endpoints, JWT auth, API key management, per-investigation access control
- **Testing**: 146 test functions across 22 test files
- **DevOps**: Dockerfile with HEALTHCHECK, docker-compose with Tor proxy, Helm chart, systemd unit, backup script, log rotation

### Changed
- Plugin system rewritten with BasePlugin ABC, timeout/retry/caching/health tracking
- Database engine configured with connection pooling (pool_pre_ping, pool_recycle, pool_size)
- Startup validation expanded to 12+ config checks
- Graceful shutdown with SIGTERM/SIGINT handling
- CORS, rate limiting, request logging, and IP allowlist middleware

### Security
- RBAC model with admin/analyst/viewer/auditor roles
- JWT authentication with TOTP 2FA support
- API key management with SHA-256 hashing and per-key rate limits
- PII redaction middleware for non-admin users
- Fernet-based evidence encryption