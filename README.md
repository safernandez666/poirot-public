# Poirot DSPM

Automated detection of sensitive data (PII/PCI) across your data sources — MySQL, S3, Kafka, and more.

**Dashboard** | Pattern management | Slack / Email / Teams / Webhook alerts | TheHive integration | AI-powered reports

---

## Quickstart

```bash
# 1. Clone this repo
git clone https://github.com/safernandez666/poirot-public.git
cd poirot-public

# 2. Configure your environment
cp .env.example .env
# Edit .env with your credentials and data sources

# 3. Start
docker compose up -d

# 4. Open
open http://localhost:8080
```

> Images are pulled automatically from GitHub Container Registry — no build required.

---

## Optional profiles

```bash
# Add TheHive case management
docker compose --profile thehive up -d

# Add local AI for reports (Ollama)
docker compose --profile ollama up -d
```

---

## Configuration

All settings live in `.env`. Copy `.env.example` and fill in your values:

| Section | Variables |
|---|---|
| **Slack** | `SLACK_ENABLED`, `SLACK_WEBHOOK_URL` |
| **Email** | `SMTP_ENABLED`, `SMTP_HOST`, `SMTP_USERNAME`, ... |
| **Teams** | `TEAMS_ENABLED`, `TEAMS_WEBHOOK_URL` |
| **Webhook** | `WEBHOOK_ENABLED`, `WEBHOOK_URL` |
| **TheHive** | `THEHIVE_ENABLED`, `THEHIVE_URL`, `THEHIVE_API_KEY` |
| **Ollama AI** | `OLLAMA_ENABLED`, `OLLAMA_URL`, `OLLAMA_MODEL` |
| **Data sources** | `SOURCE_MYSQL_NAME={"host":"..."}`, `SOURCE_S3_NAME={"bucket":"..."}` |

Data sources can also be added and managed from the dashboard UI at `http://localhost:8080/sources`.

---

## Images

| Image | Registry |
|---|---|
| Scanner | `ghcr.io/safernandez666/poirot-scanner:latest` |
| Dashboard | `ghcr.io/safernandez666/poirot-dashboard:latest` |
