# Poirot DSPM

Automated detection of sensitive data (PII/PCI) across your data sources — MySQL, Oracle, S3, Kafka, and more.

**Dashboard** | Pattern management | Slack / Email / Teams / Webhook alerts | TheHive integration | AI-powered reports | Built-in docs

---

## Screenshots

| Dashboard | Alerts |
|-----------|--------|
| ![Dashboard](screenshots/Dashboard.jpg) | ![Alerts](screenshots/Alerts.jpg) |

| Scans | Sources |
|-------|---------|
| ![Scans](screenshots/Scans.jpg) | ![Sources](screenshots/Sources.jpg) |

| Cases (TheHive) | Reports |
|-----------------|---------|
| ![Cases](screenshots/Cases.jpg) | ![Reports](screenshots/Reports.jpg) |

| Patterns | Settings |
|----------|----------|
| ![Patterns](screenshots/Patterns.jpg) | ![Settings](screenshots/Settings_1.jpg) |

| Slack Alert | Email Alert |
|-------------|-------------|
| ![Slack](screenshots/Slack.jpg) | ![Email](screenshots/Correo.jpg) |

---

## Quickstart

There are two ways to run Poirot: **connect your own data sources** or **try the demo** with pre-loaded synthetic data.

### Option A — Connect your own data sources

Use this when you already have databases, S3 buckets, or Kafka clusters you want to scan.

```bash
git clone https://github.com/safernandez666/poirot-public.git
cd poirot-public

cp .env.example .env
# Edit .env — add your real data sources (MySQL, Oracle, S3, Kafka)

docker compose up -d
open http://localhost:8080
```

This starts **only Poirot** (scanner + dashboard). You configure your data sources in `.env` or from the UI at `/sources`.

### Option B — Try the demo (no configuration needed)

Use this to explore Poirot with synthetic data. It starts MySQL, S3 (LocalStack), and Kafka (Redpanda) containers pre-loaded with fake PII (credit cards, SSNs, AWS keys, etc.) ready to scan.

```bash
git clone https://github.com/safernandez666/poirot-public.git
cd poirot-public

cp .env.example .env    # works out of the box, no edits needed

docker compose --profile demo up -d
open http://localhost:8080
```

The demo profile adds:

| Service | Description | Port |
|---------|-------------|------|
| **hawk-mysql** | MySQL 8.0 with 4 tables of synthetic PII (customers, payments, users, servers) | 3306 |
| **localstack** | S3-compatible storage with JSON files containing fake credentials and PII | 4566 |
| **redpanda** | Kafka-compatible broker with 3 topics of sensitive messages | 19092 |
| **demo-setup** | Seeds all the above with ~200 records of synthetic data, then exits | — |

Once everything is up, go to the dashboard and run a scan — you'll see alerts for credit cards, SSNs, AWS keys, and more.

> Images are pulled automatically from GitHub Container Registry — no build required.

---

## What gets started

### `docker compose up -d` (core only)

| Container | Image | Description |
|-----------|-------|-------------|
| `poirot-init` | `ghcr.io/safernandez666/poirot-scanner` | Extracts default config files on first run, then exits |
| `hawk-scanner` | `ghcr.io/safernandez666/poirot-scanner` | The scanning engine |
| `hawk-dashboard` | `ghcr.io/safernandez666/poirot-dashboard` | Web UI + API on port **8080** |

### `docker compose --profile demo up -d` (core + demo data)

Everything above, plus MySQL, LocalStack (S3), Redpanda (Kafka), and the demo seeder.

---

## Configuration

All settings live in `.env`. Copy `.env.example` and fill in your values.

### Notification channels

| Channel | Key variables |
|---------|---------------|
| **Slack** | `SLACK_ENABLED`, `SLACK_WEBHOOK_URL` |
| **Email** | `SMTP_ENABLED`, `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TO_ADDRESSES` |
| **Teams** | `TEAMS_ENABLED`, `TEAMS_WEBHOOK_URL` |
| **Webhook** | `WEBHOOK_ENABLED`, `WEBHOOK_URL` |

### Data sources

Data sources are defined in `.env` with the format `SOURCE_{TYPE}_{NAME}={"field":"value",...}`:

```bash
# MySQL
SOURCE_MYSQL_PRODUCTION={"host":"db.internal","port":3306,"user":"scanner","password":"s3cr3t","database":"app_db"}

# Oracle
SOURCE_ORACLE_PROD={"host":"oracle.internal","port":1521,"service_name":"ORCL","user":"scanner","password":"s3cr3t"}

# S3
SOURCE_S3_DATA_LAKE={"access_key":"AKIA...","secret_key":"...","bucket_name":"my-bucket","region":"us-east-1"}

# Kafka
SOURCE_KAFKA_EVENTS={"bootstrap_servers":"kafka:9092","topics":"orders,users","group_id":"poirot-scanner"}
```

Sources can also be added and managed from the dashboard UI at `/sources`.

For full configuration docs including IAM auth (S3, MSK), SASL/SCRAM, and Oracle Thin mode, open `/docs` in the dashboard after starting the stack.

---

## Images

| Image | Registry |
|---|---|
| Scanner | `ghcr.io/safernandez666/poirot-scanner:latest` |
| Dashboard | `ghcr.io/safernandez666/poirot-dashboard:latest` |
