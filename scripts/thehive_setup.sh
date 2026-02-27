#!/usr/bin/env bash
# =============================================================================
# thehive_setup.sh — First-time TheHive configuration for Poirot DSPM
#
# Creates an organisation and API user in TheHive, generates an API key,
# and writes THEHIVE_ENABLED + THEHIVE_API_KEY to your .env file.
#
# Usage:
#   docker compose --profile thehive up -d   # start TheHive first
#   chmod +x scripts/thehive_setup.sh
#   ./scripts/thehive_setup.sh
#   docker compose up -d                      # reload dashboard with new key
# =============================================================================
set -euo pipefail

THEHIVE_URL="${THEHIVE_URL:-http://localhost:9000}"
ADMIN_USER="${THEHIVE_ADMIN_USER:-admin@thehive.local}"
ADMIN_PASS="${THEHIVE_ADMIN_PASS:-secret}"
ORG_NAME="${THEHIVE_ORG:-poirot}"
API_USER="${THEHIVE_API_USER:-api@poirot.local}"
ENV_FILE="${ENV_FILE:-.env}"

# ---- helpers ----------------------------------------------------------------

die() { echo "ERROR: $*" >&2; exit 1; }

update_env() {
  local key="$1" value="$2"
  python3 - "$ENV_FILE" "$key" "$value" <<'PY'
import sys, os, re
env_file, key, value = sys.argv[1], sys.argv[2], sys.argv[3]
if not os.path.exists(env_file):
    sys.exit(f"ERROR: {env_file} not found. Run: cp .env.example .env")
with open(env_file, 'r') as f:
    lines = f.readlines()
pattern = re.compile(rf'^{re.escape(key)}\s*=')
found = False
new_lines = []
for line in lines:
    if pattern.match(line):
        new_lines.append(f"{key}={value}
")
        found = True
    else:
        new_lines.append(line)
if not found:
    new_lines.append(f"{key}={value}
")
with open(env_file, 'w') as f:
    f.writelines(new_lines)
PY
}

# ---- wait for TheHive -------------------------------------------------------

echo "==> Waiting for TheHive at $THEHIVE_URL (up to 3 min)..."
for i in $(seq 1 90); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$THEHIVE_URL/api/v1/status" 2>/dev/null || echo "000")
  if [[ "$STATUS" == "200" || "$STATUS" == "401" ]]; then
    echo "    TheHive is up (HTTP $STATUS)"
    break
  fi
  if [[ $i -eq 90 ]]; then
    die "TheHive did not start after 3 minutes. Is it running?
  docker compose --profile thehive up -d"
  fi
  printf "    Waiting... (%ds)" $((i * 2))
  sleep 2
done

# ---- login ------------------------------------------------------------------

echo "==> Logging in as $ADMIN_USER..."
COOKIE_JAR=$(mktemp)
trap 'rm -f "$COOKIE_JAR"' EXIT

LOGIN=$(curl -s -c "$COOKIE_JAR" -X POST "$THEHIVE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"user\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")

echo "$LOGIN" | grep -q "AuthenticationError" && \
  die "Login failed — wrong admin credentials.
Default: admin@thehive.local / secret"

echo "    Login OK"

# ---- create organisation (idempotent) ---------------------------------------

echo "==> Creating organisation '$ORG_NAME'..."
curl -s -b "$COOKIE_JAR" -X POST "$THEHIVE_URL/api/v1/organisation" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$ORG_NAME\",\"description\":\"Poirot DSPM\"}" > /dev/null

# ---- create API user (idempotent) -------------------------------------------

echo "==> Creating API user '$API_USER'..."
curl -s -b "$COOKIE_JAR" -X POST "$THEHIVE_URL/api/v1/user" \
  -H "Content-Type: application/json" \
  -d "{\"login\":\"$API_USER\",\"name\":\"Poirot API\",\"profile\":\"org-admin\",\"organisation\":\"$ORG_NAME\"}" > /dev/null

# ---- generate API key -------------------------------------------------------

echo "==> Generating API key for $API_USER..."
KEY_RESPONSE=$(curl -s -b "$COOKIE_JAR" -X POST \
  "$THEHIVE_URL/api/v1/user/$API_USER/key/renew")

# Response is the key as a plain JSON string: "abc123..."
API_KEY=$(echo "$KEY_RESPONSE" | tr -d '"' | tr -d '
' | tr -d ' ')

[[ -z "$API_KEY" || ${#API_KEY} -lt 10 ]] && \
  die "Could not extract API key from response: $KEY_RESPONSE"

echo "    API key: ${API_KEY:0:8}..."

# ---- write to .env ----------------------------------------------------------

echo "==> Writing to $ENV_FILE..."
update_env "THEHIVE_ENABLED" "true"
update_env "THEHIVE_API_KEY" "$API_KEY"
update_env "THEHIVE_URL" "http://localhost:9000"

echo ""
echo "✅  TheHive configured successfully!"
echo "    Organisation : $ORG_NAME"
echo "    API user     : $API_USER"
echo "    API key      : ${API_KEY:0:8}... (saved to $ENV_FILE)"
echo ""
echo "Restart the dashboard to apply the new key:"
echo "  docker compose up -d"
