#!/bin/sh
# Reset Poirot DSPM: clears alerts DB, scan history, TheHive cases, and temp files
# Each step is independent — failures don't block the rest.
# Usage: sh scripts/docker-reset.sh

set -e

DB_PATH="${ALERTS_DB_PATH:-hawk-scanner/data/alerts.db}"

# Helper: run SQL via Python's built-in sqlite3 (no sqlite3 CLI needed).
# Runs inside the container to avoid WAL lock when Flask has the DB open.
_sqlite3() {
    _db="$1"; shift
    _sql="$1"
    _py="import sqlite3,sys; c=sqlite3.connect('/app/data/alerts.db'); r=c.execute(sys.argv[1]); print(r.fetchone()[0] if r.description else ''); c.commit(); c.close()"
    if docker ps 2>/dev/null | grep -q hawk-dashboard; then
        docker exec hawk-dashboard python3 -c "$_py" "$_sql"
    elif docker ps 2>/dev/null | grep -q hawk-scanner; then
        docker exec hawk-scanner python3 -c "$_py" "$_sql"
    else
        sqlite3 "$_db" "$_sql"
    fi
}

# Read .env for TheHive config (prefer host-accessible URL)
_read_env() {
    python3 -c "
import sys
key = sys.argv[1]
try:
    with open('.env') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or '=' not in line:
                continue
            k, _, v = line.partition('=')
            if k.strip() == key:
                v = v.strip().strip(\"'\").strip('\"')
                print(v)
                break
except Exception:
    pass
" "$1" 2>/dev/null
}

THEHIVE_ENABLED=$(_read_env THEHIVE_ENABLED)
THEHIVE_API_KEY="${THEHIVE_API_KEY:-$(_read_env THEHIVE_API_KEY)}"
# Use localhost when running from host (not Docker network URL)
THEHIVE_URL="http://localhost:9000"

ALERT_COUNT=0
SCAN_COUNT=0
CASES_DELETED=0

printf '\n'
printf '=========================================\n'
printf '  Poirot DSPM - Full Reset\n'
printf '=========================================\n'
printf '\n'

# ─── 1. Clear SQLite database ────────────────────────────────────────────────
printf '[1/4] Clearing alerts database...\n'

# Detect if DB is accessible: prefer Docker container, fall back to local file
DB_AVAILABLE=false
if docker ps 2>/dev/null | grep -q 'hawk-dashboard\|hawk-scanner'; then
    DB_AVAILABLE=true
elif [ -f "$DB_PATH" ]; then
    DB_AVAILABLE=true
fi

if [ "$DB_AVAILABLE" = true ]; then
    ALERT_COUNT=$(_sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || printf '0')
    SCAN_COUNT=$(_sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM scan_runs;" 2>/dev/null || printf '0')
    SNAPSHOT_COUNT=$(_sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM scan_snapshots;" 2>/dev/null || printf '0')
    printf '  Alerts found: %s\n' "$ALERT_COUNT"
    printf '  Scan runs found: %s\n' "$SCAN_COUNT"
    printf '  Snapshots found: %s\n' "$SNAPSHOT_COUNT"
    _sqlite3 "$DB_PATH" "DELETE FROM alerts;" 2>/dev/null || true
    _sqlite3 "$DB_PATH" "DELETE FROM sqlite_sequence WHERE name='alerts';" 2>/dev/null || true
    _sqlite3 "$DB_PATH" "DELETE FROM scan_runs;" 2>/dev/null || true
    _sqlite3 "$DB_PATH" "DELETE FROM sqlite_sequence WHERE name='scan_runs';" 2>/dev/null || true
    _sqlite3 "$DB_PATH" "DELETE FROM scan_snapshots;" 2>/dev/null || true
    _sqlite3 "$DB_PATH" "DELETE FROM sqlite_sequence WHERE name='scan_snapshots';" 2>/dev/null || true
    printf '  ✅ Database cleared\n'
else
    printf '  ⚠️  No running container found and local DB not found: %s\n' "$DB_PATH"
    printf '      Make sure containers are running: docker compose up -d\n'
fi

printf '\n'

# ─── 2. Clear TheHive cases ──────────────────────────────────────────────────
printf '[2/4] Clearing TheHive cases...\n'

if [ "$THEHIVE_ENABLED" != "true" ]; then
    printf '  ℹ️  TheHive disabled (THEHIVE_ENABLED=%s) — skipping\n' "$THEHIVE_ENABLED"
elif [ -z "$THEHIVE_API_KEY" ]; then
    printf '  ⚠️  No API key configured — skipping\n'
    printf '      Run: sh scripts/thehive-setup.sh\n'
else
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $THEHIVE_API_KEY" \
        "$THEHIVE_URL/api/v1/status" 2>/dev/null || printf '000')

    case "$HTTP_CODE" in
        200)
            printf '  Connected to TheHive (%s)\n' "$THEHIVE_URL"

            CASES_JSON=$(curl -s \
                -H "Authorization: Bearer $THEHIVE_API_KEY" \
                -H "Content-Type: application/json" \
                -d '{"query":[{"_name":"listCase"}]}' \
                "$THEHIVE_URL/api/v1/query" 2>/dev/null)

            export CASES_JSON
            CASE_IDS=$(python3 -c "
import sys, json, os
try:
    cases = json.loads(os.environ.get('CASES_JSON', '[]'))
    if isinstance(cases, list):
        for c in cases:
            if isinstance(c, dict) and '_id' in c:
                print(c['_id'])
except Exception as e:
    sys.stderr.write(f'Error: {e}\n')
" 2>/dev/null)

            CASE_COUNT=0
            if [ -n "$CASE_IDS" ]; then
                CASE_COUNT=$(printf '%s\n' "$CASE_IDS" | grep -c '[^[:space:]]' || printf '0')
            fi

            printf '  Cases found: %s\n' "$CASE_COUNT"

            if [ "$CASE_COUNT" -gt 0 ]; then
                while IFS= read -r CASE_ID; do
                    [ -z "$CASE_ID" ] && continue
                    DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
                        -X DELETE \
                        -H "Authorization: Bearer $THEHIVE_API_KEY" \
                        "$THEHIVE_URL/api/v1/case/$CASE_ID?force=true" 2>/dev/null || printf '000')
                    if [ "$DEL_CODE" = "200" ] || [ "$DEL_CODE" = "204" ]; then
                        CASES_DELETED=$((CASES_DELETED + 1))
                    fi
                done <<EOF
$CASE_IDS
EOF
                printf '  ✅ %s/%s cases deleted\n' "$CASES_DELETED" "$CASE_COUNT"
            else
                printf '  ℹ️  No cases to delete\n'
            fi
            ;;
        401|403)
            printf '  ⚠️  Authentication failed (HTTP %s) — check THEHIVE_API_KEY\n' "$HTTP_CODE"
            printf '      Run: sh scripts/thehive-setup.sh\n'
            ;;
        000)
            printf '  ⚠️  Could not reach TheHive at %s\n' "$THEHIVE_URL"
            printf '      Is TheHive running? Start with: docker compose --profile thehive up -d\n'
            ;;
        *)
            printf '  ⚠️  Unexpected response (HTTP %s) — skipping\n' "$HTTP_CODE"
            ;;
    esac
fi

printf '\n'

# ─── 3. Clear scan JSON temp files ───────────────────────────────────────────
printf '[3/4] Clearing temporary scan files...\n'
if docker ps 2>/dev/null | grep -q hawk-scanner; then
    docker exec hawk-scanner sh -c "rm -f /app/alerts/*.json 2>/dev/null || true" 2>/dev/null || true
    printf '  ✅ Temporary files cleared\n'
else
    printf '  ℹ️  hawk-scanner container not running (optional)\n'
fi

printf '\n'

# ─── 4. Clear thehive_case_id references in DB ───────────────────────────────
printf '[4/4] Clearing TheHive references in DB...\n'
if [ "$DB_AVAILABLE" = true ]; then
    _sqlite3 "$DB_PATH" \
        "UPDATE alerts SET thehive_case_id=NULL, thehive_status=NULL WHERE thehive_case_id IS NOT NULL;" \
        2>/dev/null || true
    printf '  ✅ TheHive references cleared\n'
fi

printf '\n'
printf '=========================================\n'
printf '  ✅ Reset complete\n'
printf '=========================================\n'
printf '\n'
printf 'Summary:\n'
printf '  - Alerts deleted:     %s\n' "$ALERT_COUNT"
printf '  - Scan runs deleted:  %s\n' "$SCAN_COUNT"
printf '  - Snapshots deleted:  %s\n' "${SNAPSHOT_COUNT:-0}"
printf '  - TheHive cases deleted: %s\n' "$CASES_DELETED"
printf '  - Temp files: cleared\n'
printf '\n'
