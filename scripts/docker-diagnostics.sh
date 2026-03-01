#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Poirot DSPM — Diagnostics collector
# Usage:  bash scripts/docker-diagnostics.sh
# Output: poirot-diagnostics-<timestamp>.log
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

TS=$(date +%Y%m%d_%H%M%S)
OUT="poirot-diagnostics-${TS}.log"

section() { printf '\n%s\n%s\n' "=== $1 ===" "$(date -Iseconds)" >> "$OUT"; }

echo "Collecting diagnostics → $OUT"

# ── 1. Environment ──────────────────────────────────────────────────────────
section "Host info"
{ uname -a; docker --version; docker compose version; } >> "$OUT" 2>&1

# ── 2. Container status ────────────────────────────────────────────────────
section "Container status"
docker compose ps -a >> "$OUT" 2>&1

section "Container resource usage"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" \
  $(docker compose ps -q 2>/dev/null) >> "$OUT" 2>&1 || true

# ── 3. Container logs (last 200 lines each) ────────────────────────────────
for svc in hawk-scanner hawk-dashboard; do
  section "Logs: $svc (last 200 lines)"
  docker logs "$svc" --tail 200 >> "$OUT" 2>&1 || echo "  container not found" >> "$OUT"
done

# ── 4. API health & scanner status ─────────────────────────────────────────
section "API health"
curl -sf http://localhost:8080/api/health >> "$OUT" 2>&1 || echo "  unreachable" >> "$OUT"

section "Scanner status"
curl -sf http://localhost:8080/api/scanner/status | python3 -m json.tool >> "$OUT" 2>&1 || echo "  unreachable" >> "$OUT"

# ── 5. Configured sources (passwords redacted) ─────────────────────────────
section "Configured sources"
SOURCES_JSON=$(curl -sf http://localhost:8080/api/config/sources 2>/dev/null || true)
if [ -n "$SOURCES_JSON" ]; then
  echo "$SOURCES_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for s in data.get('sources', []):
    cfg = s.get('config', {})
    for k in ('password', 'secret_key', 'api_key', 'refresh_token', 'client_secret'):
        if k in cfg:
            cfg[k] = '***REDACTED***'
print(json.dumps(data, indent=2))
" >> "$OUT" 2>&1
else
  echo "  API unreachable" >> "$OUT"
fi

# ── 6. Source connectivity test ─────────────────────────────────────────────
section "Source connectivity"
if [ -n "$SOURCES_JSON" ]; then
  echo "$SOURCES_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for s in data.get('sources', []):
    host = s['config'].get('host', s['config'].get('endpoint_url', 'N/A'))
    port = s['config'].get('port', '')
    print(f'  {s[\"type\"]}/{s[\"name\"]}  →  {host}:{port}')
" >> "$OUT" 2>&1

  # Test TCP connectivity from scanner container
  for src in $(echo "$SOURCES_JSON" | python3 -c "
import sys, json
for s in json.load(sys.stdin).get('sources', []):
    h = s['config'].get('host',''); p = s['config'].get('port','')
    if h and p: print(f'{h}:{p}')
" 2>/dev/null); do
    host="${src%%:*}"; port="${src##*:}"
    printf "  TCP %s:%s → " "$host" "$port" >> "$OUT"
    docker exec hawk-scanner bash -c "timeout 3 bash -c '</dev/tcp/$host/$port' 2>/dev/null && echo OK || echo FAIL" \
      >> "$OUT" 2>&1 || echo "FAIL (container not running)" >> "$OUT"
  done
else
  echo "  API unreachable — skipping connectivity tests" >> "$OUT"
fi

# ── 7. Recent scan results ─────────────────────────────────────────────────
section "Recent scans (last 5)"
HISTORY_JSON=$(curl -sf http://localhost:8080/api/scanner/history 2>/dev/null || true)
if [ -n "$HISTORY_JSON" ]; then
  echo "$HISTORY_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for s in data.get('scans', [])[:5]:
    print(f'  {s.get(\"scan_id\",\"?\"):30s}  status={s.get(\"status\",\"?\"):10s}  findings={s.get(\"total_findings\",\"?\")}')
" >> "$OUT" 2>&1
else
  echo "  API unreachable" >> "$OUT"
fi

# ── 8. Scan result files in scanner container ───────────────────────────────
section "Scanner alert files"
docker exec hawk-scanner ls -lhtr /app/alerts/ >> "$OUT" 2>&1 || echo "  container not running" >> "$OUT"

# ── 9. connection.yml (passwords redacted) ──────────────────────────────────
section "connection.yml (redacted)"
docker exec hawk-scanner python3 -c "
import yaml, sys
with open('/app/connection.yml') as f:
    cfg = yaml.safe_load(f)
def redact(d):
    if isinstance(d, dict):
        return {k: ('***REDACTED***' if k in ('password','secret_key','api_key','refresh_token','client_secret','webhook_url') else redact(v)) for k, v in d.items()}
    if isinstance(d, list):
        return [redact(i) for i in d]
    return d
yaml.dump(redact(cfg), sys.stdout, default_flow_style=False)
" >> "$OUT" 2>&1 || echo "  container not running" >> "$OUT"

# ── 10. Docker network ─────────────────────────────────────────────────────
section "Docker network"
docker network inspect poirot_hawk-network --format '{{range .Containers}}  {{.Name}} → {{.IPv4Address}}{{"\n"}}{{end}}' \
  >> "$OUT" 2>&1 || echo "  network not found" >> "$OUT"

# ── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "Done. File: $OUT ($(wc -l < "$OUT") lines)"
echo "Share this file for troubleshooting — passwords are redacted."
