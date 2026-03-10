#!/bin/bash
# =============================================================================
# Poirot DSPM - Docker Reset Script (Compose)
# =============================================================================
# Limpia alertas y scans usando docker compose exec.
#
# Uso:
#   ./scripts/reset-docker.sh
# =============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "========================================"
echo "  Poirot DSPM - Docker Reset"
echo "========================================"
echo ""

# Verificar si docker compose está disponible
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
else
    log_error "docker compose no encontrado"
    exit 1
fi

log_info "Usando: $COMPOSE_CMD"
echo ""

# Verificar si el compose está corriendo
if ! $COMPOSE_CMD ps | grep -qE "(scanner|api)"; then
    log_error "No hay servicios de Poirot corriendo"
    log_info "Iniciá el compose primero: $COMPOSE_CMD up -d"
    exit 1
fi

# Obtener nombre del servicio scanner
SCANNER_SERVICE=$($COMPOSE_CMD ps --services | grep -E "(scanner|api)" | head -1)
log_info "Servicio encontrado: $SCANNER_SERVICE"
echo ""

# ─── 1. Contar y limpiar alertas ────────────────────────────────────────────
echo "[1/3] Limpiando base de datos de alertas..."

# Verificar si existe la base de datos
DB_EXISTS=$($COMPOSE_CMD exec -T "$SCANNER_SERVICE" test -f /app/data/alerts.db && echo "yes" || echo "no" 2>/dev/null || echo "no")

if [ "$DB_EXISTS" = "yes" ]; then
    # Contar usando Python (más confiable que sqlite3 CLI)
    COUNTS=$($COMPOSE_CMD exec -T "$SCANNER_SERVICE" python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('/app/data/alerts.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM alerts')
    alerts = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM scan_runs')
    scans = c.fetchone()[0]
    print(f'{alerts},{scans}')
    conn.close()
except:
    print('0,0')
" 2>/dev/null || echo "0,0")
    
    ALERT_COUNT=$(echo "$COUNTS" | cut -d',' -f1)
    SCAN_COUNT=$(echo "$COUNTS" | cut -d',' -f2)
    
    echo "  Alertas encontradas: $ALERT_COUNT"
    echo "  Scan runs encontrados: $SCAN_COUNT"
    
    # Limpiar usando Python
    $COMPOSE_CMD exec -T "$SCANNER_SERVICE" python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('/app/data/alerts.db')
    c = conn.cursor()
    c.execute('DELETE FROM alerts')
    c.execute(\"DELETE FROM sqlite_sequence WHERE name='alerts'\")
    c.execute('DELETE FROM scan_runs')
    c.execute(\"DELETE FROM sqlite_sequence WHERE name='scan_runs'\")
    conn.commit()
    conn.close()
    print('OK')
except Exception as e:
    print(f'Error: {e}')
" 2>/dev/null || log_warn "No se pudo limpiar con Python"
    
    log_success "Base de datos limpiada"
else
    log_warn "Base de datos no encontrada o servicio no responde"
fi

echo ""

# ─── 2. Limpiar archivos JSON ────────────────────────────────────────────────
echo "[2/3] Limpiando archivos JSON de scans..."

$COMPOSE_CMD exec -T "$SCANNER_SERVICE" sh -c "
    rm -f /app/alerts/*.json /app/alerts/latest.json 2>/dev/null || true
    rm -f /app/data/*.json 2>/dev/null || true
    rm -f /tmp/*.json /tmp/scan_*.json 2>/dev/null || true
" 2>/dev/null || log_warn "No se pudieron eliminar algunos archivos"

log_success "Archivos JSON eliminados"

echo ""

# ─── 3. Limpiar archivos temporales ──────────────────────────────────────────
echo "[3/3] Limpiando archivos temporales..."

$COMPOSE_CMD exec -T "$SCANNER_SERVICE" sh -c "
    rm -f /tmp/connection_*.yml /tmp/fingerprint_*.yml 2>/dev/null || true
    rm -f /tmp/result*.json 2>/dev/null || true
" 2>/dev/null || true

log_success "Archivos temporales limpiados"

echo ""
echo "========================================"
log_success "Reset completado!"
echo "========================================"
echo ""
echo "Para verificar los servicios:"
echo "  $COMPOSE_CMD ps"
echo ""
