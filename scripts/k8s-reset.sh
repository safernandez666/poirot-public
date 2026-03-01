#!/bin/bash
# =============================================================================
# Poirot DSPM - Kubernetes Reset Script
# =============================================================================
# Limpia alertas y scans del deployment en Kubernetes.
#
# Uso:
#   ./scripts/k8s-reset.sh              # Reset en namespace 'poirot'
#   ./scripts/k8s-reset.sh <namespace>  # Especificar namespace
#
# Requiere:
#   - kubectl configurado y apuntando al cluster correcto
#   - Variable KUBECONFIG seteada (opcional)
#
# Ejemplo:
#   export KUBECONFIG=~/.ssh/cluster-micro.conf
#   ./scripts/k8s-reset.sh
# =============================================================================

set -e

# Configuración
NAMESPACE="${1:-poirot}"
DEPLOYMENT="hawk-scanner"
DB_PATH="/app/data/alerts.db"

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
echo "  Poirot DSPM - Kubernetes Reset"
echo "========================================"
echo "  Namespace: $NAMESPACE"
echo "  Deployment: $DEPLOYMENT"
if [ -n "$KUBECONFIG" ]; then
    echo "  Kubeconfig: $KUBECONFIG"
fi
echo "========================================"
echo ""

# Verificar kubectl
if ! command -v kubectl &> /dev/null; then
    log_error "kubectl no encontrado"
    exit 1
fi

# Verificar conexión al cluster
if ! kubectl cluster-info &> /dev/null; then
    log_error "No se pudo conectar al cluster de Kubernetes"
    log_info "Verificá tu KUBECONFIG:"
    echo "  export KUBECONFIG=~/.ssh/cluster-micro.conf"
    exit 1
fi

# Verificar que el deployment existe
if ! kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" &> /dev/null; then
    log_error "Deployment '$DEPLOYMENT' no encontrado en namespace '$NAMESPACE'"
    log_info "Namespaces disponibles:"
    kubectl get namespaces 2>/dev/null | grep -v "^kube-" | tail -n +2 | head -10
    exit 1
fi

log_success "Conectado a Kubernetes"
echo ""

# Obtener nombre del pod
POD_NAME=$(kubectl get pod -n "$NAMESPACE" -l app=hawk-scanner -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -z "$POD_NAME" ]; then
    log_error "No se encontró un pod para el deployment '$DEPLOYMENT'"
    exit 1
fi

log_info "Pod encontrado: $POD_NAME"
echo ""

# Variables para contar
ALERT_COUNT=0
SCAN_COUNT=0
JSON_FILES=0

# ─── 1. Contar y limpiar base de datos ───────────────────────────────────────
echo "[1/3] Limpiando base de datos de alertas..."

# Verificar si existe la base de datos
if kubectl exec "$POD_NAME" -n "$NAMESPACE" -- test -f "$DB_PATH" 2>/dev/null; then
    # Usar Python (sqlite3 built-in) ya que el contenedor no tiene sqlite3 CLI
    DB_INFO=$(kubectl exec "$POD_NAME" -n "$NAMESPACE" -- \
        python3 -c "
import sqlite3
import sys
try:
    conn = sqlite3.connect('$DB_PATH')
    cur = conn.cursor()
    cur.execute(\"SELECT COUNT(*) FROM alerts\")
    alerts = cur.fetchone()[0]
    cur.execute(\"SELECT COUNT(*) FROM scan_runs\")
    scans = cur.fetchone()[0]
    print(f'{alerts},{scans}')
    conn.close()
except Exception as e:
    print('0,0')
" 2>/dev/null || echo "0,0")
    
    ALERT_COUNT=$(echo "$DB_INFO" | cut -d',' -f1)
    SCAN_COUNT=$(echo "$DB_INFO" | cut -d',' -f2)
    
    echo "  Alertas encontradas: $ALERT_COUNT"
    echo "  Scan runs encontrados: $SCAN_COUNT"
    
    # Limpiar usando Python
    kubectl exec "$POD_NAME" -n "$NAMESPACE" -- \
        python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('$DB_PATH')
    cur = conn.cursor()
    cur.execute('DELETE FROM alerts')
    cur.execute(\"DELETE FROM sqlite_sequence WHERE name='alerts'\")
    cur.execute('DELETE FROM scan_runs')
    cur.execute(\"DELETE FROM sqlite_sequence WHERE name='scan_runs'\")
    cur.execute('UPDATE alerts SET thehive_case_id=NULL, thehive_status=NULL WHERE thehive_case_id IS NOT NULL')
    conn.commit()
    conn.close()
    print('OK')
except Exception as e:
    print(f'Error: {e}')
" 2>/dev/null || true
    
    log_success "Base de datos limpiada"
else
    log_warn "Base de datos no encontrada en $DB_PATH"
fi

echo ""

# ─── 2. Limpiar archivos JSON ────────────────────────────────────────────────
echo "[2/3] Limpiando archivos JSON de scans..."

# Listar archivos antes de borrar
JSON_LIST=$(kubectl exec "$POD_NAME" -n "$NAMESPACE" -- \
    sh -c "ls -1 /app/alerts/*.json 2>/dev/null || echo ''" 2>/dev/null || echo "")

if [ -n "$JSON_LIST" ]; then
    JSON_FILES=$(echo "$JSON_LIST" | grep -c ".json" || echo "0")
    echo "  Archivos encontrados: $JSON_FILES"
    
    # Mostrar algunos archivos
    echo "$JSON_LIST" | head -5 | sed 's/^/    - /'
    if [ "$JSON_FILES" -gt 5 ]; then
        echo "    ... y $((JSON_FILES - 5)) más"
    fi
    
    # Borrar archivos
    kubectl exec "$POD_NAME" -n "$NAMESPACE" -- \
        sh -c "rm -f /app/alerts/*.json 2>/dev/null || true" 2>/dev/null || true
    
    # Borrar también en /tmp
    kubectl exec "$POD_NAME" -n "$NAMESPACE" -- \
        sh -c "rm -f /tmp/*.json /tmp/scan_*.json 2>/dev/null || true" 2>/dev/null || true
    
    log_success "Archivos JSON eliminados"
else
    log_warn "No se encontraron archivos JSON"
fi

echo ""

# ─── 3. Limpiar latest.json y archivos de estado ─────────────────────────────
echo "[3/3] Limpiando archivos de estado..."

kubectl exec "$POD_NAME" -n "$NAMESPACE" -- \
    sh -c "rm -f /app/alerts/latest.json /app/data/latest.json 2>/dev/null || true" 2>/dev/null || true

kubectl exec "$POD_NAME" -n "$NAMESPACE" -- \
    sh -c "rm -f /tmp/connection_*.yml /tmp/fingerprint_*.yml 2>/dev/null || true" 2>/dev/null || true

log_success "Archivos de estado limpiados"

echo ""
echo "========================================"
log_success "Reset completado!"
echo "========================================"
echo ""
echo "Resumen:"
echo "  - Alertas eliminadas:    $ALERT_COUNT"
echo "  - Scan runs eliminados:  $SCAN_COUNT"
echo "  - Archivos JSON:         $JSON_FILES"
echo ""
echo "Para verificar el estado:"
echo "  kubectl get pods -n $NAMESPACE"
echo ""
echo "Para ver los logs:"
echo "  kubectl logs -n $NAMESPACE deployment/$DEPLOYMENT -f"
echo ""
