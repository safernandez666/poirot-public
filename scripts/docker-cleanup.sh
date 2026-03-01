#!/bin/bash
# =============================================================================
# Poirot - Cleanup Script (sin TheHive)
# =============================================================================
# Este script limpia los contenedores, volúmenes y datos de Poirot
# cuando se usa sin el perfil "thehive".
#
# Uso:
#   ./scripts/docker-cleanup.sh           # Limpieza estándar
#   ./scripts/docker-cleanup.sh --all     # Limpieza completa incluyendo imágenes
# =============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funciones de ayuda
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar si estamos en el directorio correcto
if [ ! -f "docker-compose.yml" ]; then
    log_error "No se encontró docker-compose.yml"
    echo "Ejecuta este script desde el directorio raíz del proyecto"
    exit 1
fi

echo "========================================"
echo "  Poirot - Cleanup Script"
echo "========================================"
echo ""

# Detectar si hay contenedores corriendo
RUNNING_CONTAINERS=$(docker ps -q --filter "name=hawk-" --filter "name=redpanda" --filter "name=kafka-" --filter "name=localstack" 2>/dev/null || true)

if [ -n "$RUNNING_CONTAINERS" ]; then
    log_info "Deteniendo contenedores de Poirot..."
    docker compose down --remove-orphans 2>/dev/null || docker-compose down --remove-orphans 2>/dev/null || true
    log_success "Contenedores detenidos"
else
    log_warn "No hay contenedores de Poirot corriendo"
fi

echo ""
log_info "Limpiando contenedores detenidos..."
docker container prune -f --filter "label=com.docker.compose.project=poirot" 2>/dev/null || true
docker container prune -f --filter "name=hawk-" 2>/dev/null || true
docker container prune -f --filter "name=redpanda" 2>/dev/null || true
log_success "Contenedores limpiados"

echo ""
log_info "Limpiando redes huérfanas..."
docker network prune -f 2>/dev/null || true
log_success "Redes limpiadas"

# Limpiar volúmenes (excepto datos importantes)
echo ""
log_info "Limpiando volúmenes temporales..."

# Lista de volúmenes a preservar (TheHive y otros datos importantes)
PRESERVE_VOLUMES=("cassandra_data" "elasticsearch_data" "thehive_data")

# Obtener todos los volúmenes de compose
COMPOSE_VOLUMES=$(docker compose config --volumes 2>/dev/null || docker-compose config --volumes 2>/dev/null || echo "")

for volume in $COMPOSE_VOLUMES; do
    # Verificar si es un volumen a preservar
    PRESERVE=false
    for pv in "${PRESERVE_VOLUMES[@]}"; do
        if [[ "$volume" == "$pv" ]]; then
            PRESERVE=true
            break
        fi
    done
    
    if [ "$PRESERVE" = true ]; then
        log_warn "Preservando volumen: $volume"
    else
        # Verificar si el volumen existe
        if docker volume inspect "$volume" >/dev/null 2>&1; then
            docker volume rm "$volume" 2>/dev/null || true
            log_success "Volumen eliminado: $volume"
        fi
    fi
done

echo ""
log_info "Limpiando archivos temporales..."

# Limpiar archivos de alertas locales (opcional)
if [ -d "hawk-scanner/data" ]; then
    log_warn "Preservando directorio hawk-scanner/data/"
    # Si quieres borrar los datos de escaneo, descomenta la siguiente línea:
    # rm -f hawk-scanner/data/*.json hawk-scanner/data/*.db 2>/dev/null || true
fi

# Limpiar archivos temporales del sistema
rm -f /tmp/connection_*.yml /tmp/fingerprint_*.yml 2>/dev/null || true
rm -f /tmp/scan_*.json 2>/dev/null || true
log_success "Archivos temporales limpiados"

# Si se pasa --all, también eliminar imágenes
if [ "$1" == "--all" ]; then
    echo ""
    log_info "Eliminando imágenes de Poirot..."
    
    # Imágenes específicas de Poirot
    docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "(hawk|poirot)" | while read image; do
        docker rmi "$image" 2>/dev/null || true
        log_success "Imagen eliminada: $image"
    done
    
    # Imágenes dangling
    docker image prune -f 2>/dev/null || true
    log_success "Imágenes dangling eliminadas"
fi

# Limpiar build cache (opcional)
if [ "$1" == "--all" ]; then
    echo ""
    log_info "Limpiando build cache..."
    docker builder prune -f 2>/dev/null || true
    log_success "Build cache limpiado"
fi

echo ""
echo "========================================"
log_success "Cleanup completado!"
echo "========================================"
echo ""
echo "Para reiniciar Poirot:"
echo "  docker compose up -d"
echo ""
echo "Para reiniciar con perfil demo:"
echo "  docker compose --profile demo up -d"
echo ""

# Mostrar estado actual
echo "Estado de Docker:"
echo "  Contenedores: $(docker ps -q | wc -l | tr -d ' ') corriendo"
echo "  Imágenes: $(docker images -q | wc -l | tr -d ' ') disponibles"
echo "  Volúmenes: $(docker volume ls -q | wc -l | tr -d ' ') existentes"
echo ""
