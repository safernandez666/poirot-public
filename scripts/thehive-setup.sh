#!/bin/sh
# =============================================================================
# thehive-setup.sh
# Configura TheHive 5: crea organización + usuario de servicio con rol analyst,
# genera una API key y la escribe en .env.
#
# Uso:
#   sh scripts/thehive-setup.sh
#   sh scripts/thehive-setup.sh --url http://localhost:9000 --admin-pass secret
# =============================================================================

# ── Defaults ──────────────────────────────────────────────────────────────────
THEHIVE_URL="http://localhost:9000"
ADMIN_USER="admin@thehive.local"
ADMIN_PASS="secret"
ORG_NAME="poirot"
ORG_DESC="Poirot DSPM"
SERVICE_LOGIN="api@poirot.local"
SERVICE_NAME="Poirot API"
SERVICE_PROFILE="analyst"    # analyst | org-admin
ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/.env"

# ── Argument parsing ───────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case $1 in
    --url)         THEHIVE_URL="$2";  shift 2 ;;
    --admin-user)  ADMIN_USER="$2";   shift 2 ;;
    --admin-pass)  ADMIN_PASS="$2";   shift 2 ;;
    --org)         ORG_NAME="$2";     shift 2 ;;
    --service-login) SERVICE_LOGIN="$2"; shift 2 ;;
    --profile)     SERVICE_PROFILE="$2"; shift 2 ;;
    --no-write)    NO_WRITE=true;     shift   ;;
    -h|--help)
      printf "Uso: %s [opciones]\n" "$0"
      printf "  --url URL           TheHive URL (default: http://localhost:9000)\n"
      printf "  --admin-user USER   Admin login (default: admin@thehive.local)\n"
      printf "  --admin-pass PASS   Admin password (default: secret)\n"
      printf "  --org NAME          Nombre de la organización (default: poirot)\n"
      printf "  --service-login EMAIL Login del usuario de servicio (default: api@poirot.local)\n"
      printf "  --profile ROLE      Rol en la org: analyst|org-admin (default: analyst)\n"
      printf "  --no-write          No actualiza .env, solo imprime la API key\n"
      exit 0
      ;;
    *) printf "Opción desconocida: %s\n" "$1" >&2; exit 1 ;;
  esac
done

# ── Helpers ────────────────────────────────────────────────────────────────────
info() { printf "  [•] %s\n" "$*"; }
ok()   { printf "  [✓] %s\n" "$*"; }
warn() { printf "  [!] %s\n" "$*"; }
die()  { printf "\n  [✗] %s\n" "$*" >&2; exit 1; }

url_encode() {
  python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=''))"
}

# Ejecuta un llamado a la API de TheHive como superadmin.
# Deja el resultado en RESP_BODY y el HTTP code en RESP_CODE.
api() {
  _method="$1"; _path="$2"; _body="${3:-}"
  if [ -n "$_body" ]; then
    _raw=$(curl -s -w "\n%{http_code}" \
      -X "$_method" \
      -u "$ADMIN_USER:$ADMIN_PASS" \
      -H "Content-Type: application/json" \
      -d "$_body" \
      --connect-timeout 5 \
      "$THEHIVE_URL$_path" 2>/dev/null) || true
  else
    _raw=$(curl -s -w "\n%{http_code}" \
      -X "$_method" \
      -u "$ADMIN_USER:$ADMIN_PASS" \
      --connect-timeout 5 \
      "$THEHIVE_URL$_path" 2>/dev/null) || true
  fi
  RESP_BODY=$(printf '%s' "$_raw" | sed '$d')
  RESP_CODE=$(printf '%s' "$_raw" | tail -n1)
}

# Extrae un campo de un JSON simple {"campo":"valor"}
json_get() {
  python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('$1',''))" 2>/dev/null || true
}

printf "\n"
printf "════════════════════════════════════════════\n"
printf "  TheHive Setup — Poirot DSPM\n"
printf "════════════════════════════════════════════\n\n"
info "URL        : $THEHIVE_URL"
info "Admin      : $ADMIN_USER"
info "Org        : $ORG_NAME"
info "Service    : $SERVICE_LOGIN  (role: $SERVICE_PROFILE)"
printf "\n"

# ── 1. Conectividad ────────────────────────────────────────────────────────────
printf "── Paso 1: Verificar conectividad ──────────\n"
api GET "/api/v1/status"
if [ "$RESP_CODE" != "200" ] && [ "$RESP_CODE" != "401" ]; then
  die "TheHive no está disponible en $THEHIVE_URL (HTTP $RESP_CODE). ¿Está corriendo el contenedor?"
fi
ok "TheHive accesible (HTTP $RESP_CODE)"

# Verificar credenciales de admin
api GET "/api/v1/user/current"
if [ "$RESP_CODE" = "401" ]; then
  die "Credenciales de admin incorrectas. Usa --admin-pass para especificar la contraseña."
fi
ok "Autenticación admin correcta"
printf "\n"

# ── 2. Crear organización ──────────────────────────────────────────────────────
printf "── Paso 2: Organización '$ORG_NAME' ─────────\n"
api GET "/api/v1/organisation/$ORG_NAME"
if [ "$RESP_CODE" = "200" ]; then
  ok "Organización '$ORG_NAME' ya existe — se reutiliza"
elif [ "$RESP_CODE" = "404" ] || [ "$RESP_CODE" = "400" ]; then
  info "Creando organización '$ORG_NAME'..."
  api POST "/api/v1/organisation" \
    "{\"name\":\"$ORG_NAME\",\"description\":\"$ORG_DESC\",\"taskRule\":\"all\",\"observableRule\":\"all\"}"
  if [ "$RESP_CODE" = "201" ] || [ "$RESP_CODE" = "200" ]; then
    ok "Organización '$ORG_NAME' creada"
  else
    die "No se pudo crear la organización (HTTP $RESP_CODE): $RESP_BODY"
  fi
else
  die "Error verificando organización (HTTP $RESP_CODE): $RESP_BODY"
fi
printf "\n"

# ── 3. Crear usuario de servicio ───────────────────────────────────────────────
printf "── Paso 3: Usuario de servicio '$SERVICE_LOGIN' ──\n"
ENCODED_LOGIN=$(printf '%s' "$SERVICE_LOGIN" | url_encode)

api GET "/api/v1/user/$ENCODED_LOGIN"
if [ "$RESP_CODE" = "200" ]; then
  ok "Usuario '$SERVICE_LOGIN' ya existe"

  # Verificar que pertenece a la org correcta y tiene el rol correcto
  USER_ORG=$(printf '%s' "$RESP_BODY" | python3 -c "
import sys,json
d=json.loads(sys.stdin.read())
# can be 'organisation' or inside 'organisations' list
print(d.get('organisation','') or (d.get('organisations') or [{}])[0].get('name',''))
" 2>/dev/null || true)

  if [ "$USER_ORG" != "$ORG_NAME" ]; then
    info "Usuario existe en org '$USER_ORG', agregando a '$ORG_NAME' con rol $SERVICE_PROFILE..."
    api PUT "/api/v1/organisation/$ORG_NAME/user" \
      "{\"login\":\"$SERVICE_LOGIN\",\"profile\":\"$SERVICE_PROFILE\"}"
    if [ "$RESP_CODE" = "200" ] || [ "$RESP_CODE" = "201" ]; then
      ok "Usuario agregado a '$ORG_NAME' con rol $SERVICE_PROFILE"
    else
      warn "No se pudo agregar usuario a org (HTTP $RESP_CODE): $RESP_BODY"
    fi
  else
    ok "Usuario ya está en la organización '$ORG_NAME'"
  fi
else
  # Crear el usuario nuevo
  info "Creando usuario '$SERVICE_LOGIN' en org '$ORG_NAME' con rol $SERVICE_PROFILE..."
  CREATE_BODY=$(python3 -c "
import json
print(json.dumps({
  'login': '$SERVICE_LOGIN',
  'name':  '$SERVICE_NAME',
  'profile': '$SERVICE_PROFILE',
  'organisation': '$ORG_NAME'
}))
")
  api POST "/api/v1/user" "$CREATE_BODY"
  if [ "$RESP_CODE" = "201" ] || [ "$RESP_CODE" = "200" ]; then
    ok "Usuario '$SERVICE_LOGIN' creado con rol $SERVICE_PROFILE en org '$ORG_NAME'"
  else
    die "No se pudo crear el usuario (HTTP $RESP_CODE): $RESP_BODY"
  fi
fi
printf "\n"

# ── 4. Generar API key ─────────────────────────────────────────────────────────
printf "── Paso 4: Generar API key ─────────────────\n"
info "Generando (o renovando) API key para '$SERVICE_LOGIN'..."

api POST "/api/v1/user/$ENCODED_LOGIN/key/renew"
if [ "$RESP_CODE" != "200" ] && [ "$RESP_CODE" != "201" ]; then
  die "No se pudo generar API key (HTTP $RESP_CODE): $RESP_BODY"
fi

# La respuesta es una string JSON como "abc123" o un objeto {"key":"..."}
if printf '%s' "$RESP_BODY" | grep -q '"key"'; then
  API_KEY=$(printf '%s' "$RESP_BODY" | json_get "key")
else
  API_KEY=$(printf '%s' "$RESP_BODY" | tr -d '"' | tr -d '\n' | tr -d ' ')
fi

if [ -z "$API_KEY" ]; then
  die "No se pudo extraer la API key de la respuesta: $RESP_BODY"
fi
ok "API key generada"
printf "\n"

# ── 5. Mostrar resultado ───────────────────────────────────────────────────────
printf "════════════════════════════════════════════\n"
printf "  API Key generada:\n\n"
printf "    %s\n\n" "$API_KEY"
printf "════════════════════════════════════════════\n\n"

# ── 6. Escribir en .env ────────────────────────────────────────────────────────
if [ "${NO_WRITE:-false}" = "true" ]; then
  info "Flag --no-write activo, no se modifica .env"
  exit 0
fi

if [ ! -f "$ENV_FILE" ]; then
  warn ".env no encontrado en $ENV_FILE — copiá la key manualmente"
  exit 0
fi

# Actualizar THEHIVE_API_KEY
if grep -q "^THEHIVE_API_KEY=" "$ENV_FILE"; then
  sed -i.bak "s|^THEHIVE_API_KEY=.*|THEHIVE_API_KEY='${API_KEY}'|" "$ENV_FILE" && rm -f "${ENV_FILE}.bak"
else
  printf "THEHIVE_API_KEY='%s'\n" "$API_KEY" >> "$ENV_FILE"
fi

# Actualizar THEHIVE_USER
if grep -q "^THEHIVE_USER=" "$ENV_FILE"; then
  sed -i.bak "s|^THEHIVE_USER=.*|THEHIVE_USER='${SERVICE_LOGIN}'|" "$ENV_FILE" && rm -f "${ENV_FILE}.bak"
else
  printf "THEHIVE_USER='%s'\n" "$SERVICE_LOGIN" >> "$ENV_FILE"
fi

ok "THEHIVE_API_KEY actualizado en .env"
ok "THEHIVE_USER actualizado en .env ($SERVICE_LOGIN)"
printf "\n"

# ── 7. Reiniciar el dashboard para aplicar la nueva key ───────────────────────
info "Reiniciando el dashboard para aplicar la nueva API key..."
if docker compose -f "$(dirname "$ENV_FILE")/docker-compose.yml" restart dashboard >/dev/null 2>&1; then
  ok "Dashboard reiniciado — TheHive key activa"
else
  warn "No se pudo reiniciar automáticamente. Ejecutá manualmente:"
  printf "\n    docker compose restart dashboard\n\n"
fi
