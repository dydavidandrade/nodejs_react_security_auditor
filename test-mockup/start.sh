#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────
# start.sh — Levanta backend + frontend del test-mockup
# ─────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

BACKEND_PORT=3001
FRONTEND_PORT=3000

BACKEND_PID=""
FRONTEND_PID=""

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()    { echo -e "${CYAN}[mockup]${NC} $*"; }
ok()     { echo -e "${GREEN}[mockup]${NC} ✓ $*"; }
warn()   { echo -e "${YELLOW}[mockup]${NC} ⚠ $*"; }
error()  { echo -e "${RED}[mockup]${NC} ✗ $*" >&2; }
banner() { echo -e "\n${BOLD}$*${NC}\n"; }

# ── Cleanup al salir ──────────────────────────
cleanup() {
  echo ""
  log "Deteniendo servicios..."
  if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
    ok "Backend detenido (PID $BACKEND_PID)"
  fi
  if [ -n "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" 2>/dev/null || true
    wait "$FRONTEND_PID" 2>/dev/null || true
    ok "Frontend detenido (PID $FRONTEND_PID)"
  fi
}
trap cleanup INT TERM EXIT

# ── Prerequisitos ─────────────────────────────
banner "🔍 Verificando prerequisitos..."

if ! command -v node &>/dev/null; then
  error "Node.js no encontrado. Instálalo desde https://nodejs.org"
  exit 1
fi
ok "Node.js $(node --version)"

if command -v pnpm &>/dev/null; then
  PKG_MGR="pnpm"
elif command -v npm &>/dev/null; then
  PKG_MGR="npm"
else
  error "npm o pnpm requerido"
  exit 1
fi
ok "Package manager: $PKG_MGR"

# ── Instalar dependencias ─────────────────────
banner "📦 Instalando dependencias..."

if [ ! -d "$BACKEND_DIR/node_modules" ]; then
  log "Instalando backend..."
  (cd "$BACKEND_DIR" && $PKG_MGR install --silent)
  ok "Dependencias del backend instaladas"
else
  ok "Backend: node_modules ya existe"
fi

if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
  log "Instalando frontend (puede tardar unos minutos)..."
  (cd "$FRONTEND_DIR" && $PKG_MGR install --silent)
  ok "Dependencias del frontend instaladas"
else
  ok "Frontend: node_modules ya existe"
fi

# ── Función: esperar que un puerto responda ───
wait_for_port() {
  local port=$1
  local label=$2
  local retries=40   # 20 segundos máx
  for i in $(seq 1 $retries); do
    if curl -sf "http://localhost:$port" -o /dev/null 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  error "$label no respondió en el puerto $port después de 20s"
  return 1
}

# ── Levantar backend ──────────────────────────
banner "🚀 Levantando backend (puerto $BACKEND_PORT)..."

(cd "$BACKEND_DIR" && node index.js 2>&1 | sed "s/^/${CYAN}[backend]${NC} /") &
BACKEND_PID=$!

if ! wait_for_port "$BACKEND_PORT" "Backend"; then
  error "El backend falló al iniciar."
  exit 1
fi

if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  error "El proceso del backend terminó inesperadamente."
  exit 1
fi
ok "Backend listo en http://localhost:$BACKEND_PORT"

# ── Levantar frontend ─────────────────────────
banner "🖥️  Levantando frontend (puerto $FRONTEND_PORT)..."

# react-scripts usa la variable PORT para definir el puerto
(cd "$FRONTEND_DIR" && PORT=$FRONTEND_PORT BROWSER=none $PKG_MGR start 2>&1 | sed "s/^/${YELLOW}[frontend]${NC} /") &
FRONTEND_PID=$!

if ! wait_for_port "$FRONTEND_PORT" "Frontend"; then
  warn "El frontend no respondió — continuando igual (el auditor apunta al backend)"
fi

if kill -0 "$FRONTEND_PID" 2>/dev/null; then
  ok "Frontend listo en http://localhost:$FRONTEND_PORT"
else
  warn "El frontend terminó — solo el backend está disponible para la auditoría"
fi

# ── Resumen ───────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  ✅  Test-mockup listo${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Backend:${NC}          http://localhost:$BACKEND_PORT"
echo -e "  ${BOLD}Frontend:${NC}         http://localhost:$FRONTEND_PORT"
echo ""
echo -e "  ${BOLD}Credenciales:${NC}     admin / Admin@1234"
echo -e "                    user1 / User@1234"
echo ""
echo -e "  ${BOLD}Ejecutar auditor:${NC}"
echo -e "  ${CYAN}node $(dirname "$SCRIPT_DIR")/index.js http://localhost:$BACKEND_PORT${NC}"
echo ""
echo -e "  Presiona ${BOLD}Ctrl+C${NC} para detener ambos servicios."
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Mantener el script vivo mientras ambos procesos corran.
# Si cualquiera de los dos muere, el script termina (y cleanup mata al otro).
wait -n "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || wait "$BACKEND_PID" 2>/dev/null || true
