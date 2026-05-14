#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────
# start.sh — Levanta el test-mockup para SEC-Auditor
# ─────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()    { echo -e "${CYAN}[mockup]${NC} $*"; }
ok()     { echo -e "${GREEN}[mockup]${NC} $*"; }
warn()   { echo -e "${YELLOW}[mockup]${NC} $*"; }
error()  { echo -e "${RED}[mockup]${NC} $*" >&2; }
banner() { echo -e "\n${BOLD}$*${NC}\n"; }

# ── Prerequisitos ─────────────────────────────
banner "🔍 Verificando prerequisitos..."

if ! command -v node &>/dev/null; then
  error "Node.js no encontrado. Instálalo desde https://nodejs.org"
  exit 1
fi

NODE_VERSION=$(node --version)
ok "Node.js $NODE_VERSION encontrado"

# Elige npm o pnpm
if command -v pnpm &>/dev/null; then
  PKG_MGR="pnpm"
elif command -v npm &>/dev/null; then
  PKG_MGR="npm"
else
  error "npm o pnpm requerido"
  exit 1
fi
ok "Package manager: $PKG_MGR"

# ── Instalar dependencias del backend ─────────
banner "📦 Instalando dependencias del backend..."

if [ ! -d "$BACKEND_DIR/node_modules" ]; then
  (cd "$BACKEND_DIR" && $PKG_MGR install)
  ok "Dependencias instaladas"
else
  ok "node_modules ya existe — omitiendo instalación"
fi

# ── Manejar señales para cleanup limpio ───────
cleanup() {
  echo ""
  log "Deteniendo servidor..."
  if [ -n "${BACKEND_PID:-}" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
  fi
  ok "Servidor detenido."
}
trap cleanup INT TERM EXIT

# ── Levantar backend ──────────────────────────
banner "🚀 Levantando backend..."

(cd "$BACKEND_DIR" && node index.js) &
BACKEND_PID=$!

# Esperar a que el puerto esté listo (máx 10s)
BACKEND_PORT=3001
for i in $(seq 1 20); do
  if curl -sf "http://localhost:$BACKEND_PORT" -o /dev/null 2>/dev/null; then
    break
  fi
  sleep 0.5
done

# Verificar que el proceso sigue vivo
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  error "El backend falló al iniciar. Revisa los logs arriba."
  exit 1
fi

# ── Info para el auditor ──────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  ✅  Test-mockup listo${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}URL objetivo:${NC}     http://localhost:$BACKEND_PORT"
echo -e "  ${BOLD}Credenciales:${NC}     admin / Admin@1234"
echo -e "                    user1 / User@1234"
echo ""
echo -e "  ${BOLD}Ejecutar auditor:${NC}"
echo -e "  ${CYAN}node $(dirname "$SCRIPT_DIR")/index.js http://localhost:$BACKEND_PORT${NC}"
echo ""
echo -e "  Presiona ${BOLD}Ctrl+C${NC} para detener el servidor."
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Mantener el script vivo mientras el backend corre
wait "$BACKEND_PID"
