#!/usr/bin/env bash
# =============================================================================
# W3Panel v2 Updater
# Usage: sudo bash update.sh [--branch=main]
# or: sudo w3panel-update
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash update.sh"

INSTALL_DIR="/usr/local/w3panel"
VENV_DIR="$INSTALL_DIR/venv"
PANEL_USER="w3panel"
REPO_URL="https://github.com/lkylab/w3panel.git"
BRANCH="main"

for arg in "$@"; do
    case "$arg" in
        --branch=*) BRANCH="${arg#*=}" ;;
    esac
done

echo -e "${BOLD}"
echo "  ██╗    ██╗██████╗ ██████╗  █████╗ ███╗   ██╗███████╗██╗     "
echo "  ██║    ██║╚════██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝██║     "
echo "  ██║ █╗ ██║ █████╔╝██████╔╝███████║██╔██╗ ██║█████╗  ██║     "
echo "  ██║███╗██║ ╚═══██╗██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║     "
echo "  ╚███╔███╔╝██████╔╝██║     ██║  ██║██║ ╚████║███████╗███████╗"
echo "  ╚══╝╚══╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "  ${CYAN}W3Panel v2 — System Updater${NC}"
echo -e "  Target branch: ${BRANCH}"
echo ""

info "Checking system..."
if [[ ! -d "$INSTALL_DIR" ]]; then
    die "W3Panel installation not found at $INSTALL_DIR. Please install first."
fi

TMP_SRC="/tmp/w3panel-update-$$"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

if [[ -d "$SCRIPT_DIR/.git" ]]; then
    info "Fetching updates in local repository ($SCRIPT_DIR)..."
    cd "$SCRIPT_DIR"
    git fetch origin "$BRANCH"
    git reset --hard "origin/$BRANCH"
    SRC_DIR="$SCRIPT_DIR"
else
    info "Cloning latest code from ${REPO_URL} (${BRANCH})..."
    rm -rf "$TMP_SRC"
    git clone --depth 1 -b "$BRANCH" "$REPO_URL" "$TMP_SRC"
    SRC_DIR="$TMP_SRC"
fi

info "Updating panel files in ${INSTALL_DIR}..."
cp -r "$SRC_DIR"/{apps,packages,panel,services,static,templates,manage.py,requirements.txt} "$INSTALL_DIR/"
if [[ -f "$SRC_DIR/update.sh" ]]; then
    cp "$SRC_DIR/update.sh" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/update.sh"
    ln -sf "$INSTALL_DIR/update.sh" /usr/local/bin/w3panel-update
fi

chown -R "$PANEL_USER":"$PANEL_USER" "$INSTALL_DIR"
success "Panel source files updated"

info "Updating Python dependencies..."
sudo -u "$PANEL_USER" "$VENV_DIR/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
success "Python dependencies up to date"

info "Applying database migrations and collecting static assets..."
cd "$INSTALL_DIR"
export DJANGO_SETTINGS_MODULE=panel.settings
sudo -u "$PANEL_USER" "$VENV_DIR/bin/python" manage.py migrate --run-syncdb
sudo -u "$PANEL_USER" "$VENV_DIR/bin/python" manage.py collectstatic --noinput
success "Migrations and static files completed"

info "Restarting W3Panel services..."
systemctl restart w3panel-admin w3panel-user
success "Services restarted"

if [[ -d "$TMP_SRC" ]]; then
    rm -rf "$TMP_SRC"
fi

echo ""
echo -e "${GREEN}${BOLD}✓ W3Panel has been successfully updated to latest version!${NC}"
echo ""
