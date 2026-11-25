#!/usr/bin/env bash
# =============================================================================
# W3Panel v2 Installer
# Usage: bash install.sh
# =============================================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Config ────────────────────────────────────────────────────────────────────
INSTALL_DIR="/usr/local/w3panel"
VENV_DIR="$INSTALL_DIR/venv"
ETC_DIR="/etc/w3panel"
VAR_DIR="/var/lib/w3panel"
LOG_DIR="/var/log/w3panel"
DB_DIR="$VAR_DIR/db"
SSL_DIR="$ETC_DIR/ssl"
SERVICE_DIR="/etc/systemd/system"
PANEL_USER="w3panel"
ADMIN_PORT=2087
USER_PORT=2083
ADMIN_PASS="123"
REPO_URL="https://github.com/lkylab/w3panel.git"
BRANCH="main"

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"

# ── OS detection ──────────────────────────────────────────────────────────────
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VER="${VERSION_ID:-0}"
else
    die "Cannot detect OS. /etc/os-release not found."
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)          ARCH_LABEL="x86_64"  ;;
    aarch64|arm64)   ARCH_LABEL="aarch64" ;;
    *) die "Unsupported architecture: $ARCH" ;;
esac

case "$OS_ID" in
    ubuntu|debian) PKG_MGR="apt-get" ;;
    centos|rhel|almalinux|rocky) PKG_MGR="yum" ;;
    *) die "Unsupported OS: $OS_ID" ;;
esac

echo -e "${BOLD}"
echo "  ██╗    ██╗██████╗ ██████╗  █████╗ ███╗   ██╗███████╗██╗     "
echo "  ██║    ██║╚════██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝██║     "
echo "  ██║ █╗ ██║ █████╔╝██████╔╝███████║██╔██╗ ██║█████╗  ██║     "
echo "  ██║███╗██║ ╚═══██╗██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║     "
echo "  ╚███╔███╔╝██████╔╝██║     ██║  ██║██║ ╚████║███████╗███████╗"
echo "  ╚══╝╚══╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "  ${CYAN}W3Panel v2 — Modern Web Hosting Control Panel${NC}"
echo -e "  Arch: ${ARCH_LABEL}   OS: ${OS_ID} ${OS_VER}"
echo ""

# ── CLI Arguments ─────────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --branch=*) BRANCH="${arg#*=}" ;;
    esac
done

# ── System packages ───────────────────────────────────────────────────────────
info "Installing core system packages..."

if [[ "$PKG_MGR" == "apt-get" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
        python3 python3-venv python3-pip \
        git curl wget openssl \
        build-essential libssl-dev libffi-dev \
        unzip jq \
        ca-certificates lsb-release
    info "Configuring Ondřej Surý (packages.sury.org/php) Multi-PHP repository..."
    curl -sSLo /tmp/debsuryorg-archive-keyring.deb https://packages.sury.org/debsuryorg-archive-keyring.deb
    dpkg -i /tmp/debsuryorg-archive-keyring.deb >/dev/null
    rm -f /tmp/debsuryorg-archive-keyring.deb
    echo "deb [signed-by=/usr/share/keyrings/debsuryorg-archive-keyring.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list
    apt-get update -qq || true
    success "Ondřej Surý (packages.sury.org/php) Multi-PHP repository configured"
else
    yum install -y -q \
        python3 python3-pip \
        git curl wget openssl \
        gcc openssl-devel libffi-devel \
        unzip jq
fi
success "Core system packages installed"

# ── Apply High-Performance Kernel Tuning & Limits ─────────────────────────────
info "Applying production kernel tuning and resource limits..."
cat <<'EOF' > /etc/sysctl.d/99-w3panel.conf
fs.file-max = 2097152
fs.nr_open = 2097152
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF
sysctl -p /etc/sysctl.d/99-w3panel.conf 2>/dev/null || true

cat <<'EOF' > /etc/security/limits.d/99-w3panel.conf
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
w3panel soft nofile 1048576
w3panel hard nofile 1048576
www-data soft nofile 1048576
www-data hard nofile 1048576
EOF
success "Kernel tuning and limits configured"

# ── Create system user ────────────────────────────────────────────────────────
info "Creating panel user..."
if ! id "$PANEL_USER" &>/dev/null; then
    useradd -r -m -d "$INSTALL_DIR" -s /bin/bash "$PANEL_USER"
    success "User $PANEL_USER created"
else
    success "User $PANEL_USER already exists"
fi

# ── Create directories ────────────────────────────────────────────────────────
info "Creating directories..."
mkdir -p "$INSTALL_DIR" "$ETC_DIR" "$ETC_DIR/vhosts" "$VAR_DIR" "$VAR_DIR/users" "$LOG_DIR" "$DB_DIR" "$SSL_DIR"
chown -R "$PANEL_USER":"$PANEL_USER" "$ETC_DIR" "$VAR_DIR"
chmod 755 "$VAR_DIR"
chown -R "$PANEL_USER":www-data "$LOG_DIR" 2>/dev/null || chown -R "$PANEL_USER":"$PANEL_USER" "$LOG_DIR"
chmod 775 "$LOG_DIR"

# ── Copy files ────────────────────────────────────────────────────────────────
info "Installing W3Panel v2 files..."
SCRIPT_PATH="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [[ -n "$SCRIPT_PATH" && -f "$SCRIPT_PATH" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" &>/dev/null && pwd)"
fi

TMP_SRC=""
if [[ -n "$SCRIPT_DIR" && -d "$SCRIPT_DIR/apps" && -f "$SCRIPT_DIR/manage.py" ]]; then
    SRC_DIR="$SCRIPT_DIR"
else
    TMP_SRC="/tmp/w3panel-install-$$"
    info "Downloading W3Panel from ${REPO_URL} (${BRANCH})..."
    rm -rf "$TMP_SRC"
    git clone --depth 1 -b "$BRANCH" "$REPO_URL" "$TMP_SRC"
    SRC_DIR="$TMP_SRC"
fi

cp -r "$SRC_DIR"/{apps,packages,panel,services,static,templates,tests,manage.py,requirements.txt} "$INSTALL_DIR/"
if [[ -f "$SRC_DIR/update.sh" ]]; then
    cp "$SRC_DIR/update.sh" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/update.sh"
    ln -sf "$INSTALL_DIR/update.sh" /usr/local/bin/w3panel-update
fi

# Install test runner helper
cat << 'EOF' > /usr/local/bin/w3panel-test
#!/usr/bin/env bash
cd /usr/local/w3panel || exit 1
export DJANGO_SETTINGS_MODULE=panel.settings
if [[ $# -eq 0 ]]; then
    /usr/local/w3panel/venv/bin/python manage.py test tests
else
    /usr/local/w3panel/venv/bin/python manage.py test "$@"
fi
EOF
chmod +x /usr/local/bin/w3panel-test

if [[ -n "$TMP_SRC" && -d "$TMP_SRC" ]]; then
    rm -rf "$TMP_SRC"
fi

chown -R "$PANEL_USER":"$PANEL_USER" "$INSTALL_DIR"
success "Files installed to $INSTALL_DIR"

# ── Python virtual environment ────────────────────────────────────────────────
info "Setting up Python virtual environment..."
if [[ ! -d "$VENV_DIR" ]]; then
    sudo -u "$PANEL_USER" python3 -m venv "$VENV_DIR"
fi
sudo -u "$PANEL_USER" "$VENV_DIR/bin/pip" install -q --upgrade pip
sudo -u "$PANEL_USER" "$VENV_DIR/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
success "Python dependencies installed"

# ── Django setup ──────────────────────────────────────────────────────────────
info "Running Django migrations..."
cd "$INSTALL_DIR"
mkdir -p "$LOG_DIR" "$DB_DIR"
chown -R "$PANEL_USER":"$PANEL_USER" "$LOG_DIR" "$DB_DIR"
export DJANGO_SETTINGS_MODULE=panel.settings

sudo -u "$PANEL_USER" "$VENV_DIR/bin/python" manage.py migrate --run-syncdb
sudo -u "$PANEL_USER" "$VENV_DIR/bin/python" manage.py collectstatic --noinput
success "Migrations and static files complete"

# ── Create admin user ─────────────────────────────────────────────────────────
info "Creating admin user..."
sudo -u "$PANEL_USER" "$VENV_DIR/bin/python" - <<PYEOF
import os, django
os.environ['DJANGO_SETTINGS_MODULE'] = 'panel.settings'
django.setup()
from packages.core.models import User, SystemSetting
if not User.objects.filter(username='admin').exists():
    User.objects.create_user('admin', 'admin@localhost', '${ADMIN_PASS}', role='admin')
    print('Admin user created: admin / ${ADMIN_PASS}')
else:
    print('Admin user already exists')
if '${PKG_MGR}' == 'apt-get':
    SystemSetting.set('sury_repo_enabled', 'true')
PYEOF

# ── Self-signed SSL ───────────────────────────────────────────────────────────
info "Generating self-signed SSL certificate..."
if [[ ! -f "$SSL_DIR/panel.crt" ]]; then
    SERVER_IP=$(curl -4 -fsSL https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_DIR/panel.key" \
        -out "$SSL_DIR/panel.crt" \
        -subj "/C=US/ST=State/L=City/O=W3Panel/CN=${SERVER_IP}" \
        -addext "subjectAltName=IP:${SERVER_IP}" 2>/dev/null
    chmod 600 "$SSL_DIR/panel.key" "$SSL_DIR/panel.crt"
    chown -R "$PANEL_USER":"$PANEL_USER" "$SSL_DIR"
    success "Self-signed cert generated"
else
    chown -R "$PANEL_USER":"$PANEL_USER" "$SSL_DIR"
    success "SSL cert already exists"
fi

# ── Systemd services ──────────────────────────────────────────────────────────
info "Installing systemd services..."

# Admin service
cat > "$SERVICE_DIR/w3panel-admin.service" <<EOF
[Unit]
Description=W3Panel Admin (port $ADMIN_PORT)
After=network.target

[Service]
Type=simple
User=$PANEL_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/gunicorn panel.wsgi:application \\
    --bind 0.0.0.0:$ADMIN_PORT \\
    --workers 2 \\
    --timeout 120 \\
    --certfile=$SSL_DIR/panel.crt \\
    --keyfile=$SSL_DIR/panel.key \\
    --access-logfile $LOG_DIR/access.log \\
    --error-logfile $LOG_DIR/error.log
Restart=always
RestartSec=5
Environment=DJANGO_SETTINGS_MODULE=panel.settings
Environment=SERVER_PORT=$ADMIN_PORT

[Install]
WantedBy=multi-user.target
EOF

# User service
cat > "$SERVICE_DIR/w3panel-user.service" <<EOF
[Unit]
Description=W3Panel User (port $USER_PORT)
After=network.target

[Service]
Type=simple
User=$PANEL_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/gunicorn panel.wsgi:application \\
    --bind 0.0.0.0:$USER_PORT \\
    --workers 2 \\
    --timeout 120 \\
    --certfile=$SSL_DIR/panel.crt \\
    --keyfile=$SSL_DIR/panel.key \\
    --access-logfile $LOG_DIR/access.log \\
    --error-logfile $LOG_DIR/error.log
Restart=always
RestartSec=5
Environment=DJANGO_SETTINGS_MODULE=panel.settings
Environment=SERVER_PORT=$USER_PORT

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now w3panel-admin
systemctl enable --now w3panel-user
success "Systemd services installed and started"

# ── Firewall ──────────────────────────────────────────────────────────────────
info "Configuring firewall..."
if command -v ufw &>/dev/null; then
    ufw allow 22/tcp   comment "SSH" 2>/dev/null || true
    ufw allow 80/tcp   comment "HTTP" 2>/dev/null || true
    ufw allow 443/tcp  comment "HTTPS" 2>/dev/null || true
    ufw allow $ADMIN_PORT/tcp comment "W3Panel Admin" 2>/dev/null || true
    ufw allow $USER_PORT/tcp comment "W3Panel User" 2>/dev/null || true
    ufw --force enable 2>/dev/null || true
    success "UFW configured"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=$ADMIN_PORT/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=$USER_PORT/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-service=http 2>/dev/null || true
    firewall-cmd --permanent --add-service=https 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    success "firewalld configured"
fi

# ── Sudoers ───────────────────────────────────────────────────────────────────
info "Configuring sudoers..."
cat > "/etc/sudoers.d/w3panel" <<EOF
$PANEL_USER ALL=(ALL) NOPASSWD: ALL
EOF
chmod 440 "/etc/sudoers.d/w3panel"

# ── Done ──────────────────────────────────────────────────────────────────────
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
SERVER_IP="${SERVER_IP:-127.0.0.1}"

echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  W3Panel v2 (W3Host Manager & W3Client Portal) installed successfully!${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  W3Host Manager (Admin):    ${CYAN}https://${SERVER_IP}:$ADMIN_PORT${NC}"
echo -e "  W3Client Portal (User):    ${CYAN}https://${SERVER_IP}:$USER_PORT${NC}"
echo ""
echo -e "  Admin Login:        ${BOLD}admin${NC} / ${BOLD}$ADMIN_PASS${NC}"
echo ""
echo -e "  Setup:"
echo -e "    • Sign in to W3Host Manager to complete the Initial Setup Wizard"
echo -e "      (Nginx/Apache, PHP, MariaDB, PostgreSQL, Podman, Mail, FTP)."
echo -e "    • Architecture:   ${BOLD}Independent Gunicorn Daemons (Ports 2087 & 2083)${NC}"
echo ""
echo -e "  ${YELLOW}Note: Change the admin password immediately after first login!${NC}"
echo ""
echo -e "  Updates:"
echo -e "    • Run:            ${CYAN}sudo w3panel-update${NC} to update panel at any time"
echo ""