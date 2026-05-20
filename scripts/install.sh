#!/usr/bin/env bash
#
# Proxmox Manager installer.
# Run as root on a fresh Debian/Ubuntu VM:  sudo ./scripts/install.sh
#
# It will:
#   - create the 'proxmox-manager' system user
#   - install the app into /opt/proxmox-manager with a venv
#   - lay down config templates in /etc/proxmox-manager
#   - generate a session secret
#   - install and start the systemd service
#
# After it finishes you must edit two files and set an admin password.

set -euo pipefail

APP_DIR=/opt/proxmox-manager
CFG_DIR=/etc/proxmox-manager
DATA_DIR=/var/lib/proxmox-manager
SVC_USER=proxmox-manager
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

note()  { echo -e "\033[1;36m==>\033[0m $*"; }
warn()  { echo -e "\033[1;33m!!\033[0m $*"; }
die()   { echo -e "\033[1;31mERROR:\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run this script as root (sudo)."

note "Installing OS dependencies (python3, venv, pip)..."
if command -v apt-get >/dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-venv python3-pip >/dev/null
else
    warn "Non-apt system: ensure python3 + venv are installed yourself."
fi

note "Creating service user '${SVC_USER}'..."
if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi

note "Installing application to ${APP_DIR}..."
mkdir -p "$APP_DIR"
cp -r "$SRC_DIR/app" "$APP_DIR/"
cp "$SRC_DIR/requirements.txt" "$APP_DIR/"

note "Building Python virtualenv..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

note "Setting up data directory ${DATA_DIR}..."
mkdir -p "$DATA_DIR"
chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR"
chown -R root:root "$APP_DIR"

note "Setting up config directory ${CFG_DIR}..."
mkdir -p "$CFG_DIR"

ENV_FILE="$CFG_DIR/proxmox-manager.env"
CLUSTERS_FILE="$CFG_DIR/clusters.json"

if [[ ! -f "$ENV_FILE" ]]; then
    cp "$SRC_DIR/proxmox-manager.env.example" "$ENV_FILE"
    SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    sed -i "s|^SESSION_SECRET=.*|SESSION_SECRET=${SECRET}|" "$ENV_FILE"
    note "Generated a fresh SESSION_SECRET."
else
    warn "$ENV_FILE already exists — left untouched."
fi

if [[ ! -f "$CLUSTERS_FILE" ]]; then
    cp "$SRC_DIR/clusters.json.example" "$CLUSTERS_FILE"
    warn "Created $CLUSTERS_FILE from the example — EDIT IT with real clusters."
else
    warn "$CLUSTERS_FILE already exists — left untouched."
fi

# Config files contain secrets: lock them down.
chown root:"$SVC_USER" "$ENV_FILE" "$CLUSTERS_FILE"
chmod 640 "$ENV_FILE" "$CLUSTERS_FILE"

note "Installing systemd service..."
cp "$SRC_DIR/scripts/proxmox-manager.service" \
   /etc/systemd/system/proxmox-manager.service
systemctl daemon-reload

cat <<EOF

------------------------------------------------------------------
Install complete. Two manual steps remain:

  1. Set an admin password hash:
       cd $APP_DIR
       sudo ./venv/bin/python -m app.hashpw
     Copy the printed hash into BOOTSTRAP_ADMIN_PASSWORD_HASH in:
       $ENV_FILE

  2. Edit your clusters and API tokens in:
       $CLUSTERS_FILE
     (See README for how to create a scoped Proxmox API token.)

Then start the service:
     sudo systemctl enable --now proxmox-manager
     sudo systemctl status proxmox-manager

For public/HTTPS access, set up the bundled nginx config:
     scripts/nginx-proxmox-manager.conf
------------------------------------------------------------------
EOF
