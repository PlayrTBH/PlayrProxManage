#!/usr/bin/env bash
#
# Proxmox Manager — one-liner bootstrap installer.
#
# Usage (run as root on a fresh Debian/Ubuntu VM):
#   curl -fsSL https://raw.githubusercontent.com/YOUR_USER/proxmanager/main/scripts/bootstrap.sh | sudo bash
#
# What it does:
#   1. Installs git if missing.
#   2. Clones the repo into a temp directory.
#   3. Delegates to scripts/install.sh (creates user, venv, systemd service).
#   4. Cleans up the temp clone — the app lives in /opt/proxmox-manager.
#
# After it finishes you must set an admin password and edit clusters.json.
# The installer prints the exact commands.

set -euo pipefail

REPO_URL="https://github.com/YOUR_USER/proxmanager.git"
BRANCH="main"

note() { echo -e "\033[1;36m==>\033[0m $*"; }
die()  { echo -e "\033[1;31mERROR:\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run this script as root (sudo)."

# ── dependencies ────────────────────────────────────────────────────────────
if ! command -v git >/dev/null 2>&1; then
    note "git not found — installing..."
    if command -v apt-get >/dev/null; then
        apt-get update -qq
        apt-get install -y -qq git >/dev/null
    else
        die "git is not installed and this isn't an apt system. Install git manually and re-run."
    fi
fi

# ── clone ────────────────────────────────────────────────────────────────────
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

note "Cloning Proxmox Manager (${BRANCH}) into ${TMPDIR}..."
git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TMPDIR/proxmanager" \
    || die "git clone failed. Check REPO_URL and network connectivity."

# ── install ──────────────────────────────────────────────────────────────────
note "Running installer..."
bash "$TMPDIR/proxmanager/scripts/install.sh"
