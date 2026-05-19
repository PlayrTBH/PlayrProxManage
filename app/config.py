"""
Configuration.

App-level settings come from environment variables (loaded by systemd from
/etc/proxmox-manager/proxmox-manager.env).

Cluster definitions come from a separate JSON file (CLUSTERS_FILE, default
/etc/proxmox-manager/clusters.json) because there can be many of them and
each carries its own API token. See clusters.json.example for the format.

The cluster `id` is permanent — it's part of every VM's identity in the
history DB, so don't change it after data has been recorded.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


def _get(key: str, default: str | None = None, required: bool = False) -> str:
    val = os.environ.get(key, default)
    if required and not val:
        raise RuntimeError(
            f"Required config '{key}' is not set. "
            f"Edit /etc/proxmox-manager/proxmox-manager.env"
        )
    return val or ""


@dataclass(frozen=True)
class ClusterConfig:
    id: str
    name: str
    host: str
    token_id: str
    token_secret: str
    port: int = 8006
    verify_ssl: bool = False


def _load_clusters(path: str) -> list[ClusterConfig]:
    p = Path(path)
    if not p.exists():
        raise RuntimeError(
            f"Cluster file '{path}' not found. Create it (see clusters.json.example)."
        )
    try:
        raw = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Cluster file '{path}' is not valid JSON: {exc}") from exc

    if not isinstance(raw, list) or not raw:
        raise RuntimeError("Cluster file must be a non-empty JSON array.")

    clusters: list[ClusterConfig] = []
    seen_ids: set[str] = set()
    for entry in raw:
        missing = {"id", "host", "token_id", "token_secret"} - entry.keys()
        if missing:
            raise RuntimeError(f"Cluster entry missing keys: {sorted(missing)}")
        cid = str(entry["id"])
        if cid in seen_ids:
            raise RuntimeError(f"Duplicate cluster id '{cid}' in cluster file.")
        seen_ids.add(cid)
        clusters.append(
            ClusterConfig(
                id=cid,
                name=str(entry.get("name", cid)),
                host=str(entry["host"]),
                port=int(entry.get("port", 8006)),
                token_id=str(entry["token_id"]),
                token_secret=str(entry["token_secret"]),
                verify_ssl=bool(entry.get("verify_ssl", False)),
            )
        )
    return clusters


class Settings:
    def __init__(self) -> None:
        # --- this app ---
        # Bind localhost by default: nginx terminates TLS and fronts the app.
        self.bind_host = _get("BIND_HOST", "127.0.0.1")
        self.bind_port = int(_get("BIND_PORT", "8800"))
        self.db_path = _get("DB_PATH", "/var/lib/proxmox-manager/app.db")

        # --- clusters ---
        self.clusters_file = _get(
            "CLUSTERS_FILE", "/etc/proxmox-manager/clusters.json"
        )
        self.clusters = _load_clusters(self.clusters_file)

        # --- poller ---
        self.poll_interval = int(_get("POLL_INTERVAL", "30"))
        self.history_retention_days = int(_get("HISTORY_RETENTION_DAYS", "30"))

        # --- auth / sessions ---
        # Session signing secret; installer generates and pins this.
        self.session_secret = _get("SESSION_SECRET", required=True)
        # secure cookie flag: true when served over HTTPS (the normal case).
        self.cookie_secure = _get("COOKIE_SECURE", "true").lower() == "true"
        # Bootstrap admin: created on first run only if no users exist yet.
        self.bootstrap_admin_user = _get("BOOTSTRAP_ADMIN_USER", "admin")
        self.bootstrap_admin_password_hash = _get(
            "BOOTSTRAP_ADMIN_PASSWORD_HASH", required=True
        )

        # login rate-limit: failed attempts per window before lockout.
        self.login_max_attempts = int(_get("LOGIN_MAX_ATTEMPTS", "5"))
        self.login_window_seconds = int(_get("LOGIN_WINDOW_SECONDS", "300"))

        # --- invites ---
        # Public base URL of this app, used to build invite links in emails.
        # Must be the externally reachable URL (behind your VPN/Tunnel),
        # e.g. https://pmx.example.com  — no trailing slash.
        self.public_base_url = _get(
            "PUBLIC_BASE_URL", "http://localhost:8800"
        ).rstrip("/")
        self.invite_expiry_days = int(_get("INVITE_EXPIRY_DAYS", "7"))

        # --- SMTP (for sending invite emails) ---
        # If SMTP_HOST/SMTP_FROM are unset, the app falls back to showing
        # the admin the raw invite link to send manually.
        self.smtp_host = _get("SMTP_HOST", "")
        self.smtp_port = int(_get("SMTP_PORT", "587"))
        self.smtp_user = _get("SMTP_USER", "")
        self.smtp_password = _get("SMTP_PASSWORD", "")
        self.smtp_from = _get("SMTP_FROM", "")
        # Implicit TLS (port 465). Mutually exclusive with STARTTLS.
        self.smtp_use_ssl = _get("SMTP_USE_SSL", "false").lower() == "true"
        # STARTTLS upgrade on a plain connection (port 587). Default on.
        self.smtp_starttls = _get("SMTP_STARTTLS", "true").lower() == "true"

    def cluster_map(self) -> dict[str, ClusterConfig]:
        return {c.id: c for c in self.clusters}


settings = Settings()
