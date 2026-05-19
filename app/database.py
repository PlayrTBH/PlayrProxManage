"""
SQLite storage.

Tables:
  users      - app accounts (admin / operator / viewer)
  vm_grants  - which non-admin user may see/control which VM, and at what role
  invites    - pending email-invite tokens for accounts not yet activated
  vm_stats   - time-series samples from the poller (powers reporting charts)
  audit_log  - every power action and account change, for accountability

A VM is identified everywhere by the triple (cluster, node, vmid). 'node'
can change if a VM migrates, but (cluster, vmid) is stable, so grants key
on cluster + vmid only.

A user's `status` is the source of truth for whether they may log in:
  invited - created via invite, has not set a password yet
  active  - normal, can log in
  disabled- administratively blocked
An invited user has an empty password_hash until they accept.

SQLite is intentional: single service, low write volume (one batch per
poll). WAL mode keeps the poller's writes from blocking API reads.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

# Roles, most to least privileged.
ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"   # can power-control granted VMs
ROLE_VIEWER = "viewer"       # read-only on granted VMs
VALID_ROLES = {ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER}
# Roles valid for a per-VM grant (admin is global, never per-VM).
GRANT_ROLES = {ROLE_OPERATOR, ROLE_VIEWER}

# Account lifecycle states.
STATUS_INVITED = "invited"
STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT,
    password_hash TEXT NOT NULL DEFAULT '',   -- empty until invite accepted
    role          TEXT NOT NULL,              -- admin | operator | viewer
    status        TEXT NOT NULL DEFAULT 'active',  -- invited|active|disabled
    created_ts    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vm_grants (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cluster    TEXT NOT NULL,
    vmid       INTEGER NOT NULL,
    grant_role TEXT NOT NULL,             -- operator | viewer
    created_ts INTEGER NOT NULL,
    UNIQUE(user_id, cluster, vmid)
);
CREATE INDEX IF NOT EXISTS idx_grants_user ON vm_grants(user_id);

CREATE TABLE IF NOT EXISTS invites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT UNIQUE NOT NULL,     -- sha256 of the raw token
    created_ts  INTEGER NOT NULL,
    expires_ts  INTEGER NOT NULL,
    accepted_ts INTEGER,                  -- NULL until accepted
    UNIQUE(user_id)                       -- one live invite per user
);
CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(token_hash);

CREATE TABLE IF NOT EXISTS vm_stats (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    cluster    TEXT NOT NULL,
    vmid       INTEGER NOT NULL,
    node       TEXT NOT NULL,
    name       TEXT,
    status     TEXT,
    cpu        REAL,
    mem_used   INTEGER,
    mem_max    INTEGER,
    disk_read  INTEGER,
    disk_write INTEGER,
    net_in     INTEGER,
    net_out    INTEGER,
    uptime     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_stats_key_ts ON vm_stats(cluster, vmid, ts);
CREATE INDEX IF NOT EXISTS idx_stats_ts ON vm_stats(ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    actor   TEXT,
    cluster TEXT,
    vmid    INTEGER,
    node    TEXT,
    action  TEXT,
    result  TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


class Database:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """
        Lightweight in-place migration so an existing v1.0 database (which
        had no email/status columns) upgrades cleanly. Safe to run every
        startup: each ALTER is guarded by a column-existence check.
        """
        cur = self._conn.cursor()
        cur.execute("PRAGMA table_info(users)")
        cols = {row["name"] for row in cur.fetchall()}
        if "email" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "status" not in cols:
            cur.execute(
                "ALTER TABLE users ADD COLUMN status TEXT "
                "NOT NULL DEFAULT 'active'"
            )
        cur.close()

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            finally:
                cur.close()

    # ----- users ----------------------------------------------------------

    def count_users(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM users")
            return cur.fetchone()["c"]

    def create_user(
        self,
        username: str,
        password_hash: str,
        role: str,
        email: Optional[str] = None,
        status: str = STATUS_ACTIVE,
    ) -> int:
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role '{role}'")
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO users
                   (username, email, password_hash, role, status, created_ts)
                   VALUES (?,?,?,?,?,?)""",
                (username, email, password_hash, role, status,
                 int(time.time())),
            )
            return cur.lastrowid

    def get_user(self, username: str) -> Optional[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> Optional[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_users(self) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT id, username, email, role, status, created_ts "
                "FROM users ORDER BY username"
            )
            return [dict(r) for r in cur.fetchall()]

    def set_user_status(self, user_id: int, status: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE users SET status = ? WHERE id = ?", (status, user_id)
            )

    def set_user_password(self, user_id: int, password_hash: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id),
            )

    def delete_user(self, user_id: int) -> None:
        # vm_grants and invites cascade-delete via foreign keys.
        with self._cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = ?", (user_id,))

    # ----- invites --------------------------------------------------------

    def create_invite(
        self, user_id: int, token_hash: str, expires_ts: int
    ) -> int:
        """
        Store a pending invite. Replaces any existing invite for the user
        (re-send / regenerate), which also invalidates the old token since
        the old token_hash row is gone.
        """
        with self._cursor() as cur:
            cur.execute("DELETE FROM invites WHERE user_id = ?", (user_id,))
            cur.execute(
                """INSERT INTO invites
                   (user_id, token_hash, created_ts, expires_ts)
                   VALUES (?,?,?,?)""",
                (user_id, token_hash, int(time.time()), expires_ts),
            )
            return cur.lastrowid

    def get_invite_by_token(self, token_hash: str) -> Optional[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM invites WHERE token_hash = ?", (token_hash,)
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def get_invite_for_user(self, user_id: int) -> Optional[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM invites WHERE user_id = ?", (user_id,)
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def mark_invite_accepted(self, invite_id: int) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE invites SET accepted_ts = ? WHERE id = ?",
                (int(time.time()), invite_id),
            )

    def delete_invite_for_user(self, user_id: int) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM invites WHERE user_id = ?", (user_id,))

    # ----- grants ---------------------------------------------------------

    def add_grant(
        self, user_id: int, cluster: str, vmid: int, grant_role: str
    ) -> None:
        if grant_role not in GRANT_ROLES:
            raise ValueError(f"Invalid grant role '{grant_role}'")
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO vm_grants
                   (user_id, cluster, vmid, grant_role, created_ts)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(user_id, cluster, vmid)
                   DO UPDATE SET grant_role = excluded.grant_role""",
                (user_id, cluster, vmid, grant_role, int(time.time())),
            )

    def remove_grant(self, user_id: int, cluster: str, vmid: int) -> None:
        with self._cursor() as cur:
            cur.execute(
                "DELETE FROM vm_grants WHERE user_id=? AND cluster=? AND vmid=?",
                (user_id, cluster, vmid),
            )

    def list_grants(self, user_id: int) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT cluster, vmid, grant_role FROM vm_grants WHERE user_id=?",
                (user_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    def get_grant(
        self, user_id: int, cluster: str, vmid: int
    ) -> Optional[str]:
        """Returns the grant_role for this VM, or None if no grant exists."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT grant_role FROM vm_grants "
                "WHERE user_id=? AND cluster=? AND vmid=?",
                (user_id, cluster, vmid),
            )
            row = cur.fetchone()
            return row["grant_role"] if row else None

    # ----- stats ----------------------------------------------------------

    def insert_stats(self, samples: list[dict]) -> None:
        if not samples:
            return
        rows = [
            (
                s["ts"], s["cluster"], s["vmid"], s["node"], s.get("name"),
                s.get("status"), s.get("cpu"), s.get("mem_used"),
                s.get("mem_max"), s.get("disk_read"), s.get("disk_write"),
                s.get("net_in"), s.get("net_out"), s.get("uptime"),
            )
            for s in samples
        ]
        with self._cursor() as cur:
            cur.executemany(
                """INSERT INTO vm_stats
                   (ts, cluster, vmid, node, name, status, cpu, mem_used,
                    mem_max, disk_read, disk_write, net_in, net_out, uptime)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )

    def get_history(
        self, cluster: str, vmid: int, since_ts: int
    ) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(
                """SELECT ts, cpu, mem_used, mem_max, disk_read, disk_write,
                          net_in, net_out, status
                   FROM vm_stats
                   WHERE cluster=? AND vmid=? AND ts>=?
                   ORDER BY ts ASC""",
                (cluster, vmid, since_ts),
            )
            return [dict(r) for r in cur.fetchall()]

    def latest_per_vm(self) -> list[dict]:
        """Most recent sample per (cluster, vmid) — cache for Proxmox outages."""
        with self._cursor() as cur:
            cur.execute(
                """SELECT v.* FROM vm_stats v
                   JOIN (SELECT cluster, vmid, MAX(ts) AS mts
                         FROM vm_stats GROUP BY cluster, vmid) m
                   ON v.cluster=m.cluster AND v.vmid=m.vmid AND v.ts=m.mts"""
            )
            return [dict(r) for r in cur.fetchall()]

    def prune(self, retention_days: int) -> int:
        cutoff = int(time.time()) - retention_days * 86400
        with self._cursor() as cur:
            cur.execute("DELETE FROM vm_stats WHERE ts < ?", (cutoff,))
            return cur.rowcount

    # ----- audit ----------------------------------------------------------

    def add_audit(
        self,
        actor: str,
        action: str,
        result: str,
        cluster: str = "",
        vmid: Optional[int] = None,
        node: str = "",
    ) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO audit_log
                   (ts, actor, cluster, vmid, node, action, result)
                   VALUES (?,?,?,?,?,?,?)""",
                (int(time.time()), actor, cluster, vmid, node, action, result),
            )

    def get_audit(self, limit: int = 100) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
            )
            return [dict(r) for r in cur.fetchall()]
