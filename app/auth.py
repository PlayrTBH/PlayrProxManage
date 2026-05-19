"""
Authentication and authorization.

Authentication: signed, http-only session cookie. Passwords are bcrypt
hashes; plaintext is never stored. A small in-memory rate limiter slows
brute-force login attempts — important since the app may face the public web.

Authorization: helpers that resolve, for a given user and VM, whether they
may *see* it and whether they may *control* it.

  - admin     : sees and controls every VM on every cluster
  - operator  : per-VM grant with role 'operator' -> see + control
  - viewer    : per-VM grant with role 'viewer'   -> see only

This module is the single chokepoint for "is this user allowed to..." —
every VM route depends on it, so authorization can't be forgotten per-route.
"""

from __future__ import annotations

import threading
import time

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings
from .database import ROLE_ADMIN, ROLE_OPERATOR, STATUS_ACTIVE, Database

SESSION_COOKIE = "pmx_session"
SESSION_MAX_AGE = 60 * 60 * 12  # 12 hours

_serializer = URLSafeTimedSerializer(settings.session_secret, salt="pmx-session")

# The Database instance is injected at startup by main.py.
_db: Database | None = None


def bind_database(db: Database) -> None:
    global _db
    _db = db


def _require_db() -> Database:
    if _db is None:
        raise RuntimeError("auth module used before bind_database()")
    return _db


# --------------------------------------------------------------------------
# passwords
# --------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


# --------------------------------------------------------------------------
# login rate limiting (in-memory, per username+IP)
# --------------------------------------------------------------------------

class _RateLimiter:
    def __init__(self, max_attempts: int, window: int):
        self._max = max_attempts
        self._window = window
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        """True if another attempt is allowed for this key."""
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < self._window]
            self._hits[key] = hits
            return len(hits) < self._max

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._hits.setdefault(key, []).append(time.time())

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


login_limiter = _RateLimiter(
    settings.login_max_attempts, settings.login_window_seconds
)


# --------------------------------------------------------------------------
# authentication
# --------------------------------------------------------------------------

def authenticate(username: str, password: str) -> dict | None:
    """Returns the user row on success, None on failure."""
    db = _require_db()
    user = db.get_user(username)
    if user is None:
        # Dummy hash check to keep timing uniform whether or not the
        # username exists (avoids username enumeration).
        bcrypt.checkpw(b"x", bcrypt.gensalt())
        return None
    # Only 'active' accounts may log in. 'invited' users have no password
    # yet; 'disabled' users are administratively blocked.
    if user["status"] != STATUS_ACTIVE:
        bcrypt.checkpw(b"x", bcrypt.gensalt())
        return None
    if not user["password_hash"]:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def issue_session(user: dict) -> str:
    return _serializer.dumps(
        {"uid": user["id"], "u": user["username"], "iat": int(time.time())}
    )


def _read_session(token: str) -> dict:
    return _serializer.loads(token, max_age=SESSION_MAX_AGE)


# --------------------------------------------------------------------------
# FastAPI dependencies
# --------------------------------------------------------------------------

def current_user(request: Request) -> dict:
    """Dependency: returns the fresh user row, or raises 401."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    try:
        data = _read_session(token)
    except SignatureExpired:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")
    except BadSignature:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid session")

    # Re-load the user every request so a disabled/deleted account loses
    # access immediately rather than at session expiry.
    db = _require_db()
    user = db.get_user_by_id(data["uid"])
    if user is None or user["status"] != STATUS_ACTIVE:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account unavailable")
    return user


def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["role"] != ROLE_ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin role required")
    return user


# --------------------------------------------------------------------------
# authorization helpers — the per-VM access chokepoint
# --------------------------------------------------------------------------

def can_view(user: dict, cluster: str, vmid: int) -> bool:
    if user["role"] == ROLE_ADMIN:
        return True
    return _require_db().get_grant(user["id"], cluster, vmid) is not None


def can_control(user: dict, cluster: str, vmid: int) -> bool:
    if user["role"] == ROLE_ADMIN:
        return True
    grant = _require_db().get_grant(user["id"], cluster, vmid)
    return grant == ROLE_OPERATOR


def assert_can_view(user: dict, cluster: str, vmid: int) -> None:
    if not can_view(user, cluster, vmid):
        # 404 rather than 403: don't reveal that a VM the user can't see
        # even exists.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VM not found")


def assert_can_control(user: dict, cluster: str, vmid: int) -> None:
    # Must be able to see it first (404 hides existence)...
    assert_can_view(user, cluster, vmid)
    # ...then 403 if they can see but not control.
    if not can_control(user, cluster, vmid):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "You have read-only access to this VM"
        )


def visible_vm_keys(user: dict) -> set[tuple[str, int]] | None:
    """
    Set of (cluster, vmid) the user may see. Returns None for admins, which
    callers treat as 'no filter — everything'.
    """
    if user["role"] == ROLE_ADMIN:
        return None
    return {
        (g["cluster"], g["vmid"])
        for g in _require_db().list_grants(user["id"])
    }
