"""
Invite tokens.

When an admin invites a user, we generate a high-entropy random token. The
raw token goes into the invite URL given to the invitee; only its SHA-256
*hash* is stored in the database. This means a database read (e.g. a backup
leak) does not expose usable invite links — the same reasoning as not
storing plaintext passwords.

Flow:
  generate_token()        -> (raw_token, token_hash)
  raw token -> invite URL -> emailed or copied to the invitee
  invitee submits raw token + chosen password
  hash_token(raw) is looked up; if it matches a non-expired, non-accepted
  invite, the account is activated.
"""

from __future__ import annotations

import hashlib
import secrets
import time


# 32 random bytes -> 43-char url-safe string. Far beyond brute-force range.
_TOKEN_BYTES = 32


def generate_token() -> tuple[str, str]:
    """Returns (raw_token, token_hash). Store only the hash."""
    raw = secrets.token_urlsafe(_TOKEN_BYTES)
    return raw, hash_token(raw)


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def expiry_from_now(days: int) -> int:
    """Unix-epoch expiry timestamp `days` from now."""
    return int(time.time()) + days * 86400


def invite_state(invite: dict | None) -> str:
    """
    Classify an invite row for the UI / validation:
      missing   - no such invite
      accepted  - already used
      expired   - past its expiry
      valid     - usable right now
    """
    if invite is None:
        return "missing"
    if invite.get("accepted_ts"):
        return "accepted"
    if invite["expires_ts"] < int(time.time()):
        return "expired"
    return "valid"
