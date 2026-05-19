"""
Proxmox Manager — main FastAPI application.

Route groups:
  /api/login /api/logout /api/me        session auth
  /api/clusters                         configured clusters (names only)
  /api/vms                              VM/CT list, filtered to what you may see
  /api/vms/{cluster}/{node}/{vmid}      VM detail (status + config)
  /api/vms/.../history                  historical series for charts
  /api/vms/.../action                   POST a power action (needs confirm)
  /api/audit                            recent action log (admin)
  /api/admin/users ...                  user + grant management (admin)
  /api/health                           service + per-cluster connectivity
  /                                     single-page UI

Every VM route runs through the auth module's grant checks, so a sub-user
can only ever see or touch VMs explicitly assigned to them.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auth, invites, mailer
from .config import settings
from .database import (
    GRANT_ROLES,
    ROLE_ADMIN,
    STATUS_ACTIVE,
    STATUS_DISABLED,
    STATUS_INVITED,
    VALID_ROLES,
    Database,
)
from .poller import Poller
from .proxmox import ClusterRegistry, ProxmoxError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("app")

db: Database
registry: ClusterRegistry
poller: Poller


def _bootstrap_admin(database: Database) -> None:
    """Create the first admin account on a fresh database only."""
    if database.count_users() > 0:
        return
    database.create_user(
        settings.bootstrap_admin_user,
        settings.bootstrap_admin_password_hash,
        ROLE_ADMIN,
    )
    log.info(
        "Bootstrapped admin account '%s' (no users existed)",
        settings.bootstrap_admin_user,
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    global db, registry, poller
    db = Database(settings.db_path)
    auth.bind_database(db)
    _bootstrap_admin(db)
    registry = ClusterRegistry(settings.clusters)
    poller = Poller(
        registry, db, settings.poll_interval, settings.history_retention_days
    )
    poller.start()
    log.info(
        "Proxmox Manager up on %s:%s — %d cluster(s)",
        settings.bind_host, settings.bind_port, len(settings.clusters),
    )
    yield
    await poller.stop()


app = FastAPI(title="Proxmox Manager", version="1.0", lifespan=lifespan)


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        max_age=auth.SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
    )


# --------------------------------------------------------------------------
# auth routes
# --------------------------------------------------------------------------

class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/api/login")
async def login(body: LoginBody, request: Request, response: Response):
    # Rate-limit by username + client IP to blunt brute force.
    client_ip = request.client.host if request.client else "?"
    rl_key = f"{body.username}|{client_ip}"
    if not auth.login_limiter.check(rl_key):
        raise HTTPException(
            status_code=429,
            detail="Too many failed attempts. Try again shortly.",
        )

    user = auth.authenticate(body.username, body.password)
    if user is None:
        auth.login_limiter.record_failure(rl_key)
        # Deliberately generic — don't reveal which half was wrong.
        raise HTTPException(status_code=401, detail="Invalid credentials")

    auth.login_limiter.reset(rl_key)
    _set_session_cookie(response, auth.issue_session(user))
    db.add_audit(user["username"], "login", "ok")
    return {"ok": True, "user": user["username"], "role": user["role"]}


@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie(auth.SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/me")
async def me(user: dict = Depends(auth.current_user)):
    return {"user": user["username"], "role": user["role"]}


# --------------------------------------------------------------------------
# clusters
# --------------------------------------------------------------------------

@app.get("/api/clusters")
async def list_clusters(user: dict = Depends(auth.current_user)):
    # Only id + display name reach the browser — never tokens.
    return {
        "clusters": [
            {"id": c.id, "name": c.name} for c in settings.clusters
        ]
    }


# --------------------------------------------------------------------------
# VM listing & detail
# --------------------------------------------------------------------------

def _shape_vm(cluster_id: str, r: dict) -> dict:
    return {
        "cluster": cluster_id,
        "vmid": r.get("vmid"),
        "name": r.get("name"),
        "node": r.get("node"),
        "type": r.get("type"),          # qemu | lxc
        "status": r.get("status"),
        "cpu": r.get("cpu"),
        "maxcpu": r.get("maxcpu"),
        "mem": r.get("mem"),
        "maxmem": r.get("maxmem"),
        "maxdisk": r.get("maxdisk"),
        "uptime": r.get("uptime"),
    }


@app.get("/api/vms")
async def list_vms(user: dict = Depends(auth.current_user)):
    """
    Every VM the caller is allowed to see, across all clusters.
    Admins see everything; sub-users see only their granted VMs.
    """
    allowed = auth.visible_vm_keys(user)  # None == admin, no filter
    vms: list[dict] = []
    errors: dict[str, str] = {}

    for client in registry.all():
        try:
            resources = await client.get_cluster_resources(kind="vm")
        except ProxmoxError as exc:
            errors[client.cluster_id] = str(exc)
            log.warning("VM list failed for %s: %s", client.cluster_id, exc)
            continue
        for r in resources:
            key = (client.cluster_id, r.get("vmid"))
            if allowed is not None and key not in allowed:
                continue
            vms.append(_shape_vm(client.cluster_id, r))

    vms.sort(key=lambda v: (v["cluster"], v["node"] or "", v["vmid"] or 0))
    return {"vms": vms, "errors": errors}


@app.get("/api/vms/{cluster}/{node}/{vmid}")
async def vm_detail(
    cluster: str,
    node: str,
    vmid: int,
    type: str = "qemu",
    user: dict = Depends(auth.current_user),
):
    auth.assert_can_view(user, cluster, vmid)
    try:
        client = registry.get(cluster)
        status_data = await client.get_vm_status(node, vmid, kind=type)
        config = await client.get_vm_config(node, vmid, kind=type)
    except ProxmoxError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"status": status_data, "config": config}


@app.get("/api/vms/{cluster}/{node}/{vmid}/history")
async def vm_history(
    cluster: str,
    node: str,
    vmid: int,
    hours: int = 24,
    user: dict = Depends(auth.current_user),
):
    auth.assert_can_view(user, cluster, vmid)
    hours = max(1, min(hours, 24 * 90))  # clamp to retention-ish bounds
    since = int(time.time()) - hours * 3600
    return {
        "cluster": cluster,
        "vmid": vmid,
        "hours": hours,
        "samples": db.get_history(cluster, vmid, since),
    }


# --------------------------------------------------------------------------
# power actions
# --------------------------------------------------------------------------

class ActionBody(BaseModel):
    action: str
    type: str = "qemu"
    confirm: bool = False


@app.post("/api/vms/{cluster}/{node}/{vmid}/action")
async def vm_action(
    cluster: str,
    node: str,
    vmid: int,
    body: ActionBody,
    user: dict = Depends(auth.current_user),
):
    # Must have *control* (admin or operator grant) — viewers are rejected.
    auth.assert_can_control(user, cluster, vmid)
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Action requires confirm=true")

    try:
        client = registry.get(cluster)
        upid = await client.vm_action(node, vmid, body.action, kind=body.type)
        db.add_audit(
            user["username"], body.action, "submitted",
            cluster=cluster, vmid=vmid, node=node,
        )
        log.info(
            "%s -> %s on %s/%s vm %s", user["username"], body.action,
            cluster, node, vmid,
        )
        return {"ok": True, "upid": upid}
    except ProxmoxError as exc:
        db.add_audit(
            user["username"], body.action, f"error: {exc}",
            cluster=cluster, vmid=vmid, node=node,
        )
        raise HTTPException(status_code=502, detail=str(exc))


# --------------------------------------------------------------------------
# audit (admin only)
# --------------------------------------------------------------------------

@app.get("/api/audit")
async def audit(limit: int = 100, user: dict = Depends(auth.require_admin)):
    return {"entries": db.get_audit(limit=min(limit, 500))}


# --------------------------------------------------------------------------
# admin: user & grant management
# --------------------------------------------------------------------------

class InviteUserBody(BaseModel):
    """Admin invites a user — no password, they set it via the invite link."""
    username: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=254)
    role: str


class AcceptInviteBody(BaseModel):
    """Invitee accepts: raw token from the link + their chosen password."""
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(min_length=8, max_length=256)


class PasswordBody(BaseModel):
    password: str = Field(min_length=8, max_length=256)


class GrantBody(BaseModel):
    cluster: str
    vmid: int
    grant_role: str


@app.get("/api/admin/users")
async def admin_list_users(user: dict = Depends(auth.require_admin)):
    users = db.list_users()
    for u in users:
        u["grants"] = db.list_grants(u["id"])
        # Attach pending-invite info so the UI can show resend/revoke.
        if u["status"] == STATUS_INVITED:
            inv = db.get_invite_for_user(u["id"])
            u["invite_state"] = invites.invite_state(inv)
            u["invite_expires_ts"] = inv["expires_ts"] if inv else None
        else:
            u["invite_state"] = None
    return {"users": users}


async def _create_and_send_invite(user_id: int, username: str,
                                   email: str) -> dict:
    """
    Generate a fresh invite for an existing 'invited' user, store its hash,
    and try to email it. Returns a dict the API hands back to the admin:
    on email success just {ok}; on email failure also the raw link so the
    admin can deliver it manually.
    """
    raw, token_hash = invites.generate_token()
    expires = invites.expiry_from_now(settings.invite_expiry_days)
    db.create_invite(user_id, token_hash, expires)

    invite_url = f"{settings.public_base_url}/invite/{raw}"
    sent = await mailer.send_invite(
        email, username, invite_url, settings.invite_expiry_days
    )
    result = {"ok": True, "emailed": sent}
    if not sent:
        # SMTP unconfigured or send failed — surface the link to the admin.
        result["invite_url"] = invite_url
        result["note"] = (
            "Email was not sent (SMTP not configured or failed). "
            "Copy this link to the user manually."
        )
    return result


@app.post("/api/admin/users/invite")
async def admin_invite_user(
    body: InviteUserBody, user: dict = Depends(auth.require_admin)
):
    """Create an account in 'invited' state and send an invite link."""
    if body.role not in VALID_ROLES:
        raise HTTPException(400, f"role must be one of {sorted(VALID_ROLES)}")
    if "@" not in body.email:
        raise HTTPException(400, "A valid email address is required")
    if db.get_user(body.username) is not None:
        raise HTTPException(409, "Username already exists")

    # password_hash stays empty until the invite is accepted.
    uid = db.create_user(
        body.username, "", body.role,
        email=body.email, status=STATUS_INVITED,
    )
    db.add_audit(user["username"], "invite_user", body.username)
    result = await _create_and_send_invite(uid, body.username, body.email)
    result["id"] = uid
    return result


@app.post("/api/admin/users/{user_id}/invite/resend")
async def admin_resend_invite(
    user_id: int, user: dict = Depends(auth.require_admin)
):
    """Regenerate and re-send an invite (old link is invalidated)."""
    target = db.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(404, "No such user")
    if target["status"] != STATUS_INVITED:
        raise HTTPException(400, "User has already accepted their invite")
    db.add_audit(user["username"], "resend_invite", target["username"])
    return await _create_and_send_invite(
        user_id, target["username"], target["email"] or ""
    )


@app.delete("/api/admin/users/{user_id}/invite")
async def admin_revoke_invite(
    user_id: int, user: dict = Depends(auth.require_admin)
):
    """
    Revoke a pending invite. The invited account is deleted entirely, since
    an 'invited' user with no live invite can never log in anyway.
    """
    target = db.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(404, "No such user")
    if target["status"] != STATUS_INVITED:
        raise HTTPException(400, "User has already accepted their invite")
    db.delete_user(user_id)  # cascades to the invite row
    db.add_audit(user["username"], "revoke_invite", target["username"])
    return {"ok": True}


# ---- public invite-acceptance endpoints (no auth) -------------------------

@app.get("/api/invite/{token}")
async def invite_lookup(token: str):
    """
    Check an invite token. Public, but reveals only whether the token is
    usable and the username it's for — never anything else.
    """
    inv = db.get_invite_by_token(invites.hash_token(token))
    st = invites.invite_state(inv)
    if st != "valid":
        return {"valid": False, "reason": st}
    target = db.get_user_by_id(inv["user_id"])
    if target is None or target["status"] != STATUS_INVITED:
        return {"valid": False, "reason": "missing"}
    return {"valid": True, "username": target["username"]}


@app.post("/api/invite/accept")
async def invite_accept(body: AcceptInviteBody, response: Response):
    """
    Accept an invite: set the password, activate the account, consume the
    invite, and log the user straight in.
    """
    inv = db.get_invite_by_token(invites.hash_token(body.token))
    if invites.invite_state(inv) != "valid":
        raise HTTPException(400, "This invite link is invalid or expired")
    target = db.get_user_by_id(inv["user_id"])
    if target is None or target["status"] != STATUS_INVITED:
        raise HTTPException(400, "This invite is no longer valid")

    db.set_user_password(target["id"], auth.hash_password(body.password))
    db.set_user_status(target["id"], STATUS_ACTIVE)
    db.mark_invite_accepted(inv["id"])
    db.add_audit(target["username"], "accept_invite", "ok")

    # Log them in immediately so there's no extra login step.
    fresh = db.get_user_by_id(target["id"])
    _set_session_cookie(response, auth.issue_session(fresh))
    return {"ok": True, "user": fresh["username"], "role": fresh["role"]}


@app.post("/api/admin/users/{user_id}/password")
async def admin_set_password(
    user_id: int, body: PasswordBody, user: dict = Depends(auth.require_admin)
):
    """Admin password reset for an already-active account."""
    target = db.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(404, "No such user")
    if target["status"] == STATUS_INVITED:
        raise HTTPException(
            400, "User hasn't accepted their invite yet — resend it instead"
        )
    db.set_user_password(user_id, auth.hash_password(body.password))
    db.add_audit(user["username"], "reset_password", str(user_id))
    return {"ok": True}


@app.post("/api/admin/users/{user_id}/status")
async def admin_set_status(
    user_id: int, disabled: bool, user: dict = Depends(auth.require_admin)
):
    """Enable or disable an active account."""
    target = db.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(404, "No such user")
    if target["id"] == user["id"] and disabled:
        raise HTTPException(400, "You cannot disable your own account")
    if target["status"] == STATUS_INVITED:
        raise HTTPException(400, "Invited users have no active status to change")
    db.set_user_status(
        user_id, STATUS_DISABLED if disabled else STATUS_ACTIVE
    )
    db.add_audit(
        user["username"],
        "disable_user" if disabled else "enable_user",
        str(user_id),
    )
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(
    user_id: int, user: dict = Depends(auth.require_admin)
):
    target = db.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(404, "No such user")
    if target["id"] == user["id"]:
        raise HTTPException(400, "You cannot delete your own account")
    db.delete_user(user_id)
    db.add_audit(user["username"], "delete_user", target["username"])
    return {"ok": True}


@app.post("/api/admin/users/{user_id}/grants")
async def admin_add_grant(
    user_id: int, body: GrantBody, user: dict = Depends(auth.require_admin)
):
    if db.get_user_by_id(user_id) is None:
        raise HTTPException(404, "No such user")
    if body.grant_role not in GRANT_ROLES:
        raise HTTPException(400, f"grant_role must be one of {sorted(GRANT_ROLES)}")
    if body.cluster not in settings.cluster_map():
        raise HTTPException(400, f"Unknown cluster '{body.cluster}'")
    db.add_grant(user_id, body.cluster, body.vmid, body.grant_role)
    db.add_audit(
        user["username"], "add_grant",
        f"user={user_id} {body.cluster}/{body.vmid} {body.grant_role}",
    )
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}/grants")
async def admin_remove_grant(
    user_id: int,
    cluster: str,
    vmid: int,
    user: dict = Depends(auth.require_admin),
):
    db.remove_grant(user_id, cluster, vmid)
    db.add_audit(
        user["username"], "remove_grant", f"user={user_id} {cluster}/{vmid}"
    )
    return {"ok": True}


# --------------------------------------------------------------------------
# health
# --------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    """Unauthenticated — safe target for an uptime monitor."""
    cluster_status = {}
    for client in registry.all():
        try:
            await client.ping()
            cluster_status[client.cluster_id] = {"connected": True, "error": None}
        except ProxmoxError as exc:
            cluster_status[client.cluster_id] = {
                "connected": False, "error": str(exc),
            }
    return JSONResponse(
        {
            "service": "ok",
            "clusters": cluster_status,
            "poller_last_run": poller.last_run_ts,
            "poller_cluster_errors": poller.cluster_errors,
        }
    )


# --------------------------------------------------------------------------
# static UI
# --------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/")
async def index():
    return FileResponse("app/static/index.html")


@app.get("/invite/{token}")
async def invite_page(token: str):
    # The page is static; it reads the token from its own URL and calls
    # /api/invite/{token} then /api/invite/accept. Token isn't used here.
    return FileResponse("app/static/invite.html")
