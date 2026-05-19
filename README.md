# Proxmox Manager

A self-hosted management and reporting tool for Proxmox VE virtual machines
and containers. It runs as a service on a VM, talks to one or more Proxmox
clusters over their REST API, records stat history for reporting, and lets
you delegate scoped access to sub-users.

## Why this exists

The stock Proxmox UI is good but ties every action to a Proxmox login. This
tool adds:

- **Cross-cluster view** — every VM/CT from every cluster in one list.
- **Historical reporting** — a poller records CPU/memory/disk/network over
  time into SQLite, so you get trend charts the Proxmox RRD doesn't expose
  as conveniently.
- **Scoped sub-users** — give someone access to *only* the one VM that's
  theirs, as a read-only `viewer` or a `operator` who can power-control it.
  They never see the rest of your infrastructure and never get a Proxmox
  account.

## Architecture

```
Browser ──HTTPS──> nginx (TLS + rate-limit) ──> FastAPI service
                                                  │
                                                  ├─ SQLite: users, grants,
                                                  │          stat history, audit
                                                  └─ poller (every 30s)
                                                        │
                              ┌─────────────────────────┼──────────────┐
                         Cluster A API            Cluster B API   ...   │
```

The browser only ever talks to this app's `/api`. Proxmox API tokens stay
server-side and are never sent to the client.

## Roles

| Role       | Scope                                                       |
|------------|-------------------------------------------------------------|
| `admin`    | Every VM on every cluster; manages users and grants.        |
| `operator` | Only VMs explicitly granted; **can** power-control them.    |
| `viewer`   | Only VMs explicitly granted; **read-only**, no controls.    |

`operator`/`viewer` is set per VM grant, so one user can be operator on one
VM and viewer on another.

## Requirements

- A VM running Debian 12 / Ubuntu 22.04+ with Python 3.10+.
- Network reachability from that VM to each Proxmox cluster on port 8006.
- A Proxmox API token per cluster (see below).

## Creating a Proxmox API token

On each Proxmox cluster, as root in the shell or via the UI
(Datacenter → Permissions → API Tokens):

```sh
# create a dedicated user and a token for it
pveum user add pmxmgr@pve
pveum user token add pmxmgr@pve reporter --privsep 1
# grant privileges. For read-only reporting:        PVEAuditor
# To also allow start/stop/reboot from this app:    PVEVMAdmin
pveum acl modify / --user pmxmgr@pve --role PVEVMAdmin
pveum acl modify / --token 'pmxmgr@pve!reporter' --role PVEVMAdmin
```

The `token add` command prints the secret **once** — copy it into
`clusters.json`. Use `PVEAuditor` instead of `PVEVMAdmin` if you want this
app to be read-only at the Proxmox level regardless of app roles.

## Install

```sh
git clone <this repo> proxmox-manager
cd proxmox-manager
sudo ./scripts/install.sh
```

Then complete the two manual steps the installer prints:

1. **Set the admin password.**
   ```sh
   cd /opt/proxmox-manager
   sudo ./venv/bin/python -m app.hashpw
   ```
   Paste the printed hash into `BOOTSTRAP_ADMIN_PASSWORD_HASH` in
   `/etc/proxmox-manager/proxmox-manager.env`.

2. **Define your clusters** in `/etc/proxmox-manager/clusters.json`
   (the installer seeds it from `clusters.json.example`).

Start it:

```sh
sudo systemctl enable --now proxmox-manager
sudo systemctl status proxmox-manager
journalctl -u proxmox-manager -f      # logs
```

The admin account is created from the bootstrap values on first run only
(when the database has no users). After that, manage users in the UI.

## Public / HTTPS access

The app binds `127.0.0.1` by default and expects a reverse proxy in front.

```sh
sudo apt install nginx certbot python3-certbot-nginx
sudo cp scripts/nginx-proxmox-manager.conf \
        /etc/nginx/sites-available/proxmox-manager
# edit the file: set your hostname
sudo ln -s /etc/nginx/sites-available/proxmox-manager \
           /etc/nginx/sites-enabled/
sudo certbot --nginx -d pmx.example.com
sudo nginx -t && sudo systemctl reload nginx
```

### A note on exposing this to the internet

The app is built to be exposure-tolerant: TLS-only secure cookies, a login
rate limiter (app-side *and* nginx-side), generic auth errors, no Proxmox
secrets in the browser, and 404-not-403 responses that hide VMs a user may
not see. The systemd unit is also sandboxed (`ProtectSystem=strict`, a
dedicated unprivileged user, a single writable data dir).

That said, **the strongest setup still keeps it off the raw public
internet.** Preferred deployments, best first:

1. Reachable only over a VPN (WireGuard/Tailscale).
2. Behind a Cloudflare Tunnel or similar (no open inbound port).
3. A public port, but then *also* add `fail2ban` and consider IP allow-lists.

Hardening the app and hardening the network are two different jobs — do
both.

## Configuration reference

`/etc/proxmox-manager/proxmox-manager.env`

| Variable | Meaning |
|---|---|
| `BIND_HOST` / `BIND_PORT` | Where the app listens. Keep `127.0.0.1` behind nginx. |
| `DB_PATH` | SQLite file for users, grants, history, audit. |
| `CLUSTERS_FILE` | Path to the cluster JSON. |
| `POLL_INTERVAL` | Seconds between stat samples (default 30). |
| `HISTORY_RETENTION_DAYS` | How long stat history is kept (default 30). |
| `SESSION_SECRET` | Cookie signing key; generated by the installer. |
| `COOKIE_SECURE` | `true` over HTTPS (default); `false` only for plain HTTP. |
| `BOOTSTRAP_ADMIN_USER` / `..._PASSWORD_HASH` | First-run admin account. |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW_SECONDS` | Login rate-limit window. |

`/etc/proxmox-manager/clusters.json` — array of clusters; see
`clusters.json.example`. The `id` is permanent: it's part of every VM's
identity in the history database, so don't rename it after data exists.

## Inviting users

Admins don't set passwords for other people. Instead:

1. In **Users & Access**, click **Invite user** and enter a username,
   email, and role.
2. The app generates a one-time invite link valid for `INVITE_EXPIRY_DAYS`
   (default 7).
3. If SMTP is configured, the link is emailed automatically. If not, the
   UI shows the link for you to copy and send yourself — so the feature
   works either way.
4. The invitee opens the link, sets their own password, and the account
   activates. They're logged straight in.

For a pending invite you can **re-send** it (generates a fresh link,
invalidating the old one) or **revoke** it (removes the account). Both are
in the user's *Manage* dialog.

Only the SHA-256 *hash* of each invite token is stored, so a database leak
never exposes usable invite links.

### SMTP configuration

Set these in `proxmox-manager.env` to enable automatic invite emails:

| Variable | Notes |
|---|---|
| `SMTP_HOST` / `SMTP_PORT` | Your mail server. 587 for STARTTLS, 465 for SSL. |
| `SMTP_USER` / `SMTP_PASSWORD` | Leave blank for an unauthenticated relay. |
| `SMTP_FROM` | From address, e.g. `Proxmox Manager <noreply@example.com>`. |
| `SMTP_STARTTLS` | `true` for port 587 (default). |
| `SMTP_USE_SSL` | `true` for implicit TLS on port 465; then set STARTTLS false. |
| `PUBLIC_BASE_URL` | The externally reachable URL — invite links are built from it. |

If `SMTP_HOST`/`SMTP_FROM` are blank the app falls back to the copy-link
flow automatically.

## Usage

- **Virtual Machines** — all VMs you can see, with live status and usage.
  Click a row for detail: live stats, 24-hour history charts, config, and
  (if you have control) power buttons. Every power action asks for
  confirmation.
- **Users & Access** (admin) — invite accounts, assign per-VM grants,
  re-send or revoke pending invites, reset passwords, disable or delete
  users.
- **Audit Log** (admin) — every power action and account change, with who
  and when.

## API

All endpoints are under `/api`. Auth is a signed session cookie from
`POST /api/login`. Highlights:

- `GET /api/vms` — VMs visible to the caller (admins: all; others: granted).
- `GET /api/vms/{cluster}/{node}/{vmid}` — detail.
- `GET /api/vms/{cluster}/{node}/{vmid}/history?hours=24` — stat series.
- `POST /api/vms/{cluster}/{node}/{vmid}/action` — body
  `{"action": "reboot", "type": "qemu", "confirm": true}`. `confirm` must be
  `true`. Allowed actions: `start`, `stop`, `shutdown`, `reboot`,
  `suspend`, `resume`.
- `GET /api/health` — unauthenticated; per-cluster connectivity. Point an
  uptime monitor here.

## Backup

Everything stateful is the one SQLite file at `DB_PATH`. Back it up with:

```sh
sqlite3 /var/lib/proxmox-manager/app.db ".backup '/path/to/backup.db'"
```

## Limitations / roadmap ideas

This v1 deliberately keeps scope tight. Natural next steps:

- VM console (noVNC) proxying.
- Alerting (email/webhook) on thresholds or VM down.
- Create/clone/delete VMs and snapshot management.
- CSV/PDF export of reports.
- Per-action approval (operator requests, admin approves).
- Self-service password reset (forgot-password email).
