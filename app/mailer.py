"""
Email delivery over SMTP.

Used to send account-invite links. SMTP is configured via environment
variables (see config.py). If SMTP is not configured, send_invite() returns
False and the caller falls back to showing the admin the raw link to send
manually — so the invite feature still works without a mail server.

Uses only the Python standard library (smtplib / email), so no extra
dependency. Runs the blocking smtplib call in a thread so it doesn't stall
the async event loop.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage

from .config import settings

log = logging.getLogger("email")


def smtp_configured() -> bool:
    """True if enough SMTP settings are present to attempt delivery."""
    return bool(settings.smtp_host and settings.smtp_from)


def _send_blocking(to_addr: str, subject: str, text: str, html: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = to_addr
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    if settings.smtp_use_ssl:
        # Implicit TLS (typically port 465).
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(
            settings.smtp_host, settings.smtp_port, context=ctx, timeout=20
        ) as srv:
            if settings.smtp_user:
                srv.login(settings.smtp_user, settings.smtp_password)
            srv.send_message(msg)
    else:
        # Plain connection, optionally upgraded with STARTTLS (port 587).
        with smtplib.SMTP(
            settings.smtp_host, settings.smtp_port, timeout=20
        ) as srv:
            srv.ehlo()
            if settings.smtp_starttls:
                srv.starttls(context=ssl.create_default_context())
                srv.ehlo()
            if settings.smtp_user:
                srv.login(settings.smtp_user, settings.smtp_password)
            srv.send_message(msg)


async def send_invite(
    to_addr: str, username: str, invite_url: str, expiry_days: int
) -> bool:
    """
    Send an invite email. Returns True on success, False if SMTP is not
    configured or sending failed (the caller then shows the link instead).
    """
    if not smtp_configured():
        return False

    subject = "You've been invited to Proxmox Manager"
    text = (
        f"Hello,\n\n"
        f"An account '{username}' has been created for you on Proxmox "
        f"Manager.\n\nTo set your password and activate it, open:\n\n"
        f"{invite_url}\n\n"
        f"This link expires in {expiry_days} days.\n\n"
        f"If you weren't expecting this, you can ignore this email."
    )
    html = f"""\
<html><body style="font-family:sans-serif;color:#222">
  <h2 style="color:#e8862e">Proxmox Manager</h2>
  <p>An account <b>{username}</b> has been created for you.</p>
  <p>
    <a href="{invite_url}"
       style="background:#e8862e;color:#fff;padding:10px 18px;
              border-radius:6px;text-decoration:none;display:inline-block">
      Set your password
    </a>
  </p>
  <p style="color:#666;font-size:13px">
    Or paste this link into your browser:<br>
    <span style="font-family:monospace">{invite_url}</span>
  </p>
  <p style="color:#666;font-size:13px">
    This link expires in {expiry_days} days. If you weren't expecting
    this, you can ignore this email.
  </p>
</body></html>"""

    try:
        # smtplib is blocking; keep it off the event loop.
        await asyncio.to_thread(
            _send_blocking, to_addr, subject, text, html
        )
        log.info("Invite email sent to %s", to_addr)
        return True
    except Exception as exc:  # noqa: BLE001
        # Don't raise: the caller falls back to the copy-link path.
        log.warning("Invite email to %s failed: %s", to_addr, exc)
        return False
