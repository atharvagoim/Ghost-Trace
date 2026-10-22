"""Email alerts for new high-risk findings."""

import html
import logging
import smtplib
import ssl
from email.message import EmailMessage

from pymongo.database import Database

from ..config import get_settings
from ..db import Doc, find_one, insert

log = logging.getLogger("ghosttrace.alerts")
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEV_COLOR = {"critical": "#ff4d6d", "high": "#ff8a3d", "medium": "#f5c84c", "low": "#4cc9f0"}


class EmailNotConfigured(Exception):
    pass


def send_email(to: str, subject: str, text_body: str, html_body: str) -> None:
    s = get_settings()
    if not s.smtp_host:
        raise EmailNotConfigured("SMTP is not configured (set SMTP_HOST, SMTP_USER, SMTP_PASSWORD).")
    msg = EmailMessage()
    msg["From"] = s.smtp_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    ctx = ssl.create_default_context()
    if s.smtp_port == 465:
        with smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, context=ctx, timeout=20) as server:
            if s.smtp_user:
                server.login(s.smtp_user, s.smtp_password or "")
            server.send_message(msg)
    else:
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=20) as server:
            if s.smtp_starttls:
                server.starttls(context=ctx)
            if s.smtp_user:
                server.login(s.smtp_user, s.smtp_password or "")
            server.send_message(msg)


def _render(scan: Doc, findings: list[Doc]) -> tuple[str, str]:
    s = get_settings()
    link = f"{s.frontend_url}/app/scans/{scan.id}"
    rows_text = "\n".join(
        f"- [{f.severity.upper()}] {f.credential_type} in {f.repository or ''}{'/' if f.repository else ''}{f.file_path or ''}"
        f":{f.line_number or ''} (risk {f.risk_score:.0f})"
        for f in findings
    )
    text = (
        f"GhostTrace found {len(findings)} new exposed credential(s) while scanning {scan.target}.\n\n{rows_text}\n\n"
        f"Review and rotate them: {link}\n"
    )
    rows_html = "".join(
        f"<tr><td style='padding:8px 10px;border-bottom:1px solid #1d2c45'>"
        f"<span style='color:{SEV_COLOR[f.severity]};font-family:monospace;font-size:12px;text-transform:uppercase'>{f.severity}</span></td>"
        f"<td style='padding:8px 10px;border-bottom:1px solid #1d2c45;color:#e6ecf5'>{html.escape(f.credential_type)}<br>"
        f"<span style='color:#9aabc4;font-family:monospace;font-size:12px'>{html.escape((f.repository or '') + ('/' if f.repository else '') + (f.file_path or ''))}:{f.line_number or ''}</span></td>"
        f"<td style='padding:8px 10px;border-bottom:1px solid #1d2c45;color:#e6ecf5;font-family:monospace'>{f.risk_score:.0f}</td></tr>"
        for f in findings[:25]
    )
    body = f"""<div style="background:#050a14;padding:32px;font-family:Arial,sans-serif">
<div style="max-width:620px;margin:0 auto;background:#08111f;border:1px solid #162a47;border-radius:12px;padding:28px">
<div style="color:#22d3ee;font-family:monospace;font-size:12px;letter-spacing:2px">GHOSTTRACE ALERT</div>
<h2 style="color:#fff;margin:10px 0 6px">{len(findings)} exposed credential(s) found</h2>
<p style="color:#9aabc4;margin:0 0 18px">Target: <b style="color:#e6ecf5">{html.escape(scan.target)}</b></p>
<table style="width:100%;border-collapse:collapse;font-size:14px">{rows_html}</table>
<a href="{link}" style="display:inline-block;margin-top:22px;background:#22d3ee;color:#050a14;padding:11px 20px;border-radius:8px;font-weight:bold;text-decoration:none">Review findings</a>
<p style="color:#6b7f9e;font-size:12px;margin-top:22px">Rotate any exposed secret immediately; deleting the file does not remove it from git history.</p>
</div></div>"""
    return text, body


def alert_for_scan(db: Database, scan: Doc, findings: list[Doc]) -> Doc | None:
    user = find_one(db, "users", {"_id": scan.user_id})
    if user is None or not user.alerts_enabled:
        return None
    threshold = SEV_RANK.get(user.alert_min_severity, 2)
    # Only alert on credentials that have not been seen in an earlier scan.
    earlier = set(db.findings.distinct("fingerprint", {"user_id": user.id, "scan_id": {"$ne": scan.id}}))
    fresh = [
        f for f in findings
        if SEV_RANK[f.severity] >= threshold and f.status == "open" and f.fingerprint not in earlier
    ]
    if not fresh:
        return None
    fresh.sort(key=lambda f: -f.risk_score)
    subject = f"[GhostTrace] {len(fresh)} exposed credential(s) in {scan.target}"
    alert = Doc(user_id=user.id, scan_id=scan.id, channel="email", subject=subject, findings_count=len(fresh), error=None)
    try:
        text, body = _render(scan, fresh)
        send_email(user.email, subject, text, body)
        alert.status = "sent"
    except EmailNotConfigured as exc:
        alert.status = "skipped"
        alert.error = str(exc)
    except Exception as exc:  # noqa: BLE001
        log.warning("Alert email failed: %s", exc)
        alert.status = "failed"
        alert.error = str(exc)
    return insert(db, "alerts", alert)


def send_password_reset(user: Doc, token: str) -> bool:
    """Email a reset link. Returns False if SMTP is not configured (the link is logged for local development)."""
    link = f"{get_settings().frontend_url}/reset-password?token={token}"
    text = (
        "Someone asked to reset the password for your GhostTrace account.\n\n"
        f"Choose a new password (link valid for 30 minutes): {link}\n\n"
        "If this wasn't you, ignore this email; your password stays the same.\n"
    )
    body = f"""<div style="background:#050a14;padding:32px;font-family:Arial,sans-serif">
<div style="max-width:560px;margin:0 auto;background:#08111f;border:1px solid #162a47;border-radius:12px;padding:28px">
<div style="color:#22d3ee;font-family:monospace;font-size:12px;letter-spacing:2px">GHOSTTRACE</div>
<h2 style="color:#fff;margin:10px 0 6px">Reset your password</h2>
<p style="color:#9aabc4">Use the button below to choose a new password. The link is valid for 30 minutes.</p>
<a href="{html.escape(link)}" style="display:inline-block;margin-top:14px;background:#22d3ee;color:#050a14;padding:11px 20px;border-radius:8px;font-weight:bold;text-decoration:none">Reset password</a>
<p style="color:#6b7f9e;font-size:12px;margin-top:22px">If you didn't request this, ignore this email; your password stays the same.</p>
</div></div>"""
    try:
        send_email(user.email, "Reset your GhostTrace password", text, body)
        return True
    except EmailNotConfigured:
        log.warning("SMTP not configured. Password reset link for %s: %s", user.email, link)
        return False
    except Exception as exc:  # noqa: BLE001
        log.warning("Password reset email failed: %s", exc)
        return False
