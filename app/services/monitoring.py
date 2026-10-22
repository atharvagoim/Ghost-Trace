"""Scheduled re-checks of monitored targets."""

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

from pymongo.database import Database

from ..config import get_settings
from ..db import Doc, find, find_one, get_db, insert
from ..intel.breach import BreachLookupError
from .alerts import EmailNotConfigured, send_email
from .scanner import new_scan, run_github_scan

log = logging.getLogger("ghosttrace.monitoring")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def start_monitor(monitor_id: int) -> int | None:
    """Record a monitor run. Email monitors are checked right away (a few seconds); GitHub monitors get a queued
    scan whose id is returned so the caller decides where it runs (background task, browser request or cron)."""
    db = get_db()
    m = find_one(db, "monitors", {"_id": monitor_id})
    if m is None:
        return None
    db.monitors.update_one({"_id": m.id}, {"$set": {"last_run_at": datetime.now(timezone.utc)}})
    if m.target_type == "email":
        _run_email_monitor(db, m)
        return None
    scan = insert(db, "scans", new_scan(m.user_id, m.target_type, m.target, monitor_id=m.id, message="Queued by monitor"))
    return scan.id


def run_monitor(monitor_id: int, deadline: float | None = None) -> None:
    scan_id = start_monitor(monitor_id)
    if scan_id is not None:
        run_github_scan(scan_id, include_history=True, deadline=deadline)


def _run_email_monitor(db: Database, m: Doc) -> None:
    from ..routers.breach import run_email_check

    user = find_one(db, "users", {"_id": m.user_id})
    previous = find(db, "breach_checks", {"user_id": m.user_id, "email": m.target}, sort=[("checked_at", -1)], limit=1)
    previous = previous[0] if previous else None
    known = {b.get("name") for b in (previous.breaches if previous else [])}
    try:
        check = asyncio.run(run_email_check(db, user, m.target))
    except BreachLookupError as exc:
        log.warning("Email monitor %s failed: %s", m.id, exc)
        return
    new = [b for b in check.breaches if b.get("name") not in known]
    if previous is not None and new and user.alerts_enabled:
        subject = f"[GhostTrace] {m.target} appeared in {len(new)} new breach(es)"
        names = ", ".join(b.get("name") or "?" for b in new)
        alert = Doc(user_id=user.id, scan_id=None, channel="email", subject=subject, findings_count=len(new), error=None)
        try:
            send_email(user.email, subject, f"{m.target} was found in: {names}. Change the password on these services.",
                       f"<p><b>{m.target}</b> was found in: {names}.</p><p>Change the password on these services and anywhere it was reused.</p>")
            alert.status = "sent"
        except EmailNotConfigured as exc:
            alert.status, alert.error = "skipped", str(exc)
        except Exception as exc:  # noqa: BLE001
            alert.status, alert.error = "failed", str(exc)
        insert(db, "alerts", alert)


def run_due_monitors(budget_seconds: float | None = None) -> dict:
    """Run every enabled monitor whose interval has passed. With a budget (serverless cron), stop starting new
    monitors once it is spent; the rest are picked up on the next run because their last_run_at is unchanged."""
    started = time.monotonic()
    deadline = started + budget_seconds if budget_seconds is not None else None
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=get_settings().monitor_interval_minutes)
    due_docs = find(get_db(), "monitors", {"enabled": True, "$or": [{"last_run_at": None}, {"last_run_at": {"$lte": cutoff}}]})
    # Least recently checked first, so a time budget never starves anyone.
    due = [m.id for m in sorted(due_docs, key=lambda m: m.last_run_at or EPOCH)]
    ran = 0
    for mid in due:
        # Leave at least 30 s for a GitHub scan to do something useful before the shared deadline.
        if deadline is not None and time.monotonic() > deadline - 30:
            break
        try:
            run_monitor(mid, deadline)
            ran += 1
        except Exception:  # noqa: BLE001
            log.exception("Monitor %s failed", mid)
    return {"due": len(due), "ran": ran}


def start_scheduler():
    from apscheduler.schedulers.background import BackgroundScheduler

    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(run_due_monitors, "interval", minutes=5, id="monitors", max_instances=1, coalesce=True)
    scheduler.start()
    return scheduler
