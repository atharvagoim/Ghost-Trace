"""Public app metadata for the UI, and the endpoint Vercel Cron calls to run monitors."""

import hmac

from fastapi import APIRouter, Header, HTTPException, status

from ..config import get_settings
from ..services.monitoring import run_due_monitors

router = APIRouter(prefix="/api", tags=["system"])


def _cadence(minutes: int) -> str:
    if minutes % 60:
        return f"every {minutes} minutes"
    hours = minutes // 60
    return "every hour" if hours == 1 else f"every {hours} hours"


@router.get("/meta")
def meta() -> dict:
    """Limits the frontend shows to people before they hit them."""
    s = get_settings()
    return {
        "serverless": s.run_scans_inline,
        "max_upload_mb": s.max_upload_mb,
        "monitor_cadence": "daily" if s.run_scans_inline else _cadence(s.monitor_interval_minutes),
        "scan_time_limit_seconds": s.scan_time_budget_seconds or None,
        "persistent_storage": not s.in_memory_db,
        "ai_enabled": s.ai_enabled,
    }


@router.get("/cron/monitors", include_in_schema=False)
def cron_monitors(authorization: str | None = Header(default=None)) -> dict:
    """Vercel Cron sends `Authorization: Bearer $CRON_SECRET`. Without a configured secret the endpoint stays off,
    so nobody else can trigger expensive scans."""
    secret = get_settings().cron_secret
    if not secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Set CRON_SECRET to enable scheduled monitoring.")
    if not authorization or not hmac.compare_digest(authorization, f"Bearer {secret}"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized")
    # Vercel Hobby functions may run for 300 s; stop starting new work at 250 s.
    return run_due_monitors(budget_seconds=250)
