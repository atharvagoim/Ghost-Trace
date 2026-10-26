from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.database import Database

from ..config import get_settings
from ..db import Doc, find, get_db, insert
from ..schemas import AlertOut
from ..security import get_current_user
from ..services.alerts import EmailNotConfigured, send_email

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> list[Doc]:
    return find(db, "alerts", {"user_id": user.id}, sort=[("created_at", -1)], limit=200)


@router.get("/config")
def alert_config(_: Doc = Depends(get_current_user)) -> dict:
    s = get_settings()
    return {"email_configured": bool(s.smtp_host), "github_token_configured": bool(s.github_token),
            "breach_source": "Have I Been Pwned" if s.hibp_api_key else "XposedOrNot", "ai_configured": s.ai_enabled, "ai_model": s.groq_model if s.ai_enabled else None}


@router.post("/test")
def send_test(user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> dict:
    subject = "[GhostTrace] Test alert"
    alert = Doc(user_id=user.id, scan_id=None, channel="email", subject=subject, findings_count=0, error=None)
    try:
        send_email(user.email, subject, "Email alerts from GhostTrace are working.",
                   "<p style='font-family:Arial'>Email alerts from <b>GhostTrace</b> are working.</p>")
        alert.status = "sent"
    except EmailNotConfigured as exc:
        alert.status, alert.error = "skipped", str(exc)
    except Exception as exc:  # noqa: BLE001
        alert.status, alert.error = "failed", str(exc)
    insert(db, "alerts", alert)
    if alert.status != "sent":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, alert.error)
    return {"status": "sent", "to": user.email}
