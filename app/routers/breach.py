from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.database import Database

from ..db import Doc, find, get_db, insert
from ..intel.breach import BreachLookupError, check_email, password_strength, pwned_password_count
from ..schemas import BreachEmailIn, BreachOut, PasswordCheckIn, PasswordCheckOut
from ..security import get_current_user

router = APIRouter(prefix="/api/breach", tags=["breach"])


async def run_email_check(db: Database, user: Doc, email: str) -> Doc:
    result = await check_email(email)
    return insert(db, "breach_checks", {
        "user_id": user.id, "email": email.lower(), "breach_count": len(result["breaches"]), "breaches": result["breaches"],
        "exposed_data": result["data_classes"], "risk_score": result["risk"], "source": result["source"],
        "checked_at": datetime.now(timezone.utc),
    })


@router.post("/email", response_model=BreachOut)
async def email_check(body: BreachEmailIn, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    try:
        return await run_email_check(db, user, body.email)
    except BreachLookupError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))


@router.get("/history", response_model=list[BreachOut])
def history(user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> list[Doc]:
    return find(db, "breach_checks", {"user_id": user.id}, sort=[("checked_at", -1)], limit=100)


@router.post("/password", response_model=PasswordCheckOut)
async def password_check(body: PasswordCheckIn, _: Doc = Depends(get_current_user)) -> PasswordCheckOut:
    try:
        count = await pwned_password_count(body.password)
    except BreachLookupError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    score, label, feedback = password_strength(body.password)
    if count:
        score, label = 0, "Compromised"
        feedback.insert(0, f"This password appears {count:,} times in known breaches. Never use it.")
    return PasswordCheckOut(pwned=count > 0, count=count, strength=score, strength_label=label, feedback=feedback)
