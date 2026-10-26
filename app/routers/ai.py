"""AI Security Analyst API. Every route requires a signed-in user and only touches that user's own data."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from pymongo.database import Database

from ..ai import service
from ..ai.groq import AIError
from ..config import get_settings
from ..db import Doc, find, find_one, get_db
from ..security import get_current_user
from ..sources.github import GitHubError, parse_pr_target

router = APIRouter(prefix="/api/ai", tags=["ai"])


class InsightIn(BaseModel):
    refresh: bool = False


class PRReviewIn(BaseModel):
    url: str = Field(min_length=5, max_length=300)
    refresh: bool = False


def _http(exc: AIError) -> HTTPException:
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
    return HTTPException(exc.status_code, exc.message, headers=headers)


def _finding(db: Database, user: Doc, finding_id: int) -> Doc:
    f = find_one(db, "findings", {"_id": finding_id, "user_id": user.id})
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return f


@router.get("/status")
def ai_status(_: Doc = Depends(get_current_user)) -> dict:
    s = get_settings()
    return {
        "enabled": s.ai_enabled, "provider": "Groq", "model": s.groq_model if s.ai_enabled else None,
        "features": ["explain", "remediate", "patch", "pr_review", "posture"],
        "limits": {"finding_per_10min": s.ai_finding_limit_per_10min, "pr_per_hour": s.ai_pr_limit_per_hour,
                   "posture_per_hour": s.ai_posture_limit_per_hour, "daily": s.ai_daily_limit},
    }


@router.get("/findings/{finding_id}/insights")
def finding_insights(finding_id: int, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> dict:
    """Previously generated answers for this finding (shared by every copy of the same secret). Never calls the AI."""
    return service.cached_insights(db, user, _finding(db, user, finding_id))


@router.post("/findings/{finding_id}/{kind}")
async def finding_insight(finding_id: int, kind: Literal["explain", "remediate", "patch"], body: InsightIn | None = None,
                          user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> dict:
    f = _finding(db, user, finding_id)
    try:
        return await service.finding_insight(db, user, f, kind, refresh=bool(body and body.refresh))
    except AIError as exc:
        raise _http(exc)


@router.post("/pr-reviews")
async def create_pr_review(body: PRReviewIn, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> dict:
    try:
        repo, number = parse_pr_target(body.url)
    except GitHubError as exc:
        raise HTTPException(422, str(exc))
    try:
        return await service.pr_review(db, user, repo, number, refresh=body.refresh)
    except GitHubError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    except AIError as exc:
        raise _http(exc)


@router.get("/pr-reviews")
def list_pr_reviews(limit: int = Query(20, ge=1, le=100), user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> list[dict]:
    docs = find(db, "pr_reviews", {"user_id": user.id}, sort=[("created_at", -1)], limit=limit)
    return [{
        "id": d.id, "repo": d.repo, "number": d.number, "title": d.title, "url": d.url, "created_at": d.created_at,
        "verdict": (d.result or {}).get("verdict"), "risk_score": (d.result or {}).get("risk_score"),
        "issues": len((d.result or {}).get("issues", [])), "secrets": len(d.detected_secrets or []),
    } for d in docs]


@router.get("/pr-reviews/{review_id}")
def get_pr_review(review_id: int, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> dict:
    d = find_one(db, "pr_reviews", {"_id": review_id, "user_id": user.id})
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Review not found")
    return {**service.review_out(d), "cached": True}


@router.delete("/pr-reviews/{review_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_pr_review(review_id: int, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> None:
    if db.pr_reviews.delete_one({"_id": review_id, "user_id": user.id}).deleted_count == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Review not found")


@router.get("/posture")
def get_posture(user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> dict | None:
    return service.latest_posture(db, user)


@router.post("/posture")
async def create_posture(user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> dict:
    try:
        return await service.posture(db, user)
    except AIError as exc:
        raise _http(exc)
