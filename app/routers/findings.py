import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pymongo.database import Database

from ..db import Doc, find, find_one, get_db
from ..schemas import FindingOut, FindingPage, FindingUpdate
from ..security import get_current_user

router = APIRouter(prefix="/api/findings", tags=["findings"])

SORTS = {
    "risk": [("risk_score", -1), ("_id", -1)],
    "newest": [("first_seen", -1), ("_id", -1)],
    "oldest": [("first_seen", 1), ("_id", -1)],
}


def filtered_query(user_id: int, severity: str | None, category: str | None, status_: str | None, q: str | None,
                   repository: str | None, scan_id: int | None) -> dict:
    query: dict = {"user_id": user_id}
    if severity:
        query["severity"] = {"$in": severity.split(",")}
    if category:
        query["category"] = {"$in": category.split(",")}
    if status_:
        query["status"] = {"$in": status_.split(",")}
    if repository:
        query["repository"] = repository
    if scan_id:
        query["scan_id"] = scan_id
    if q and q.strip():
        pattern = {"$regex": re.escape(q.strip()), "$options": "i"}  # escaped: user input is matched literally
        query["$or"] = [{field: pattern} for field in ("credential_type", "repository", "file_path", "secret_masked")]
    return query


@router.get("", response_model=FindingPage)
def list_findings(
    severity: str | None = None, category: str | None = None, status_: str | None = Query(None, alias="status"),
    q: str | None = None, repository: str | None = None, scan_id: int | None = None,
    sort: Literal["risk", "newest", "oldest"] = "risk", page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
    user: Doc = Depends(get_current_user), db: Database = Depends(get_db),
) -> FindingPage:
    query = filtered_query(user.id, severity, category, status_, q, repository, scan_id)
    total = db.findings.count_documents(query)
    items = find(db, "findings", query, sort=SORTS[sort], limit=page_size, skip=(page - 1) * page_size)
    return FindingPage(items=[FindingOut.model_validate(f) for f in items], total=total, page=page, page_size=page_size)


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    f = find_one(db, "findings", {"_id": finding_id, "user_id": user.id})
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return f


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: int, body: FindingUpdate, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    f = get_finding(finding_id, user, db)
    # Apply the triage decision to every occurrence of the same secret.
    db.findings.update_many({"user_id": user.id, "fingerprint": f.fingerprint}, {"$set": {"status": body.status}})
    f.status = body.status
    return f
