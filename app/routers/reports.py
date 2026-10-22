import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response, StreamingResponse
from pymongo.database import Database

from ..db import Doc, find, find_one, get_db
from ..security import get_current_user
from ..services.reports import build_pdf
from .findings import filtered_query

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _cell(value):
    """Repository and file names come from other people's code. A leading = + - @ would run as a formula in Excel."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


@router.get("/findings.csv")
def findings_csv(
    severity: str | None = None, category: str | None = None, status_: str | None = Query(None, alias="status"),
    q: str | None = None, scan_id: int | None = None, user: Doc = Depends(get_current_user), db: Database = Depends(get_db),
):
    rows = find(db, "findings", filtered_query(user.id, severity, category, status_, q, None, scan_id), sort=[("risk_score", -1)])
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "severity", "risk_score", "confidence", "credential_type", "category", "status", "repository", "file_path",
                "line", "commit", "history_only", "secret_masked", "first_seen", "url"])
    for f in rows:
        w.writerow([_cell(c) for c in (
            f.id, f.severity, f.risk_score, f.confidence, f.credential_type, f.category, f.status, f.repository or "",
            f.file_path or "", f.line_number or "", f.commit_sha or "", f.in_history_only, f.secret_masked,
            f.first_seen.isoformat(), f.url or "")])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="ghosttrace-findings-{stamp}.csv"'})


@router.get("/summary.pdf")
def summary_pdf(user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Response:
    findings = find(db, "findings", {"user_id": user.id})
    scans = find(db, "scans", {"user_id": user.id})
    pdf = build_pdf(user, findings, scans, "Exposure summary", "All open findings across every scan in this workspace.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="ghosttrace-summary-{stamp}.pdf"'})


@router.get("/scan/{scan_id}.pdf")
def scan_pdf(scan_id: int, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Response:
    scan = find_one(db, "scans", {"_id": scan_id, "user_id": user.id})
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    findings = find(db, "findings", {"scan_id": scan.id})
    sub = f"{scan.target_type.replace('_', ' ').title()}: {scan.target} · {scan.repos_scanned} repos, {scan.files_scanned} files, {scan.commits_scanned} commits"
    pdf = build_pdf(user, findings, [scan], f"Scan #{scan.id}: {scan.target}", sub)
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="ghosttrace-scan-{scan.id}.pdf"'})
