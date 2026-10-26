from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from pymongo.database import Database

from ..config import get_settings
from ..db import Doc, find, find_one, get_db, insert
from ..ratelimit import rate_limit
from ..schemas import FindingOut, GithubScanIn, ScanOut, TextScanIn
from ..security import get_current_user
from ..services.alerts import alert_for_scan
from ..services.scanner import (
    expire_stale_scans, new_scan, persist_hits, run_github_scan, scan_local_repo, scan_text_blob, scan_upload,
)
from ..sources.localrepo import LocalRepoError
from ..sources.github import GitHubError, parse_owner_target, parse_repo_target

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _get_scan(db: Database, user: Doc, scan_id: int) -> Doc:
    scan = find_one(db, "scans", {"_id": scan_id, "user_id": user.id})
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


def _complete_inline(db: Database, scan: Doc, stats) -> Doc:
    now = datetime.now(timezone.utc)
    db.scans.update_one({"_id": scan.id}, {"$set": {"status": "running", "started_at": now}})
    findings = persist_hits(db, scan, stats.hits)
    db.scans.update_one({"_id": scan.id}, {"$set": {
        "files_scanned": stats.files, "status": "completed", "progress": 100,
        "finished_at": datetime.now(timezone.utc), "message": f"Scanned {stats.files} file(s)",
    }})
    scan = find_one(db, "scans", {"_id": scan.id})
    alert_for_scan(db, scan, findings)
    return scan


@router.post("/github", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(rate_limit("scan-github", 30, 3600))])
def start_github_scan(body: GithubScanIn, tasks: BackgroundTasks, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    try:
        target = parse_repo_target(body.target) if body.target_type == "github_repo" else parse_owner_target(body.target)
    except GitHubError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    expire_stale_scans(db, user.id)
    if db.scans.count_documents({"user_id": user.id, "status": {"$in": ["queued", "running"]}}) >= 3:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "You already have 3 scans running. Wait for one to finish.")
    scan = insert(db, "scans", new_scan(user.id, body.target_type, target, message="Queued"))
    if not get_settings().run_scans_inline:
        tasks.add_task(run_github_scan, scan.id, body.include_history)
    # Otherwise (serverless) the browser starts it with POST /api/scans/{id}/run right after this returns.
    return scan


@router.post("/{scan_id}/run", response_model=ScanOut)
def run_scan(scan_id: int, include_history: bool = True, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    """Run a queued GitHub scan inside this request and return it when done. If it is already running or finished
    (for example a background task picked it up first) this returns immediately, so calling it twice is harmless."""
    scan = _get_scan(db, user, scan_id)
    if scan.status == "queued" and scan.target_type.startswith("github"):
        run_github_scan(scan.id, include_history)
        scan = _get_scan(db, user, scan_id)
    return scan


@router.post("/text", response_model=ScanOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(rate_limit("scan-text", 60, 3600))])
def scan_text_content(body: TextScanIn, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    scan = insert(db, "scans", new_scan(user.id, "text", body.label or "Pasted text"))
    return _complete_inline(db, scan, scan_text_blob(body.content, body.label or "pasted.txt", "text"))


@router.post("/upload", response_model=ScanOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(rate_limit("scan-upload", 30, 3600))])
async def scan_file(file: UploadFile = File(...), label: str = Form(default=""), user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    limit_mb = get_settings().max_upload_mb
    data = await file.read(limit_mb * 1024 * 1024 + 1)
    if len(data) > limit_mb * 1024 * 1024:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"Files must be {limit_mb} MB or smaller.")
    name = (file.filename or "upload.txt")[:200]
    label = label.strip()[:200]
    scan = insert(db, "scans", new_scan(user.id, "file", label or name))
    try:
        stats = scan_upload(name, data)
    except Exception as exc:  # bad zip etc.
        error = f"Could not read file: {exc}"
        db.scans.update_one({"_id": scan.id}, {"$set": {"status": "failed", "error": error}})
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, error)
    return _complete_inline(db, scan, stats)


@router.post("/local", response_model=ScanOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(rate_limit("scan-local", 30, 3600))])
async def scan_local_repository(request: Request, name: str = Query("repository.zip", max_length=200), label: str = Query("", max_length=200),
                                history: bool = True, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    """Scan a zipped local repository, including its git history when the zip contains the .git folder.

    The zip is sent as the raw request body (not multipart), read into memory and never written to disk: multipart
    uploads over 1 MB are spooled to a temporary file, which this endpoint avoids. Only masked findings are saved.
    """
    limit = get_settings().max_upload_mb * 1024 * 1024
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"Zips must be {get_settings().max_upload_mb} MB or smaller.")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > limit:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"Zips must be {get_settings().max_upload_mb} MB or smaller.")
    if not buf:
        raise HTTPException(422, "The upload was empty.")
    filename = name.replace("\\", "/").rsplit("/", 1)[-1] or "repository.zip"
    scan = insert(db, "scans", new_scan(user.id, "local_repo", label.strip() or filename.removesuffix(".zip"), message="Reading the zip"))
    try:
        stats, repo_name, had_git = scan_local_repo(filename, bytes(buf), include_history=history)
    except LocalRepoError as exc:
        db.scans.update_one({"_id": scan.id}, {"$set": {"status": "failed", "error": str(exc), "finished_at": datetime.now(timezone.utc)}})
        raise HTTPException(422, str(exc))
    except Exception as exc:  # noqa: BLE001 - corrupt git data etc.
        error = f"Could not read the repository: {exc}"
        db.scans.update_one({"_id": scan.id}, {"$set": {"status": "failed", "error": error, "finished_at": datetime.now(timezone.utc)}})
        raise HTTPException(422, error)
    finally:
        del buf  # drop the archive bytes as soon as the scan is done

    db.scans.update_one({"_id": scan.id}, {"$set": {"status": "running", "started_at": datetime.now(timezone.utc)}})
    findings = persist_hits(db, scan, stats.hits)
    if had_git and history:
        summary = f"Scanned {stats.files} files and {stats.commits} commits of {repo_name}"
    elif had_git:
        summary = f"Scanned {stats.files} files of {repo_name} (history skipped)"
    else:
        summary = f"Scanned {stats.files} files of {repo_name}. No .git folder in the zip, so history was not checked"
    if stats.truncated:
        summary += " (stopped early at the time limit; showing what was found so far)"
    db.scans.update_one({"_id": scan.id}, {"$set": {
        "files_scanned": stats.files, "commits_scanned": stats.commits, "repos_scanned": 1, "status": "completed", "progress": 100,
        "finished_at": datetime.now(timezone.utc), "message": summary,
    }})
    scan = find_one(db, "scans", {"_id": scan.id})
    alert_for_scan(db, scan, findings)
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(limit: int = Query(50, le=200), offset: int = 0, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> list[Doc]:
    expire_stale_scans(db, user.id)
    return find(db, "scans", {"user_id": user.id}, sort=[("created_at", -1)], limit=limit, skip=offset)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    expire_stale_scans(db, user.id)
    return _get_scan(db, user, scan_id)


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
def scan_findings(scan_id: int, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> list[Doc]:
    scan = _get_scan(db, user, scan_id)
    return find(db, "findings", {"scan_id": scan.id}, sort=[("risk_score", -1)])


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: int, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> None:
    scan = _get_scan(db, user, scan_id)
    if scan.status == "running":
        raise HTTPException(status.HTTP_409_CONFLICT, "Wait for the scan to finish before deleting it.")
    db.findings.delete_many({"scan_id": scan.id})
    db.alerts.update_many({"scan_id": scan.id}, {"$set": {"scan_id": None}})
    db.scans.delete_one({"_id": scan.id})
