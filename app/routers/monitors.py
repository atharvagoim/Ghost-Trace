from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from ..config import get_settings
from ..db import Doc, find, find_one, get_db, insert
from ..schemas import MonitorIn, MonitorOut, MonitorRunOut, MonitorUpdate
from ..security import get_current_user
from ..services.monitoring import run_monitor, start_monitor
from ..services.scanner import run_github_scan
from ..sources.github import GitHubError, parse_owner_target, parse_repo_target

MAX_MONITORS = 25

router = APIRouter(prefix="/api/monitors", tags=["monitors"])


def _normalize(body: MonitorIn) -> str:
    if body.target_type == "email":
        if "@" not in body.target:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Enter a valid email address.")
        return body.target.strip().lower()
    try:
        return parse_repo_target(body.target) if body.target_type == "github_repo" else parse_owner_target(body.target)
    except GitHubError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))


def _get(db: Database, user: Doc, monitor_id: int) -> Doc:
    m = find_one(db, "monitors", {"_id": monitor_id, "user_id": user.id})
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Monitor not found")
    return m


@router.get("", response_model=list[MonitorOut])
def list_monitors(user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> list[Doc]:
    return find(db, "monitors", {"user_id": user.id}, sort=[("created_at", -1)])


@router.post("", response_model=MonitorOut, status_code=status.HTTP_201_CREATED)
def create_monitor(body: MonitorIn, tasks: BackgroundTasks, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    target = _normalize(body)
    if db.monitors.count_documents({"user_id": user.id}) >= MAX_MONITORS:
        raise HTTPException(status.HTTP_409_CONFLICT, f"You can watch up to {MAX_MONITORS} targets. Remove one to add another.")
    duplicate = HTTPException(status.HTTP_409_CONFLICT, "You are already monitoring this target.")
    if find_one(db, "monitors", {"user_id": user.id, "target_type": body.target_type, "target": target}):
        raise duplicate
    try:
        m = insert(db, "monitors", {"user_id": user.id, "target_type": body.target_type, "target": target, "enabled": True, "last_run_at": None})
    except DuplicateKeyError:
        raise duplicate
    if not get_settings().run_scans_inline:
        tasks.add_task(run_monitor, m.id)  # baseline run
    # Serverless: the browser calls POST /{id}/run next and follows the baseline scan it returns.
    return m


@router.patch("/{monitor_id}", response_model=MonitorOut)
def update_monitor(monitor_id: int, body: MonitorUpdate, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> Doc:
    m = _get(db, user, monitor_id)
    db.monitors.update_one({"_id": m.id}, {"$set": {"enabled": body.enabled}})
    m.enabled = body.enabled
    return m


@router.post("/{monitor_id}/run", response_model=MonitorRunOut, status_code=status.HTTP_202_ACCEPTED)
def run_now(monitor_id: int, tasks: BackgroundTasks, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> MonitorRunOut:
    """Email monitors are checked immediately. GitHub monitors queue a scan and return its id; the scan page runs it
    (serverless) or a background task does (regular server)."""
    m = _get(db, user, monitor_id)
    scan_id = start_monitor(m.id)
    if scan_id is not None and not get_settings().run_scans_inline:
        tasks.add_task(run_github_scan, scan_id, True)
    return MonitorRunOut(monitor=MonitorOut.model_validate(_get(db, user, monitor_id)), scan_id=scan_id)


@router.delete("/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_monitor(monitor_id: int, user: Doc = Depends(get_current_user), db: Database = Depends(get_db)) -> None:
    m = _get(db, user, monitor_id)
    db.monitors.delete_one({"_id": m.id})
    db.scans.update_many({"monitor_id": m.id}, {"$set": {"monitor_id": None}})
