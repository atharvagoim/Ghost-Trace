"""Scan orchestration: GitHub targets, pasted text and uploaded files."""

import asyncio
import io
import logging
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from pymongo.database import Database

from ..config import get_settings
from ..db import Doc, find_one, get_db, insert
from ..detection.engine import (
    MAX_FILE_BYTES, Match, is_sensitive_path, is_test_path, looks_binary, mask_secret, should_skip_path, scan_diff_patch, scan_text,
)
from ..ml.features import FindingContext
from ..ml.scorer import score_all
from ..sources.github import GitHubClient, GitHubError, RepoInfo, parse_owner_target, parse_repo_target

log = logging.getLogger("ghosttrace.scanner")


@dataclass
class RawHit:
    match: Match
    source_type: str
    repository: str | None = None
    file_path: str | None = None
    commit_sha: str | None = None
    url: str | None = None
    public: bool = True
    history_only: bool = False


@dataclass
class ScanStats:
    repos: int = 0
    files: int = 0
    commits: int = 0
    hits: list[RawHit] = field(default_factory=list)
    deadline: float | None = None  # time.monotonic() value after which the scan wraps up with what it has
    truncated: bool = False

    def out_of_time(self) -> bool:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.truncated = True
        return self.truncated


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _update(db: Database, scan: Doc, **fields) -> None:
    scan.update(fields)
    db.scans.update_one({"_id": scan.id}, {"$set": fields})


# ---------------------------------------------------------------- GitHub

def vendored_prefixes(paths) -> tuple[str, ...]:
    """Directories that hold installed third-party packages (e.g. a Lambda 'package/' folder with pillow-*.dist-info).

    Anything next to a *.dist-info or *.egg-info folder is library code, not the user's, so it is skipped.
    """
    prefixes: set[str] = set()
    for path in paths:
        parts = path.split("/")
        for i, part in enumerate(parts[:-1]):
            if part.endswith((".dist-info", ".egg-info")):
                prefixes.add("/".join(parts[:i]) + "/" if i else "")
                break
    return tuple(p for p in prefixes if p)

async def _scan_repo(gh: GitHubClient, repo: RepoInfo, include_history: bool, stats: ScanStats, progress_cb) -> None:
    settings = get_settings()
    tree = await gh.get_tree(repo)
    vendored = vendored_prefixes(f.path for f in tree)
    files = [
        f for f in tree
        if not should_skip_path(f.path) and f.size <= MAX_FILE_BYTES and not f.path.startswith(vendored)
    ]
    # Sensitive-looking files first so they are always covered when the per-repo cap applies.
    files.sort(key=lambda f: (not is_sensitive_path(f.path), f.size))
    files = files[: settings.github_max_files_per_repo]

    head_fingerprints: set[str] = set()

    async def fetch_and_scan(path: str) -> None:
        data = await gh.get_file(repo, path)
        if data is None or looks_binary(data):
            return
        text = data.decode("utf-8", errors="ignore")
        stats.files += 1
        for m in scan_text(text, path):
            head_fingerprints.add(m.fingerprint)
            stats.hits.append(RawHit(
                match=m, source_type="github", repository=repo.full_name, file_path=path,
                url=f"{repo.html_url}/blob/{repo.default_branch}/{path}#L{m.line}", public=not repo.private,
            ))

    batch = 24
    for i in range(0, len(files), batch):
        if stats.out_of_time():
            break
        await asyncio.gather(*(fetch_and_scan(f.path) for f in files[i:i + batch]))
        progress_cb(i + batch, len(files))

    if include_history and not stats.out_of_time():
        shas = await gh.list_commits(repo, settings.github_max_commits_per_repo)
        commit_files = await asyncio.gather(*(gh.get_commit_files(repo, sha) for sha in shas))
        seen_history: set[str] = set()
        for cfs in commit_files:
            if cfs:
                stats.commits += 1
            for cf in cfs:
                if should_skip_path(cf.path):
                    continue
                for m in scan_diff_patch(cf.patch, cf.path):
                    if m.fingerprint in head_fingerprints or m.fingerprint in seen_history:
                        continue
                    seen_history.add(m.fingerprint)
                    stats.hits.append(RawHit(
                        match=m, source_type="github", repository=repo.full_name, file_path=cf.path, commit_sha=cf.sha,
                        url=cf.html_url, public=not repo.private, history_only=True,
                    ))
    stats.repos += 1


async def _run_github(db: Database, scan: Doc, include_history: bool, deadline: float | None = None) -> ScanStats:
    settings = get_settings()
    budget = settings.scan_time_budget_seconds
    limits = [d for d in (deadline, time.monotonic() + budget if budget > 0 else None) if d is not None]
    stats = ScanStats(deadline=min(limits) if limits else None)
    async with GitHubClient() as gh:
        if scan.target_type == "github_repo":
            repos = [await gh.get_repo(parse_repo_target(scan.target))]
        else:
            owner = parse_owner_target(scan.target)
            kind = "org" if scan.target_type == "github_org" else "user"
            repos = await gh.list_repos(owner, kind, settings.github_max_repos_per_owner)
            if not repos:
                _update(db, scan, message=f"No public repositories found for {owner}.")
        total = max(len(repos), 1)
        for idx, repo in enumerate(repos):
            if stats.out_of_time():
                break
            _update(db, scan, message=f"Scanning {repo.full_name} ({idx + 1}/{len(repos)})", progress=int(5 + 85 * idx / total))

            def cb(done: int, of: int, _idx=idx) -> None:
                frac = min(done / of, 1.0) if of else 1.0
                _update(db, scan, progress=int(5 + 85 * (_idx + frac * 0.8) / total), files_scanned=stats.files)

            try:
                await _scan_repo(gh, repo, include_history, stats, cb)
            except GitHubError as exc:
                log.warning("Skipping %s: %s", repo.full_name, exc)
            _update(db, scan, repos_scanned=stats.repos, files_scanned=stats.files, commits_scanned=stats.commits)
    return stats


# ---------------------------------------------------------------- text / files

def scan_text_blob(text: str, label: str, source_type: str) -> ScanStats:
    stats = ScanStats(files=1)
    for m in scan_text(text, label):
        stats.hits.append(RawHit(match=m, source_type=source_type, file_path=label, public=False))
    return stats


MAX_ZIP_ENTRIES = 5_000
MAX_ZIP_UNPACKED_BYTES = 200 * 1024 * 1024  # a small zip can expand a thousandfold; stop before it fills memory


def scan_upload(filename: str, data: bytes) -> ScanStats:
    stats = ScanStats()
    if filename.lower().endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise ValueError(f"The archive has more than {MAX_ZIP_ENTRIES} files")
            if sum(i.file_size for i in infos) > MAX_ZIP_UNPACKED_BYTES:
                raise ValueError("The archive unpacks to more than 200 MB")
            for info in infos:
                if info.is_dir() or info.file_size > MAX_FILE_BYTES or should_skip_path(info.filename):
                    continue
                content = zf.read(info)
                if looks_binary(content):
                    continue
                stats.files += 1
                for m in scan_text(content.decode("utf-8", errors="ignore"), info.filename):
                    stats.hits.append(RawHit(match=m, source_type="file", file_path=info.filename, public=False))
        return stats
    if looks_binary(data):
        return stats
    stats.files = 1
    for m in scan_text(data.decode("utf-8", errors="ignore"), filename):
        stats.hits.append(RawHit(match=m, source_type="file", file_path=filename, public=False))
    return stats


# ---------------------------------------------------------------- persistence

def persist_hits(db: Database, scan: Doc, hits: list[RawHit]) -> list[Doc]:
    now = _now()
    # Triage state and first-seen date carry forward from earlier sightings of the same secret; the oldest wins.
    prior: dict[str, tuple[str, datetime]] = {}
    for row in db.findings.find({"user_id": scan.user_id}, {"fingerprint": 1, "status": 1, "first_seen": 1}).sort("first_seen", -1):
        prior[row["fingerprint"]] = (row["status"], row["first_seen"])

    unique: list[RawHit] = []
    seen: set[tuple[str, str | None]] = set()
    for h in hits:
        key = (h.match.fingerprint, h.repository)
        if key not in seen:
            seen.add(key)
            unique.append(h)

    scores = score_all([
        (FindingContext(
            category=h.match.rule.category, base_severity=h.match.rule.severity, specific=h.match.rule.specific,
            secret=h.match.secret, entropy=h.match.entropy, placeholder=h.match.placeholder, test_path=is_test_path(h.file_path),
            sensitive_path=is_sensitive_path(h.file_path), history_only=h.history_only, line=h.match.snippet, public=h.public,
        ), h.match.rule.name, h.file_path, h.source_type)
        for h in unique
    ])

    findings: list[Doc] = []
    for h, sc in zip(unique, scores):
        m = h.match
        prev_status, prev_first_seen = prior.get(m.fingerprint, (None, None))
        findings.append(insert(db, "findings", {
            "user_id": scan.user_id, "scan_id": scan.id, "credential_type": m.rule.name, "category": m.rule.category,
            "rule_id": m.rule.id, "secret_masked": mask_secret(m.secret, m.rule.category), "fingerprint": m.fingerprint,
            "source_type": h.source_type, "repository": h.repository, "file_path": h.file_path, "line_number": m.line,
            "commit_sha": h.commit_sha, "url": h.url, "snippet": m.snippet, "in_history_only": h.history_only,
            "entropy": m.entropy, "confidence": sc.confidence, "risk_score": sc.risk, "severity": sc.severity,
            "risk_factors": sc.factors, "status": "false_positive" if prev_status == "false_positive" else "open",
            "first_seen": prev_first_seen or now, "last_seen": now,
        }))
    _update(db, scan, findings_count=len(findings), max_risk=max((f.risk_score for f in findings), default=0.0))
    return findings


def new_scan(user_id: int, target_type: str, target: str, **extra) -> dict:
    """Fields of a freshly queued scan document."""
    return {
        "user_id": user_id, "monitor_id": None, "target_type": target_type, "target": target, "status": "queued",
        "progress": 0, "message": "", "repos_scanned": 0, "files_scanned": 0, "commits_scanned": 0, "findings_count": 0,
        "max_risk": 0.0, "error": None, "started_at": None, "finished_at": None, **extra,
    }


def claim_scan(db: Database, scan_id: int) -> bool:
    """Atomically move a scan from queued to running. Only one caller wins, so a scan never runs twice
    (for example when both a background task and the browser's /run request try to start it)."""
    result = db.scans.update_one(
        {"_id": scan_id, "status": "queued"},
        {"$set": {"status": "running", "started_at": _now(), "progress": 2, "message": "Connecting to GitHub"}},
    )
    return result.modified_count == 1


def expire_stale_scans(db: Database, user_id: int | None = None) -> None:
    """Fail scans that have been queued or running for too long, e.g. because a serverless function hit its time
    limit or the browser tab that would have started the scan was closed."""
    cutoff = _now() - timedelta(minutes=get_settings().stale_scan_minutes)
    query: dict = {
        "status": {"$in": ["queued", "running"]},
        "$or": [{"started_at": {"$lt": cutoff}}, {"started_at": None, "created_at": {"$lt": cutoff}}],
    }
    if user_id is not None:
        query["user_id"] = user_id
    db.scans.update_many(query, {"$set": {
        "status": "failed", "finished_at": _now(), "message": "Scan failed",
        "error": "The scan stopped before it finished (it ran out of time or was never started). Please run it again.",
    }})


def run_github_scan(scan_id: int, include_history: bool = True, deadline: float | None = None) -> None:
    """Runs a queued GitHub scan to completion. Safe to call more than once: only the first call does the work."""
    db = get_db()
    if not claim_scan(db, scan_id):
        return
    scan = find_one(db, "scans", {"_id": scan_id})
    if scan is None:
        return
    try:
        stats = asyncio.run(_run_github(db, scan, include_history, deadline))
        _update(db, scan, progress=95, message="Scoring findings with the AI model")
        findings = persist_hits(db, scan, stats.hits)
        summary = f"Scanned {stats.repos} repos, {stats.files} files and {stats.commits} commits"
        if stats.truncated:
            summary += " (stopped early at the time limit; showing what was found so far)"
        _update(db, scan, status="completed", progress=100, finished_at=_now(), message=summary)
        from .alerts import alert_for_scan

        alert_for_scan(db, scan, findings)
    except GitHubError as exc:
        _update(db, scan, status="failed", error=str(exc), finished_at=_now(), message="Scan failed")
    except Exception as exc:  # noqa: BLE001
        log.exception("Scan %s crashed", scan_id)
        _update(db, scan, status="failed", error=f"Unexpected error: {exc}", finished_at=_now(), message="Scan failed")
