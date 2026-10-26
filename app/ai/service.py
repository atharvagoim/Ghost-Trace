"""AI Security Analyst features, built on GhostTrace's existing findings, detection engine and MongoDB data.

Nothing here sends raw secrets: findings only ever store masked previews, code fetched from GitHub is redacted with
the detection engine before use, and GroqClient.chat_json runs a final guard over the exact request.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta, timezone

from pymongo.database import Database

from ..config import get_settings
from ..db import Doc, find, find_one, insert
from ..detection.engine import looks_binary, mask_secret, scan_diff_patch, should_skip_path
from ..ratelimit import check_limit
from ..sources.github import GitHubClient, GitHubError, parse_repo_target
from .groq import AINotConfigured, AIResult, GroqClient
from .prompts import PROMPT_VERSION, SCHEMAS, SYSTEM, user_message
from .redact import redact_obj, redact_text

LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "composer.lock", "Cargo.lock", "go.sum", "Gemfile.lock"}
MAX_FILE_FOR_PATCH = 300_000
PATCH_WINDOW = 12  # lines of context each side of the finding

# Per-feature output caps (kept out of the JSON Schema; see prompts._str_list).
CLIP = {
    "explain": {"attack_scenarios": 4},
    "remediate": {"steps": 8, "prevention": 5, "verify": 4},
    "patch": {"explanation": 6, "env_vars": 6, "gitignore_additions": 6, "notes": 4},
    "pr_review": {"issues": 20, "good_practices": 5},
    "posture": {"top_risks": 5, "priorities": 6, "wins": 4},
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def require_enabled() -> None:
    if not get_settings().ai_enabled:
        raise AINotConfigured()


def charge(user: Doc, bucket: str) -> None:
    """Per-user rate limits. Only charged when the AI is actually called (cached answers are free)."""
    s = get_settings()
    limits = {
        "finding": (s.ai_finding_limit_per_10min, 600),
        "pr": (s.ai_pr_limit_per_hour, 3600),
        "posture": (s.ai_posture_limit_per_hour, 3600),
    }
    limit, window = limits[bucket]
    check_limit(f"ai-{bucket}", str(user.id), limit, window)
    check_limit("ai-daily", str(user.id), s.ai_daily_limit, 86400)


def _clip_and_clean(kind: str, data: dict) -> tuple[dict, int]:
    """Enforce list caps and numeric ranges, then redact anything secret-like the model produced."""
    for key, cap in CLIP.get(kind, {}).items():
        if isinstance(data.get(key), list):
            data[key] = data[key][:cap]
    for key in ("risk_score", "score"):
        if isinstance(data.get(key), (int, float)):
            data[key] = int(max(0, min(100, data[key])))
    if isinstance(data.get("estimated_minutes"), (int, float)):
        data["estimated_minutes"] = int(max(1, min(24 * 60, data["estimated_minutes"])))
    return redact_obj(data)


def _validate(kind: str, data: dict) -> None:
    missing = [k for k in SCHEMAS[kind]["required"] if k not in data]
    if missing:
        from .groq import AIError

        raise AIError(502, "The AI returned an incomplete answer. Please try again.")


async def _ask(kind: str, context: dict, client: GroqClient | None = None, max_tokens: int | None = None) -> tuple[dict, AIResult, int]:
    context_json = json.dumps(context, ensure_ascii=False, default=str, indent=1)
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_message(kind, context_json)}]
    result = await (client or GroqClient()).chat_json(messages, SCHEMAS[kind], f"ghosttrace_{kind}", max_tokens)
    _validate(kind, result.data)
    clean, out_redactions = _clip_and_clean(kind, result.data)
    return clean, result, out_redactions


def _envelope(doc: Doc | dict, cached: bool) -> dict:
    return {
        "kind": doc["kind"], "result": doc["result"], "model": doc["model"], "cached": cached,
        "created_at": doc["created_at"], "redactions": doc.get("redactions", 0), "prompt_version": doc.get("prompt_version"),
    }


# ------------------------------------------------------------------ findings: explain / remediate / patch

def finding_context(f: Doc) -> dict:
    """What the model sees about a finding. Only masked/derived data; the snippet is redacted again regardless."""
    snippet, _ = redact_text(f.snippet or "", f.file_path)
    age_days = (_now() - (f.first_seen if f.first_seen.tzinfo else f.first_seen.replace(tzinfo=timezone.utc))).days if f.first_seen else None
    return {
        "credential_type": f.credential_type,
        "category": f.category,
        "detector_rule": f.rule_id,
        "severity": f.severity,
        "risk_score": round(float(f.risk_score or 0), 1),
        "model_confidence_real": round(float(f.confidence or 0), 3),
        "entropy_bits_per_char": round(float(f.entropy or 0), 2),
        "risk_factors": f.risk_factors or [],
        "source": f.source_type,
        "repository": f.repository,
        "file_path": f.file_path,
        "line": f.line_number,
        "only_in_git_history": bool(f.in_history_only),
        "triage_status": f.status,
        "days_since_first_seen": age_days,
        "code_line_redacted": snippet,
    }


async def _code_window(f: Doc) -> dict | None:
    """For a GitHub finding still in the latest code, fetch the surrounding lines and redact the whole file first."""
    if f.source_type != "github" or not f.repository or not f.file_path or f.in_history_only or not f.line_number:
        return None
    try:
        async with GitHubClient() as gh:
            repo = await gh.get_repo(parse_repo_target(f.repository))
            data = await gh.get_file(repo, f.file_path)
    except GitHubError:
        return None
    if not data or len(data) > MAX_FILE_FOR_PATCH or looks_binary(data):
        return None
    text, n = redact_text(data.decode("utf-8", errors="ignore"), f.file_path)
    lines = text.splitlines()
    start = max(1, f.line_number - PATCH_WINDOW)
    end = min(len(lines), f.line_number + PATCH_WINDOW)
    window = "\n".join(lines[start - 1:end])
    return {"start_line": start, "end_line": end, "finding_line": f.line_number, "code_redacted": window, "redactions_in_file": n}


async def finding_insight(db: Database, user: Doc, f: Doc, kind: str, refresh: bool = False, client: GroqClient | None = None) -> dict:
    require_enabled()
    key = {"user_id": user.id, "kind": kind, "fingerprint": f.fingerprint}
    if not refresh:
        cached = find_one(db, "ai_insights", key)
        if cached and cached.get("prompt_version") == PROMPT_VERSION:
            return _envelope(cached, cached=True)
    charge(user, "finding")
    context = finding_context(f)
    if kind == "patch":
        window = await _code_window(f)
        if window:
            context["code"] = window
        else:
            context["code"] = {"note": "Only the single redacted line is available (history-only, pasted text or upload).",
                               "code_redacted": context["code_line_redacted"]}
    data, res, out_red = await _ask(kind, context, client)
    doc = {**key, "finding_id": f.id, "result": data, "model": res.model, "created_at": _now(), "prompt_version": PROMPT_VERSION,
           "redactions": res.redactions + out_red, "usage": res.usage}
    db.ai_insights.update_one(key, {"$set": doc}, upsert=True)
    return _envelope(doc, cached=False)


def cached_insights(db: Database, user: Doc, f: Doc) -> dict:
    docs = find(db, "ai_insights", {"user_id": user.id, "fingerprint": f.fingerprint, "prompt_version": PROMPT_VERSION})
    return {d["kind"]: _envelope(d, cached=True) for d in docs}


# ------------------------------------------------------------------ pull-request review

def _review_order(item: dict) -> tuple:
    return (-len(item["secrets"]), -(item["additions"] or 0))


async def pr_review(db: Database, user: Doc, repo_full: str, number: int, refresh: bool = False, client: GroqClient | None = None) -> dict:
    require_enabled()
    async with GitHubClient() as gh:
        pr = await gh.get_pull(repo_full, number)
        head_sha = (pr.get("head") or {}).get("sha", "")
        key = {"user_id": user.id, "repo": repo_full, "number": number, "head_sha": head_sha}
        if not refresh:
            cached = find_one(db, "pr_reviews", key)
            if cached and cached.get("prompt_version") == PROMPT_VERSION:
                return {**review_out(cached), "cached": True}
        charge(user, "pr")
        files = await gh.get_pull_files(repo_full, number)

    detected: list[dict] = []
    items: list[dict] = []
    skipped = 0
    for fl in files:
        name = fl.get("filename") or ""
        patch = fl.get("patch") or ""
        base = name.rsplit("/", 1)[-1]
        if not patch or should_skip_path(name) or base in LOCKFILES:
            skipped += 1
            continue
        secrets = [m for m in scan_diff_patch(patch, name) if not m.placeholder and m.rule.category != "email"]
        for m in secrets:
            detected.append({"file": name, "line": m.line, "rule_id": m.rule.id, "credential_type": m.rule.name,
                             "severity": m.rule.severity, "masked": mask_secret(m.secret, m.rule.category)})
        red_patch, _ = redact_text(patch, name)
        items.append({"file": name, "status": fl.get("status"), "additions": fl.get("additions"), "deletions": fl.get("deletions"),
                      "patch": red_patch, "secrets": secrets})

    budget = get_settings().ai_pr_max_diff_chars
    included, omitted, used = [], [], 0
    for it in sorted(items, key=_review_order):
        cost = len(it["patch"]) + len(it["file"]) + 40
        if used + cost > budget:
            # Still show the model a truncated head of large files that contain secrets, then stop.
            if it["secrets"] and used < budget:
                room = max(0, budget - used - len(it["file"]) - 60)
                included.append({**{k: it[k] for k in ("file", "status", "additions", "deletions")}, "patch": it["patch"][:room] + "\n…[truncated]"})
                used = budget
            else:
                omitted.append(it["file"])
            continue
        included.append({k: it[k] for k in ("file", "status", "additions", "deletions", "patch")})
        used += cost

    body, _ = redact_text((pr.get("body") or "")[:1500])
    title, _ = redact_text((pr.get("title") or "")[:300])
    context = {
        "repository": repo_full, "pull_request": number, "title": title, "description": body,
        "base_branch": (pr.get("base") or {}).get("ref"), "changed_files": pr.get("changed_files"),
        "additions": pr.get("additions"), "deletions": pr.get("deletions"),
        "secrets_found_by_ghosttrace": [{k: d[k] for k in ("file", "line", "credential_type", "severity")} for d in detected],
        "files": included, "files_not_shown": omitted[:50], "files_skipped_as_generated_or_binary": skipped,
    }
    data, res, out_red = await _ask("pr_review", context, client)
    doc = {
        **key, "url": pr.get("html_url") or f"https://github.com/{repo_full}/pull/{number}", "title": title,
        "author": (pr.get("user") or {}).get("login"), "state": "merged" if pr.get("merged_at") else pr.get("state"),
        "stats": {"changed_files": pr.get("changed_files"), "additions": pr.get("additions"), "deletions": pr.get("deletions"),
                  "reviewed_files": len(included), "omitted_files": len(omitted), "skipped_files": skipped},
        "detected_secrets": detected, "result": data, "model": res.model, "prompt_version": PROMPT_VERSION,
        "redactions": res.redactions + out_red, "usage": res.usage, "created_at": _now(),
    }
    existing = find_one(db, "pr_reviews", key)
    if existing:
        db.pr_reviews.update_one({"_id": existing.id}, {"$set": doc})
        doc["_id"] = existing.id
    else:
        doc = insert(db, "pr_reviews", doc)
    return {**review_out(Doc(doc)), "cached": False}


def review_out(d: Doc | dict) -> dict:
    return {
        "id": d["_id"], "url": d["url"], "repo": d["repo"], "number": d["number"], "title": d.get("title"), "author": d.get("author"),
        "state": d.get("state"), "head_sha": d.get("head_sha"), "stats": d.get("stats", {}), "detected_secrets": d.get("detected_secrets", []),
        "result": d["result"], "model": d.get("model"), "created_at": d["created_at"], "redactions": d.get("redactions", 0),
    }


# ------------------------------------------------------------------ security posture

def posture_context(db: Database, user: Doc) -> dict:
    """Aggregate statistics only: no secrets, snippets, masked previews or email addresses."""
    now = _now()
    fields = {"status": 1, "severity": 1, "category": 1, "credential_type": 1, "risk_score": 1, "repository": 1,
              "first_seen": 1, "in_history_only": 1, "source_type": 1}
    fs = find(db, "findings", {"user_id": user.id}, projection=fields)
    aware = lambda d: d if d.tzinfo else d.replace(tzinfo=timezone.utc)  # noqa: E731
    open_f = [f for f in fs if f.status == "open"]
    sev = Counter(f.severity for f in open_f)
    repos: dict[str, Counter] = {}
    for f in open_f:
        if f.repository:
            repos.setdefault(f.repository, Counter())[f.severity] += 1
    top_repos = sorted(repos.items(), key=lambda kv: (-kv[1]["critical"], -kv[1]["high"], -sum(kv[1].values())))[:6]
    week_ago, two_weeks = now - timedelta(days=7), now - timedelta(days=14)
    new_7 = sum(1 for f in fs if f.first_seen and aware(f.first_seen) >= week_ago)
    prev_7 = sum(1 for f in fs if f.first_seen and two_weeks <= aware(f.first_seen) < week_ago)
    ages = [(now - aware(f.first_seen)).days for f in open_f if f.first_seen]
    scans = find(db, "scans", {"user_id": user.id}, projection={"status": 1, "created_at": 1, "files_scanned": 1})
    breaches = find(db, "breach_checks", {"user_id": user.id}, projection={"email": 1, "breach_count": 1, "breaches": 1, "checked_at": 1})
    latest: dict[str, Doc] = {}
    for b in sorted(breaches, key=lambda b: b.checked_at or now, reverse=True):
        latest.setdefault(b.email, b)
    breach_names = Counter(x.get("name") for b in latest.values() for x in (b.breaches or []) if x.get("name"))
    resolved = sum(1 for f in fs if f.status == "resolved")
    decided = resolved + len(open_f)
    return {
        "findings_total": len(fs),
        "open": len(open_f),
        "open_by_severity": {s: sev.get(s, 0) for s in ("critical", "high", "medium", "low")},
        "rotated": resolved,
        "marked_not_a_secret": sum(1 for f in fs if f.status == "false_positive"),
        "rotation_rate_percent": round(100 * resolved / decided, 1) if decided else None,
        "open_older_than_7_days": sum(1 for a in ages if a > 7),
        "open_older_than_30_days": sum(1 for a in ages if a > 30),
        "median_open_age_days": sorted(ages)[len(ages) // 2] if ages else None,
        "open_only_in_git_history": sum(1 for f in open_f if f.in_history_only),
        "open_by_credential_type": dict(Counter(f.credential_type for f in open_f).most_common(8)),
        "open_by_category": dict(Counter(f.category for f in open_f).most_common(8)),
        "most_exposed_repositories": [{"repository": r, **{s: c.get(s, 0) for s in ("critical", "high", "medium", "low")}} for r, c in top_repos],
        "new_findings_last_7_days": new_7,
        "new_findings_previous_7_days": prev_7,
        "scans_total": len(scans),
        "files_scanned_total": sum(int(s.files_scanned or 0) for s in scans),
        "last_scan_days_ago": (now - aware(max(s.created_at for s in scans))).days if scans else None,
        "active_monitors": db.monitors.count_documents({"user_id": user.id, "enabled": True}),
        "emails_checked": len(latest),
        "emails_in_breaches": sum(1 for b in latest.values() if (b.breach_count or 0) > 0),
        "most_common_breaches": [n for n, _ in breach_names.most_common(5)],
    }


_TIME_KEYS = {"open_older_than_7_days", "open_older_than_30_days", "median_open_age_days", "new_findings_last_7_days",
              "new_findings_previous_7_days", "last_scan_days_ago"}


def _stats_hash(ctx: dict) -> str:
    """Fingerprint of the underlying data (not of the clock), so a summary only goes stale when the data changes."""
    stable = {k: v for k, v in ctx.items() if k not in _TIME_KEYS}
    return hashlib.sha256(json.dumps(stable, sort_keys=True, default=str).encode()).hexdigest()[:16]


async def posture(db: Database, user: Doc, client: GroqClient | None = None) -> dict:
    require_enabled()
    ctx = posture_context(db, user)
    if ctx["findings_total"] == 0 and ctx["scans_total"] == 0:
        from .groq import AIError

        raise AIError(409, "Run at least one scan first, so there is something to summarise.")
    charge(user, "posture")
    data, res, out_red = await _ask("posture", ctx, client)
    doc = {"user_id": user.id, "kind": "posture", "result": data, "stats": ctx, "stats_hash": _stats_hash(ctx), "model": res.model,
           "prompt_version": PROMPT_VERSION, "redactions": res.redactions + out_red, "usage": res.usage, "created_at": _now()}
    db.ai_posture.update_one({"user_id": user.id}, {"$set": doc}, upsert=True)
    return {**_envelope(doc, cached=False), "stats": ctx, "stale": False}


def latest_posture(db: Database, user: Doc) -> dict | None:
    doc = find_one(db, "ai_posture", {"user_id": user.id})
    if not doc:
        return None
    current = _stats_hash(posture_context(db, user))
    return {**_envelope(doc, cached=True), "stats": doc.get("stats"), "stale": current != doc.get("stats_hash")}
