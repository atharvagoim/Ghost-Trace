"""Behaviour that matters on Vercel: scans run in the /run request, the cron endpoint is locked down, and limits
are exposed to the UI."""

import os
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.db import get_db, insert
from app.services.scanner import new_scan
from app.sources.github import RepoInfo, TreeFile


def _fake_github(monkeypatch, content=b"# nothing here\n"):
    from app.sources import github as gh

    repo = RepoInfo("acme/site", "main", False, "https://github.com/acme/site", False, False, None)

    async def get_repo(self, full_name):
        return repo

    async def get_tree(self, r):
        return [TreeFile("README.md", "sha", len(content))]

    async def get_file(self, r, path):
        return content

    async def list_commits(self, r, limit):
        return []

    for name, fn in [("get_repo", get_repo), ("get_tree", get_tree), ("get_file", get_file), ("list_commits", list_commits)]:
        monkeypatch.setattr(gh.GitHubClient, name, fn)


def test_inline_scan_waits_for_run_request(auth_client, monkeypatch):
    _fake_github(monkeypatch)
    monkeypatch.setattr(get_settings(), "run_scans_inline", True)
    r = auth_client.post("/api/scans/github", json={"target_type": "github_repo", "target": "acme/site"})
    assert r.status_code == 202
    scan_id = r.json()["id"]
    assert auth_client.get(f"/api/scans/{scan_id}").json()["status"] == "queued"

    done = auth_client.post(f"/api/scans/{scan_id}/run?include_history=false").json()
    assert done["status"] == "completed" and done["files_scanned"] == 1
    # A second /run is a no-op instead of scanning twice.
    again = auth_client.post(f"/api/scans/{scan_id}/run").json()
    assert again["finished_at"] == done["finished_at"]


def test_stale_scans_are_failed(auth_client):
    me = auth_client.get("/api/auth/me").json()
    old = datetime.now(timezone.utc) - timedelta(hours=5)
    scan_id = insert(get_db(), "scans", new_scan(me["id"], "github_repo", "acme/x", status="running", started_at=old, created_at=old)).id
    s = auth_client.get(f"/api/scans/{scan_id}").json()
    assert s["status"] == "failed" and "run it again" in s["error"]


def test_cron_requires_secret(client, monkeypatch):
    assert client.get("/api/cron/monitors").status_code == 503
    monkeypatch.setattr(get_settings(), "cron_secret", "s3cret-value-for-tests")
    assert client.get("/api/cron/monitors").status_code == 401
    assert client.get("/api/cron/monitors", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = client.get("/api/cron/monitors", headers={"Authorization": "Bearer s3cret-value-for-tests"})
    assert ok.status_code == 200 and ok.json() == {"due": 0, "ran": 0}


def test_health_reports_database(client):
    expected = "in-memory" if get_settings().in_memory_db else "connected"
    assert client.get("/api/health").json()["database"] == expected


def test_meta_and_upload_limit(auth_client, monkeypatch):
    meta = auth_client.get("/api/meta").json()
    assert meta["max_upload_mb"] == 20 and meta["serverless"] is False
    monkeypatch.setattr(get_settings(), "max_upload_mb", 1)
    big = b"x" * (1024 * 1024 + 10)
    r = auth_client.post("/api/scans/upload", files={"file": ("big.txt", big)})
    assert r.status_code == 413 and "1 MB" in r.json()["detail"]


def test_vercel_settings(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("SECRET_KEY", "x" * 40)
    monkeypatch.setenv("MONGODB_URI", "mongodb+srv://u:p@cluster0.example.mongodb.net/")
    monkeypatch.setenv("VERCEL_PROJECT_PRODUCTION_URL", "ghosttrace.vercel.app")
    s = Settings(_env_file=None)
    assert s.mongodb_uri.startswith("mongodb+srv://")
    assert s.run_scans_inline and not s.enable_scheduler and s.max_upload_mb == 4 and s.trusted_proxy_hops == 1
    assert s.frontend_url == "https://ghosttrace.vercel.app"

    for missing, name in (("SECRET_KEY", "SECRET_KEY"), ("MONGODB_URI", "MONGODB_URI")):
        saved = os.environ.pop(missing)
        try:
            Settings(_env_file=None)
        except ValueError as exc:
            assert name in str(exc)
        else:
            raise AssertionError(f"missing {name} must fail on Vercel")
        finally:
            os.environ[missing] = saved


def test_blank_mongodb_uri_means_in_memory(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("MONGODB_URI", "   ")
    assert Settings(_env_file=None).in_memory_db
