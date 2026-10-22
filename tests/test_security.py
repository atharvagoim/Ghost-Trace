import io
import zipfile

import pytest

from app.db import find_one, get_db
from app.security import create_reset_token
from app.services.scanner import MAX_ZIP_ENTRIES, scan_upload
from app.sources.github import GitHubError, parse_owner_target, parse_repo_target


def test_security_headers_on_api_and_pages(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_old_sessions_end_when_the_password_is_reset(auth_client):
    assert auth_client.get("/api/auth/me").status_code == 200
    user = find_one(get_db(), "users", {"email": "dev@example.com"})
    r = auth_client.post("/api/auth/reset-password", json={"token": create_reset_token(user), "password": "a-brand-new-pass1"})
    assert r.status_code == 200
    assert auth_client.get("/api/auth/me").status_code == 401  # the token from before the reset no longer works


def test_overlong_password_is_rejected_not_a_500(client):
    r = client.post("/api/auth/register", json={"email": "long@example.com", "password": "é" * 40})  # 80 bytes  # ghosttrace:ignore
    assert r.status_code == 422


@pytest.mark.parametrize("bad", ["../etc", "evil?x=1", "name with space", "-leading", "x" * 40])
def test_github_owner_must_be_a_real_name(bad):
    with pytest.raises(GitHubError):
        parse_owner_target(bad)


@pytest.mark.parametrize("bad", ["owner/..", "owner/repo?x", "own er/repo", "../repo"])
def test_github_repo_must_be_a_real_name(bad):
    with pytest.raises(GitHubError):
        parse_repo_target(bad)


def test_github_targets_still_accept_normal_input():
    assert parse_repo_target("https://github.com/octocat/Hello-World.git") == "octocat/Hello-World"
    assert parse_owner_target("@octocat") == "octocat"


def test_zip_with_too_many_entries_is_refused():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(MAX_ZIP_ENTRIES + 1):
            zf.writestr(f"f{i}.txt", "x")
    with pytest.raises(ValueError):
        scan_upload("bomb.zip", buf.getvalue())


def test_csv_export_neutralises_formulas(auth_client):
    from app.routers.reports import _cell

    assert _cell("=HYPERLINK(\"http://evil\")") == "'=HYPERLINK(\"http://evil\")"
    assert _cell("@cmd") == "'@cmd"
    assert _cell("normal/path.py") == "normal/path.py"
    assert _cell(12) == 12


def test_monitor_count_is_capped(auth_client):
    from app.routers.monitors import MAX_MONITORS

    for i in range(MAX_MONITORS):
        assert auth_client.post("/api/monitors", json={"target_type": "email", "target": f"u{i}@example.com"}).status_code == 201
    r = auth_client.post("/api/monitors", json={"target_type": "email", "target": "one-too-many@example.com"})
    assert r.status_code == 409
