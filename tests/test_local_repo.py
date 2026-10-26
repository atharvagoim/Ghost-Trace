"""Zipped local repositories: working tree + git history, read in memory, never written to disk."""

import io
import os
import random
import shutil
import string
import subprocess
import tempfile
import zipfile

import pytest

_r = random.Random(11)
AWS_OLD = "AKIA" + "".join(_r.choice(string.ascii_uppercase + string.digits) for _ in range(16))
GHP_NOW = "ghp_" + "".join(_r.choice(string.ascii_letters + string.digits) for _ in range(36))
ENV_PASS = "Zq8xLm2Pw9RtK4"

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git CLI not available to build the fixture repo")


def _git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=env)


def _make_repo(packed: bool) -> bytes:
    """A repo where an AWS key was committed then deleted, a GitHub token is still in the code, and an
    untracked .env holds a password. Returned as zip bytes with a top-level folder, like Explorer/Finder make."""
    tmp = tempfile.mkdtemp()
    try:
        root = os.path.join(tmp, "my-app")
        os.makedirs(os.path.join(root, "src"))
        _git(root, "init", "-q", "-b", "main")
        with open(os.path.join(root, "src", "config.py"), "w") as f:
            f.write(f'DEBUG = True\nAWS_KEY = "{AWS_OLD}"\n')
        _git(root, "add", ".")
        _git(root, "commit", "-q", "-m", "add config")
        with open(os.path.join(root, "src", "config.py"), "w") as f:
            f.write('import os\nDEBUG = True\nAWS_KEY = os.environ["AWS_KEY"]\n')
        with open(os.path.join(root, "src", "deploy.sh"), "w") as f:
            f.write(f"#!/bin/sh\nexport GITHUB_TOKEN={GHP_NOW}\n")
        _git(root, "add", ".")
        _git(root, "commit", "-q", "-m", "use env var")
        with open(os.path.join(root, ".env"), "w") as f:
            f.write(f"DB_PASSWORD={ENV_PASS}\n")
        os.makedirs(os.path.join(root, "node_modules", "lib"))
        with open(os.path.join(root, "node_modules", "lib", "index.js"), "w") as f:
            f.write('const k = "' + "AKIA" + "Z" * 16 + '"\n')
        if packed:
            _git(root, "gc", "-q", "--aggressive")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for d, _, files in os.walk(root):
                for name in files:
                    full = os.path.join(d, name)
                    zf.write(full, os.path.relpath(full, tmp))
        return buf.getvalue()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _post(client, data: bytes, **params):
    return client.post("/api/scans/local", params={"name": "my-app.zip", **params}, content=data,
                       headers={"Content-Type": "application/zip"})


@needs_git
@pytest.mark.parametrize("packed", [False, True], ids=["loose-objects", "packfile"])
def test_local_repo_scan_finds_tree_and_history(auth_client, packed):
    r = _post(auth_client, _make_repo(packed))
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "completed" and scan["target_type"] == "local_repo" and scan["target"] == "my-app"
    assert scan["commits_scanned"] == 2 and "2 commits" in scan["message"]
    findings = auth_client.get(f"/api/scans/{scan['id']}/findings").json()
    by_rule = {f["rule_id"]: f for f in findings}

    gh = by_rule["github_pat"]
    assert gh["file_path"] == "src/deploy.sh" and gh["line_number"] == 2 and not gh["in_history_only"]
    assert gh["source_type"] == "local" and gh["repository"] == "my-app"

    aws = by_rule["aws_access_key_id"]
    assert aws["in_history_only"] and aws["file_path"] == "src/config.py" and aws["line_number"] == 2 and len(aws["commit_sha"]) == 40
    assert "Local repository" in " ".join(aws["risk_factors"])

    assert by_rule["env_password"]["file_path"] == ".env"
    assert not any("node_modules" in (f["file_path"] or "") for f in findings)
    for f in findings:  # only masked values are stored
        assert AWS_OLD not in str(f) and GHP_NOW not in str(f) and ENV_PASS not in str(f)


@needs_git
def test_history_can_be_skipped(auth_client):
    scan = _post(auth_client, _make_repo(False), history="false").json()
    assert scan["commits_scanned"] == 0 and "history skipped" in scan["message"]
    rules = {f["rule_id"] for f in auth_client.get(f"/api/scans/{scan['id']}/findings").json()}
    assert "aws_access_key_id" not in rules and "github_pat" in rules


def test_zip_without_git_still_scans_files(auth_client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/app.py", f'TOKEN = "{GHP_NOW}"\n')
    scan = _post(auth_client, buf.getvalue()).json()
    assert scan["status"] == "completed" and "No .git folder" in scan["message"] and scan["findings_count"] == 1


def test_rejects_non_zip_and_empty(auth_client):
    assert _post(auth_client, b"hello world").status_code == 422
    assert _post(auth_client, b"").status_code == 422


def test_size_limit(auth_client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "max_upload_mb", 1)
    assert _post(auth_client, b"PK\x03\x04" + b"0" * (1024 * 1024 + 10)).status_code == 413


def test_requires_login(client):
    assert client.post("/api/scans/local", content=b"PK\x03\x04").status_code == 401


@needs_git
def test_nothing_is_written_to_disk(auth_client, monkeypatch):
    """The endpoint must not create temp files: patch every way Python creates them and fail if one is used."""
    data = _make_repo(True)

    def boom(*a, **k):
        raise AssertionError("a temporary file was created")

    for name in ("NamedTemporaryFile", "TemporaryFile", "SpooledTemporaryFile", "mkstemp", "mkdtemp", "TemporaryDirectory"):
        monkeypatch.setattr(tempfile, name, boom)
    assert _post(auth_client, data).status_code == 201
