import io
import random
import string
import zipfile

from app.sources.github import CommitFile, RepoInfo, TreeFile

_r = random.Random(9)
AWS = "AKIA" + "".join(_r.choice(string.ascii_uppercase + string.digits) for _ in range(16))


def test_text_scan_scores_and_triage(auth_client):
    content = f"AWS_ACCESS_KEY_ID={AWS}\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    r = auth_client.post("/api/scans/text", json={"content": content, "label": ".env"})
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "completed" and scan["findings_count"] == 2

    items = auth_client.get(f"/api/scans/{scan['id']}/findings").json()
    real, fake = items[0], items[1]
    assert real["risk_score"] > fake["risk_score"]
    assert real["confidence"] > 0.5 > fake["confidence"]
    assert AWS not in str(items)

    r = auth_client.patch(f"/api/findings/{fake['id']}", json={"status": "false_positive"})
    assert r.json()["status"] == "false_positive"
    page = auth_client.get("/api/findings", params={"status": "open"}).json()
    assert page["total"] == 1

    dash = auth_client.get("/api/dashboard/summary").json()
    assert dash["totals"]["open"] == 1 and dash["totals"]["false_positives"] == 1
    assert auth_client.get("/api/dashboard/timeline").status_code == 200


def test_zip_upload_and_reports(auth_client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/.env", "DATABASE_URL=postgres://svc:Hq7rT2mVx9Lp4wZs@pg.internal:5432/core\n")  # ghosttrace:ignore
        zf.writestr("proj/node_modules/x.js", f"k='{AWS}'")
        zf.writestr("proj/logo.png", b"\x89PNG\x00\x00")
    r = auth_client.post("/api/scans/upload", files={"file": ("proj.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 201, r.text
    assert r.json()["findings_count"] == 1 and r.json()["files_scanned"] == 1

    csv = auth_client.get("/api/reports/findings.csv")
    assert csv.status_code == 200 and "Database connection string" in csv.text
    pdf = auth_client.get("/api/reports/summary.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert auth_client.get(f"/api/reports/scan/{r.json()['id']}.pdf").content.startswith(b"%PDF")


def test_github_scan_with_history(auth_client, monkeypatch):
    from app.sources import github as gh

    repo = RepoInfo("acme/api", "main", False, "https://github.com/acme/api", False, False, None)
    files = {
        "config/settings.py": f'AWS_KEY = "{AWS}"\n'.encode(),
        "README.md": b"# api\n",
    }
    r3 = random.Random(3)
    removed = "ghp_" + "".join(r3.choice(string.ascii_letters + string.digits) for _ in range(36))

    async def get_repo(self, full_name):
        return repo

    async def get_tree(self, r):
        return [TreeFile(p, "sha", len(c)) for p, c in files.items()] + [TreeFile("node_modules/a.js", "s", 3)]

    async def get_file(self, r, path):
        return files.get(path)

    async def list_commits(self, r, limit):
        return ["abc1234"]

    async def get_commit_files(self, r, sha):
        return [CommitFile(sha, "deploy.sh", f"@@ -0,0 +1 @@\n+export GITHUB_TOKEN={removed}", "https://github.com/acme/api/commit/abc1234", None)]

    for name, fn in [("get_repo", get_repo), ("get_tree", get_tree), ("get_file", get_file),
                     ("list_commits", list_commits), ("get_commit_files", get_commit_files)]:
        monkeypatch.setattr(gh.GitHubClient, name, fn)

    r = auth_client.post("/api/scans/github", json={"target_type": "github_repo", "target": "https://github.com/acme/api"})
    assert r.status_code == 202, r.text
    scan = auth_client.get(f"/api/scans/{r.json()['id']}").json()
    assert scan["status"] == "completed", scan
    assert scan["target"] == "acme/api" and scan["files_scanned"] == 2 and scan["commits_scanned"] == 1
    findings = auth_client.get(f"/api/scans/{scan['id']}/findings").json()
    by_rule = {f["rule_id"]: f for f in findings}
    assert by_rule["aws_access_key_id"]["severity"] == "critical"
    assert by_rule["github_pat"]["in_history_only"] is True
    alerts = auth_client.get("/api/alerts").json()
    assert alerts and alerts[0]["status"] == "skipped"  # SMTP not configured in tests


def test_github_errors_surface(auth_client, monkeypatch):
    from app.sources import github as gh

    async def boom(self, *a):
        raise gh.GitHubError("User ghost-nobody was not found on GitHub.")

    monkeypatch.setattr(gh.GitHubClient, "list_repos", boom)
    r = auth_client.post("/api/scans/github", json={"target_type": "github_user", "target": "ghost-nobody"})
    scan = auth_client.get(f"/api/scans/{r.json()['id']}").json()
    assert scan["status"] == "failed" and "not found" in scan["error"]
