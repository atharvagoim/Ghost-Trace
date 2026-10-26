"""AI Security Analyst: features, caching, limits, error handling, and above all: no raw secret ever reaches Groq."""

import io
import json
import random
import string

import httpx
import pytest

from app.ai import service
from app.ai.groq import GroqClient
from app.ai.redact import guard_payload, leaks, redact_text
from app.config import get_settings
from app.ratelimit import reset_limits
from app.sources.github import RepoInfo

_r = random.Random(42)


def _rnd(n, chars=string.ascii_letters + string.digits):
    return "".join(_r.choice(chars) for _ in range(n))


AWS = "AKIA" + _rnd(16, string.ascii_uppercase + string.digits)
STRIPE = "sk_live_" + _rnd(24)
GHP = "ghp_" + _rnd(36)
UNKNOWN = _rnd(20) + "9Zq" + _rnd(20)  # no provider prefix: only the entropy sweep can catch it
RAW_SECRETS = [AWS, STRIPE, GHP, UNKNOWN]

CANNED = {
    "ghosttrace_explain": {"summary": "An AWS access key is exposed.", "what_it_is": "AWS IAM access key.", "why_it_matters": "Account access.",
                           "verdict": "likely_real", "verdict_reasoning": "High entropy, sensitive file.", "attack_scenarios": ["Spin up miners"],
                           "blast_radius": "Whole AWS account.", "urgency": "immediate"},
    "ghosttrace_remediate": {"summary": "Rotate now.", "steps": [{"title": "Deactivate", "detail": "IAM console", "command": "aws iam update-access-key --status Inactive"}],
                             "prevention": ["Use a secrets manager"], "verify": ["Old key fails"], "estimated_minutes": 15},
    "ghosttrace_patch": {"summary": "Load from env.", "language": "python", "original": "AWS_KEY = \"[REDACTED:aws_access_key_id]\"",
                         "patched": "import os\nAWS_KEY = os.environ[\"AWS_ACCESS_KEY_ID\"]", "explanation": ["Reads env var"],
                         "env_vars": [{"name": "AWS_ACCESS_KEY_ID", "description": "IAM key"}], "gitignore_additions": [".env"], "notes": []},
    "ghosttrace_pr_review": {"summary": "Adds a hard-coded key.", "verdict": "request_changes", "risk_score": 140,
                             "issues": [{"severity": "critical", "category": "secret", "file": "deploy.sh", "line": 2, "title": "Hard-coded AWS key",
                                         "explanation": "Key in script", "recommendation": "Use env", "suggested_fix": "export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"}],
                             "good_practices": ["Small PR"]},
    "ghosttrace_posture": {"headline": "Two critical leaks need rotating.", "score": 48, "grade": "D", "summary": "Exposure is high.",
                           "top_risks": [{"title": "AWS key", "detail": "Open 3 days", "severity": "critical"}],
                           "priorities": [{"action": "Rotate AWS key", "impact": "Removes account takeover risk", "effort": "low"}],
                           "trend": "Rising", "wins": []},
}


class FakeGroq:
    """httpx transport standing in for api.groq.com. Records every request body."""

    def __init__(self):
        self.requests: list[dict] = []
        self.script: list = []  # optional queue of (status, json_or_text, headers)
        self.override: dict | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        assert request.headers["authorization"] == "Bearer test-groq-key"
        if self.script:
            status, payload, headers = self.script.pop(0)
            if isinstance(payload, str):
                return httpx.Response(status, text=payload, headers=headers or {})
            return httpx.Response(status, json=payload, headers=headers or {})
        name = body["response_format"]["json_schema"]["name"]
        content = self.override or CANNED[name]
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(content)}}],
                                         "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}})

    def sent_text(self) -> str:
        return json.dumps(self.requests)


@pytest.fixture()
def groq(monkeypatch):
    fake = FakeGroq()
    s = get_settings()
    monkeypatch.setattr(s, "groq_api_key", "test-groq-key")
    monkeypatch.setattr(s, "groq_fallback_model", "openai/gpt-oss-20b")
    monkeypatch.setattr(service, "GroqClient", lambda: GroqClient(transport=httpx.MockTransport(fake.handler)))
    monkeypatch.setattr("app.ai.groq.asyncio.sleep", _no_sleep)
    reset_limits()
    yield fake
    reset_limits()


async def _no_sleep(_):
    return None


def _text_finding(client, content=None):
    content = content or f'# config.py\nAWS_KEY = "{AWS}"; STRIPE = "{STRIPE}"\ntoken = "{UNKNOWN}"\nowner = "dev@acme.io"\n'
    r = client.post("/api/scans/text", json={"content": content, "label": "config.py"})
    assert r.status_code == 201, r.text
    findings = client.get(f"/api/scans/{r.json()['id']}/findings").json()
    return {f["rule_id"]: f for f in findings}


# ---------------------------------------------------------------- redaction unit tests

def test_redaction_removes_known_and_unknown_secrets():
    text = f'key = "{AWS}"\nstripe = "{STRIPE}"\ntok = "{UNKNOWN}"\nurl = "postgres://app:Pa55w0rdLong@db/x"\nmail = "a@b.io"\n' \
           'value = os.getenv("API_KEY")\ndef handle_request_and_validate_user_session(): pass\n'
    out, n = redact_text(text, "settings.py")
    for s in [AWS, STRIPE, UNKNOWN, "Pa55w0rdLong", "a@b.io"]:
        assert s not in out
    assert 'os.getenv("API_KEY")' in out and "handle_request_and_validate_user_session" in out
    assert n >= 5 and leaks(out) == []


def test_guard_payload_cleans_anything_left():
    safe, n = guard_payload([{"role": "user", "content": f"look at {GHP} please"}])
    assert GHP not in safe[0]["content"] and n == 1


def test_snippet_masks_every_secret_on_a_shared_line(auth_client):
    by_rule = _text_finding(auth_client)
    for f in by_rule.values():
        for s in RAW_SECRETS:
            assert s not in (f["snippet"] or "")


# ---------------------------------------------------------------- access control and configuration

def test_ai_routes_require_login(client):
    assert client.get("/api/ai/status").status_code == 401
    assert client.post("/api/ai/findings/1/explain").status_code == 401
    assert client.post("/api/ai/pr-reviews", json={"url": "https://github.com/a/b/pull/1"}).status_code == 401
    assert client.post("/api/ai/posture").status_code == 401


def test_disabled_without_key(auth_client):
    f = _text_finding(auth_client)["aws_access_key_id"]
    status = auth_client.get("/api/ai/status").json()
    assert status["enabled"] is False
    r = auth_client.post(f"/api/ai/findings/{f['id']}/explain")
    assert r.status_code == 503 and "GROQ_API_KEY" in r.json()["detail"]
    assert auth_client.get("/api/meta").json()["ai_enabled"] is False


def test_cannot_use_someone_elses_finding(auth_client, groq):
    f = _text_finding(auth_client)["aws_access_key_id"]
    other = auth_client.post("/api/auth/register", json={"email": "eve@example.com", "password": "supersecret2"}).json()["access_token"]  # ghosttrace:ignore
    r = auth_client.post(f"/api/ai/findings/{f['id']}/explain", headers={"Authorization": f"Bearer {other}"})
    assert r.status_code == 404 and groq.requests == []


# ---------------------------------------------------------------- finding insights

def test_explain_remediate_patch_cache_and_never_leak(auth_client, groq):
    f = _text_finding(auth_client)["aws_access_key_id"]
    for kind in ("explain", "remediate", "patch"):
        r = auth_client.post(f"/api/ai/findings/{f['id']}/{kind}")
        assert r.status_code == 200, r.text
        assert r.json()["cached"] is False and r.json()["model"] == "openai/gpt-oss-120b"
    assert len(groq.requests) == 3
    # cached: no new calls
    again = auth_client.post(f"/api/ai/findings/{f['id']}/explain").json()
    assert again["cached"] is True and len(groq.requests) == 3
    assert set(auth_client.get(f"/api/ai/findings/{f['id']}/insights").json()) == {"explain", "remediate", "patch"}
    # refresh calls again
    assert auth_client.post(f"/api/ai/findings/{f['id']}/explain", json={"refresh": True}).json()["cached"] is False
    assert len(groq.requests) == 4
    sent = groq.sent_text()
    for s in RAW_SECRETS + ["dev@acme.io"]:
        assert s not in sent, f"raw secret {s[:6]}… was sent to the AI"
    body = groq.requests[0]
    assert body["response_format"]["json_schema"]["strict"] is True and body["reasoning_effort"] == "low"
    assert "<untrusted>" in body["messages"][1]["content"]


def test_patch_fetches_github_file_and_redacts_it(auth_client, groq, monkeypatch):
    from app.sources import github as gh
    from app.db import get_db, insert

    me = auth_client.get("/api/auth/me").json()
    insert(get_db(), "findings", {
        "user_id": me["id"], "scan_id": 1, "credential_type": "AWS access key ID", "category": "aws", "rule_id": "aws_access_key_id",
        "secret_masked": "AKIA••••", "fingerprint": "f" * 64, "source_type": "github", "repository": "acme/api", "file_path": "app/settings.py",
        "line_number": 3, "commit_sha": None, "url": None, "snippet": 'AWS_KEY = "AKIA••••"', "in_history_only": False, "entropy": 4.2,
        "confidence": 0.97, "risk_score": 92.0, "severity": "critical", "risk_factors": [], "status": "open",
        "first_seen": __import__("datetime").datetime.now(__import__("datetime").timezone.utc), "last_seen": None,
    })
    fid = get_db().findings.find_one({"fingerprint": "f" * 64})["_id"]
    file_body = f'import os\n\nAWS_KEY = "{AWS}"\nGITHUB = "{GHP}"\nDEBUG = True\n'.encode()

    async def get_repo(self, name):
        return RepoInfo("acme/api", "main", False, "https://github.com/acme/api", False, False, None)

    async def get_file(self, repo, path):
        return file_body

    monkeypatch.setattr(gh.GitHubClient, "get_repo", get_repo)
    monkeypatch.setattr(gh.GitHubClient, "get_file", get_file)
    r = auth_client.post(f"/api/ai/findings/{fid}/patch")
    assert r.status_code == 200, r.text
    sent = groq.sent_text()
    assert AWS not in sent and GHP not in sent
    assert "[REDACTED:aws_access_key_id]" in sent and "DEBUG = True" in sent and "start_line" in sent
    assert "os.environ" in r.json()["result"]["patched"]


def test_model_output_is_redacted_too(auth_client, groq):
    f = _text_finding(auth_client)["aws_access_key_id"]
    groq.override = {**CANNED["ghosttrace_patch"], "patched": f'AWS_KEY = "{AWS}"  # model invented this'}
    r = auth_client.post(f"/api/ai/findings/{f['id']}/patch").json()
    assert AWS not in json.dumps(r) and "[REDACTED" in r["result"]["patched"] and r["redactions"] >= 1


# ---------------------------------------------------------------- limits and errors

def test_per_user_rate_limit(auth_client, groq, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "rate_limit_enabled", True)
    monkeypatch.setattr(s, "ai_finding_limit_per_10min", 2)
    f = _text_finding(auth_client)["aws_access_key_id"]
    codes = [auth_client.post(f"/api/ai/findings/{f['id']}/explain", json={"refresh": True}).status_code for _ in range(3)]
    assert codes == [200, 200, 429] and len(groq.requests) == 2
    # cached answers stay available while limited
    assert auth_client.post(f"/api/ai/findings/{f['id']}/explain").status_code == 200


def test_groq_rate_limit_maps_to_429_with_retry_after(auth_client, groq):
    f = _text_finding(auth_client)["aws_access_key_id"]
    busy = (429, {"error": {"code": "rate_limit_exceeded"}}, {"retry-after": "30"})
    groq.script = [busy, busy]
    r = auth_client.post(f"/api/ai/findings/{f['id']}/explain")
    assert r.status_code == 429 and r.headers["retry-after"] == "30"
    assert [q["model"] for q in groq.requests] == ["openai/gpt-oss-120b", "openai/gpt-oss-20b"]  # fell back before giving up


def test_bad_key_is_a_clean_502(auth_client, groq):
    f = _text_finding(auth_client)["aws_access_key_id"]
    groq.script = [(401, {"error": {"code": "invalid_api_key", "message": "Invalid API Key"}}, None)]
    r = auth_client.post(f"/api/ai/findings/{f['id']}/explain")
    assert r.status_code == 502 and "GROQ_API_KEY" in r.json()["detail"] and "Invalid API Key" not in r.text


def test_unreadable_answer_is_retried(auth_client, groq):
    f = _text_finding(auth_client)["aws_access_key_id"]
    groq.script = [(200, {"choices": [{"message": {"content": "not json at all"}}]}, None)]
    r = auth_client.post(f"/api/ai/findings/{f['id']}/explain")
    assert r.status_code == 200 and len(groq.requests) == 2


def test_retired_model_falls_back(auth_client, groq):
    f = _text_finding(auth_client)["aws_access_key_id"]
    groq.script = [(404, {"error": {"code": "model_not_found"}}, None)]
    r = auth_client.post(f"/api/ai/findings/{f['id']}/remediate")
    assert r.status_code == 200 and r.json()["model"] == "openai/gpt-oss-20b"


def test_timeout_is_a_clean_504(auth_client, groq, monkeypatch):
    f = _text_finding(auth_client)["aws_access_key_id"]

    def boom(request):
        raise httpx.ReadTimeout("slow", request=request)

    monkeypatch.setattr(service, "GroqClient", lambda: GroqClient(transport=httpx.MockTransport(boom)))
    r = auth_client.post(f"/api/ai/findings/{f['id']}/explain")
    assert r.status_code == 504


# ---------------------------------------------------------------- pull-request review

@pytest.mark.parametrize("bad", ["https://evil.com/a/b/pull/1", "a/b", "https://github.com/a/b/pull/x", "https://github.com/../b/pull/1", "not a url"])
def test_pr_url_is_validated(auth_client, groq, bad):
    r = auth_client.post("/api/ai/pr-reviews", json={"url": bad})
    assert r.status_code == 422 and groq.requests == []


def _mock_pr(monkeypatch, head="abc123"):
    from app.sources import github as gh

    async def get_pull(self, repo, number):
        return {"title": "Add deploy script", "body": f"Uses {GHP} for now", "state": "open", "user": {"login": "dev"},
                "head": {"sha": head}, "base": {"ref": "main"}, "changed_files": 3, "additions": 12, "deletions": 0,
                "html_url": f"https://github.com/{repo}/pull/{number}", "merged_at": None}

    async def get_pull_files(self, repo, number, max_files=300):
        return [
            {"filename": "deploy.sh", "status": "added", "additions": 3, "deletions": 0,
             "patch": f"@@ -0,0 +1,3 @@\n+#!/bin/sh\n+export AWS_ACCESS_KEY_ID={AWS}\n+aws s3 sync . s3://bucket"},
            {"filename": "app/views.py", "status": "modified", "additions": 2, "deletions": 0,
             "patch": "@@ -1,2 +1,4 @@\n import db\n+def search(q):\n+    return db.execute(\"SELECT * FROM t WHERE name = '%s'\" % q)"},
            {"filename": "package-lock.json", "status": "modified", "additions": 900, "deletions": 0, "patch": "@@ -1 +1 @@\n+{}"},
        ]

    monkeypatch.setattr(gh.GitHubClient, "get_pull", get_pull)
    monkeypatch.setattr(gh.GitHubClient, "get_pull_files", get_pull_files)


def test_pr_review_end_to_end(auth_client, groq, monkeypatch):
    _mock_pr(monkeypatch)
    r = auth_client.post("/api/ai/pr-reviews", json={"url": "https://github.com/acme/api/pull/7/files"})
    assert r.status_code == 200, r.text
    rev = r.json()
    assert rev["repo"] == "acme/api" and rev["number"] == 7 and rev["cached"] is False
    assert rev["result"]["risk_score"] == 100  # clamped from 140
    assert len(rev["detected_secrets"]) == 1 and rev["detected_secrets"][0]["file"] == "deploy.sh" and rev["detected_secrets"][0]["line"] == 2
    assert AWS not in json.dumps(rev)
    assert rev["stats"]["skipped_files"] == 1  # lockfile
    sent = groq.sent_text()
    assert AWS not in sent and GHP not in sent
    assert "SELECT * FROM t" in sent  # real code still reviewed
    # same head commit: cached
    again = auth_client.post("/api/ai/pr-reviews", json={"url": "acme/api#7"}).json()
    assert again["cached"] is True and len(groq.requests) == 1
    listed = auth_client.get("/api/ai/pr-reviews").json()
    assert listed[0]["verdict"] == "request_changes" and listed[0]["secrets"] == 1
    assert auth_client.get(f"/api/ai/pr-reviews/{rev['id']}").status_code == 200
    assert auth_client.delete(f"/api/ai/pr-reviews/{rev['id']}").status_code == 204
    assert auth_client.get(f"/api/ai/pr-reviews/{rev['id']}").status_code == 404


def test_pr_review_github_error_is_reported(auth_client, groq, monkeypatch):
    from app.sources import github as gh

    async def nope(self, repo, number):
        raise gh.GitHubError("Pull request acme/api#9 was not found on GitHub.")

    monkeypatch.setattr(gh.GitHubClient, "get_pull", nope)
    r = auth_client.post("/api/ai/pr-reviews", json={"url": "acme/api#9"})
    assert r.status_code == 502 and "not found" in r.json()["detail"]


# ---------------------------------------------------------------- posture summary

def test_posture_summary(auth_client, groq):
    assert auth_client.post("/api/ai/posture").status_code == 409  # nothing scanned yet
    assert auth_client.get("/api/ai/posture").json() is None
    _text_finding(auth_client)
    from app.db import get_db, insert

    me = auth_client.get("/api/auth/me").json()
    insert(get_db(), "breach_checks", {"user_id": me["id"], "email": "ceo@acme.io", "breach_count": 1, "breaches": [{"name": "LinkedIn"}],
                                       "exposed_data": [], "risk_score": 50, "source": "xposedornot",
                                       "checked_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc)})
    r = auth_client.post("/api/ai/posture")
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["result"]["grade"] == "D" and p["stats"]["open"] >= 1 and p["stats"]["emails_in_breaches"] == 1
    sent = groq.sent_text()
    assert "ceo@acme.io" not in sent and "LinkedIn" in sent and AWS not in sent and "••" not in sent
    latest = auth_client.get("/api/ai/posture").json()
    assert latest["stale"] is False
    _text_finding(auth_client, f'NEW = "{GHP}"\n')  # data changed
    assert auth_client.get("/api/ai/posture").json()["stale"] is True


# ---------------------------------------------------------------- regression: values that once slipped through

def test_env_file_values_never_reach_the_ai(auth_client, groq):
    env = ("DB_HOST=jCLSbRdIGWmLTukeQvFIDruMgNaNhXKx\nDB_USER=railway\nDB_PASSWORD=Hq8vLx2Wm9PzRt4K\nPORT=3306\n"
           "EMAIL_USER=me@gmail.com\nEMAIL_PASS=hlnv vhsg dlrl rnpw\nSECRET_KEY=correct horse battery staple\n")
    r = auth_client.post("/api/scans/text", json={"content": env, "label": ".env"})
    findings = auth_client.get(f"/api/scans/{r.json()['id']}/findings").json()
    rules = {f["rule_id"] for f in findings}
    assert {"env_password", "app_password"} <= rules
    for f in findings:
        assert auth_client.post(f"/api/ai/findings/{f['id']}/explain").status_code == 200
    sent = groq.sent_text()
    for raw in ["jCLSbRdIGWmLTukeQvFIDruMgNaNhXKx", "Hq8vLx2Wm9PzRt4K", "hlnv vhsg dlrl rnpw", "correct horse battery staple", "me@gmail.com"]:
        assert raw not in sent


def test_redaction_keeps_code_readable():
    code = ("const apiKey = process.env.API_KEY\nconst XMLHttpRequestEventTarget = handleRequestAndValidateUserSession()\n"
            "TOKEN_EXPIRY=3600\n")
    out, _ = redact_text(code, "app.js")
    assert out == code
