import random
import string

from app.detection.engine import mask_secret, scan_diff_patch, scan_text, should_skip_path


def rnd(alpha, n, seed=1):
    r = random.Random(seed)
    return "".join(r.choice(alpha) for _ in range(n))


AWS = "AKIA" + rnd(string.ascii_uppercase + string.digits, 16)
GHP = "ghp_" + rnd(string.ascii_letters + string.digits, 36, 2)


def rules(text, path="app.py"):
    return {m.rule.id for m in scan_text(text, path)}


def test_provider_rules():
    assert "aws_access_key_id" in rules(f"key={AWS}")
    assert "github_pat" in rules(f"token: {GHP}")
    assert "google_api_key" in rules("k = 'AIza" + rnd(string.ascii_letters + string.digits + "-_", 35, 3) + "'")
    assert "stripe_live_secret" in rules("sk_live_" + rnd(string.ascii_letters + string.digits, 30, 4))
    assert "database_url" in rules("DATABASE_URL=postgres://app:Zq8vLm2pXr7t@db.prod:5432/core")  # ghosttrace:ignore
    assert "private_key" in rules("-----BEGIN OPENSSH PRIVATE KEY-----\n" + rnd(string.ascii_letters, 70, 5) + "\n-----END OPENSSH PRIVATE KEY-----")
    assert "password_assignment" in rules('password = "Tr0ub4dor&3x"')  # ghosttrace:ignore
    assert "email_address" in rules("contact priya@fintrack.in")  # ghosttrace:ignore


def test_specific_rule_beats_generic():
    found = scan_text(f'api_key = "{AWS}"')
    assert [m.rule.id for m in found] == ["aws_access_key_id"]


def test_placeholders_and_noise():
    found = scan_text('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE')  # ghosttrace:ignore
    assert found and found[0].placeholder
    assert not rules("email user@example.com or noreply@github.com")
    assert not rules('api_key = "aaaaaaaaaaaaaaaaaaaa"')  # below entropy floor


def test_masking_never_leaks_secret():
    m = scan_text(f"token: {GHP}")[0]
    assert GHP not in m.snippet and GHP not in mask_secret(GHP)
    assert mask_secret(GHP).startswith("ghp_")


def test_line_numbers_and_diff():
    assert scan_text(f"a\nb\nkey={AWS}\n")[0].line == 3
    patch = f"@@ -10,2 +10,3 @@\n context\n-old\n+AWS={AWS}\n"
    m = scan_diff_patch(patch, "x.sh")
    assert m and m[0].line == 11


def test_skip_paths():
    assert should_skip_path("node_modules/a/index.js")
    assert should_skip_path("package-lock.json")
    assert should_skip_path("img/logo.png")
    assert not should_skip_path("src/.env")


def test_code_references_are_not_secrets():
    code = (
        "secret = base64.b64decode(value)\n"
        "api_key = request.query_params.get('k')\n"
        "aws_secret_access_key=S3_SECRET_KEY,\n"
        "password = Prompt.ask('pw')\n"
    )
    assert scan_text(code, path="app.py", include_emails=False) == []


def test_real_literals_still_detected():
    env = "DB_PASSWORD=Hq7rT2mVx9Lp4wZs\nSTRIPE_SECRET=Zk8Qw3Lm9Xv2Rt7Yp5Nc\n"
    assert len(scan_text(env, path=".env", include_emails=False)) == 2
    py = 'db_password = "Hq7rT2mVx9Lp4wZs"\n'
    assert len(scan_text(py, path="settings.py", include_emails=False)) == 1


def test_code_expressions_are_not_secrets():
    # Variables, env lookups, function calls and f-string interpolation (false positives from a real scan).
    code = "\n".join([
        "S3_SECRET_KEY = os.getenv('S3_SECRET_KEY')",
        "    aws_secret_access_key=S3_SECRET_KEY,",
        "AWS_SECRET_KEY = AWS_SECRET_KEY",
        "    password_hash=hash_password(body.password),",
        "secret = m.group(rule.group)",
        "line = f'db_password = \"{human_password(r)}\"'",
        "const apiKey = process.env.GEMINI_API_KEY;",
    ])
    assert scan_text(code, "app.py") == []
    # A label that merely repeats the key name is kept but marked as a placeholder, so it scores low.
    assert all(m.placeholder for m in scan_text('labels = {"password": "Passwords"}', "app.py"))


def test_env_password_rule_skips_source_files():
    assert rules("SMTP_PASSWORD=Kp9vQ2xLm7Rt", ".env") == {"env_password"}
    assert "env_password" not in rules("SMTP_PASSWORD=Kp9vQ2xLm7Rt", "settings.py")


def test_private_key_built_in_code_is_ignored():
    builder = '"-----BEGIN RSA PRIVATE KEY-----\\n" + "\\n".join(rnd(B64, 64) for _ in range(6)) + "\\n-----END RSA PRIVATE KEY-----"'
    assert "private_key" not in rules(builder, "train.py")
    body = rnd(string.ascii_letters + string.digits + "+/", 64, 8)
    escaped = '"private_key": "-----BEGIN PRIVATE KEY-----\\n' + body + "\\n" + body + '\\n-----END PRIVATE KEY-----\\n"'
    assert "private_key" in rules(escaped, "service-account.json")  # GCP JSON keys use literal \n


def test_ignore_marker_and_attribution_files():
    assert rules(f"key={AWS}  # ghosttrace:ignore") == set()
    assert rules("Copyright 2010 Jane <jane@leclan.ch>", "LICENSE") == set()
    assert rules("sender = 'alerts@ghosttrace.local'") == set()


def test_vendored_packages_are_skipped():
    from app.services.scanner import vendored_prefixes

    paths = ["package/PIL/Image.py", "package/pillow-12.2.0.dist-info/METADATA", "app.py"]
    prefixes = vendored_prefixes(paths)
    assert prefixes == ("package/",)
    assert not "app.py".startswith(prefixes)
