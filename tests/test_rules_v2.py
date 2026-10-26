"""New detectors (v2 rule set): each fires on a realistic sample and stays quiet on look-alikes."""

import random
import string

import pytest

from app.detection.engine import scan_text
from app.detection.rules import RULES

_r = random.Random(7)
HEX = "0123456789abcdef"


def g(n, chars=string.ascii_letters + string.digits):
    return "".join(_r.choice(chars) for _ in range(n))


POSITIVE = {
    "azure_ad_client_secret": (f'AZURE_CLIENT_SECRET="{g(3)}8Q~{g(32)}"', "settings.txt"),
    "supabase_token": (f"token = 'sbp_{g(40, HEX)}'", "config.txt"),
    "databricks_token": (f"DATABRICKS='dapi{g(32, HEX)}'", "config.txt"),
    "pulumi_token": (f"x = 'pul-{g(40, HEX)}'", "config.txt"),
    "doppler_token": (f"DOPPLER = 'dp.st.{g(43)}'", "config.txt"),
    "gitlab_other_token": (f"runner: glrt-{g(20)}", "ci.yml"),
    "npmrc_auth": (f"//registry.npmjs.org/:_authToken={g(36)}", ".npmrc"),
    "groq_api_key": (f"GROQ = 'gsk_{g(52)}'", "config.txt"),
    "openrouter_api_key": (f"k='sk-or-v1-{g(64, HEX)}'", "config.txt"),
    "xai_api_key": (f"k='xai-{g(80)}'", "config.txt"),
    "perplexity_api_key": (f"k='pplx-{g(48)}'", "config.txt"),
    "replicate_token": (f"k='r8_{g(37)}'", "config.txt"),
    "stripe_webhook_secret": (f"k='whsec_{g(32)}'", "config.txt"),
    "brevo_api_key": (f"k='xkeysib-{g(64, HEX)}-{g(16)}'", "config.txt"),
    "resend_api_key": (f"k='re_{g(8)}_{g(24)}'", "config.txt"),
    "notion_token": (f"k='ntn_{g(11, string.digits)}{g(35)}'", "config.txt"),
    "airtable_pat": (f"k='pat{g(14)}.{g(64, HEX)}'", "config.txt"),
    "postman_api_key": (f"k='PMAK-{g(24, HEX)}-{g(34, HEX)}'", "config.txt"),
    "grafana_token": (f"k='glsa_{g(32)}_{g(8, HEX)}'", "config.txt"),
    "mapbox_secret_token": (f"k='sk.eyJ{g(60)}.{g(22)}'", "config.txt"),
    "age_secret_key": ("AGE-SECRET-KEY-1" + g(58, "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"), "key.txt"),
    "jdbc_password": ("url=jdbc:mysql://db:3306/app?user=root&password=Xk92mPq7Lr", "app.properties"),
    "connection_string_password": ('conn = "Server=db.acme.io;Database=app;User Id=sa;Password=Xk92mPq7Lr!;"', "appsettings.txt"),
    "app_password": ("EMAIL_PASS=hlnv vhsg dlrl rnpw", ".env"),
    "env_password": ("SMTP_PASS=Zq8xLm2Pw9Rt", ".env"),
    "env_token": (f"GITHUB_TOKEN={g(40)}", ".env"),
}

NEGATIVE = [
    ("const appPassword = getPassword(user)", "a.js"),
    ("STRIPE_PUBLISHABLE_KEY=pk_live_" + g(30), ".env"),
    ("NEXT_PUBLIC_API_KEY=" + g(30), ".env"),
    ("GOOGLE_CLIENT_ID=" + g(30), ".env"),
    ("SESSION_KEY_PATH=/etc/keys/session.pem", ".env"),
    ("const re_render_count_and_more = 1", "a.js"),
    ("TOKEN_EXPIRY=3600", ".env"),
    ("let mail_password_field = 'passwordinputfield'", "a.js"),
]


@pytest.mark.parametrize("rule_id", sorted(POSITIVE))
def test_new_rule_detects(rule_id):
    line, path = POSITIVE[rule_id]
    assert rule_id in [m.rule.id for m in scan_text(line, path)]


@pytest.mark.parametrize("line,path", NEGATIVE)
def test_no_false_positive(line, path):
    assert [m.rule.id for m in scan_text(line, path) if not m.placeholder] == []


def test_rule_table_is_consistent():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    for r in RULES:
        assert all(k == k.lower() for k in r.keywords), r.id  # the prefilter compares against lowercased text


def test_keyword_prefilter_never_hides_a_match():
    for rule_id, (line, path) in POSITIVE.items():
        rule = next(r for r in RULES if r.id == rule_id)
        assert not rule.keywords or any(k in line.lower() for k in rule.keywords), rule_id
