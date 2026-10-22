"""Credential detection rules.

Each rule has a regex whose `group` captures the secret value. Provider-specific rules are
`specific=True`; they win over generic rules when spans overlap.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str  # aws | cloud | api_key | token | jwt | private_key | database | password | email | webhook
    severity: str  # base severity before AI scoring: critical | high | medium | low
    pattern: re.Pattern
    group: int = 0
    specific: bool = True
    min_entropy: float = 0.0


def _r(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


RULES: list[Rule] = [
    # ---- AWS / cloud ----
    Rule("aws_access_key_id", "AWS access key ID", "aws", "critical", _r(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), 1),
    Rule("aws_secret_access_key", "AWS secret access key", "aws", "critical",
         _r(r"(?i)aws.{0,25}?(?:secret|private)?.{0,25}?['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), 1, min_entropy=3.8),
    Rule("gcp_service_account", "Google Cloud service account key", "cloud", "critical",
         _r(r"\"private_key_id\"\s*:\s*\"([a-f0-9]{40})\""), 1),
    Rule("google_api_key", "Google API key", "api_key", "high", _r(r"\b(AIza[0-9A-Za-z\-_]{35})(?![0-9A-Za-z\-_])"), 1),
    Rule("google_oauth_secret", "Google OAuth client secret", "api_key", "high", _r(r"\b(GOCSPX-[A-Za-z0-9\-_]{28})(?![A-Za-z0-9\-_])"), 1),
    Rule("azure_storage_key", "Azure storage account key", "cloud", "critical", _r(r"AccountKey=([A-Za-z0-9+/]{86}==)"), 1),
    Rule("digitalocean_token", "DigitalOcean token", "cloud", "critical", _r(r"\b(do[opr]_v1_[a-f0-9]{64})\b"), 1),
    Rule("heroku_api_key", "Heroku API key", "cloud", "high",
         _r(r"(?i)heroku.{0,25}[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"), 1),
    Rule("hashicorp_vault_token", "HashiCorp Vault token", "cloud", "critical", _r(r"\b(hvs\.[A-Za-z0-9_\-]{90,120})\b"), 1),
    Rule("firebase_fcm_key", "Firebase Cloud Messaging server key", "api_key", "high",
         _r(r"\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})\b"), 1),

    # ---- source control / package registries ----
    Rule("github_pat", "GitHub personal access token", "token", "critical", _r(r"\b(ghp_[A-Za-z0-9]{36})\b"), 1),
    Rule("github_fine_grained_pat", "GitHub fine-grained token", "token", "critical", _r(r"\b(github_pat_[A-Za-z0-9_]{82})\b"), 1),
    Rule("github_app_token", "GitHub OAuth / app token", "token", "high", _r(r"\b(gh[ousr]_[A-Za-z0-9]{36})\b"), 1),
    Rule("gitlab_pat", "GitLab personal access token", "token", "critical", _r(r"\b(glpat-[A-Za-z0-9\-_]{20})(?![A-Za-z0-9\-_])"), 1),
    Rule("npm_token", "npm access token", "token", "high", _r(r"\b(npm_[A-Za-z0-9]{36})\b"), 1),
    Rule("pypi_token", "PyPI upload token", "token", "high", _r(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})"), 1),

    # ---- AI providers ----
    Rule("openai_api_key", "OpenAI API key", "api_key", "critical",
         _r(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,200}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?![A-Za-z0-9_\-])"), 1),
    Rule("anthropic_api_key", "Anthropic API key", "api_key", "critical",
         _r(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,120})(?![A-Za-z0-9_\-])"), 1),
    Rule("huggingface_token", "Hugging Face token", "token", "high", _r(r"\b(hf_[A-Za-z0-9]{34})\b"), 1),

    # ---- payments ----
    Rule("stripe_live_secret", "Stripe live secret key", "api_key", "critical", _r(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b"), 1),
    Rule("stripe_test_secret", "Stripe test secret key", "api_key", "low", _r(r"\b(sk_test_[0-9a-zA-Z]{24,99})\b"), 1),
    Rule("square_token", "Square access token", "api_key", "high", _r(r"\b(EAAA[A-Za-z0-9\-_]{60}|sq0csp-[0-9A-Za-z\-_]{43})(?![A-Za-z0-9\-_])"), 1),
    Rule("braintree_token", "PayPal Braintree access token", "api_key", "critical",
         _r(r"(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})"), 1),
    Rule("shopify_token", "Shopify access token", "api_key", "high", _r(r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"), 1),

    # ---- messaging / SaaS ----
    Rule("slack_token", "Slack token", "token", "high", _r(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,72})(?![0-9A-Za-z\-])"), 1),
    Rule("slack_webhook", "Slack incoming webhook", "webhook", "medium",
         _r(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24})"), 1),
    Rule("discord_webhook", "Discord webhook", "webhook", "medium",
         _r(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{60,70})"), 1),
    Rule("discord_bot_token", "Discord bot token", "token", "high",
         _r(r"\b([MNO][A-Za-z\d_\-]{23,25}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,38})\b"), 1),
    Rule("telegram_bot_token", "Telegram bot token", "token", "high", _r(r"\b(\d{8,10}:AA[0-9A-Za-z_\-]{33})(?![0-9A-Za-z_\-])"), 1),
    Rule("twilio_api_key", "Twilio API key", "api_key", "high", _r(r"\b(SK[0-9a-fA-F]{32})\b"), 1),
    Rule("sendgrid_api_key", "SendGrid API key", "api_key", "high", _r(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9_\-])"), 1),
    Rule("mailgun_api_key", "Mailgun API key", "api_key", "high", _r(r"\b(key-[0-9a-zA-Z]{32})\b"), 1),
    Rule("mailchimp_api_key", "Mailchimp API key", "api_key", "medium", _r(r"\b([0-9a-f]{32}-us\d{1,2})\b"), 1),
    Rule("dropbox_token", "Dropbox access token", "token", "high", _r(r"\b(sl\.[A-Za-z0-9\-_]{130,152})(?![A-Za-z0-9\-_])"), 1),
    Rule("linear_api_key", "Linear API key", "api_key", "medium", _r(r"\b(lin_api_[A-Za-z0-9]{40})\b"), 1),
    Rule("atlassian_token", "Atlassian API token", "api_key", "high", _r(r"\b(ATATT3[A-Za-z0-9_\-=]{180,200})(?![A-Za-z0-9_\-=])"), 1),
    Rule("newrelic_key", "New Relic API key", "api_key", "medium", _r(r"\b(NRAK-[A-Z0-9]{27})\b"), 1),
    Rule("sentry_dsn", "Sentry DSN", "webhook", "low", _r(r"(https://[0-9a-f]{32}@o\d+\.ingest\.(?:us\.)?sentry\.io/\d+)"), 1),
    Rule("facebook_token", "Facebook access token", "token", "high", _r(r"\b(EAACEdEose0cBA[0-9A-Za-z]+)\b"), 1),
    Rule("cloudinary_url", "Cloudinary credentials", "api_key", "medium", _r(r"cloudinary://\d+:([A-Za-z0-9_\-]{20,})@\w+"), 1),

    # ---- tokens / keys ----
    Rule("jwt", "JSON Web Token", "jwt", "medium",
         _r(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})(?![A-Za-z0-9_\-])"), 1),
    Rule("private_key", "Private key (PEM / OpenSSH)", "private_key", "critical",
         _r(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{20,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), 1),
    Rule("putty_private_key", "PuTTY private key", "private_key", "critical", _r(r"(PuTTY-User-Key-File-\d: [^\r\n]+)"), 1),

    # ---- databases / connection strings ----
    Rule("database_url", "Database connection string", "database", "critical",
         _r(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://[^\s:@/'\"]+:([^\s@/'\"]{3,})@[^\s'\"<>]+"), 1),
    Rule("basic_auth_url", "Credentials in URL", "password", "high",
         _r(r"\bhttps?://[A-Za-z0-9._~%\-]+:([^\s:@/'\"]{4,})@[A-Za-z0-9.\-]+"), 1),

    # ---- generic ----
    Rule("password_assignment", "Hard-coded password", "password", "high",
         _r(r"(?i)\b[\w.\-]*(?:password|passwd|pwd|passphrase|db_pass)\b['\"]?\s*(?:[:=]|=>)\s*['\"]([^'\"\s]{6,128})['\"]"), 1,
         specific=False, min_entropy=2.5),
    Rule("env_password", "Password in environment file", "password", "high",
         _r(r"(?m)^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|PASSPHRASE|_PWD|SECRET)[A-Z0-9_]*\s*=\s*['\"]?([^\s'\"#]{6,128})['\"]?\s*$"), 1,
         specific=False, min_entropy=2.5),
    Rule("generic_api_key", "Generic API key or secret", "api_key", "medium",
         _r(r"(?i)\b[\w.\-]*(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|secret[_\-]?key|app[_\-]?secret|private[_\-]?key)\b['\"]?\s*(?:[:=]|=>)\s*['\"]?([A-Za-z0-9_\-.+/=]{16,128})['\"]?"), 1,
         specific=False, min_entropy=3.5),
    Rule("email_address", "Email address", "email", "low",
         _r(r"(?<![\w.+\-])([A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,24})\b"), 1, specific=False),
]

CATEGORY_LABELS = {
    "aws": "AWS credentials",
    "cloud": "Cloud credentials",
    "api_key": "API keys",
    "token": "Access tokens",
    "jwt": "JWT tokens",
    "private_key": "Private keys",
    "database": "Database credentials",
    "password": "Passwords",
    "email": "Email addresses",
    "webhook": "Webhooks",
}
