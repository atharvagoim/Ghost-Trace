"""Credential detection rules.

Each rule has a regex whose `group` captures the secret value. Provider-specific rules are `specific=True`; they win
over generic rules when spans overlap.

Speed: every rule lists `keywords`, lowercase substrings that any match must contain. The engine lowercases a file
once and skips a rule's regex entirely when none of its keywords appear, which is most rules for most files (the same
idea gitleaks uses). Generic rules start at their keyword instead of scanning `[\\w.-]*` from every word boundary.
A rule with no keywords always runs.
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
    keywords: tuple[str, ...] = ()
    deny: re.Pattern | None = None  # skip a match when its line matches this (e.g. public keys)
    require: re.Pattern | None = None  # keep a match only when its line also matches this


def _r(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


R = Rule  # short alias to keep the table readable

RULES: list[Rule] = [
    # ---- AWS / cloud ----
    R("aws_access_key_id", "AWS access key ID", "aws", "critical", _r(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), 1,
      keywords=("akia", "asia", "abia", "acca")),
    R("aws_secret_access_key", "AWS secret access key", "aws", "critical",
      _r(r"(?i)aws.{0,25}?(?:secret|private)?.{0,25}?['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), 1,
      min_entropy=3.8, keywords=("aws",)),
    R("gcp_service_account", "Google Cloud service account key", "cloud", "critical",
      _r(r"\"private_key_id\"\s*:\s*\"([a-f0-9]{40})\""), 1, keywords=("private_key_id",)),
    R("google_api_key", "Google API key", "api_key", "high", _r(r"\b(AIza[0-9A-Za-z\-_]{35})(?![0-9A-Za-z\-_])"), 1, keywords=("aiza",)),
    R("google_oauth_secret", "Google OAuth client secret", "api_key", "high",
      _r(r"\b(GOCSPX-[A-Za-z0-9\-_]{28})(?![A-Za-z0-9\-_])"), 1, keywords=("gocspx-",)),
    R("azure_storage_key", "Azure storage account key", "cloud", "critical", _r(r"AccountKey=([A-Za-z0-9+/]{86}==)"), 1,
      keywords=("accountkey=",)),
    R("azure_ad_client_secret", "Azure AD client secret", "cloud", "critical",
      _r(r"(?:^|[\s'\"=:,(])([A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.\-]{31,34})(?![A-Za-z0-9_~.\-])"), 1, keywords=("q~",)),
    R("digitalocean_token", "DigitalOcean token", "cloud", "critical", _r(r"\b(do[opr]_v1_[a-f0-9]{64})\b"), 1,
      keywords=("dop_v1_", "doo_v1_", "dor_v1_")),
    R("heroku_api_key", "Heroku API key", "cloud", "high",
      _r(r"(?i)heroku.{0,25}[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"), 1, keywords=("heroku",)),
    R("hashicorp_vault_token", "HashiCorp Vault token", "cloud", "critical", _r(r"\b(hvs\.[A-Za-z0-9_\-]{90,120})\b"), 1,
      keywords=("hvs.",)),
    R("firebase_fcm_key", "Firebase Cloud Messaging server key", "api_key", "high",
      _r(r"\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})\b"), 1, keywords=("aaaa",)),
    R("supabase_token", "Supabase secret / access token", "cloud", "critical",
      _r(r"\b(sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_\-]{20,64})(?![A-Za-z0-9_\-])"), 1, keywords=("sbp_", "sb_secret_")),
    R("databricks_token", "Databricks access token", "cloud", "high", _r(r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b"), 1, keywords=("dapi",)),
    R("pulumi_token", "Pulumi access token", "cloud", "high", _r(r"\b(pul-[a-f0-9]{40})\b"), 1, keywords=("pul-",)),
    R("doppler_token", "Doppler token", "cloud", "high", _r(r"\b(dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44})\b"), 1,
      keywords=("dp.",)),

    # ---- source control / package registries ----
    R("github_pat", "GitHub personal access token", "token", "critical", _r(r"\b(ghp_[A-Za-z0-9]{36})\b"), 1, keywords=("ghp_",)),
    R("github_fine_grained_pat", "GitHub fine-grained token", "token", "critical", _r(r"\b(github_pat_[A-Za-z0-9_]{82})\b"), 1,
      keywords=("github_pat_",)),
    R("github_app_token", "GitHub OAuth / app token", "token", "high", _r(r"\b(gh[ousr]_[A-Za-z0-9]{36})\b"), 1,
      keywords=("gho_", "ghu_", "ghs_", "ghr_")),
    R("gitlab_pat", "GitLab personal access token", "token", "critical", _r(r"\b(glpat-[A-Za-z0-9\-_]{20})(?![A-Za-z0-9\-_])"), 1,
      keywords=("glpat-",)),
    R("gitlab_other_token", "GitLab runner / deploy token", "token", "high",
      _r(r"\b(gl(?:rt|dt|ptt|ft|soat)-[A-Za-z0-9_\-]{20,64})(?![A-Za-z0-9_\-])"), 1, keywords=("glrt-", "gldt-", "glptt-", "glft-", "glsoat-")),
    R("npm_token", "npm access token", "token", "high", _r(r"\b(npm_[A-Za-z0-9]{36})\b"), 1, keywords=("npm_",)),
    R("npmrc_auth", "Registry auth token (.npmrc)", "token", "high",
      _r(r"(?i)_auth(?:Token)?\s*=\s*['\"]?([A-Za-z0-9_\-.=+/]{20,256})"), 1, min_entropy=3.5, keywords=("_auth",)),
    R("pypi_token", "PyPI upload token", "token", "high", _r(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})"), 1, keywords=("pypi-",)),

    # ---- AI providers ----
    R("openai_api_key", "OpenAI API key", "api_key", "critical",
      _r(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,200}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?![A-Za-z0-9_\-])"), 1,
      keywords=("sk-",)),
    R("anthropic_api_key", "Anthropic API key", "api_key", "critical",
      _r(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,120})(?![A-Za-z0-9_\-])"), 1, keywords=("sk-ant-",)),
    R("groq_api_key", "Groq API key", "api_key", "critical", _r(r"\b(gsk_[A-Za-z0-9]{52})\b"), 1, keywords=("gsk_",)),
    R("openrouter_api_key", "OpenRouter API key", "api_key", "high", _r(r"\b(sk-or-v1-[a-f0-9]{64})\b"), 1, keywords=("sk-or-v1-",)),
    R("xai_api_key", "xAI API key", "api_key", "high", _r(r"\b(xai-[A-Za-z0-9]{80})\b"), 1, keywords=("xai-",)),
    R("perplexity_api_key", "Perplexity API key", "api_key", "high", _r(r"\b(pplx-[A-Za-z0-9]{48})\b"), 1, keywords=("pplx-",)),
    R("replicate_token", "Replicate API token", "api_key", "high", _r(r"\b(r8_[A-Za-z0-9]{37})\b"), 1, keywords=("r8_",)),
    R("huggingface_token", "Hugging Face token", "token", "high", _r(r"\b(hf_[A-Za-z0-9]{34})\b"), 1, keywords=("hf_",)),

    # ---- payments ----
    R("stripe_live_secret", "Stripe live secret key", "api_key", "critical", _r(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b"), 1,
      keywords=("sk_live_", "rk_live_")),
    R("stripe_test_secret", "Stripe test secret key", "api_key", "low", _r(r"\b(sk_test_[0-9a-zA-Z]{24,99})\b"), 1, keywords=("sk_test_",)),
    R("stripe_webhook_secret", "Stripe webhook signing secret", "api_key", "high", _r(r"\b(whsec_[A-Za-z0-9]{32,64})\b"), 1,
      keywords=("whsec_",)),
    R("square_token", "Square access token", "api_key", "high",
      _r(r"\b(EAAA[A-Za-z0-9\-_]{60}|sq0csp-[0-9A-Za-z\-_]{43})(?![A-Za-z0-9\-_])"), 1, keywords=("eaaa", "sq0csp-")),
    R("braintree_token", "PayPal Braintree access token", "api_key", "critical",
      _r(r"(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})"), 1, keywords=("access_token$production$",)),
    R("shopify_token", "Shopify access token", "api_key", "high", _r(r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"), 1,
      keywords=("shpat_", "shpca_", "shppa_", "shpss_")),

    # ---- messaging / SaaS ----
    R("slack_token", "Slack token", "token", "high", _r(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,72})(?![0-9A-Za-z\-])"), 1,
      keywords=("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-")),
    R("slack_webhook", "Slack incoming webhook", "webhook", "medium",
      _r(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24})"), 1, keywords=("hooks.slack.com",)),
    R("discord_webhook", "Discord webhook", "webhook", "medium",
      _r(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{60,70})"), 1, keywords=("/api/webhooks/",)),
    R("discord_bot_token", "Discord bot token", "token", "high",
      _r(r"\b([MNO][A-Za-z\d_\-]{23,25}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,38})\b"), 1),
    R("telegram_bot_token", "Telegram bot token", "token", "high", _r(r"\b(\d{8,10}:AA[0-9A-Za-z_\-]{33})(?![0-9A-Za-z_\-])"), 1,
      keywords=(":aa",)),
    R("twilio_api_key", "Twilio API key", "api_key", "high", _r(r"\b(SK[0-9a-fA-F]{32})\b"), 1, keywords=("sk",)),
    R("sendgrid_api_key", "SendGrid API key", "api_key", "high",
      _r(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9_\-])"), 1, keywords=("sg.",)),
    R("mailgun_api_key", "Mailgun API key", "api_key", "high", _r(r"\b(key-[0-9a-zA-Z]{32})\b"), 1, keywords=("key-",)),
    R("mailchimp_api_key", "Mailchimp API key", "api_key", "medium", _r(r"\b([0-9a-f]{32}-us\d{1,2})\b"), 1, keywords=("-us",)),
    R("brevo_api_key", "Brevo (Sendinblue) API key", "api_key", "high", _r(r"\b(xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16})\b"), 1,
      keywords=("xkeysib-",)),
    R("resend_api_key", "Resend API key", "api_key", "high", _r(r"\b(re_[A-Za-z0-9]{8}_[A-Za-z0-9]{24})\b"), 1, keywords=("re_",)),
    R("dropbox_token", "Dropbox access token", "token", "high", _r(r"\b(sl\.[A-Za-z0-9\-_]{130,152})(?![A-Za-z0-9\-_])"), 1,
      keywords=("sl.",)),
    R("linear_api_key", "Linear API key", "api_key", "medium", _r(r"\b(lin_api_[A-Za-z0-9]{40})\b"), 1, keywords=("lin_api_",)),
    R("notion_token", "Notion integration token", "api_key", "high", _r(r"\b(secret_[A-Za-z0-9]{43}|ntn_\d{11}[A-Za-z0-9]{35})\b"), 1,
      keywords=("secret_", "ntn_")),
    R("airtable_pat", "Airtable personal access token", "api_key", "high", _r(r"\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b"), 1,
      keywords=("pat",)),
    R("postman_api_key", "Postman API key", "api_key", "high", _r(r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b"), 1, keywords=("pmak-",)),
    R("atlassian_token", "Atlassian API token", "api_key", "high", _r(r"\b(ATATT3[A-Za-z0-9_\-=]{180,200})(?![A-Za-z0-9_\-=])"), 1,
      keywords=("atatt3",)),
    R("newrelic_key", "New Relic API key", "api_key", "medium", _r(r"\b(NRAK-[A-Z0-9]{27})\b"), 1, keywords=("nrak-",)),
    R("grafana_token", "Grafana token", "api_key", "high",
      _r(r"\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}|glc_[A-Za-z0-9+/]{32,400}={0,2})(?![A-Za-z0-9+/=_])"), 1, keywords=("glsa_", "glc_")),
    R("sentry_dsn", "Sentry DSN", "webhook", "low", _r(r"(https://[0-9a-f]{32}@o\d+\.ingest\.(?:us\.)?sentry\.io/\d+)"), 1,
      keywords=("sentry.io",)),
    R("facebook_token", "Facebook access token", "token", "high", _r(r"\b(EAACEdEose0cBA[0-9A-Za-z]+)\b"), 1, keywords=("eaacedeose0cba",)),
    R("cloudinary_url", "Cloudinary credentials", "api_key", "medium", _r(r"cloudinary://\d+:([A-Za-z0-9_\-]{20,})@\w+"), 1,
      keywords=("cloudinary://",)),
    R("mapbox_secret_token", "Mapbox secret token", "api_key", "high",
      _r(r"\b(sk\.eyJ[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{20,})(?![A-Za-z0-9_\-])"), 1, keywords=("sk.eyj",)),

    # ---- tokens / keys ----
    R("jwt", "JSON Web Token", "jwt", "medium",
      _r(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})(?![A-Za-z0-9_\-])"), 1, keywords=("eyj",)),
    R("private_key", "Private key (PEM / OpenSSH)", "private_key", "critical",
      _r(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{20,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), 1,
      keywords=("private key",)),
    R("putty_private_key", "PuTTY private key", "private_key", "critical", _r(r"(PuTTY-User-Key-File-\d: [^\r\n]+)"), 1,
      keywords=("putty-user-key-file",)),
    R("age_secret_key", "age encryption secret key", "private_key", "critical",
      _r(r"\b(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})\b"), 1, keywords=("age-secret-key-1",)),

    # ---- databases / connection strings ----
    R("database_url", "Database connection string", "database", "critical",
      _r(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://[^\s:@/'\"]+:([^\s@/'\"]{3,})@[^\s'\"<>]+"), 1,
      keywords=("://",)),
    R("jdbc_password", "JDBC connection password", "database", "critical",
      _r(r"(?i)jdbc:[a-z0-9]+:[^\s'\"]*?[;?&]password=([^;&\s'\"]{4,128})"), 1, keywords=("jdbc:",)),
    R("connection_string_password", "Password in connection string", "database", "high",
      _r(r"(?i)(?:server|data source|host|address)\s*=[^;'\"\n]+;[^'\"\n]*?\b(?:password|pwd)\s*=\s*([^;'\"\n]{4,128})"), 1,
      specific=False, min_entropy=2.5, keywords=("password=", "pwd=", "password =", "pwd =")),
    R("basic_auth_url", "Credentials in URL", "password", "high",
      _r(r"\bhttps?://[A-Za-z0-9._~%\-]+:([^\s:@/'\"]{4,})@[A-Za-z0-9.\-]+"), 1, keywords=("://",)),

    # ---- generic ----
    # App passwords (Gmail, Outlook, iCloud) are 16 lowercase letters, often written in groups of four.
    R("app_password", "Email app password", "password", "high",
      _r(r"(?i)(?:pass|pwd)\w*['\"]?\s*(?:[:=]|=>)\s*['\"]?([a-z]{4}[ \-]?[a-z]{4}[ \-]?[a-z]{4}[ \-]?[a-z]{4})(?![A-Za-z0-9])"), 1,
      min_entropy=3.0, keywords=("pass", "pwd"), require=_r(r"(?i)(?:mail|smtp|imap|app)[\w\-]{0,24}(?:pass|pwd)")),
    R("password_assignment", "Hard-coded password", "password", "high",
      _r(r"(?i)(?:password|passwd|pwd|passphrase|db_pass)\b['\"]?\s*(?:[:=]|=>)\s*['\"]([^'\"\s]{6,128})['\"]"), 1,
      specific=False, min_entropy=2.5, keywords=("pass", "pwd")),
    R("env_password", "Password in environment file", "password", "high",
      _r(r"(?m)^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|PASSPHRASE|_PASS|_PWD|SECRET)[A-Z0-9_]*[ \t]*=[ \t]*['\"]?([^\s'\"#]{6,128})['\"]?[ \t]*\r?$"), 1,
      specific=False, min_entropy=2.5, keywords=("pass", "pwd", "secret")),
    R("env_token", "Token or key in environment file", "api_key", "medium",
      _r(r"(?m)^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:_TOKEN|_API_KEY|_APIKEY|_SECRET_KEY|_ACCESS_KEY|_AUTH_KEY|_PRIVATE_KEY|_CLIENT_SECRET|_KEY)[A-Z0-9_]*[ \t]*=[ \t]*['\"]?([^\s'\"#]{12,256})['\"]?[ \t]*\r?$"), 1,
      specific=False, min_entropy=3.5, keywords=("token", "key", "secret"),
      deny=_r(r"(?i)^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:PUBLIC|PUBLISHABLE|_ID\b|_URL\b|_PATH\b|_FILE\b)")),
    R("generic_api_key", "Generic API key or secret", "api_key", "medium",
      _r(r"(?i)(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|secret[_\-]?key|app[_\-]?secret|private[_\-]?key)\b['\"]?\s*(?:[:=]|=>)\s*['\"]?([A-Za-z0-9_\-.+/=]{16,128})['\"]?"), 1,
      specific=False, min_entropy=3.5, keywords=("key", "token", "secret"),
      deny=_r(r"(?i)(?:public|publishable)[\w\-]*['\"]?\s*(?:[:=]|=>)")),
    R("email_address", "Email address", "email", "low",
      _r(r"(?<![\w.+\-])([A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,24})\b"), 1, specific=False, keywords=("@",)),
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
