from functools import lru_cache

import logging
import os
import secrets

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SECRET = "change-me-in-production"
MIN_SECRET_LENGTH = 32
IN_MEMORY = "mongomock://"


def on_vercel() -> bool:
    """Vercel sets VERCEL=1 in every build and function."""
    return os.environ.get("VERCEL") == "1"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "GhostTrace"

    # MongoDB. Atlas gives a mongodb+srv://… string; Vercel's MongoDB Atlas integration sets MONGODB_URI for you.
    # Unset (outside Vercel) means an in-memory database that is wiped when the server stops.
    mongodb_uri: str = IN_MEMORY
    mongodb_db: str = "ghosttrace"

    # Auth
    secret_key: str = DEFAULT_SECRET
    access_token_minutes: int = 60 * 24
    rate_limit_enabled: bool = True
    # Reverse proxies in front of the app that append to X-Forwarded-For (1 on Vercel, 0 when exposed directly).
    trusted_proxy_hops: int = 0

    # CORS / links
    cors_origins: str = "http://localhost:5173"
    frontend_url: str = "http://localhost:5173"

    # GitHub API (a classic token with no scopes is enough for public repositories).
    github_token: str | None = None
    github_max_files_per_repo: int = 400
    github_max_repos_per_owner: int = 30
    github_max_commits_per_repo: int = 40

    # Email alerts (SMTP)
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "GhostTrace <alerts@ghosttrace.local>"
    smtp_starttls: bool = True

    # Breach intelligence
    xposedornot_api_url: str = "https://api.xposedornot.com/v1"
    pwned_passwords_api_url: str = "https://api.pwnedpasswords.com"
    hibp_api_key: str | None = None

    # Monitoring. Locally an in-process scheduler re-checks monitors every few minutes;
    # on Vercel a daily Cron Job calls /api/cron/monitors instead.
    monitor_interval_minutes: int = 60
    enable_scheduler: bool = True
    cron_secret: str | None = None

    # AI Security Analyst (Groq). The key stays on the server; the browser never sees it.
    # Secrets are redacted before anything is sent (see app/ai/redact.py).
    groq_api_key: str | None = None
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "openai/gpt-oss-120b"
    groq_fallback_model: str | None = "openai/gpt-oss-20b"  # used when the main model is busy or unavailable
    groq_reasoning_effort: str | None = "low"  # gpt-oss models: low | medium | high; empty to omit
    groq_timeout_seconds: float = 45.0
    ai_max_output_tokens: int = 2048
    ai_pr_max_diff_chars: int = 14000  # keeps a PR review inside Groq's per-minute token budget
    ai_finding_limit_per_10min: int = 30
    ai_pr_limit_per_hour: int = 10
    ai_posture_limit_per_hour: int = 6
    ai_daily_limit: int = 200  # AI calls per user per day, across all features

    # Serverless behaviour (switched on automatically when VERCEL=1).
    # run_scans_inline: GitHub scans run inside the browser's POST /api/scans/{id}/run request instead of a background
    # thread, which a serverless function could freeze as soon as it has responded.
    run_scans_inline: bool = False
    scan_time_budget_seconds: int = 0  # stop and keep what was found after this long (0 = no limit)
    max_upload_mb: int = 100  # Vercel caps request bodies at 4.5 MB (lowered automatically there)
    local_repo_max_commits: int = 1000  # commits of history read from a zipped local repository
    stale_scan_minutes: int = 120  # scans stuck longer than this are marked failed

    @field_validator("mongodb_uri", mode="before")
    @classmethod
    def _blank_means_in_memory(cls, v):
        # `MONGODB_URI=` (left empty in .env) means "no database configured", not an empty address.
        return v.strip() if isinstance(v, str) and v.strip() else IN_MEMORY

    @model_validator(mode="after")
    def _platform_defaults(self):
        explicit = self.model_fields_set
        if on_vercel():
            if self.mongodb_uri == IN_MEMORY:
                raise ValueError(
                    "MONGODB_URI is not set. Connect MongoDB Atlas in Vercel > Project > Storage (or Integrations), "
                    "or add MONGODB_URI under Settings > Environment Variables."
                )
            if self.secret_key == DEFAULT_SECRET:
                raise ValueError(
                    "SECRET_KEY is not set. Add it in Vercel > Project > Settings > Environment Variables "
                    "(generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\")."
                )
            host = os.environ.get("VERCEL_PROJECT_PRODUCTION_URL") or os.environ.get("VERCEL_URL")
            defaults = {
                "frontend_url": f"https://{host}" if host else self.frontend_url,
                "enable_scheduler": False,
                "trusted_proxy_hops": 1,  # Vercel's edge sets X-Forwarded-For to the real client address
                "run_scans_inline": True,
                "scan_time_budget_seconds": 240,  # Hobby functions stop at 300 s; leave time to score and save
                "max_upload_mb": 4,
                "stale_scan_minutes": 10,
                "monitor_interval_minutes": 60 * 23,  # the Vercel cron fires once a day
            }
            for key, value in defaults.items():
                if key not in explicit:
                    setattr(self, key, value)
        if self.secret_key == DEFAULT_SECRET:
            # The default is public (it is in the source), so anyone could forge a login token with it.
            if not self.in_memory_db:
                raise ValueError(
                    "SECRET_KEY is still the public default. Set a long random value in .env "
                    "(python -c \"import secrets; print(secrets.token_urlsafe(48))\")."
                )
            self.secret_key = secrets.token_urlsafe(48)  # throwaway dev database: a per-run secret is fine
            logging.getLogger("ghosttrace").warning("SECRET_KEY is not set: using a random one for this run, so logins reset on restart.")
        elif len(self.secret_key) < MIN_SECRET_LENGTH:
            logging.getLogger("ghosttrace").warning("SECRET_KEY is shorter than %d characters. Use a longer random value.", MIN_SECRET_LENGTH)
        return self

    @field_validator("groq_api_key", "groq_fallback_model", "groq_reasoning_effort", mode="before")
    @classmethod
    def _blank_is_none(cls, v):
        return v.strip() if isinstance(v, str) and v.strip() else None

    @property
    def ai_enabled(self) -> bool:
        return bool(self.groq_api_key)

    @property
    def in_memory_db(self) -> bool:
        return self.mongodb_uri.startswith("mongomock://")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
