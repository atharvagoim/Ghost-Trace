from functools import lru_cache

import os

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SECRET = "change-me-in-production"
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

    # Serverless behaviour (switched on automatically when VERCEL=1).
    # run_scans_inline: GitHub scans run inside the browser's POST /api/scans/{id}/run request instead of a background
    # thread, which a serverless function could freeze as soon as it has responded.
    run_scans_inline: bool = False
    scan_time_budget_seconds: int = 0  # stop and keep what was found after this long (0 = no limit)
    max_upload_mb: int = 20  # Vercel caps request bodies at 4.5 MB
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
        return self

    @property
    def in_memory_db(self) -> bool:
        return self.mongodb_uri.startswith("mongomock://")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
