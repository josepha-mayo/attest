from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ATTEST_", env_file=".env", extra="ignore")

    admin_token: SecretStr | None = Field(default=None, min_length=32)
    replay_mode: bool = False

    # Ring
    ring_access_token: str = "sandbox-token"
    ring_refresh_token: SecretStr | None = None  # enables RFC 6749 refresh on 401
    ring_client_id: str | None = None
    ring_token_url: str = "https://oauth.ring.com/oauth/token"
    ring_base_url: str = "http://127.0.0.1:8787"
    ring_webhook_key: str = "attest-dev-hmac-key"
    # Comma-separated origins allowed to receive media downloads (Ring presigned URLs).
    # Entries are HTTPS origins like https://host or wildcard hosts like *.amazonaws.com.
    ring_media_origins: str = ""

    # Storage
    data_dir: Path = Path("./data")
    signing_key_path: Path | None = None  # defaults to data_dir / "attest-ed25519.key"

    # Visit engine
    arrival_grace_minutes: int = 30  # how early/late an arrival still matches a schedule
    idle_close_minutes: int = 20  # close a visit after this much silence following departure cues
    snapshot_window_seconds: int = 45
    # Poll GET /v1/history when webhooks can't reach us (Playground tokens). 0 disables.
    poll_history_seconds: int = 0

    # Retention preview policy. Reporting only — deletion is a separate explicit action.
    retention_visits_days: int = 180
    retention_media_days: int = 180
    retention_deliveries_days: int = 30
    retention_grants_days: int = 7
    retention_seen_days: int = 30
    retention_late_days: int = 90

    # Summaries
    summarizer: str = "template"  # template | bedrock
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"

    # Presentation
    public_base_url: str = "http://127.0.0.1:8000"
    timezone: str = "America/Los_Angeles"

    @property
    def key_path(self) -> Path:
        return self.signing_key_path or (self.data_dir / "attest-ed25519.key")


settings = Settings()
