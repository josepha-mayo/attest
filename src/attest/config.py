from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ATTEST_", env_file=".env", extra="ignore")

    # Ring
    ring_access_token: str = "sandbox-token"
    ring_base_url: str = "http://127.0.0.1:8787"
    ring_webhook_key: str = "attest-dev-hmac-key"

    # Storage
    data_dir: Path = Path("./data")
    signing_key_path: Path | None = None  # defaults to data_dir / "attest-ed25519.key"

    # Visit engine
    arrival_grace_minutes: int = 30  # how early/late an arrival still matches a schedule
    idle_close_minutes: int = 20  # close a visit after this much silence following departure cues
    snapshot_window_seconds: int = 45

    # Summaries
    summarizer: str = "template"  # template | bedrock
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"

    # Presentation
    public_base_url: str = "http://127.0.0.1:8000"
    timezone: str = "America/Los_Angeles"

    @property
    def key_path(self) -> Path:
        return self.signing_key_path or (self.data_dir / "attest-ed25519.key")


settings = Settings()
