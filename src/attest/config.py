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
    # No shipped default: a public constant here would be live in every
    # deployment that forgets to configure a real key — forged HMAC-signed
    # webhooks would ingest as genuine Ring traffic. The demo mints a fresh
    # per-run key; `attest replay` needs ATTEST_RING_WEBHOOK_KEY set to the
    # server's value.
    ring_webhook_key: str | None = None
    # Freshness bound on inbound webhooks: meta.time is inside the signed body,
    # so a captured delivery replayed verbatim is authentic but stale. Generous
    # default — must comfortably exceed Ring's retry window; it bounds replay
    # damage if a dedupe tombstone is ever purged, it is not the primary dedupe.
    webhook_max_age_s: int = 3600
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
    # Cadence for self-issued period digests: the ledger summarizes itself on a
    # rolling window (the weekly report a coordinator can hand upstream). 0 disables.
    digest_interval_seconds: int = 604800

    # Retention preview policy. Reporting only — deletion is a separate explicit action.
    retention_visits_days: int = 180
    retention_media_days: int = 180
    retention_deliveries_days: int = 30
    retention_grants_days: int = 7
    retention_seen_days: int = 0  # 0 = keep dedupe tombstones forever (replay protection)
    retention_late_days: int = 90
    retention_poll_days: int = 90
    retention_coverage_days: int = 90
    retention_liveview_days: int = 90

    # Summaries
    summarizer: str = "template"  # template | bedrock
    aws_region: str = "us-east-1"
    # When set, the Ed25519 signing key is envelope-encrypted under this KMS
    # key — the PEM on disk is AES-GCM wrapped and unwrap needs a live Decrypt.
    kms_key_id: str | None = None
    # Nova Lite is a first-party multimodal model (no Anthropic use-case form needed).
    bedrock_model_id: str = "us.amazon.nova-lite-v1:0"

    # Presentation
    public_base_url: str = "http://127.0.0.1:8000"
    timezone: str = "America/Los_Angeles"

    @property
    def key_path(self) -> Path:
        return self.signing_key_path or (self.data_dir / "attest-ed25519.key")


settings = Settings()
