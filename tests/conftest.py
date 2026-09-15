from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from ring_sandbox import RingClient
from ring_sandbox.world import DeviceKind

from attest.config import Settings
from attest.engine import VisitEngine
from attest.ledger import Signer
from attest.media import MediaStore
from attest.models import Role, Schedule, Site, Worker
from attest.store import Store
from attest.summarize import TemplateSummarizer

# ring_sandbox's fixtures (ring_client, ring_control, ring_world) load via its pytest11 entry point.


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        admin_token="test-admin-token-only-" + "x" * 32,
        ring_webhook_key="k",
        summarizer="template",
        timezone="UTC",
        idle_close_minutes=20,
        arrival_grace_minutes=30,
    )


@pytest.fixture
def store() -> Store:
    return Store(":memory:")


@pytest.fixture
def engine(store: Store, ring_client: RingClient, settings: Settings, tmp_path: Path) -> VisitEngine:
    return VisitEngine(
        store,
        ring_client,
        Signer.ephemeral(),
        MediaStore(tmp_path / "media"),
        TemplateSummarizer("UTC"),
        settings,
    )


@pytest.fixture
def household(store: Store, ring_world):
    cam = next(d for d in ring_world.devices.values() if d.kind == DeviceKind.DOORBELL)
    sensor = next(d for d in ring_world.devices.values() if d.kind == DeviceKind.CONTACT_SENSOR)
    site = store.put_site(
        Site(
            name="Alvarez residence",
            ring_account_id=ring_world.account_id,
            door_camera_id=cam.id,
            door_sensor_id=sensor.id,
        )
    )
    worker = store.put_worker(Worker(name="Maria Chen", role=Role.HOME_HEALTH_AIDE, checkin_token="tok123"))
    return site, worker, cam, sensor


@pytest.fixture
def t0() -> datetime:
    """A schedule window start safely in the past (the emulator rejects future media timestamps)
    but inside HistoryPoller's 24-hour lookback floor at any time of day."""
    return (datetime.now(tz=UTC) - timedelta(hours=6)).replace(microsecond=0)


@pytest.fixture
def schedule(store: Store, household, t0):
    site, worker, *_ = household
    return store.put_schedule(
        Schedule(
            site_id=site.id,
            worker_id=worker.id,
            window_start=t0,
            window_end=t0 + timedelta(hours=1),
            expected_minutes=90,
            service="Morning care",
        )
    )
