import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager

import httpx
import pytest
import uvicorn
from ring_sandbox.emulator import create_app as sandbox_app

from attest.app import create_app
from attest.config import Settings
from attest.ledger import verify_chain
from attest.models import Receipt, ReviewBundle
from attest.reviews import verify_bundle


@contextmanager
def serve(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(32)
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive()


@pytest.mark.parametrize(
    "scenario,event_count,has_observations",
    [
        ("home_aide_visit", 7, True),
        ("camera_only_visit", 4, True),
        ("no_show", 1, False),
    ],
)
def test_replay_cli_shares_clock_with_auto_checkin_and_signs_receipt(
    tmp_path, scenario, event_count, has_observations
):
    token = secrets.token_urlsafe(32)
    with serve(sandbox_app()) as ring_url:
        settings = Settings(
            _env_file=None,
            admin_token=token,
            replay_mode=True,
            data_dir=tmp_path,
            ring_base_url=ring_url,
            timezone="UTC",
            summarizer="template",
        )
        app = create_app(settings)
        with serve(app) as app_url:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "attest.cli",
                    "replay",
                    scenario,
                    "--speed",
                    "100000",
                    "--auto-checkin",
                    "--ring-url",
                    ring_url,
                    "--public-url",
                    app_url,
                ],
                env={
                    **os.environ,
                    "ATTEST_ADMIN_TOKEN": token,
                    "ATTEST_REPLAY_MODE": "true",
                    "ATTEST_RING_BASE_URL": ring_url,
                    "ATTEST_SUMMARIZER": "template",
                },
                capture_output=True,
                text=True,
                timeout=45,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            with httpx.Client(base_url=app_url, auth=("admin", token)) as client:
                receipts = [Receipt.model_validate(r) for r in client.get("/receipts.json").json()]
                assert len(receipts) == 1
                assert verify_chain(receipts, public_key=app.state.signer.public_key_b64)[0]
                payload = receipts[0].payload
                assert payload["clock"]["mode"] == "replay"
                if scenario == "camera_only_visit":
                    assert payload["site"]["door_sensor_id"] is None
                if has_observations:
                    assert payload["checked_in_at"] <= payload["last_observed_at"]
                    assert payload["clock"]["checkin_received_at"] > payload["checked_in_at"]
                    assert payload["observed_span_minutes"] >= 90
                else:
                    assert payload["state"] == "no_observation"
                    assert payload["first_observed_at"] is None and payload["checked_in_at"] is None
                assert "clock_conflict" not in {flag["code"] for flag in payload["flags"]}
                assert client.get("/api/webhook-queue").json() == {"done": event_count}
                assert "LOCAL REPLAY" in client.get("/").text
                visit_id = receipts[0].visit_id
                original = receipts[0].model_dump_json()
                link = client.post(f"/api/visits/{visit_id}/review-link").json()["path"]
                response = client.post(
                    link,
                    auth=None,
                    data={
                        "decision": "correction",
                        "statement": "My own account of this simulated visit.",
                        "reported_start": payload["first_observed_at"],
                        "reported_end": payload["last_observed_at"],
                    },
                )
                assert response.status_code == 200
                response = client.post(
                    f"/api/visits/{visit_id}/reviews",
                    json={
                        "decision": "inconclusive",
                        "statement": "Worker statement received; not independent proof.",
                    },
                )
                assert response.status_code == 200
                bundle = ReviewBundle.model_validate(client.get(f"/visits/{visit_id}/bundle.json").json())
                assert len(bundle.reviews) == 2
                assert verify_bundle(bundle, public_key=app.state.signer.public_key_b64)[0]
                assert bundle.original.model_dump_json() == original
                assert "Append coordinator statement" in client.get(f"/visits/{visit_id}").text


def test_replay_story_cycles_patterns_and_survives_late_events(tmp_path):
    """--story must produce the mixed dataset: observed, lapsed no-observation,
    and an unmatched visit whose events land past the last schedule's window."""
    token = secrets.token_urlsafe(32)
    with serve(sandbox_app()) as ring_url:
        settings = Settings(
            _env_file=None,
            admin_token=token,
            replay_mode=True,
            data_dir=tmp_path,
            ring_base_url=ring_url,
            timezone="UTC",
            summarizer="template",
        )
        app = create_app(settings)
        with serve(app) as app_url:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "attest.cli",
                    "replay",
                    "home_aide_visit",
                    "--days",
                    "3",
                    "--story",
                    "observed,no_show,unmatched",
                    "--speed",
                    "100000",
                    "--ring-url",
                    ring_url,
                    "--public-url",
                    app_url,
                ],
                env={
                    **os.environ,
                    "ATTEST_ADMIN_TOKEN": token,
                    "ATTEST_REPLAY_MODE": "true",
                    "ATTEST_RING_BASE_URL": ring_url,
                    "ATTEST_SUMMARIZER": "template",
                },
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            with httpx.Client(base_url=app_url, auth=("admin", token)) as client:
                visits = client.get("/api/state").json()["visits"]
                states = sorted(v["state"] for v in visits)
                # unmatched day yields both an unmatched observation and its
                # displaced schedule lapsing to no_observation.
                assert states == ["closed", "closed", "no_observation", "no_observation"]
                unmatched = [v for v in visits if not v["schedule_id"]]
                assert len(unmatched) == 1
                receipts = [Receipt.model_validate(r) for r in client.get("/receipts.json").json()]
                assert len(receipts) == 4
                assert verify_chain(receipts, public_key=app.state.signer.public_key_b64)[0]


def test_replay_story_rejects_unknown_pattern(tmp_path):
    token = secrets.token_urlsafe(32)
    with serve(sandbox_app()) as ring_url:
        settings = Settings(
            _env_file=None,
            admin_token=token,
            replay_mode=True,
            data_dir=tmp_path,
            ring_base_url=ring_url,
            timezone="UTC",
        )
        with serve(create_app(settings)) as app_url:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "attest.cli",
                    "replay",
                    "home_aide_visit",
                    "--story",
                    "observed,bogus",
                    "--speed",
                    "100000",
                    "--ring-url",
                    ring_url,
                    "--public-url",
                    app_url,
                ],
                env={
                    **os.environ,
                    "ATTEST_ADMIN_TOKEN": token,
                    "ATTEST_REPLAY_MODE": "true",
                    "ATTEST_RING_BASE_URL": ring_url,
                },
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert result.returncode != 0
            assert "bogus" in result.stderr + result.stdout
