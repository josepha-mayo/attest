import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime

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
                # The no-show day's signed receipt must attest *watched* silence:
                # polls tile the window in lookback-sized strides, so the whole
                # window was queried and Ring returned nothing. The unmatched
                # day's displaced schedule lapses with thinner coverage.
                no_show = sorted(
                    (v for v in visits if v["state"] == "no_observation"),
                    key=lambda v: v["arrived_at"],
                )[0]
                receipt = next(r for r in receipts if r.visit_id == no_show["id"])
                cov = receipt.payload["history_poll_coverage"]
                assert cov["state"] == "observed" and cov["fraction"] >= 0.99, cov
                assert cov["events"] == 0 and cov["gaps"] == []


def test_replay_default_story_produces_the_full_demo_dataset(tmp_path):
    """The shipped default — all seven day-patterns in one run — must yield the
    complete judge-visible dataset: watched silence, a signed camera-outage
    explanation, an unmatched observation, and a live session in coverage."""
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
                    "7",
                    "--story",
                    "observed,late,blackout,no_show,early_out,unmatched,liveview",
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
                timeout=120,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            with httpx.Client(base_url=app_url, auth=("admin", token)) as client:
                visits = client.get("/api/state").json()["visits"]
                # unmatched day yields an unmatched observation *and* its
                # displaced schedule lapsing to no_observation.
                assert sorted(v["state"] for v in visits) == ["closed"] * 6 + ["no_observation"] * 2
                receipts = [Receipt.model_validate(r) for r in client.get("/receipts.json").json()]
                assert len(receipts) == 8
                assert verify_chain(receipts, public_key=app.state.signer.public_key_b64)[0]
                coverages = [r.payload["history_poll_coverage"] for r in receipts]
                # blackout day — the outage is a signed interruption.
                assert any(
                    [i["kind"] for i in c["interruptions"]] == ["device_offline", "device_online"]
                    for c in coverages
                )
                # liveview day — a bounded session signed into coverage.
                live = [s for c in coverages for s in c["live_sessions"]]
                assert len(live) == 1 and live[0]["opened_at"] and live[0]["closed_at"]
                # no_show day — watched silence, never "proof of absence".
                assert any(c["events"] == 0 and c["state"] == "observed" for c in coverages)
                # The exported case pack's offline browser carries the live mark.
                site = client.get("/api/state").json()["sites"][0]["id"]
                pack = client.get(f"/sites/{site}/pack.zip")
                assert pack.status_code == 200
                import io
                import zipfile

                archive = zipfile.ZipFile(io.BytesIO(pack.content))
                index = archive.read("index.html").decode()
                assert "viewership" in index


def test_replay_liveview_day_signs_the_session_into_coverage(tmp_path):
    """The 'liveview' story day opens a coordinator stream mid-window: the
    journaled session lands inside the visit's signed coverage payload —
    'a stream was established' attested, viewership never claimed."""
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
                    "1",
                    "--story",
                    "liveview",
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
                receipts = [Receipt.model_validate(r) for r in client.get("/receipts.json").json()]
                assert len(receipts) == 1
                sessions = receipts[0].payload["history_poll_coverage"]["live_sessions"]
                assert len(sessions) == 1
                assert sessions[0]["opened_at"] and sessions[0]["closed_at"]
                page = client.get(f"/visits/{receipts[0].visit_id}").text
                assert "stream established" in page


def test_replay_blackout_day_signs_the_lifecycle_explanation(tmp_path):
    """The 'blackout' story day drops the camera mid-visit: arrival is observed,
    departure never is — and the signed coverage must carry the device_offline/
    device_online rows so the quiet span reads explained, not absent."""
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
                    "1",
                    "--story",
                    "blackout",
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
            assert "camera drops offline mid-visit" in result.stdout
            with httpx.Client(base_url=app_url, auth=("admin", token)) as client:
                receipts = [Receipt.model_validate(r) for r in client.get("/receipts.json").json()]
                assert len(receipts) == 1
                assert verify_chain(receipts, public_key=app.state.signer.public_key_b64)[0]
                cov = receipts[0].payload["history_poll_coverage"]
                kinds = [i["kind"] for i in cov["interruptions"]]
                assert kinds == ["device_offline", "device_online"], cov
                # The departure was never observed — the signed window extends
                # past the last event, so the interruption lands inside it.
                assert cov["window"]["end"] > receipts[0].payload["last_observed_at"]
                page = client.get(f"/visits/{receipts[0].visit_id}").text
                assert "device offline" in page


def test_verify_live_sweep_reports_every_surface():
    """The evidence command exercises each official surface against the API —
    account, integration, subscriptions, devices, history, media, and the
    WHEP open/close — and reports pass/fail honestly per check."""
    from ring_sandbox import RingClient

    from attest import verifylive

    with serve(sandbox_app()) as ring_url:
        with RingClient("sandbox-token", base_url=ring_url) as ring:
            report = verifylive.run(ring)
    by_check = {c["check"]: c for c in report["checks"]}
    assert by_check["users/me"]["status"] == "pass"
    assert by_check["devices"]["status"] == "pass"
    assert by_check["media download"]["status"] == "pass"
    assert by_check["WHEP live view"]["status"] == "pass"
    assert "closed" in by_check["WHEP live view"]["detail"]
    assert report["summary"]["fail"] == 0
    # the report never carries the raw token — only the masked hint
    assert "sandbox-token" not in str(report)


def test_verify_live_marks_failures_honestly():
    """A dead endpoint is reported FAIL per check, not swallowed or crashed —
    verification evidence must include what did not work."""
    from ring_sandbox import RingClient

    from attest import verifylive

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    dead_port = sock.getsockname()[1]
    sock.close()  # nothing listening — every check fails fast
    with RingClient("sandbox-token", base_url=f"http://127.0.0.1:{dead_port}") as ring:
        report = verifylive.run(ring)
    assert report["summary"]["fail"] >= 4
    assert all(c["status"] in ("fail", "skip") for c in report["checks"])


def test_replay_late_day_produces_source_divergence(tmp_path):
    """The 'late' story day defers the worker check-in ~65 min past the
    camera's first observation — the corroboration panel must surface the
    divergence row instead of pretending the sources agree."""
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
                    "1",
                    "--story",
                    "late",
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
                timeout=60,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            with httpx.Client(base_url=app_url, auth=("admin", token)) as client:
                receipts = [Receipt.model_validate(r) for r in client.get("/receipts.json").json()]
                assert len(receipts) == 1
                payload = receipts[0].payload
                checkin = datetime.fromisoformat(payload["checked_in_at"])
                arrived = datetime.fromisoformat(payload["first_observed_at"])
                assert (checkin - arrived).total_seconds() >= 3600
                page = client.get(f"/visits/{receipts[0].visit_id}").text
                assert "Source divergence" in page


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


@pytest.mark.parametrize(
    "scenario,extra_args,expected_flags,checked_in,deliveries",
    [
        # Camera dies 20 min in: arrival + check-in observed, departure never.
        ("partial_blackout", ["--auto-checkin"], {"departure_unconfirmed"}, True, 6),
        # Courier in the aide's window: doorstep activity, no door cycle, no check-in.
        ("visitor_not_worker", [], {"departure_unconfirmed", "no_checkin"}, False, 5),
    ],
)
def test_replay_named_example_scenarios_stay_honest(
    tmp_path, scenario, extra_args, expected_flags, checked_in, deliveries
):
    """The wheel-shipped example scenarios resolve by name and produce honest
    records: observed activity is never upgraded to worker attendance."""
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
                    scenario,  # name only — resolved from the wheel-shipped examples
                    "--speed",
                    "100000",
                    "--ring-url",
                    ring_url,
                    "--public-url",
                    app_url,
                    *extra_args,
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
                flag_codes = {f["code"] for f in payload["flags"]}
                assert expected_flags <= flag_codes
                assert payload["departed_at"] is None
                assert payload["assessment"]["departure_verified"] is False
                assert payload["assessment"]["identity_verified"] is False
                # Only the arrival/doorstep cluster was observed — the record
                # never inflates it into continuous presence.
                assert payload["observed_span_minutes"] < 5
                if checked_in:
                    assert payload["checked_in_at"] is not None
                    assert payload["assessment"]["attendance"] == "self_reported"
                else:
                    assert payload["checked_in_at"] is None
                    assert payload["assessment"]["attendance"] == "unknown"
                assert client.get("/api/webhook-queue").json() == {"done": deliveries}


def test_demo_command_spins_up_full_stack(tmp_path):
    """attest demo must boot emulator + server + story replay and leave a live dashboard."""
    import re

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "attest.cli",
            "demo",
            "--days",
            "2",
            "--story",
            "observed,no_show",
            "--speed",
            "100000",
            "--data-dir",
            str(tmp_path / "demo"),
        ],
        env={**os.environ, "ATTEST_SUMMARIZER": "template"},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        out = ""
        deadline = time.monotonic() + 60
        while "Press Ctrl+C" not in out and time.monotonic() < deadline:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            out += line
        assert "Demo is live" in out, out
        url = re.search(r"dashboard\s+(http://\S+)", out).group(1)
        # Browsers send URL userinfo as Basic auth; httpx keeps it in the URL
        # but never promotes it to a header — split it out and pass auth=.
        parsed = httpx.URL(url)
        creds = (parsed.username, parsed.password)
        clean = parsed.copy_with(username=None, password=None)
        with httpx.Client() as client:
            assert client.get(clean, auth=creds).status_code == 200
    finally:
        proc.terminate()
        proc.wait(timeout=15)
