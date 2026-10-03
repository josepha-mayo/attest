"""``attest`` command line — run ``attest --help`` for the full command list.

Most-used: ``attest demo`` (one-command seeded demo), ``attest serve``,
``attest replay`` (scenario driver), ``attest export`` (case pack),
``attest verify`` (offline artifact check), ``attest anchor`` (signed
checkpoint), ``attest stamp`` (OpenTimestamps notarization),
``attest status`` (runtime self-audit), ``attest doctor`` (deployment
preflight), ``attest attack-demo`` (tamper battery), ``attest diff``
(compare two exports).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx
from ring_sandbox import RingClient

from .config import settings
from .models import Role, Schedule, Site, Worker


def _terminal_qr(data: str) -> list[str] | None:
    """QR as ANSI background-color rows — pure ASCII + escape codes, so it
    survives cp1252 consoles where half-block glyphs can't encode. Returns
    None when segno is unavailable."""
    try:
        import segno
    except ImportError:
        return None
    m = segno.make(data, error="m").matrix
    w = len(m[0])
    border = "\033[47m" + " " * (2 * w + 8) + "\033[0m"
    rows = [border, border]
    for bits in m:
        rows.append(
            "\033[47m    "
            + "".join("\033[40m  " if b else "\033[47m  " for b in bits)
            + "\033[47m    \033[0m"
        )
    rows += [border, border]
    return rows


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    from .app import create_app
    from .instance import acquire_instance_lock

    if settings.admin_token is None:
        sys.exit("Set ATTEST_ADMIN_TOKEN to at least 32 random characters before starting Attest.")
    acquire_instance_lock(settings.data_dir)
    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        print("note: empty runtime — `attest demo` boots emulator + server + a scripted week")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        # uvicorn serves plain HTTP — a non-loopback bind puts the admin Basic
        # credentials and bearer-link tokens on the wire in cleartext.
        print(
            f"WARNING: serving HTTP on {args.host}:{args.port} — admin credentials "
            "and link tokens transit in cleartext. Put a TLS terminator in front "
            "or keep the listener on loopback."
        )
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info", access_log=False)


def _seed(args: argparse.Namespace) -> dict:
    """Create a site bound to the sandbox's doorbell + contact sensor, a worker, and a schedule
    whose window starts now (so the very next arrival cue opens a matched visit)."""
    with RingClient(settings.ring_access_token, base_url=args.ring_url) as ring:
        bundles = ring.devices(include=["capabilities", "status"])
    cam = next((b for b in bundles if b.capabilities and b.capabilities.is_camera), None)
    sensor = next(
        (b for b in bundles if b.status and b.status.attributes.contact_detection is not None), None
    )
    if getattr(args, "camera_only", False) or getattr(args, "scenario", None) == "camera_only_visit":
        sensor = None
    if cam is None:
        sys.exit("no camera device visible with this token")

    with RingClient(settings.ring_access_token, base_url=args.ring_url) as ring:
        try:
            account_id = ring.me().account_id
        except Exception:  # noqa: BLE001 - Playground tokens may lack the users scope
            account_id = "unknown"
    site = Site(
        name=args.site_name,
        ring_account_id=account_id,
        door_camera_id=cam.id,
        door_sensor_id=sensor.id if sensor else None,
        owner_name="Ruth Alvarez",
        owner_contact="daughter: +1 555 0142",
    )
    worker = Worker(
        name=args.worker_name,
        role=Role.HOME_HEALTH_AIDE,
        agency="Evergreen Home Care",
        phone="+1 555 0199",
    )
    if settings.admin_token is None:
        sys.exit("Set ATTEST_ADMIN_TOKEN to authenticate to Attest.")
    with httpx.Client(
        base_url=args.public_url, auth=("admin", settings.admin_token.get_secret_value())
    ) as api:
        response = api.get("/api/clock")
        response.raise_for_status()
        clock = response.json()
    if not clock["ready"]:
        sys.exit("Start the replay clock first, or use attest replay with a fresh runtime.")
    now = datetime.fromisoformat(clock["now"])
    # Replayed scenarios are back-dated by their length + 60s, so open the window well before now.
    schedule = Schedule(
        site_id=site.id,
        worker_id=worker.id,
        window_start=now - (timedelta(minutes=5) if clock["mode"] == "replay" else timedelta(hours=3)),
        window_end=now + timedelta(minutes=args.window_minutes),
        expected_minutes=args.expected_minutes,
        service="Morning care visit",
    )
    if settings.admin_token is None:
        sys.exit("Set ATTEST_ADMIN_TOKEN to authenticate to Attest.")
    with httpx.Client(
        base_url=args.public_url,
        timeout=10,
        auth=("admin", settings.admin_token.get_secret_value()),
    ) as api:
        for path, obj in (
            ("/api/sites", site),
            ("/api/workers", worker),
            ("/api/schedules", schedule),
        ):
            api.post(
                path, content=obj.model_dump_json(), headers={"Content-Type": "application/json"}
            ).raise_for_status()
    out = {
        "site": site.id,
        "camera": cam.id,
        "sensor": sensor.id if sensor else None,
        "worker": worker.id,
        "dashboard_url": args.public_url,
        "schedule": schedule.id,
    }
    print(json.dumps(out, indent=2))
    return out


def _replay(args: argparse.Namespace) -> None:
    from pathlib import Path

    from ring_sandbox import webhooks
    from ring_sandbox.scenarios import resolve

    if not settings.admin_token or not math.isfinite(args.speed) or args.speed <= 0:
        sys.exit("Replay requires admin authentication and a finite positive speed.")
    if not settings.ring_webhook_key:
        sys.exit(
            "Replay signs simulated webhooks — set ATTEST_RING_WEBHOOK_KEY to the "
            "same value the target server verifies with. `attest demo` mints one "
            "per run automatically."
        )
    if args.days < 1:
        sys.exit("--days must be at least 1")
    if getattr(args, "rotate_day", None) is not None and not 0 <= args.rotate_day < args.days:
        sys.exit("--rotate-day must name a story day (0..days-1)")
    if getattr(args, "revoke_day", None) is not None and not 0 <= args.revoke_day < args.days:
        sys.exit("--revoke-day must name a story day (0..days-1)")
    if args.scenario.endswith((".yml", ".yaml")) and not Path(args.scenario).exists():
        sys.exit(f"no scenario file at {args.scenario}")
    try:
        scenario = resolve(args.scenario)
    except KeyError as exc:
        sys.exit(str(exc.args[0]))
    for address in (args.ring_url, args.public_url):
        try:
            parsed = urlsplit(address)
            host = parsed.hostname
        except ValueError:
            sys.exit(f"malformed URL {address!r}")
        if (
            parsed.scheme != "http"
            or host not in ("127.0.0.1", "localhost", "::1")
            or parsed.username
            or parsed.password
        ):
            sys.exit("Replay only targets local HTTP services, never real Ring devices.")

    def drain(api: httpx.Client) -> None:
        """Run the durable inbox to empty; a claim can still be in flight right after."""
        deadline = time.monotonic() + 60
        while True:
            response = api.post("/api/process-webhooks")
            response.raise_for_status()
            queue = response.json()["queue"]
            if queue.get("failed") or queue.get("rejected"):
                sys.exit("Replay delivery failed; inspect the queue before continuing.")
            if not queue.get("pending") and not queue.get("processing"):
                return
            if time.monotonic() > deadline:
                sys.exit("Replay stopped while waiting for persisted event processing.")
            time.sleep(0.05)

    def advance(api: httpx.Client, at: datetime) -> None:
        """Advance the replay clock, draining first; the background worker can hold a
        claimed delivery briefly, so a 409 means drain-and-retry, not failure."""
        drain(api)
        deadline = time.monotonic() + 60
        while True:
            response = api.post("/api/replay/advance", json={"at": at.isoformat()})
            if response.status_code != 409:
                response.raise_for_status()
                return
            # Only the queued-delivery guard is transient; a ValueError like
            # "cannot rewind" or "in the future" would spin forever on retry.
            if "queued deliveries" not in response.json().get("detail", ""):
                response.raise_for_status()
            if time.monotonic() > deadline:
                sys.exit("Replay clock stayed blocked by queued deliveries.")
            time.sleep(0.25)
            drain(api)

    with (
        httpx.Client(
            base_url=args.public_url, timeout=60, auth=("admin", settings.admin_token.get_secret_value())
        ) as api,
        httpx.Client(base_url=args.ring_url, timeout=10) as sandbox,
    ):
        deadline = time.monotonic() + 10
        while True:
            try:
                clock_response = api.get("/api/clock")
                sandbox.get("/_sandbox/health").raise_for_status()
                break
            except httpx.ConnectError:
                if time.monotonic() >= deadline:
                    sys.exit("Start the local Attest and emulator servers before replaying.")
                time.sleep(0.1)
        clock_response.raise_for_status()
        clock = clock_response.json()
        if clock["mode"] != "replay" or api.get("/api/state").json()["sites"]:
            sys.exit("Start Attest with ATTEST_REPLAY_MODE=true and a fresh private data directory.")
        # Replay already requires a fresh Attest runtime; reset the emulator too, or
        # stale history events would be ingested by the coverage poll before the first
        # webhook binds the site's ingestion source.
        sandbox.post("/_sandbox/reset").raise_for_status()
        if not clock["ready"]:
            # The replay clock may only simulate the past, so a multi-day replay
            # starts args.days back — every day's window stays behind wall time.
            response = api.post(
                "/api/replay/start",
                json={"at": (datetime.now(UTC) - timedelta(days=args.days)).isoformat()},
            )
            response.raise_for_status()
            clock = response.json()
        start = datetime.fromisoformat(clock["now"])
        seeded = _seed(args)
        state_response = sandbox.get("/_sandbox/state")
        state_response.raise_for_status()
        devices = state_response.json()["devices"]
        if args.no_show_day is not None and not 0 <= args.no_show_day < args.days:
            sys.exit("--no-show-day must be a day index within --days")
        story_patterns = {
            "observed",
            "late",
            "early_out",
            "no_show",
            "unmatched",
            "blackout",
            "sub_lapse",
            "liveview",
        }
        patterns = [p.strip() for p in args.story.split(",") if p.strip()] if args.story else []
        if bad := set(patterns) - story_patterns:
            sys.exit(f"unknown --story pattern(s) {sorted(bad)}; choose from {sorted(story_patterns)}")
        last_event_at = start
        for day in range(args.days):
            day_start = start + timedelta(days=day)
            pattern = (
                patterns[day % len(patterns)]
                if patterns
                else ("no_show" if day == args.no_show_day else "observed")
            )
            if getattr(args, "rotate_day", None) == day:
                r = api.post(
                    "/api/admin/rotate-key", json={"reason": "scheduled key rotation"}
                ).raise_for_status()
                rj = r.json()
                print(
                    f"Day {day}: signing key rotated "
                    f"({rj['previous_key'][:16]}... -> {rj['new_key'][:16]}...) — "
                    "the signed pivot rides the chain",
                    flush=True,
                )
            if getattr(args, "revoke_day", None) == day:
                # In-story incident response: rotate away from the hot key,
                # then the successor revokes it — its whole output becomes a
                # signed suspect-window annotation, never an erasure.
                rj = (
                    api.post("/api/admin/rotate-key", json={"reason": "key compromise drill"})
                    .raise_for_status()
                    .json()
                )
                api.post(
                    "/api/admin/revoke-key",
                    json={
                        "revoked_key": rj["previous_key"],
                        "reason": "compromise drill — retired key declared suspect",
                    },
                ).raise_for_status()
                print(
                    f"Day {day}: compromise drill — retired key revoked; its "
                    "records still verify, every verifier flags the suspect window",
                    flush=True,
                )
            schedule_id = None
            if day > 0:
                schedule = Schedule(
                    site_id=seeded["site"],
                    worker_id=seeded["worker"],
                    window_start=day_start - timedelta(minutes=5),
                    window_end=day_start + timedelta(minutes=args.window_minutes),
                    expected_minutes=args.expected_minutes,
                    service="Morning care visit",
                )
                api.post(
                    "/api/schedules",
                    content=schedule.model_dump_json(),
                    headers={"Content-Type": "application/json"},
                ).raise_for_status()
                advance(api, day_start - timedelta(minutes=5))
                schedule_id = schedule.id
            else:
                schedule_id = seeded["schedule"]
            if pattern == "no_show":
                # Polls must tile the empty window — a no-observation receipt
                # only means something if the pipeline was watching. Each poll
                # attests only its own 30-min lookback, so step the clock in
                # lookback-sized strides from the window's actual start (the
                # schedule opens 5 min before day_start) to just past its end.
                t = day_start - timedelta(minutes=5)
                window_end = day_start + timedelta(minutes=args.window_minutes + 1)
                while t < window_end:
                    t = min(t + timedelta(minutes=30), window_end)
                    advance(api, t)
                    api.post("/api/poll").raise_for_status()
                print(
                    f"Day {day}: window watched with no events — the schedule will lapse to no_observation",
                    flush=True,
                )
                continue
            if pattern == "unmatched":
                # Events land past the window + grace: an unmatched observation
                # AND a lapsed no-observation schedule — the honest ambiguous case.
                print(
                    f"Day {day}: events replayed outside the window — unmatched + lapsed schedule", flush=True
                )
            elif pattern == "blackout":
                print(
                    f"Day {day}: camera drops offline mid-visit — departure unobserved, "
                    "gap explained by lifecycle events",
                    flush=True,
                )
            elif pattern == "sub_lapse":
                print(
                    f"Day {day}: the Ring plan lapses mid-visit — observation stops "
                    "being delivered; the lifecycle webhook is the signed explanation",
                    flush=True,
                )
            elif pattern == "liveview":
                print(
                    f"Day {day}: coordinator opens a live view mid-visit — "
                    "journaled human attention, signed into coverage",
                    flush=True,
                )
            # Poll history once at window start so coverage rows bracket the visit
            # (poll observations sit on the same logical clock as the events).
            api.post("/api/poll").raise_for_status()
            import dataclasses

            steps = sorted(scenario.steps, key=lambda step: step.offset_s)
            if pattern == "late":
                # arrival cluster shifts +25 min; departure stays on schedule
                steps = [
                    dataclasses.replace(s, offset_s=s.offset_s + 1500) if s.offset_s < 300 else s
                    for s in steps
                ]
            elif pattern == "early_out":
                # departure evidence never arrives — closes "departure unconfirmed"
                steps = [s for s in steps if s.offset_s < 4800]
            elif pattern == "blackout":
                # The camera dies mid-visit: arrival is observed, departure never
                # is — and the lifecycle events sign *why* the channel went quiet.
                steps = [s for s in steps if s.offset_s < 3600]
                off = dataclasses.replace(steps[0], type="device_offline", sub_type=None, offset_s=1500)
                on = dataclasses.replace(steps[0], type="device_online", sub_type=None, offset_s=6000)
                steps = sorted([*steps, off, on], key=lambda s: s.offset_s)
            elif pattern == "sub_lapse":
                # The plan lapses mid-visit: Ring stops delivering observation
                # events for the device, so the story drops them — exactly what
                # entitlement suppression produces upstream. The lifecycle
                # webhook still arrives and journals as the coverage cause.
                steps = [s for s in steps if s.offset_s < 1800]
                lapse = dataclasses.replace(
                    steps[0], type="subscription_deactivated", sub_type=None, offset_s=2100
                )
                steps = sorted([*steps, lapse], key=lambda s: s.offset_s)
            elif pattern == "unmatched":
                shift = (args.window_minutes + settings.arrival_grace_minutes + 10) * 60
                steps = [dataclasses.replace(s, offset_s=s.offset_s + shift) for s in steps]
            previous_offset = 0
            did_checkin = False
            liveview_done = False
            # On a "late" day the check-in lands well after the shifted arrival
            # cluster — the worker's own self-report diverges from the camera's
            # observation, and the corroboration panel says so explicitly.
            checkin_at_s = 3300 if pattern == "late" else 0
            for step in steps:
                if pattern == "liveview" and not liveview_done and step.offset_s - previous_offset >= 1800:
                    # A long event silence is where a coordinator would open a
                    # live view: broker a WHEP session 15 min into the gap and
                    # close it 10 min later — bounded, inside the window, signed
                    # into coverage before the visit closes.
                    mid = day_start + timedelta(seconds=previous_offset + 900)
                    advance(api, mid)
                    lv = api.post(
                        f"/api/sites/{seeded['site']}/liveview",
                        content=(
                            "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=attest-demo\r\nt=0 0\r\n"
                            "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
                        ),
                        headers={"Content-Type": "application/sdp"},
                    )
                    if lv.status_code == 200:
                        advance(api, mid + timedelta(minutes=10))
                        api.post(
                            f"/api/sites/{seeded['site']}/liveview/{lv.json()['session_id']}/close"
                        ).raise_for_status()
                    liveview_done = True
                time.sleep((step.offset_s - previous_offset) / args.speed)
                at = day_start + timedelta(seconds=step.offset_s)
                advance(api, at)
                if step.device is None:
                    device_id = seeded["camera"]
                else:
                    match = [d["id"] for d in devices if step.device in (d["id"], d["name"])]
                    if not match:
                        known = ", ".join(d["name"] for d in devices)
                        sys.exit(f"scenario step names unknown device {step.device!r}; known: {known}")
                    device_id = match[0]
                response = sandbox.post(
                    "/_sandbox/events",
                    json={
                        "device_id": device_id,
                        "type": step.type,
                        "sub_type": step.sub_type,
                        "at": at.isoformat(),
                        "duration_ms": step.duration_ms,
                        "deliver": False,
                    },
                )
                response.raise_for_status()
                raw = webhooks.encode(response.json()["webhook"])
                response = api.post(
                    "/webhooks/ring",
                    content=raw,
                    auth=None,
                    headers={
                        "Content-Type": "application/json",
                        webhooks.SIGNATURE_HEADER: webhooks.sign(settings.ring_webhook_key, raw),
                    },
                )
                response.raise_for_status()
                drain(api)
                api.post("/api/poll").raise_for_status()
                if not did_checkin and step.offset_s >= checkin_at_s and args.auto_checkin:
                    visits = api.get("/api/state").json()["visits"]
                    for visit in visits:
                        if visit["state"] == "open" and visit["schedule_id"] == schedule_id:
                            response = api.post(f"/api/visits/{visit['id']}/checkin-link")
                            response.raise_for_status()
                            if api.post(response.json()["path"], auth=None).status_code != 200:
                                sys.exit(
                                    "Simulated check-in rejected. "
                                    "Inspect the record without exposing the link."
                                )
                            did_checkin = True
                print(f"Replayed {step.type} at {at.isoformat()} (local simulation)", flush=True)
                last_event_at = max(last_event_at, at)
                previous_offset = step.offset_s
            # One active visit per site: close this day's before the next day's schedule.
            for visit in api.get("/api/state").json()["visits"]:
                if visit["state"] in ("open", "in_progress", "unmatched"):
                    api.post(f"/api/visits/{visit['id']}/close").raise_for_status()
        # Push the clock past the last window + grace so elapsed schedules lapse to no_observation.
        end = max(
            start
            + timedelta(
                days=args.days - 1,
                minutes=args.window_minutes + settings.arrival_grace_minutes + 1,
            ),
            last_event_at + timedelta(minutes=settings.arrival_grace_minutes + 1),
        )
        api.post("/api/poll").raise_for_status()
        advance(api, end)
        api.post("/api/sweep").raise_for_status()
        visits = api.get("/api/state").json()["visits"]
        for visit in visits:
            if visit["state"] in ("open", "in_progress", "unmatched"):
                api.post(f"/api/visits/{visit['id']}/close").raise_for_status()
        if args.worker_review:
            targets = [
                v
                for v in api.get("/api/state").json()["visits"]
                if v["state"] != "no_observation" and v.get("schedule_id")
            ]
            if not targets:
                sys.exit("no observed visit to post the worker review against")

            # Prefer the visit whose worker check-in diverges most from the
            # camera's first observation — the canned dispute is an ARRIVAL
            # claim ("I arrived before the first observation shown"), and on a
            # 'late' story day the deferred check-in makes that record show the
            # Source divergence row. Fall back to the newest observed visit.
            def _lag(v):
                if not v.get("checked_in_at") or not v.get("arrived_at"):
                    return -1.0
                return abs(
                    (
                        datetime.fromisoformat(v["checked_in_at"]) - datetime.fromisoformat(v["arrived_at"])
                    ).total_seconds()
                )

            target = max(targets, key=_lag)
            response = api.post(f"/api/visits/{target['id']}/review-link")
            response.raise_for_status()
            decision, statement, reason = (
                ("confirm", "Confirmed — I was present for the scheduled window.", None)
                if args.worker_review == "confirm"
                else (
                    "dispute",
                    "I dispute this record — I arrived before the first observation shown.",
                    # self-reported coded reason — classifies the account, never verified
                    "schedule_difference",
                )
            )
            posted = api.post(
                response.json()["path"],
                auth=None,
                data={"decision": decision, "statement": statement, "reason_code": reason or ""},
            )
            if posted.status_code != 200:
                sys.exit("Simulated worker review rejected; inspect the record.")
            print(f"Worker review posted on {target['id']} ({decision})", flush=True)
        print(
            f"Replay records are ready for review at {args.public_url}; "
            "no live Ring attendance was verified.",
            flush=True,
        )


def _demo(args: argparse.Namespace) -> None:
    """One-command demo: in-process emulator + server + story replay, then serve."""
    import secrets
    import socket
    import tempfile
    import threading
    from pathlib import Path

    import uvicorn
    from pydantic import SecretStr
    from ring_sandbox.emulator import create_app as sandbox_app
    from ring_sandbox.world import Chaos

    from .app import create_app
    from .config import Settings

    def serve(
        app, port: int = 0, host: str = "127.0.0.1", display_host: str | None = None
    ) -> tuple[str, uvicorn.Server, threading.Thread, socket.socket]:
        sock = socket.socket()
        sock.bind((host, port))
        sock.listen(32)
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False))
        thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started:
            if time.monotonic() > deadline:
                sys.exit("demo server failed to start")
            time.sleep(0.01)
        return f"http://{display_host or host}:{sock.getsockname()[1]}", server, thread, sock

    def lan_ip() -> str:
        """Best-guess LAN address so printed URLs/QRs resolve from a phone on
        the same network — a UDP connect picks the outbound interface without
        sending a packet."""
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 80))  # TEST-NET-1: routed nowhere, just picks the iface
            return probe.getsockname()[0]
        except OSError:
            return "127.0.0.1"
        finally:
            probe.close()

    # --chaos injects delivery faults that cannot change the story: duplicates
    # collapse on request_id dedupe and jitter is waited out — drops would
    # silently rewrite "observed" into "no_observation", so they stay out.
    chaos = Chaos(seed=0, duplicate=0.35, delay_ms=200, jitter_ms=600) if args.chaos else None
    ring_url, ring_server, _ring_thread, ring_sock = serve(sandbox_app(chaos=chaos))

    if args.data_dir:
        data_dir = Path(args.data_dir)
        if data_dir.exists() and any(data_dir.iterdir()):
            sys.exit("--data-dir must be empty — the demo always starts a fresh runtime")
        data_dir.mkdir(parents=True, exist_ok=True)
    else:
        data_dir = Path(tempfile.mkdtemp(prefix="attest-demo-"))
    from .instance import acquire_instance_lock

    acquire_instance_lock(data_dir)

    token = secrets.token_urlsafe(32)
    # The demo owns this CLI process; point the replay driver at the token it minted.
    settings.admin_token = SecretStr(token)
    # Webhook HMAC keys are never shipped: mint a fresh one per run and hand it
    # to both the app's verifier and the in-process replay driver's signer.
    webhook_key = secrets.token_urlsafe(32)
    settings.ring_webhook_key = webhook_key
    demo = Settings(
        _env_file=None,
        admin_token=token,
        replay_mode=True,
        data_dir=data_dir,
        ring_base_url=ring_url,
        ring_webhook_key=webhook_key,
        timezone="UTC",
        summarizer="template",
    )
    # --lan binds the demo on all interfaces so the QR-door-step moment works
    # from a real phone. app_url stays loopback — the replay driver only
    # targets local services; display_url is the LAN address for printed links.
    if args.lan:
        lan = lan_ip()
        app_url, app_server, _app_thread, app_sock = serve(
            create_app(demo), args.port, host="0.0.0.0", display_host="127.0.0.1"
        )
        display_url = f"http://{lan}:{app_sock.getsockname()[1]}"
    else:
        app_url, app_server, _app_thread, app_sock = serve(create_app(demo), args.port)
        display_url = app_url

    replay = argparse.Namespace(
        scenario="home_aide_visit",
        days=args.days,
        story=args.story,
        no_show_day=None,
        rotate_day=args.rotate_day,
        revoke_day=args.revoke_day,
        worker_review="dispute",
        auto_checkin=True,
        speed=args.speed,
        ring_url=ring_url,
        public_url=app_url,
        window_minutes=args.window_minutes,
        expected_minutes=args.expected_minutes,
        site_name=args.site_name,
        worker_name=args.worker_name,
        camera_only=args.camera_only,
    )
    _replay(replay)

    # Sign a coverage attestation over the replayed window up front, so every
    # case pack the judge exports already carries the "was anyone watching?"
    # answer — silence inside it is meaningful, never an absence claim.
    from datetime import timedelta

    from ring_sandbox import RingClient

    from .engine import VisitEngine
    from .keycustody import load_or_create_signer
    from .media import MediaStore
    from .store import Store
    from .summarize import TemplateSummarizer

    store = Store(data_dir / "attest.sqlite3")
    family_url = None
    signed_ids: dict[str, str] = {}
    resolved_visit = None
    try:
        engine = VisitEngine(
            store,
            RingClient(None, base_url=ring_url),
            load_or_create_signer(
                demo.key_path,
                kms_key_id=demo.kms_key_id,
                aws_region=demo.aws_region,
                custody=demo.key_custody,
            ),
            MediaStore(data_dir / "media"),
            TemplateSummarizer("UTC"),
            demo,
        )
        sites = store.sites()
        if sites:
            end = engine.clock.now()
            receipt = engine.issue_coverage_attestation(
                sites[0], end - timedelta(days=args.days, hours=1), end
            )
            cov = receipt.payload["coverage"]
            print(
                f"Signed {receipt.id}: coverage {cov['state']}"
                f" ({cov['fraction'] * 100:.0f}%) over the story window.",
                flush=True,
            )
            signed_ids["coverage"] = receipt.id
        # Sign the emulator API sweep too — the ledger and every exported pack
        # then carry the verification_report shape a real `verify-live --sign`
        # produces, honestly labeled with the loopback base URL. A sweep
        # failure must not kill the demo after the story already replayed.
        from . import verifylive

        try:
            vreport = verifylive.run(RingClient("sandbox-token", base_url=ring_url))
            vreceipt = engine.issue_verification_report(vreport)
            vs = vreport["summary"]
            print(
                f"Signed {vreceipt.id}: API sweep vs emulator "
                f"({vs['pass']} pass/{vs['fail']} fail) — deployment provenance.",
                flush=True,
            )
            signed_ids["verify"] = vreceipt.id
        except Exception as exc:  # noqa: BLE001 — demo provenance is best-effort
            print(f"API sweep skipped ({type(exc).__name__}: {exc})", flush=True)
        # Pre-issue a scoped family link on the record the worker disputed —
        # the tour can hand the judge the family view in one click. The
        # household's own (contradicting) account is appended too, so the
        # showcase record is trilateral: camera vs worker vs household.
        from .models import HouseholdStatementInput
        from .reviews import ReviewService

        for v in store.visits():
            if any(
                e.receipt.payload.get("actor", {}).get("role") == "worker" for e in store.reviews_for(v.id)
            ):
                family_token = engine.issue_family_link(v.id)
                ReviewService(store, engine.signer, engine.clock).household_statement(
                    family_token,
                    HouseholdStatementInput(
                        perception="no_one_seen",
                        statement=(
                            "My mother was home all morning and says the doorbell "
                            "never rang — nobody came to the door before ten."
                        ),
                    ),
                )
                family_url = f"{display_url}/family/{family_token}"
                break
        # Resolve the honest no-observation day — the terminal state of the
        # dispute loop needs to exist for judges to see it. The contested
        # visit is deliberately left unresolved so "Conclude the record"
        # stays an interactive beat in the tour.
        from .models import ResolutionInput

        for v in store.visits():
            if v.state.value == "no_observation" and store.receipt_for_visit(v.id):
                ReviewService(store, engine.signer, engine.clock).resolve(
                    v.id,
                    ResolutionInput(
                        outcome="inconclusive",
                        statement=(
                            "No observations arrived in the scheduled window and coverage "
                            "shows the channel was watched — but silence is not proof of "
                            "absence. Closing as inconclusive: the record states what was "
                            "seen, not what happened."
                        ),
                        reason_code="no_electronic_confirmation",
                    ),
                )
                resolved_visit = v.id
                print(
                    f"Resolved {v.id}: inconclusive — the record says what was watched, not what happened.",
                    flush=True,
                )
                break
        # Period digest last — it counts review entries, so it must see the
        # worker dispute and household statement that just landed.
        if sites:
            dreceipt = engine.issue_period_digest(sites[0], end - timedelta(days=args.days, hours=1), end)
            print(
                f"Signed {dreceipt.id}: period digest over the story window.",
                flush=True,
            )
            signed_ids["digest"] = dreceipt.id
    finally:
        store.close()

    print()
    print("Demo is live — simulated data only, no real Ring account involved.", flush=True)
    if chaos:
        print(
            "  chaos       emulator is duplicating + jittering webhook deliveries —",
            flush=True,
        )
        print("              the ledger must show one evidence row per real event", flush=True)
    dash_host = display_url.split("://", 1)[1].rsplit(":", 1)[0]
    dash_url = f"http://admin:{token}@{dash_host}:{app_sock.getsockname()[1]}/"
    print(f"  dashboard   {dash_url}", flush=True)
    if args.lan:
        print("  lan         listening on all interfaces — the QR codes resolve", flush=True)
        print("              from a phone on this network; admin still needs the token", flush=True)
    print(f"  admin user  admin / {token}", flush=True)
    print(f"  data dir    {data_dir}", flush=True)
    print("", flush=True)
    print("Three-minute tour:", flush=True)
    print("  1. Open the dashboard — 'Needs review' triages the week; click", flush=True)
    print("     'Run agent brief' for the Strands/Bedrock agent's own read.", flush=True)
    print("  2. Open the contested visit from 'Needs review' — the worker's signed", flush=True)
    print("     dispute sits atop the evidence, and Source divergence shows their", flush=True)
    print("     check-in landing ~65 min after the camera saw them. 'Conclude the", flush=True)
    print("     record' signs the coordinator's call — pick a coded reason too:", flush=True)
    print("     EVV-style exception codes classify the stated explanation, never", flush=True)
    print("     a verified cause, and they aggregate on the signed period digest.", flush=True)
    if args.rotate_day is not None:
        print(
            f"     (The signing key rotated on story day {args.rotate_day} — receipts",
            flush=True,
        )
        print("      on both sides verify through the signed key_rotation pivot.)", flush=True)
    if getattr(args, "revoke_day", None) is not None:
        print(
            f"     (Compromise drill on story day {args.revoke_day}: the retired key is",
            flush=True,
        )
        print("      revoked — 'attest status' and every pack verifier flag its", flush=True)
        print("      output as a suspect window; nothing was erased.)", flush=True)
    print("  3. Download a pack, then 'Verify a pack in-browser' on the dashboard —", flush=True)
    print("     drop the .zip; it self-verifies, no install, no unzip. Site packs", flush=True)
    print("     carry the signed coverage cert: 'was anyone watching?' In the", flush=True)
    print("     default story one camera dies mid-visit and the Ring plan", flush=True)
    print("     lapses on another day — the records sign the device_offline and", flush=True)
    print("     subscription_deactivated lifecycle, so quiet spans read", flush=True)
    print("     explained (a fault, a billing event), never absent.", flush=True)
    print("     Open the pack's index.html — a week strip of the whole window", flush=True)
    print("     first, then each record toggles between the technical view and", flush=True)
    print("     a plain-language family view. Or skip the install entirely:", flush=True)
    print("     https://josepha-mayo.github.io/attest/verify.html hosts the verifier.", flush=True)
    print("  4. On the visit: 'Printable brief' — one page for a mediator or", flush=True)
    print("     filing: state, sources, all three voices, signed anchors, and", flush=True)
    print("     the verify steps. Media digests only — safe to hand over.", flush=True)
    print("  5. Dashboard → 'Integrity posture' — the runtime's self-audit, live:", flush=True)
    print("     chain verification, journal replay, key custody, per-site watching.", flush=True)
    print("     Then the site page: 'Open live view' brokers a real WHEP stream —", flush=True)
    print("     journaled as 'a stream was opened', never evidence of what it saw.", flush=True)
    print("     The default story's last day already carries one: its signed", flush=True)
    print("     coverage names the session; the week strip draws the mark.", flush=True)
    print("  In another terminal, point at the demo's store first:", flush=True)
    print(f'    $env:ATTEST_DATA_DIR="{data_dir}"   (PowerShell)', flush=True)
    print(f"    ATTEST_DATA_DIR={data_dir} <cmd>      (POSIX)", flush=True)
    print("  6. attest status       — audits the whole runtime offline (--json for scripts)", flush=True)
    print("  7. attest triage       — the week's brief (agent when AWS is reachable)", flush=True)
    print("  8. attest verify <zip|url> — a pack verifies itself, even straight", flush=True)
    print("     from https://josepha-mayo.github.io/attest/sample-pack.zip", flush=True)
    print("  9. attest explain <visit_or_receipt_id> — full provenance, in words", flush=True)
    print(" 10. attest doctor       — the deployment preflight; it also shows this", flush=True)
    print("     demo process holding the runtime's writer lock", flush=True)
    print("     (read-only commands run alongside the live demo; writer commands —", flush=True)
    print("      export, coverage, digest, rotate-key, attack-demo — take the", flush=True)
    print("      single-instance lock, so Ctrl+C the demo first. The dashboard's", flush=True)
    print("      pack download and /api/admin/rotate-key are the live paths.)", flush=True)
    print(" 11. attest attack-demo — the tamper battery, every attempt caught", flush=True)
    print("     and rolled back (offline runtimes only — it holds the writer lock)", flush=True)
    print(" 12. rotate the signing key live — the pivot is a signed chain event", flush=True)
    print("     and receipts on both sides still verify:", flush=True)
    print(
        f'     curl -u admin:{token} -X POST "{app_url}/api/admin/rotate-key"',
        flush=True,
    )
    print("     (attest rotate-key is the offline path — it rotates the key file", flush=True)
    print("      while the server is stopped; the running server keeps its", flush=True)
    print("      loaded signer. --rotate-day K does the live pivot mid-story.)", flush=True)
    print("     then the incident-response move — declare the retired key's", flush=True)
    print("     signatures suspect without erasing a record:", flush=True)
    print(
        f'     curl -u admin:{token} -X POST "{app_url}/api/admin/revoke-key" '
        '-d \'{"revoked_key":"<old-key>","reason":"compromise"}\'',
        flush=True,
    )
    if "verify" in signed_ids:
        print(f"     e.g. attest explain {signed_ids['verify']} — the API sweep just", flush=True)
        print("     signed as a chained attestation (verify-live --sign does it live)", flush=True)
    if resolved_visit:
        print(
            f"  Also: {resolved_visit} is already concluded 'inconclusive' — the",
            flush=True,
        )
        print("  terminal state of the dispute loop, coded no_electronic_confirmation", flush=True)
        print("  (resolved visits leave Needs review; find it under Records). ", flush=True)
    print("  '/household' on any visit is the family's view —", flush=True)
    print("  plain language, glanceable; 'Share the household view' issues a scoped", flush=True)
    print("  link (/family/…) with a QR code for the door-step scan, same as", flush=True)
    print("  the worker links (re-run with --lan to scan it from a real phone).", flush=True)
    print("  --redact-media exports keep signed digests while", flush=True)
    print("  withholding footage; attest diff A.zip B.zip proves appends only", flush=True)
    print("  ever add — never rewrite.", flush=True)
    if family_url:
        print(f"  Family view, pre-issued on the disputed visit: {family_url}", flush=True)
        print("    (carries camera vs worker vs household accounts — the family", flush=True)
        print("     can add their own account from that page; it signs in verbatim)", flush=True)
        if sys.stdout.isatty():
            for line in _terminal_qr(family_url) or []:
                print(f"    {line}", flush=True)
    print("", flush=True)
    if args.open:
        import webbrowser

        webbrowser.open(dash_url)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        app_server.should_exit = True
        ring_server.should_exit = True
        app_sock.close()
        ring_sock.close()


def _is_loopback(host: str) -> bool:
    """127/8 and ::1 — not just the spelled-out 127.0.0.1 — plus the
    localhost name. Non-IP hostnames are never loopback."""
    import ipaddress

    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _fetch_issuer_doc(url: str, client=None) -> dict:
    """Fetch ``<url>/.well-known/attest-issuer.json`` — the remote pin for
    verification. HTTPS only, loopback excepted (the document itself warns
    that issuer authenticity rides on transport). Byte-capped and
    schema-checked; anything else fails closed. A local file path loads a
    document previously written by ``attest issuer --out`` instead."""
    from pathlib import Path

    if "://" not in url and Path(url).is_file():
        try:
            raw = Path(url).read_bytes()
        except OSError as exc:
            sys.exit(f"issuer document unreadable: {exc}")
        if len(raw) > 4 * 1024 * 1024:
            sys.exit("issuer document exceeds the 4 MB bound")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            sys.exit(f"issuer document is not valid JSON: {exc}")
        if doc.get("schema") != "attest.issuer/1" or not doc.get("issuer_key"):
            sys.exit(f"{url} is not an attest.issuer/1 document")
        return doc
    base = urlsplit(url if "://" in url else f"https://{url}")
    host = base.hostname or ""
    if base.scheme != "https" and not _is_loopback(host):
        sys.exit("issuer discovery requires HTTPS — loopback excepted for local verification")
    endpoint = f"{base.scheme}://{base.netloc}/.well-known/attest-issuer.json"
    stream_ctx = client.stream if client is not None else httpx.stream
    try:
        with stream_ctx("GET", endpoint, timeout=15) as r:
            if r.status_code != 200:
                sys.exit(f"issuer discovery failed: HTTP {r.status_code} from {endpoint}")
            raw = bytearray()
            for chunk in r.iter_bytes(1 << 16):
                raw.extend(chunk)
                if len(raw) > 4 * 1024 * 1024:
                    sys.exit("issuer document exceeds the 4 MB bound")
    except httpx.HTTPError as exc:
        sys.exit(f"issuer discovery failed: {exc}")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        sys.exit(f"issuer document is not valid JSON: {exc}")
    if doc.get("schema") != "attest.issuer/1" or not doc.get("issuer_key"):
        sys.exit(f"{endpoint} did not serve an attest.issuer/1 document")
    return doc


def _verify(args: argparse.Namespace) -> None:
    """Verify a downloaded artifact offline: review bundle, bare receipt, anchor,
    or a receipts.json export list."""
    from pathlib import Path

    from . import ledger, reviews
    from .models import Receipt, ReviewBundle

    pinned_key = args.key
    known_rotations: list | None = None
    if getattr(args, "issuer_url", None):
        doc = _fetch_issuer_doc(args.issuer_url)
        pinned_key = doc["issuer_key"]
        try:
            known_rotations = [Receipt.model_validate(r) for r in doc.get("key_receipts") or []]
        except Exception as exc:  # noqa: BLE001
            sys.exit(f"issuer document carried malformed key receipts: {exc}")
        print(
            f"pinned to issuer key served by {args.issuer_url} "
            f"({len(known_rotations)} lifecycle receipt(s)) — authenticity rides on transport"
        )

    path = Path(args.bundle)
    remote = args.bundle.startswith(("http://", "https://"))
    # --issuer-url pins the artifact to a DEPLOYMENT's discovery document
    # rather than a raw key: issuer_key pins verification, key_receipts
    # extend the trusted lineage in both directions (pre-rotation packs
    # still verify against the deployment's current signer).
    if remote:
        # Verification is cryptographic — transport trust is not required —
        # but stream with a byte cap so a hostile endpoint can't buffer
        # unbounded content into memory before we can reject it.
        raw, n = bytearray(), 0
        try:
            with httpx.stream("GET", args.bundle, follow_redirects=True, timeout=30) as r:
                if r.status_code != 200:
                    sys.exit(f"fetch failed: HTTP {r.status_code} for {args.bundle}")
                for chunk in r.iter_bytes(1 << 20):
                    n += len(chunk)
                    if n > 256 * 1024 * 1024:
                        sys.exit("artifact exceeds the 256 MB verification bound")
                    raw.extend(chunk)
        except httpx.HTTPError as exc:
            sys.exit(f"fetch failed: {exc}")
        path = Path(args.bundle.rstrip("/").rsplit("/", 1)[-1] or "remote-artifact")
    else:
        raw = path.read_bytes()
    if raw[:2] == b"PK":
        _verify_zip(raw, pinned_key, known_rotations)
        return
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        sys.exit(f"not a JSON artifact: {path.name}\n  a .zip pack verifies directly — pass the zip itself.")
    except json.JSONDecodeError as exc:
        sys.exit(f"not valid JSON: {exc}")
    pinned = " (against the pinned issuer key)" if pinned_key else ""
    trust_note = (
        "under that key"
        if pinned_key
        else "under the artifact's self-declared issuer key — pin a trusted key with --key"
    )

    if isinstance(data, list):
        receipts = [Receipt.model_validate(r) for r in data]
        ok, reason = ledger.verify_chain(
            receipts, public_key=pinned_key, extra_key_receipts=known_rotations
        )
        if not ok:
            sys.exit(f"verification failed: {reason}")
        print(f"OK{pinned}: {reason}.")
        print(f"Note: a valid chain proves record integrity {trust_note}, not physical truth.")
        return

    if isinstance(data, dict) and "payload" in data and "signature" in data:
        receipt = Receipt.model_validate(data)
        trusted_key = pinned_key
        if pinned_key and known_rotations is not None:
            # The issuer document's signed lifecycle names every key the
            # deployment ever signed under — a receipt written before the
            # rotation verifies under the pin too, and a foreign key fails.
            lineage = ledger.trusted_issuer_keys(
                pinned_key, known_rotations
            ) | ledger.descendant_issuer_keys(pinned_key, known_rotations)
            if receipt.public_key not in lineage:
                sys.exit(
                    "verification failed: receipt signed by a key outside the "
                    "pinned issuer document's lineage"
                )
            trusted_key = receipt.public_key
        ok, reason = ledger.verify_receipt(receipt, public_key=trusted_key)
        if not ok:
            sys.exit(f"verification failed: {reason}")
        kind = receipt.payload.get("record_type") or receipt.payload.get("schema")
        print(f"OK{pinned}: {kind} {receipt.id} — {reason}.")
        print(f"Note: a valid signature proves record integrity {trust_note}, not physical truth.")
        # The sibling-.ots check only makes sense for a local file — for a URL
        # artifact the basename would match some unrelated CWD file (or crash
        # on a path that doesn't exist locally).
        if not remote:
            _report_sibling_ots(Path(args.bundle))
        return

    try:
        bundle = ReviewBundle.model_validate(data)
    except Exception:
        sys.exit(
            f"not a reviewable artifact: {path.name}\n"
            "  expected a bundle.json, receipt, anchor, or receipts.json export list."
        )
    key = pinned_key or bundle.original.public_key
    kr_path = path.parent / "key_rotations.json"
    rotations = list(known_rotations or [])
    if kr_path.is_file():
        # Mirror the embedded verify_bundle.py: reviews appended after a key
        # rotation verify under the successor — legitimate only through the
        # signed rotation+adoption links the pack ships next to the bundle.
        try:
            rj = json.loads(kr_path.read_text(encoding="utf-8"))
            rotations += [Receipt.model_validate(r) for r in rj.get("rotations") or []]
        except Exception as exc:  # noqa: BLE001
            sys.exit(f"verification failed: key_rotations.json malformed ({exc})")
    if rotations:
        trusted = ledger.trusted_issuer_keys(key, rotations) | ledger.descendant_issuer_keys(key, rotations)
        ok, reason = reviews.verify_bundle(bundle, trusted_keys=trusted)
    else:
        ok, reason = reviews.verify_bundle(bundle, public_key=key)
    if not ok:
        sys.exit(f"verification failed: {reason}")
    print(f"OK{pinned}: {reason}.")
    stance = reviews.countersign_status(bundle)
    print(f"Worker stance: {stance['state']} — {stance['detail']}")
    print(f"Note: a valid signature proves record integrity {trust_note}, not physical truth.")


def _verify_zip(raw: bytes, pinned_key: str | None, known_rotations: list | None = None) -> None:
    """Verify a dispute pack or case pack zip in place — same checks as the
    embedded verify_case.py and the /verify page. Without --key the pack's own
    declared issuer key is pinned (self-consistency); --key pins a deployment key.
    ``known_rotations`` (e.g. fetched via --issuer-url) extends trust forward
    through the deployment's signed lifecycle — a pack exported before a
    rotation still verifies under the current issuer."""
    import io
    import zipfile

    from .app import _verify_pack
    from .models import ReviewBundle
    from .packdiff import BoundedZip

    try:
        z = BoundedZip(zipfile.ZipFile(io.BytesIO(raw)))
        names = set(z.namelist())
        if "manifest.json" in names:
            declared = json.loads(z.read("manifest.json")).get("issuer_key")
        elif "bundle.json" in names:
            declared = ReviewBundle.model_validate(json.loads(z.read("bundle.json"))).original.public_key
        else:
            sys.exit("zip contains no manifest.json or bundle.json — not an Attest pack")
    except zipfile.BadZipFile:
        sys.exit("not a valid zip file")
    except Exception as exc:
        sys.exit(f"could not read pack issuer: {exc}")
    key = pinned_key or declared
    ok, detail = _verify_pack(raw, key, known_rotations=known_rotations)
    if not ok:
        sys.exit(f"verification failed: {detail}")
    print(f"OK: {detail}")
    if pinned_key:
        print("Note: a valid pack proves record integrity under the pinned issuer key, not physical truth.")
    else:
        print(
            "Note: a valid pack proves record integrity under the pack's self-declared "
            "issuer key — pin a trusted key with --key. Signatures are not physical truth."
        )


def _report_sibling_ots(path) -> None:
    """If FILE.ots sits next to the artifact, report its OpenTimestamps status
    and check the stamped digest still matches the file's bytes."""
    import hashlib

    from .timestamp import extract_digest, ots_status

    ots_path = path.with_name(path.name + ".ots")
    if not ots_path.exists():
        return
    ots = ots_path.read_bytes()
    stamped = extract_digest(ots)
    actual = hashlib.sha256(path.read_bytes()).digest()
    if stamped == actual:
        match = "digest matches this file"
    else:
        match = "stamped digest differs — file changed since stamping"
    print(f"OpenTimestamps: {ots_status(ots)} — {match}.")


def _anchor(args: argparse.Namespace) -> None:
    """Write a signed anchor: the journal head and receipt-chain head at this
    instant. Publish it anywhere — later deletion of the log's tail or of
    receipts is provable against the anchor."""
    from pathlib import Path

    from .keycustody import load_or_create_signer
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    from .instance import acquire_instance_lock

    acquire_instance_lock(settings.data_dir)
    store = Store(db)
    try:
        signer = load_or_create_signer(
            settings.key_path,
            kms_key_id=settings.kms_key_id,
            custody=settings.key_custody,
            aws_region=settings.aws_region,
        )
        prev = store.latest_receipt()
        entries = store._conn.execute("SELECT COUNT(*) FROM journal").fetchone()[0]
        anchor = signer.issue(
            visit_id="anchor",
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "anchor",
                "journal_head": store.journal_head(),
                "journal_entries": entries,
                "receipt_head": prev.payload_hash if prev else None,
                "receipt_count": len(store.receipts()),
                "visit_count": store.stats()["visits"]["total"],
                "boundary": (
                    "Anchors that a record state existed at issuance. Truncating the "
                    "journal or removing receipts after this anchor is provable."
                ),
            },
        )
        out = Path(args.out or "attest-anchor.json")
        out.write_text(anchor.model_dump_json(indent=2), encoding="utf-8")
        print(
            f"wrote {out} — journal head {anchor.payload['journal_head'][:16]}…, "
            f"{entries} entries, {anchor.payload['receipt_count']} receipts pinned"
        )
        if args.publish:
            _publish_anchor(args.publish, out, anchor.payload_hash, settings.aws_region)
        if args.timestamp:
            _stamp_file(out)
    finally:
        store.close()


def _stamp_file(path) -> None:
    """Submit a file's sha256 to the public OTS calendars and write FILE.ots —
    an independently-verifiable 'existed before this Bitcoin block' proof."""
    from .timestamp import ots_status, stamp_bytes

    try:
        ots, cal = stamp_bytes(path.read_bytes())
    except RuntimeError as exc:
        sys.exit(f"timestamp failed: {exc}")
    ots_path = path.with_name(path.name + ".ots")
    # Write-then-rename: a crash mid-write must not leave a truncated .ots
    # next to a valid artifact looking like its proof.
    tmp = ots_path.with_name(ots_path.name + ".tmp")
    tmp.write_bytes(ots)
    tmp.replace(ots_path)
    print(
        f"wrote {ots_path} — submitted via {cal}; {ots_status(ots)}.\n"
        f"  upgrade once the calendar commits to Bitcoin: attest stamp --upgrade {ots_path}\n"
        f"  verify independently: `ots verify {ots_path}` (pip install opentimestamps-client)"
    )


def _stamp(args: argparse.Namespace) -> None:
    """Notarize any file's digest on the public OpenTimestamps calendars — or
    refresh a pending proof once its calendar has committed to Bitcoin."""
    from pathlib import Path

    from .timestamp import ots_status, upgrade

    target = Path(args.file)
    if args.upgrade:
        old = target.read_bytes()
        try:
            new = upgrade(old)
        except RuntimeError as exc:
            sys.exit(f"upgrade failed: {exc}")
        if new is None:
            print(f"{ots_status(old)} — the calendar is reachable; check again later")
        elif new != old:
            tmp = target.with_name(target.name + ".tmp")
            tmp.write_bytes(new)
            tmp.replace(target)
            print(f"upgraded {target} — {ots_status(new)}")
        else:
            print(f"{ots_status(new)} — check again later")
        return
    _stamp_file(target)


def _publish_anchor(uri: str, path, payload_hash: str, region: str) -> None:
    """Upload a signed anchor to S3 — external custody for the checkpoint, so a
    later-truncated journal or removed receipt is provable against an object
    the deployment doesn't control."""
    import hashlib

    if not uri.startswith("s3://"):
        sys.exit("--publish takes an s3://bucket/key URI")
    bucket_key = uri[5:].split("/", 1)
    if len(bucket_key) != 2 or not all(bucket_key):
        sys.exit("--publish takes an s3://bucket/key URI")
    bucket, key = bucket_key
    try:
        import boto3
    except ImportError:
        sys.exit("--publish s3://… requires boto3 (pip install 'attest[aws]')")
    body = path.read_bytes()
    sha = hashlib.sha256(body).hexdigest()
    try:
        boto3.client("s3", region_name=region).put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            Metadata={"attest-record-type": "anchor", "sha256": sha, "payload-hash": payload_hash},
        )
    except Exception as exc:  # noqa: BLE001 — surface the AWS error verbatim
        sys.exit(f"S3 publish failed: {exc}")
    print(f"published {uri} (sha256 {sha[:16]}…) — the checkpoint now has external custody")


def _triage(args: argparse.Namespace) -> None:
    """Print the week's 'needs attention' brief — a Strands agent reading the
    ledger through real tools when Bedrock is reachable, else the deterministic
    triage. The output always labels which source produced it."""
    from .keycustody import load_or_create_signer
    from .reviews import ReviewService
    from .store import Store
    from .triage import run_triage

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    store = Store(db)
    try:
        signer = load_or_create_signer(
            settings.key_path,
            kms_key_id=settings.kms_key_id,
            custody=settings.key_custody,
            aws_region=settings.aws_region,
        )
        from .clock import ExecutionClock

        # Triage never writes; the clock only needs to match the store's mode.
        replay = (store.setting("execution_mode") or {}).get("mode") == "replay"
        clock = ExecutionClock(
            store, replay=replay, ring_base_url="http://127.0.0.1" if replay else settings.ring_base_url
        )
        reviews = ReviewService(store, signer, clock)
        result = run_triage(
            store,
            reviews,
            model_id=settings.bedrock_model_id,
            region=settings.aws_region,
        )
        print(result.brief)
        if result.source == "strands-agent":
            print(f"\n[source: Strands agent over Bedrock {result.model}]")
        else:
            print(f"\n[source: deterministic triage — agent unavailable: {result.fallback_reason}]")
    finally:
        store.close()


def _must_store():
    """Open the runtime store — or refuse. An integrity/inspection command must
    never let SQLite silently CREATE an empty db and then report it intact
    ('attest journal' on a never-written dir must not print entries: 0, ok)."""
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db} — run `attest serve` or `attest replay` first")
    return Store(db)


def _cli_engine(store):
    """A real VisitEngine over an existing store for offline issuance commands
    (coverage/digest/export signing). The Ring client is never called."""
    from ring_sandbox import RingClient

    from .engine import VisitEngine
    from .keycustody import load_or_create_signer
    from .media import MediaStore
    from .summarize import TemplateSummarizer

    # No writer lock here — explain uses this engine read-only. The mutating
    # commands that call it (coverage/digest/export/rotate) acquire it first.
    # The store's persisted mode wins — a replay-runtime store must be read
    # with a replay clock even when ATTEST_REPLAY_MODE isn't set in this shell.
    mode = (store.setting("execution_mode") or {}).get("mode", "wall")
    eff = settings.model_copy(update={"replay_mode": mode == "replay"})
    base = settings.ring_base_url
    if eff.replay_mode and urlsplit(base).hostname not in ("127.0.0.1", "localhost", "::1"):
        base = "http://127.0.0.1:9"  # inert — satisfies the loopback-only guard
    return VisitEngine(
        store,
        RingClient(settings.ring_access_token, base_url=base),
        load_or_create_signer(
            settings.key_path,
            kms_key_id=settings.kms_key_id,
            custody=settings.key_custody,
            aws_region=settings.aws_region,
        ),
        MediaStore(settings.data_dir / "media"),
        TemplateSummarizer(settings.timezone),
        eff,
    )


def _coverage_cert(args: argparse.Namespace) -> None:
    """Sign a coverage attestation for an interval: 'the pipeline checked K times,
    Ring returned M events' — a standalone answer to 'was anyone watching?'."""
    from datetime import datetime

    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    from .instance import acquire_instance_lock

    acquire_instance_lock(settings.data_dir)
    store = Store(db)
    try:
        site = store.site(args.site) if args.site else (store.sites()[0] if store.sites() else None)
        if site is None:
            sys.exit("no site found — seed or run a replay first")
        end = datetime.fromisoformat(args.to) if args.to else None
        start = datetime.fromisoformat(args.start) if args.start else None
        if end is None or start is None or start.tzinfo is None or end.tzinfo is None:
            sys.exit("--from and --to must be ISO timestamps with timezone")
        receipt = _cli_engine(store).issue_coverage_attestation(site, start, end)
        cov = receipt.payload["coverage"]
        explained = sum(1 for g in cov["gaps"] if g.get("explained"))
        print(
            f"signed {receipt.id} — coverage {cov['state']} ({cov['fraction'] * 100:.1f}%), "
            f"{cov['polls']} polls, {cov['events']} events, {len(cov['gaps'])} gap(s)"
            + (f" ({explained} explained by lifecycle events)" if explained else "")
        )
    finally:
        store.close()


def _rotate_key(args: argparse.Namespace) -> None:
    """Retire the deployment signing key and adopt a fresh one.

    Order is the trust story: the retiring key first signs a ``key_rotation``
    receipt naming its successor (the chain's pivot — receipts before it
    verify under the old key, receipts after under the new), then the new key
    lands on disk under the same custody posture (plaintext PEM, KMS wrap, or DPAPI),
    then the new key signs a ``key_adoption`` receipt proving the successor
    holder consented. A crash after the receipt but before the key write is
    safe — re-running is idempotent and the ledger never carries a pivot to a
    key that doesn't exist on disk."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .keycustody import load_or_create_signer, persist_signer_key
    from .ledger import Signer
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    from .instance import acquire_instance_lock

    acquire_instance_lock(settings.data_dir)
    store = Store(db)
    try:
        engine = _cli_engine(store)
        old_key = engine.signer.public_key_b64

        sk = Ed25519PrivateKey.generate()
        pem = sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        new_signer = Signer(sk)
        new_key = new_signer.public_key_b64

        def _adopt() -> Signer:
            persist_signer_key(
                settings.key_path,
                pem,
                kms_key_id=settings.kms_key_id,
                custody=settings.key_custody,
                aws_region=settings.aws_region,
            )
            return load_or_create_signer(
                settings.key_path,
                kms_key_id=settings.kms_key_id,
                custody=settings.key_custody,
                aws_region=settings.aws_region,
            )

        # Shared rotate path: pending-adoption resume, pivot, persist+reload,
        # adoption — serialized under the signing barrier so a crash window
        # has a recovery at every step.
        rotation, adopted = engine.rotate_signing_key(new_key, _adopt, args.reason or "")
        print(f"key rotated: {old_key[:16]}... -> {new_key[:16]}...")
        print(f"  rotation receipt  {rotation.id}")
        print(f"  adoption receipt  {adopted.id}")
        print(
            "  history still verifies: the chain reads the rotation receipt as "
            "the pivot; `attest status` and pack verification follow it."
        )
        if settings.kms_key_id:
            print("  successor wrapped under the configured KMS key")
        elif settings.key_custody == "dpapi":
            print("  successor wrapped under the Windows DPAPI user master key")
    finally:
        store.close()


def _revoke_key(args: argparse.Namespace) -> None:
    """Sign a ``key_revocation`` receipt under the CURRENT issuer — the
    incident-response counterpart to rotation: it declares the named key's
    post-``--suspect-after`` signatures untrustworthy without erasing or
    rewriting a single record. Rotate first if the suspect key is still
    live — a key cannot revoke itself."""
    from .instance import acquire_instance_lock
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    acquire_instance_lock(settings.data_dir)
    store = Store(db)
    try:
        engine = _cli_engine(store)
        if args.suspect_after:
            try:
                when = datetime.fromisoformat(args.suspect_after.replace("Z", "+00:00"))
            except ValueError:
                sys.exit(f"--suspect-after is not ISO 8601: {args.suspect_after!r}")
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
        else:
            # Default: the key's first signed receipt — when a compromise was
            # discovered is knowable, when it started is not; the honest
            # default declares the key's whole output suspect. An explicit
            # --suspect-after narrows it when forensics justify a later bound.
            # (Mirrors POST /api/admin/revoke-key.)
            when = next(
                (r.issued_at for r in store.receipts() if r.public_key == args.key),
                engine.clock.now(),
            )
        try:
            receipt = engine.issue_key_revocation(args.key, when, args.reason or "")
        except ValueError as exc:
            sys.exit(str(exc))
        print(f"key revoked: {args.key[:16]}... declared suspect after {when.isoformat()}")
        print(f"  revocation receipt  {receipt.id}")
        print(
            "  records still verify — every verifier now annotates the "
            "suspect window instead of failing the chain."
        )
    finally:
        store.close()


def _issuer(args: argparse.Namespace) -> None:
    """Write this deployment's issuer-discovery document — the same doc
    ``/.well-known/attest-issuer.json`` serves — for out-of-band pinning
    (`attest verify pack.zip --issuer-url issuer.json`) or audit exchange."""
    import os
    from pathlib import Path

    from . import ledger
    from .keycustody import load_or_create_signer
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    store = Store(db)
    try:
        signer = load_or_create_signer(
            settings.key_path,
            kms_key_id=settings.kms_key_id,
            custody=settings.key_custody,
            aws_region=settings.aws_region,
        )
        doc = ledger.issuer_document(signer.public_key_b64, store.receipts())
    finally:
        store.close()
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_name(out.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, out)
        print(f"wrote {out} — issuer {doc['issuer_key'][:16]}..., {len(doc['key_receipts'])} key receipt(s)")
    else:
        print(text, end="")


def _digest(args: argparse.Namespace) -> None:
    """Sign a digest of the records written for an interval — counts by outcome,
    review counts by stance, and the exact receipt set summarized."""
    from datetime import datetime

    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    from .instance import acquire_instance_lock

    acquire_instance_lock(settings.data_dir)
    store = Store(db)
    try:
        site = store.site(args.site) if args.site else (store.sites()[0] if store.sites() else None)
        if site is None:
            sys.exit("no site found — seed or run a replay first")
        end = datetime.fromisoformat(args.to) if args.to else None
        start = datetime.fromisoformat(args.start) if args.start else None
        if end is None or start is None or start.tzinfo is None or end.tzinfo is None:
            sys.exit("--from and --to must be ISO timestamps with timezone")
        receipt = _cli_engine(store).issue_period_digest(site, start, end)
        counts = receipt.payload["counts"]
        resolved = f", {counts['records_resolved']} resolved"
        if counts.get("median_resolution_minutes") is not None:
            resolved += f" (median {counts['median_resolution_minutes']} min to conclusion)"
        print(
            f"signed {receipt.id} — {counts['visits_observed']} observed, "
            f"{counts['visits_no_observation']} no-observation, "
            f"{counts['visits_unmatched']} unmatched, "
            f"{counts['worker_disputes']}/{counts['worker_statements']} worker disputes/statements, "
            f"{counts.get('household_statements', 0)} household statement(s)"
            f"{resolved}"
        )
    finally:
        store.close()


def _tamper_demo(args: argparse.Namespace) -> None:
    """Non-destructive: forge one row inside a transaction, show the journal catching
    it, then roll back — the store is left exactly as it was."""
    from .instance import acquire_instance_lock

    acquire_instance_lock(settings.data_dir)
    store = _must_store()
    try:
        row = store._conn.execute("SELECT id, body FROM visits LIMIT 1").fetchone()
        if not row:
            sys.exit("no visits in this store — run `attest replay home_aide_visit` first")
        visit_id, body = row
        forged = json.loads(body)
        forged["state"] = "attended_verified"  # the claim the record must refuse to carry

        pre = store.verify_journal()
        if pre["entries"] == 0 and pre["untracked_rows"]:
            stamped = store.journal_baseline()
            print(f"store predates journaling — stamped {stamped} rows as baseline")

        class _Rollback(Exception):
            pass

        try:
            with store.transaction():
                store._conn.execute("UPDATE visits SET body=? WHERE id=?", (json.dumps(forged), visit_id))
                report = store.verify_journal()
                print(f"forged {visit_id}.state = 'attended_verified'")
                print(f"intact: {report['intact']}")
                for m in report["mismatches"]:
                    print(f"  detected: {m}")
                raise _Rollback  # roll back both the forged row and the check
        except _Rollback:
            pass
        after = store.verify_journal()
        print(f"after rollback — intact: {after['intact']}, entries: {after['entries']}")
    finally:
        store.close()


def _journal(args: argparse.Namespace) -> None:
    store = _must_store()
    try:
        if args.baseline:
            from .instance import acquire_instance_lock

            acquire_instance_lock(settings.data_dir)
            stamped = store.journal_baseline()
            print(f"stamped {stamped} existing rows as journal baseline")
        report = store.verify_journal()
        print(json.dumps(report, indent=2))
        if not report["intact"]:
            sys.exit(1)
    finally:
        store.close()


def _status(args: argparse.Namespace) -> None:
    """One-command self-audit: journal integrity, receipt chain, coverage, queue —
    the integrity posture of the local runtime, checkable without the server."""
    from .inbox import WebhookInbox
    from .ledger import revoked_issuer_keys, suspect_receipts, verify_chain
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db} — run `attest serve` or `attest replay` first")
    store = Store(db)
    try:
        stats = store.stats()
        journal = store.verify_journal()
        all_receipts = store.receipts()
        chain_ok, chain_detail = verify_chain(all_receipts)
        inbox_path = settings.data_dir / "webhooks.sqlite3"
        queue: dict = {}
        if inbox_path.exists():
            inbox = WebhookInbox(inbox_path)
            try:
                queue = inbox.counts()
            finally:
                inbox.close()
        by_state = ", ".join(f"{k}={n}" for k, n in stats["visits"]["by_state"].items())
        # A row with no journal entry at all means an out-of-band write (or
        # journal rows truncated after the last pin) — never "healthy".
        healthy = journal["intact"] and chain_ok and journal["untracked_rows"] == 0
        mode = (store.setting("execution_mode") or {}).get("mode", "wall")
        # Site-level chain events: coverage certs, digests, exports, disconnects —
        # the signed ledger's record of watching, summarizing, and consent.
        att_types: dict[str, int] = {}
        for r in all_receipts:
            if ":" in r.visit_id:
                rtype = r.payload.get("record_type") or "record"
                att_types[rtype] = att_types.get(rtype, 0) + 1
        # Revocation overlays the chain: integrity still verifies — this is
        # how many receipts sit inside a declared suspect window.
        revoked = revoked_issuer_keys(all_receipts)
        suspect_n = len(suspect_receipts(all_receipts, revoked=revoked))
        # The running server records its own posture at boot — a bare `attest
        # status` reports the deployment's truth, not this process's env.
        posture = store.setting("webhook_intake") or {}
        if posture.get("polling"):
            intake = "polling mode — webhook intake disabled"
        elif posture.get("armed"):
            intake = f"HMAC-verified, {posture.get('max_age_s', 3600)}s freshness window"
        elif posture:
            intake = "OFF — no signing key at last server boot; deliveries rejected 503"
        else:
            intake = "unknown — server has not booted since this field existed"
        # Key custody is what's on disk, not what env asks for — a dpapi blob
        # wrapped by a different user just fails unwrap; the files themselves
        # are the deployment's truth.
        key_path = settings.key_path
        if (key_path.parent / (key_path.name + ".kms.json")).exists():
            custody = "AWS KMS envelope"
        elif (key_path.parent / (key_path.name + ".dpapi")).exists():
            custody = "Windows DPAPI"
        elif key_path.exists():
            custody = "plaintext PEM"
        else:
            custody = "no key yet"
        # Issuer lineage from the signed chain itself: a rotated runtime still
        # verifies (the key_rotation receipt is the pivot), so distinct keys in
        # receipt order ARE the linked lineage when the chain is intact.
        issuers = list(dict.fromkeys(r.public_key for r in store.receipts()))
        issuer_count = len(issuers) if chain_ok else 0
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "healthy": healthy,
                        "store": str(db),
                        "mode": mode,
                        "journal": journal,
                        "chain": {"ok": chain_ok, "detail": chain_detail},
                        "stats": stats,
                        "queue": queue,
                        "webhook": posture or None,
                        "custody": custody,
                        "issuer_keys": issuer_count,
                        "revoked_issuers": revoked,
                        "suspect_receipts": suspect_n,
                        "attestations": att_types,
                    },
                    default=str,
                )
            )
            if not healthy:
                sys.exit(1)
            return
        print(f"store:    {db} ({mode} clock)")
        print(f"visits:   {stats['visits']['total']} ({by_state or 'none'})")
        print(f"receipts: {stats['receipts']['total']} — {chain_detail}")
        _pl = lambda n, w, p=None: f"{n} {(w if n == 1 else (p or w + 's'))}"  # noqa: E731
        intact = "intact" if journal["intact"] else "VIOLATED"
        line = f"journal:  {intact} — {_pl(journal['entries'], 'entry', 'entries')}"
        if journal.get("pinned_heads"):
            line += f", {journal['pinned_heads']} signature-pinned heads"
        if journal.get("unpinned_entries"):
            line += (
                f", {_pl(journal['unpinned_entries'], 'entry', 'entries')} "
                "not yet pinned (`attest anchor` to pin)"
            )
        if journal["untracked_rows"]:
            line += f", {journal['untracked_rows']} untracked rows (run `attest journal --baseline`)"
        if journal["mismatches"]:
            line += f", {len(journal['mismatches'])} mismatches"
        print(line)
        print(
            f"coverage: {_pl(stats['poll_observations'], 'poll observation')}, "
            f"{_pl(stats['coverage_events'], 'lifecycle event')}, "
            f"{_pl(stats['liveview_sessions'], 'live-view session')} on record"
        )
        if att_types:
            detail = ", ".join(f"{n} {t}" for t, n in sorted(att_types.items()))
            print(f"attestations: {detail}")
        print(f"reviews:  {stats['reviews']}, late events retained: {stats['late_events']}")
        print(f"inbox:    {queue if queue else 'empty'}")
        print(f"webhooks: {intake}")
        key_line = f"key:      {custody}"
        if issuer_count > 1:
            key_line += f" — {issuer_count} issuer keys linked via the signed rotation chain"
        print(key_line)
        if revoked:
            print(
                f"revoked:  {len(revoked)} issuer key(s) declared suspect — "
                f"{suspect_n} receipt(s) sit inside suspect windows"
            )
        print(f"status:   {'healthy' if healthy else 'ATTENTION — integrity check failed'}")
        if not healthy:
            sys.exit(1)
    finally:
        store.close()


def _doctor(args: argparse.Namespace) -> None:
    """Deployment preflight for the *configuration*, not the store: `status`
    audits journal and chain integrity; doctor checks the posture around it —
    the things an operator verifies before real traffic, each with its
    remediation. Exit 1 when any check fails, 0 with warnings."""
    import os
    import tempfile
    from zoneinfo import ZoneInfo

    from .instance import writer_held
    from .keycustody import _check_custody_combo, _check_stray_custody_artifact

    checks: list[tuple[str, str, str]] = []

    def add(level: str, name: str, detail: str) -> None:
        checks.append((level, name, detail))

    # --- authentication surfaces -------------------------------------------
    if settings.admin_token is None:
        add(
            "fail",
            "admin token",
            "unset — every private route returns 401. Set ATTEST_ADMIN_TOKEN (>=32 chars).",
        )
    else:
        add("ok", "admin token", "set — private surfaces are authenticated")
    if settings.ring_webhook_key:
        add(
            "ok",
            "webhook intake",
            f"armed — HMAC-verified, {settings.webhook_max_age_s}s freshness window",
        )
    elif settings.poll_history_seconds > 0:
        add(
            "warn",
            "webhook intake",
            "closed (no ATTEST_RING_WEBHOOK_KEY) — deliveries 503; ingestion relies "
            f"on history polling every {settings.poll_history_seconds}s",
        )
    else:
        add(
            "warn",
            "webhook intake",
            "closed (no ATTEST_RING_WEBHOOK_KEY) and polling disabled — nothing "
            "ingests. Set the key, or ATTEST_POLL_HISTORY_SECONDS for polling.",
        )
    # --- deployment posture -------------------------------------------------
    if settings.replay_mode:
        add(
            "fail",
            "replay mode",
            "ATTEST_REPLAY_MODE=true is a coordinated-demo posture — it must never "
            "reach a deployment; real events would record on a simulated clock.",
        )
    else:
        add("ok", "replay mode", "off — wall clock")
    try:
        ZoneInfo(settings.timezone)
        add("ok", "timezone", settings.timezone)
    except Exception:
        add("fail", "timezone", f"{settings.timezone!r} is not a valid IANA zone")
    host = urlsplit(settings.public_base_url).hostname or ""
    if urlsplit(settings.public_base_url).scheme != "https" and host not in (
        "127.0.0.1",
        "localhost",
        "::1",
    ):
        add(
            "warn",
            "public base URL",
            f"{settings.public_base_url} is plain HTTP on a routable host — "
            "link URLs go out over the wire; terminate TLS in front.",
        )
    else:
        add("ok", "public base URL", settings.public_base_url)
    # --- signing-key custody -------------------------------------------------
    key_path = settings.key_path
    try:
        _check_custody_combo(settings.kms_key_id, settings.key_custody)
        _check_stray_custody_artifact(key_path, settings.kms_key_id, settings.key_custody)
    except (ValueError, RuntimeError) as exc:
        add("fail", "key custody", str(exc))
    else:
        kms_blob = key_path.parent / (key_path.name + ".kms.json")
        dpapi_blob = key_path.parent / (key_path.name + ".dpapi")
        if kms_blob.exists():
            add("ok", "key custody", "AWS KMS envelope — unwrap needs a live Decrypt")
        elif dpapi_blob.exists():
            add("ok", "key custody", "Windows DPAPI — bound to this user and machine")
        elif key_path.exists():
            add(
                "warn",
                "key custody",
                "plaintext PEM — set ATTEST_KMS_KEY_ID or ATTEST_KEY_CUSTODY=dpapi "
                "to wrap the issuer key at rest (wraps in place; identity keeps).",
            )
        else:
            add(
                "info",
                "key custody",
                "no key yet — first boot mints one under the configured posture",
            )
        if settings.key_custody == "dpapi" and os.name != "nt":
            add("fail", "key custody", "ATTEST_KEY_CUSTODY=dpapi requested on a non-Windows host")
    # --- filesystem + runtime ------------------------------------------------
    data_dir = settings.data_dir
    if data_dir.exists():
        try:
            with tempfile.NamedTemporaryFile(dir=data_dir, prefix=".doctor-", delete=True):
                pass
            add("ok", "data dir", f"{data_dir} writable")
        except OSError as exc:
            add("fail", "data dir", f"{data_dir} is not writable: {exc}")
    else:
        add("info", "data dir", f"{data_dir} does not exist — created on first boot")
    held, holder = writer_held(data_dir)
    if held:
        add(
            "info",
            "writer lock",
            f"held{(' by pid ' + str(holder)) if holder else ''} — a live server or "
            "writer command owns this runtime; offline writers will refuse, "
            "read-only commands still work",
        )
    if not settings.ring_media_origins.strip():
        add(
            "warn",
            "media origins",
            "ATTEST_RING_MEDIA_ORIGINS empty — no origin may serve media bytes; "
            "downloads fail closed until an allowlist is configured.",
        )
    if settings.rate_limit_webhook_per_min == 0 and settings.rate_limit_grant_per_min == 0:
        add(
            "warn",
            "rate limits",
            "both buckets disabled — the unauthenticated POST surfaces are "
            "unthrottled; an upstream limiter (nginx limit_req) must carry it.",
        )
    elif settings.rate_limit_webhook_per_min == 0 or settings.rate_limit_grant_per_min == 0:
        add(
            "info",
            "rate limits",
            f"webhook {settings.rate_limit_webhook_per_min}/min, grants "
            f"{settings.rate_limit_grant_per_min}/min — one surface unthrottled; "
            "cover it upstream or it accepts unlimited floods",
        )
    else:
        add(
            "ok",
            "rate limits",
            f"webhook {settings.rate_limit_webhook_per_min}/min, grants "
            f"{settings.rate_limit_grant_per_min}/min per client IP",
        )
    db = data_dir / "attest.sqlite3"
    add(
        "info",
        "runtime store",
        "present — `attest status` audits journal + receipt chain"
        if db.exists()
        else "absent — first boot mints it",
    )
    if settings.summarizer == "bedrock":
        add(
            "info",
            "summarizer",
            f"Bedrock {settings.bedrock_model_id} in {settings.aws_region} — needs "
            "credentials and on-demand quota at request time; falls back to template",
        )

    fails = sum(1 for level, _, _ in checks if level == "fail")
    warns = sum(1 for level, _, _ in checks if level == "warn")
    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "ready": fails == 0,
                    "checks": [
                        {"level": level, "check": name, "detail": detail} for level, name, detail in checks
                    ],
                },
                indent=2,
            )
        )
    else:
        mark = {"ok": " ok ", "info": "info", "warn": "WARN", "fail": "FAIL"}
        for level, name, detail in checks:
            print(f" {mark[level]} {name:<17} {detail}")
        print()
        print(f"deployment readiness: {fails} failed, {warns} warning(s)")
    if fails:
        sys.exit(1)


def _export(args: argparse.Namespace) -> None:
    """Write a case pack for a site straight from the store — no server needed."""
    from pathlib import Path

    from .disputepack import build_case_pack
    from .instance import acquire_instance_lock
    from .models import ReviewBundle
    from .reviews import countersign_status

    store = _must_store()
    acquire_instance_lock(settings.data_dir)  # export signs a case_export receipt
    try:
        site = store.site(args.site) if args.site else (store.sites()[0] if store.sites() else None)
        if site is None:
            sys.exit("no site found — seed or run a replay first")
        entries = []
        for visit in store.visits(site_id=site.id, limit=10_000):
            receipt = store.receipt_for_visit(visit.id)
            if receipt is None:
                continue  # open visits have no signed record to export
            bundle = ReviewBundle(original=receipt, reviews=store.reviews_for(visit.id))
            entries.append((visit, bundle, countersign_status(bundle)))
        if not entries:
            sys.exit(f"no signed records for {site.name} yet")
        engine = _cli_engine(store)
        data = build_case_pack(
            store,
            settings.data_dir / "media",
            site,
            entries,
            redact_media=args.redact_media,
            manifest_signer=lambda m: engine.issue_export_manifest(site, m),
            issuer_key=engine.signer.public_key_b64,
        )
        out = Path(args.out or f"case-{site.id}.zip")
        out.write_bytes(data)
        note = " (media withheld — digests preserved)" if args.redact_media else ""
        print(f"wrote {out}{note} — {len(entries)} visit record(s); verify with `python verify_case.py .`")
        # Self-check before shipping: an export that doesn't verify is worse
        # than no export — catch a corrupted zip at write time, not at review.
        import io
        import zipfile

        from .app import _verify_case_pack

        with zipfile.ZipFile(io.BytesIO(data)) as z:
            ok, why = _verify_case_pack(z, engine.signer.public_key_b64)
        if ok:
            print("self-check: pack verifies under this deployment's issuer key")
        else:
            print(f"WARNING: self-check failed — {why}", file=sys.stderr)
            sys.exit(2)
    finally:
        store.close()


def _attack_demo(args: argparse.Namespace) -> None:
    """Adversarial self-test: real tamper attempts, each caught then rolled back."""
    from .attackdemo import run
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db} — run `attest replay home_aide_visit` first")
    from .instance import acquire_instance_lock

    acquire_instance_lock(settings.data_dir)
    store = Store(db)
    # The webhook inbox is a separate database — the delivery-id conflict
    # attack needs it, and the refused write leaves nothing to roll back.
    inbox = None
    inbox_path = settings.data_dir / "webhooks.sqlite3"
    if inbox_path.exists():
        from .inbox import WebhookInbox

        inbox = WebhookInbox(inbox_path)
    try:
        out = run(store, settings.data_dir / "media", inbox=inbox)
        if out.get("baseline_note"):
            print(out["baseline_note"])
        caught = skipped = 0
        for r in out["results"]:
            mark = "SKIPPED" if r["caught"] is None else ("CAUGHT " if r["caught"] else "MISSED ")
            skipped += r["caught"] is None
            caught += r["caught"] is True
            print(f"{mark} {r['attack']}\n        {r['detail']}")
        attempted = len(out["results"]) - skipped
        suffix = f" — {skipped} not applicable on this store" if skipped else ""
        print(
            f"{caught}/{attempted} attacks caught{suffix} — "
            f"store {'unchanged' if out['unchanged'] else 'CHANGED (investigate)'}"
        )
        if not out["unchanged"]:
            sys.exit(1)
    finally:
        store.close()
        if inbox is not None:
            inbox.close()


def _diff(args: argparse.Namespace) -> None:
    """Compare two exports (case pack, dispute pack, or bundle.json) — append-only
    drift is normal; vanished or altered records are anomalies."""
    import zipfile

    from .models import Receipt
    from .packdiff import diff

    key = args.key
    extra: list | None = None
    if getattr(args, "issuer_url", None):
        doc = _fetch_issuer_doc(args.issuer_url)
        key = doc["issuer_key"]
        try:
            extra = [Receipt.model_validate(r) for r in doc.get("key_receipts") or []]
        except Exception as exc:  # noqa: BLE001
            sys.exit(f"issuer document carried malformed key receipts: {exc}")
        print(
            f"pinned to issuer key served by {args.issuer_url} "
            f"({len(extra)} lifecycle receipt(s)) — authenticity rides on transport"
        )

    try:
        if getattr(args, "json", False):
            import json as _json

            from .packdiff import diff_report

            report = diff_report(args.old, args.new, key=key, extra_key_receipts=extra)
            print(_json.dumps(report, indent=2))
            sys.exit(0 if report["clean"] else 1)
        lines, anomalies = diff(args.old, args.new, key=key, extra_key_receipts=extra)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, zipfile.BadZipFile) as exc:
        sys.exit(f"cannot compare: {exc}")
    for line in lines:
        print(line)
    if anomalies:
        sys.exit(1)


def _deliveries(args: argparse.Namespace) -> None:
    from .inbox import WebhookInbox

    inbox_path = settings.data_dir / "webhooks.sqlite3"
    if not inbox_path.exists():
        sys.exit(f"no webhook inbox at {inbox_path}")
    inbox = WebhookInbox(inbox_path)
    try:
        if args.requeue:
            # Requeue mutates the durable inbox — hold the writer lock so a
            # requeue can't race a live server's claim cycle.
            from .instance import acquire_instance_lock

            acquire_instance_lock(settings.data_dir)
            print(json.dumps({"requeued": inbox.requeue(), "queue": inbox.counts()}))
        else:
            print(json.dumps({"counts": inbox.counts(), "entries": inbox.entries()}, indent=2))
    finally:
        inbox.close()


def _explain(args: argparse.Namespace) -> None:
    """Explain one record in human terms: every source's account side by side,
    the signed anchors, the review chain, and the derived stance — the visit
    page as text for people who live in a terminal."""
    from .corroborate import corroboration
    from .reviews import ReviewService, verify_bundle
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    store = Store(db)
    try:
        visit = store.visit(args.visit)
        if visit is None:
            _explain_attestation(store, args.visit, as_json=getattr(args, "json", False))
            return
        site = store.site(visit.site_id)
        schedule = store.schedule(visit.schedule_id) if visit.schedule_id else None
        evidence = store.evidence_for(visit.id)
        receipt = store.receipt_for_visit(visit.id)
        engine = _cli_engine(store)
        reviews = ReviewService(store, engine.signer, engine.clock)

        if getattr(args, "json", False):
            print(
                json.dumps(
                    _explain_report(store, visit, site, schedule, evidence, receipt, reviews),
                    indent=2,
                    default=str,
                )
            )
            return

        print(f"{visit.id} — {visit.state.value} at {site.name if site else visit.site_id}")
        if visit.has_observations:
            print(f"  observed {visit.arrived_at.isoformat()} -> {visit.last_activity_at.isoformat()}")
        elif visit.arrived_at:
            # no_observation records stamp the scheduled window bounds — say so
            print(
                f"  scheduled window {visit.arrived_at.isoformat()} -> {visit.last_activity_at.isoformat()}"
            )
            print("  no device observations were received in that window")
        for f in visit.flags:
            print(f"  review note: {f.code} ({f.severity})")
        print()
        print("Source-by-source:")
        for row in corroboration(visit, site, schedule, evidence, receipt):
            detail = f" — {row['detail']}" if row["detail"] else ""
            print(f"  {row['source']:<28} {row['status']}{detail}")
            print(f"  {'':<28} ({row['establishes']})")
        print()
        if receipt:
            print(f"Signed receipt {receipt.id} · seq {receipt.sequence} · {receipt.payload_hash[:16]}…")
            digests = [
                e["media_sha256"] for e in receipt.payload.get("evidence", []) if e.get("media_sha256")
            ]
            if digests:
                print(f"  media digests signed: {len(digests)}")
            interruptions = (receipt.payload.get("history_poll_coverage") or {}).get("interruptions") or []
            if interruptions:
                print("  lifecycle signed into coverage:")
                for i in interruptions:
                    dev = f" ({i['device_id']})" if i.get("device_id") else " (account)"
                    print(f"    {i['at']} — {i['kind'].replace('_', ' ')}{dev}")
            live = (receipt.payload.get("history_poll_coverage") or {}).get("live_sessions") or []
            if live:
                print("  live-view sessions signed into coverage:")
                for s in live:
                    end = s["closed_at"] or "still open when signed"
                    print(f"    {s['opened_at']} -> {end} — stream established, viewership not shown")
        else:
            print("No signed receipt — record still open.")
        bundle = reviews.bundle(visit.id) if receipt else None
        if bundle:
            ok, why = verify_bundle(
                bundle, trusted_keys=reviews.trusted_issuer_keys(bundle.original.public_key)
            )
            print(f"Review chain: {'OK' if ok else 'FAILED'} — {why}")
            for r in bundle.reviews:
                rv = r.receipt.payload["review"]
                actor = r.receipt.payload["actor"]
                label = (
                    f"resolution: {rv['outcome'].replace('_', ' ')}"
                    if rv.get("kind") == "resolution"
                    else f"household account: {rv.get('perception', '').replace('_', ' ')}"
                    if rv.get("kind") == "household_account"
                    else rv.get("decision", "statement")
                )
                reason = f" — reason {rv['reason_code']} (stated)" if rv.get("reason_code") else ""
                print(f"  rev {r.revision}: {label} — {actor.get('name', '?')} ({actor.get('role')}){reason}")
            status = reviews.countersign(visit.id)
            print(f"Derived stance: {status['state']} — {status['detail']}")
        attestations = [
            r
            for r in store.receipts()
            if r.visit_id == f"source:{visit.site_id}"
            or r.visit_id.startswith(f"coverage:{visit.site_id}:")
            or r.visit_id.startswith(f"digest:{visit.site_id}:")
            or r.visit_id.startswith(f"export:{visit.site_id}:")
        ]
        if attestations:
            print()
            print(f"Site attestations ({len(attestations)} signed chain event(s)):")
            for r in attestations:
                rtype = r.payload.get("record_type", "record")
                spans = ""
                cov = r.payload.get("coverage") or {}
                window = cov.get("window") or {}
                if rtype == "coverage_attestation" and visit.arrived_at:
                    # Compare as datetimes — the signed window stores the
                    # caller's ISO verbatim, so a "-07:00" offset would sort
                    # wrong as a string against UTC.
                    try:
                        ws = datetime.fromisoformat(window.get("start", ""))
                        we = datetime.fromisoformat(window.get("end", ""))
                        spans = " — spans this visit's window" if ws <= visit.arrived_at <= we else ""
                    except ValueError:
                        spans = ""
                print(f"  {rtype:<22} {r.payload_hash[:16]}…{spans}")
        print()
        print("Boundary: sources establish what they reported; the signature proves")
        print("the record is intact — never identity, attendance, or physical truth.")
    finally:
        store.close()


def _explain_report(store, visit, site, schedule, evidence, receipt, reviews) -> dict:
    """The explain narrative as structured data — same sources, same derived
    stance, same boundary. `attest explain --json` feeds scripted evaluation."""
    from .corroborate import corroboration
    from .reviews import verify_bundle

    bundle = reviews.bundle(visit.id) if receipt else None
    out: dict = {
        "visit_id": visit.id,
        "state": visit.state.value,
        "site": site.name if site else visit.site_id,
        "site_id": visit.site_id,
        "scheduled_window": (
            {"start": schedule.window_start, "end": schedule.window_end} if schedule else None
        ),
        "observed": (
            {"first": visit.arrived_at, "last": visit.last_activity_at} if visit.has_observations else None
        ),
        "worker_check_in": visit.checked_in_at,
        "flags": [{"code": f.code, "severity": f.severity, "message": f.message} for f in visit.flags],
        "sources": corroboration(visit, site, schedule, evidence, receipt),
        "receipt": None,
        "review_chain": None,
        "stance": None,
        "attestations": [],
        "boundary": (
            "sources establish what they reported; the signature proves the record "
            "is intact — never identity, attendance, or physical truth"
        ),
    }
    if receipt:
        cov = receipt.payload.get("history_poll_coverage") or {}
        out["receipt"] = {
            "id": receipt.id,
            "sequence": receipt.sequence,
            "payload_hash": receipt.payload_hash,
            "media_digests": [
                e["media_sha256"] for e in receipt.payload.get("evidence", []) if e.get("media_sha256")
            ],
            "coverage_interruptions": cov.get("interruptions") or [],
            "live_sessions": cov.get("live_sessions") or [],
        }
    if bundle:
        ok, why = verify_bundle(bundle, trusted_keys=reviews.trusted_issuer_keys(bundle.original.public_key))
        out["review_chain"] = {
            "verified": ok,
            "detail": why,
            "entries": [
                {
                    "revision": r.revision,
                    "kind": r.receipt.payload["review"].get("kind"),
                    "role": r.receipt.payload["actor"].get("role"),
                    "actor": r.receipt.payload["actor"].get("name"),
                    "outcome": r.receipt.payload["review"].get("outcome"),
                    "decision": r.receipt.payload["review"].get("decision"),
                    "perception": r.receipt.payload["review"].get("perception"),
                    "reason_code": r.receipt.payload["review"].get("reason_code"),
                    "reason_basis": r.receipt.payload["review"].get("reason_basis"),
                    "payload_hash": r.receipt.payload_hash,
                }
                for r in bundle.reviews
            ],
        }
        out["stance"] = reviews.countersign(visit.id)

    def _spans(r) -> bool:
        """Does this coverage attestation's signed window cover the visit's
        first observation? Compare as datetimes — the payload stores the
        caller's ISO verbatim, offsets included."""
        cov = (r.payload.get("coverage") or {}).get("window") or {}
        if r.payload.get("record_type") != "coverage_attestation" or not visit.arrived_at:
            return False
        try:
            return (
                datetime.fromisoformat(cov["start"]) <= visit.arrived_at <= datetime.fromisoformat(cov["end"])
            )
        except (KeyError, ValueError):
            return False

    out["attestations"] = [
        {
            "receipt_id": r.id,
            "visit_id": r.visit_id,
            "record_type": r.payload.get("record_type"),
            "payload_hash": r.payload_hash,
            "spans_visit_window": _spans(r),
        }
        for r in store.receipts()
        if r.visit_id == f"source:{visit.site_id}"
        or r.visit_id.startswith(f"coverage:{visit.site_id}:")
        or r.visit_id.startswith(f"digest:{visit.site_id}:")
        or r.visit_id.startswith(f"export:{visit.site_id}:")
    ]
    return out


def _explain_attestation(store, ident: str, *, as_json: bool = False) -> None:
    """Narrate a site-level chain event (coverage cert, digest, export,
    disconnect) by pseudo visit_id or receipt id — same honesty rules."""
    from .ledger import verify_receipt

    receipt = store.receipt_for_visit(ident)
    if receipt is None:
        receipt = next((r for r in store.receipts() if r.id == ident), None)
    if receipt is None:
        sys.exit(f"no visit or attestation {ident}")
    ok, why = verify_receipt(receipt, public_key=receipt.public_key)
    p = receipt.payload
    rtype = p.get("record_type", "record")
    if as_json:
        print(
            json.dumps(
                {
                    "receipt_id": receipt.id,
                    "visit_id": receipt.visit_id,
                    "record_type": rtype,
                    "sequence": receipt.sequence,
                    "payload_hash": receipt.payload_hash,
                    "issued_at": receipt.issued_at,
                    "issuer_key": receipt.public_key,
                    "signature": {"verified": ok, "detail": why},
                    "payload": p,
                    "boundary": (
                        "sources establish what they reported; the signature proves the "
                        "record is intact — never identity, attendance, or physical truth"
                    ),
                },
                indent=2,
                default=str,
            )
        )
        return
    print(f"{receipt.id} — {rtype} · seq {receipt.sequence} · {receipt.payload_hash[:16]}…")
    print(f"  signature: {'OK' if ok else 'FAILED'} — {why}")
    print(f"  issued {receipt.issued_at.isoformat()} · under issuer key {receipt.public_key[:16]}…")
    if rtype == "coverage_attestation":
        cov = p.get("coverage", {})
        w = cov.get("window", {})
        print(f"  window {w.get('start')} -> {w.get('end')}")
        print(
            f"  watched {cov.get('fraction', 0) * 100:.0f}% of it — "
            f"{cov.get('polls')} poll(s), {cov.get('events')} event(s), "
            f"{len(cov.get('gaps', []))} gap(s) — silence is not absence"
        )
        interruptions = cov.get("interruptions") or []
        if interruptions:
            print(f"  lifecycle interruptions signed in: {', '.join(i['kind'] for i in interruptions)}")
        live = cov.get("live_sessions") or []
        if live:
            print(
                f"  live-view sessions signed in: {len(live)} — stream(s) established, viewership not shown"
            )
        explained = sum(1 for g in cov.get("gaps", []) if g.get("explained"))
        if explained:
            print(f"  {explained} gap(s) carry a recorded cause — context, never absence")
    elif rtype == "period_digest":
        i = p.get("interval", {})
        c = p.get("counts", {})
        print(f"  interval {i.get('start')} -> {i.get('end')}")
        print(
            f"  {c.get('visits_observed', 0)} observed · {c.get('visits_no_observation', 0)} "
            f"no-observation · {c.get('worker_disputes', 0)} dispute(s) · "
            f"{c.get('coordinator_resolutions', 0)} resolution(s) · "
            f"{c.get('liveview_sessions', 0)} live session(s) — counts of signed records"
        )
    elif rtype == "source_disconnected":
        print(f"  disconnected {p.get('disconnected_at')} — {p.get('reason') or 'no reason given'}")
        dev = p.get("devices", {})
        print(f"  devices unbound: {', '.join(v for v in dev.values() if v) or 'none'}")
        print("  ingestion and polling stopped; the signed history stays intact")
    elif rtype == "case_export":
        n = len(p.get("receipt_hashes", {}))
        print(f"  export manifest pins {n} record(s), sha256 {str(p.get('manifest_sha256'))[:16]}…")
    elif rtype == "verification_report":
        print(f"  official-API sweep — {p.get('base_url')} · {p.get('generated_at')}")
        for c in p.get("checks", []):
            print(f"    {c.get('status', '?').upper():<5} {c.get('check')}: {c.get('detail')}")
        s = p.get("summary", {})
        print(
            f"  {s.get('pass', 0)} pass · {s.get('fail', 0)} fail · "
            f"{s.get('warn', 0)} warn · {s.get('skip', 0)} skip — "
            "only PASS is verified evidence"
        )
    elif rtype == "key_rotation":
        print(
            f"  {str(p.get('previous_key'))[:16]}… retires, endorsing "
            f"{str(p.get('new_key'))[:16]}… — the chain's trust pivot"
        )
        if p.get("reason"):
            print(f"  stated reason: {p['reason']} (unverified, like all stated facts)")
        print("  receipts before this pivot verify under the retiring key;")
        print("  later receipts verify under the successor. This proves a")
        print("  signed handoff — never that either key was uncompromised.")
    elif rtype == "key_adoption":
        link = p.get("rotation_receipt") or {}
        print(
            f"  successor {str(p.get('new_key') or receipt.public_key)[:16]}… countersigns "
            f"the rotation {str(link.get('id'))[:16]}…"
        )
        print("  proof the new key holder accepted the handoff — consent,")
        print("  not physical possession by an identified person.")
    elif rtype == "key_revocation":
        print(
            f"  issuer declares {str(p.get('revoked_key'))[:16]}… compromised — "
            f"its signatures are suspect for records after {p.get('suspect_after')}"
        )
        if p.get("reason"):
            print(f"  stated reason: {p['reason']} (unverified, like all stated facts)")
        print("  a trust annotation, not an erasure: the records still verify;")
        print("  verifiers weight them as suspect-window signatures.")
    print()
    print("Boundary: a signature attests what the record claims and that it is")
    print("intact under the issuer key — never identity, attendance, or truth.")


def _retention(args: argparse.Namespace) -> None:
    """Print a non-destructive lifecycle report for the local runtime. Deletes nothing."""
    from . import retention
    from .inbox import WebhookInbox

    policy = retention.RetentionPolicy(
        visits_days=settings.retention_visits_days,
        media_days=settings.retention_media_days,
        deliveries_days=settings.retention_deliveries_days,
        grants_days=settings.retention_grants_days,
        seen_days=settings.retention_seen_days,
        late_events_days=settings.retention_late_days,
        poll_observations_days=settings.retention_poll_days,
        coverage_events_days=settings.retention_coverage_days,
        liveview_sessions_days=settings.retention_liveview_days,
    )
    store = _must_store()
    inbox_path = settings.data_dir / "webhooks.sqlite3"
    inbox = WebhookInbox(inbox_path) if inbox_path.exists() else None
    media_dir = settings.data_dir / "media"
    try:
        if args.apply:
            try:
                # Purging rows is the one destructive write the CLI performs —
                # never run it while a server might be mid-transaction.
                from .instance import acquire_instance_lock

                acquire_instance_lock(settings.data_dir)
                result = retention.apply(store, inbox, media_dir, policy=policy, confirm=args.apply)
            except ValueError as exc:
                sys.exit(f"retention refused: {exc}")
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(retention.build_report(store, inbox, media_dir, policy=policy), indent=2))
    finally:
        store.close()
        if inbox is not None:
            inbox.close()


def _verify_live(args: argparse.Namespace) -> None:
    """Sweep the official API with a live token and print an evidence report."""
    from pathlib import Path

    from ring_sandbox import RingClient

    from . import verifylive

    token = args.token or settings.ring_access_token
    base = args.ring_url or settings.ring_base_url
    with RingClient(
        token,
        base_url=base,
        media_origins=[o.strip() for o in settings.ring_media_origins.split(",") if o.strip()],
    ) as ring:
        report = verifylive.run(ring, do_whep=not args.no_whep)

    if args.sign:
        from .store import Store

        db = settings.data_dir / "attest.sqlite3"
        if not db.exists():
            sys.exit("--sign needs a runtime store — run `attest serve` once first")
        from .instance import acquire_instance_lock

        acquire_instance_lock(settings.data_dir)
        store = Store(db)
        try:
            receipt = _cli_engine(store).issue_verification_report(report)
        finally:
            store.close()
        print(f"signed into the ledger as {receipt.id} (record_type=verification_report)")
        if args.out:
            Path(args.out).write_text(receipt.model_dump_json(indent=2), encoding="utf-8")
            print(f"wrote {args.out} — verify with `attest verify {args.out}`")
    elif args.out:
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"wrote {args.out}")
    icon = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}
    print(f"official-API verification — {report['generated_at']} — {report['base_url']}")
    for c in report["checks"]:
        print(f"  {icon.get(c['status'], '????')} {c['check']}: {c['detail']}")
    s = report["summary"]
    print(f"  {s['pass']} pass · {s['fail']} fail · {s['warn']} warn · {s['skip']} skip")
    print("Only checks marked PASS may be described as officially verified.")
    if s["fail"]:
        sys.exit(1)


def main(argv: list[str] | None = None) -> None:
    # Windows consoles default to cp1252 — em-dashes and ellipses in output
    # would crash mid-print. UTF-8 bytes degrade to mojibake there instead of
    # a UnicodeEncodeError, and stay correct when redirected to a file.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(
        prog="attest", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    from . import __version__

    p.add_argument("--version", action="version", version=f"attest {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=_serve)

    s = sub.add_parser(
        "retention", help="preview lifecycle candidates, or apply with the preview's apply_token"
    )
    s.add_argument(
        "--apply",
        metavar="TOKEN",
        default=None,
        help="delete the previewed non-chain candidates; must equal the current apply_token",
    )
    s.set_defaults(fn=_retention)

    s = sub.add_parser(
        "tamper-demo",
        help="forge a row inside a transaction and show the journal catching it (rolls back)",
    )
    s.set_defaults(fn=_tamper_demo)

    s = sub.add_parser("journal", help="verify the hash-chained mutation journal")
    s.add_argument(
        "--baseline",
        action="store_true",
        help="stamp all existing rows as the audit baseline (one-time, explicit)",
    )
    s.set_defaults(fn=_journal)

    s = sub.add_parser("status", help="self-audit the local store: journal, receipt chain, coverage, inbox")
    s.add_argument("--json", action="store_true", help="emit the audit as a single JSON object")
    s.set_defaults(fn=_status)

    s = sub.add_parser(
        "doctor",
        help="deployment preflight — grades configuration posture (auth, custody, "
        "TLS, replay mode, writer lock) with remediation; exit 1 on any failure",
    )
    s.add_argument("--json", action="store_true", help="emit the checks as a single JSON object")
    s.set_defaults(fn=_doctor)

    s = sub.add_parser("verify", help="verify a downloaded bundle.json offline")
    s.add_argument(
        "bundle",
        help="bundle.json, receipt, anchor, receipts.json, a pack .zip — or an http(s) URL to one",
    )
    g = s.add_mutually_exclusive_group()
    g.add_argument("--key", default=None, help="issuer public key (base64) to pin against")
    g.add_argument(
        "--issuer-url",
        default=None,
        metavar="URL_OR_FILE",
        help="pin to the issuer key served by <url>/.well-known/attest-issuer.json "
        "(HTTPS; loopback excepted) or an issuer document file written by "
        "`attest issuer --out` — the deployment's signed lifecycle extends "
        "trust to pre-rotation packs",
    )
    s.set_defaults(fn=_verify)

    s = sub.add_parser(
        "export", help="write a site case pack (all signed visits + media + verifier) to a zip"
    )
    s.add_argument("--site", default=None, help="site id (defaults to the only site)")
    s.add_argument("--out", default=None, help="output path (default case-<site>.zip)")
    s.add_argument(
        "--redact-media",
        action="store_true",
        help="withhold media bytes; signed digests are preserved and the verifier reports them withheld",
    )
    s.set_defaults(fn=_export)

    s = sub.add_parser(
        "attack-demo",
        help="run real tamper attempts (forge, delete, truncate, key swap, replay, media swap), "
        "all rolled back",
    )
    s.set_defaults(fn=_attack_demo)

    s = sub.add_parser(
        "diff",
        help="compare two exports — appended records are normal; vanished or altered ones are anomalies",
    )
    s.add_argument("old", help="earlier export: case pack, pack.zip, or bundle.json")
    s.add_argument("new", help="later export")
    g = s.add_mutually_exclusive_group()
    g.add_argument(
        "--key",
        help="trusted issuer public key (base64) — verify against this, not the pack's self-declared key",
    )
    g.add_argument(
        "--issuer-url",
        default=None,
        metavar="URL_OR_FILE",
        help="pin to the issuer key served by <url>/.well-known/attest-issuer.json "
        "(HTTPS; loopback excepted) or an issuer document file written by "
        "`attest issuer --out` — the deployment's signed lifecycle extends "
        "trust to pre-rotation exports",
    )
    s.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable report (severity/target/detail per event) — "
        "exit 1 on any anomaly, so the append-only audit can gate CI",
    )
    s.set_defaults(fn=_diff)

    s = sub.add_parser(
        "anchor",
        help="write a signed anchor pinning the journal head + receipt chain head — publish it anywhere",
    )
    s.add_argument("--out", default=None, help="output path (default attest-anchor.json)")
    s.add_argument(
        "--publish",
        default=None,
        metavar="s3://bucket/key",
        help="also upload the anchor to S3 — external custody for the checkpoint",
    )
    s.add_argument(
        "--timestamp",
        action="store_true",
        help="also notarize the anchor on public OpenTimestamps calendars (writes FILE.ots)",
    )
    s.set_defaults(fn=_anchor)

    s = sub.add_parser(
        "stamp",
        help="notarize any file's digest via OpenTimestamps — 'existed before this Bitcoin block'",
    )
    s.add_argument("file", help="file to stamp (or the FILE.ots to upgrade)")
    s.add_argument(
        "--upgrade",
        action="store_true",
        help="refresh a pending .ots proof once the calendar has committed to Bitcoin",
    )
    s.set_defaults(fn=_stamp)

    s = sub.add_parser(
        "coverage",
        help="sign a coverage attestation for an interval — 'checked K times, saw M events', never absence",
    )
    s.add_argument("--site", default=None, help="site id (defaults to the only site)")
    s.add_argument("--from", dest="start", required=True, help="interval start (ISO 8601, tz-aware)")
    s.add_argument("--to", dest="to", required=True, help="interval end (ISO 8601, tz-aware)")
    s.set_defaults(fn=_coverage_cert)

    s = sub.add_parser(
        "digest",
        help="sign a period digest — counts of the records written, linked to every receipt summarized",
    )
    s.add_argument("--site", default=None, help="site id (defaults to the only site)")
    s.add_argument("--from", dest="start", required=True, help="interval start (ISO 8601, tz-aware)")
    s.add_argument("--to", dest="to", required=True, help="interval end (ISO 8601, tz-aware)")
    s.set_defaults(fn=_digest)

    s = sub.add_parser(
        "rotate-key",
        help="retire the signing key — the old key signs a key_rotation attestation "
        "endorsing its successor, the successor lands under the same custody "
        "(plaintext, KMS, or DPAPI) and signs a key_adoption receipt; history stays "
        "verifiable through the pivot",
    )
    s.add_argument("--reason", default="", help="why the key is being rotated (signed into the receipt)")
    s.set_defaults(fn=_rotate_key)

    s = sub.add_parser(
        "revoke-key",
        help="declare a prior issuer key's signatures suspect after an instant — "
        "signed under the live key (rotate away from a compromised key first); "
        "records still verify, verifiers annotate the suspect window",
    )
    s.add_argument("key", help="base64 public key to revoke — must already exist in this chain's history")
    s.add_argument(
        "--suspect-after",
        help="ISO 8601 instant; the key's signatures after it are declared suspect "
        "(default: the key's first signed receipt — compromise timing is unknowable)",
    )
    s.add_argument("--reason", default="", help="incident note signed into the receipt")
    s.set_defaults(fn=_revoke_key)

    s = sub.add_parser(
        "issuer",
        help="write the issuer-discovery document (same doc as "
        "/.well-known/attest-issuer.json) — pin packs to this deployment "
        "with `attest verify pack.zip --issuer-url <doc-or-url>`",
    )
    s.add_argument("--out", default=None, help="write the document here (default: stdout)")
    s.set_defaults(fn=_issuer)

    s = sub.add_parser(
        "triage",
        help="agentic weekly triage — a Strands agent reads the ledger via tools, or a deterministic brief",
    )
    s.set_defaults(fn=_triage)

    s = sub.add_parser(
        "explain",
        help="explain one record in human terms — every source's account, anchors, and stance",
    )
    s.add_argument(
        "visit",
        help="visit id, or an attestation (coverage:/digest:/export:/source: pseudo id, or receipt id)",
    )
    s.add_argument("--json", action="store_true", help="emit the same account machine-readable")
    s.set_defaults(fn=_explain)

    s = sub.add_parser("deliveries", help="show durable webhook inbox state, or requeue failed deliveries")
    s.add_argument(
        "--requeue",
        action="store_true",
        help="move all failed deliveries back to pending with a fresh attempt budget",
    )
    s.set_defaults(fn=_deliveries)

    s = sub.add_parser(
        "verify-live",
        help="one fresh Ring token in, a timestamped official-API evidence report out",
    )
    s.add_argument("--token", default=None, help="access token (default ATTEST_RING_ACCESS_TOKEN)")
    s.add_argument("--ring-url", default=None, help="API base (default ATTEST_RING_BASE_URL)")
    s.add_argument("--out", default=None, help="also write the report JSON here")
    s.add_argument(
        "--sign",
        action="store_true",
        help="chain the report into the runtime ledger as a verification_report "
        "receipt; --out then writes the signed receipt (`attest verify` checks it)",
    )
    s.add_argument(
        "--no-whep",
        action="store_true",
        help="skip the WHEP open/close probe (it creates a real on-demand session)",
    )
    s.set_defaults(fn=_verify_live)

    _HELP = {
        "seed": "seed a demo site + schedule + worker against a Ring sandbox",
        "demo": "one command: in-process sandbox + server + a seeded story week + live dashboard",
        "replay": "drive a scenario (builtin or YAML) through the webhook path on a replay clock",
    }
    for name, fn in (("seed", _seed), ("demo", _demo), ("replay", _replay)):
        s = sub.add_parser(name, help=_HELP[name])
        s.add_argument("--ring-url", default=settings.ring_base_url)
        s.add_argument("--public-url", default=settings.public_base_url)
        s.add_argument("--site-name", default="Alvarez residence")
        s.add_argument("--worker-name", default="Maria Chen")
        s.add_argument("--window-minutes", type=int, default=120)
        s.add_argument("--expected-minutes", type=int, default=90)
        s.add_argument("--camera-only", action="store_true", help="leave the optional contact sensor unbound")
        if name in ("demo", "replay"):
            s.add_argument(
                "--rotate-day",
                type=int,
                default=None,
                metavar="K",
                help="on story day K rotate the signing key live via the admin "
                "endpoint — receipts on both sides verify through the signed pivot",
            )
            s.add_argument(
                "--revoke-day",
                type=int,
                default=None,
                metavar="K",
                help="on story day K run the compromise drill — rotate to a fresh key "
                "and revoke the retired one, so its whole output reports suspect "
                "while every record still verifies",
            )
        if name == "demo":
            s.add_argument(
                "--port",
                type=int,
                default=0,
                help="port for the demo dashboard (default: random)",
            )
            s.add_argument(
                "--data-dir",
                default=None,
                help="persist the demo runtime here (must be empty); default is a temp dir",
            )
            s.add_argument("--days", type=int, default=8)
            s.add_argument(
                "--story",
                default="observed,late,blackout,sub_lapse,no_show,early_out,unmatched,liveview",
                metavar="PATTERNS",
                help="day-pattern cycle: observed,late,blackout,sub_lapse,early_out,no_show,"
                "unmatched,liveview",
            )
            s.add_argument("--speed", type=float, default=10000)
            s.add_argument(
                "--chaos",
                action="store_true",
                help="inject webhook duplication + delivery jitter into the emulator "
                "(dedupe must hold; drops stay off so the story can't change)",
            )
            s.add_argument(
                "--open",
                action="store_true",
                help="open the authenticated dashboard in the default browser once live",
            )
            s.add_argument(
                "--lan",
                action="store_true",
                help="bind the demo on all interfaces and print the LAN URL — "
                "a phone on the same network can scan the door-step QR for real",
            )
        if name == "replay":
            s.add_argument(
                "scenario",
                help="a ring_sandbox scenario name — built-in (home_aide_visit, short_visit, "
                "no_show, device_flap, camera_only_visit, delivery) or wheel-shipped example "
                "(late_arrival, partial_blackout, visitor_not_worker) — or a .yml/.yaml file",
            )
            s.add_argument("--speed", type=float, default=60)
            s.add_argument(
                "--auto-checkin", action="store_true", help="simulate a worker self-report locally"
            )
            s.add_argument(
                "--days",
                type=int,
                default=1,
                help="repeat the scenario over N consecutive daily schedules",
            )
            s.add_argument(
                "--no-show-day",
                type=int,
                default=None,
                metavar="K",
                help="0-based day index where no events play — the schedule lapses to no_observation",
            )
            s.add_argument(
                "--worker-review",
                choices=("confirm", "dispute"),
                default=None,
                help="auto-post a worker review on the final observed visit",
            )
            s.add_argument(
                "--story",
                default=None,
                metavar="PATTERNS",
                help="comma list cycled across --days: observed,late,blackout,early_out,no_show,"
                "unmatched,sub_lapse,liveview "
                "(e.g. --days 5 --story observed,late,no_show,early_out,observed)",
            )
        s.set_defaults(fn=fn)

    args = p.parse_args(argv)
    from .store import StoreCorrupt

    try:
        args.fn(args)
    except (StoreCorrupt, OSError, ValueError) as exc:
        # Fail closed with an error line, never a traceback — the surfaces that
        # report "valid/invalid" must never crash ambiguously. StoreCorrupt is
        # the store's own fail-closed signal; ValueError covers malformed
        # artifact JSON (pydantic), bad --from/--to dates, and missing files
        # the subcommand didn't phrase for a human.
        sys.exit(f"attest: {exc}")


if __name__ == "__main__":
    main()
