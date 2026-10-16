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

from . import transparency
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
    # The admin token rides every request below — it must never leave in
    # cleartext to a non-local target. Loopback HTTP is the dev path;
    # anything else requires HTTPS.
    try:
        parsed = urlsplit(args.public_url)
    except ValueError:
        sys.exit(f"malformed --public-url {args.public_url!r}")
    if (
        parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1")
    ) or parsed.scheme not in ("http", "https"):
        sys.exit(
            "seed sends admin credentials — --public-url must be HTTPS, "
            "or loopback HTTP for local development"
        )
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
    if not settings.webhook_signing_key:
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
            "late_delivery",
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
            elif pattern == "late_delivery":
                # Nothing arrives inside the window — it lapses to
                # no_observation at the final sweep; the buffered webhook that
                # only delivers AFTER that is posted below (post-sweep), where
                # it lands as a late event AND flags the lapsed record
                # contradicted_no_observation.
                steps = []
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
                        webhooks.SIGNATURE_HEADER: webhooks.sign(settings.webhook_signing_key, raw),
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
        if "late_delivery" in patterns:
            # The camera's motion webhook was buffered upstream and only
            # delivers now — its occurred_at sits INSIDE a window that already
            # lapsed to no_observation at the sweep above. The engine keeps it
            # as a late event and flags that signed record
            # contradicted_no_observation: the ledger admits when its own
            # earlier claim was contested.
            day_idx = patterns.index("late_delivery")
            if day_idx >= args.days:
                sys.exit(
                    "--story slots late_delivery at day "
                    f"{day_idx + 1} but --days is {args.days} — "
                    "that window never ran, so nothing lapsed to contradict"
                )
            late_at = start + timedelta(days=day_idx, minutes=5)
            response = sandbox.post(
                "/_sandbox/events",
                json={
                    "device_id": seeded["camera"],
                    "type": "motion_detected",
                    "sub_type": "human",
                    "at": late_at.isoformat(),
                    "deliver": False,
                },
            )
            response.raise_for_status()
            raw = webhooks.encode(response.json()["webhook"])
            api.post(
                "/webhooks/ring",
                content=raw,
                auth=None,
                headers={
                    "Content-Type": "application/json",
                    webhooks.SIGNATURE_HEADER: webhooks.sign(settings.webhook_signing_key, raw),
                },
            ).raise_for_status()
            drain(api)
            print(
                f"Late-delivered a motion event from {late_at.isoformat()} — the "
                "lapsed record now carries a contradicted_no_observation flag",
                flush=True,
            )
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
    settings.ring_webhook_key = SecretStr(webhook_key)
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
                svc = ReviewService(store, engine.signer, engine.clock)
                svc.household_statement(
                    family_token,
                    HouseholdStatementInput(
                        perception="no_one_seen",
                        statement=(
                            "My mother was home all morning and says the doorbell "
                            "never rang — nobody came to the door before ten."
                        ),
                    ),
                )
                # The household's own account contradicts itself — the product
                # thesis made literal: first nobody came, then somebody was
                # seen, and the garbled original plus its re-send both stay
                # signed on the chain (the U+FFFD is the "typo" — verbatim).
                svc.household_statement(
                    family_token,
                    HouseholdStatementInput(
                        perception="saw_someone",
                        statement=(
                            "I was home that afternoon � I heard the doorbell "
                            "a little after six and saw someone at the door. "
                            "I can't say how long she stayed."
                        ),
                    ),
                )
                svc.household_statement(
                    family_token,
                    HouseholdStatementInput(
                        perception="saw_someone",
                        statement=(
                            "I was home that afternoon; I heard the doorbell "
                            "a little after six and saw someone at the door. "
                            "I can't say how long she stayed. (Re-sending — "
                            "my earlier message had a garbled character.)"
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
        # worker dispute and household statements that just landed.
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
    print("     check-in landing ~65 min after the camera saw them. The household's", flush=True)
    print("     signed account contradicts itself — 'nobody came', then 'I heard the", flush=True)
    print("     doorbell', then a re-send a day later; the chain keeps all three.", flush=True)
    print("     'Conclude the record' signs the coordinator's call — coded reasons", flush=True)
    print("     classify the stated explanation, never a verified cause, and they", flush=True)
    print("     aggregate on the signed period digest.", flush=True)
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
    print(" 11. attest attack-demo — the tamper battery; 21 caught, 1 named", flush=True)
    print("     boundary (the unkeyed journal needs an external anchor)", flush=True)
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
    import os
    from pathlib import Path

    if "://" not in url and Path(url).is_file():
        try:
            raw = Path(url).read_bytes()
        except OSError as exc:
            sys.exit(f"issuer document unreadable: {exc}")
        if len(raw) > 4 * 1024 * 1024:
            sys.exit("issuer document exceeds the 4 MB bound")
        return _parse_issuer_doc(raw, url)
    if "://" not in url and (
        Path(url).suffix.lower() == ".json" or os.sep in url or (os.altsep and os.altsep in url)
    ):
        # Path-shaped input that doesn't exist — a mistyped local path fails
        # with a clear error instead of becoming a hostname lookup.
        sys.exit(f"issuer document not found: {url}")
    if "://" in url:
        base = urlsplit(url)
    else:
        # A schemeless loopback host (localhost:8080) means a plain-HTTP dev
        # server — forcing https would fail on TLS. The downgrade must happen
        # BEFORE the scheme check: urlsplit("https://…") always reads https,
        # so probing scheme first would leave this branch unreachable. Only
        # loopback gets the downgrade; remote hosts never do.
        probe = urlsplit(f"https://{url}")
        base = urlsplit(f"{'http' if _is_loopback(probe.hostname or '') else 'https'}://{url}")
    host = base.hostname or ""
    if base.scheme != "https" and not _is_loopback(host):
        sys.exit("issuer discovery requires HTTPS — loopback excepted for local verification")
    endpoint = f"{base.scheme}://{base.netloc}/.well-known/attest-issuer.json"
    stream_ctx = client.stream if client is not None else httpx.stream
    import time as _time

    deadline = _time.monotonic() + 30  # total wall-clock bound, not per-read
    try:
        with stream_ctx("GET", endpoint, timeout=15) as r:
            if r.status_code != 200:
                sys.exit(f"issuer discovery failed: HTTP {r.status_code} from {endpoint}")
            raw = bytearray()
            for chunk in r.iter_bytes(1 << 16):
                raw.extend(chunk)
                if len(raw) > 4 * 1024 * 1024:
                    sys.exit("issuer document exceeds the 4 MB bound")
                if _time.monotonic() > deadline:
                    sys.exit("issuer discovery timed out")
    except httpx.HTTPError as exc:
        sys.exit(f"issuer discovery failed: {exc}")
    except httpx.InvalidURL as exc:
        sys.exit(f"issuer discovery URL malformed: {exc}")
    return _parse_issuer_doc(raw, endpoint)


def _parse_issuer_doc(raw: bytes, source: str) -> dict:
    """JSON → a validated attest.issuer/1 dict — the shared shape check for
    the file and HTTP fetch paths. Anything else fails closed, never a
    traceback."""
    try:
        doc = transparency.json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        sys.exit(f"issuer document is not valid JSON: {exc}")
    if (
        not isinstance(doc, dict)
        or doc.get("schema") != "attest.issuer/1"
        or not isinstance(doc.get("issuer_key"), str)
        or not doc["issuer_key"]
    ):
        sys.exit(f"{source} did not serve a valid attest.issuer/1 document")
    if not isinstance(doc.get("key_receipts") or [], list):
        sys.exit(f"{source}: issuer document key_receipts is not a list")
    # The lineage walk verifies a signature per candidate per hop — bound
    # the pool the same way the witness endpoint does (64 entries is far
    # past any real lifecycle), so a hostile named deployment can't serve
    # a CPU denial-of-service amplifier as its identity document.
    if len(doc.get("key_receipts") or []) > 64:
        sys.exit(f"{source}: issuer document key_receipts exceeds the 64-entry bound")
    return doc


def _verify(args: argparse.Namespace) -> None:
    """Verify a downloaded artifact offline: review bundle, bare receipt, anchor,
    or a receipts.json export list."""
    from pathlib import Path

    from . import ledger, reviews
    from .models import Receipt, ReviewBundle

    json_mode = getattr(args, "json", False)

    def fail(detail: str, **kw) -> None:
        """Every verification verdict exits the same way on both surfaces —
        with --json stdout still carries exactly one object, so a pipeline
        can gate on .ok without parsing prose. The verdict emits BEFORE the
        badge write — a badge path that can't be written must never eat
        the machine-readable answer."""
        if json_mode:
            print(json.dumps({"ok": False, "detail": detail, **kw}, indent=2))
        _write_verdict_badge(
            getattr(args, "badge", None), False, detail, link=getattr(args, "badge_link", None)
        )
        if json_mode:
            sys.exit(1)
        sys.exit(detail)

    pinned_key = args.key
    known_rotations: list | None = None
    issuer_doc: dict | None = None
    live_base: str | None = None
    if getattr(args, "issuer_url", None):
        issuer_doc = _fetch_issuer_doc(args.issuer_url)
        pinned_key = issuer_doc["issuer_key"]
        try:
            known_rotations = [Receipt.model_validate(r) for r in issuer_doc.get("key_receipts") or []]
        except Exception as exc:  # noqa: BLE001
            fail(f"issuer document carried malformed key receipts: {exc}")
        # The pin note rides stderr in --json mode — stdout carries only the
        # machine-readable verdict (same discipline as `attest diff --json`).
        print(
            f"pinned to issuer key served by {args.issuer_url} "
            f"({len(known_rotations)} lifecycle receipt(s)) — authenticity rides on transport",
            file=sys.stderr if json_mode else sys.stdout,
        )
        if args.issuer_url.startswith(("http://", "https://")):
            live_base = urlsplit(args.issuer_url)._replace(path="", query="", fragment="").geturl()

    # Named-witness policy resolution: --witness-key names raw keys;
    # --witness-url names DEPLOYMENTS — each one's issuer document resolves
    # to its certified lineage, so "vouched by https://witness.example" means
    # the whole rotation-aware identity, not one frozen key. A witness that
    # can't be identified can't vouch — an unreachable doc fails loudly.
    required_witnesses: set[str] = set()
    witness_names: dict[str, str] = {}
    _revoked_known: set[str] = set()
    for _wurl in getattr(args, "witness_url", None) or []:
        from . import logmonitor as _lmw

        _wdoc = _fetch_issuer_doc(_wurl)
        _host = urlsplit(_wurl).netloc if "://" in _wurl else _wurl
        # A revoked lineage key can still SIGN — it just can't vouch: the
        # revocation is the issuer declaring the key suspect, so it is
        # excluded from the named requirement (windowing by the cosig's own
        # issued_at can't work — the suspect key signs that field too).
        _wreceipts = []
        for _x in _wdoc.get("key_receipts") or []:
            try:
                _wreceipts.append(Receipt.model_validate(_x))
            except Exception:  # noqa: BLE001 — malformed entries just can't revoke
                continue
        _wrevoked = set(ledger.revoked_issuer_keys(_wreceipts, issuer_key=_wdoc["issuer_key"]))
        _wtrusted = _lmw._trusted_set(_wdoc)
        _revoked_known |= _wrevoked & _wtrusted
        for _k in _wtrusted - _wrevoked:
            witness_names.setdefault(_k, _host or _wurl)
            required_witnesses.add(_k)
        print(
            f"requiring a counter-signature from witness {_host or _wurl} "
            f"({len(_wtrusted)} key(s) in its certified lineage)",
            file=sys.stderr if json_mode else sys.stdout,
        )
    for _k in getattr(args, "witness_key", None) or []:
        if _k in witness_names:
            # Resolves to an already-named deployment — one identity, not
            # two; counting it twice would let one witness satisfy 2-of-n.
            print(
                f"--witness-key {_k[:16]}… resolves to named witness "
                f"{witness_names[_k]} — one identity, counted once",
                file=sys.stderr if json_mode else sys.stdout,
            )
            continue
        if _k in _revoked_known:
            print(
                f"--witness-key {_k[:16]}… is revoked inside a named "
                "witness's lineage — a declared-suspect key cannot vouch; "
                "excluding it from the requirement",
                file=sys.stderr if json_mode else sys.stdout,
            )
            continue
        # A raw key with no resolvable deployment is a per-KEY identity —
        # two lineage keys of one rotated witness can't be told apart
        # from two witnesses here; --witness-url is the rotation-aware form.
        required_witnesses.add(_k)
    witness_threshold = int(getattr(args, "witness_threshold", 1) or 1)
    if witness_threshold < 1:
        fail("--witness-threshold must be at least 1")
    if required_witnesses:
        required_witnesses = sorted(required_witnesses)
    else:
        required_witnesses = []

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
                    fail(f"fetch failed: HTTP {r.status_code} for {args.bundle}")
                for chunk in r.iter_bytes(1 << 20):
                    n += len(chunk)
                    if n > 256 * 1024 * 1024:
                        fail("artifact exceeds the 256 MB verification bound")
                    raw.extend(chunk)
        except httpx.InvalidURL as exc:
            # InvalidURL extends Exception, not HTTPError — a malformed
            # URL must not escape the verdict path as a traceback.
            fail(f"fetch failed: malformed URL {args.bundle}: {exc}")
        except httpx.HTTPError as exc:
            fail(f"fetch failed: {exc}")
        path = Path(args.bundle.rstrip("/").rsplit("/", 1)[-1] or "remote-artifact")
    else:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            fail(f"cannot read artifact: {exc}")
    if raw[:2] == b"PK":
        _verify_zip(
            raw,
            pinned_key,
            known_rotations,
            json_mode=json_mode,
            live_base=live_base,
            issuer_doc=issuer_doc,
            required_witnesses=required_witnesses,
            witness_names=witness_names,
            witness_threshold=witness_threshold,
            badge=getattr(args, "badge", None),
            badge_link=getattr(args, "badge_link", None),
            attest=getattr(args, "attest", False),
        )
        return
    if getattr(args, "attest", False):
        fail("--attest signs a verdict on a pack .zip — pass the zip itself")
    if getattr(args, "badge", None):
        # The zip path is the only one that writes the badge on PASS —
        # elsewhere a stale green/red file would outlive this verdict.
        # sys.exit, not fail() — this is a usage refusal, not a verdict,
        # and fail() would write a red badge for a pack never checked.
        sys.exit("attest: --badge renders a pack-verdict shield — pass the .zip itself")
    try:
        data = transparency.json_loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        fail(f"not a JSON artifact: {path.name}\n  a .zip pack verifies directly — pass the zip itself.")
    except (json.JSONDecodeError, RecursionError) as exc:
        fail(f"not valid JSON: {exc}")
    pinned = " (against the pinned issuer key)" if pinned_key else ""
    trust_note = (
        "under that key"
        if pinned_key
        else "under the artifact's self-declared issuer key — pin a trusted key with --key"
    )

    if isinstance(data, list):
        try:
            receipts = [Receipt.model_validate(r) for r in data]
        except Exception as exc:  # noqa: BLE001 — a malformed entry IS the verdict
            fail(f"not a receipts.json list: {exc}", kind="receipt_chain")
        ok, reason = ledger.verify_chain(receipts, public_key=pinned_key, extra_key_receipts=known_rotations)
        if not ok:
            fail(f"verification failed: {reason}", kind="receipt_chain")
        if json_mode:
            print(
                json.dumps(
                    {
                        "ok": True,
                        "kind": "receipt_chain",
                        "detail": reason,
                        "pinned": bool(pinned_key),
                    },
                    indent=2,
                )
            )
        else:
            print(f"OK{pinned}: {reason}.")
            print(f"Note: a valid chain proves record integrity {trust_note}, not physical truth.")
        return

    if isinstance(data, dict) and "payload" in data and "signature" in data:
        try:
            receipt = Receipt.model_validate(data)
        except Exception as exc:  # noqa: BLE001 — receipt-shaped but malformed
            fail(f"not a valid receipt: {exc}", kind="receipt")
        trusted_key = pinned_key
        if pinned_key and known_rotations is not None:
            # The issuer document's signed lifecycle names every key the
            # deployment ever signed under — a receipt written before the
            # rotation verifies under the pin too, and a foreign key fails.
            lineage = ledger.trusted_issuer_keys(pinned_key, known_rotations) | ledger.descendant_issuer_keys(
                pinned_key, known_rotations
            )
            if receipt.public_key not in lineage:
                fail(
                    "verification failed: receipt signed by a key outside the "
                    "pinned issuer document's lineage",
                    kind="receipt",
                )
            trusted_key = receipt.public_key
        ok, reason = ledger.verify_receipt(receipt, public_key=trusted_key)
        if not ok:
            fail(f"verification failed: {reason}", kind="receipt")
        kind = receipt.payload.get("record_type") or receipt.payload.get("schema")
        warnings = []
        if known_rotations:
            # The issuer doc's revocations are a trust overlay too — the
            # browser verifier warns on suspect-window signings; match it.
            # Anchor at the pinned key: the doc's pool is attacker-controlled,
            # so pool position must never confer revocation authority.
            revoked = ledger.revoked_issuer_keys(known_rotations, issuer_key=pinned_key or receipt.public_key)
            if ledger.suspect_receipts([receipt], revoked=revoked):
                warnings.append(
                    "signed inside its issuer's declared suspect window — integrity intact, trust qualified"
                )
        # The sibling-.ots check only makes sense for a local file — for a URL
        # artifact the basename would match some unrelated CWD file (or crash
        # on a path that doesn't exist locally).
        ots = _sibling_ots_report(Path(args.bundle)) if not remote else None
        if json_mode:
            out = {
                "ok": True,
                "kind": "receipt",
                "record_type": kind,
                "receipt_id": receipt.id,
                "detail": reason,
                "pinned": bool(pinned_key),
                "warnings": warnings,
            }
            if ots:
                out["ots"] = ots
            print(json.dumps(out, indent=2))
        else:
            print(f"OK{pinned}: {kind} {receipt.id} — {reason}.")
            for w in warnings:
                print(f"WARNING: {w}")
            print(f"Note: a valid signature proves record integrity {trust_note}, not physical truth.")
            if ots:
                print(f"OpenTimestamps: {ots}.")
        return

    # --- transparency-log artifacts: the CLI's checkpoint/prove/consistency
    # outputs, and the log_checkpoint.json member packs carry. The signed
    # tree head anchors everything; proofs check out against it or not at all.
    if isinstance(data, dict) and (
        isinstance(data.get("checkpoint"), dict)
        or ("proof" in data and "first" in data)
        or ("path" in data and "leaf_index" in data)
    ):
        _verify_log_doc(
            data,
            args,
            pinned_key,
            known_rotations,
            fail,
            json_mode=json_mode,
            required_witnesses=required_witnesses,
            witness_names=witness_names,
            witness_threshold=witness_threshold,
        )
        return

    if required_witnesses or getattr(args, "witness_threshold", None):
        # The flags looked like they did something — "requiring witness X"
        # printed — but nothing below enforces them. Refuse instead of
        # letting a passed verdict carry a policy it never checked.
        fail(
            "--witness-* applies to pack .zip and checkpoint documents — "
            "nothing else has a log head to cosign"
        )

    try:
        bundle = ReviewBundle.model_validate(data)
    except Exception:
        fail(
            f"not a reviewable artifact: {path.name}\n"
            "  expected a bundle.json, receipt, anchor, checkpoint doc, or receipts.json export list."
        )
    key = pinned_key or bundle.original.public_key
    kr_path = path.parent / "key_rotations.json"
    rotations = list(known_rotations or [])
    if not remote and kr_path.is_file():
        # Mirror the embedded verify_bundle.py: reviews appended after a key
        # rotation verify under the successor — legitimate only through the
        # signed rotation+adoption links the pack ships next to the bundle.
        try:
            rj = transparency.json_loads(kr_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            fail(f"verification failed: key_rotations.json malformed ({exc})")
        extra = rj.get("rotations") if isinstance(rj, dict) else None
        if not isinstance(extra, list):
            fail("verification failed: key_rotations.json malformed")
        # Unsigned pool content: malformed members are inert-skipped — only
        # signed, adoption-consented pivots can ever extend trust.
        for r in extra:
            try:
                rotations.append(Receipt.model_validate(r))
            except Exception:  # noqa: BLE001
                continue
    if rotations:
        trusted = ledger.trusted_issuer_keys(key, rotations) | ledger.descendant_issuer_keys(key, rotations)
        ok, reason = reviews.verify_bundle(bundle, trusted_keys=trusted)
    else:
        ok, reason = reviews.verify_bundle(bundle, public_key=key)
    if not ok:
        fail(f"verification failed: {reason}", kind="bundle")
    warnings = []
    if rotations:
        # Match verify_bundle.py: a revocation overlays trust without
        # touching the verdict — surface suspect-window signings, anchored
        # at the verified key so a grafted foreign receipt stays inert.
        revoked = ledger.revoked_issuer_keys(rotations, issuer_key=key)
        if ledger.suspect_receipts([bundle.original] + [e.receipt for e in bundle.reviews], revoked=revoked):
            warnings.append(
                "record(s) signed inside their issuer's declared suspect window — "
                "integrity intact, trust qualified"
            )
    stance = reviews.countersign_status(bundle)
    if json_mode:
        print(
            json.dumps(
                {
                    "ok": True,
                    "kind": "bundle",
                    "detail": reason,
                    "pinned": bool(pinned_key),
                    "worker_stance": stance,
                    "warnings": warnings,
                },
                indent=2,
            )
        )
    else:
        print(f"OK{pinned}: {reason}.")
        for w in warnings:
            print(f"WARNING: {w}")
        print(f"Worker stance: {stance['state']} — {stance['detail']}")
        print(f"Note: a valid signature proves record integrity {trust_note}, not physical truth.")


def _verify_log_doc(
    data: dict,
    args: argparse.Namespace,
    pinned_key: str | None,
    known_rotations: list | None,
    fail,
    *,
    json_mode: bool = False,
    required_witnesses: list | None = None,
    witness_names: dict | None = None,
    witness_threshold: int = 1,
) -> None:
    """Offline check for the CLI's transparency artifacts: a checkpoint doc
    (``attest checkpoint --out`` / a pack's ``log_checkpoint.json``), an
    inclusion proof (``attest prove``), or a consistency bridge (``attest
    consistency``). Proofs are checked against a SIGNED head supplied with
    --checkpoint / --against — never against bare size claims in the doc."""
    from pathlib import Path

    from . import ledger, transparency
    from .models import Receipt

    def head_doc(path_str: str | None, label: str):
        """Parse a checkpoint document → (receipt, tree_size, root_bytes), or fail."""
        if not path_str:
            fail(f"this artifact needs a signed head to check against — pass --{label} FILE")
        try:
            doc = transparency.json_loads(Path(path_str).read_bytes())
        except (OSError, json.JSONDecodeError, RecursionError) as exc:
            fail(f"--{label}: unreadable checkpoint document ({exc})")
        raw_cp = doc.get("checkpoint") if isinstance(doc, dict) else None
        if not isinstance(raw_cp, dict):
            fail(f"--{label}: not a checkpoint document (expected {{'checkpoint': <receipt>}})")
        try:
            cp = Receipt.model_validate(raw_cp)
        except Exception as exc:  # noqa: BLE001
            fail(f"--{label}: malformed checkpoint receipt ({exc})")
        trusted(cp, label)
        ok, why = ledger.verify_receipt(cp, public_key=cp.public_key)
        if not ok:
            fail(f"--{label}: checkpoint receipt invalid ({why})")
        try:
            if not transparency.json_is_int(cp.payload.get("tree_size")):
                fail(f"--{label}: checkpoint carries a malformed root or size")
            size = int(cp.payload["tree_size"])
            if size < 1 or size > transparency.MAX_TREE_SIZE:
                fail(f"--{label}: checkpoint carries a malformed root or size")
            return (
                cp,
                size,
                transparency.hex_bytes(cp.payload["root_sha256"], length=32),
            )
        except (KeyError, TypeError, ValueError) as exc:
            fail(f"--{label}: checkpoint payload malformed ({exc})")

    def trusted(cp: Receipt, label: str) -> None:
        if cp.payload.get("record_type") != "log_checkpoint":
            fail(f"{label}: receipt is a {cp.payload.get('record_type')!r}, not a log_checkpoint")
        if pinned_key:
            lineage = {pinned_key}
            if known_rotations is not None:
                lineage = ledger.trusted_issuer_keys(pinned_key, known_rotations) | (
                    ledger.descendant_issuer_keys(pinned_key, known_rotations)
                )
            if cp.public_key not in lineage:
                fail(f"{label}: checkpoint signed outside the pinned issuer lineage")

    def emit(kind: str, detail: str, **kw) -> None:
        if json_mode:
            print(
                json.dumps(
                    {"ok": True, "kind": kind, "detail": detail, "pinned": bool(pinned_key), **kw}, indent=2
                )
            )
        else:
            print(f"OK: {detail}.")

    if isinstance(data.get("checkpoint"), dict):
        try:
            cp = Receipt.model_validate(data["checkpoint"])
        except Exception as exc:  # noqa: BLE001
            fail(f"malformed checkpoint receipt: {exc}", kind="log_checkpoint")
        trusted(cp, "checkpoint")
        ok, why = ledger.verify_receipt(cp, public_key=cp.public_key)
        if not ok:
            fail(f"checkpoint signature invalid: {why}", kind="log_checkpoint")
        try:
            if not transparency.json_is_int(cp.payload.get("tree_size")):
                fail("checkpoint carries a malformed root or size", kind="log_checkpoint")
            size = int(cp.payload["tree_size"])
            root = transparency.hex_bytes(cp.payload["root_sha256"], length=32)
        except (KeyError, TypeError, ValueError) as exc:
            fail(f"checkpoint payload malformed: {exc}", kind="log_checkpoint")
        if size < 1 or size > transparency.MAX_TREE_SIZE:
            fail("checkpoint carries a malformed root or size", kind="log_checkpoint")
        proven = None
        proofs = data.get("proofs")
        # `proofs` is an optional addition to a standalone checkpoint doc —
        # `attest checkpoint --out` omits it unless --include embedded
        # receipts. Absent means nothing to prove; present-but-not-an-object
        # is a lie (Python `.items()` would crash where JS Object.entries
        # iterates a list — same split the pack verifiers gate on). A doc
        # with receipts and absent proofs still fails below: every embedded
        # receipt must carry a working proof.
        if proofs is None:
            proofs = {}
        elif not isinstance(proofs, dict):
            fail("checkpoint document: 'proofs' must be an object", kind="log_checkpoint")
        proven = 0
        for ph, p in proofs.items():
            try:
                idx = p["leaf_index"]
                path = p.get("path") if isinstance(p, dict) else None
                good = (
                    isinstance(p, dict)
                    and transparency.json_is_int(idx)
                    # path absent/null reads as an empty proof on every
                    # surface; a non-list path must not iterate dict keys
                    and (path is None or isinstance(path, list))
                    and transparency.verify_inclusion(
                        transparency.hex_bytes(ph, length=32),
                        size,
                        int(idx),
                        [transparency.hex_bytes(b, length=32) for b in path or []],
                        root,
                    )
                )
            except (KeyError, ValueError, TypeError):
                good = False
            if not good:
                fail(
                    f"inclusion proof for {ph[:16]}… fails against this signed head — never committed there",
                    kind="log_checkpoint",
                )
            proven += 1
        # Embedded evidence receipts (e.g. `attest checkpoint --out doc
        # --include monitor:`): each must verify under a key inside the
        # issuer's lineage AND carry an inclusion proof — the two checks
        # together prove 'this signed observation sits inside this signed
        # head' with no store access needed.
        allowed = {cp.public_key}
        if pinned_key:
            allowed = {pinned_key}
            if known_rotations is not None:
                allowed = ledger.trusted_issuer_keys(pinned_key, known_rotations) | (
                    ledger.descendant_issuer_keys(pinned_key, known_rotations)
                )
        receipts = data.get("receipts")
        if receipts is not None:
            if not isinstance(receipts, list) or len(receipts) > 2048:
                fail(
                    "checkpoint document: 'receipts' must be a list of at most 2048",
                    kind="log_checkpoint",
                )
            seen_ids: set[str] = set()
            for raw in receipts:
                try:
                    r = Receipt.model_validate(raw)
                except Exception as exc:  # noqa: BLE001
                    fail(f"embedded receipt malformed: {exc}", kind="log_checkpoint")
                if r.id in seen_ids:
                    fail(f"embedded receipt {r.id[:24]}… listed twice", kind="log_checkpoint")
                seen_ids.add(r.id)
                if r.public_key not in allowed:
                    fail(
                        f"embedded receipt {r.id[:24]}… signed by a key outside the "
                        "issuer lineage — pin the lineage with --issuer-url to "
                        "cover rotation, or this receipt doesn't belong",
                        kind="log_checkpoint",
                    )
                ok, why = ledger.verify_receipt(r, public_key=r.public_key)
                if not ok:
                    fail(f"embedded receipt {r.id[:24]}… invalid: {why}", kind="log_checkpoint")
                if not isinstance(proofs, dict) or r.payload_hash not in proofs:
                    fail(
                        f"embedded receipt {r.id[:24]}… carries no inclusion "
                        "proof — 'inside the signed head' is unproven",
                        kind="log_checkpoint",
                    )
            detail_extra = f" — {len(receipts)} embedded receipt(s) verified inside the signed head"
        else:
            detail_extra = ""
        # The signed checkpoint chain (`chain`) — prior heads an export
        # embeds so two packs reconcile offline. Same closed discipline as
        # the pack surfaces: each member is a signed log_checkpoint receipt
        # inside the issuer lineage, strictly below the doc's head, one root
        # per tree size.
        chain = data.get("chain")
        size_ids: dict[int, str] = {}
        if chain is not None:
            if not isinstance(chain, list) or len(chain) > 64:
                fail(
                    "checkpoint document: 'chain' must be a list of at most 64",
                    kind="log_checkpoint",
                )
            seen_cids: set[str] = set()
            seen_sizes: dict[int, bytes] = {}
            for raw in chain:
                try:
                    mr = Receipt.model_validate(raw)
                except Exception as exc:  # noqa: BLE001
                    fail(f"chain member malformed: {exc}", kind="log_checkpoint")
                if mr.id in seen_cids:
                    fail(f"chain member {mr.id[:24]}… listed twice", kind="log_checkpoint")
                seen_cids.add(mr.id)
                mp = mr.payload
                if not isinstance(mp, dict) or mp.get("record_type") != "log_checkpoint":
                    fail(
                        f"chain member {mr.id[:24]}… is not a log_checkpoint receipt",
                        kind="log_checkpoint",
                    )
                if mr.public_key not in allowed:
                    fail(
                        f"chain member {mr.id[:24]}… signed by a key outside the issuer lineage",
                        kind="log_checkpoint",
                    )
                ok, why = ledger.verify_receipt(mr, public_key=mr.public_key)
                if not ok:
                    fail(f"chain member {mr.id[:24]}… invalid: {why}", kind="log_checkpoint")
                msize, mroot = mp.get("tree_size"), mp.get("root_sha256")
                try:
                    mroot_b = transparency.hex_bytes(mroot, length=32)
                except (TypeError, ValueError):
                    mroot_b = None
                if not transparency.json_is_int(msize) or not 1 <= int(msize) < size or mroot_b is None:
                    fail(
                        f"chain member {mr.id[:24]}… carries a malformed or non-prior head",
                        kind="log_checkpoint",
                    )
                if transparency.verify_extends(mp) is False:
                    fail(
                        f"chain member {mr.id[:24]}… signs a bridge it cannot prove",
                        kind="log_checkpoint",
                    )
                # Dedupe on decoded bytes so hex-case variants of one head
                # don't convict, and a non-hex spelling fails closed like the
                # browser's regex gate.
                if msize in seen_sizes and seen_sizes[msize] != mroot_b:
                    fail(
                        f"chain carries two signed heads at size {msize}",
                        kind="log_checkpoint",
                    )
                seen_sizes[msize] = mroot_b
                size_ids[int(msize)] = mr.id
            detail_extra += f" — {len(chain)} prior signed head(s) verified in the embedded chain"
        detail = f"signed transparency head: tree size {size}, root {cp.payload['root_sha256'][:16]}…"
        detail += detail_extra
        if proven is not None:
            detail += f" — {proven} packed inclusion proof(s) verified"
        # The checkpoint's own signed continuity claim: verify_extends with
        # no expectations just asks whether the embedded bridge internally
        # verifies — a checkpoint that signs a broken bridge is lying about
        # its own ancestry and fails like any other bad signature.
        self_ext = transparency.verify_extends(cp.payload)
        if self_ext is False:
            fail(
                "checkpoint's embedded `extends` bridge does not verify — "
                "the signed head attests a history it cannot prove",
                kind="log_checkpoint",
            )
        if self_ext is True:
            e = cp.payload["extends"]
            # The bridge's cryptographic claim is (size, root, proof) — its
            # `checkpoint_id` label is signed text but only verifiable when
            # the named member rides in this document's own chain. Report it
            # as what it is: verified when it matches the embedded member,
            # "names" when unchecked, flagged when the two disagree.
            cid = str(e.get("checkpoint_id") or "")
            try:
                efirst = transparency.coerce_int(e.get("first"))
            except (TypeError, ValueError):
                efirst = None
            named = size_ids.get(efirst) if efirst is not None else None
            detail += f" — embedded bridge provably reaches size {e.get('first')}"
            if cid and named is not None and named == cid:
                detail += f" (checkpoint {cid[:16]}…)"
            elif cid and named is not None:
                detail += (
                    f" — NOTE: bridge names checkpoint {cid[:16]}… but the signed "
                    f"chain member at that size is {named[:16]}… (inconsistent label; "
                    "the size+root binding still verifies)"
                )
            elif cid:
                detail += f" (names checkpoint {cid[:16]}…)"
        # Witness counter-signatures: auxiliary attestations — verified and
        # reported, never the gate. A third party holding this doc sees WHO
        # countersigned this head, not just that the issuer signed it.
        from . import logmonitor as _lm

        _lineage = (
            ledger.trusted_issuer_keys(pinned_key, known_rotations or [])
            | ledger.descendant_issuer_keys(pinned_key, known_rotations or [])
            if pinned_key
            else None
        )
        n_cosig, cosigners = _lm.check_cosignatures(
            data, cp.id, size, cp.payload["root_sha256"], issuer_keys=_lineage
        )
        if n_cosig:
            detail += (
                f" — cosigned by {n_cosig} witness(es) ({', '.join(k[:12] + '…' for k in cosigners[:3])})"
            )
        # A packed witness anchor that doesn't verify is a lie indicator,
        # not a downgrade — fail closed like the pin check does.
        _anch, _aerr = _lm.check_cosig_anchors(data)
        if _aerr:
            fail(f"checkpoint document: {_aerr[0]}", kind="log_checkpoint")
        if _anch:
            detail += f" — {_anch} attestation(s) anchored in the witness's own published log"
        if required_witnesses:
            # Threshold counts distinct witness IDENTITIES, not keys: every
            # lineage key of one --witness-url maps to that deployment's
            # name, so a rotated witness signing with old+new keys still
            # counts once — k-of-n really means k cooperating parties.
            identities = sorted(
                {(witness_names or {}).get(k, k) for k in cosigners if k in required_witnesses}
            )
            shown = [i if len(i) <= 40 else i[:12] + "…" for i in identities]
            if len(identities) < witness_threshold:
                fail(
                    f"counter-signatures from required witnesses insufficient — "
                    f"{len(identities)} distinct witness(es) of {witness_threshold} required "
                    f"({len(required_witnesses)} named key(s); {n_cosig} valid cosig(s) total)",
                    kind="log_checkpoint",
                )
            detail += (
                f" — vouched by required witness {shown[0]}"
                if witness_threshold == 1
                else f" — vouched by {len(identities)} required witnesses ({', '.join(shown)})"
            )
        # --against pins the earlier head: the checkpoint must bridge FROM
        # that exact signed head, offline, no consistency endpoint needed.
        if getattr(args, "against", None):
            _ocp, old_size, old_root = head_doc(args.against, "against")
            if _ocp.public_key != cp.public_key:
                fail(
                    "--against and checkpoint heads are signed by different issuers",
                    kind="log_checkpoint",
                )
            br = transparency.verify_extends(cp.payload, first=old_size, first_root=old_root)
            if br is True:
                detail += f"; provably extends the --against head (size {old_size})"
            elif br is False:
                fail(
                    f"checkpoint does not extend the --against head — its "
                    f"embedded bridge cannot reach the pinned root at size {old_size}",
                    kind="log_checkpoint",
                )
            else:
                fail(
                    "checkpoint carries no embedded bridge from the --against "
                    "head — verify continuity with a `attest consistency` "
                    "bridge document instead",
                    kind="log_checkpoint",
                )
        ots = (
            _sibling_ots_report(Path(args.bundle))
            if not args.bundle.startswith(("http://", "https://"))
            else None
        )
        emit(
            "log_checkpoint",
            detail,
            tree_size=size,
            root_sha256=cp.payload["root_sha256"],
            proven=proven,
            **({"ots": ots} if ots else {}),
        )
        if not json_mode and ots:
            print(f"OpenTimestamps: {ots}.")
        if not json_mode and not pinned_key:
            print(
                "Note: the head verifies under its self-declared key — "
                "pin the issuer with --key or --issuer-url."
            )
        return

    if "proof" in data and "first" in data:
        old_cp, old_size, old_root = head_doc(getattr(args, "against", None), "against")
        new_cp, new_size, new_root = head_doc(getattr(args, "checkpoint", None), "checkpoint")
        if new_cp.public_key != old_cp.public_key:
            fail("--against and --checkpoint heads are signed by different issuers", kind="consistency_proof")
        try:
            first = transparency.coerce_int(data["first"])
            nodes = [transparency.hex_bytes(b, length=32) for b in data["proof"]]
        except (ValueError, TypeError) as exc:
            fail(f"consistency bridge malformed: {exc}", kind="consistency_proof")
        if first != old_size:
            fail(
                f"bridge starts at size {first} but --against signs "
                f"{old_size} — pair each head with its own file",
                kind="consistency_proof",
            )
        try:
            bridge_size = transparency.coerce_int(data.get("tree_size", new_size))
        except (ValueError, TypeError):
            fail("consistency bridge malformed: tree_size is not an integer", kind="consistency_proof")
        if bridge_size != new_size:
            fail(
                f"bridge was emitted for a tree of size {data.get('tree_size')} "
                f"but --checkpoint signs {new_size}",
                kind="consistency_proof",
            )
        if not transparency.verify_consistency(old_root, first, new_root, new_size, nodes):
            fail(
                "consistency proof does not bridge these heads — history may have been rewritten",
                kind="consistency_proof",
            )
        emit(
            "consistency_proof",
            f"append-only extension verified: tree grew {first} → {new_size} without rewriting",
            old_size=first,
            new_size=new_size,
        )
        return

    # Inclusion proof doc: {tree_size, leaf_index, leaf, path}.
    _, size, root = head_doc(getattr(args, "checkpoint", None), "checkpoint")
    try:
        index = data["leaf_index"]
        if not transparency.json_is_int(index):
            raise ValueError("leaf_index is not a JSON integer")
        index = int(index)
        leaf = transparency.hex_bytes(data["leaf"], length=32)
        path_nodes = [transparency.hex_bytes(b, length=32) for b in data["path"]]
    except (ValueError, TypeError, KeyError) as exc:
        fail(f"inclusion proof malformed: {exc}", kind="inclusion_proof")
    try:
        proof_size = transparency.coerce_int(data.get("tree_size", size))
    except (ValueError, TypeError):
        fail("inclusion proof malformed: tree_size is not an integer", kind="inclusion_proof")
    if proof_size != size:
        fail(
            f"proof was computed at tree size {data.get('tree_size')} but --checkpoint signs {size} — "
            "it reaches a different root",
            kind="inclusion_proof",
        )
    if not transparency.verify_inclusion(leaf, size, index, path_nodes, root):
        fail(
            "inclusion proof does not reach the signed root — the leaf was never committed there",
            kind="inclusion_proof",
        )
    emit(
        "inclusion_proof",
        f"receipt {data['leaf'][:16]}… sits at index {index} inside the signed head of size {size}",
        leaf_index=index,
        tree_size=size,
    )


def _pack_key_pool(z, names) -> list:
    """Lifecycle receipts the pack itself carries — case packs list them
    in ``manifest.attestations``, single-visit packs in
    ``key_rotations.json``. Malformed members already failed the verify
    pass; this pool only widens the issuer lineage used for self-vouch
    exclusion and reporting, so unreadable entries are skipped."""
    from .models import Receipt

    pool: list = []
    if "manifest.json" in names:
        try:
            manifest = transparency.json_loads(z.read("manifest.json"))
        except Exception:  # noqa: BLE001 — manifest itself already failed the verify pass
            manifest = {}
        for a in manifest.get("attestations") or []:
            rid = a.get("receipt_id") if isinstance(a, dict) else None
            if not rid or f"attestations/{rid}.json" not in names:
                continue
            try:
                att = Receipt.model_validate(transparency.json_loads(z.read(f"attestations/{rid}.json")))
            except Exception:  # noqa: BLE001 — skip the member, not the pool
                continue
            if att.payload.get("record_type") in ("key_rotation", "key_adoption", "key_revocation"):
                pool.append(att)
    if "key_rotations.json" in names:
        try:
            kr = transparency.json_loads(z.read("key_rotations.json"))
        except Exception:  # noqa: BLE001
            kr = {}
        for r in kr.get("rotations") or []:
            try:
                pool.append(Receipt.model_validate(r))
            except Exception:  # noqa: BLE001
                continue
    return pool


def _attestation_engine():
    """``verify --attest`` — the journal a signed verdict lands in. Mutating,
    so it takes the instance writer lock like every other issuance command;
    a missing store is a loud error, never a silent skip."""
    from .instance import acquire_instance_lock
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"--attest needs a store to sign into — none at {db}")
    acquire_instance_lock(settings.data_dir)
    return _cli_engine(Store(db))


def _lifecycle_fp(pool: list | None) -> str | None:
    """Content fingerprint of an issuer-lifecycle receipt pool — part of the
    trust context an attestation binds (a changed pool is a changed claim).
    Hashes payload_hash (content-derived), not receipt ids — a pool member
    swapped under a reused id still changes the fingerprint."""
    import hashlib

    if not pool:
        return None
    return hashlib.sha256(
        json.dumps(sorted(r.payload_hash for r in pool), separators=(",", ":")).encode()
    ).hexdigest()


def _checker_verifier(checker: str, func) -> dict:
    """Verifier identity for attestation receipts — name, version, the entry
    point that produced the verdict, and a content hash of that module's
    source, so a verdict from different checking rules never collapses."""
    import hashlib
    import inspect
    from pathlib import Path

    from . import __version__

    return {
        "name": "attest-cli",
        "version": __version__,
        "checker": checker,
        "verifier_sha256": hashlib.sha256(Path(inspect.getfile(func)).read_bytes()).hexdigest(),
    }


def _verify_zip(
    raw: bytes,
    pinned_key: str | None,
    known_rotations: list | None = None,
    *,
    json_mode: bool = False,
    live_base: str | None = None,
    issuer_doc: dict | None = None,
    required_witnesses: list | None = None,
    witness_names: dict | None = None,
    witness_threshold: int = 1,
    badge: str | None = None,
    badge_link: str | None = None,
    attest: bool = False,
) -> None:
    """Verify a dispute pack or case pack zip in place — same checks as the
    embedded verify_case.py and the /verify page. Without --key the pack's own
    declared issuer key is pinned (self-consistency); --key pins a deployment key.
    ``known_rotations`` (e.g. fetched via --issuer-url) extends trust forward
    through the deployment's signed lifecycle — a pack exported before a
    rotation still verifies under the current issuer. In --json mode stdout
    carries exactly one object: {ok, kind, detail, pinned} — a CI can gate on
    it without parsing prose."""
    import io
    import zipfile

    from . import ledger
    from .app import _verify_pack
    from .models import ReviewBundle
    from .packdiff import BoundedZip

    # --attest signs the verdict itself into the deployment's journal: the
    # audit becomes auditable. Built BEFORE the pack is opened so a missing
    # store fails fast instead of after the (potentially slow) check. The
    # attestation binds sha256(pack bytes) + the verifier's content identity
    # + the trust context (pin, lifecycle pool, witness policy, live check),
    # so a re-run reaching a different verdict can never reuse this receipt.
    try:
        attest_engine = _attestation_engine() if attest else None
    except (OSError, RuntimeError) as exc:
        sys.exit(f"attest: --attest unavailable — {exc}")

    live_report: dict | None = None
    live_line: str | None = None

    def _attest(ok: bool, detail: str) -> None:
        if attest_engine is None:
            return
        import hashlib

        try:
            receipt = attest_engine.issue_pack_verification(
                hashlib.sha256(raw).hexdigest(),
                len(raw),
                "ok" if ok else "fail",
                detail,
                _checker_verifier("attest.app._verify_pack", _verify_pack),
                context={
                    "issuer_pin": pinned_key,
                    "lifecycle_sha256": _lifecycle_fp(known_rotations),
                    "witness_policy": (
                        {
                            "required": sorted(required_witnesses),
                            "threshold": witness_threshold,
                        }
                        if required_witnesses
                        else None
                    ),
                    "live_log": live_report,
                },
            )
        except Exception as exc:  # noqa: BLE001 — never mask the verdict
            sys.exit(
                f"attest: could not sign the attestation — {exc} "
                f"(the verdict was: {'ok' if ok else 'FAIL'} — {detail})"
            )
        print(
            f"Attestation {receipt.id}: verdict signed into this deployment's journal",
            file=sys.stderr if json_mode else sys.stdout,
        )

    def fail(detail: str, **kw) -> None:
        if json_mode:
            # The verdict lands on stdout before the attestation write — a
            # signing failure must not eat the machine-readable result.
            print(json.dumps({"ok": False, "detail": detail, **kw}, indent=2))
            _attest(False, detail)
            _write_verdict_badge(badge, False, detail, link=badge_link)
            sys.exit(1)
        _attest(False, detail)
        _write_verdict_badge(badge, False, detail, link=badge_link)
        sys.exit(detail)

    try:
        z = BoundedZip(zipfile.ZipFile(io.BytesIO(raw)))
        names = set(z.namelist())
        if "manifest.json" in names:
            kind = "case-pack"
            declared = transparency.json_loads(z.read("manifest.json")).get("issuer_key")
        elif "bundle.json" in names:
            kind = "pack"
            declared = ReviewBundle.model_validate(
                transparency.json_loads(z.read("bundle.json"))
            ).original.public_key
        else:
            fail("zip contains no manifest.json or bundle.json — not an Attest pack")
    except zipfile.BadZipFile:
        fail("not a valid zip file")
    except Exception as exc:
        fail(f"could not read pack issuer: {exc}")
    key = pinned_key or declared
    ok, detail = _verify_pack(raw, key, known_rotations=known_rotations)
    if not ok:
        fail(f"verification failed: {detail}", kind=kind)
    if live_base and issuer_doc is not None and "log_checkpoint.json" in names:
        # The pack's checkpoint proves membership in A log; the live head
        # answers WHICH log — a deployment that mints a consistent-but-forked
        # log per victim must still bridge this head to the one it serves
        # everyone else, or the pack's claimed history is provably not theirs.
        from . import logmonitor

        try:
            cpdoc = transparency.json_loads(z.read("log_checkpoint.json"))
            head = logmonitor.fetch_json(f"{live_base}/api/log/head")
            trusted_set = logmonitor._trusted_set(issuer_doc)
            verdict, live_line = logmonitor.live_check(
                cpdoc.get("checkpoint") or {},
                head,
                lambda f_, s_: logmonitor.fetch_json(f"{live_base}/api/log/consistency?first={f_}&size={s_}"),
                trusted_set,
            )
        except ValueError as exc:
            # Transport failed — the pack's own verdict stands; say so plainly.
            live_line = f"live log unreachable ({exc}) — pack verdict unaffected"
            live_report = {"checked": False, "detail": live_line}
        else:
            live_report = {"checked": verdict is not None, "same_log": verdict, "detail": live_line}
            if verdict is False:
                fail(f"live log cross-check: {live_line}", kind=kind)
    if required_witnesses:
        # Named-witness policy (sigsum-style): reporting a cosig count is one
        # thing — a verifier that knows WHICH witness it trusts can require a
        # counter-signature from that party specifically. A sock-puppet cosig
        # from the issuer itself cannot satisfy a named-witness requirement.
        from . import logmonitor

        if "log_checkpoint.json" not in names:
            fail(
                "--witness-key requires a counter-signed transparency checkpoint — this pack carries none",
                kind=kind,
            )
        cpdoc = transparency.json_loads(z.read("log_checkpoint.json"))
        _cp, _p = cpdoc["checkpoint"], cpdoc["checkpoint"]["payload"]
        # Self-vouch exclusion needs the WHOLE issuer family — the pack's
        # own lifecycle receipts name rotated issuer keys that
        # --issuer-url material alone can't see.
        _pool = _pack_key_pool(z, names) + list(known_rotations or [])
        _lineage = ledger.trusted_issuer_keys(key, _pool) | (ledger.descendant_issuer_keys(key, _pool))
        _, signers = logmonitor.check_cosignatures(
            cpdoc, _cp["id"], int(_p["tree_size"]), _p["root_sha256"], issuer_keys=_lineage
        )
        # Distinct witness identities, not keys — a rotated witness's two
        # lineage keys resolve to the same deployment name and count once.
        identities = sorted({(witness_names or {}).get(k, k) for k in signers if k in required_witnesses})
        shown = [i if len(i) <= 40 else i[:12] + "…" for i in identities]
        if len(identities) < witness_threshold:
            fail(
                f"counter-signatures from required witnesses insufficient — "
                f"{len(identities)} distinct witness(es) of {witness_threshold} required "
                f"({len(required_witnesses)} named key(s); {len(signers)} valid cosig(s) total)",
                kind=kind,
            )
        detail += (
            f" — vouched by required witness {shown[0]}"
            if witness_threshold == 1
            else f" — vouched by {len(identities)} required witnesses ({', '.join(shown)})"
        )
    if json_mode:
        extra: dict = {}
        if "log_checkpoint.json" in names:
            # The pin check already verified the head and every proof — this
            # just reports the commitment shape so a CI can gate on it too
            # (e.g. require the log to have grown since a prior export).
            try:
                cp = transparency.json_loads(z.read("log_checkpoint.json"))
                from . import logmonitor as _lm2

                _p = cp["checkpoint"]["payload"]
                _pool = _pack_key_pool(z, names) + list(known_rotations or [])
                _nc, _sig = _lm2.check_cosignatures(
                    cp,
                    cp["checkpoint"]["id"],
                    int(_p["tree_size"]),
                    _p["root_sha256"],
                    issuer_keys=ledger.trusted_issuer_keys(key, _pool)
                    | ledger.descendant_issuer_keys(key, _pool),
                )
                _anch, _aerr = _lm2.check_cosig_anchors(cp)
                extra["log"] = {
                    "tree_size": _p["tree_size"],
                    "proven": len(cp.get("proofs") or {}),
                    "cosigned": _nc,
                    "anchored_cosigs": _anch,
                }
                if _aerr:
                    extra["log"]["anchor_errors"] = _aerr
            except Exception:  # noqa: BLE001 — verified pack; report what parses
                pass
        if live_report is not None:
            extra["live_log"] = live_report
        print(
            json.dumps(
                {"ok": True, "kind": kind, "detail": detail, "pinned": bool(pinned_key), **extra},
                indent=2,
            )
        )
        _attest(True, detail)
        _write_verdict_badge(badge, True, detail, link=badge_link)
        return
    print(f"OK: {detail}")
    _attest(True, detail)
    _write_verdict_badge(badge, True, detail, link=badge_link)
    if live_line:
        print(f"Live log: {live_line}")
    if pinned_key:
        print("Note: a valid pack proves record integrity under the pinned issuer key, not physical truth.")
    else:
        print(
            "Note: a valid pack proves record integrity under the pack's self-declared "
            "issuer key — pin a trusted key with --key. Signatures are not physical truth."
        )


def _write_verdict_badge(path: str | None, ok: bool, detail: str, link: str | None = None) -> None:
    """``verify --badge`` — render the verdict as a self-contained SVG shield,
    the evidence-pack analogue of a CI badge. Written on failure too: a red
    badge that says FAILED is honest output, not an error artifact. The full
    verdict detail rides in ``<title>`` so a hover carries the real string.
    ``--badge-link`` wraps the shield in an ``<a>`` so a badge opened
    standalone still leads back to a verifier."""
    if not path:
        return
    from html import escape as _esc

    label, value, color = "attest", ("verified" if ok else "FAILED"), ("#2e8b57" if ok else "#c0392b")
    # ~6.2px per Verdana-11 glyph plus padding, per the shields.io convention.
    lw, rw = round(6.2 * len(label)) + 12, round(6.2 * len(value)) + 12
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + rw}" height="20" role="img" '
        f'aria-label="{_esc(label)}: {_esc(value)}"><title>{_esc(detail)}</title>'
        f'<rect width="{lw}" height="20" rx="3" fill="#555"/>'
        f'<rect x="{lw}" width="{rw}" height="20" rx="3" fill="{color}"/>'
        f'<rect x="{lw}" width="4" height="20" fill="{color}"/>'
        f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2:.0f}" y="14" text-anchor="middle">{_esc(label)}</text>'
        f'<text x="{lw + rw / 2:.0f}" y="14" text-anchor="middle">{_esc(value)}</text>'
        f"</g></svg>\n"
    )
    if link:
        svg = (
            svg.replace(
                "<svg ",
                '<svg xmlns:xlink="http://www.w3.org/1999/xlink" ',
                1,
            )
            .replace(
                f'<rect width="{lw}"',
                f'<a xlink:href="{_esc(link, quote=True)}" href="{_esc(link, quote=True)}">'
                f'<rect width="{lw}"',
                1,
            )
            .replace("</svg>", "</a></svg>", 1)
        )
    _atomic_write(path, svg)
    print(f"verdict badge written to {path}", file=sys.stderr)


def _sibling_ots_report(path) -> str | None:
    """If FILE.ots sits next to the artifact, describe its OpenTimestamps status
    and whether the stamped digest still matches the file's bytes."""
    import hashlib

    from .timestamp import extract_digest, ots_status

    ots_path = path.with_name(path.name + ".ots")
    if not ots_path.exists():
        return None
    ots = ots_path.read_bytes()
    stamped = extract_digest(ots)
    actual = hashlib.sha256(path.read_bytes()).digest()
    if stamped == actual:
        match = "digest matches this file"
    else:
        match = "stamped digest differs — file changed since stamping"
    return f"{ots_status(ots)} — {match}"


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
        from .ledger import check_signer_continuity

        check_signer_continuity(prev, signer)
        entries = store._conn.execute("SELECT COUNT(*) FROM journal").fetchone()[0]
        # The Merkle head too: receipt_head alone only proves the tail's hash —
        # an auditor holding just this anchor could verify a chain, but not a
        # compact inclusion proof. The tree head turns the anchor into an
        # external STH: publish or notarize it and a retroactive log fork is
        # provable without ever seeing the chain.
        from . import transparency

        leaves = transparency.leaf_hashes(store.receipts())
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
                "log_tree_size": len(leaves),
                "log_root_sha256": transparency.root(leaves).hex(),
                "visit_count": store.stats()["visits"]["total"],
                "boundary": (
                    "Anchors that a record state existed at issuance. Truncating the "
                    "journal or removing receipts after this anchor is provable — and "
                    "the pinned Merkle head lets a holder verify an inclusion proof "
                    "for any receipt committed up to log_tree_size."
                ),
            },
        )
        out = Path(args.out or "attest-anchor.json")
        _atomic_write(out, anchor.model_dump_json(indent=2))
        print(
            f"wrote {out} — journal head {anchor.payload['journal_head'][:16]}…, "
            f"{entries} entries, {anchor.payload['receipt_count']} receipts, "
            f"log root {anchor.payload['log_root_sha256'][:16]}… ({len(leaves)} leaves) pinned"
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
    store = Store(db, read_only=True)
    try:
        signer = load_or_create_signer(
            settings.key_path,
            kms_key_id=settings.kms_key_id,
            custody=settings.key_custody,
            aws_region=settings.aws_region,
            create=False,  # triage is read-only — never mint or migrate a key
        )
        from .clock import ExecutionClock

        # Triage never writes; the clock only needs to match the store's mode
        # and must not persist the mode row (journaled write) either.
        replay = (store.setting("execution_mode") or {}).get("mode") == "replay"
        clock = ExecutionClock(
            store,
            replay=replay,
            ring_base_url="http://127.0.0.1" if replay else settings.ring_base_url,
            persist=False,
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


def _atomic_write(path, data) -> None:
    """Temp-file-then-rename for every artifact the CLI publishes — a crash
    mid-write must never leave a truncated pack, badge, report, or evidence
    document that reads like the real thing."""
    import os
    from pathlib import Path

    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    if isinstance(data, str):
        tmp.write_text(data, encoding="utf-8")
    else:
        tmp.write_bytes(data)
    os.replace(tmp, path)


def _must_store(*, read_only: bool = False):
    """Open the runtime store — or refuse. An integrity/inspection command must
    never let SQLite silently CREATE an empty db and then report it intact
    ('attest journal' on a never-written dir must not print entries: 0, ok).
    ``read_only`` opens without schema DDL or journal-mode writes, so an
    inspection can't leave marks in the runtime it audits."""
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db} — run `attest serve` or `attest replay` first")
    return Store(db, read_only=read_only)


def _cli_engine(store, *, read_only: bool = False):
    """A real VisitEngine over an existing store for offline issuance commands
    (coverage/digest/export signing). The Ring client is never called.

    ``read_only=True`` is the contract for explain/triage-style callers:
    the signer only *loads* (never mints, never custody-migrates), the
    clock never persists its mode row, and the media dir is never created —
    a command documented as read-only must not write into the runtime it
    inspects."""
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
    try:
        signer = load_or_create_signer(
            settings.key_path,
            kms_key_id=settings.kms_key_id,
            custody=settings.key_custody,
            aws_region=settings.aws_region,
            create=not read_only,
        )
    except FileNotFoundError:
        if not read_only:
            raise
        # Keyless store: a deployment that never signed has no PEM to load —
        # and read-only commands must not mint one. Verification paths never
        # trust the engine signer's own key (receipts carry their public key);
        # an ephemeral stand-in preserves that, just without a disk write.
        from .ledger import Signer

        signer = Signer.ephemeral()
    if not read_only:
        from .ledger import check_signer_continuity

        check_signer_continuity(store.latest_receipt(), signer)
    return VisitEngine(
        store,
        RingClient(settings.ring_access_token, base_url=base),
        signer,
        MediaStore(settings.data_dir / "media", create=not read_only),
        TemplateSummarizer(settings.timezone),
        eff,
        persist_clock=not read_only,
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

    from .keycustody import persist_signer_key
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
            # Adopt from the key material in hand once the persist lands —
            # never a second custody round-trip: a post-persist load failure
            # would leave disk on the new key while this signer stayed retired,
            # and receipts minted in that gap break the chain the moment the
            # next boot's adoption sweep consummates the pivot.
            persist_signer_key(
                settings.key_path,
                pem,
                kms_key_id=settings.kms_key_id,
                custody=settings.key_custody,
                aws_region=settings.aws_region,
            )
            return Signer(sk)

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
                # Same contract sweep/check-in enforce: a signed timestamp
                # must name its offset — guessing UTC for a forensic cutoff
                # silently shifts which records fall suspect.
                sys.exit("--suspect-after must be timezone-aware (ISO 8601 with offset)")
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
    store = Store(db, read_only=True)
    try:
        signer = load_or_create_signer(
            settings.key_path,
            kms_key_id=settings.kms_key_id,
            custody=settings.key_custody,
            aws_region=settings.aws_region,
            # issuer is read-only against the runtime: minting a fresh key
            # here would publish an identity with no lineage behind it.
            create=False,
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


def _checkpoint(args: argparse.Namespace) -> None:
    """Sign the transparency log's current Merkle Tree Head — an STH receipt
    committing to exactly the receipts chained so far. Two checkpoints can be
    bridged by a consistency proof and any receipt can carry an inclusion
    proof — 'append-only' becomes checkable without enumerating the chain."""
    from .instance import acquire_instance_lock
    from .store import Store

    if getattr(args, "timestamp", False) and not args.out:
        # Validate before minting — a refused flag combination must not leave
        # a checkpoint receipt in the ledger anyway.
        sys.exit("--timestamp needs --out — the notarized proof rides next to the checkpoint file")
    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    acquire_instance_lock(settings.data_dir)
    store = Store(db)
    try:
        engine = _cli_engine(store)
        # A size-0 head attests an empty log — legal to mint but every
        # verifier rejects it as a malformed tree head, so serving it would
        # make a monitor ALERT forever against an honest deployment. Refuse
        # before minting: an empty log is 'nothing to pin yet'.
        leaves_pre = engine.log_leaves()
        if not leaves_pre:
            sys.exit("log is empty — nothing to checkpoint yet")
        include = getattr(args, "include", None) or []
        embedded_pre: list = []
        if include:
            # Validate the include set against the CURRENT tree before the
            # mint — a receipt outside it has no inclusion path, and a
            # refused --include must not leave the checkpoint it rode on.
            embedded_pre = [r for r in store.receipts() if any(r.visit_id.startswith(p) for p in include)]
            leaf_hashes = set(leaves_pre)
            for r in embedded_pre:
                if bytes.fromhex(r.payload_hash) not in leaf_hashes:
                    sys.exit(f"--include: receipt {r.id} is not inside the committed tree")
        receipt = engine.issue_log_checkpoint()
        p = receipt.payload
        out = {
            "checkpoint": receipt.model_dump(mode="json"),
            "boundary": p.get("boundary"),
        }
        # The signed checkpoint chain — prior heads, oldest first — so a
        # monitor (or a second export) holding an older head reconciles this
        # doc offline hop-by-hop, the same walk `attest diff` performs.
        prior = [
            r
            for r in store.receipts()
            if r.payload.get("record_type") == "log_checkpoint" and r.id != receipt.id
        ]
        prior.sort(key=lambda r: r.payload.get("tree_size") or 0)
        if prior:
            out["chain"] = [r.model_dump(mode="json") for r in prior[-32:]]
        witnesses = getattr(args, "witness", None) or []
        if witnesses:
            out["cosignatures"] = []
            from . import ledger, logmonitor

            issuer_doc = ledger.issuer_document(engine.signer.public_key_b64, store.receipts())
            for url in witnesses:
                base = url.rstrip("/")
                try:
                    cosig, line, anchor = logmonitor.cosign_at(
                        base,
                        issuer_doc,
                        out["checkpoint"],
                        lambda pinned_size: engine.consistency_proof(pinned_size, int(p["tree_size"])),
                    )
                except ValueError as exc:
                    print(f"witness {base}: unreachable ({exc}) — checkpoint unsigned by it", file=sys.stderr)
                    continue
                if cosig:
                    out["cosignatures"].append(cosig)
                    if anchor:
                        out.setdefault("cosig_anchors", {})[cosig["id"]] = anchor
                    print(f"witness {base}: {line}")
                else:
                    print(f"witness {base}: {line}", file=sys.stderr)
        if include:
            # Embed the matching receipts plus an inclusion proof each —
            # the doc then proves 'these signed observations are inside
            # this signed head' on its own, no store access needed. The
            # membership check already ran pre-mint; this block only builds
            # proofs.
            from .transparency import inclusion_path

            leaves = engine.log_leaves()[: int(p["tree_size"])]
            proofs = {}
            for r in embedded_pre:
                idx = leaves.index(bytes.fromhex(r.payload_hash))
                proofs[r.payload_hash] = {
                    "leaf_index": idx,
                    "path": [n.hex() for n in inclusion_path(leaves, idx)],
                }
            if embedded_pre:
                out["receipts"] = [r.model_dump(mode="json") for r in embedded_pre]
                out["proofs"] = proofs
            else:
                print(f"note: --include {include} matched no receipts", file=sys.stderr)
        if args.out:
            from pathlib import Path

            _atomic_write(args.out, json.dumps(out, indent=2, ensure_ascii=False) + "\n")
            print(f"wrote {args.out}")
        print(
            f"checkpoint {receipt.id[:24]}… — tree size {p['tree_size']}, "
            f"root {p['root_sha256'][:24]}… (verify with `attest status`)"
        )
        if getattr(args, "timestamp", False):
            # Notarize the signed head itself — after the calendar commits,
            # the deployment cannot re-date this root, let alone rewrite it.
            _stamp_file(Path(args.out))
    finally:
        store.close()


def _prove(args: argparse.Namespace) -> None:
    """Emit the RFC 6962 inclusion proof for one receipt — the compact
    answer to 'was this receipt in the deployment's published log?'."""
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    store = Store(db, read_only=True)
    try:
        receipt = store.receipt(args.receipt_id)
        if receipt is None:
            sys.exit(f"unknown receipt {args.receipt_id}")
        # Read-only: no engine, so no key custody, media dir, or clock row —
        # a proof command must never mint state into the runtime it audits.
        from . import transparency

        proof = transparency.inclusion_proof(transparency.leaf_hashes(store.receipts()), receipt.payload_hash)
        if proof is None:
            sys.exit(f"receipt {receipt.id} is not in the log's committed order")
        print(json.dumps(proof, indent=2, ensure_ascii=False))
    finally:
        store.close()


def _consistency(args: argparse.Namespace) -> None:
    """Emit the RFC 6962 consistency proof bridging an earlier signed tree
    head to the current one — 'the log only appended since' in O(log n),
    verifiable offline against the checkpoint the auditor already holds."""
    from .store import Store

    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db}")
    store = Store(db, read_only=True)
    try:
        from . import transparency

        proof = transparency.consistency_proof(
            transparency.leaf_hashes(store.receipts()), args.first, getattr(args, "size", None)
        )
        if proof is None:
            sys.exit(f"cannot prove consistency from size {args.first}")
        print(json.dumps(proof, indent=2, ensure_ascii=False))
    finally:
        store.close()


def _https_base(url: str, role: str) -> str:
    """Normalize a deployment URL to a scheme://netloc base under the
    remote-trust policy: HTTPS everywhere except loopback, where a
    schemeless host means a plain-HTTP dev server."""
    if "://" in url:
        base = urlsplit(url)
    else:
        probe = urlsplit(f"https://{url}")
        base = urlsplit(f"{'http' if _is_loopback(probe.hostname or '') else 'https'}://{url}")
    if base.scheme != "https" and not _is_loopback(base.hostname or ""):
        sys.exit(f"{role} requires HTTPS — loopback excepted")
    return f"{base.scheme}://{base.netloc}"


def _monitor(args: argparse.Namespace) -> None:
    """Watch a deployment's transparency log like a Certificate-Transparency
    monitor watches a CT log: pin the signed tree head, then require every
    later checkpoint to prove it extends the pinned one — a rewritten or
    forked log cannot produce the bridging nodes, so the monitor catches
    what a signature check alone never would. No local store needed: the
    pin lives in a small state file next to wherever the auditor runs this."""
    import time
    from datetime import UTC, datetime

    from . import logmonitor

    if getattr(args, "interval", None) is not None and (
        not math.isfinite(args.interval) or args.interval <= 0
    ):
        sys.exit("--interval must be a finite positive number")
    base = _https_base(args.url, "monitoring a remote deployment")
    import hashlib

    state_path = args.state or f"attest-monitor-{hashlib.sha256(base.encode()).hexdigest()[:12]}.json"
    issuer_src = args.issuer or base

    # --journal turns detection into evidence: every cycle mints a signed
    # monitor_observation receipt into this runtime's transparency log, so
    # a caught fork is itself an exportable, third-party-verifiable fact.
    # Mutating, so the runtime's single-writer lock applies — unlike the
    # default lock-free monitor.
    j_engine = None
    j_store = None
    journal_failed = {"v": False}  # a failed journal write must leak into the exit code
    if getattr(args, "journal", False):
        from .instance import acquire_instance_lock
        from .store import Store

        acquire_instance_lock(settings.data_dir)
        db = settings.data_dir / "attest.sqlite3"
        if not db.exists():
            print(f"note: initializing monitor journal at {db}", file=sys.stderr)
        j_store = Store(db)
        j_engine = _cli_engine(j_store)

    def _journal(
        ok: bool,
        lines: list[str],
        *,
        state,
        new_state,
        verdict,
        pin,
        wbase,
        head,
        doc,
        whead=None,
        crash=False,
        crash_pin=None,
    ) -> None:
        """Mint one monitor_observation for the cycle — including cycles that
        never reached the deployment, so an outage is durable evidence rather
        than a silent gap in the trail."""
        if j_engine is None:
            return
        # "ALERT" anywhere catches wrapped alerts too ('witness log: ALERT:
        # …') — a witness-log contradiction is alert evidence like any other.
        alert = verdict in ("diverged", "dishonest") or any("ALERT" in str(ln) for ln in lines)
        served_head = None
        _cp = (head or {}).get("checkpoint") if isinstance(head, dict) else None
        _p = _cp.get("payload") if isinstance(_cp, dict) else None
        if isinstance(_p, dict):
            served_head = {
                "checkpoint_id": _cp.get("id"),
                "tree_size": _p.get("tree_size"),
                "root_sha256": _p.get("root_sha256"),
            }

        def _pin_fields(s):
            if not isinstance(s, dict):
                return None
            return {k: s.get(k) for k in ("issuer_key", "tree_size", "root_sha256", "checkpoint_id")}

        if ok:
            if state is None:
                outcome = "pinned"
            elif _pin_fields(new_state) != _pin_fields(state):
                outcome = "advanced"
            else:
                outcome = "steady"
        elif alert:
            outcome = verdict if verdict in ("diverged", "dishonest") else "alert"
        else:
            outcome = "unverifiable"
        observation = {
            "observed_at": datetime.now(tz=UTC).isoformat(),
            "subject": {"url": base, "issuer_key": (doc or {}).get("issuer_key")},
            "outcome": outcome,
            "served_head": served_head,
            "pin_before": _pin_fields(state),
            "pin_after": _pin_fields(new_state),
            "witness_view": (
                {"url": wbase, "verdict": verdict, "pin_issuer_key": (pin or {}).get("issuer_key")}
                if wbase
                else None
            ),
            # On an alert — or a crash mid-evaluation — the served material
            # itself is the evidence, verbatim, so the signed record can be
            # re-checked against exactly what broke the verifier.
            "served_doc": head if (alert or crash) else None,
            "served_witness_pin": (pin if alert else None) or crash_pin,
            "served_witness_head": whead if (alert or crash) and whead else None,
        }
        try:
            obs_receipt = j_engine.issue_monitor_observation(observation)
            lines.append(f"journaled observation {obs_receipt.id[:24]}… ({outcome})")
        except Exception as exc:  # noqa: BLE001 — a failed journal write
            # must not silence the watch; the trail records the gap, and the
            # process exit code reports that a cycle went unrecorded.
            journal_failed["v"] = True
            lines.append(f"journal write failed: {exc}")

    def cycle() -> tuple[bool, list[str], dict | None, bool]:
        state = logmonitor.state_load(state_path)
        doc = head = None
        try:
            doc = _fetch_issuer_doc(issuer_src)
        except SystemExit as exc:
            lines = [f"issuer document: {exc.code}"]
            _journal(
                False,
                lines,
                state=state,
                new_state=state,
                verdict=None,
                pin=None,
                wbase=None,
                head=head,
                doc=doc,
            )
            return False, lines, state, False
        try:
            head = logmonitor.fetch_json(f"{base}/api/log/head")
        except ValueError as exc:
            lines = [str(exc)]
            _journal(
                False,
                lines,
                state=state,
                new_state=state,
                verdict=None,
                pin=None,
                wbase=None,
                head=head,
                doc=doc,
            )
            return False, lines, state, False

        def fetch_consistency(first: int, size: int):
            # NOT swallowed: a transport failure must not read as "the
            # deployment served no proof" — that mints a signed ALERT for a
            # DNS blip. The ValueError propagates through check() to the
            # cycle guard, which journals an unverifiable observation
            # naming the fetch failure instead of a false contradiction.
            return logmonitor.fetch_json(f"{base}/api/log/consistency?first={first}&size={size}")

        try:
            new_state, ok, lines = logmonitor.check(
                state, doc, head, fetch_consistency, datetime.now(tz=UTC).isoformat()
            )
        except Exception as exc:  # noqa: BLE001 — a hostile payload must fail
            # the cycle, not kill the watch: an unhandled shape inside
            # check() is recorded as an unverifiable observation (the
            # journal is exactly where 'the watch was attacked mid-cycle'
            # belongs), the pin is untouched, and the loop continues.
            lines = [f"monitor cycle crashed evaluating served material: {exc}"]
            _journal(
                False,
                lines,
                state=state,
                new_state=state,
                verdict=None,
                pin=None,
                wbase=None,
                head=head,
                doc=doc,
                crash=True,
            )
            return False, lines, state, False
        # check() rebuilds the state fresh each cycle — carry forward the
        # witness-log pins, or any cycle that doesn't refresh them (witness
        # outage, failed wlog check) silently drops the view the anchor
        # check pins against — and the next cycle would re-pin whatever the
        # witness serves, including the head that just failed. A fresh wlog
        # pin below overlays its slot.
        if new_state is not None and isinstance(state, dict) and isinstance(state.get("witness_logs"), dict):
            new_state["witness_logs"] = dict(state["witness_logs"])
        # Cross-view: compare what THIS monitor pinned against what an
        # independent witness deployment attests — two signed views of the
        # same issuer's log that either agree or expose a fork visible to
        # only one observer. Only compared after a successful check cycle:
        # a failed pin is no trustworthy view to compare from.
        #
        # Repinning policy: the local check already VERIFIED new_state, so a
        # witness availability problem (unreachable, malformed, unverifiable
        # view) reports the cycle as failed but must not freeze the pin — a
        # downed or DoS'd witness shouldn't stall honest advancement. Only a
        # `diverged` verdict blocks repinning: equal-size distinct roots mean
        # one of the two views sits on a fork, and pinning commits us to the
        # possibly-forked one — a human must reconcile that by hand.
        repin = True
        verdict = None
        pin = None
        wbase = None
        whead = None
        crash = False
        crash_pin = None
        if ok and new_state is not None and getattr(args, "witness", None):
            wbase = _https_base(args.witness, "witness")
            try:
                heads = logmonitor.fetch_json(f"{wbase}/api/witness/heads")
                # The pin's own fields are unsigned hints — the comparison
                # only believes the signed cosignature, and only under the
                # witness's certified lineage, so fetch its issuer doc too.
                wdoc = _fetch_issuer_doc(wbase)
            except ValueError as exc:
                ok = False
                lines.append(f"witness view unreachable: {exc}")
            except SystemExit as exc:
                ok = False
                lines.append(f"witness issuer document: {exc.code}")
            else:
                if not isinstance(heads, dict) or not isinstance(heads.get("pins"), list):
                    ok = False
                    lines.append("witness heads response is malformed — cannot compare views")
                else:
                    wlog_state = None
                    try:
                        wtrusted = logmonitor._trusted_set(wdoc)
                        # A revoked WITNESS key can still sign — it just can't
                        # vouch: the revocation is the deployment declaring the
                        # key suspect, so its attestations don't count as an
                        # independent second view (same discipline as
                        # --witness-url's named-requirement set).
                        from . import ledger as _ledger
                        from .models import Receipt as _Rc

                        _wrecs = []
                        for _x in wdoc.get("key_receipts") or []:
                            try:
                                _wrecs.append(_Rc.model_validate(_x))
                            except Exception:  # noqa: BLE001 — malformed entries can't revoke
                                continue
                        wtrusted -= set(_ledger.revoked_issuer_keys(_wrecs, issuer_key=wdoc["issuer_key"]))
                    except Exception as exc:  # noqa: BLE001 — hostile witness
                        # lifecycle material fails the cycle closed; it must
                        # not kill the watch or its journal.
                        ok = False
                        wtrusted = None
                        lines.append(f"witness lineage evaluation failed: {exc}")

                    # Pin the WITNESS's own log head too: a served
                    # witness_anchor only means 'in the published log' when
                    # it provably reconciles with the head THIS monitor
                    # pins — an anchor over a private per-victim fork
                    # verifies in isolation and means nothing. The fetch
                    # budget is capped per cycle: a witness answering with
                    # thousands of pins that each demand a consistency proof
                    # stalls the watch for days — beyond the cap the anchor
                    # reads unverifiable, never silently trusted.
                    _wfetch_budget = {"n": 8}

                    def _wconsistency(first: int, size: int):
                        if _wfetch_budget["n"] <= 0:
                            return None
                        _wfetch_budget["n"] -= 1
                        try:
                            return logmonitor.fetch_json(
                                f"{wbase}/api/log/consistency?first={first}&size={size}"
                            )
                        except ValueError:
                            return None

                    try:
                        whead = logmonitor.fetch_json(f"{wbase}/api/log/head")
                    except ValueError as exc:
                        ok = False
                        lines.append(f"witness log head unreachable: {exc}")
                    else:
                        prev_wlog = None
                        if isinstance(state, dict) and isinstance(state.get("witness_logs"), dict):
                            prev_wlog = state["witness_logs"].get(wbase)
                        if not isinstance(prev_wlog, dict):
                            prev_wlog = None  # corrupt slot never enters the check
                        try:
                            wlog_state, wok, wlines = logmonitor.check(
                                prev_wlog,
                                wdoc,
                                whead,
                                _wconsistency,
                                datetime.now(tz=UTC).isoformat(),
                            )
                        except Exception as exc:  # noqa: BLE001 — hostile
                            # witness-log material fails the cycle closed; it
                            # must not kill the watch or its journal.
                            wlog_state, wok, wlines = (
                                prev_wlog,
                                False,
                                [f"witness log check crashed: {exc}"],
                            )
                        for _wl in wlines:
                            lines.append(f"witness log: {_wl}")
                        if not wok:
                            ok = False
                    if wtrusted is not None:
                        # Pins key on the issuer's canonical LINEAGE identity —
                        # match any key inside the lineage we track, not just
                        # the tip our issuer doc happens to claim. A non-string
                        # issuer_key can never be a member (and would crash the
                        # hash lookup); unhashable served pins are skipped.
                        _ilineage = logmonitor._trusted_set(doc)
                        cand_pins = [
                            p
                            for p in heads["pins"]
                            if isinstance(p, dict)
                            and isinstance(p.get("issuer_key"), str)
                            and p["issuer_key"] in _ilineage
                        ]
                        # The witness controls serving order, so evaluation
                        # order is chosen HERE, deterministically: pins whose
                        # unsigned fields already hint at a fork (same size,
                        # different root) go first — agreeable decoys can't
                        # bury them past an evaluation cap — then a stable
                        # id key breaks every other tie so same-rank picks
                        # never depend on wire order.
                        _ours = new_state if isinstance(new_state, dict) else {}

                        def _porder(p: dict):
                            fork_hint = (
                                _ours.get("tree_size") is not None
                                and p.get("tree_size") == _ours["tree_size"]
                                and p.get("root_sha256") != _ours["root_sha256"]
                            )
                            return (not fork_hint, str(p.get("checkpoint_id") or p.get("id") or ""))

                        cand_pins.sort(key=_porder)
                        # Every pin whose unsigned fields hint at a fork is
                        # always compared; beyond that a witness has ≤2
                        # legitimate live pins per lineage, so 64 examined
                        # slots is generous — the remainder is REPORTED, not
                        # silently dropped. Combined with the fetch budget
                        # above, a 4 MB wall of pins can't stall the watch.
                        _rank = {
                            "agree": 0,
                            "unseen": 1,
                            "unverifiable": 2,
                            "diverged": 3,
                            "dishonest": 4,
                        }
                        if not cand_pins:
                            verdict, line, pin = (
                                "unseen",
                                "the witness has never cosigned this issuer — no second view exists",
                                None,
                            )
                        else:
                            verdict, line, pin = "agree", "views agree", cand_pins[0]
                            examined = 0
                            agree_ln = None
                            for cand in cand_pins:
                                if examined >= 64:
                                    break
                                examined += 1
                                try:
                                    v, ln = logmonitor.compare_views(
                                        new_state,
                                        cand,
                                        wtrusted,
                                        witness_pin=wlog_state,
                                        fetch_wconsistency=_wconsistency,
                                        issuer_lineage=_ilineage,
                                    )
                                except Exception as exc:  # noqa: BLE001 — the witness
                                    # view is remote input: a crash shape is an
                                    # unverifiable view, never a dead watch.
                                    v, ln = "unverifiable", f"cross-view crashed: {exc}"
                                    crash, crash_pin = True, cand
                                if v == "agree":
                                    agree_ln = ln
                                if _rank.get(v, 2) > _rank.get(verdict, 2):
                                    verdict, line, pin = v, ln, cand
                                if _rank.get(verdict, 2) == 4:
                                    break  # 'dishonest' is terminal — nothing worse to find
                            if verdict == "agree" and agree_ln:
                                line = agree_ln
                            if len(cand_pins) > examined:
                                line += f" (+{len(cand_pins) - examined} further pin(s) unexamined)"
                        lines.append(f"witness cross-view [{verdict}]: {line}")
                    if wlog_state is not None and new_state is not None:
                        # The monitor's own witness-log pin rides the state
                        # file alongside the issuer pin — persisted through
                        # the same repin discipline. Copied: an identity
                        # share between the two states would be circular.
                        new_state.setdefault("witness_logs", {})[wbase] = {
                            k: v for k, v in wlog_state.items() if k != "witness_logs"
                        }
                    if verdict in ("diverged", "dishonest"):
                        # Contradictory views — OR a witness serving
                        # verifiably false material (a bad anchor, a
                        # self-contradicting pin). Either way one view may
                        # be a fork: never repin past it.
                        ok = False
                        repin = False
                    elif verdict == "unverifiable":
                        ok = False
        _journal(
            ok,
            lines,
            state=state,
            new_state=new_state,
            verdict=verdict,
            pin=pin,
            wbase=wbase,
            head=head,
            doc=doc,
            whead=whead,
            crash=crash,
            crash_pin=crash_pin,
        )
        return ok, lines, new_state, repin

    try:
        while True:
            ok, lines, new_state, repin = cycle()
            if getattr(args, "json", False):
                print(json.dumps({"ok": ok, "state": new_state, "lines": lines}, ensure_ascii=False))
            else:
                for line in lines:
                    print(line)
            if new_state is not None and (ok or repin):
                try:
                    logmonitor.state_save(state_path, new_state)
                except OSError as exc:
                    sys.exit(f"cannot persist monitor state at {state_path}: {exc}")
            if args.once:
                # A journaled run that failed to journal reports failure — an
                # unrecorded cycle must not read as a clean exit.
                sys.exit(0 if ok and not journal_failed["v"] else 1)
            if not ok:
                if repin and new_state is not None:
                    print(
                        "watch continues — locally-verified head repinned; the "
                        "cross-view failure stays on the record"
                    )
                else:
                    print(f"watch continues — pinned state at {state_path} unchanged")
            time.sleep(args.interval)
    finally:
        if j_store is not None:
            j_store.close()


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
        forged = transparency.json_loads(body)
        forged["state"] = "attended_verified"  # the claim the record must refuse to carry

        pre = store.verify_journal()
        if pre["entries"] == 0 and pre["untracked_rows"]:
            stamped = store.journal_baseline()
            print(f"store predates journaling — stamped {stamped} rows as baseline")

        class _Rollback(Exception):
            pass

        report = None
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
        # The demo exists to PROVE detection — an intact verdict on a forged
        # row, or a store that fails to restore clean, is a failed demo, not
        # a quiet zero.
        if report is None or report["intact"]:
            sys.exit("tamper-demo failed — the journal did not detect the forged row")
        after = store.verify_journal()
        print(f"after rollback — intact: {after['intact']}, entries: {after['entries']}")
        if not after["intact"]:
            sys.exit("tamper-demo failed — the store did not restore to a clean journal")
    finally:
        store.close()


def _journal(args: argparse.Namespace) -> None:
    store = _must_store(read_only=not args.baseline)
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
    store = Store(db, read_only=True)
    try:
        stats = store.stats()
        journal = store.verify_journal()
        all_receipts = store.receipts()
        chain_ok, chain_detail = verify_chain(all_receipts)
        inbox_path = settings.data_dir / "webhooks.sqlite3"
        queue: dict = {}
        if inbox_path.exists():
            inbox = WebhookInbox(inbox_path, read_only=True)
            try:
                queue = inbox.counts()
            finally:
                inbox.close()
        by_state = ", ".join(f"{k}={n}" for k, n in stats["visits"]["by_state"].items())
        # A zero-receipt store isn't unhealthy — but "healthy" must not read as
        # "the ledger is populated". Report the empty state loudly and on its
        # own line so a wiped deployment can't hide behind a green word — and
        # when the journal records receipt-table writes, zero receipts is not
        # "fresh", it's a wipe: the journal just testified records existed.
        empty = not all_receipts
        receipt_writes = 0
        if empty:
            receipt_writes = store._conn.execute(
                "SELECT COUNT(*) FROM journal WHERE table_name='receipts'"
            ).fetchone()[0]
        # A row with no journal entry at all means an out-of-band write (or
        # journal rows truncated after the last pin) — never "healthy".
        healthy = (
            journal["intact"]
            and chain_ok
            and journal["untracked_rows"] == 0
            and not (empty and receipt_writes)
        )
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
        # Transparency head: the Merkle root over the receipt chain — one
        # commitment to the whole log. The latest signed checkpoint and how
        # many leaves postdate it show how stale the proofs are. Checkpoint
        # receipts are not leaves (engine.log_leaves) — counting them would
        # report a different log than the checkpoints and /api/log/head serve.
        from .transparency import root as _mth

        content = [r for r in all_receipts if r.payload.get("record_type") != "log_checkpoint"]
        tree_root = _mth([bytes.fromhex(r.payload_hash) for r in content]).hex()
        checkpoints = [r for r in all_receipts if r.payload.get("record_type") == "log_checkpoint"]
        last_cp = checkpoints[-1].payload if checkpoints else None
        uncommitted = len(content) - int(last_cp["tree_size"]) if last_cp else len(content)
        from . import logmonitor as _lm

        w_pins = _lm.witness_heads(store, "")["pins"]
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "healthy": healthy,
                        "empty": empty,
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
                        "transparency": {
                            "tree_size": len(content),
                            "root_sha256": tree_root,
                            "checkpoint_size": (last_cp or {}).get("tree_size"),
                            "leaves_since_checkpoint": uncommitted,
                            "witness_pins": len(w_pins),
                        },
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
        cp_note = (
            f"checkpoint at size {last_cp['tree_size']} ({uncommitted} newer leaf/leaves)"
            if last_cp
            else "no checkpoint yet (`attest checkpoint` to sign one)"
        )
        print(f"log:      {len(content)} leaves — Merkle root {tree_root[:24]}…; {cp_note}")
        if w_pins:
            print(
                f"witness:  this deployment cosigns {_pl(len(w_pins), 'issuer head')} "
                "— published at /api/witness/heads"
            )
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
        if receipt_writes:
            print(
                f"status:   ATTENTION — journal records {receipt_writes} receipt write(s) "
                "but the receipts table is empty (the journal itself is intact)"
            )
        elif empty and healthy:
            # EMPTY only when the store is clean — an empty store with
            # untracked rows or journal damage is a signal, not a fresh start.
            print("status:   EMPTY — no signed records yet")
        else:
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
    if settings.webhook_signing_key:
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

    from .disputepack import build_case_pack, log_member
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
        for visit in store.visits(site_id=site.id, limit=None):
            receipt = store.receipt_for_visit(visit.id)
            if receipt is None:
                continue  # open visits have no signed record to export
            bundle = ReviewBundle(
                kind="attest.review_bundle/1", original=receipt, reviews=store.reviews_for(visit.id)
            )
            entries.append((visit, bundle, countersign_status(bundle)))
        if not entries:
            sys.exit(f"no signed records for {site.name} yet")
        engine = _cli_engine(store)
        cosign_fn = None
        witnesses = getattr(args, "witness", None) or []
        if witnesses:
            from . import ledger, logmonitor

            issuer_doc = ledger.issuer_document(engine.signer.public_key_b64, store.receipts())

            def cosign_fn(cp):
                cosigs, anchors = [], {}
                for url in witnesses:
                    base = url.rstrip("/")
                    try:
                        cosig, line, anchor = logmonitor.cosign_at(
                            base,
                            issuer_doc,
                            cp.model_dump(mode="json"),
                            lambda pinned: engine.consistency_proof(pinned, int(cp.payload["tree_size"])),
                        )
                    except ValueError as exc:
                        print(f"witness {base}: unreachable ({exc})", file=sys.stderr)
                        continue
                    if cosig:
                        cosigs.append(cosig)
                        if anchor:
                            anchors[cosig["id"]] = anchor
                        print(f"witness {base}: {line}")
                    else:
                        print(f"witness {base}: {line}", file=sys.stderr)
                return cosigs, anchors

        data = build_case_pack(
            store,
            settings.data_dir / "media",
            site,
            entries,
            redact_media=args.redact_media,
            manifest_signer=lambda m: engine.issue_export_manifest(site, m),
            issuer_key=engine.signer.public_key_b64,
            tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"site:{site.id}", t),
            log_fn=lambda rs, pack_members=None: log_member(
                engine, rs, cosign_fn=cosign_fn, pack_members=pack_members
            ),
        )
        out = Path(args.out or f"case-{site.id}.zip")
        # Self-check BEFORE shipping: an export that doesn't verify is worse
        # than no export — catch a corrupted build here, not at review, and
        # never leave the bad bytes on disk for someone to ship anyway.
        import io
        import zipfile

        from .app import _verify_case_pack

        with zipfile.ZipFile(io.BytesIO(data)) as z:
            ok, why = _verify_case_pack(z, engine.signer.public_key_b64)
        if not ok:
            sys.exit(f"refusing to write — pack self-check failed: {why}")
        _atomic_write(out, data)
        note = " (media withheld — digests preserved)" if args.redact_media else ""
        print(f"wrote {out}{note} — {len(entries)} visit record(s); verify with `python verify_case.py .`")
        print("self-check: pack verifies under this deployment's issuer key")
        if args.tamper_twin:
            from .disputepack import tamper_twin

            tdata, desc = tamper_twin(data, attack=args.attack, visit=getattr(args, "tamper_visit", None))
            tpath = Path(args.tamper_twin)
            _atomic_write(tpath, tdata)
            print(f"wrote {tpath} — doctored: {desc}")
            # Mirror-image self-check: a twin that verifies must never ship.
            with zipfile.ZipFile(io.BytesIO(tdata)) as z:
                ok2, why2 = _verify_case_pack(z, engine.signer.public_key_b64)
            if ok2:
                sys.exit("WARNING: tampered twin verifies — do not ship it")
            print(f"twin self-check: correctly refused — {why2}")
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
        # The engine lets the battery mint a real signed pack, so the
        # forged-verifier attack exercises the issuer pin end to end —
        # its receipts roll back with the attempt like everything else.
        # When no signer can load (unreachable KMS, keyless store) the rest
        # of the battery still runs — the attack just reports SKIPPED.
        try:
            engine = _cli_engine(store)
        except Exception as exc:  # noqa: BLE001
            print(f"note: no signer available ({exc}) — pack-minting attacks will skip")
            engine = None
        out = run(store, settings.data_dir / "media", inbox=inbox, engine=engine)
        if out.get("baseline_note"):
            print(out["baseline_note"])
        caught = skipped = errors = boundaries = 0
        for r in out["results"]:
            mark = (
                "SKIPPED"
                if r["caught"] is None
                else (
                    "ERROR  "
                    if r["caught"] == "error"
                    else (
                        "BOUNDARY — EXPECTED MISS"
                        if r.get("boundary") and r["caught"] is False
                        else ("CAUGHT " if r["caught"] else "MISSED ")
                    )
                )
            )
            skipped += r["caught"] is None
            errors += r["caught"] == "error"
            caught += r["caught"] is True
            boundaries += bool(r.get("boundary") and r["caught"] is False)
            print(f"{mark} {r['attack']}\n        {r['detail']}")
        attempted = len(out["results"]) - skipped - errors
        suffix = f" — {skipped} not applicable on this store" if skipped else ""
        err_suffix = f" — {errors} battery error(s)" if errors else ""
        bound_suffix = (
            f" — {boundaries} documented detection boundary (external anchoring required)"
            if boundaries
            else ""
        )
        print(
            f"{caught}/{attempted} attacks caught{suffix}{bound_suffix}{err_suffix} — "
            f"store {'unchanged' if out['unchanged'] else 'CHANGED (investigate)'}"
        )
        # A MISSED attack is a failed self-test — exit 1 so a CI gate can't
        # read "store unchanged" as success on an undetected tamper. Documented
        # boundary cases are expected misses and do not fail the run; an ERROR
        # verdict always does — the battery itself is suspect.
        if not out["unchanged"] or errors or caught + boundaries < attempted:
            sys.exit(1)
    finally:
        store.close()
        if inbox is not None:
            inbox.close()


def _split_demo(args: argparse.Namespace) -> None:
    """The fork a single observer can never catch: one issuer key signs two
    histories, a witness pins one, the monitor pins the other — and the
    cross-view reports the one verdict no honest log can produce. Runs in
    scratch space (no runtime touched, no lock needed); only the emitted
    evidence document is real output."""
    from pathlib import Path

    from .splitdemo import run

    story = run(Path(args.out) if args.out else None)
    print(
        f"\ndivergence proven: the witness signed size {story['fork_head']['tree_size']} root "
        f"{story['fork_head']['root_sha256'][:16]}…, the monitor pinned size "
        f"{story['true_head']['tree_size']} root {story['true_head']['root_sha256'][:16]}… — "
        "same issuer lineage, two histories, one caught fork."
    )
    print(
        "boundary: the demo fabricates the fork; every signature, proof, and "
        "the verdict itself is real — it shows detection, not which side lied."
    )


def _judge(args: argparse.Namespace) -> None:
    """The judge's walkthrough, printed where a judge actually looks: the
    terminal. Pure output — reads nothing, locks nothing."""
    # These counts shift whenever the demo corpus regrows — read the shipped
    # artifacts so the printed numbers can never stale.
    from pathlib import Path

    n, nr, nv = "every", "every", "every"
    docs = Path(__file__).resolve().parents[2] / "docs"
    try:
        _mf = json.loads((docs / "site-manifest.json").read_text(encoding="utf-8"))
        n = str(len(_mf["payload"]["artifacts"]))
    except Exception:
        pass
    try:
        nr = str(len(list((docs / "demo-receipts").glob("*.json"))))
    except Exception:
        pass
    try:
        _vm = json.loads((docs / "vectors-manifest.json").read_text(encoding="utf-8"))
        nv = str(len(_vm if isinstance(_vm, list) else _vm["vectors"]))
    except Exception:
        pass
    # The battery's size is a property of attackdemo.run()'s attempt list —
    # count the appends so this paragraph can never drift from the battery.
    try:
        import inspect as _inspect

        from . import attackdemo as _ad

        _src = _inspect.getsource(_ad)
        na = str(_src.count("results.append"))
        nb = str(_src.count("boundary=True"))
    except Exception:
        na, nb = "several", "one"
    # The gauntlet's artifact count lives in verifyjs.py's seq list — count
    # the ["name","expect"] rows so the claim tracks the page it describes.
    try:
        import re as _re

        from . import verifyjs as _vj

        _vsrc = _inspect.getsource(_vj)
        _seq = _re.search(r"const seq=\[(.*?)\];", _vsrc, _re.S)
        ng = str(len(_re.findall(r'\["[^"\]]+","', _seq.group(1)))) if _seq else "nine"
    except Exception:
        ng = "nine"
    print(
        """\
Attest — records, not verdicts. The ten-minute path:

  Zero install (hosted):
    0. rather watch than click? https://josepha-mayo.github.io/attest/tour.html
       — twelve self-playing beats, every frame the live artifact
    1. green VERIFIED … https://josepha-mayo.github.io/attest/verify.html#sample-pack
    2. red FAILED   … https://josepha-mayo.github.io/attest/verify.html#sample-pack-tampered
       (one doctored field — the contested visit's observed span padded past
        its schedule — caught; click "name what changed" and the verifier
        points at the forged field itself)
    3. the attack gallery + caught fork + real-API sweep: same page, one click each
       + pipeline.svg — the seven verification gates, each attack pinned to
         the gate that kills it
       + #sample-pack-pinned — the pack verified against an issuer doc it
         didn't ship (TOFU over a second transport)
       + #verify-self — the page hashes its own bytes against the pack's
         signed pin: PINNED or PIN MISMATCH
       + #verify-site — the site attests itself: a signed manifest pins
         __N__ artifact sha256s; hash every file → SITE VERIFIED or TAMPER
       + #tamper-lab — commit the attack yourself: rewrite a signed field
         in-page, download your doctored pack, watch the signature refuse it
       + #gauntlet — one click verifies all __G__ shipped artifacts against
         the shared oracle and scores agreement: ORACLE AGREEMENT __G__/__G__
       + #compare-packs — two packs at once: each verified, then their signed
         membership diffed and the two log heads reconciled ("both verify" and
         "both identical" are different claims)
       + #compare-earlier — the same compare, weeks apart: the pack I kept vs
         today's export, reconciled offline through embedded signed checkpoint
         hops — no server contacted
    4. after a green stamp: open index.html — the pack hands you its own
       record browser, which re-verifies every record itself
    5. the product face, no install: demo-dashboard.html, demo-visit.html (the
       contested record), demo-household.html (+ -es), demo-integrity.html —
       plus the scoped links each side gets texted: demo-family.html (+ -es)
       and demo-worker.html (+ -es) — snapshots of the running app
    6. the raw layer: demo-receipts.html — all __R__ signed receipts, drawn as
       the hash chain itself, each a one-click verify.html deep link —
       incl. the verify/diff --attest receipts (the audit, audited — a new
       schema minted alongside the old; identical claims dedupe per schema)
       (+ anatomy.html — one receipt decomposed field-by-field, chain links
       walkable)
    7. the adversarial corpus: vectors.html — __V__ conformance packs the oracle
       says must pass or fail; each a deep link landing on the verdict

  With the repo:
    attest demo           # emulator + server + an eight-day story, prints a URL
      … open /integrity   # the deployment auditing itself, each section signed
      … append ?lang=es   # household/worker surfaces in Spanish (accessibility)
    attest tamper-demo    # 5 seconds: forge a visit in-place, watch the
                          # journal catch it, roll back — non-destructive
    attest attack-demo    # __A__ real tamper attempts — all caught on the
                          # demo store except __B__ deliberate EXPECTED MISS
                          # naming the journal's boundary (unkeyed chain —
                          # only external anchoring bounds it); zero skips
                          # (a SKIPPED row means the fixture lacked a target)
    attest split-demo     # a witness + monitor catching a forked log
    attest verify pack.zip --witness-url <w> --witness-threshold 2
                          # require k-of-n named witnesses to have vouched
    attest export --tamper-twin twin.zip --attack forged-verifier
    attest diff pack.zip twin.zip --html report.html
                          # append-only audit — names the moved field, proves
                          # the log only grew (or calls the fork), writes the
                          # page a mediator attaches to the dispute
    attest verify pack.zip --attest
                          # sign the verdict itself into the journal — the
                          # mediator's "I checked" becomes evidence too
    attest status && attest doctor

  To read: JUDGE.md (scoring map) · THREATMODEL.md (limits are the point) ·
           FRICTIONLOG.md (17 API-friction entries)
""".replace("__N__", n)
        .replace("__R__", nr)
        .replace("__V__", nv)
        .replace("__A__", na)
        .replace("__B__", nb)
        .replace("__G__", ng)
    )


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
        # The pin note rides on stderr — with --json, stdout must carry only
        # the machine-readable report a pipeline parses.
        print(
            f"pinned to issuer key served by {args.issuer_url} "
            f"({len(extra)} lifecycle receipt(s)) — authenticity rides on transport",
            file=sys.stderr,
        )

    # --attest signs the reconciliation itself: a pack_comparison receipt
    # binds both pack digests, the machine verdict (log_heads + anomaly
    # count), and the verifier identity — the coordinator's "the log
    # provably grew" is evidence too. The report path is forced so the
    # attestation binds the same log_heads the JSON surface reports.
    attest_engine = None
    if getattr(args, "attest", False):
        try:
            attest_engine = _attestation_engine()
        except (OSError, RuntimeError) as exc:
            sys.exit(f"attest: --attest unavailable — {exc}")

    def _attest_comparison(report: dict):
        if attest_engine is None:
            return None
        import hashlib
        import json as _json

        from .packdiff import diff_report as _dr

        # The digests ride the report — the exact bytes load_artifact
        # verified, not a re-read of paths that could have been swapped.
        events_sha = hashlib.sha256(
            _json.dumps(report["events"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        detail = (
            f"log heads: {report['log_heads'] or 'unpaired'} — "
            f"{report['anomalies']} anomaly(ies), "
            f"{'clean' if report['clean'] else 'anomalous'}"
        )
        try:
            receipt = attest_engine.issue_pack_comparison(
                report["old"]["sha256"],
                report["new"]["sha256"],
                report["old"]["bytes"],
                report["new"]["bytes"],
                report["log_heads"],
                report["clean"],
                report["anomalies"],
                events_sha,
                detail,
                _checker_verifier("attest.packdiff.diff_report", _dr),
                context={
                    "issuer_pin": key,
                    "lifecycle_sha256": _lifecycle_fp(extra),
                },
            )
        except Exception as exc:  # noqa: BLE001 — a signing failure is loud
            sys.exit(f"attest: could not sign the comparison — {exc}")
        print(
            f"Attestation {receipt.id}: comparison signed into this deployment's journal",
            file=sys.stderr,
        )
        return receipt

    try:
        if getattr(args, "json", False) or getattr(args, "html", None) or attest_engine is not None:
            from .packdiff import diff_report

            report = diff_report(args.old, args.new, key=key, extra_key_receipts=extra)
            if key:
                report["pin"] = {"issuer_key": key}
                if getattr(args, "issuer_url", None):
                    report["pin"]["issuer_url"] = args.issuer_url
                    report["pin"]["lifecycle_receipts"] = len(extra)
            att = _attest_comparison(report)
            if att is not None:
                # The report names the receipt that signs it — a mediator's
                # attachable page points back at the audit entry itself.
                import hashlib as _hl
                import json as _jl

                report["attestation"] = {
                    "receipt_id": att.id,
                    "pseudo_id": att.visit_id,
                    "events_sha256": _hl.sha256(
                        _jl.dumps(report["events"], sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                }
            # --html writes BEFORE the --json exit: the flags compose ("also
            # write"), not either/or — the page renders the same event stream
            # the JSON and text lines carry.
            if getattr(args, "html", None):
                from .packdiff import diff_html

                _atomic_write(args.html, diff_html(report))
            if getattr(args, "json", False):
                import json as _json

                print(_json.dumps(report, indent=2))
                sys.exit(0 if report["clean"] else 1)
            # --html / --attest: the text lines and the page render the same
            # event stream — `line` rides the report so the two can never
            # disagree.
            for e in report["events"]:
                if e.get("line"):
                    print(e["line"])
            anomalies = report["anomalies"]
            if getattr(args, "html", None):
                print(f"html report written: {args.html}")
        else:
            lines, anomalies = diff(args.old, args.new, key=key, extra_key_receipts=extra)
            for line in lines:
                print(line)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, zipfile.BadZipFile) as exc:
        sys.exit(f"cannot compare: {exc}")
    if anomalies:
        sys.exit(1)


def _deliveries(args: argparse.Namespace) -> None:
    from .inbox import WebhookInbox

    inbox_path = settings.data_dir / "webhooks.sqlite3"
    if not inbox_path.exists():
        sys.exit(f"no webhook inbox at {inbox_path}")
    inbox = WebhookInbox(inbox_path, read_only=not args.requeue)
    try:
        if args.requeue:
            # Requeue mutates the durable inbox — hold the writer lock so a
            # requeue can't race a live server's claim cycle.
            from .instance import acquire_instance_lock

            acquire_instance_lock(settings.data_dir)
            print(json.dumps({"requeued": inbox.requeue(), "queue": inbox.counts()}))
        else:
            entries = inbox.entries()
            total = sum(inbox.counts().values())
            out = {"counts": inbox.counts(), "entries": entries}
            if len(entries) < total:
                # entries() caps at 1000 — say so rather than let a flooded
                # queue read as smaller than it is.
                out["truncated"] = f"showing {len(entries)} of {total} deliveries"
            print(json.dumps(out, indent=2))
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
    store = Store(db, read_only=True)
    try:
        visit = store.visit(args.visit)
        if visit is None:
            _explain_attestation(store, args.visit, as_json=getattr(args, "json", False))
            return
        site = store.site(visit.site_id)
        schedule = store.schedule(visit.schedule_id) if visit.schedule_id else None
        evidence = store.evidence_for(visit.id)
        receipt = store.receipt_for_visit(visit.id)
        engine = _cli_engine(store, read_only=True)
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
        failed = False
        if bundle:
            # Trust anchors in this deployment's issuer lineage — never in the
            # receipt's self-declared key (a forged receipt would vouch for
            # its own attacker key and read OK). The verified receipt chain
            # plus the loaded signer's rotation links are the deployment's
            # attested key set.
            from .ledger import descendant_issuer_keys, trusted_issuer_keys, verify_chain

            trusted = reviews.trusted_issuer_keys()
            all_rcpts = store.receipts()
            chain_ok, _chain_detail = verify_chain(all_rcpts)
            if chain_ok:
                rots = [r for r in all_rcpts if r.visit_id.startswith("key:")]
                for k in {r.public_key for r in all_rcpts}:
                    trusted |= trusted_issuer_keys(k, rots) | descendant_issuer_keys(k, rots)
            ok, why = verify_bundle(bundle, trusted_keys=trusted)
            failed = failed or not ok
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
            or r.visit_id.startswith(f"late:{visit.site_id}:")
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
        if failed:
            sys.exit(1)
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
        or r.visit_id.startswith(f"late:{visit.site_id}:")
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
        # Content-keyed pseudo-ids carry a `:<fp>` suffix — a bare
        # coverage:/digest: window resolves iff exactly one version exists.
        matches = [r for r in store.receipts() if r.visit_id.startswith(ident + ":")]
        if len(matches) == 1:
            receipt = matches[0]
        elif len(matches) > 1:
            names = "\n".join(f"  {r.visit_id}" for r in matches)
            sys.exit(f"{ident} has {len(matches)} signed versions — name one fully:\n{names}")
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
        if not ok:
            sys.exit(1)
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
    elif rtype == "late_event":
        e = p.get("event", {})
        c = p.get("contradicts", {})
        w = c.get("window") or []
        print(
            f"  {e.get('event_type', 'event')} occurred {e.get('occurred_at')} — "
            f"delivered {p.get('delivered_at')}"
        )
        print(
            f"  contests {c.get('visit_id')} ({c.get('claim')}) — "
            f"its signed window {w[0][:19] if w else '?'} -> {w[1][11:19] if len(w) > 1 else '?'}"
        )
        print("  the earlier receipt stands unedited; the ledger admits the claim was contradicted")
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
    elif rtype == "pack_verification":
        v = p.get("verifier") or {}
        ctx = p.get("context") or {}
        print(
            f"  verifier {v.get('name')} {v.get('version')} ({v.get('checker', 'unknown checker')}) ran over"
        )
        print(f"  sha256:{str(p.get('pack_sha256'))[:32]}… ({p.get('pack_bytes')} bytes)")
        print(f"  and returned: {str(p.get('verdict')).upper()} — {p.get('detail')}")
        if "context" not in p:
            print("  trust context: not recorded (pre-context attestation)")
        else:
            pin = ctx.get("issuer_pin")
            print(
                "  pinned issuer: " + (str(pin)[:24] + "…" if pin else "self-declared (the pack's own key)")
            )
        if ctx.get("witness_policy"):
            w = ctx["witness_policy"]
            print(
                f"  witness policy: {w.get('threshold')}-of-{len(w.get('required') or [])} required witnesses"
            )
        if ctx.get("live_log"):
            print(f"  live-log cross-check: {ctx['live_log'].get('detail')}")
        print("  the audit act itself, signed — it never claims the verdict is")
        print("  right. Re-run the pinned verifier on those exact bytes to check.")
    elif rtype == "pack_comparison":
        v = p.get("verifier") or {}
        ctx = p.get("context") or {}
        print(f"  differ {v.get('name')} {v.get('version')} ({v.get('checker', 'unknown checker')}) compared")
        print(f"  old sha256:{str(p.get('pack_a_sha256'))[:32]}… ({p.get('pack_a_bytes')} bytes)")
        print(f"  new sha256:{str(p.get('pack_b_sha256'))[:32]}… ({p.get('pack_b_bytes')} bytes)")
        print(
            f"  and reported: {p.get('log_heads') or 'unpaired'} — "
            f"{p.get('anomalies')} anomaly(ies), "
            f"{'clean' if p.get('clean') else 'anomalous'}"
        )
        if "context" not in p:
            print("  trust context: not recorded (pre-context attestation)")
        else:
            pin = ctx.get("issuer_pin")
            print(
                "  pinned issuer: " + (str(pin)[:24] + "…" if pin else "self-declared (the packs' own keys)")
            )
        print("  the reconciliation itself, signed — it never claims the")
        print("  comparison is right. Re-run attest diff on those bytes to check.")
    print()
    print("Boundary: a signature attests what the record claims and that it is")
    print("intact under the issuer key — never identity, attendance, or truth.")
    if not ok:
        sys.exit(1)


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
    store = _must_store(read_only=not args.apply)
    inbox_path = settings.data_dir / "webhooks.sqlite3"
    inbox = WebhookInbox(inbox_path, read_only=not args.apply) if inbox_path.exists() else None
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
            _atomic_write(args.out, receipt.model_dump_json(indent=2))
            print(f"wrote {args.out} — verify with `attest verify {args.out}`")
    elif args.out:
        _atomic_write(args.out, json.dumps(report, indent=2))
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

    s = sub.add_parser("verify", help="verify a signed artifact — pack, receipt, checkpoint, anchor, or URL")
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
        "trust to pre-rotation packs; a URL pin also cross-checks the pack's "
        "signed log head against the deployment's LIVE /api/log/head, so a "
        "forked history served only to this auditor fails",
    )
    s.add_argument(
        "--json",
        action="store_true",
        help="emit the verdict as one JSON object ({ok, kind, detail, pinned, "
        "warnings}) — exit 1 on failure, so a CI gate needs no prose parsing",
    )
    s.add_argument(
        "--badge",
        default=None,
        metavar="SVG_PATH",
        help="also write the verdict as a self-contained SVG shield — a CI "
        "badge for evidence packs; written red on failure, not withheld",
    )
    s.add_argument(
        "--attest",
        action="store_true",
        help="sign the verdict itself into this deployment's journal — a "
        "pack_verification receipt binding sha256(pack bytes), the verdict, "
        "and the verifier's content identity, so a mediator's audit is itself "
        "auditable. Requires an initialized ATTEST_DATA_DIR store; pack "
        ".zip inputs only; FAIL verdicts are signed too — a forged pack "
        "attested as forged is evidence",
    )
    s.add_argument(
        "--badge-link",
        default=None,
        metavar="URL",
        help="wrap the badge shield in a link to this URL (e.g. a verifier "
        "page), so a badge opened standalone still leads to the check",
    )
    s.add_argument(
        "--witness-key",
        action="append",
        default=None,
        metavar="KEY_B64",
        help="require a counter-signature from at least one of these witness keys "
        "(repeatable) — sigsum-style named-witness policy: 'cosigned by N witnesses' "
        "counts anyone, this gates on the witnesses YOU trust",
    )
    s.add_argument(
        "--witness-url",
        action="append",
        default=None,
        metavar="URL",
        help="require a counter-signature from the named witness deployment "
        "(repeatable) — its own issuer document resolves the certified key "
        "lineage, so the requirement survives the witness's key rotations",
    )
    s.add_argument(
        "--witness-threshold",
        type=int,
        default=1,
        metavar="N",
        help="require counter-signatures from at least N of the named witnesses "
        "(k-of-n policy — a single cooperating witness can't vouch alone)",
    )
    s.add_argument(
        "--checkpoint",
        default=None,
        metavar="FILE",
        help="signed tree-head doc (`attest checkpoint --out`) an inclusion "
        "proof or consistency bridge verifies against",
    )
    s.add_argument(
        "--against",
        default=None,
        metavar="FILE",
        help="the older signed head a consistency bridge must extend from",
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
    s.add_argument(
        "--witness",
        action="append",
        default=[],
        metavar="URL",
        help="stamp witness counter-signatures into the pack's log checkpoint — "
        "repeatable; each witness only signs a head it proves extends its pin",
    )
    s.add_argument(
        "--tamper-twin",
        default=None,
        metavar="PATH",
        help="also write a deliberately doctored copy of the pack to PATH — one "
        "signed field changed, so the twin must FAIL verification; for demos "
        "and QA of the verifier itself",
    )
    s.add_argument(
        "--attack",
        choices=["duration", "missing-record", "smuggled-file", "forged-verifier"],
        default="duration",
        help="which attack --tamper-twin plants: duration doctors a signed field, "
        "missing-record deletes a committed record, smuggled-file injects an "
        "uncommitted member, forged-verifier swaps the embedded checker",
    )
    s.add_argument(
        "--tamper-visit",
        default=None,
        metavar="VISIT_ID",
        help="for --attack duration: doctor this visit's bundle instead of the "
        "shortest observed stay — e.g. the story's contested visit",
    )
    s.set_defaults(fn=_export)

    s = sub.add_parser(
        "attack-demo",
        help="run real tamper attempts (forge, delete, truncate, key swap, replay, media swap), "
        "all rolled back",
    )
    s.set_defaults(fn=_attack_demo)

    s = sub.add_parser(
        "split-demo",
        help="fabricate a split-view log fork in scratch space — a witness pins one "
        "history, the monitor pins the other — and watch the cross-view catch it "
        "as a signed divergence observation",
    )
    s.add_argument(
        "--out",
        metavar="DIR",
        default=None,
        help="write the self-verifying evidence document "
        "(divergence-checkpoint.json — verify with `attest verify`) to DIR",
    )
    s.set_defaults(fn=_split_demo)

    s = sub.add_parser(
        "judge",
        help="print the ten-minute judge walkthrough — hosted deep links, the "
        "repo path, and the docs that carry the scoring evidence",
    )
    s.set_defaults(fn=_judge)

    s = sub.add_parser(
        "diff",
        help="compare two exports — appended records are normal; vanished or altered ones are anomalies; "
        "signed log heads reconcile offline through the newer export's embedded checkpoint chain",
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
    s.add_argument(
        "--html",
        metavar="PATH",
        help="also write a self-contained HTML report of the diff — the "
        "attachable version a mediator or filing gets; renders the same "
        "events the text output prints",
    )
    s.add_argument(
        "--attest",
        action="store_true",
        help="sign the comparison itself into this deployment's journal — a "
        "pack_comparison receipt binding both pack digests, the log_heads "
        "verdict, and the verifier identity; the mediator's reconciliation "
        "becomes evidence too. Requires an initialized ATTEST_DATA_DIR store",
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
        "checkpoint",
        help="sign the transparency log's Merkle tree head — the checkpoint "
        "receipt every pack's log_checkpoint.json proves inclusion against",
    )
    s.add_argument("--out", default=None, help="also write the checkpoint document here")
    s.add_argument(
        "--timestamp",
        action="store_true",
        help="notarize the checkpoint file on public OpenTimestamps calendars (requires --out)",
    )
    s.add_argument(
        "--witness",
        action="append",
        default=[],
        metavar="URL",
        help="ask a cosigning witness (another Attest deployment's base URL) to "
        "counter-sign the checkpoint — repeatable; the witness only signs a "
        "head it can prove extends its own pin, so a forked log can't collect",
    )
    s.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="PREFIX",
        help=(
            "embed receipts whose visit_id starts with PREFIX plus their "
            "inclusion proofs in the written doc (repeatable) — e.g. "
            "--include monitor: exports the signed monitor trail as one "
            "self-verifying evidence file"
        ),
    )
    s.set_defaults(fn=_checkpoint)

    s = sub.add_parser(
        "prove",
        help="print the RFC 6962 inclusion proof for one receipt id",
    )
    s.add_argument("receipt_id", help="receipt id (rcpt_…) to prove inclusion for")
    s.set_defaults(fn=_prove)

    s = sub.add_parser(
        "consistency",
        help="prove the log extended a checkpoint: RFC 6962 consistency proof "
        "from an earlier tree size to the current head",
    )
    s.add_argument("first", type=int, help="earlier tree size to prove extension from")
    s.add_argument(
        "--size",
        type=int,
        default=None,
        help="bound the proof to the tree at this size — the checkpoint the "
        "auditor holds usually sits behind the live tip",
    )
    s.set_defaults(fn=_consistency)

    s = sub.add_parser(
        "monitor",
        help="watch a deployment's transparency log — pin the signed tree head, "
        "then require each later checkpoint to extend it by consistency proof",
    )
    s.add_argument("url", help="deployment base URL (or its issuer-doc URL)")
    s.add_argument(
        "--issuer",
        default=None,
        help="pin to a local attest.issuer/1 document instead of fetching the well-known one",
    )
    s.add_argument("--state", default=None, help="monitor state file (default: attest-monitor-<hash>.json)")
    s.add_argument("--interval", type=int, default=60, help="seconds between checks (default: 60)")
    s.add_argument("--once", action="store_true", help="run one check and exit — the CI-gate mode")
    s.add_argument("--json", action="store_true", help="emit each cycle's verdict as one JSON object")
    s.add_argument(
        "--journal",
        action="store_true",
        help=(
            "sign every cycle into this runtime's transparency log as a "
            "monitor_observation receipt — detection becomes exportable "
            "evidence (mutating; takes the runtime's writer lock). Export "
            "the trail with `attest checkpoint --out doc.json --include monitor:`"
        ),
    )
    s.add_argument(
        "--witness",
        default=None,
        metavar="URL",
        help=(
            "an independent witness deployment to cross-view against — after each "
            "cycle, compare my pinned head with the head this witness attests "
            "(/api/witness/heads); a same-size different-root divergence fails"
        ),
    )
    s.set_defaults(fn=_monitor)

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
        help="visit id, or an attestation (coverage:/digest:/export:/source: pseudo id — a bare "
        "coverage:/digest: window resolves when exactly one signed version exists — or receipt id)",
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
                default="observed,late,blackout,sub_lapse,late_delivery,early_out,unmatched,liveview",
                metavar="PATTERNS",
                help="day-pattern cycle: observed,late,blackout,sub_lapse,early_out,no_show,"
                "unmatched,liveview,late_delivery",
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
                "unmatched,sub_lapse,liveview,late_delivery "
                "(e.g. --days 5 --story observed,late,no_show,early_out,observed)",
            )
        s.set_defaults(fn=fn)

    args = p.parse_args(argv)
    import sqlite3 as _sqlite3

    from .store import StoreCorrupt

    try:
        args.fn(args)
    except httpx.HTTPError as exc:
        # Seed/replay/monitor/witness talk HTTP — a connection refused or an
        # unexpected 500 must never end as a traceback.
        sys.exit(f"attest: request failed — {exc}")
    except (StoreCorrupt, OSError, ValueError, RuntimeError, _sqlite3.Error) as exc:
        # Fail closed with an error line, never a traceback — the surfaces that
        # report "valid/invalid" must never crash ambiguously. StoreCorrupt is
        # the store's own fail-closed signal; ValueError covers malformed
        # artifact JSON (pydantic), bad --from/--to dates, and missing files
        # the subcommand didn't phrase for a human. RuntimeError covers the
        # writer lock's contention refusal (names the holding pid); sqlite3
        # errors cover a locked/corrupt/non-db attest.sqlite3 — the read-only
        # commands open it too, so the catch lives here, not per-command.
        sys.exit(f"attest: {exc}")


if __name__ == "__main__":
    main()
