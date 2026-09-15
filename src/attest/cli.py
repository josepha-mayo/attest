"""``attest`` command line.

attest serve [--port 8000]
attest seed  [--ring-url http://127.0.0.1:8787] [--public-url http://127.0.0.1:8000]
attest demo                # seeds, registers the webhook with the sandbox, prints next steps
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


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    from .app import create_app

    if settings.admin_token is None:
        sys.exit("Set ATTEST_ADMIN_TOKEN to at least 32 random characters before starting Attest.")
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


def _demo(args: argparse.Namespace) -> None:
    out = _seed(args)
    hook = f"{args.public_url}/webhooks/ring"
    r = httpx.post(
        f"{args.ring_url}/_sandbox/webhooks",
        json={"url": hook, "signing_key": settings.ring_webhook_key},
    )
    r.raise_for_status()
    print(f"\nsandbox will deliver signed webhooks to {hook}")
    print("\nNext:")
    print(f"  open {args.public_url}/            (dashboard)")
    print(f"  issue a visit-scoped check-in link from {out['dashboard_url']} after the first event")
    print(f"  ring-sandbox play home_aide_visit --url {args.ring_url} --speed 60   (90-min visit in ~90s)")
    print(
        f"  ring-sandbox play short_visit     --url {args.ring_url} --speed 20   (12-min visit -> shortfall)"
    )


def _replay(args: argparse.Namespace) -> None:
    from ring_sandbox import webhooks
    from ring_sandbox.scenarios import BUILTIN

    if not settings.admin_token or not math.isfinite(args.speed) or args.speed <= 0:
        sys.exit("Replay requires admin authentication and a finite positive speed.")
    for address in (args.ring_url, args.public_url):
        parsed = urlsplit(address)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in ("127.0.0.1", "localhost", "::1")
            or parsed.username
            or parsed.password
        ):
            sys.exit("Replay only targets local HTTP services, never real Ring devices.")
    scenario = BUILTIN[args.scenario]
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
        if not clock["ready"]:
            response = api.post(
                "/api/replay/start", json={"at": (datetime.now(UTC) - timedelta(days=1)).isoformat()}
            )
            response.raise_for_status()
            clock = response.json()
        start = datetime.fromisoformat(clock["now"])
        seeded = _seed(args)
        state_response = sandbox.get("/_sandbox/state")
        state_response.raise_for_status()
        devices = state_response.json()["devices"]
        previous_offset = 0
        for index, step in enumerate(sorted(scenario.steps, key=lambda step: step.offset_s)):
            time.sleep((step.offset_s - previous_offset) / args.speed)
            at = start + timedelta(seconds=step.offset_s)
            response = api.post("/api/replay/advance", json={"at": at.isoformat()})
            response.raise_for_status()
            device_id = (
                seeded["camera"]
                if step.device is None
                else next(d["id"] for d in devices if step.device in (d["id"], d["name"]))
            )
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
            deadline = time.monotonic() + 60
            while True:
                response = api.post("/api/process-webhooks")
                response.raise_for_status()
                queue = response.json()["queue"]
                if queue.get("failed") or queue.get("rejected"):
                    sys.exit("Replay delivery failed; inspect the queue before continuing.")
                if not queue.get("pending") and not queue.get("processing"):
                    break
                if time.monotonic() > deadline:
                    sys.exit("Replay stopped while waiting for persisted event processing.")
                time.sleep(0.05)
            if index == 0 and args.auto_checkin:
                visits = api.get("/api/state").json()["visits"]
                for visit in visits:
                    if visit["state"] == "open" and visit["schedule_id"] == seeded["schedule"]:
                        response = api.post(f"/api/visits/{visit['id']}/checkin-link")
                        response.raise_for_status()
                        if api.post(response.json()["path"], auth=None).status_code != 200:
                            sys.exit(
                                "Simulated check-in rejected. Inspect the record without exposing the link."
                            )
            print(f"Replayed {step.type} at {at.isoformat()} (local simulation)")
            previous_offset = step.offset_s
        visits = api.get("/api/state").json()["visits"]
        for visit in visits:
            if visit["state"] in ("open", "in_progress", "unmatched"):
                api.post(f"/api/visits/{visit['id']}/close").raise_for_status()
        if not visits:
            end = max(
                start + timedelta(seconds=scenario.length_s),
                start + timedelta(minutes=args.window_minutes + settings.arrival_grace_minutes + 1),
            )
            api.post("/api/replay/advance", json={"at": end.isoformat()}).raise_for_status()
            api.post("/api/sweep").raise_for_status()
        print(
            f"Replay records are ready for review at {args.public_url}; no live Ring attendance was verified."
        )


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        prog="attest", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=_serve)

    for name, fn in (("seed", _seed), ("demo", _demo), ("replay", _replay)):
        s = sub.add_parser(name)
        s.add_argument("--ring-url", default=settings.ring_base_url)
        s.add_argument("--public-url", default=settings.public_base_url)
        s.add_argument("--site-name", default="Alvarez residence")
        s.add_argument("--worker-name", default="Maria Chen")
        s.add_argument("--window-minutes", type=int, default=120)
        s.add_argument("--expected-minutes", type=int, default=90)
        s.add_argument("--camera-only", action="store_true", help="leave the optional contact sensor unbound")
        if name == "replay":
            from ring_sandbox.scenarios import BUILTIN

            s.add_argument("scenario", choices=sorted(BUILTIN))
            s.add_argument("--speed", type=float, default=60)
            s.add_argument(
                "--auto-checkin", action="store_true", help="simulate a worker self-report locally"
            )
        s.set_defaults(fn=fn)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
