"""``attest`` command line.

attest serve [--port 8000]
attest seed  [--ring-url http://127.0.0.1:8787] [--public-url http://127.0.0.1:8000]
attest demo                # seeds, registers the webhook with the sandbox, prints next steps
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta

import httpx
from ring_sandbox import RingClient

from .config import settings
from .models import Role, Schedule, Site, Worker


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    from .app import create_app

    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")


def _seed(args: argparse.Namespace) -> dict:
    """Create a site bound to the sandbox's doorbell + contact sensor, a worker, and a schedule
    whose window starts now (so the very next arrival cue opens a matched visit)."""
    with RingClient(settings.ring_access_token, base_url=args.ring_url) as ring:
        bundles = ring.devices(include=["capabilities"])
    cam = next((b for b in bundles if b.capabilities and b.capabilities.is_camera), None)
    sensor = next((b for b in bundles if b.name.lower().endswith("sensor")), None)
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
        checkin_token=args.token or Worker().checkin_token,
    )
    now = datetime.now(tz=UTC)
    # Replayed scenarios are back-dated by their length + 60s, so open the window well before now.
    schedule = Schedule(
        site_id=site.id,
        worker_id=worker.id,
        window_start=now - timedelta(hours=3),
        window_end=now + timedelta(minutes=args.window_minutes),
        expected_minutes=args.expected_minutes,
        service="Morning care visit",
    )
    with httpx.Client(base_url=args.public_url, timeout=10) as api:
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
        "checkin_url": f"{args.public_url}/checkin/{worker.checkin_token}",
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
    print(f"  open {out['checkin_url']}          (worker's phone)")
    print(f"  ring-sandbox play home_aide_visit --url {args.ring_url} --speed 60   (90-min visit in ~90s)")
    print(
        f"  ring-sandbox play short_visit     --url {args.ring_url} --speed 20   (12-min visit -> shortfall)"
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

    for name, fn in (("seed", _seed), ("demo", _demo)):
        s = sub.add_parser(name)
        s.add_argument("--ring-url", default=settings.ring_base_url)
        s.add_argument("--public-url", default=settings.public_base_url)
        s.add_argument("--site-name", default="Alvarez residence")
        s.add_argument("--worker-name", default="Maria Chen")
        s.add_argument("--token", help="fixed check-in token (handy for demos)")
        s.add_argument("--window-minutes", type=int, default=120)
        s.add_argument("--expected-minutes", type=int, default=90)
        s.set_defaults(fn=fn)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
