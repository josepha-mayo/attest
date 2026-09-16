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
    if args.days < 1:
        sys.exit("--days must be at least 1")
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
        for day in range(args.days):
            day_start = start + timedelta(days=day)
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
            if day == args.no_show_day:
                print(f"Day {day}: no events replayed — the schedule will lapse to no_observation")
                continue
            # Poll history once at window start so coverage rows bracket the visit
            # (poll observations sit on the same logical clock as the events).
            api.post("/api/poll").raise_for_status()
            previous_offset = 0
            for index, step in enumerate(sorted(scenario.steps, key=lambda step: step.offset_s)):
                time.sleep((step.offset_s - previous_offset) / args.speed)
                at = day_start + timedelta(seconds=step.offset_s)
                advance(api, at)
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
                drain(api)
                api.post("/api/poll").raise_for_status()
                if index == 0 and args.auto_checkin:
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
                print(f"Replayed {step.type} at {at.isoformat()} (local simulation)")
                previous_offset = step.offset_s
            # One active visit per site: close this day's before the next day's schedule.
            for visit in api.get("/api/state").json()["visits"]:
                if visit["state"] in ("open", "in_progress", "unmatched"):
                    api.post(f"/api/visits/{visit['id']}/close").raise_for_status()
        # Push the clock past the last window + grace so elapsed schedules lapse to no_observation.
        end = start + timedelta(
            days=args.days - 1,
            minutes=args.window_minutes + settings.arrival_grace_minutes + 1,
        )
        api.post("/api/poll").raise_for_status()
        advance(api, end)
        api.post("/api/sweep").raise_for_status()
        visits = api.get("/api/state").json()["visits"]
        for visit in visits:
            if visit["state"] in ("open", "in_progress", "unmatched"):
                api.post(f"/api/visits/{visit['id']}/close").raise_for_status()
        if args.worker_review:
            targets = [v for v in api.get("/api/state").json()["visits"] if v["state"] != "no_observation"]
            if not targets:
                sys.exit("no observed visit to post the worker review against")
            # /api/state lists newest first — review the most recent observed visit.
            target = targets[0]
            response = api.post(f"/api/visits/{target['id']}/review-link")
            response.raise_for_status()
            decision, statement = (
                ("confirm", "Confirmed — I was present for the scheduled window.")
                if args.worker_review == "confirm"
                else (
                    "dispute",
                    "I dispute this record — I arrived before the first observation shown.",
                )
            )
            posted = api.post(
                response.json()["path"],
                auth=None,
                data={"decision": decision, "statement": statement},
            )
            if posted.status_code != 200:
                sys.exit("Simulated worker review rejected; inspect the record.")
            print(f"Worker review posted on {target['id']} ({decision})")
        print(
            f"Replay records are ready for review at {args.public_url}; no live Ring attendance was verified."
        )


def _verify(args: argparse.Namespace) -> None:
    """Verify a downloaded bundle offline: signatures, revision order, chain anchoring."""
    from pathlib import Path

    from . import reviews
    from .models import ReviewBundle

    bundle = ReviewBundle.model_validate(json.loads(Path(args.bundle).read_text()))
    key = args.key or bundle.original.public_key
    ok, reason = reviews.verify_bundle(bundle, public_key=key)
    if not ok:
        sys.exit(f"verification failed: {reason}")
    pinned = " (against the supplied issuer key)" if args.key else ""
    print(f"OK{pinned}: {reason}.")
    stance = reviews.countersign_status(bundle)
    print(f"Worker stance: {stance['state']} — {stance['detail']}")
    print("Note: a valid signature proves record integrity under that key, not physical truth.")


def _tamper_demo(args: argparse.Namespace) -> None:
    """Non-destructive: forge one row inside a transaction, show the journal catching
    it, then roll back — the store is left exactly as it was."""
    from .store import Store

    store = Store(settings.data_dir / "attest.sqlite3")
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
    from .store import Store

    store = Store(settings.data_dir / "attest.sqlite3")
    try:
        if args.baseline:
            stamped = store.journal_baseline()
            print(f"stamped {stamped} existing rows as journal baseline")
        report = store.verify_journal()
        print(json.dumps(report, indent=2))
        if not report["intact"]:
            sys.exit(1)
    finally:
        store.close()


def _deliveries(args: argparse.Namespace) -> None:
    from .inbox import WebhookInbox

    inbox_path = settings.data_dir / "webhooks.sqlite3"
    if not inbox_path.exists():
        sys.exit(f"no webhook inbox at {inbox_path}")
    inbox = WebhookInbox(inbox_path)
    try:
        if args.requeue:
            print(json.dumps({"requeued": inbox.requeue(), "queue": inbox.counts()}))
        else:
            print(json.dumps({"counts": inbox.counts(), "entries": inbox.entries()}, indent=2))
    finally:
        inbox.close()


def _retention(args: argparse.Namespace) -> None:
    """Print a non-destructive lifecycle report for the local runtime. Deletes nothing."""
    from . import retention
    from .inbox import WebhookInbox
    from .store import Store

    policy = retention.RetentionPolicy(
        visits_days=settings.retention_visits_days,
        media_days=settings.retention_media_days,
        deliveries_days=settings.retention_deliveries_days,
        grants_days=settings.retention_grants_days,
        seen_days=settings.retention_seen_days,
        late_events_days=settings.retention_late_days,
    )
    store = Store(settings.data_dir / "attest.sqlite3")
    inbox_path = settings.data_dir / "webhooks.sqlite3"
    inbox = WebhookInbox(inbox_path) if inbox_path.exists() else None
    media_dir = settings.data_dir / "media"
    try:
        if args.apply:
            try:
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


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        prog="attest", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
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

    s = sub.add_parser("verify", help="verify a downloaded bundle.json offline")
    s.add_argument("bundle", help="path to the exported original + review chain JSON")
    s.add_argument("--key", default=None, help="issuer public key (base64) to pin against")
    s.set_defaults(fn=_verify)

    s = sub.add_parser("deliveries", help="show durable webhook inbox state, or requeue failed deliveries")
    s.add_argument(
        "--requeue",
        action="store_true",
        help="move all failed deliveries back to pending with a fresh attempt budget",
    )
    s.set_defaults(fn=_deliveries)

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
        s.set_defaults(fn=fn)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
