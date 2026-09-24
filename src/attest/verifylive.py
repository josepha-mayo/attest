"""One-shot official-API verification sweep: a fresh access token in, a
timestamped evidence report out.

Every check is read-only except WHEP — opening a live-view session is a
real stream (it lands in the account's Event History as an on-demand
entry), so it is opened and immediately closed, and the report says so.

The report is evidence for the submission record and for the README's
"officially verified" claims: only checks that pass here may be described
as verified. A failed check is honest data — it stays in the report with
the API's own error, never silently dropped.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from ring_sandbox import RingAPIError, RingClient

_OFFER = (
    "v=0\r\n"
    "o=- 0 0 IN IP4 127.0.0.1\r\n"
    "s=attest-verify-live\r\n"
    "t=0 0\r\n"
    "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
    "a=recvonly\r\n"
)


def _masked(value: str | None, keep: int = 8) -> str | None:
    """Identifiers are evidence; full ids/tokens never leave the report."""
    if not value:
        return value
    return value[:keep] + "…" if len(value) > keep else value


def run(client: RingClient, *, do_whep: bool = True) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def check(name: str, fn) -> Any:
        """Run one probe. Returns the parsed result or records the failure —
        a check that fails is evidence about the API, not a crash."""
        try:
            result = fn()
        except RingAPIError as exc:
            checks.append(
                {"check": name, "status": "fail", "detail": f"HTTP {exc.status_code}: {exc.code or exc}"}
            )
            return None
        except Exception as exc:  # noqa: BLE001 — report, don't hide
            checks.append({"check": name, "status": "fail", "detail": f"{type(exc).__name__}: {exc}"})
            return None
        checks.append(result)
        return result.get("_result")

    check(
        "users/me",
        lambda: {
            "check": "users/me",
            "status": "pass",
            "detail": "account reachable",
            "_result": client.me(),
        },
    )

    def _integration():
        ai = client.app_integration()
        return {
            "check": "app-integration state",
            "status": "pass",
            "detail": f"status={ai.status}" if ai else "no integration linked on this account",
        }

    check("app-integration state", _integration)

    check(
        "subscriptions",
        lambda: {
            "check": "subscriptions",
            "status": "pass",
            "detail": (
                f"{len(subs)} subscription(s): "
                + ", ".join(sorted({getattr(s, "plan_id", "?") or "?" for s in subs}))
                if (subs := client.subscriptions())
                else "none on this account"
            ),
        },
    )

    def _devices():
        ds = client.devices(("capabilities", "status"))
        return {
            "check": "devices",
            "status": "pass",
            "detail": f"{len(ds)} device(s) returned" if ds else "0 devices",
            "_result": ds,
        }

    devices = check("devices", _devices)

    camera = None
    if devices:
        for bundle in devices:
            caps = bundle.capabilities
            if caps is not None and caps.is_camera:
                camera = bundle.device
                break
        if camera is None:
            camera = devices[0].device
            checks.append(
                {
                    "check": "camera present",
                    "status": "warn",
                    "detail": "no device reported video capabilities; using the first device",
                }
            )

    if camera is not None:
        cam_id = camera.id
        check(
            "device status",
            lambda: {
                "check": "device status",
                "status": "pass",
                "detail": f"device {_masked(cam_id)} status endpoint returned",
                "_result": client.status(cam_id),
            },
        )

        check(
            "event history",
            lambda: {
                "check": "event history",
                "status": "pass",
                "detail": _history_detail(pg := client.events_page(cam_id)),
                "_result": pg,
            },
        )

        def _media():
            snap = client.snapshot_latest(
                cam_id, datetime.now(tz=UTC) - timedelta(hours=24), datetime.now(tz=UTC)
            )
            if not snap.content:
                return {"check": "media download", "status": "fail", "detail": "empty body"}
            return {
                "check": "media download",
                "status": "pass",
                "detail": (
                    f"{len(snap.content)} bytes {snap.content_type} "
                    f"sha256:{hashlib.sha256(snap.content).hexdigest()[:16]}"
                ),
            }

        check("media download", _media)

        if do_whep:
            check("WHEP live view", lambda: _whep(client, cam_id))
        else:
            checks.append({"check": "WHEP live view", "status": "skip", "detail": "--no-whep"})
    else:
        for name in ("device status", "event history", "media download", "WHEP live view"):
            checks.append({"check": name, "status": "skip", "detail": "no device returned"})

    generated = datetime.now(tz=UTC)
    counts = {k: sum(1 for c in checks if c["status"] == k) for k in ("pass", "fail", "warn", "skip")}
    return {
        "generated_at": generated.isoformat(timespec="seconds"),
        "base_url": str(client.base_url),
        "token_hint": _masked(client.access_token),
        "checks": [{k: v for k, v in c.items() if not k.startswith("_")} for c in checks],
        "summary": counts,
        "note": (
            "Checks that pass here are the only ones describable as 'officially verified'. "
            "The WHEP check opens and immediately closes a real live-view session — it may "
            "appear in the account's Event History as an on-demand entry."
        ),
    }


def _history_detail(page) -> str:
    events = list(page.data or [])
    if not events:
        return "0 events in the first page"
    kinds = sorted({ev.attributes.event_type for ev in events})
    newest = events[0].attributes.started_at.isoformat(timespec="seconds")
    return f"{len(events)} event(s) in first page; types: {', '.join(kinds)}; newest {newest}"


def _whep(client: RingClient, device_id: str) -> dict[str, Any]:
    """Open then immediately close a real WHEP session — the one check that
    exercises the live-view path end to end."""
    session = client.whep_session(device_id=device_id, sdp_offer=_OFFER)
    detail = "session opened (201 + Location + SDP answer)"
    try:
        client.whep_close(session)
        detail += ", closed cleanly"
    except Exception as exc:  # noqa: BLE001 — an orphaned session must be reported
        detail += f", close failed: {type(exc).__name__} — session may linger"
        return {"check": "WHEP live view", "status": "warn", "detail": detail}
    return {"check": "WHEP live view", "status": "pass", "detail": detail}
