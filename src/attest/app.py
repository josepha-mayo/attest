"""HTTP surface: Ring webhook receiver, worker check-in, dashboard, receipts, verification."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import sqlite3
import statistics
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, UploadFile
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from ring_sandbox import RingAPIError, RingClient, webhooks

from . import ledger, retention, taxonomy
from .config import Settings
from .config import settings as default_settings
from .corroborate import corroboration
from .disputepack import build_case_pack, build_pack
from .engine import NotYetAdmissible, VisitEngine
from .i18n import pick as pick_lang
from .i18n import strings as lang_strings
from .inbox import WebhookInbox
from .ledger import Signer
from .media import MediaStore
from .models import (
    HouseholdStatementInput,
    Receipt,
    ReplayTime,
    RequeueDeliveries,
    ResolutionInput,
    RetentionApply,
    ReviewBundle,
    ReviewInput,
    Schedule,
    Site,
    Visit,
    VisitState,
    Worker,
    utcnow,
)
from .poller import HistoryPoller
from .reviews import ReviewService, verify_bundle
from .setup import SetupService
from .store import Store, StoreCorrupt
from .summarize import build as build_summarizer
from .triage import attention_items, deterministic_brief, run_triage

log = logging.getLogger("attest")
_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _register_template_helpers() -> None:
    from .timeline import close_reason_label, kind_label, state_label

    _TEMPLATES.env.globals["kind_label"] = kind_label
    _TEMPLATES.env.globals["state_label"] = state_label
    _TEMPLATES.env.globals["close_reason_label"] = close_reason_label
    # Signed payload fields carry ISO strings — the `t` macros apply `|iso` so
    # datetimes and ISO strings render through one local-tz path.
    _TEMPLATES.env.filters["iso"] = lambda x: (
        x if isinstance(x, datetime) else (datetime.fromisoformat(str(x)) if x else None)
    )


_register_template_helpers()

_MAX_WEBHOOK_BYTES = 256 * 1024
_MAX_VERIFY_BYTES = 32 * 1024 * 1024
_MAX_BODY_BYTES = 1024 * 1024


def create_app(
    settings: Settings | None = None,
    *,
    store: Store | None = None,
    ring: RingClient | None = None,
    signer: Signer | None = None,
    sweep_interval_s: float = 30.0,
) -> FastAPI:
    s = settings or default_settings
    s.data_dir.mkdir(parents=True, exist_ok=True)
    store = store or Store(s.data_dir / "attest.sqlite3")
    if ring is None:
        stored_auth = store.setting("ring_auth") or {}
        ring = RingClient(
            stored_auth.get("access_token") or s.ring_access_token,
            base_url=s.ring_base_url,
            media_origins=[o.strip() for o in s.ring_media_origins.split(",") if o.strip()],
            refresh_token=stored_auth.get("refresh_token")
            or (s.ring_refresh_token.get_secret_value() if s.ring_refresh_token else None),
            token_url=s.ring_token_url,
            client_id=s.ring_client_id,
            on_token_refresh=lambda tokens: store.put_setting("ring_auth", tokens),
        )
    if signer is None:
        from .keycustody import load_or_create_signer

        signer = load_or_create_signer(s.key_path, kms_key_id=s.kms_key_id, aws_region=s.aws_region)
    media = MediaStore(s.data_dir / "media")
    summarizer = build_summarizer(
        s.summarizer, tz=s.timezone, model_id=s.bedrock_model_id, region=s.aws_region
    )
    engine = VisitEngine(store, ring, signer, media, summarizer, s)
    inbox = WebhookInbox(s.data_dir / "webhooks.sqlite3")
    # Record the deployment's actual webhook posture — `attest status` runs in
    # a separate process without the server's env; this journaled setting is
    # how it learns whether intake was armed at last boot.
    store.put_setting(
        "webhook_intake",
        {
            "armed": bool(s.ring_webhook_key) and s.poll_history_seconds <= 0,
            "polling": s.poll_history_seconds > 0,
            "max_age_s": s.webhook_max_age_s,
        },
    )
    reviews = ReviewService(store, signer, engine.clock)
    setup = SetupService(store, ring, engine.clock, s.arrival_grace_minutes)

    def process_webhook() -> bool:
        job = inbox.claim()
        if job is None:
            return False
        try:
            if not s.ring_webhook_key:
                raise ValueError("webhook signing key not configured")
            ev = webhooks.parse(job["raw_body"], signing_key=s.ring_webhook_key, signature=job["signature"])
            outcome = engine.ingest(ev)
            reason = outcome.ignored_reason or ""
            rejected = reason in (
                "account mismatch",
                "ingestion source changed; reconciliation required",
            ) or ("not bound to a site" in reason)
            inbox.complete(job, "rejected" if rejected else "done")
        except NotYetAdmissible as exc:
            # Early, not poison: retry at the admissibility instant and never
            # let early arrivals exhaust the attempt budget into "failed".
            inbox.fail(
                job,
                "future_timestamp",
                retry_at=exc.admissible_at.timestamp(),
                terminal=False,
            )
        except Exception as exc:
            inbox.fail(job, type(exc).__name__)
            log.warning("queued webhook processing failed: %s", type(exc).__name__)
        return True

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async def sweeper():
            while True:
                await asyncio.sleep(sweep_interval_s)
                try:
                    changed = await asyncio.to_thread(engine.sweep)
                    for v in changed:
                        log.info("sweep: visit %s -> %s", v.id, v.state)
                    for site in store.sites():
                        d = await asyncio.to_thread(
                            engine.maybe_period_digest, site, s.digest_interval_seconds
                        )
                        if d:
                            log.info("sweep: period digest %s issued for site %s", d.id, site.id)
                except Exception:  # noqa: BLE001
                    log.exception("sweep failed")

        async def history_poller():
            poller = HistoryPoller(engine, store, ring)
            log.info("history polling every %ss (webhook-less mode)", s.poll_history_seconds)
            while True:
                try:
                    n = await asyncio.to_thread(poller.poll_once)
                    if n:
                        log.info("history poll ingested %d event(s)", n)
                except Exception:  # noqa: BLE001
                    log.exception("history poll failed")
                await asyncio.sleep(s.poll_history_seconds)

        stopping = asyncio.Event()

        async def webhook_worker():
            while not stopping.is_set():
                try:
                    worked = await asyncio.to_thread(process_webhook)
                except Exception as exc:
                    log.warning("webhook inbox unavailable: %s", type(exc).__name__)
                    worked = False
                if not worked:
                    try:
                        await asyncio.wait_for(stopping.wait(), timeout=0.25)
                    except TimeoutError:
                        pass

        worker_task = asyncio.create_task(webhook_worker())
        tasks = []
        if sweep_interval_s > 0 and not s.replay_mode:
            tasks.append(asyncio.create_task(sweeper()))
        if s.poll_history_seconds > 0:
            tasks.append(asyncio.create_task(history_poller()))
        try:
            yield
        finally:
            stopping.set()
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await worker_task
            inbox.close()

    basic = HTTPBasic(auto_error=False)

    async def authorize(request: Request):
        if request.url.path in ("/webhooks/ring", "/healthz"):
            return
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            expected_origin = str(request.base_url).rstrip("/")
            if request.headers.get("sec-fetch-site") == "cross-site" or (
                origin is not None and origin != expected_origin
            ):
                raise HTTPException(403, "cross-origin writes are not allowed")
        if request.url.path.startswith(("/checkin/", "/review/", "/family/")):
            return
        if s.admin_token is None:
            raise HTTPException(503, "Configure ATTEST_ADMIN_TOKEN before using the application")
        credentials = await basic(request)
        if (
            credentials is None
            or not secrets.compare_digest(
                credentials.password.encode(), s.admin_token.get_secret_value().encode()
            )
            or credentials.username != "admin"
        ):
            raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Basic"})

    app = FastAPI(title="Attest", version="0.1.0", lifespan=lifespan, dependencies=[Depends(authorize)])

    @app.middleware("http")
    async def privacy_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.middleware("http")
    async def bound_request_body(request: Request, call_next):
        limit = (
            _MAX_WEBHOOK_BYTES
            if request.url.path == "/webhooks/ring"
            else _MAX_VERIFY_BYTES
            if request.url.path == "/verify"
            else _MAX_BODY_BYTES
        )
        try:
            declared = int(request.headers.get("content-length", "0"))
        except ValueError:
            declared = 0
        if declared > limit:
            return JSONResponse({"error": "request body too large"}, status_code=413)
        if request.method in ("POST", "PUT", "PATCH"):
            # Content-Length can be absent (chunked) or lie — bound the actual
            # stream, then cache it so form/body parsing replays the same bytes.
            received = bytearray()
            async for chunk in request.stream():
                received += chunk
                if len(received) > limit:
                    return JSONResponse({"error": "request body too large"}, status_code=413)
            request._body = bytes(received)
        return await call_next(request)

    app.state.store, app.state.engine, app.state.ring, app.state.signer = (
        store,
        engine,
        ring,
        signer,
    )
    app.state.settings, app.state.media = s, media
    app.state.inbox = inbox
    tz = ZoneInfo(s.timezone)

    def render(request: Request, name: str, **ctx) -> HTMLResponse:
        return _TEMPLATES.TemplateResponse(
            request,
            name,
            {
                "settings": s,
                "tz": tz,
                "now": engine.clock.now() if engine.clock.snapshot()["ready"] else utcnow(),
                "clock": engine.clock.snapshot(),
                "summarizer": summarizer.name,
                **ctx,
            },
        )

    # ------------------------------------------------------------------ Ring webhook

    @app.post("/webhooks/ring")
    async def ring_webhook(request: Request) -> JSONResponse:
        if s.poll_history_seconds > 0:
            return JSONResponse(
                {"error": "history polling is enabled; webhook intake disabled"}, status_code=409
            )
        if not s.ring_webhook_key:
            return JSONResponse(
                {"error": "no Ring webhook signing key configured — set ATTEST_RING_WEBHOOK_KEY"},
                status_code=503,
            )
        chunks = bytearray()
        async for chunk in request.stream():
            if len(chunks) + len(chunk) > _MAX_WEBHOOK_BYTES:
                return JSONResponse({"error": "payload too large"}, status_code=413)
            chunks.extend(chunk)
        raw = bytes(chunks)
        try:
            ev = webhooks.parse(
                raw,
                signing_key=s.ring_webhook_key,
                signature=request.headers.get(webhooks.SIGNATURE_HEADER),
                max_age_s=s.webhook_max_age_s,
            )
        except webhooks.SignatureError as exc:
            stale = "freshness" in str(exc)
            return JSONResponse(
                {
                    "error": (
                        "stale delivery — meta.time outside the freshness window"
                        if stale
                        else "invalid signature"
                    )
                },
                status_code=401,
            )
        except ValueError:
            return JSONResponse({"error": "invalid webhook payload"}, status_code=400)
        if ev.occurred_at.tzinfo is None:
            # A naive timestamp can't be ordered against aware clocks — reject at
            # intake rather than let it burn inbox retries into a TypeError.
            return JSONResponse(
                {"error": "event timestamps must be timezone-aware (ISO 8601 with offset)"},
                status_code=400,
            )
        try:
            added = await asyncio.to_thread(
                inbox.enqueue,
                f"{ev.meta.account_id}:{ev.request_id}",
                raw,
                request.headers[webhooks.SIGNATURE_HEADER],
            )
        except ValueError:
            return JSONResponse({"error": "conflicting delivery identifier"}, status_code=409)
        except (sqlite3.Error, OverflowError):
            return JSONResponse({"error": "webhook inbox unavailable; retry delivery"}, status_code=503)
        return JSONResponse({"status": "queued" if added else "already_received"}, status_code=202)

    # ------------------------------------------------------------------ worker check-in

    def _dead_link(request: Request, what: str, status_code: int = 404):
        if what == "family view":
            mechanics = (
                "Family view links are visit-scoped and expire after 7 days — "
                "the link itself is the authorization to view that one record."
            )
            gates = "reading the record"
        else:
            mechanics = (
                "Worker check-in and review links are visit-scoped, expire, and are "
                "single-use — a link that was already used or has expired cannot be reopened."
            )
            gates = "checking in" if what == "check-in" else "adding a statement"
        tail = "invalid or expired." if what == "family view" else "invalid, expired, or already used."
        ctx = {
            "detail": f"This {what} link is {tail}",
            "mechanics": mechanics,
            "gates": gates,
        }
        if what == "family view":
            # The only failure page a family member can hit — honor ?lang so the
            # household isn't dead-ended in a language they didn't choose.
            s = lang_strings(pick_lang(request.query_params.get("lang")))
            ctx.update(
                html_lang=s["lang"],
                title=s["dead_title"],
                heading=s["dead_heading"],
                detail=s["dead_family_detail"],
                mechanics=s["dead_family_mechanics"],
                cta=s["dead_cta"],
                gates_full=s["dead_gates_family"],
                gates=None,
            )
        resp = render(request, "link_expired.html", **ctx)
        resp.status_code = status_code
        return resp

    def _not_found(request: Request, what: str, back_href: str = "/", back_label: str = "the dashboard"):
        """A styled 404 for browser-facing record pages — a stale bookmark or
        retention-deleted visit should never hit raw JSON."""
        resp = render(
            request,
            "link_expired.html",
            title="Record not found",
            heading="Record not found",
            detail=(
                f"No {what} exists at this address — it may have been "
                "mistyped, or the record was removed by a retention purge."
            ),
            mechanics="Signed records are append-only; nothing here was silently edited or hidden.",
            cta="Open",
            back_href=back_href,
            back_label=back_label,
        )
        resp.status_code = 404
        return resp

    @app.exception_handler(404)
    async def _catch_all_404(request: Request, exc: HTTPException):
        """A mistyped URL in a browser gets the styled page; API clients and
        non-GET requests keep the JSON detail. Never leak raw JSON to someone
        exploring the console."""
        accept = request.headers.get("accept", "")
        if request.method == "GET" and "text/html" in accept:
            return _not_found(request, "page")
        return JSONResponse({"detail": exc.detail}, status_code=404)

    @app.exception_handler(StoreCorrupt)
    async def _store_corrupt(request: Request, exc: StoreCorrupt):
        """A corrupt row means the store was tampered with or damaged — the
        honest response is a styled 500 naming the condition and pointing at
        the journal (which reports exactly which bodies diverge), never a
        traceback or a silently-truncated page."""
        detail = (
            "A stored record failed to parse — the store is corrupt or was "
            "modified outside Attest. The signed journal is the source of "
            "truth: `attest status` / /integrity report the divergent bodies."
        )
        accept = request.headers.get("accept", "")
        if request.method == "GET" and "text/html" in accept:
            resp = render(
                request,
                "link_expired.html",
                title="Store integrity failure",
                heading="Store integrity failure",
                detail=detail,
                mechanics=(
                    "Signed records are append-only; a body that no longer parses is flagged, not skipped."
                ),
                cta="Open",
                back_href="/integrity",
                back_label="the integrity report",
            )
            resp.status_code = 500
            return resp
        return JSONResponse({"detail": detail, "error": "store_corrupt"}, status_code=500)

    @app.get("/qr.svg")
    async def link_qr(request: Request, target: str = ""):
        """QR-code a worker link for the door-step scan: the coordinator shows
        it, the aide's phone opens the check-in/review page directly. The code
        encodes the absolute URL — the origin this server was reached at — so a
        phone scanner actually resolves it (a bare path scans as plain text).
        Scoped to the worker-link path prefixes — QR encoding is not a
        capability, but there is no reason to make this an open encoder."""
        allowed = target.startswith(("/checkin/", "/review/", "/family/"))
        if not allowed or len(target) > 300:
            raise HTTPException(400, "target must be a /checkin/, /review/, or /family/ path")
        import io

        import segno

        absolute = str(request.base_url).rstrip("/") + target
        buf = io.BytesIO()
        segno.make(absolute, error="m").save(buf, kind="svg", xmldecl=False, dark="#1c2733", light=None)
        return Response(buf.getvalue(), media_type="image/svg+xml", headers={"Cache-Control": "no-store"})

    @app.get("/checkin/{token}", response_class=HTMLResponse)
    async def checkin_page(request: Request, token: str = PathParam(max_length=128)):
        target = engine.checkin_target(token)
        if target is None:
            return _dead_link(request, "check-in")
        _, visit, worker = target
        return render(
            request,
            "checkin.html",
            worker=worker,
            visit=visit,
            site=store.site(visit.site_id),
            token=token,
            done=False,
        )

    @app.post("/checkin/{token}")
    async def checkin_submit(request: Request, token: str = PathParam(max_length=128)):
        try:
            visit = await asyncio.to_thread(engine.check_in, token)
        except ValueError as exc:
            # A semantic conflict (check-in before the first observation) —
            # re-render the page with the reason, never raw JSON.
            target = engine.checkin_target(token)
            if target is None:
                return _dead_link(request, "check-in", status_code=410)
            _, v, w = target
            resp = render(
                request,
                "checkin.html",
                visit=v,
                worker=w,
                site=store.site(v.site_id),
                token=token,
                done=False,
                checkin_error=str(exc),
            )
            resp.status_code = 409
            return resp
        if visit is None:
            return _dead_link(request, "check-in", status_code=410)
        return render(
            request,
            "checkin.html",
            visit=visit,
            worker=store.worker(visit.worker_id),
            site=store.site(visit.site_id),
            token=None,
            done=True,
        )

    # ------------------------------------------------------------------ dashboard

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        visits = store.visits(limit=50)
        worker_stats: dict[str, dict] = {}
        for v in visits:
            if v.worker_id and v.checked_in_at and v.has_observations:
                st = worker_stats.setdefault(v.worker_id, {"visits": 0, "lags": []})
                st["visits"] += 1
                st["lags"].append((v.checked_in_at - v.arrived_at).total_seconds() / 60)
        for st in worker_stats.values():
            st["median_lag"] = statistics.median(st["lags"]) if st["lags"] else None
            st["max_lag"] = max(st["lags"]) if st["lags"] else None
        stances = {v.id: reviews.countersign(v.id) for v in visits if v.receipt_id}
        attention = attention_items(store, reviews)

        # The journal replay is O(rows) and holds the store lock — run it off
        # the event loop AND cache the verdict briefly so the 5s auto-reload
        # of N coordinator tabs doesn't serialize continuous replays against
        # the single writer. Keyed on the journal head: any journaled write
        # re-runs it, and the cache expires on its own after 15s. `/integrity`
        # and `attest status` always run the full uncached audit.
        async def verify_journal_cached() -> dict:
            now = time.monotonic()
            cached = getattr(app.state, "_journal_cache", None)
            if cached and cached[0] == store.journal_head() and now - cached[1] < 15.0:
                return cached[2]
            result = await asyncio.to_thread(store.verify_journal)
            app.state._journal_cache = (store.journal_head(), now, result)
            return result

        journal = await verify_journal_cached()
        return render(
            request,
            "dashboard.html",
            visits=visits,
            signed_sites={v.site_id for v in store.visits(limit=10_000) if v.receipt_id},
            sites={x.id: x for x in store.sites()},
            workers={w.id: w for w in store.workers()},
            schedules={x.id: x for x in store.schedules()},
            upcoming=store.schedules()[:20],
            chain=ledger.verify_chain(store.receipts(), public_key=signer.public_key_b64),
            journal=journal,
            worker_stats=worker_stats,
            queue=inbox.counts(),
            failed_deliveries=[
                {**e, "received_at": datetime.fromtimestamp(e["received_at"], tz=UTC)}
                for e in inbox.entries(limit=50)
                if e["status"] == "failed"
            ],
            countersign=stances,
            attention=attention,
            triage_brief=(getattr(app.state, "last_triage", None) or {}).get("brief")
            or deterministic_brief(store, reviews),
            triage_source=(getattr(app.state, "last_triage", None) or {}).get("source_label"),
        )

    @app.get("/integrity", response_class=HTMLResponse)
    async def integrity(request: Request):
        """The self-audit surface — the same checks `attest status` runs,
        rendered for the coordinator: chain, journal, custody, coverage."""

        def gather() -> dict:
            # Every read holds the store lock — collect once, off the loop.
            receipts = store.receipts()
            att_types: dict[str, dict] = {}
            for r in receipts:
                if ":" in r.visit_id:
                    rtype = r.payload.get("record_type") or "record"
                    slot = att_types.setdefault(rtype, {"count": 0, "latest": None, "rid": None})
                    slot["count"] += 1
                    if slot["latest"] is None or r.issued_at > slot["latest"]:
                        slot["latest"], slot["rid"] = r.issued_at, r.id
            return {
                "stats": store.stats(),
                "journal": store.verify_journal(),
                "chain": ledger.verify_chain(receipts, public_key=signer.public_key_b64),
                "attestations": att_types,
                "poll": {
                    sid: {
                        "count": p["count"],
                        "last": datetime.fromisoformat(p["last"]) if p["last"] else None,
                    }
                    for sid, p in store.poll_coverage_by_site().items()
                },
                "lifecycle": {
                    sid: {
                        "count": p["count"],
                        "last": datetime.fromisoformat(p["last"]) if p["last"] else None,
                        "last_kind": p["last_kind"],
                    }
                    for sid, p in store.lifecycle_by_site().items()
                },
                "sites": {x.id: x for x in store.sites()},
                "queue": inbox.counts(),
                "mode": (store.setting("execution_mode") or {}).get("mode", "wall"),
            }

        data = await asyncio.to_thread(gather)
        return render(
            request,
            "integrity.html",
            custody=(
                f"AWS KMS envelope — unwrap audited (key {s.kms_key_id})"
                if s.kms_key_id
                else "local key file — plaintext at rest"
            ),
            webhook={
                "armed": bool(s.ring_webhook_key) and s.poll_history_seconds <= 0,
                "polling": s.poll_history_seconds > 0,
                "max_age_s": s.webhook_max_age_s,
            },
            issuer=signer.public_key_b64,
            healthy=(
                data["journal"]["intact"]
                and data["chain"][0]
                and data["journal"].get("untracked_rows", 0) == 0
            ),
            **data,
        )

    @app.get("/integrity.json")
    async def integrity_json():
        """The same self-audit, machine-readable — for scripted evaluation
        and CI gates that shouldn't scrape the HTML page."""

        def gather() -> dict:
            receipts = store.receipts()
            att_types: dict[str, dict] = {}
            for r in receipts:
                if ":" in r.visit_id:
                    rtype = r.payload.get("record_type") or "record"
                    slot = att_types.setdefault(rtype, {"count": 0, "latest": None, "rid": None})
                    slot["count"] += 1
                    if slot["latest"] is None or r.issued_at > slot["latest"]:
                        slot["latest"], slot["rid"] = r.issued_at, r.id
            journal = store.verify_journal()
            chain_ok, chain_why = ledger.verify_chain(receipts, public_key=signer.public_key_b64)
            return {
                "healthy": journal["intact"] and chain_ok and journal.get("untracked_rows", 0) == 0,
                "issuer": signer.public_key_b64,
                "mode": (store.setting("execution_mode") or {}).get("mode", "wall"),
                "journal": journal,
                "chain": {"ok": chain_ok, "detail": chain_why},
                "custody": (
                    f"AWS KMS envelope — unwrap audited (key {s.kms_key_id})"
                    if s.kms_key_id
                    else "local key file — plaintext at rest"
                ),
                "webhook": {
                    "armed": bool(s.ring_webhook_key) and s.poll_history_seconds <= 0,
                    "polling": s.poll_history_seconds > 0,
                    "max_age_s": s.webhook_max_age_s,
                },
                "attestations": {
                    k: {
                        "count": v["count"],
                        "latest": v["latest"].isoformat() if v["latest"] else None,
                        "receipt": v["rid"],
                    }
                    for k, v in att_types.items()
                },
                "sites": {x.id: {"name": x.name} for x in store.sites()},
                "queue": inbox.counts(),
                "stats": store.stats(),
            }

        return await asyncio.to_thread(gather)

    @app.get("/visits/{visit_id}", response_class=HTMLResponse)
    async def visit_page(request: Request, visit_id: str = PathParam(max_length=128)):
        v = store.visit(visit_id)
        if v is None:
            return _not_found(request, "visit record")
        receipt = store.receipt_for_visit(visit_id)
        bundle = reviews.bundle(visit_id) if receipt else None
        site = store.site(v.site_id)
        schedule = store.schedule(v.schedule_id) if v.schedule_id else None
        evidence = store.evidence_for(visit_id)
        from .coverage import coverage_report
        from .timeline import timeline_strip

        cov = receipt.payload.get("history_poll_coverage") if receipt else None
        if cov is None and site and schedule:
            device = site.door_camera_id or site.door_sensor_id
            start = schedule.window_start
            end = min(schedule.window_end, engine.clock.now())
            if end > start:
                cov = coverage_report(store, device, start, end, now=engine.clock.now(), site_id=site.id)
        cov = _coverage_local(cov)
        late = [r["body"] for r in store.late_event_rows() if r["site_id"] == v.site_id]
        strip = timeline_strip(
            schedule=schedule,
            evidence=evidence,
            checked_in_at=v.checked_in_at,
            coverage=cov,
            late_events=late,
        )
        return render(
            request,
            "visit.html",
            visit=v,
            timeline=strip,
            site=site,
            worker=store.worker(v.worker_id) if v.worker_id else None,
            schedule=schedule,
            evidence=evidence,
            corroboration=corroboration(v, site, schedule, evidence, receipt),
            receipt=receipt,
            bundle=bundle,
            reviews=bundle.reviews if bundle else [],
            review_verification=verify_bundle(bundle, public_key=signer.public_key_b64) if bundle else None,
            verified=ledger.verify_receipt(receipt, public_key=signer.public_key_b64) if receipt else None,
            countersign=reviews.countersign(visit_id) if bundle else None,
            coverage=cov,
            late_count=len(late),
            reason_options=[
                (code, taxonomy.REASON_CODES[code]) for code in taxonomy.suggest(f.code for f in v.flags)
            ],
            family_link_active=any(
                g.id == visit_id and g.expires_at > utcnow() for g in store.family_grants()
            ),
            s=lang_strings("en"),  # _timeline.html legend strings default to English
        )

    def _coverage_local(cov: dict | None) -> dict | None:
        """Signed coverage times arrive as ISO strings; return a copy with parsed
        datetimes so every human surface renders them through the local-tz `t()`
        instead of UTC-slicing — one clock across the page."""
        if not cov:
            return cov
        import copy

        out = copy.deepcopy(cov)
        for g in out.get("gaps") or []:
            g["start"] = datetime.fromisoformat(g["start"])
            g["end"] = datetime.fromisoformat(g["end"])
        for i in out.get("interruptions") or []:
            if i.get("at"):
                i["at"] = datetime.fromisoformat(i["at"])
        for srow in out.get("live_sessions") or []:
            srow["opened_at"] = datetime.fromisoformat(srow["opened_at"])
            if srow.get("closed_at"):
                srow["closed_at"] = datetime.fromisoformat(srow["closed_at"])
        return out

    def _record_context(v: Visit) -> dict:
        """Everything a human-facing record view needs — the coordinator's
        household page, the scoped family link, and the printable brief share
        this gather so the three surfaces can never disagree."""
        receipt = store.receipt_for_visit(v.id)
        bundle = reviews.bundle(v.id) if receipt else None
        site = store.site(v.site_id)
        schedule = store.schedule(v.schedule_id) if v.schedule_id else None
        evidence = store.evidence_for(v.id)
        from .coverage import coverage_report
        from .timeline import timeline_strip

        cov = receipt.payload.get("history_poll_coverage") if receipt else None
        if cov is None and site and schedule:
            device = site.door_camera_id or site.door_sensor_id
            start = schedule.window_start
            end = min(schedule.window_end, engine.clock.now())
            if end > start:
                cov = coverage_report(store, device, start, end, now=engine.clock.now(), site_id=site.id)
        strip = timeline_strip(
            schedule=schedule,
            evidence=evidence,
            checked_in_at=v.checked_in_at,
            coverage=cov,
            late_events=[],
        )
        # "Scheduled worker" means the schedule's worker — the signed
        # receipt names the same person under payload.scheduled_worker.
        scheduled_worker = (
            schedule.worker_id
            if schedule
            else ((receipt.payload.get("scheduled_worker") or {}).get("id") if receipt else None)
        )
        cov_local = _coverage_local(cov)
        return {
            "visit": v,
            "timeline": strip,
            "site": site,
            "worker": store.worker(scheduled_worker) if scheduled_worker else None,
            "schedule": schedule,
            "evidence": evidence,
            "receipt": receipt,
            "bundle": bundle,
            "reviews": bundle.reviews if bundle else [],
            "countersign": reviews.countersign(v.id) if bundle else None,
            "coverage": cov_local,
            # Signed payload times arrive as ISO strings; human surfaces need
            # datetimes for the local-tz `t()` macro — convert once, here.
            "live_sessions": [
                {"opened_at": srow["opened_at"], "closed_at": srow.get("closed_at")}
                for srow in (cov_local or {}).get("live_sessions", [])
            ],
        }

    def _household_render(
        request: Request,
        v: Visit,
        media_base: str,
        via_link: bool = False,
        lang: str = "en",
        **extra,
    ):
        """Shared context for the coordinator's /visits/{id}/household and the
        scoped /family/{token} view — same record, same honesty constraints.
        ?lang=es localizes the chrome; signed content stays verbatim."""
        return render(
            request,
            "household.html",
            **_record_context(v),
            media_base=media_base,
            via_link=via_link,
            s=lang_strings(lang),
            **extra,
        )

    @app.get("/visits/{visit_id}/brief", response_class=HTMLResponse)
    async def brief_page(request: Request, visit_id: str = PathParam(max_length=128)):
        """The printable case brief — one page a customer can hand to a
        mediator or attach to a filing. It carries the signed anchors (receipt
        hash, issuer key, verification steps) but never media bytes: the sheet
        is safe to hand over because it proves integrity without exposing
        footage."""
        v = store.visit(visit_id)
        if v is None:
            return _not_found(request, "visit record")
        ctx = _record_context(v)
        bundle = ctx["bundle"]
        site = ctx["site"]
        return render(
            request,
            "brief.html",
            **ctx,
            corroboration=corroboration(v, site, ctx["schedule"], ctx["evidence"], ctx["receipt"]),
            review_verification=verify_bundle(bundle, public_key=signer.public_key_b64) if bundle else None,
            issuer_key=signer.public_key_b64,
            generated_at=engine.clock.now(),
        )

    @app.get("/visits/{visit_id}/household", response_class=HTMLResponse)
    async def household_page(request: Request, visit_id: str = PathParam(max_length=128)):
        """The household's view of one record — plain language, no console.

        The coordinator dashboard answers "what does the operation need?"; this
        answers "was anyone at my mother's door on Tuesday?" in words a
        non-operator can act on — with the same honesty constraints, since a
        worried family member deserves the boundary more than anyone.
        """
        v = store.visit(visit_id)
        if v is None:
            return _not_found(request, "visit record")
        return _household_render(
            request, v, f"/visits/{v.id}", lang=pick_lang(request.query_params.get("lang"))
        )

    @app.post("/api/visits/{visit_id}/family-link")
    async def issue_family_link(visit_id: str = PathParam(max_length=128)):
        """Issue a scoped view+statement link to the household view — the coordinator
        texts it to the family; the token is the authorization (hashed at rest,
        expires in 7 days, revocable by deleting the grant)."""
        try:
            token = await action(engine.issue_family_link, visit_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc
        return {"path": f"/family/{token}", "expires_in_seconds": 604800}

    @app.post("/api/visits/{visit_id}/family-link/revoke")
    async def revoke_family_link(visit_id: str = PathParam(max_length=128)):
        """Kill the visit's family link immediately — the journaled delete
        records the revocation; existing links 404/dead-link from now on."""
        if not await action(engine.revoke_family_link, visit_id):
            raise HTTPException(404, "no family link on this record")
        return {"revoked": True}

    @app.get("/family/{token}", response_class=HTMLResponse)
    async def family_page(request: Request, token: str = PathParam(max_length=128)):
        visit = await action(engine.family_target, token)
        if visit is None:
            return _dead_link(request, "family view")
        return _household_render(
            request,
            visit,
            f"/family/{token}",
            via_link=True,
            lang=pick_lang(request.query_params.get("lang")),
        )

    @app.post("/family/{token}/statement", response_class=HTMLResponse)
    async def family_statement(request: Request, token: str = PathParam(max_length=128)):
        """The household's own account, appended verbatim to the signed chain —
        the family link stays view+append (never edit), multi-use until expiry."""
        visit = await action(engine.family_target, token)
        if visit is None:
            return _dead_link(request, "family view")
        lang = pick_lang(request.query_params.get("lang"))
        s = lang_strings(lang)
        try:
            data = HouseholdStatementInput.model_validate(dict(await request.form()))
        except ValidationError:
            return _household_render(
                request,
                visit,
                f"/family/{token}",
                via_link=True,
                lang=lang,
                statement_error=s["err_incomplete"],
            )
        try:
            await asyncio.to_thread(reviews.household_statement, token, data)
        except ValueError as exc:
            if "statement limit" in str(exc):
                return _household_render(
                    request,
                    visit,
                    f"/family/{token}",
                    via_link=True,
                    lang=lang,
                    statement_error=s["err_limit"],
                )
            return _dead_link(request, "family view")
        return _household_render(
            request, visit, f"/family/{token}", via_link=True, lang=lang, statement_posted=True
        )

    @app.get("/family/{token}/media/{name}")
    async def family_media(token: str = PathParam(max_length=128), name: str = PathParam(max_length=255)):
        visit = await action(engine.family_target, token)
        if visit is None:
            raise HTTPException(404)
        for e in store.evidence_for(visit.id):
            if e.media_path and Path(e.media_path).name == name:
                # The signed digest is the contract: never serve bytes that
                # fail it — a swapped file must surface as missing evidence,
                # not render inside a page that displays the original digest.
                if e.media_sha256 and not media.verify(e.media_path, e.media_sha256):
                    log.warning("media digest mismatch for %s on %s", name, visit.id)
                    raise HTTPException(410, "media failed integrity check")
                data = media.read(e.media_path)
                if data is None:
                    raise HTTPException(404)
                mime = "image/png" if data.startswith(b"\x89PNG") else "image/jpeg"
                return Response(content=data, media_type=mime)
        raise HTTPException(404)

    @app.get("/visits/{visit_id}/media/{name}")
    async def visit_media(visit_id: str = PathParam(max_length=128), name: str = PathParam(max_length=255)):
        for e in store.evidence_for(visit_id):
            if e.media_path and Path(e.media_path).name == name:
                if e.media_sha256 and not media.verify(e.media_path, e.media_sha256):
                    log.warning("media digest mismatch for %s on %s", name, visit_id)
                    raise HTTPException(410, "media failed integrity check")
                data = media.read(e.media_path)
                if data is None:
                    break
                mime = "image/png" if data.startswith(b"\x89PNG") else "image/jpeg"
                return Response(data, media_type=mime, headers={"X-Content-SHA256": e.media_sha256 or ""})
        raise HTTPException(404)

    # ------------------------------------------------------------------ receipts

    @app.get("/receipts/{receipt_id}.json")
    async def receipt_json(receipt_id: str = PathParam(max_length=128)):
        r = store.receipt(receipt_id)
        if r is None:
            raise HTTPException(404)
        return JSONResponse(
            json.loads(r.model_dump_json()),
            headers={"Content-Disposition": f'attachment; filename="{receipt_id}.json"'},
        )

    @app.get("/receipts.json")
    async def receipts_export():
        return JSONResponse([json.loads(r.model_dump_json()) for r in store.receipts()])

    @app.get("/about", response_class=HTMLResponse)
    async def about_page(request: Request):
        return render(request, "about.html")

    @app.get("/verify", response_class=HTMLResponse)
    async def verify_page(request: Request):
        return render(request, "verify.html", result=None, public_key=signer.public_key_b64)

    @app.post("/verify", response_class=HTMLResponse)
    async def verify_submit(request: Request, file: UploadFile | None = None, text: str = Form("")):
        if file and file.filename:
            data = await file.read(_MAX_VERIFY_BYTES + 1)
            if len(data) > _MAX_VERIFY_BYTES:
                resp = render(
                    request,
                    "verify.html",
                    result=(
                        False,
                        "That file is too large to verify here — split it or use `attest verify` offline.",
                    ),
                    public_key=signer.public_key_b64,
                )
                resp.status_code = 413
                return resp
            if data[:2] == b"PK":
                return render(
                    request,
                    "verify.html",
                    result=_verify_pack(data, signer.public_key_b64),
                    public_key=signer.public_key_b64,
                )
            raw = data.decode("utf-8", errors="replace")
        else:
            if len(text.encode("utf-8")) > _MAX_VERIFY_BYTES:
                raise HTTPException(413, "verification input too large")
            raw = text
        try:
            data = json.loads(raw)
            pk = signer.public_key_b64
            if isinstance(data, list):
                ok, why = ledger.verify_chain([Receipt.model_validate(d) for d in data], public_key=pk)
            elif isinstance(data, dict) and data.get("kind") == "attest.review_bundle/1":
                ok, why = verify_bundle(ReviewBundle.model_validate(data), public_key=pk)
            else:
                ok, why = ledger.verify_receipt(data, public_key=pk)
        except Exception as exc:  # noqa: BLE001
            ok, why = False, f"could not parse receipt: {exc}"
        return render(request, "verify.html", result=(ok, why), public_key=signer.public_key_b64)

    @app.get("/verify-pack", response_class=HTMLResponse)
    async def verify_pack_page(request: Request):
        """The same dependency-free browser verifier every pack embeds — drop a
        downloaded .zip straight onto the running dashboard; nothing uploads."""
        from .verifyjs import VERIFY_HTML

        return HTMLResponse(VERIFY_HTML)

    # ------------------------------------------------------------------ admin (JSON)

    @app.post("/api/sites")
    async def api_site(site: Site):
        return await action(
            setup.register_site, site.name, site.door_camera_id, site.door_sensor_id, supplied=site
        )

    @app.post("/api/workers")
    async def api_worker(worker: Worker):
        registered = await action(setup.register_worker, worker)
        return registered.model_dump(exclude={"checkin_token"})

    @app.post("/api/schedules")
    async def api_schedule(schedule: Schedule):
        return await action(setup.register_schedule, schedule)

    @app.post("/api/visits/{visit_id}/checkin-link")
    async def issue_checkin_link(visit_id: str = PathParam(max_length=128)):
        try:
            token = await asyncio.to_thread(engine.issue_checkin, visit_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"path": f"/checkin/{token}", "expires_in_seconds": 900}

    async def action(function, *args, **kwargs):
        try:
            return await asyncio.to_thread(function, *args, **kwargs)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        except RingAPIError as exc:
            raise HTTPException(
                502, f"Ring API returned HTTP {exc.status_code}; check access and retry"
            ) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(502, "Ring service unavailable; check connectivity and retry") from exc

    def setup_view(request: Request, *, devices=None, error=None):
        ready = engine.clock.snapshot()["ready"]
        now = engine.clock.now() if ready else utcnow()
        return render(
            request,
            "setup.html",
            devices=devices or [],
            error=error,
            sites=store.sites(),
            workers=store.workers(),
            schedules=store.schedules(),
            default_start=now.isoformat(timespec="minutes"),
            default_end=(now + timedelta(minutes=30)).isoformat(timespec="minutes"),
        )

    async def setup_form(request: Request, function, *args, **kwargs):
        try:
            await action(function, *args, **kwargs)
        except HTTPException as exc:
            response = setup_view(request, error=exc.detail)
            response.status_code = exc.status_code
            return response
        return RedirectResponse("/setup", status_code=303)

    @app.get("/setup", response_class=HTMLResponse)
    async def setup_page(request: Request, discover: bool = False):
        try:
            devices = await action(setup.discover) if discover else []
            return setup_view(request, devices=devices)
        except HTTPException as exc:
            return setup_view(request, error=exc.detail)

    @app.post("/setup/sites")
    async def setup_site(
        request: Request, name: str = Form(...), camera_id: str = Form(...), sensor_id: str = Form("")
    ):
        return await setup_form(request, setup.register_site, name, camera_id, sensor_id or None)

    @app.post("/setup/workers")
    async def setup_worker(
        request: Request, name: str = Form(...), role: str = Form("other"), agency: str = Form("")
    ):
        return await setup_form(
            request, lambda: setup.register_worker(Worker(name=name, role=role, agency=agency))
        )

    @app.post("/setup/schedules")
    async def setup_schedule(
        request: Request,
        site_id: str = Form(...),
        worker_id: str = Form(...),
        window_start: str = Form(...),
        window_end: str = Form(...),
        expected_minutes: int = Form(...),
        service: str = Form(""),
    ):
        return await setup_form(
            request,
            lambda: setup.register_schedule(
                Schedule(
                    site_id=site_id,
                    worker_id=worker_id,
                    window_start=window_start,
                    window_end=window_end,
                    expected_minutes=expected_minutes,
                    service=service,
                )
            ),
        )

    @app.post("/setup/schedules/{schedule_id}/cancel")
    async def cancel_schedule(request: Request, schedule_id: str = PathParam(max_length=128)):
        return await setup_form(request, setup.cancel_schedule, schedule_id)

    @app.get("/visits/{visit_id}/bundle.json")
    async def review_bundle(visit_id: str = PathParam(max_length=128)):
        return await action(reviews.bundle, visit_id)

    @app.get("/visits/{visit_id}/pack.zip")
    async def dispute_pack(
        request: Request, visit_id: str = PathParam(max_length=128), redact_media: bool = False
    ):
        """Portable dispute pack: bundle + media + a stdlib-only offline verifier.
        ?redact_media=1 withholds media bytes — signed digests stay verifiable."""
        if "text/html" in (request.headers.get("accept") or ""):
            v = store.visit(visit_id)
            if v is None:
                return _not_found(request, "visit record")
            if store.receipt_for_visit(visit_id) is None:
                resp = render(
                    request,
                    "link_expired.html",
                    title="Nothing to export",
                    heading="Nothing to export yet",
                    detail="This record isn't signed yet — the dispute pack assembles the signed bundle.",
                    mechanics="Records sign when the visit closes; open records have nothing to verify.",
                    cta="Open",
                    back_href=f"/visits/{visit_id}",
                    back_label="the record",
                )
                resp.status_code = 409
                return resp
        bundle = await action(reviews.bundle, visit_id)
        data = await asyncio.to_thread(
            build_pack, store, s.data_dir / "media", bundle, redact_media=redact_media
        )
        return Response(
            data,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="attest-{visit_id}.zip"'},
        )

    @app.get("/sites/{site_id}", response_class=HTMLResponse)
    async def site_page(request: Request, site_id: str = PathParam(max_length=128)):
        """The longitudinal view — every visit at one site, worker stances,
        and coverage, so a coordinator sees a pattern rather than incidents."""
        site = store.site(site_id)
        if site is None:
            return _not_found(request, "site", back_href="/")
        visits = store.visits(site_id=site.id, limit=100)
        stances = {v.id: reviews.countersign(v.id) for v in visits if v.receipt_id}
        coverage_summaries = {}
        for v in visits:
            r = store.receipt_for_visit(v.id)
            cov = (r.payload.get("history_poll_coverage") or {}) if r else {}
            if cov:
                coverage_summaries[v.id] = cov
        workers = {w.id: w for w in store.workers()}
        schedules = {x.id: x for x in store.schedules_for_site(site.id)}
        digests = [r for r in store.receipts() if r.visit_id.startswith(f"digest:{site.id}:")]
        exports = [r for r in store.receipts() if r.visit_id.startswith(f"export:{site.id}:")]
        coverage_certs = [r for r in store.receipts() if r.visit_id.startswith(f"coverage:{site.id}:")]
        from .timeline import day_strips

        days = day_strips(
            visits=visits,
            evidence_by_visit={v.id: store.evidence_for(v.id) for v in visits},
            schedules=list(schedules.values()),
            coverage_by_visit=coverage_summaries,
            tz=tz,
            late_events=[r["body"] for r in store.late_event_rows() if r["site_id"] == site.id],
        )
        return render(
            request,
            "site.html",
            site=site,
            visits=visits,
            signed_visits=sum(1 for v in visits if v.receipt_id),
            workers=workers,
            schedules=schedules,
            countersign=stances,
            coverage=coverage_summaries,
            coverage_events=await asyncio.to_thread(lambda: store.coverage_events(site.id, limit=20)[::-1]),
            liveview_sessions=await asyncio.to_thread(
                lambda: store.liveview_sessions(site.id, limit=20)[::-1]
            ),
            receipts={v.id: store.receipt_for_visit(v.id) for v in visits},
            digests=digests,
            exports=exports,
            coverage_certs=coverage_certs,
            days=days,
        )

    @app.get("/sites/{site_id}/schedule.ics")
    async def site_schedule_ics(site_id: str = PathParam(max_length=128)):
        """Subscribable calendar of the site's visit windows (RFC 5545) — the
        *plan*, readable in any calendar app. Entries are expectations, never
        observation evidence."""
        site = store.site(site_id)
        if site is None:
            raise HTTPException(404, "unknown site")
        from .exports import schedule_ics

        schedules = store.schedules_for_site(site.id)
        workers = {w.id: w for w in store.workers()}
        return Response(
            content=schedule_ics(site, schedules, workers),
            media_type="text/calendar; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{site.id}-schedule.ics"'},
        )

    @app.get("/sites/{site_id}/visits.csv")
    async def site_visits_csv(site_id: str = PathParam(max_length=128)):
        """The visit register as CSV — one row per record for billing
        reconciliation or a mediator's spreadsheet. Column names stay honest:
        'observed', never 'arrived'; worker names marked self-reported."""
        site = store.site(site_id)
        if site is None:
            raise HTTPException(404, "unknown site")
        from .exports import visits_csv

        visits = store.visits(site_id=site.id, limit=10_000)
        schedules = {x.id: x for x in store.schedules_for_site(site.id)}
        workers = {w.id: w for w in store.workers()}
        review_states = {
            v.id: (cs["state"] if (cs := reviews.countersign(v.id)) else "") for v in visits if v.receipt_id
        }
        receipt_hashes = {
            v.id: (r.payload_hash if (r := store.receipt_for_visit(v.id)) else "") for v in visits
        }
        resolutions: dict[str, dict | None] = {}
        worker_reasons: dict[str, str] = {}
        for v in visits:
            if not v.receipt_id:
                continue
            bundle = reviews.bundle(v.id)
            if bundle:
                for entry in reversed(bundle.reviews):
                    rv = entry.receipt.payload.get("review")
                    if not isinstance(rv, dict):
                        continue
                    actor = entry.receipt.payload.get("actor")
                    if rv.get("kind") == "resolution" and v.id not in resolutions:
                        resolutions[v.id] = rv
                    if (
                        isinstance(actor, dict)
                        and actor.get("role") == "worker"
                        and rv.get("reason_code")
                        and v.id not in worker_reasons
                    ):
                        worker_reasons[v.id] = rv["reason_code"]
                # reversed() scan: first hit per role is the latest statement
        return Response(
            content=visits_csv(
                site, visits, schedules, workers, review_states, receipt_hashes, resolutions, worker_reasons
            ),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{site.id}-visits.csv"'},
        )

    @app.post("/api/sites/{site_id}/digest")
    async def site_digest(site_id: str = PathParam(max_length=128)):
        """Sign a period digest covering every record this site page shows —
        counts of records, never claims about physical presence."""
        site = store.site(site_id)
        if site is None:
            raise HTTPException(404, "unknown site")
        visits = [v for v in store.visits(site_id=site.id, limit=10_000) if v.arrived_at]
        if not visits:
            raise HTTPException(409, "no records to digest")
        start = min(v.arrived_at for v in visits)
        end = max(v.last_activity_at for v in visits)
        receipt = await asyncio.to_thread(engine.issue_period_digest, site, start, end)
        return receipt.model_dump(mode="json")

    @app.post("/api/sites/{site_id}/disconnect")
    async def site_disconnect(request: Request, site_id: str = PathParam(max_length=128)):
        """Revoke the site's Ring source: tombstone the binding and sign a
        source_disconnected receipt naming exactly what was unbound. Ingestion
        and Event History polling stop; signed records are never altered."""
        site = store.site(site_id)
        if site is None:
            raise HTTPException(404, "unknown site")
        reason = ""
        try:
            body = await request.json()
            reason = str(body.get("reason") or "")[:500]
        except Exception:
            pass
        try:
            receipt = await asyncio.to_thread(engine.disconnect_site, site, reason)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return receipt.model_dump(mode="json")

    @app.post("/api/sites/{site_id}/liveview")
    async def liveview_open(request: Request, site_id: str = PathParam(max_length=128)):
        """Broker a WHEP live-view session: the browser's SDP offer goes to Ring
        verbatim, the session Ring actually establishes is journaled, and the
        SDP answer comes back for the coordinator's RTCPeerConnection. The row
        proves a stream was opened — never that anyone watched it."""
        offer = (await request.body()).decode("utf-8", "replace")
        row, answer = await action(engine.open_liveview, site_id, offer)
        return {"session_id": row.id, "sdp_answer": answer}

    @app.post("/api/sites/{site_id}/liveview/{session_id}/close")
    async def liveview_close(
        site_id: str = PathParam(max_length=128), session_id: str = PathParam(max_length=128)
    ):
        """End a brokered session — Ring-side first, then the journaled row
        closes. An orphaned row reading 'open' would overstate attention."""
        row = await action(engine.close_liveview, site_id, session_id)
        return {"session_id": row.id, "closed_at": row.closed_at}

    @app.get("/sites/{site_id}/pack.zip")
    async def case_pack(
        request: Request, site_id: str = PathParam(max_length=128), redact_media: bool = False
    ):
        """Site-level case pack: every visit's signed bundle, a manifest of receipt
        hashes + worker stances, and a stdlib verifier — for pattern disputes.
        ?redact_media=1 withholds media bytes; digests are preserved."""
        site = store.site(site_id)
        if site is None:
            raise HTTPException(404, "unknown site")
        if "text/html" in (request.headers.get("accept") or "") and not any(
            store.receipt_for_visit(v.id) for v in store.visits(site_id=site.id, limit=10_000)
        ):
            # A browser following the export link gets a styled page, not raw JSON.
            resp = render(
                request,
                "link_expired.html",
                title="Nothing to export",
                heading="Nothing to export yet",
                detail=(
                    f"{site.name} has no signed records yet — the case pack "
                    "assembles closed, signed visit records only."
                ),
                mechanics=(
                    "Records sign as visits close; open or unobserved "
                    "schedules contribute nothing to the pack."
                ),
                cta="Come back once a visit has closed, or open",
                back_href=f"/sites/{site.id}",
                back_label="the site view",
            )
            resp.status_code = 409
            return resp

        def build() -> bytes:
            entries = []
            for visit in store.visits(site_id=site.id, limit=10_000):
                # Only closed records carry signed receipts; open visits have
                # nothing to verify and are skipped from the case export.
                if store.receipt_for_visit(visit.id) is None:
                    continue
                bundle = reviews.bundle(visit.id)
                entries.append((visit, bundle, reviews.countersign(visit.id)))
            if not entries:
                raise HTTPException(409, "no signed records for this site yet")
            return build_case_pack(
                store,
                s.data_dir / "media",
                site,
                entries,
                redact_media=redact_media,
                manifest_signer=lambda m: engine.issue_export_manifest(site, m),
            )

        data = await asyncio.to_thread(build)
        return Response(
            data,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="attest-case-{site_id}.zip"'},
        )

    @app.post("/api/visits/{visit_id}/reviews")
    async def coordinator_review(body: ReviewInput, visit_id: str = PathParam(max_length=128)):
        return await action(reviews.coordinator_review, visit_id, body)

    @app.post("/api/visits/{visit_id}/resolve")
    async def resolve_visit(body: ResolutionInput, visit_id: str = PathParam(max_length=128)):
        return await action(reviews.resolve, visit_id, body)

    @app.post("/api/visits/{visit_id}/review-link")
    async def issue_review_link(visit_id: str = PathParam(max_length=128)):
        token = await action(reviews.issue_worker_link, visit_id)
        return {"path": f"/review/{token}", "expires_in_seconds": 86400}

    async def _worker_ctx(token: str):
        """The worker-facing render context — the timeline is built from the
        signed payload itself, so the strip is exactly what they countersign."""
        target = await action(reviews.worker_target, token)
        if target is None:
            return None
        _, bundle = target
        from .timeline import timeline_strip

        p = bundle.original.payload
        return {
            "original": p,
            "token": token,
            "done": False,
            "reason_options": [
                (code, taxonomy.REASON_CODES[code])
                for code in taxonomy.suggest(f["code"] for f in p.get("flags", []))
            ],
            "timeline": timeline_strip(
                schedule=p.get("schedule"),
                evidence=p.get("evidence") or [],
                checked_in_at=p.get("checked_in_at"),
                coverage=p.get("history_poll_coverage"),
            ),
        }

    @app.get("/review/{token}", response_class=HTMLResponse)
    async def worker_review_page(request: Request, token: str = PathParam(max_length=128)):
        ctx = await _worker_ctx(token)
        if ctx is None:
            return _dead_link(request, "review")
        return render(request, "worker_review.html", **ctx)

    @app.post("/review/{token}", response_class=HTMLResponse)
    async def worker_review_submit(
        request: Request,
        token: str = PathParam(max_length=128),
        decision: str = Form(...),
        statement: str = Form(...),
        reported_start: str = Form(""),
        reported_end: str = Form(""),
        reason_code: str = Form(""),
    ):
        try:
            body = ReviewInput(
                decision=decision,
                statement=statement,
                reported_start=reported_start or None,
                reported_end=reported_end or None,
                reason_code=reason_code or None,
            )
        except ValueError:
            ctx = await _worker_ctx(token)
            if ctx is None:
                return _dead_link(request, "review")
            resp = render(
                request,
                "worker_review.html",
                **ctx,
                form_error=(
                    "Your statement didn't submit — check that it's not empty and that "
                    "either both reported times or neither are filled, each with a UTC "
                    "offset like 2026-09-15T09:00:00-07:00."
                ),
                form={
                    "decision": decision,
                    "statement": statement,
                    "reported_start": reported_start,
                    "reported_end": reported_end,
                    "reason_code": reason_code,
                },
            )
            resp.status_code = 422
            return resp
        try:
            await action(reviews.worker_review, token, body)
        except HTTPException as exc:
            if exc.status_code == 409 and "review link" in str(exc.detail):
                return _dead_link(request, "review", status_code=410)
            if exc.status_code == 409 and "review limit reached" in str(exc.detail):
                ctx = await _worker_ctx(token)
                if ctx is None:
                    return _dead_link(request, "review")
                resp = render(
                    request,
                    "worker_review.html",
                    **ctx,
                    form_error=(
                        "This record's review chain is full — no further statements "
                        "can be appended. Ask the coordinator to export the case pack."
                    ),
                    form={
                        "decision": decision,
                        "statement": statement,
                        "reported_start": reported_start,
                        "reported_end": reported_end,
                        "reason_code": reason_code,
                    },
                )
                resp.status_code = 409
                return resp
            raise
        return render(request, "worker_review.html", original=None, token=None, done=True)

    @app.get("/api/clock")
    async def clock_status():
        return engine.clock.snapshot()

    @app.post("/api/replay/start")
    async def start_replay(body: ReplayTime):
        return await action(engine.clock.start, body.at)

    @app.post("/api/replay/advance")
    async def advance_replay(body: ReplayTime):
        if any(inbox.counts().get(status, 0) for status in ("pending", "processing", "failed")):
            raise HTTPException(409, "process or resolve queued deliveries before advancing the clock")
        return await action(engine.clock.advance, body.at)

    @app.post("/api/visits/{visit_id}/close")
    async def close_for_review(visit_id: str = PathParam(max_length=128)):
        return await action(engine.close_for_review, visit_id)

    @app.get("/api/state")
    async def api_state():
        return store.dump()

    @app.get("/api/retention")
    async def api_retention():
        """Non-destructive lifecycle report: what exists, its age, what policy would touch."""
        policy = retention.RetentionPolicy(
            visits_days=s.retention_visits_days,
            media_days=s.retention_media_days,
            deliveries_days=s.retention_deliveries_days,
            grants_days=s.retention_grants_days,
            seen_days=s.retention_seen_days,
            late_events_days=s.retention_late_days,
            poll_observations_days=s.retention_poll_days,
            coverage_events_days=s.retention_coverage_days,
            liveview_sessions_days=s.retention_liveview_days,
        )
        return await asyncio.to_thread(
            retention.build_report, store, inbox, s.data_dir / "media", policy=policy
        )

    @app.post("/api/retention/apply")
    async def api_retention_apply(body: RetentionApply):
        """Delete the previewed non-chain candidates. The confirm token must match the
        current preview, so deletion only ever targets the set an operator just saw."""
        policy = retention.RetentionPolicy(
            visits_days=s.retention_visits_days,
            media_days=s.retention_media_days,
            deliveries_days=s.retention_deliveries_days,
            grants_days=s.retention_grants_days,
            seen_days=s.retention_seen_days,
            late_events_days=s.retention_late_days,
            poll_observations_days=s.retention_poll_days,
            coverage_events_days=s.retention_coverage_days,
            liveview_sessions_days=s.retention_liveview_days,
        )
        try:
            return await asyncio.to_thread(
                retention.apply,
                store,
                inbox,
                s.data_dir / "media",
                policy=policy,
                confirm=body.confirm,
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/sweep")
    async def api_sweep(now: datetime | None = None):
        changed = await asyncio.to_thread(engine.sweep, now)
        return {"changed": [v.id for v in changed]}

    @app.post("/api/process-webhooks")
    async def api_process_webhook():
        processed = await asyncio.to_thread(process_webhook)
        return {"processed": processed, "queue": inbox.counts()}

    @app.get("/api/webhook-queue")
    async def api_webhook_queue():
        return inbox.counts()

    @app.get("/api/journal")
    async def api_journal():
        """Replay the mutation journal: every store write is hash-chained."""
        return await asyncio.to_thread(store.verify_journal)

    @app.post("/api/webhook-queue/requeue")
    async def api_requeue(body: RequeueDeliveries | None = None):
        """Return failed deliveries to pending for another processing cycle."""
        requeued = await asyncio.to_thread(inbox.requeue, body.ids if body else None)
        return {"requeued": requeued, "queue": inbox.counts()}

    @app.post("/api/poll")
    async def api_poll():
        n = await asyncio.to_thread(HistoryPoller(engine, store, ring).poll_once)
        return {"ingested": n}

    @app.post("/api/triage")
    async def api_triage():
        """Run the weekly triage brief — a Strands agent reading the ledger
        through tools when Bedrock is reachable, else the deterministic brief.
        The response always labels which source wrote it."""
        result = await asyncio.to_thread(
            run_triage, store, reviews, model_id=s.bedrock_model_id, region=s.aws_region
        )
        # Keep the last run so the dashboard's live-reload doesn't revert the
        # brief to deterministic — the rendered label keeps its provenance.
        label = (
            f"source: Strands agent over Bedrock {result.model or ''}"
            if result.source == "strands-agent"
            else f"source: deterministic triage — agent unavailable ({result.fallback_reason or '?'})"
        )
        app.state.last_triage = {"brief": result.brief, "source_label": label}
        return {
            "brief": result.brief,
            "source": result.source,
            "model": result.model,
            "fallback_reason": result.fallback_reason,
        }

    @app.get("/healthz")
    async def healthz():
        # Unauthenticated liveness only — deployment details (Ring endpoint,
        # summarizer) are not broadcast to whoever can reach the port.
        return {"ok": True}

    return app


def _verify_pack(data: bytes, public_key: str) -> tuple[bool, str]:
    """Verify an exported pack: dispute pack (bundle.json) or site case pack
    (manifest.json + visits/<id>/bundle.json) — signatures + media digests."""
    import io
    import zipfile

    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        # Bound total decompressed size — a small zip can expand unboundedly.
        if sum(i.file_size for i in z.infolist()) > 256 * 1024 * 1024:
            return False, "pack expands beyond the 256 MB verification bound"
        from .packdiff import BoundedZip

        z = BoundedZip(z)
        names = set(z.namelist())
        if "manifest.json" in names:
            return _verify_case_pack(z, public_key)
        bundle = ReviewBundle.model_validate(json.loads(z.read("bundle.json")))
        ok, detail = _check_pack_bundle(z, bundle, public_key, media_prefix="media/")
        if not ok:
            return False, detail
        # Fail closed on files the pack format doesn't name (media members are
        # digest-checked in _check_pack_bundle).
        allowed = {
            "bundle.json",
            "README.txt",
            "verify_bundle.py",
            "verify.html",
            "index.html",
            "redaction.json",
        }
        for name in names:
            if name.endswith("/") or name in allowed or name.startswith("media/"):
                continue
            return False, f"{name}: present but not in the signed manifest"
        return True, detail
    except Exception as exc:  # noqa: BLE001
        return False, f"not a valid exported pack: {exc}"


def _check_pack_bundle(z, bundle: ReviewBundle, public_key: str, *, media_prefix: str) -> tuple[bool, str]:
    ok, why = verify_bundle(bundle, public_key=public_key)
    if not ok:
        return False, f"bundle: {why}"
    digests = {
        e.get("media_sha256") for e in bundle.original.payload.get("evidence", []) if e.get("media_sha256")
    }
    withheld: set[str] = set()
    marker_name = media_prefix.rsplit("media/", 1)[0] + "redaction.json"
    if marker_name in z.namelist():
        marker = json.loads(z.read(marker_name))
        withheld = set(marker.get("withheld_digests", []))
        if not withheld <= digests:
            return False, "bundle: redaction.json lists digests not in the signed evidence"
    media_members = [
        (name, hashlib.sha256(z.read(name)).hexdigest())
        for name in z.namelist()
        if name.startswith(media_prefix) and not name.endswith("/")
    ]
    # A media member that doesn't hash to a digest the signed evidence names
    # is smuggled content riding inside a "VERIFIED" pack — fail closed.
    for name, sha in media_members:
        if sha not in digests:
            return False, f"{name}: media member not named by the signed evidence"
    present = {sha for _, sha in media_members}
    matched = len(digests & present)
    covered = matched + len(withheld & digests)
    detail = f"{why}; {matched}/{len(digests)} signed media digests found in pack" + (
        f", {len(withheld & digests)} withheld by redaction" if withheld else ""
    )
    return (covered == len(digests), detail)


def _verify_case_pack(z, public_key: str) -> tuple[bool, str]:
    """Verify every visit bundle in a case pack plus the manifest's hash list."""
    manifest = json.loads(z.read("manifest.json"))
    if manifest.get("schema") != "attest.case-pack/1":
        return False, f"unsupported case pack schema {manifest.get('schema')!r}"
    if manifest.get("issuer_key") != public_key:
        return False, "case pack was not issued under this deployment's key"
    lines = []
    for v in manifest.get("visits", []):
        vid = v.get("visit_id", "?")
        try:
            bundle = ReviewBundle.model_validate(json.loads(z.read(f"visits/{vid}/bundle.json")))
        except Exception as exc:  # noqa: BLE001
            return False, f"{vid}: missing or invalid bundle ({exc})"
        ok, detail = _check_pack_bundle(z, bundle, public_key, media_prefix=f"visits/{vid}/media/")
        if not ok:
            return False, f"{vid}: {detail}"
        if bundle.original.payload_hash != v.get("payload_hash"):
            return False, f"{vid}: manifest hash disagrees with signed original"
        marker_name = f"visits/{vid}/redaction.json"
        if marker_name in z.namelist():
            marker = json.loads(z.read(marker_name))
            if set(v.get("media_withheld", [])) != set(marker.get("withheld_digests", [])):
                return False, f"{vid}: manifest redaction list disagrees with redaction.json"
        media_detail = detail.split("; ", 1)[-1] if "; " in detail else detail
        lines.append(f"{vid}: {v.get('state')} ({v.get('countersign', {}).get('state')}) — {media_detail}")
    total = len(manifest.get("visits", []))
    sig = manifest.get("signature_receipt")
    manifest_note = "unsigned manifest (pre-signature pack)"
    if sig is not None:
        ok, why = ledger.verify_receipt(Receipt.model_validate(sig), public_key=public_key)
        if not ok:
            return False, f"manifest signature: {why}"
        core = {k: v for k, v in manifest.items() if k != "signature_receipt"}
        if ledger.payload_hash(core) != sig["payload"].get("manifest_sha256"):
            return False, "manifest content hash mismatch (manifest was altered)"
        signed_hashes = sig["payload"].get("receipt_hashes", {})
        listed = {v["visit_id"]: v["payload_hash"] for v in manifest.get("visits", [])}
        if listed != signed_hashes:
            return False, "manifest visit list disagrees with the signed export"
        manifest_note = f"export signed: {total} record(s)"
    for a in manifest.get("attestations", []):
        rid = a.get("receipt_id", "?")
        try:
            att = Receipt.model_validate(json.loads(z.read(f"attestations/{rid}.json")))
        except Exception as exc:  # noqa: BLE001
            return False, f"attestation {rid}: missing or invalid ({exc})"
        if att.public_key != public_key:
            return False, f"attestation {rid}: issued under a different key"
        ok, why = ledger.verify_receipt(att, public_key=public_key)
        if not ok:
            return False, f"attestation {rid}: {why}"
        if att.visit_id != a.get("visit_id") or att.payload_hash != a.get("payload_hash"):
            return False, f"attestation {rid}: does not match the manifest's signed entry"
    # Fail closed on ANY file the signed manifest doesn't name — a smuggled
    # top-level file or an extra member inside a listed visit directory would
    # otherwise ride inside a "VERIFIED" pack. Media members are digest-checked
    # per visit in _check_pack_bundle.
    visit_ids = {v.get("visit_id") for v in manifest.get("visits", [])}
    allowed = {"manifest.json", "README.txt", "verify_case.py", "verify.html", "index.html"}
    allowed |= {f"attestations/{a.get('receipt_id')}.json" for a in manifest.get("attestations", [])}
    for vid in visit_ids:
        allowed |= {f"visits/{vid}/bundle.json", f"visits/{vid}/redaction.json"}
    for name in z.namelist():
        if name.endswith("/") or name in allowed:
            continue
        parts = name.split("/")
        if len(parts) >= 4 and parts[0] == "visits" and parts[2] == "media" and parts[1] in visit_ids:
            continue  # digest-checked against the signed evidence above
        return False, f"{name}: present but not in the signed manifest"
    return True, f"case pack verified — {total} visit record(s) intact ({manifest_note}): " + "; ".join(lines)


__all__ = ["create_app", "VisitState"]
