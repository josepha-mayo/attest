"""HTTP surface: Ring webhook receiver, worker check-in, dashboard, receipts, verification."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, UploadFile
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic
from fastapi.templating import Jinja2Templates
from ring_sandbox import RingAPIError, RingClient, webhooks

from . import ledger, retention
from .config import Settings
from .config import settings as default_settings
from .corroborate import corroboration
from .disputepack import build_case_pack, build_pack
from .engine import VisitEngine
from .inbox import WebhookInbox
from .ledger import Signer
from .media import MediaStore
from .models import (
    Receipt,
    ReplayTime,
    RequeueDeliveries,
    RetentionApply,
    ReviewBundle,
    ReviewInput,
    Schedule,
    Site,
    VisitState,
    Worker,
    utcnow,
)
from .poller import HistoryPoller
from .reviews import ReviewService, verify_bundle
from .setup import SetupService
from .store import Store
from .summarize import build as build_summarizer

log = logging.getLogger("attest")
_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

_MAX_WEBHOOK_BYTES = 256 * 1024
_MAX_VERIFY_BYTES = 4 * 1024 * 1024
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
    signer = signer or Signer.load_or_create(s.key_path)
    media = MediaStore(s.data_dir / "media")
    summarizer = build_summarizer(
        s.summarizer, tz=s.timezone, model_id=s.bedrock_model_id, region=s.aws_region
    )
    engine = VisitEngine(store, ring, signer, media, summarizer, s)
    inbox = WebhookInbox(s.data_dir / "webhooks.sqlite3")
    reviews = ReviewService(store, signer, engine.clock)
    setup = SetupService(store, ring, engine.clock, s.arrival_grace_minutes)

    def process_webhook() -> bool:
        job = inbox.claim()
        if job is None:
            return False
        try:
            ev = webhooks.parse(job["raw_body"], signing_key=s.ring_webhook_key, signature=job["signature"])
            outcome = engine.ingest(ev)
            reason = outcome.ignored_reason or ""
            rejected = reason in (
                "account mismatch",
                "ingestion source changed; reconciliation required",
            ) or ("not bound to a site" in reason)
            inbox.complete(job, "rejected" if rejected else "done")
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
        if request.url.path.startswith(("/checkin/", "/review/")):
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
        if s.ring_base_url == "https://api.amazonvision.com" and s.ring_webhook_key == "attest-dev-hmac-key":
            return JSONResponse({"error": "configure the issued Ring webhook signing key"}, status_code=503)
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
            )
        except webhooks.SignatureError:
            return JSONResponse({"error": "invalid signature"}, status_code=401)
        except ValueError:
            return JSONResponse({"error": "invalid webhook payload"}, status_code=400)
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

    @app.get("/checkin/{token}", response_class=HTMLResponse)
    async def checkin_page(request: Request, token: str = PathParam(max_length=128)):
        target = engine.checkin_target(token)
        if target is None:
            raise HTTPException(404, "invalid, expired, or used check-in link")
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
        visit = await asyncio.to_thread(engine.check_in, token)
        if visit is None:
            raise HTTPException(409, "invalid, expired, or used check-in link")
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
            lags = sorted(st["lags"])
            st["median_lag"] = lags[len(lags) // 2] if lags else None
        return render(
            request,
            "dashboard.html",
            visits=visits,
            sites={x.id: x for x in store.sites()},
            workers={w.id: w for w in store.workers()},
            schedules={x.id: x for x in store.schedules()},
            upcoming=store.schedules()[:20],
            chain=ledger.verify_chain(store.receipts(), public_key=signer.public_key_b64),
            journal=store.verify_journal(),
            worker_stats=worker_stats,
            queue=inbox.counts(),
            countersign={v.id: reviews.countersign(v.id) for v in visits if v.receipt_id},
        )

    @app.get("/visits/{visit_id}", response_class=HTMLResponse)
    async def visit_page(request: Request, visit_id: str = PathParam(max_length=128)):
        v = store.visit(visit_id)
        if v is None:
            raise HTTPException(404)
        receipt = store.receipt_for_visit(visit_id)
        bundle = reviews.bundle(visit_id) if receipt else None
        site = store.site(v.site_id)
        schedule = store.schedule(v.schedule_id) if v.schedule_id else None
        evidence = store.evidence_for(visit_id)
        return render(
            request,
            "visit.html",
            visit=v,
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
        )

    @app.get("/visits/{visit_id}/media/{name}")
    async def visit_media(visit_id: str = PathParam(max_length=128), name: str = PathParam(max_length=255)):
        for e in store.evidence_for(visit_id):
            if e.media_path and Path(e.media_path).name == name:
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
                raise HTTPException(413, "verification input too large")
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
    async def dispute_pack(visit_id: str = PathParam(max_length=128)):
        """Portable dispute pack: bundle + media + a stdlib-only offline verifier."""
        bundle = await action(reviews.bundle, visit_id)
        data = await asyncio.to_thread(build_pack, store, s.data_dir / "media", bundle)
        return Response(
            data,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="attest-{visit_id}.zip"'},
        )

    @app.get("/sites/{site_id}/pack.zip")
    async def case_pack(site_id: str = PathParam(max_length=128)):
        """Site-level case pack: every visit's signed bundle, a manifest of receipt
        hashes + worker stances, and a stdlib verifier — for pattern disputes."""
        site = store.site(site_id)
        if site is None:
            raise HTTPException(404, "unknown site")

        def build() -> bytes:
            entries = []
            for visit in store.visits(site_id=site.id):
                # Only closed records carry signed receipts; open visits have
                # nothing to verify and are skipped from the case export.
                if store.receipt_for_visit(visit.id) is None:
                    continue
                bundle = reviews.bundle(visit.id)
                entries.append((visit, bundle, reviews.countersign(visit.id)))
            return build_case_pack(store, s.data_dir / "media", site, entries)

        data = await asyncio.to_thread(build)
        return Response(
            data,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="attest-case-{site_id}.zip"'},
        )

    @app.post("/api/visits/{visit_id}/reviews")
    async def coordinator_review(body: ReviewInput, visit_id: str = PathParam(max_length=128)):
        return await action(reviews.coordinator_review, visit_id, body)

    @app.post("/api/visits/{visit_id}/review-link")
    async def issue_review_link(visit_id: str = PathParam(max_length=128)):
        token = await action(reviews.issue_worker_link, visit_id)
        return {"path": f"/review/{token}", "expires_in_seconds": 86400}

    @app.get("/review/{token}", response_class=HTMLResponse)
    async def worker_review_page(request: Request, token: str = PathParam(max_length=128)):
        target = await action(reviews.worker_target, token)
        if target is None:
            raise HTTPException(404, "invalid, expired, or used review link")
        _, bundle = target
        return render(
            request, "worker_review.html", original=bundle.original.payload, token=token, done=False
        )

    @app.post("/review/{token}", response_class=HTMLResponse)
    async def worker_review_submit(
        request: Request,
        token: str = PathParam(max_length=128),
        decision: str = Form(...),
        statement: str = Form(...),
        reported_start: str = Form(""),
        reported_end: str = Form(""),
    ):
        try:
            body = ReviewInput(
                decision=decision,
                statement=statement,
                reported_start=reported_start or None,
                reported_end=reported_end or None,
            )
        except ValueError as exc:
            raise HTTPException(
                422, "Use a valid decision, non-empty statement, and two ordered offset-aware times"
            ) from exc
        await action(reviews.worker_review, token, body)
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

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "summarizer": summarizer.name, "ring_base_url": s.ring_base_url}

    return app


def _verify_pack(data: bytes, public_key: str) -> tuple[bool, str]:
    """Verify an exported pack: dispute pack (bundle.json) or site case pack
    (manifest.json + visits/<id>/bundle.json) — signatures + media digests."""
    import io
    import zipfile

    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = set(z.namelist())
        if "manifest.json" in names:
            return _verify_case_pack(z, public_key)
        bundle = ReviewBundle.model_validate(json.loads(z.read("bundle.json")))
    except Exception as exc:  # noqa: BLE001
        return False, f"not a dispute pack: {exc}"
    return _check_pack_bundle(z, bundle, public_key, media_prefix="media/")


def _check_pack_bundle(z, bundle: ReviewBundle, public_key: str, *, media_prefix: str) -> tuple[bool, str]:
    ok, why = verify_bundle(bundle, public_key=public_key)
    if not ok:
        return False, f"bundle: {why}"
    digests = {
        e.get("media_sha256") for e in bundle.original.payload.get("evidence", []) if e.get("media_sha256")
    }
    matched = 0
    for name in z.namelist():
        if name.startswith(media_prefix) and not name.endswith("/"):
            if hashlib.sha256(z.read(name)).hexdigest() in digests:
                matched += 1
    detail = f"{why}; {matched}/{len(digests)} signed media digests found in pack"
    return (matched == len(digests), detail)


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
        lines.append(f"{vid}: {v.get('state')} ({v.get('countersign', {}).get('state')})")
    total = len(manifest.get("visits", []))
    return True, f"case pack verified — {total} visit record(s) intact: " + "; ".join(lines)


__all__ = ["create_app", "VisitState"]
