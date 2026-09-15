"""HTTP surface: Ring webhook receiver, worker check-in, dashboard, receipts, verification."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic
from fastapi.templating import Jinja2Templates
from ring_sandbox import RingClient, webhooks

from . import ledger
from .config import Settings
from .config import settings as default_settings
from .engine import VisitEngine
from .inbox import WebhookInbox
from .ledger import Signer
from .media import MediaStore
from .models import Receipt, Schedule, Site, VisitState, Worker, utcnow
from .poller import HistoryPoller
from .store import Store
from .summarize import build as build_summarizer

log = logging.getLogger("attest")
_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


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
    ring = ring or RingClient(s.ring_access_token, base_url=s.ring_base_url)
    signer = signer or Signer.load_or_create(s.key_path)
    media = MediaStore(s.data_dir / "media")
    summarizer = build_summarizer(
        s.summarizer, tz=s.timezone, model_id=s.bedrock_model_id, region=s.aws_region
    )
    engine = VisitEngine(store, ring, signer, media, summarizer, s)
    inbox = WebhookInbox(s.data_dir / "webhooks.sqlite3")

    def process_webhook() -> bool:
        job = inbox.claim()
        if job is None:
            return False
        try:
            ev = webhooks.parse(job["raw_body"], signing_key=s.ring_webhook_key, signature=job["signature"])
            outcome = engine.ingest(ev)
            rejected = outcome.ignored_reason not in (None, "duplicate request_id")
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
        if sweep_interval_s > 0:
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
        if request.url.path.startswith("/checkin/"):
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
                "now": utcnow(),
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
            if len(chunks) + len(chunk) > 256 * 1024:
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
    async def checkin_page(request: Request, token: str):
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
    async def checkin_submit(request: Request, token: str):
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
        return render(
            request,
            "dashboard.html",
            visits=visits,
            sites={x.id: x for x in store.sites()},
            workers={w.id: w for w in store.workers()},
            schedules={x.id: x for x in store.schedules()},
            upcoming=[x for x in store.schedules() if x.window_end > utcnow() - timedelta(hours=1)][:10],
            chain=ledger.verify_chain(store.receipts(), public_key=signer.public_key_b64),
        )

    @app.get("/visits/{visit_id}", response_class=HTMLResponse)
    async def visit_page(request: Request, visit_id: str):
        v = store.visit(visit_id)
        if v is None:
            raise HTTPException(404)
        receipt = store.receipt_for_visit(visit_id)
        return render(
            request,
            "visit.html",
            visit=v,
            site=store.site(v.site_id),
            worker=store.worker(v.worker_id) if v.worker_id else None,
            schedule=store.schedule(v.schedule_id) if v.schedule_id else None,
            evidence=store.evidence_for(visit_id),
            receipt=receipt,
            verified=ledger.verify_receipt(receipt, public_key=signer.public_key_b64) if receipt else None,
        )

    @app.get("/visits/{visit_id}/media/{name}")
    async def visit_media(visit_id: str, name: str):
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
    async def receipt_json(receipt_id: str):
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

    @app.get("/verify", response_class=HTMLResponse)
    async def verify_page(request: Request):
        return render(request, "verify.html", result=None, public_key=signer.public_key_b64)

    @app.post("/verify", response_class=HTMLResponse)
    async def verify_submit(request: Request, file: UploadFile | None = None, text: str = Form("")):
        raw = (await file.read()).decode() if file and file.filename else text
        try:
            data = json.loads(raw)
            pk = signer.public_key_b64
            if isinstance(data, list):
                ok, why = ledger.verify_chain([Receipt.model_validate(d) for d in data], public_key=pk)
            else:
                ok, why = ledger.verify_receipt(data, public_key=pk)
        except Exception as exc:  # noqa: BLE001
            ok, why = False, f"could not parse receipt: {exc}"
        return render(request, "verify.html", result=(ok, why), public_key=signer.public_key_b64)

    # ------------------------------------------------------------------ admin (JSON)

    @app.post("/api/sites")
    async def api_site(site: Site):
        return store.put_site(site)

    @app.post("/api/workers")
    async def api_worker(worker: Worker):
        return store.put_worker(worker).model_dump(exclude={"checkin_token"})

    @app.post("/api/schedules")
    async def api_schedule(schedule: Schedule):
        return store.put_schedule(schedule)

    @app.post("/api/visits/{visit_id}/checkin-link")
    async def issue_checkin_link(visit_id: str):
        try:
            token = await asyncio.to_thread(engine.issue_checkin, visit_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"path": f"/checkin/{token}", "expires_in_seconds": 900}

    @app.get("/api/state")
    async def api_state():
        return store.dump()

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

    @app.post("/api/poll")
    async def api_poll():
        n = await asyncio.to_thread(HistoryPoller(engine, store, ring).poll_once)
        return {"ingested": n}

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "summarizer": summarizer.name, "ring_base_url": s.ring_base_url}

    return app


__all__ = ["create_app", "VisitState"]
