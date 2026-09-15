"""HTTP surface: Ring webhook receiver, worker check-in, dashboard, receipts, verification."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from ring_sandbox import RingClient, webhooks

from . import ledger
from .config import Settings
from .config import settings as default_settings
from .engine import VisitEngine
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

        tasks = []
        if sweep_interval_s > 0:
            tasks.append(asyncio.create_task(sweeper()))
        if s.poll_history_seconds > 0:
            tasks.append(asyncio.create_task(history_poller()))
        yield
        for t in tasks:
            t.cancel()

    app = FastAPI(title="Attest", version="0.1.0", lifespan=lifespan)
    app.state.store, app.state.engine, app.state.ring, app.state.signer = (
        store,
        engine,
        ring,
        signer,
    )
    app.state.settings, app.state.media = s, media
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
        raw = await request.body()
        try:
            ev = webhooks.parse(
                raw,
                signing_key=s.ring_webhook_key,
                signature=request.headers.get(webhooks.SIGNATURE_HEADER),
            )
        except webhooks.SignatureError:
            return JSONResponse({"error": "invalid signature"}, status_code=401)
        except ValueError as exc:
            return JSONResponse({"error": f"bad payload: {exc}"}, status_code=400)
        outcome = await asyncio.to_thread(engine.ingest, ev)
        return JSONResponse(
            {
                "status": "processed",
                "event": ev.event_type,
                "visit": outcome.visit.id if outcome.visit else None,
                "transitions": outcome.transitions,
                "ignored": outcome.ignored_reason,
            }
        )

    # ------------------------------------------------------------------ worker check-in

    @app.get("/checkin/{token}", response_class=HTMLResponse)
    async def checkin_page(request: Request, token: str):
        worker = store.worker_by_token(token)
        if worker is None:
            raise HTTPException(404, "unknown check-in link")
        active = [store.active_visit(site.id) for site in store.sites()]
        active = [v for v in active if v and v.worker_id in (None, worker.id)]
        return render(
            request,
            "checkin.html",
            worker=worker,
            visit=active[0] if active else None,
            site=store.site(active[0].site_id) if active else None,
            token=token,
        )

    @app.post("/checkin/{token}")
    async def checkin_submit(token: str):
        visit = await asyncio.to_thread(engine.check_in, token)
        if visit is None:
            raise HTTPException(409, "no open visit to check in to")
        return RedirectResponse(f"/checkin/{token}?done=1", status_code=303)

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
        return store.put_worker(worker)

    @app.post("/api/schedules")
    async def api_schedule(schedule: Schedule):
        return store.put_schedule(schedule)

    @app.get("/api/state")
    async def api_state():
        return store.dump()

    @app.post("/api/sweep")
    async def api_sweep(now: datetime | None = None):
        changed = await asyncio.to_thread(engine.sweep, now)
        return {"changed": [v.id for v in changed]}

    @app.post("/api/poll")
    async def api_poll():
        n = await asyncio.to_thread(HistoryPoller(engine, store, ring).poll_once)
        return {"ingested": n}

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "summarizer": summarizer.name, "ring_base_url": s.ring_base_url}

    return app


__all__ = ["create_app", "VisitState"]
