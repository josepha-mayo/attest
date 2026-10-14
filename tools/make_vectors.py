"""Regenerate tests/vectors/ — the conformance corpus every verifier shares.

Each vector is a small directory holding a real exported pack (pack.zip)
plus expected.json describing what EVERY verifier must conclude about it:
server-side _verify_pack, the embedded verify_bundle.py/verify_case.py
scripts, and the browser _JS_LIB algorithms under node. Fixed Ed25519 seed
bytes keep the issuer keys stable across regenerations; timestamps are
wall-time at generation (the corpus is committed, not byte-reproduced).

Run:  .\\.venv\\Scripts\\python tools/make_vectors.py
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from ring_sandbox import WebhookEvent, webhooks  # noqa: E402
from ring_sandbox.client import RingClient  # noqa: E402
from ring_sandbox.emulator import create_app  # noqa: E402
from ring_sandbox.pytest_plugin import _SyncASGITransport  # noqa: E402
from ring_sandbox.world import DeviceKind, default_world  # noqa: E402

from attest.config import Settings  # noqa: E402
from attest.disputepack import build_case_pack, build_pack, log_member  # noqa: E402
from attest.engine import VisitEngine  # noqa: E402
from attest.ledger import Signer, issuer_document  # noqa: E402
from attest.media import MediaStore  # noqa: E402
from attest.models import ReviewInput, Role, Schedule, Site, Worker  # noqa: E402
from attest.reviews import ReviewService, countersign_status  # noqa: E402
from attest.store import Store  # noqa: E402
from attest.summarize import TemplateSummarizer  # noqa: E402

VECTORS = ROOT / "tests" / "vectors"

# Fixed seed material — the corpus's issuer identities are stable so a regen
# diffs only in timestamps/ids, never in which keys the vectors name.
KEY_A = Signer(Ed25519PrivateKey.from_private_bytes(b"\x11" * 32))
KEY_B = Signer(Ed25519PrivateKey.from_private_bytes(b"\x22" * 32))
KEY_W = Signer(Ed25519PrivateKey.from_private_bytes(b"\x77" * 32))
ATTACKER = Signer(Ed25519PrivateKey.from_private_bytes(b"\x66" * 32))


def _sandbox():
    world = default_world()
    client = RingClient(
        "sandbox-token",
        base_url="http://sandbox",
        transport=_SyncASGITransport(create_app(world)),
    )
    return world, client


def _deployment(tmp: Path, signer: Signer):
    """A fresh engine + a household: site, worker, doorbell cam, sensor."""
    world, client = _sandbox()
    tmp.mkdir(parents=True, exist_ok=True)
    store = Store(tmp / "attest.sqlite3")
    settings = Settings(
        data_dir=tmp,
        admin_token="vectors-admin-token" + "x" * 32,
        ring_webhook_key="k",
        summarizer="template",
        timezone="UTC",
        idle_close_minutes=20,
        arrival_grace_minutes=30,
    )
    engine = VisitEngine(
        store, client, signer, MediaStore(tmp / "media"), TemplateSummarizer("UTC"), settings
    )
    cam = next(d for d in world.devices.values() if d.kind == DeviceKind.DOORBELL)
    sensor = next(d for d in world.devices.values() if d.kind == DeviceKind.CONTACT_SENSOR)
    site = store.put_site(
        Site(
            name="Vector household",
            ring_account_id=world.account_id,
            door_camera_id=cam.id,
            door_sensor_id=sensor.id,
        )
    )
    worker = store.put_worker(Worker(name="Sam Vector", role=Role.HOME_HEALTH_AIDE))
    t0 = (datetime.now(tz=UTC) - timedelta(hours=6)).replace(microsecond=0)
    store.put_schedule(
        Schedule(
            site_id=site.id,
            worker_id=worker.id,
            window_start=t0,
            window_end=t0 + timedelta(hours=1),
            expected_minutes=60,
            service="Vector visit",
        )
    )
    return store, engine, site, cam, t0, world


def _visit(engine: VisitEngine, cam, t0: datetime, world, offset_min: int = 0):
    at = t0 + timedelta(minutes=offset_min)
    # The event must exist in device history before snapshot fetches can
    # serve media for it — mirror what ring_sandbox's fixtures do.
    world.record_event(cam.id, "button_press", at_ms=int(at.timestamp() * 1000))
    ev = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=cam.id, occurred_at=at)
    )
    visit = engine.ingest(ev).visit
    engine.close_for_review(visit.id)
    return visit


def _case_pack(store, engine, site, visits, tmp: Path, *, redact=False, log_fn=None) -> bytes:
    service = ReviewService(store, engine.signer, engine.clock)
    entries = [(v, service.bundle(v.id), countersign_status(service.bundle(v.id))) for v in visits]
    return build_case_pack(
        store,
        tmp / "media",
        site,
        entries,
        redact_media=redact,
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        issuer_key=engine.signer.public_key_b64,
        tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"site:{site.id}", t),
        log_fn=log_fn or (lambda rs: log_member(engine, rs)),
    )


def _dispute_pack(store, engine, media_root, bundle, **kw) -> bytes:
    """A single-visit pack pinned like a real export: the verifier_manifest
    receipt binds this pack's visit scope."""
    vid = bundle.original.visit_id
    return build_pack(
        store,
        media_root,
        bundle,
        tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"visit:{vid}", t),
        log_fn=lambda rs: log_member(engine, rs),
        **kw,
    )


def _rewrite_zip(data: bytes, transform) -> bytes:
    """Rebuild the zip through transform(name, bytes) -> bytes|None|DROP."""
    src = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name in src.namelist():
            if name.endswith("/"):
                continue
            body = transform(name, src.read(name))
            if body is not None:
                z.writestr(name, body)
    return out.getvalue()


def _write_vector(name: str, pack: bytes, expected: dict, extras: dict[str, bytes] | None = None) -> None:
    d = VECTORS / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    (d / "pack.zip").write_bytes(pack)
    # LF bytes explicitly — .gitattributes pins tests/vectors/** to -text, so
    # a CRLF from Windows text mode would land in the committed corpus.
    (d / "expected.json").write_bytes((json.dumps(expected, indent=2) + "\n").encode("utf-8"))
    for fname, body in (extras or {}).items():
        (d / fname).write_bytes(body)
    print(f"  {name}: {expected['note']}")


def main() -> None:
    print("generating conformance vectors into tests/vectors/")
    tmp = Path(tempfile.mkdtemp(prefix="attest-vectors-"))

    # --- deployment one: rotate mid-story, then revoke the retired key ---
    store, engine, site, cam, t0, world = _deployment(tmp / "d1", KEY_A)
    v1 = _visit(engine, cam, t0, world)
    service_a = ReviewService(store, KEY_A, engine.clock)
    bundle1 = service_a.bundle(v1.id)
    media_root = tmp / "d1" / "media"

    clean_bundle = _dispute_pack(store, engine, media_root, bundle1)
    _write_vector(
        "ok-clean-bundle",
        clean_bundle,
        {
            "kind": "bundle",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["verified", "media", "pinned", "transparency log"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 1,
                "suspect_count": 0,
                "lifecycle_suspect_count": 0,
                "verdict": "ok",
            },
            "note": "one visit, one key, media digests all present — the baseline",
        },
    )

    redacted = _dispute_pack(store, engine, media_root, bundle1, redact_media=True)
    _write_vector(
        "ok-redacted-media",
        redacted,
        {
            "kind": "bundle",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["withheld", "pinned", "transparency log"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 1,
                "suspect_count": 0,
                "lifecycle_suspect_count": 0,
                "verdict": "ok",
            },
            "note": "media bytes withheld by redaction; signed digests still verify",
        },
    )

    # The pre-rotation export: every record signed under KEY_A and no
    # lifecycle attestations aboard — the issuer-doc vectors pin it through
    # the discovery document alone.
    pre_rotation_pack = _case_pack(store, engine, site, [v1], tmp / "d1")

    first_signed = store.receipt_for_visit(v1.id).issued_at
    rotation = engine.issue_key_rotation(KEY_B.public_key_b64, "planned rotation")
    engine.signer = KEY_B
    engine.issue_key_adoption(KEY_A.public_key_b64, rotation)
    v2 = _visit(engine, cam, t0, world, offset_min=90)

    rotated_pack = _case_pack(store, engine, site, [v1, v2], tmp / "d1")
    _write_vector(
        "ok-rotated-case",
        rotated_pack,
        {
            "kind": "case",
            "pin": KEY_A.public_key_b64,  # pinning the RETIRED key still verifies
            "verdict": "ok",
            "detail_contains": [
                "issuer keys linked via the signed rotation chain",
                "pinned",
                "transparency log",
            ],
            "js": {
                "bundle_ok": True,
                "trusted_count": 2,
                "suspect_count": 0,
                "lifecycle_suspect_count": 0,
                "verdict": "ok",
            },
            "note": "case pack spanning a signed rotation — predecessor pin verifies both eras",
        },
    )

    # The pool-root graft: key_rotations.json is unsigned pack content, so a
    # self-signed key_revocation written at sequence 0 sorts ahead of every
    # honest receipt. Revocation authority must anchor at the verified
    # issuer's lineage, not pool position — the graft is inert everywhere.
    bundle2 = ReviewService(store, KEY_B, engine.clock).bundle(v2.id)
    forged_revocation = ATTACKER.issue(
        visit_id="key:graft",
        sequence=0,
        prev_hash=None,
        facts={
            "record_type": "key_revocation",
            "revoked_key": KEY_B.public_key_b64,
            "suspect_after": "2000-01-01T00:00:00+00:00",
            "reason": "grafted low-sequence smear attempt",
        },
    )

    def graft_revocation(name: str, body: bytes):
        if name != "key_rotations.json":
            return body
        rj = json.loads(body)
        rj["rotations"] = [forged_revocation.model_dump(mode="json")] + rj["rotations"]
        return json.dumps(rj).encode()

    _write_vector(
        "ok-grafted-revocation",
        _rewrite_zip(_dispute_pack(store, engine, media_root, bundle2), graft_revocation),
        {
            "kind": "bundle",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["verified", "pinned", "transparency log"],
            "detail_excludes": ["suspect window"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 2,
                "suspect_count": 0,
                "lifecycle_suspect_count": 0,
                "verdict": "ok",
            },
            "note": "a self-signed key_revocation grafted into key_rotations.json "
            "is inert twice over — it can't join the signed trust walk, and "
            "foreign-signed receipts owe no log proof so the graft can't "
            "kill the pack either",
        },
    )

    # Revoke the retired key with a suspect window covering its whole output —
    # the rotation receipt itself lands inside the window (an honest pack
    # flags that the pivot's own provenance is qualified).
    engine.issue_key_revocation(KEY_A.public_key_b64, first_signed - timedelta(seconds=1), "demo compromise")
    revoked_pack = _case_pack(store, engine, site, [v1, v2], tmp / "d1")
    _write_vector(
        "ok-revoked-case",
        revoked_pack,
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["suspect window", "trust pivot", "pinned", "transparency log"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 2,
                "suspect_count": 1,
                "lifecycle_suspect_count": 1,
                "verdict": "ok",
            },
            "note": "revocation annotates: records + the pivot receipt itself sit in the suspect window",
        },
    )

    # --- issuer-document pinning: the discovery doc's signed lifecycle is
    # the only bridge between a pre-rotation export and the current key ---
    issuer_doc_now = issuer_document(KEY_B.public_key_b64, store.receipts())
    _write_vector(
        "ok-issuer-doc-pin",
        pre_rotation_pack,
        {
            "kind": "case",
            "issuer_doc": "issuer.json",
            "verdict": "ok",
            "detail_contains": ["suspect window", "pinned", "transparency log"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 1,
                "pin_linked": True,
                "suspect_count": 1,
                "lifecycle_suspect_count": 1,
                "verdict": "ok",
            },
            "note": "pre-rotation pack pinned to the deployment's CURRENT issuer "
            "through the discovery document — and the doc's revocation still "
            "annotates the retired key's window",
        },
        extras={"issuer.json": json.dumps(issuer_doc_now, indent=2).encode()},
    )

    # The same graft riding the discovery channel: an issuer document whose
    # key_receipts carry a forged seq-0 revocation naming the CURRENT key.
    # The honest revocation (retired KEY_A) must still annotate while the
    # graft stays inert — the suspect count proves both at once.
    issuer_doc_grafted = json.loads(json.dumps(issuer_doc_now))
    issuer_doc_grafted["key_receipts"] = [forged_revocation.model_dump(mode="json")] + issuer_doc_grafted[
        "key_receipts"
    ]
    _write_vector(
        "ok-issuer-doc-graft",
        rotated_pack,
        {
            "kind": "case",
            "issuer_doc": "issuer.json",
            "verdict": "ok",
            "detail_contains": ["suspect window", "pinned", "transparency log"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 2,
                "pin_linked": True,
                "suspect_count": 1,
                # the KEY_A-signed rotation rides BOTH the doc and the pack's
                # own attestations — two copies inside its suspect window
                "lifecycle_suspect_count": 2,
                "verdict": "ok",
            },
            "note": "a forged revocation inside the issuer document cannot "
            "smear the live key — the honest revocation still annotates",
        },
        extras={"issuer.json": json.dumps(issuer_doc_grafted, indent=2).encode()},
    )

    _write_vector(
        "ok-issuer-doc-older",
        rotated_pack,
        {
            "kind": "case",
            "issuer_doc": "issuer.json",
            "verdict": "ok",
            "detail_contains": ["issuer keys linked", "pinned", "transparency log"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 2,
                "pin_linked": True,
                "suspect_count": 0,
                "lifecycle_suspect_count": 0,
                "verdict": "ok",
            },
            "note": "an OLDER document still verifies the rotated deployment's "
            "newer packs — the link runs the other direction through the pack's "
            "own lifecycle attestations",
        },
        extras={
            "issuer.json": json.dumps(
                {
                    "schema": "attest.issuer/1",
                    "issuer_key": KEY_A.public_key_b64,
                    "key_receipts": [],
                },
                indent=2,
            ).encode()
        },
    )

    # A foreign deployment's document: real signed lifecycle receipts, just
    # the wrong lineage — the pin has no signed link to this pack.
    attacker_successor = Signer(Ed25519PrivateKey.from_private_bytes(b"\x77" * 32))
    foreign_rotation = ATTACKER.issue(
        visit_id="key:rot",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "key_rotation",
            "previous_key": ATTACKER.public_key_b64,
            "new_key": attacker_successor.public_key_b64,
        },
    )
    foreign_adoption = attacker_successor.issue(
        visit_id="key:adopt",
        sequence=2,
        prev_hash=foreign_rotation.payload_hash,
        facts={
            "record_type": "key_adoption",
            "previous_key": ATTACKER.public_key_b64,
            "rotation_receipt": {"id": foreign_rotation.id, "hash": foreign_rotation.payload_hash},
        },
    )
    foreign_doc = {
        "schema": "attest.issuer/1",
        "issuer_key": ATTACKER.public_key_b64,
        "key_receipts": [
            foreign_rotation.model_dump(mode="json"),
            foreign_adoption.model_dump(mode="json"),
        ],
    }
    _write_vector(
        "fail-foreign-issuer-doc",
        pre_rotation_pack,
        {
            "kind": "case",
            "issuer_doc": "issuer.json",
            "verdict": "fail",
            "detail_contains": ["issuer"],
            "js": {"bundle_ok": True, "pin_linked": False, "verdict": "fail"},
            "note": "a foreign deployment's document cannot pin this pack — "
            "the pin must reach the issuer through signed lifecycle",
        },
        extras={"issuer.json": json.dumps(foreign_doc, indent=2).encode()},
    )

    # --- deployment two: orphaned rotation (pivot without countersign) ---
    s2, e2, site2, cam2, t02, world2 = _deployment(tmp / "d2", KEY_A)
    w1 = _visit(e2, cam2, t02, world2)
    e2.issue_key_rotation(KEY_B.public_key_b64, "crash before adoption")
    e2.signer = KEY_B  # successor signs a visit but NEVER countersigned
    w2 = _visit(e2, cam2, t02, world2, offset_min=90)
    orphan_pack = _case_pack(s2, e2, site2, [w1, w2], tmp / "d2")
    _write_vector(
        "fail-orphan-rotation",
        orphan_pack,
        {
            "kind": "case",
            "pin": KEY_A.public_key_b64,
            "verdict": "fail",
            "detail_contains": ["issuer"],
            # issuer self-declares as B; the A-signed bundle can't verify
            "js": {"bundle_ok": False, "verdict": "fail"},
            "note": "a rotation the successor never countersigned cannot pivot trust",
        },
    )

    # --- negative vectors: byte-level tampering on the clean pack ---
    def tamper_payload(name: str, body: bytes):
        if name != "bundle.json":
            return body
        b = json.loads(body)
        b["original"]["payload"]["tampered"] = True
        return json.dumps(b).encode()

    _write_vector(
        "fail-payload-tamper",
        _rewrite_zip(clean_bundle, tamper_payload),
        {
            "kind": "bundle",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["hash"],
            "js": {"bundle_ok": False, "verdict": "fail"},
            "note": "a flipped payload field breaks the signed hash",
        },
    )

    def tamper_sig(name: str, body: bytes):
        if name != "bundle.json":
            return body
        b = json.loads(body)
        b["original"]["signature"] = "A" + b["original"]["signature"][1:]
        return json.dumps(b).encode()

    _write_vector(
        "fail-signature-tamper",
        _rewrite_zip(clean_bundle, tamper_sig),
        {
            "kind": "bundle",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": [],
            "js": {"bundle_ok": False, "verdict": "fail"},
            "note": "a corrupted signature must never verify",
        },
    )

    def tamper_media(name: str, body: bytes):
        if name.startswith("media/"):
            return bytes([body[0] ^ 0xFF]) + body[1:]
        return body

    _write_vector(
        "fail-media-mismatch",
        _rewrite_zip(clean_bundle, tamper_media),
        {
            "kind": "bundle",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["media"],
            # bundle_ok stays true: only the pack-driver media pass catches it
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "media bytes that don't hash to the signed digest are caught",
        },
    )

    src = zipfile.ZipFile(io.BytesIO(clean_bundle))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n in src.namelist():
            if not n.endswith("/"):
                z.writestr(n, src.read(n))
        z.writestr("smuggled.txt", b"planted content")
    _write_vector(
        "fail-smuggled-member",
        out.getvalue(),
        {
            "kind": "bundle",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["smuggled.txt"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a member the pack format doesn't name fails closed",
        },
    )

    _write_vector(
        "fail-wrong-pin",
        clean_bundle,
        {
            "kind": "bundle",
            "pin": ATTACKER.public_key_b64,
            "verdict": "fail",
            "detail_contains": [],
            # The browser has no --key flag: self-declared it verifies — the
            # pin is enforced where a pin can be expressed (server/CLI/doc).
            "js": {"bundle_ok": True, "verdict": "ok"},
            "note": "pinning an unrelated key must not bless the pack",
        },
    )

    # --- negative vectors: the signed verifier_manifest pin. Membership
    # whitelists check names — only the pin binds the tooling BYTES, so every
    # surface must reject forged, grafted, or foreign-signed pins alike.
    # The tool tamper stays benign (a comment) so the honest check inside
    # the running script still fires and reports itself.
    def forged_tool(name: str, body: bytes):
        if name != "verify_bundle.py":
            return body
        return body + b"\n# doctored\n"

    _write_vector(
        "fail-forged-verifier-tool",
        _rewrite_zip(clean_bundle, forged_tool),
        {
            "kind": "bundle",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["bytes differ from the issuer-signed pin"],
            "js": {"verdict": "fail"},
            "note": "a modified verify_bundle.py fails its own signed pin — "
            "membership whitelists names, only the manifest pins bytes",
        },
    )

    # A pinned member absent from the zip — the membership whitelist only
    # bounds what MAY be present, never what MUST be.
    _write_vector(
        "fail-missing-pinned-tool",
        _rewrite_zip(rotated_pack, lambda name, body: None if name == "verify.html" else body),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["pinned verifier tool missing"],
            "js": {"verdict": "fail"},
            "note": "a tool the signed pin names but the pack lacks fails — the pin binds both directions",
        },
    )

    # Legacy packs predate the pin — absence is reported, never failed.
    _write_vector(
        "ok-legacy-no-manifest",
        _rewrite_zip(
            clean_bundle,
            lambda name, body: None if name == "verifier_manifest.json" else body,
        ),
        {
            "kind": "bundle",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["verified", "media", "transparency log"],
            "detail_excludes": ["pinned by issuer-signed manifest"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 1,
                "suspect_count": 0,
                "lifecycle_suspect_count": 0,
                "verdict": "ok",
            },
            "note": "a pre-pin pack still verifies — the manifest is optional "
            "when absent, mandatory when present",
        },
    )

    # Case pack with a manifest-listed visit removed from the zip.
    gone = _rewrite_zip(
        rotated_pack,
        lambda name, body: None if name == f"visits/{v1.id}/bundle.json" else body,
    )
    _write_vector(
        "fail-missing-listed",
        gone,
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": [v1.id],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a bundle the signed manifest lists but the zip lacks fails",
        },
    )

    # --- verifier tooling pin: the signed verifier_manifest binds the pack's
    # own scripts to the issuer — a forged always-green verifier can no
    # longer ride a genuine pack. The ok-path pin is exercised by every
    # regenerated vector above; these vectors attack the pin itself. ---
    doctored = _rewrite_zip(
        rotated_pack,
        lambda name, body: body + b"\n# doctored after export\n" if name == "verify_case.py" else body,
    )
    _write_vector(
        "fail-doctored-verifier",
        doctored,
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["issuer-signed pin"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a post-export edit to verify_case.py — membership checks "
            "names, only the signed pin checks the bytes",
        },
    )

    # A valid verifier_manifest replayed from a DIFFERENT scope: the dispute
    # pack's pin names visit:{v1}, the case pack expects site:{site} — the
    # scope binding makes the graft detectable on every surface.
    vm_visit_scope = zipfile.ZipFile(io.BytesIO(clean_bundle)).read("verifier_manifest.json")
    grafted_pin = _rewrite_zip(
        rotated_pack,
        lambda name, body: vm_visit_scope if name == "verifier_manifest.json" else body,
    )
    _write_vector(
        "fail-grafted-pin",
        grafted_pin,
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["different pack"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a verifier_manifest signed for another pack cannot pin "
            "this one — the scope binding stops the replay",
        },
    )

    # A well-formed pin under a foreign key: the receipt verifies, the scope
    # matches, but the signer sits outside the trusted issuer chain.
    real_tools = json.loads(zipfile.ZipFile(io.BytesIO(rotated_pack)).read("verifier_manifest.json"))[
        "payload"
    ]["tools"]
    foreign_vm = ATTACKER.issue(
        visit_id="export-tools:foreign",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "verifier_manifest",
            "scope": f"site:{site.id}",
            "tools": real_tools,
        },
    )
    foreign_pin = _rewrite_zip(
        rotated_pack,
        lambda name, body: (
            json.dumps(foreign_vm.model_dump(mode="json"), indent=2).encode()
            if name == "verifier_manifest.json"
            else body
        ),
    )
    _write_vector(
        "fail-foreign-pin",
        foreign_pin,
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["outside the trusted issuer chain"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a valid pin receipt under an untrusted key — signature "
            "integrity is not issuer authority",
        },
    )

    # --- transparency grafts: the log member is as attackable as the pack ---
    def _log_edit(pack: bytes, fn) -> bytes:
        return _rewrite_zip(
            pack,
            lambda name, body: (
                json.dumps(fn(json.loads(body)), indent=2).encode() if name == "log_checkpoint.json" else body
            ),
        )

    def _drop_first_proof(doc: dict) -> dict:
        doc["proofs"].pop(sorted(doc["proofs"])[0])
        return doc

    _write_vector(
        "fail-missing-log-proof",
        _log_edit(rotated_pack, _drop_first_proof),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["no inclusion proof"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a pack receipt silently dropped from log_checkpoint.json — "
            "the pack cannot claim log membership it does not prove",
        },
    )

    def _swap_first_two_proofs(doc: dict) -> dict:
        keys = sorted(doc["proofs"])
        doc["proofs"][keys[0]], doc["proofs"][keys[1]] = (
            doc["proofs"][keys[1]],
            doc["proofs"][keys[0]],
        )
        return doc

    _write_vector(
        "fail-grafted-log-proof",
        _log_edit(rotated_pack, _swap_first_two_proofs),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["does not reach the signed tree head"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "another receipt's audit path grafted on — the Merkle "
            "math catches what a presence check never would",
        },
    )

    # --- the embedded checkpoint chain: prior signed heads ride the pack so
    # non-adjacent exports reconcile offline. Mint a mid-history checkpoint
    # first so the export's `chain` list is non-empty. ---
    engine.issue_log_checkpoint()
    chain_pack = _case_pack(store, engine, site, [v1, v2], tmp / "d1")
    _write_vector(
        "ok-checkpoint-chain",
        chain_pack,
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["prior signed head(s)"],
            "js": {"bundle_ok": True, "verdict": "ok"},
            "note": "the pack embeds prior signed checkpoint heads — each "
            "verified under the issuer lineage so two exports can reconcile "
            "non-adjacent heads offline, hop-by-hop",
        },
    )

    _RESERVED = {"schema", "sequence", "prev_hash", "receipt_id", "issued_at", "visit_id"}

    def _foreign_chain_member(doc: dict) -> dict:
        doc = dict(doc)
        m0 = doc["chain"][0]["payload"]
        foreign = ATTACKER.issue(
            visit_id="log-fork:foreign",
            sequence=1,
            prev_hash=None,
            facts={k: v for k, v in m0.items() if k not in _RESERVED},
        ).model_dump(mode="json")
        doc["chain"] = doc["chain"] + [foreign]
        return doc

    _write_vector(
        "fail-chain-foreign-member",
        _log_edit(chain_pack, _foreign_chain_member),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["outside the issuer lineage"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a chain member signed by a foreign key — the walk could "
            "never trust a bridge it names, so the pack fails closed",
        },
    )

    def _dup_chain_head(doc: dict) -> dict:
        # A second signed head at an existing chain member's size under a
        # different root — the issuer's own key signs it, so only the
        # one-root-per-size rule can catch it.
        doc = dict(doc)
        mp = dict(doc["chain"][0]["payload"])
        forged = engine.signer.issue(
            visit_id=f"log-fork-dup:{mp['tree_size']}",
            sequence=1,
            prev_hash=None,
            facts={
                "record_type": "log_checkpoint",
                "tree_size": mp["tree_size"],
                "root_sha256": "ab" * 32,
                "journal_head": "ab" * 32,
            },
        ).model_dump(mode="json")
        doc["chain"] = doc["chain"] + [forged]
        return doc

    _write_vector(
        "fail-chain-dup-size",
        _log_edit(chain_pack, _dup_chain_head),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["two signed heads"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "two issuer-signed heads at one tree size inside a single "
            "document is a fork claim the reconcile cannot read honestly — "
            "the pack refuses it at verification time",
        },
    )

    def _case_variant_member(doc: dict) -> dict:
        # The boundary twin of dup-size: two members at one size whose roots
        # differ only in hex CASE are the same decoded head — dedupe on
        # bytes, not spelling, or the browser convicts where Python passes.
        doc = dict(doc)
        mp = dict(doc["chain"][0]["payload"])
        twin = engine.signer.issue(
            visit_id=f"log-case:{mp['tree_size']}",
            sequence=1,
            prev_hash=None,
            facts={k: (v.upper() if k == "root_sha256" else v) for k, v in mp.items() if k not in _RESERVED},
        ).model_dump(mode="json")
        doc["chain"] = doc["chain"] + [twin]
        return doc

    _write_vector(
        "ok-chain-case-roots",
        _log_edit(chain_pack, _case_variant_member),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["prior signed head(s)"],
            "js": {"bundle_ok": True, "verdict": "ok"},
            "note": "two members carry the SAME head at one size, spelled "
            "upper- and lower-case — one head, not a collision; every surface "
            "dedupes on the decoded root",
        },
    )

    def _quoted_bridge_member(doc: dict) -> dict:
        # A signed member whose `extends.first` is spelled as a digit STRING —
        # verify_extends coerces it on every surface, so intake and the
        # reconcile walk must read it identically (a strict isinstance gate
        # dead-ends Python where the browser still walks).
        doc = dict(doc)
        donor = next(m for m in doc["chain"] if isinstance(m["payload"].get("extends"), dict))
        mp = {k: v for k, v in donor["payload"].items() if k not in _RESERVED}
        mp = json.loads(json.dumps(mp))
        mp["extends"]["first"] = str(mp["extends"]["first"])
        respelled = engine.signer.issue(
            visit_id=f"log-quoted:{mp['tree_size']}",
            sequence=1,
            prev_hash=None,
            facts=mp,
        ).model_dump(mode="json")
        doc["chain"] = [m for m in doc["chain"] if m["payload"]["tree_size"] != mp["tree_size"]] + [respelled]
        return doc

    _write_vector(
        "ok-chain-quoted-bridge",
        _log_edit(chain_pack, _quoted_bridge_member),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["prior signed head(s)"],
            "js": {"bundle_ok": True, "verdict": "ok"},
            "note": "a member's signed extends.first spelled as a digit "
            "string — signed material is evaluated with JS-mirrored "
            "coercion, so the quoted hop is legal on every surface",
        },
    )

    def _nonhex_root_member(doc: dict) -> dict:
        # 64 chars but not hex — a len()==64 gate alone would pass it, then
        # Python's decode-and-skip vs the browser's string compare would
        # deliver different verdicts on one artifact. Strict hex at intake.
        doc = dict(doc)
        mp = dict(doc["chain"][0]["payload"])
        forged = engine.signer.issue(
            visit_id=f"log-nonhex:{mp['tree_size']}",
            sequence=1,
            prev_hash=None,
            facts={
                "record_type": "log_checkpoint",
                "tree_size": mp["tree_size"],
                "root_sha256": "zz" * 32,
                "journal_head": "ab" * 32,
            },
        ).model_dump(mode="json")
        doc["chain"] = [m for m in doc["chain"] if m["payload"]["tree_size"] != mp["tree_size"]] + [forged]
        return doc

    _write_vector(
        "fail-chain-nonhex-root",
        _log_edit(chain_pack, _nonhex_root_member),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["malformed or non-prior head"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a 64-char non-hex member root — the strictest spelling "
            "wins on every surface, so the pack fails closed at intake "
            "instead of diverging mid-walk",
        },
    )

    # --- a cosigned checkpoint: the witness attestation riding the pack ---
    def _attach_cosig(doc: dict) -> dict:
        from attest.ledger import Signer

        cp = doc["checkpoint"]
        p = cp["payload"]
        witness = Signer.ephemeral()
        cosig = witness.issue(
            visit_id=f"witness:{p.get('issuer', 'x')[:8]}:{cp['id']}",
            sequence=1,
            prev_hash=None,
            facts={
                "record_type": "witness_cosignature",
                "subject_checkpoint": cp["id"],
                "subject_tree_size": p["tree_size"],
                "subject_root_sha256": p["root_sha256"],
                "subject_issuer": cp["public_key"],
            },
        )
        doc["cosignatures"] = [cosig.model_dump(mode="json")]
        return doc

    _write_vector(
        "ok-witness-cosigned",
        _log_edit(rotated_pack, _attach_cosig),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["cosigned by 1 witness"],
            "js": {"bundle_ok": True, "verdict": "ok"},
            "note": "an independent witness's counter-signature rides the "
            "checkpoint doc — verified under its own key, reported as an "
            "auxiliary attestation, never a gate",
        },
    )

    def _mismatch_cosig(doc: dict) -> dict:
        doc = _attach_cosig(doc)
        doc["cosignatures"][0]["payload"]["subject_root_sha256"] = "00" * 32
        return doc

    _write_vector(
        "ok-forged-cosig-ignored",
        _log_edit(rotated_pack, _mismatch_cosig),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "ok",
            "js": {"bundle_ok": True, "verdict": "ok"},
            "note": "a cosig attesting a DIFFERENT head (or one whose "
            "signature fails after the edit) counts as absent — the pack "
            "still verifies on its own proofs; auxiliary attestations "
            "report honestly, never gate",
        },
    )

    # --- a REAL witness deployment: cosignature + its own-log anchor. The
    # witness is a second Attest runtime — the cosign exchange runs the same
    # code the /api/witness/cosign route serves, so the anchor the pack
    # carries is the artifact a live deployment produces. ---
    from attest import logmonitor
    from attest.models import Receipt as _Receipt

    w_store, w_engine, _ws, _wc, _wt, _ww = _deployment(tmp / "wit", KEY_W)

    def _cosign_with_anchor(cp):
        status, out = logmonitor.witness_cosign(
            w_store,
            w_engine.signer,
            {
                "issuer_doc": issuer_document(engine.signer.public_key_b64, store.receipts()),
                "checkpoint": cp.model_dump(mode="json"),
            },
        )
        assert status == 200, out
        cosig = out["cosignature"]
        # Mirror the app route: the witness checkpoints its own log on the
        # spot and returns the cosig's inclusion proof — 'the witness
        # attested this' is committed the moment it is served.
        w_cp = w_engine.issue_log_checkpoint()
        proof = w_engine.inclusion_proof(_Receipt.model_validate(cosig), size=int(w_cp.payload["tree_size"]))
        anchors = {}
        if proof is not None:
            anchors[cosig["id"]] = {"checkpoint": w_cp.model_dump(mode="json"), "proof": proof}
        return [cosig], anchors

    anchored_pack = _case_pack(
        store,
        engine,
        site,
        [v1],
        tmp / "d1",
        log_fn=lambda rs: log_member(engine, rs, cosign_fn=_cosign_with_anchor),
    )
    _write_vector(
        "ok-witness-anchored",
        anchored_pack,
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["anchored in the witness", "own published log"],
            "js": {"bundle_ok": True, "verdict": "ok"},
            "note": "the witness's attestation is itself committed to the "
            "witness's own transparency log — the pack proves the cosignature "
            "was published, not just signed and handed over",
        },
    )

    def _break_anchor(doc: dict) -> dict:
        cid = next(iter(doc["cosig_anchors"]))
        doc["cosig_anchors"][cid]["proof"]["path"] = ["00" * 32]
        return doc

    _write_vector(
        "fail-anchor-proof-graft",
        _log_edit(anchored_pack, _break_anchor),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["does not reach"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a packed anchor whose cosig cannot reach the anchor's "
            "signed head — a claimed anchor is either verifiable or a lie; "
            "every verifier fails closed",
        },
    )

    # --- embedded evidence receipts: `attest checkpoint --include monitor:`
    # rides a site pack the same way it rides an exported checkpoint doc ---
    obs1 = engine.issue_monitor_observation(
        {
            "observed_at": t0.isoformat(),
            "subject": {"url": "https://vector.example", "issuer_key": engine.signer.public_key_b64},
            "outcome": "steady",
            "served_head": {"tree_size": 3, "root_sha256": "aa" * 32},
            "pin_before": {"issuer_key": engine.signer.public_key_b64, "tree_size": 3},
            "pin_after": {"issuer_key": engine.signer.public_key_b64, "tree_size": 3},
        }
    )
    obs2 = engine.issue_monitor_observation(
        {
            "observed_at": (t0 + timedelta(minutes=5)).isoformat(),
            "subject": {"url": "https://vector.example", "issuer_key": engine.signer.public_key_b64},
            "outcome": "alert",
            "served_head": {"tree_size": 3, "root_sha256": "bb" * 32},
            "pin_before": {"issuer_key": engine.signer.public_key_b64, "tree_size": 3},
            "served_doc": {"tree_size": 3, "root_sha256": "bb" * 32, "note": "served verbatim"},
        }
    )

    def _log_embed(rs):
        doc = log_member(engine, rs)
        n = int(doc["checkpoint"]["payload"]["tree_size"])
        doc["receipts"] = [r.model_dump(mode="json") for r in (obs1, obs2)]
        for r in (obs1, obs2):
            proof = engine.inclusion_proof(r, size=n)
            assert proof is not None, "monitor receipt must be inside the committed tree"
            doc["proofs"][r.payload_hash] = proof
        return doc

    embedded_pack = _case_pack(store, engine, site, [v1], tmp / "d1", log_fn=_log_embed)
    _write_vector(
        "ok-embedded-monitor-trail",
        embedded_pack,
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["receipt(s) proven inside"],
            "js": {"bundle_ok": True, "verdict": "ok"},
            "note": "monitor_observation receipts embedded in the checkpoint "
            "doc — each verified under the issuer lineage and proven inside "
            "the signed head, so the watch trail travels with the pack",
        },
    )

    def _foreign_embed(doc: dict) -> dict:
        fake = ATTACKER.issue(
            visit_id=f"monitor:{('cd' * 8)}",
            sequence=1,
            prev_hash=None,
            facts={"record_type": "monitor_observation", "outcome": "steady"},
        )
        doc["receipts"] = doc["receipts"] + [fake.model_dump(mode="json")]
        return doc

    _write_vector(
        "fail-embedded-foreign-receipt",
        _log_edit(embedded_pack, _foreign_embed),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["outside the issuer lineage"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "an embedded receipt signed outside the issuer lineage — "
            "embedded evidence must bind the pack's issuer or it is grafted "
            "testimony",
        },
    )

    def _tamper_embed(doc: dict) -> dict:
        doc["receipts"][0]["payload"]["outcome"] = "alert"
        return doc

    _write_vector(
        "fail-embedded-tampered-receipt",
        _log_edit(embedded_pack, _tamper_embed),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["embedded receipt"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "an embedded receipt's payload flipped — payload hash "
            "and signature both fail; a doctored observation can never ride "
            "the signed head",
        },
    )

    def _junk_proof(doc: dict) -> dict:
        doc["proofs"]["ff" * 32] = {"leaf_index": 0, "path": ["00" * 32]}
        return doc

    _write_vector(
        "fail-unreferenced-junk-proof",
        _log_edit(embedded_pack, _junk_proof),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["unreferenced inclusion proof"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a proof entry referencing nothing and reaching nothing — "
            "every proofs entry must verify; unexplained material is a lie, "
            "not decoration",
        },
    )

    # --- cross-surface JSON-typing conformance: a verifier that treats these
    # edge spellings differently from its siblings hands an attacker two
    # verdicts for the same bytes. These vectors pin the contract end-to-end.
    def _edit_first_proof(mutate):
        def f(doc: dict) -> dict:
            key = sorted(doc["proofs"])[0]
            mutate(doc["proofs"][key])
            return doc

        return f

    def _float_index(p: dict) -> None:
        p["leaf_index"] = float(p["leaf_index"])

    def _fractional_index(p: dict) -> None:
        p["leaf_index"] = p["leaf_index"] + 0.5

    def _string_index(p: dict) -> None:
        p["leaf_index"] = str(p["leaf_index"])

    _write_vector(
        "ok-float-leaf-index",
        _log_edit(embedded_pack, _edit_first_proof(_float_index)),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["pinned", "transparency log"],
            "js": {"bundle_ok": True, "verdict": "ok"},
            "note": "leaf_index spelled 5.0 — JSON keeps no int/float "
            "distinction, so Number.isInteger parity means every verifier "
            "accepts integral floats identically",
        },
    )

    _write_vector(
        "fail-fractional-leaf-index",
        _log_edit(embedded_pack, _edit_first_proof(_fractional_index)),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["does not reach the signed tree head"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "leaf_index 5.5 — non-integral indices are not integers "
            "on any surface; Python must not silently truncate where JS rejects",
        },
    )

    _write_vector(
        "fail-string-leaf-index",
        _log_edit(embedded_pack, _edit_first_proof(_string_index)),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["does not reach the signed tree head"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "leaf_index as a quoted string — JSON-typed fields must "
            "not pass through Python's permissive int() where JS === rejects",
        },
    )

    _write_vector(
        "fail-bool-leaf-index",
        _log_edit(embedded_pack, _edit_first_proof(lambda p: p.__setitem__("leaf_index", True))),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["does not reach the signed tree head"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "leaf_index true — bool is an int subclass in Python but "
            "not an integer in JSON; Number.isInteger parity rejects it",
        },
    )

    def _space_hex(doc: dict) -> dict:
        key = sorted(doc["proofs"])[0]
        node = doc["proofs"][key]["path"][0]
        doc["proofs"][key]["path"][0] = " ".join(node[i : i + 2] for i in range(0, len(node), 2))
        return doc

    _write_vector(
        "fail-spaced-hex-proof",
        _log_edit(embedded_pack, _space_hex),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["log_checkpoint.json:", "proof"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a proof node spelled with spaces between byte pairs — "
            "Python bytes.fromhex tolerates whitespace where strict hex "
            "rejects; every surface now fails closed identically",
        },
    )

    def _crafted_head(tree_size_fn):
        """Swap the checkpoint for a fresh signed head with a doctored
        tree_size — the signature stays valid, so the vector isolates the
        tree-head type/bounds check rather than signature rejection."""

        def _log_fn(rs):
            doc = log_member(engine, rs)
            payload = doc["checkpoint"]["payload"]
            n = payload["tree_size"]
            cp = engine.signer.issue(
                visit_id=f"log:{n}:crafted-head",
                sequence=doc["checkpoint"]["sequence"] + 1,
                prev_hash=doc["checkpoint"]["payload_hash"],
                facts={
                    "record_type": "log_checkpoint",
                    "tree_size": tree_size_fn(n),
                    "root_sha256": payload["root_sha256"],
                    "leaf_input": payload.get("leaf_input"),
                    "journal_head": payload.get("journal_head"),
                },
            )
            doc["checkpoint"] = cp.model_dump(mode="json")
            return doc

        return _log_fn

    _write_vector(
        "ok-float-tree-size",
        _case_pack(store, engine, site, [v1], tmp / "d1", log_fn=_crafted_head(float)),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["pinned", "transparency log"],
            "js": {"bundle_ok": True, "verdict": "ok"},
            "note": "a properly SIGNED head claiming tree_size 5.0 — the "
            "signature verifies on the literal bytes, and Number.isInteger "
            "parity means integral floats verify identically everywhere",
        },
    )

    _write_vector(
        "fail-oversize-tree-size",
        _case_pack(store, engine, site, [v1], tmp / "d1", log_fn=_crafted_head(lambda n: 2**40)),
        {
            "kind": "case",
            "pin": "declared",
            "verdict": "fail",
            "detail_contains": ["malformed tree head"],
            "js": {"bundle_ok": True, "verdict": "fail"},
            "note": "a properly SIGNED head claiming tree_size 2^40 — valid "
            "signature, impossible size: JS bitwise ops die past 2^31, so "
            "every surface rejects it rather than diverging",
        },
    )

    # --- deterministic lineage picks: a second deployment without the
    # revocation noise, rotated A->B cleanly, lets the ordering vectors show
    # that pool position must never decide who is trusted ---
    store3, engine3, site3, cam3, t03, world3 = _deployment(tmp / "d3", KEY_A)
    v3a = _visit(engine3, cam3, t03, world3)

    # A competing CONSENTED successor committed to the log FIRST: K_A really
    # did sign a rotation to the attacker's key, and the attacker really did
    # countersign — an abandoned draft rotation is real history. Its lower
    # sequence loses to the honest pivot on every correct verifier; a
    # first-match-in-pool implementation picks the attacker and fails here.
    latest3 = store3.latest_receipt()
    decoy_rot = KEY_A.issue(
        visit_id=f"key:{KEY_A.public_key_b64[:12]}:{ATTACKER.public_key_b64[:12]}",
        sequence=latest3.sequence + 1,
        prev_hash=latest3.payload_hash,
        facts={
            "record_type": "key_rotation",
            "previous_key": KEY_A.public_key_b64,
            "new_key": ATTACKER.public_key_b64,
            "reason": "abandoned draft rotation — never the lineage",
        },
    )
    store3.put_receipt(decoy_rot)
    decoy_adopt = ATTACKER.issue(
        visit_id=f"key:{KEY_A.public_key_b64[:12]}:{ATTACKER.public_key_b64[:12]}:adopted",
        sequence=decoy_rot.sequence + 1,
        prev_hash=decoy_rot.payload_hash,
        facts={
            "record_type": "key_adoption",
            "previous_key": KEY_A.public_key_b64,
            "rotation_receipt": {"id": decoy_rot.id, "hash": decoy_rot.payload_hash},
        },
    )
    store3.put_receipt(decoy_adopt)

    rotation3 = engine3.issue_key_rotation(KEY_B.public_key_b64, "planned rotation")
    engine3.signer = KEY_B
    engine3.issue_key_adoption(KEY_A.public_key_b64, rotation3)
    # A review appended after the pivot signs under K_B on a K_A original —
    # exactly the case descendant_keys() exists for.
    ReviewService(store3, KEY_B, engine3.clock).coordinator_review(
        v3a.id,
        ReviewInput(decision="confirm", statement="Coordinator note appended after the key rotation"),
    )
    bundle_a = ReviewService(store3, KEY_B, engine3.clock).bundle(v3a.id)

    _write_vector(
        "ok-decoy-successor-order",
        _dispute_pack(store3, engine3, tmp / "d3" / "media", bundle_a),
        {
            "kind": "bundle",
            "pin": "declared",
            "verdict": "ok",
            "detail_contains": ["verified", "pinned", "transparency log"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 2,
                "suspect_count": 0,
                "lifecycle_suspect_count": 0,
                "verdict": "ok",
            },
            "note": "a consented decoy successor listed FIRST in "
            "key_rotations.json — only the highest-sequence consented "
            "pivot (K_A->K_B) may inherit trust; a first-match-in-pool "
            "verifier would pick the attacker and fail this pack",
        },
    )

    # The mirror image for the ANCESTOR walk: a clean A->B deployment (the
    # losing predecessor's receipts must not ride the pack — they'd be
    # foreign to the winning lineage), then an issuer document claiming a
    # SECOND consented predecessor. A < ATK lexicographically, so the pinned
    # predecessor is K_A; the doc lists the attacker's pair first.
    store4, engine4, site4, cam4, t04, world4 = _deployment(tmp / "d4", KEY_A)
    v4a = _visit(engine4, cam4, t04, world4)
    rotation4 = engine4.issue_key_rotation(KEY_B.public_key_b64, "planned rotation")
    engine4.signer = KEY_B
    adoption4 = engine4.issue_key_adoption(KEY_A.public_key_b64, rotation4)
    pred_rot = ATTACKER.issue(
        visit_id=f"key:{ATTACKER.public_key_b64[:12]}:{KEY_B.public_key_b64[:12]}",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "key_rotation",
            "previous_key": ATTACKER.public_key_b64,
            "new_key": KEY_B.public_key_b64,
            "reason": "decoy predecessor — countersigned by K_B, never the lineage",
        },
    )
    pred_adopt = KEY_B.issue(
        visit_id=f"key:{ATTACKER.public_key_b64[:12]}:{KEY_B.public_key_b64[:12]}:adopted",
        sequence=2,
        prev_hash=None,
        facts={
            "record_type": "key_adoption",
            "previous_key": ATTACKER.public_key_b64,
            "rotation_receipt": {"id": pred_rot.id, "hash": pred_rot.payload_hash},
        },
    )
    issuer_doc_minpick = {
        "schema": "attest.issuer/1",
        # A is the lexicographically smaller predecessor — the pinned side.
        "issuer_key": KEY_A.public_key_b64,
        # The decoy pair rides the doc FIRST: a first-match-in-pool verifier
        # resolves K_B's ancestor as the attacker and rejects the pin.
        "key_receipts": [
            pred_rot.model_dump(mode="json"),
            pred_adopt.model_dump(mode="json"),
            rotation4.model_dump(mode="json"),
            adoption4.model_dump(mode="json"),
        ],
    }
    case4_pack = _case_pack(store4, engine4, site4, [v4a], tmp / "d4")
    _write_vector(
        "ok-min-predecessor",
        case4_pack,
        {
            "kind": "case",
            "issuer_doc": "issuer.json",
            "verdict": "ok",
            "detail_contains": ["pinned", "transparency log"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 2,
                "pin_linked": True,
                "suspect_count": 0,
                "lifecycle_suspect_count": 0,
                "verdict": "ok",
            },
            "note": "two consented predecessors claim K_B — the issuer doc "
            "lists the wrong one first, but the min-key pick must still "
            "resolve the pinned predecessor; order can never grant trust",
        },
        extras={"issuer.json": json.dumps(issuer_doc_minpick, indent=2).encode()},
    )

    _write_readme()
    print("done — commit tests/vectors/ and run tests/test_conformance.py")


def _write_readme() -> None:
    (VECTORS / "README.md").write_bytes(
        """# Verifier conformance vectors

Fixed evidence packs that every Attest verifier must judge identically —
the same discipline Wycheproof vectors bring to crypto implementations.
`pack.zip` is real exported evidence; `expected.json` is the shared oracle:

- `kind`: `bundle` (single-visit dispute pack) or `case` (site case pack)
- `pin`: `"declared"` (self-consistency under the pack's own issuer) or an
  explicit base64 Ed25519 public key — pinning the retired key exercises
  the rotation lineage
- `issuer_doc`: an attest.issuer/1 document file in the vector dir — its
  issuer_key pins verification and its key_receipts supply the lineage
  pool on every surface (`--issuer`, `known_rotations`, the browser drop)
- `verdict`: `ok` or `fail` — integrity verdicts are identical everywhere
- `detail_contains`: fragments the human-readable detail must carry
- `detail_excludes`: fragments that must NOT appear — e.g. a grafted
  revocation must leave no "suspect window" annotation behind
- `js`: browser-lib expectations when the check is algorithm-level —
  `bundle_ok`, `trusted_count` (issuer lineage width), `suspect_count`
  (records inside a revoked key's suspect window), `pin_linked` (whether
  the issuer document's key is reachable through the signed lifecycle)

Regenerate with `tools/make_vectors.py` when the pack format changes —
never hand-edit the zips. The vectors are the contract: a verifier that
disagrees with `expected.json` is wrong, whatever surface it runs on.
""".encode()
    )


if __name__ == "__main__":
    main()
