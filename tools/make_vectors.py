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
from attest.disputepack import build_case_pack, build_pack  # noqa: E402
from attest.engine import VisitEngine  # noqa: E402
from attest.ledger import Signer, issuer_document  # noqa: E402
from attest.media import MediaStore  # noqa: E402
from attest.models import Role, Schedule, Site, Worker  # noqa: E402
from attest.reviews import ReviewService, countersign_status  # noqa: E402
from attest.store import Store  # noqa: E402
from attest.summarize import TemplateSummarizer  # noqa: E402

VECTORS = ROOT / "tests" / "vectors"

# Fixed seed material — the corpus's issuer identities are stable so a regen
# diffs only in timestamps/ids, never in which keys the vectors name.
KEY_A = Signer(Ed25519PrivateKey.from_private_bytes(b"\x11" * 32))
KEY_B = Signer(Ed25519PrivateKey.from_private_bytes(b"\x22" * 32))
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


def _case_pack(store, engine, site, visits, tmp: Path, *, redact=False) -> bytes:
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
            "detail_contains": ["verified", "media", "pinned"],
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
            "detail_contains": ["withheld", "pinned"],
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
            "detail_contains": ["issuer keys linked via the signed rotation chain", "pinned"],
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
            "detail_contains": ["verified", "pinned"],
            "detail_excludes": ["suspect window"],
            "js": {
                "bundle_ok": True,
                "trusted_count": 2,
                "suspect_count": 0,
                "lifecycle_suspect_count": 0,
                "verdict": "ok",
            },
            "note": "a self-signed key_revocation grafted at sequence 0 cannot "
            "make itself the revocation root — the smear is inert",
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
            "detail_contains": ["suspect window", "trust pivot", "pinned"],
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
            "detail_contains": ["suspect window", "pinned"],
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
            "detail_contains": ["suspect window", "pinned"],
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
            "detail_contains": ["issuer keys linked", "pinned"],
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
            "detail_contains": ["verified", "media"],
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
