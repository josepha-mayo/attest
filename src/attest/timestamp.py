"""OpenTimestamps anchoring — notarize a digest on public calendar servers so
the record provably existed before a future Bitcoin block.

A signature proves a record is unaltered since signing; it does not prove
*when* it existed. OTS calendars aggregate submitted digests into a Merkle
tree whose root is committed to a Bitcoin transaction. Once confirmed, the
``.ots`` proof attests the digest existed before that block — verifiable by
anyone with the free ``ots`` reference tool, independent of Attest and of any
single timestamping authority.

We deliberately do not reimplement proof verification: the calendar wire
calls are tiny (POST/GET), but proof validation belongs to the reference
client (``pip install opentimestamps-client`` / https://opentimestamps.org).
What we do here is submit, wrap, upgrade, and *detect status* by scanning
for attestation tags:

- ``0588960d73d71901`` — BitcoinBlockHeaderAttestation (confirmed)
- ``83dfe30d2ef90c8e`` — PendingAttestation (calendar URI, awaiting upgrade)
"""

from __future__ import annotations

import hashlib

CALENDARS = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://c.pool.opentimestamps.org",
)

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\x01"
_SHA256_OP = 0x08
_BITCOIN_ATTEST = bytes.fromhex("0588960d73d71901")
_PENDING_ATTEST = bytes.fromhex("83dfe30d2ef90c8e")

# Hosts a crafted .ots may not redirect us to — pending-attestation URIs are
# attacker-controlled bytes, so upgrades only follow https:// on the public
# calendar domains.
_CALENDAR_HOST_SUFFIXES = (
    ".opentimestamps.org",
    ".eternitywall.com",
    ".catallaxy.com",
)


def _trusted_calendar(uri: str) -> bool:
    from urllib.parse import urlsplit

    try:
        host = urlsplit(uri).hostname or ""
    except ValueError:
        return False
    return uri.startswith("https://") and any(
        host == s.lstrip(".") or host.endswith(s) for s in _CALENDAR_HOST_SUFFIXES
    )


def stamp_bytes(payload: bytes, calendars=CALENDARS, poster=None) -> tuple[bytes, str]:
    """Submit sha256(payload) to the calendars; return (ots_bytes, calendar).

    The file is a valid standalone .ots proof for one calendar — the pending
    attestation carries that calendar's URI so `ots upgrade` knows where to
    poll. Raises RuntimeError if every calendar is unreachable.
    """
    digest = hashlib.sha256(payload).digest()
    post = poster or _post
    errors = []
    for cal in calendars:
        try:
            body = post(f"{cal}/digest", digest)
        except Exception as exc:  # noqa: BLE001 — keep trying other calendars
            errors.append(f"{cal}: {exc}")
            continue
        if body:
            return MAGIC + bytes([_SHA256_OP]) + digest + body, cal
    raise RuntimeError("no calendar responded (" + "; ".join(errors) + ")")


class _NotReady(Exception):
    """The calendar is reachable but the proof has not been upgraded yet —
    OTS calendars answer /timestamp/{digest} with 404 while still pending."""


def upgrade(ots: bytes, calendars=CALENDARS, getter=None) -> bytes | None:
    """Ask calendars for an upgraded proof once the Bitcoin commitment has
    confirmed. Returns new bytes when upgraded, None when a live calendar
    says 'not yet', and raises only if every calendar is unreachable.
    Prefers the calendar URI embedded in the pending attestation."""
    digest = extract_digest(ots)
    if digest is None:
        raise RuntimeError("not a single-calendar .ots file — use the ots reference tool")
    get = getter or _get
    tried = list(_pending_calendars(ots))
    reachable = False
    for cal in tried + [c for c in calendars if c not in tried]:
        try:
            body = get(f"{cal}/timestamp/{digest.hex()}")
        except _NotReady:
            reachable = True
            continue
        except Exception:  # noqa: BLE001 — fall through to the next calendar
            continue
        if body:
            return MAGIC + bytes([_SHA256_OP]) + digest + body
        reachable = True
    if reachable:
        return None
    raise RuntimeError("no calendar responded")


def extract_digest(ots: bytes) -> bytes | None:
    """Pull the stamped sha256 digest out of a file we wrote (single calendar)."""
    head = MAGIC + bytes([_SHA256_OP])
    if not ots.startswith(head) or len(ots) < len(head) + 32:
        return None
    return ots[len(head) : len(head) + 32]


def ots_status(ots: bytes) -> str:
    """Classify a proof by scanning for attestation tags — sufficient for
    reporting, never a substitute for `ots verify`. A tag's presence is not
    proof the calendar committed this digest to a real Bitcoin block."""
    if _BITCOIN_ATTEST in ots:
        return "Bitcoin attestation tag present (verify the proof itself with `ots verify`)"
    if _PENDING_ATTEST in ots:
        return "pending (calendar has not yet committed to Bitcoin)"
    return "unrecognized proof — inspect with the ots reference tool"


def _pending_calendars(ots: bytes) -> list[str]:
    """Extract the calendar URIs from pending attestations, best-effort."""
    out = []
    i = 0
    while True:
        i = ots.find(_PENDING_ATTEST, i)
        if i < 0:
            return out
        j = i + len(_PENDING_ATTEST)
        try:
            _, k = _varint(ots, j)  # skip the attestation payload length
            n, k = _varint(ots, k)  # the URI is a varstr inside the payload
            uri = ots[k : k + n].decode()
            if _trusted_calendar(uri):
                out.append(uri)
        except Exception:  # noqa: BLE001 — best-effort parse only
            pass
        i = j


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    if buf[i] < 0xFD:
        return buf[i], i + 1
    if buf[i] == 0xFD:
        return int.from_bytes(buf[i + 1 : i + 3], "little"), i + 3
    if buf[i] == 0xFE:
        return int.from_bytes(buf[i + 1 : i + 5], "little"), i + 5
    return int.from_bytes(buf[i + 1 : i + 9], "little"), i + 9


def _post(url: str, body: bytes) -> bytes:
    import httpx

    r = httpx.post(url, content=body, timeout=15)
    return r.content if r.status_code == 200 else b""


def _get(url: str) -> bytes:
    import httpx

    r = httpx.get(url, timeout=15)
    if r.status_code == 200:
        return r.content
    if r.status_code == 404:
        raise _NotReady
    raise OSError(f"HTTP {r.status_code}")
