"""OpenTimestamps plumbing: submit → wrap → status → upgrade, with fake
transports so no network is touched."""

import hashlib

import pytest

from attest.timestamp import (
    MAGIC,
    extract_digest,
    ots_status,
    stamp_bytes,
    upgrade,
)

_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
_BITCOIN = bytes.fromhex("0588960d73d71901")


def _pending_body(uri=b"https://a.pool.opentimestamps.org"):
    """A fake calendar /digest response: ops ending in a PendingAttestation —
    tag + varint(payload_len) + varint(uri_len) + uri, matching the wire format."""
    payload = bytes([len(uri)]) + uri
    return b"\x00\x01\xff" + _PENDING + bytes([len(payload)]) + payload


def _confirmed_body():
    return b"\x00\x01" + _BITCOIN + b"\x00\x00\x00\x01"


def test_stamp_wraps_digest_and_reports_pending():
    seen = {}

    def poster(url, body):
        seen["url"], seen["digest"] = url, body
        return _pending_body()

    payload = b"the anchor file bytes"
    ots, cal = stamp_bytes(payload, poster=poster)
    assert seen["url"].endswith("/digest")
    assert seen["digest"] == hashlib.sha256(payload).digest()
    assert cal.startswith("https://")
    assert extract_digest(ots) == hashlib.sha256(payload).digest()
    assert ots_status(ots) == "pending (calendar has not yet committed to Bitcoin)"


def test_stamp_tries_next_calendar_on_failure():
    calls = []

    def poster(url, body):
        calls.append(url)
        if "a.pool" in url:
            raise OSError("unreachable")
        return _pending_body()

    ots, cal = stamp_bytes(b"x", poster=poster)
    assert calls == [
        "https://a.pool.opentimestamps.org/digest",
        "https://b.pool.opentimestamps.org/digest",
    ]
    assert "b.pool" in cal
    assert ots.startswith(MAGIC)


def test_stamp_fails_when_every_calendar_down():
    def poster(url, body):
        raise OSError("down")

    with pytest.raises(RuntimeError, match="no calendar responded"):
        stamp_bytes(b"x", poster=poster)


def test_upgrade_prefers_the_uri_in_the_pending_attestation():
    ots, _ = stamp_bytes(b"x", poster=lambda url, body: _pending_body())
    got = []

    def getter(url):
        got.append(url)
        return _confirmed_body()

    new = upgrade(ots, getter=getter)
    assert got[0].startswith("https://a.pool.opentimestamps.org/timestamp/")
    assert ots_status(new).startswith("confirmed")


def test_upgrade_falls_back_to_all_calendars():
    ots = MAGIC + b"\x08" + b"\x00" * 32 + b"\x01\x02"  # no pending URI to parse
    got = []

    def getter(url):
        got.append(url)
        if "a.pool" not in url:
            return _confirmed_body()
        raise OSError("down")

    new = upgrade(ots, getter=getter)
    assert len(got) == 2
    assert ots_status(new).startswith("confirmed")


def test_extract_digest_rejects_foreign_proofs():
    assert extract_digest(b"not an ots file") is None
    assert extract_digest(MAGIC + b"\x08" + b"short") is None


def test_status_unrecognized():
    assert "unrecognized" in ots_status(MAGIC + b"\x08" + b"\x00" * 40)
