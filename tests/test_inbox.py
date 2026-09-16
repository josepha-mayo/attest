from concurrent.futures import ThreadPoolExecutor

from attest.inbox import WebhookInbox


def test_pending_delivery_survives_restart(tmp_path):
    path = tmp_path / "inbox.sqlite3"
    inbox = WebhookInbox(path)
    assert inbox.enqueue("account:request", b"payload", "signature")
    assert not inbox.enqueue("account:request", b"payload", "signature")
    inbox.close()
    recovered = WebhookInbox(path)
    job = recovered.claim(now=100)
    assert job["raw_body"] == b"payload" and job["signature"] == "signature"
    recovered.complete(job, "done")
    assert recovered.claim(now=101) is None
    recovered.close()


def test_only_one_worker_claims_delivery(tmp_path):
    inbox = WebhookInbox(tmp_path / "inbox.sqlite3")
    inbox.enqueue("request", b"payload", "signature")
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = list(pool.map(lambda _: inbox.claim(now=100), range(4)))
    assert sum(job is not None for job in jobs) == 1
    inbox.close()


def test_expired_lease_recovers_and_stale_worker_cannot_ack(tmp_path):
    inbox = WebhookInbox(tmp_path / "inbox.sqlite3")
    inbox.enqueue("request", b"payload", "signature")
    first = inbox.claim(now=100)
    assert inbox.claim(now=101) is None
    second = inbox.claim(now=1000)
    assert second["lease"] != first["lease"]
    inbox.complete(first, "done")
    assert inbox.counts()["processing"] == 1
    inbox.complete(second, "done")
    assert inbox.counts()["done"] == 1
    inbox.close()


def test_retry_is_delayed_and_eventually_dead_lettered(tmp_path):
    inbox = WebhookInbox(tmp_path / "inbox.sqlite3")
    inbox.enqueue("request", b"payload", "signature")
    for attempt in range(5):
        now = 100 + attempt * 1000
        job = inbox.claim(now=now)
        inbox.fail(job, "RuntimeError", now=now)
        assert inbox.claim(now=now + 0.1) is None
    assert inbox.counts()["failed"] == 1
    assert inbox.claim(now=99999) is None
    inbox.close()


def test_requeue_revives_failed_with_fresh_attempts(tmp_path):
    inbox = WebhookInbox(tmp_path / "inbox.sqlite3")
    inbox.enqueue("req-a-fail", b"payload", "signature")
    inbox.enqueue("req-b-done", b"payload", "signature")
    # claim order is (received_at, id): req-a-fail is claimed first and dead-letters
    for attempt in range(5):
        now = 1000 + attempt * 1000
        inbox.fail(inbox.claim(now=now), "RuntimeError", now=now)
    done = inbox.claim(now=99998)
    inbox.complete(done, "done")
    assert inbox.counts() == {"failed": 1, "done": 1}

    assert inbox.requeue(["nonexistent"]) == 0
    assert inbox.requeue(["req-b-done"]) == 0  # done is terminal, never requeued
    assert inbox.requeue(["req-a-fail"]) == 1
    assert inbox.counts() == {"pending": 1, "done": 1}
    job = inbox.claim(now=99999)  # claimable again with attempts reset
    assert job["id"] == "req-a-fail" and job["attempts"] == 1
    inbox.fail(job, "RuntimeError", now=99999)
    assert inbox.counts()["pending"] == 1  # fresh budget: not instantly failed again
    inbox.close()
