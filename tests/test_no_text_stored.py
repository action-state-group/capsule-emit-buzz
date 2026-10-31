# SPDX-License-Identifier: Apache-2.0
"""No message text is stored: capturing an event writes the digest of the full
signed event, never the text or a bare hash of it, to the artifact store, the
log or any other file."""
from __future__ import annotations

import hashlib
import json

import pytest

pytest.importorskip("capsule_emit.connector", reason="needs capsule-emit>=0.8.4 (ConnectorPort)")

from capsule_emit_buzz import BuzzEvent  # noqa: E402
from nostr_helpers import signed  # noqa: E402
from stores import connector  # noqa: E402

TEXT = b"a message whose text must never be stored"


def test_capture_stores_the_digest_never_the_text(tmp_path):
    conn, artifacts, log = connector(tmp_path)
    event = BuzzEvent(signed(TEXT.decode()))

    result = conn.capture(conn.to_connector_event(event))
    log.close()

    stored = artifacts.get(result.capsule_id)
    assert stored.artifacts == [], "no original is retained beside the record"
    record = stored.capsule.decode("utf-8")
    assert hashlib.sha256(event.event_bytes).hexdigest() in record, "the event is committed by its digest"
    assert hashlib.sha256(TEXT).hexdigest() not in record, "no bare hash of the text"
    assert TEXT.decode() not in record
    json.loads(record)
    assert TEXT not in stored.producer_envelope
    # The artifact file encodes the record, so it is checked decoded above;
    # every file is also checked as written.
    assert len([line for line in (tmp_path / "artifacts.jsonl").read_text().splitlines() if line.strip()]) == 1
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert TEXT not in path.read_bytes(), f"{path.name} holds the message text"
