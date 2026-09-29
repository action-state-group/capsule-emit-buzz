# SPDX-License-Identifier: Apache-2.0
"""No message text is stored: capturing an event writes the digest of the full
signed event, never the text or a bare hash of it, to the ledger or any other
file."""
from __future__ import annotations

import hashlib
import json

import pytest

pytest.importorskip("capsule_emit.connector", reason="needs capsule-emit>=0.8.4 (ConnectorPort)")

from capsule_emit_buzz import BuzzConnector, BuzzEvent  # noqa: E402
from nostr_helpers import signed  # noqa: E402

TEXT = b"a message whose text must never be stored"


def test_capture_stores_the_digest_never_the_text(tmp_path, monkeypatch):
    monkeypatch.setenv("CAPSULE_WITNESS", "off")
    monkeypatch.setenv("CAPSULE_SIGNING_KEY_PATH", str(tmp_path / "key.pem"))
    ledger = tmp_path / "ledger.jsonl"
    conn = BuzzConnector(operator="op", developer="dev/0.0.1", ledger=str(ledger))
    event = BuzzEvent(signed(TEXT.decode()))

    conn.capture(conn.to_connector_event(event))

    records = [line for line in ledger.read_text().splitlines() if line.strip()]
    assert len(records) == 1
    assert hashlib.sha256(event.event_bytes).hexdigest() in records[0], "the event is committed by its digest"
    assert hashlib.sha256(TEXT).hexdigest() not in records[0], "no bare hash of the text"
    assert TEXT.decode() not in records[0]
    json.loads(records[0])
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert TEXT not in path.read_bytes(), f"{path.name} holds the message text"
