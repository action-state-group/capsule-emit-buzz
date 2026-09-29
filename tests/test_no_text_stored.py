# SPDX-License-Identifier: Apache-2.0
"""No message text is stored: capturing an event writes its content's digest,
never the content itself, to the ledger or to any other file."""
from __future__ import annotations

import hashlib
import json

from capsule_emit_buzz import BuzzConnector, BuzzEvent

TEXT = b"a message whose text must never be stored"


def test_capture_stores_the_digest_never_the_text(tmp_path, monkeypatch):
    monkeypatch.setenv("CAPSULE_WITNESS", "off")
    monkeypatch.setenv("CAPSULE_SIGNING_KEY_PATH", str(tmp_path / "key.pem"))
    ledger = tmp_path / "ledger.jsonl"
    conn = BuzzConnector(operator="op", developer="dev/0.0.1", ledger=str(ledger))
    event = BuzzEvent(event_id="a" * 64, pubkey="b" * 64, kind=1, content_bytes=TEXT)

    conn.capture(conn.to_connector_event(event))

    records = [line for line in ledger.read_text().splitlines() if line.strip()]
    assert len(records) == 1
    assert hashlib.sha256(TEXT).hexdigest() in records[0], "the content is committed by its digest"
    assert TEXT.decode() not in records[0]
    json.loads(records[0])
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert TEXT not in path.read_bytes(), f"{path.name} holds the message text"
