# SPDX-License-Identifier: Apache-2.0
"""BuzzConnector structurally conforms to capsule-emit's ConnectorPort, and
capture() carries (received), never seals.

Skipped when capsule-emit is not installed.
"""
from __future__ import annotations

import pytest

pytest.importorskip(
    "capsule_emit.connector",
    reason="capsule-emit>=0.8.4 (ConnectorPort) not installed in this env",
)

from capsule_emit import read_ledger  # noqa: E402
from capsule_emit.connector import BoundaryClass, ConnectorEvent, ConnectorPort  # noqa: E402

from capsule_emit_buzz.adapter import BuzzConnector  # noqa: E402
from capsule_emit_buzz.event import BuzzEvent  # noqa: E402


def test_isinstance_connector_port():
    conn = BuzzConnector(operator="op", developer="dev/0.0.1")
    assert isinstance(conn, ConnectorPort)


def test_boundary_class_is_listener():
    conn = BuzzConnector(operator="op", developer="dev/0.0.1")
    assert conn.boundary_class == BoundaryClass.LISTENER.value


def test_capture_refuses_non_foreign_event():
    # A Buzz event is always a foreign, already-signed artifact. capture() must
    # refuse to seal a non-foreign event rather than falsely claiming authorship.
    conn = BuzzConnector(operator="op", developer="dev/0.0.1")
    non_foreign = ConnectorEvent(name="not-a-buzz-event", tool_input={"a": 1})
    with pytest.raises(ValueError):
        conn.capture(non_foreign)


def test_capture_carries_via_received_not_seal(tmp_path):
    # The real end-to-end proof for the module docstring's claim #1: capture()
    # on a genuine Buzz event takes the received() branch, never seal() — the
    # returned capsule must show a carried_artifact (received()'s signature),
    # not a seal() mint of the event bytes as this adapter's own content.
    ledger = tmp_path / "l.jsonl"
    conn = BuzzConnector(operator="op", developer="dev/0.0.1", ledger=str(ledger))
    buzz_event = BuzzEvent(event_id="6" * 64, pubkey="c" * 64, kind=1, content_bytes=b"agent-job progress")
    connector_event = conn.to_connector_event(buzz_event)

    result = conn.capture(connector_event)

    carried = result.capsule["model_attestation"]["compute_attestation"]["carried_artifact"]
    assert carried["type"] == "application/buzz-nostr-event"
    entries = list(read_ledger(ledger))
    assert len(entries) == 1
