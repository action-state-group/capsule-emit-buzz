# SPDX-License-Identifier: Apache-2.0
"""BuzzConnector structurally conforms to capsule-emit's ConnectorPort, and
capture() carries (received), never seals.

Skipped when capsule-emit is not installed.
"""
from __future__ import annotations

import pytest

pytest.importorskip("capsule_emit.connector", reason="needs capsule-emit>=0.8.4 (ConnectorPort)")

from capsule_emit import read_ledger  # noqa: E402
from capsule_emit.connector import BoundaryClass, ConnectorEvent, ConnectorPort  # noqa: E402

from capsule_emit_buzz.adapter import BuzzConnector  # noqa: E402
from capsule_emit_buzz.event import BuzzEvent  # noqa: E402
from capsule_emit_buzz.nip01 import NostrEventError  # noqa: E402
from nostr_helpers import PUBKEY, edited, signed  # noqa: E402


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
    buzz_event = BuzzEvent(signed("agent-job progress"))
    connector_event = conn.to_connector_event(buzz_event)

    result = conn.capture(connector_event)

    carried = result.capsule["model_attestation"]["compute_attestation"]["carried_artifact"]
    assert carried["type"] == "application/buzz-nostr-event"
    entries = list(read_ledger(ledger))
    assert len(entries) == 1


def test_the_record_names_the_event_it_carries(tmp_path):
    ledger = tmp_path / "l.jsonl"
    conn = BuzzConnector(operator="op", developer="dev/0.0.1", ledger=str(ledger))
    ev = BuzzEvent(signed("agent-job progress"))
    conn.capture(conn.to_connector_event(ev))
    (entry,) = list(read_ledger(ledger))
    link = entry["model_attestation"]["compute_attestation"]["buzz_event"]
    assert link == {"event_id": ev.event_id, "pubkey": PUBKEY, "semantic_digest": ev.semantic_digest()}
    carried = entry["model_attestation"]["compute_attestation"]["carried_artifact"]
    assert carried["digest"] == ev.semantic_digest(), "the carried artifact is the exact event bytes"


def test_capture_refuses_an_unverified_event_and_logs_nothing(tmp_path):
    ledger = tmp_path / "l.jsonl"
    conn = BuzzConnector(operator="op", developer="dev/0.0.1", ledger=str(ledger))
    forged = ConnectorEvent(name="buzz.event.1", foreign=True, foreign_type="application/buzz-nostr-event",
                            foreign_bytes=edited(signed("real"), content="forged"))
    with pytest.raises(NostrEventError):
        conn.capture(forged)
    assert not ledger.exists() or not ledger.read_text().strip()


def test_witness_defaults_to_capsule_emit_and_can_be_turned_off():
    assert BuzzConnector(operator="op", developer="d")._witness is None
    assert BuzzConnector(operator="op", developer="d", witness=False)._witness is False
