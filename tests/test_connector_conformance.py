# SPDX-License-Identifier: Apache-2.0
"""BuzzConnector structurally conforms to capsule-emit's ConnectorPort, and
capture() carries (received), never seals.

Skipped when capsule-emit is not installed.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("capsule_emit.connector", reason="needs capsule-emit>=0.8.4 (ConnectorPort)")

from capsule_emit.connector import BoundaryClass, ConnectorEvent, ConnectorPort  # noqa: E402
from capsule_emit.produce import verify_capsule, verify_envelope  # noqa: E402

from capsule_emit_buzz.event import BuzzEvent  # noqa: E402
from capsule_emit_buzz.nip01 import NostrEventError  # noqa: E402
from nostr_helpers import PUBKEY, edited, signed  # noqa: E402
from stores import committed, connector  # noqa: E402


def test_isinstance_connector_port():
    conn, _, _ = connector()
    assert isinstance(conn, ConnectorPort)


def test_boundary_class_is_listener():
    conn, _, _ = connector()
    assert conn.boundary_class == BoundaryClass.LISTENER.value


def test_capture_refuses_non_foreign_event():
    # A Buzz event is always a foreign, already-signed artifact. capture() must
    # refuse to seal a non-foreign event rather than falsely claiming authorship.
    conn, artifacts, log = connector()
    non_foreign = ConnectorEvent(name="not-a-buzz-event", tool_input={"a": 1})
    with pytest.raises(ValueError):
        conn.capture(non_foreign)
    assert log.scan_entries(0, 10) == []


def test_capture_carries_via_received_not_seal():
    # The real end-to-end proof for the module docstring's claim #1: capture()
    # on a genuine Buzz event takes the received() branch, never seal() — the
    # returned capsule must show a carried_artifact (received()'s signature),
    # not a seal() mint of the event bytes as this adapter's own content.
    conn, artifacts, log = connector()
    buzz_event = BuzzEvent(signed("agent-job progress"))
    connector_event = conn.to_connector_event(buzz_event)

    result = conn.capture(connector_event)

    assert verify_capsule(result.payload).capsule_id == result.capsule_id
    verify_envelope(result.capsule_id, result.envelope)
    capsule = json.loads(result.payload)
    carried = capsule["model_attestation"]["compute_attestation"]["carried_artifact"]
    assert carried["type"] == "application/buzz-nostr-event"
    assert committed(artifacts, log) == [capsule], "put into the artifact store, then committed by the log"
    assert artifacts.get(result.capsule_id).producer_envelope == result.envelope


def test_the_record_names_the_event_it_carries():
    conn, artifacts, log = connector()
    ev = BuzzEvent(signed("agent-job progress"))
    conn.capture(conn.to_connector_event(ev))
    (entry,) = committed(artifacts, log)
    assert entry["action_id"] == f"buzz.event/{ev.event_id}"
    link = entry["buzz_event"]
    assert link == {"event_id": ev.event_id, "pubkey": PUBKEY, "semantic_digest": ev.semantic_digest()}
    carried = entry["model_attestation"]["compute_attestation"]["carried_artifact"]
    assert carried["digest"] == ev.semantic_digest(), "the carried artifact is the exact event bytes"


def test_capture_refuses_an_unverified_event_and_logs_nothing():
    conn, artifacts, log = connector()
    forged = ConnectorEvent(name="buzz.event.1", foreign=True, foreign_type="application/buzz-nostr-event",
                            foreign_bytes=edited(signed("real"), content="forged"))
    with pytest.raises(NostrEventError):
        conn.capture(forged)
    assert log.scan_entries(0, 10) == []


def test_a_failed_put_commits_nothing():
    # The log append is the commit, and it comes after the put: a record the
    # artifact store refused is never committed.
    conn, artifacts, log = connector()

    def refuse(_record):
        raise OSError("artifact store unavailable")

    artifacts.put = refuse
    with pytest.raises(OSError):
        conn.capture(conn.to_connector_event(BuzzEvent(signed("x"))))
    assert log.scan_entries(0, 10) == []
