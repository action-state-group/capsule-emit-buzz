# SPDX-License-Identifier: Apache-2.0
"""Round-trip: record -> Buzz-event shape and back, byte-identical on the
fields the event owns.

The event owns event_id, pubkey (inside principal_ref), and the optional
relay_hint. content_bytes is intentionally NOT recoverable — the record stores
only the semantic_digest; the bytes were never retained (digests only). So the
round-trip must be byte-identical on the owned fields and silent on content.

Runs without capsule-emit installed.
"""
from __future__ import annotations

from capsule_emit_buzz.event import BuzzEvent
from capsule_emit_buzz.record import record_subject, record_to_event

PUBKEY = "b" * 64
EVENT_ID = "5" * 64


def test_round_trip_owned_fields_byte_identical():
    original = BuzzEvent(
        event_id=EVENT_ID,
        pubkey=PUBKEY,
        kind=1,
        content_bytes=b"payload",
        relay_hint="wss://relay.example",
    )
    subject = record_subject(original)
    shape = record_to_event(subject)

    assert shape["event_id"] == original.event_id
    assert shape["pubkey"] == original.pubkey
    assert shape["relay_hint"] == original.relay_hint


def test_round_trip_omits_relay_hint_when_absent():
    original = BuzzEvent(event_id=EVENT_ID, pubkey=PUBKEY, kind=1, content_bytes=b"payload")
    shape = record_to_event(record_subject(original))
    assert "relay_hint" not in shape


def test_round_trip_does_not_carry_content():
    original = BuzzEvent(event_id=EVENT_ID, pubkey=PUBKEY, kind=1, content_bytes=b"secret content")
    shape = record_to_event(record_subject(original))
    # No field on the round-tripped shape carries the content bytes (digests only).
    assert all(b"secret content" not in repr(v).encode() for v in shape.values())
