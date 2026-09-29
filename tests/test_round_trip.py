# SPDX-License-Identifier: Apache-2.0
"""Round-trip: record -> Buzz-event shape, byte-identical on the fields the
event owns (event_id, pubkey, the optional relay_hint), and silent on content.

Runs without capsule-emit installed."""
from __future__ import annotations

from capsule_emit_buzz.event import BuzzEvent
from capsule_emit_buzz.record import record_subject, record_to_event
from nostr_helpers import PUBKEY, signed


def test_round_trip_owned_fields_byte_identical():
    original = BuzzEvent(signed("payload"), relay_hint="wss://relay.example")
    shape = record_to_event(record_subject(original))
    assert shape["event_id"] == original.event_id
    assert shape["pubkey"] == original.pubkey == PUBKEY
    assert shape["relay_hint"] == original.relay_hint


def test_round_trip_omits_relay_hint_when_absent():
    shape = record_to_event(record_subject(BuzzEvent(signed("payload"))))
    assert "relay_hint" not in shape


def test_round_trip_does_not_carry_content():
    shape = record_to_event(record_subject(BuzzEvent(signed("secret content"))))
    assert all("secret content" not in repr(v) for v in shape.values())
