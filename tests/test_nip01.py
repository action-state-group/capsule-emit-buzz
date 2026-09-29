# SPDX-License-Identifier: Apache-2.0
"""NIP-01 verification: real signed events pass; altered or unsigned ones fail
with a reason, and the error never carries the content."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from capsule_emit_buzz.event import BuzzEvent
from capsule_emit_buzz.nip01 import NostrEventError, serialize_for_id, verify_event
from nostr_helpers import OTHER_KEY, edited, signed

VECTORS = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "nip01-vectors" / "rust-nostr.json").read_text(encoding="utf-8")
)["events"]


@pytest.mark.parametrize("event", VECTORS, ids=[e["id"][:12] for e in VECTORS])
def test_real_signed_events_from_another_implementation_verify(event):
    raw = json.dumps(event, ensure_ascii=False).encode("utf-8")
    assert verify_event(raw)["id"] == event["id"]
    assert BuzzEvent(raw).event_id == event["id"]


def test_the_serialization_escapes_exactly_as_nip01_says():
    assert serialize_for_id("p", 1, 1, [["t", 'a"b']], 'x\n"\\\r\t\b\fé <&>') == (
        '[0,"p",1,1,[["t","a\\"b"]],"x\\n\\"\\\\\\r\\t\\b\\fé <&>"]'.encode("utf-8")
    )


SECRET = "the quiet message 4c1d"


@pytest.mark.parametrize("change, reason", [
    ({"content": SECRET + "!"}, "id_mismatch"),
    ({"id": "0" * 64}, "id_mismatch"),
    ({"sig": "0" * 128}, "bad_signature"),
    ({"sig": ""}, "unsigned"),
    ({"created_at": "soon"}, "malformed"),
])
def test_an_altered_event_is_refused_with_a_reason_that_never_echoes_content(change, reason):
    raw = edited(signed(SECRET), **change)
    with pytest.raises(NostrEventError) as info:
        BuzzEvent(raw)
    assert info.value.reason == reason
    assert SECRET not in str(info.value)


def test_a_signature_by_another_key_is_refused():
    genuine = json.loads(signed(SECRET))
    other = json.loads(signed(SECRET, key=OTHER_KEY))
    with pytest.raises(NostrEventError) as info:
        verify_event(edited(signed(SECRET), sig=other["sig"]))
    assert info.value.reason == "bad_signature"
    assert other["pubkey"] != genuine["pubkey"]


def test_an_event_with_no_signature_field_is_refused():
    event = json.loads(signed(SECRET))
    del event["sig"]
    with pytest.raises(NostrEventError) as info:
        BuzzEvent(json.dumps(event).encode())
    assert info.value.reason == "unsigned"


@pytest.mark.parametrize("raw", [b"not json", b"[]", b'{"sig":"x"}'])
def test_malformed_input_is_refused_never_raises_otherwise(raw):
    with pytest.raises(NostrEventError):
        BuzzEvent(raw)
