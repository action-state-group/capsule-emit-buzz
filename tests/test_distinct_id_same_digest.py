# SPDX-License-Identifier: Apache-2.0
"""event_id and semantic_digest are two distinct fields, and the digest is
bound to one event: the SHA-256 of the full signed event as received.

Runs without capsule-emit installed."""
from __future__ import annotations

import hashlib

import pytest

from capsule_emit_buzz.event import BuzzEvent
from capsule_emit_buzz.record import EvidenceRecordSubject, record_subject
from nostr_helpers import PUBKEY, signed

CONTENT = '{"decision":"labeled","policy":"x"}'


def test_two_events_with_the_same_content_have_different_ids_and_digests():
    a = record_subject(BuzzEvent(signed(CONTENT, created_at=1)))
    b = record_subject(BuzzEvent(signed(CONTENT, created_at=2)))
    assert a.event_id != b.event_id
    assert a.semantic_digest != b.semantic_digest, "the digest is bound to the event, not the text"
    assert a.event_id != a.semantic_digest and b.event_id != b.semantic_digest


def test_the_same_event_received_twice_has_the_same_digest():
    raw = signed(CONTENT)
    assert record_subject(BuzzEvent(raw)).semantic_digest == record_subject(BuzzEvent(raw)).semantic_digest


def test_the_digest_is_the_hash_of_the_full_event_never_of_the_text():
    raw = signed("yes")
    digest = record_subject(BuzzEvent(raw)).semantic_digest
    assert digest == hashlib.sha256(raw).hexdigest()
    assert digest != hashlib.sha256(b"yes").hexdigest(), "a short text is not confirmable from the record"


def test_subject_refuses_event_id_reused_as_digest():
    val = "4" * 64
    with pytest.raises(ValueError):
        EvidenceRecordSubject(event_id=val, semantic_digest=val, principal_ref="nostr-pubkey:" + PUBKEY)
