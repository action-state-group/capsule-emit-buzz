# SPDX-License-Identifier: Apache-2.0
"""THE test: event_id and semantic_digest are two distinct fields.

Two Buzz events with IDENTICAL content and DIFFERENT ids must produce DIFFERENT
records (their event_ids differ) that carry the SAME semantic_digest (content is
identical). This is the whole point of keeping the two fields separate; a mutant
that reused event_id as the semantic digest, or that derived event_id from
content, must turn this red.

This test depends only on capsule_emit_buzz's own event/record modules, so it
runs without capsule-emit installed.
"""
from __future__ import annotations

from capsule_emit_buzz.event import BuzzEvent
from capsule_emit_buzz.record import record_subject

PUBKEY = "a" * 64
# Two DISTINCT Nostr event ids (transport references)...
EVENT_ID_1 = "1" * 64
EVENT_ID_2 = "2" * 64
# ...over IDENTICAL content bytes.
CONTENT = b'{"decision":"labeled","policy":"x"}'


def _event(event_id: str) -> BuzzEvent:
    return BuzzEvent(event_id=event_id, pubkey=PUBKEY, kind=1, content_bytes=CONTENT)


def test_identical_content_different_ids_same_semantic_digest_distinct_records():
    a = record_subject(_event(EVENT_ID_1))
    b = record_subject(_event(EVENT_ID_2))

    # Distinct records: the event ids differ.
    assert a.event_id != b.event_id
    assert a.event_id == EVENT_ID_1
    assert b.event_id == EVENT_ID_2

    # Same semantic digest: the content is identical.
    assert a.semantic_digest == b.semantic_digest

    # And the two fields are never the same value on either record.
    assert a.event_id != a.semantic_digest
    assert b.event_id != b.semantic_digest


def test_different_content_changes_semantic_digest_only():
    same_id = "3" * 64
    e1 = BuzzEvent(event_id=same_id, pubkey=PUBKEY, kind=1, content_bytes=b"one")
    e2 = BuzzEvent(event_id=same_id, pubkey=PUBKEY, kind=1, content_bytes=b"two")
    s1 = record_subject(e1)
    s2 = record_subject(e2)

    assert s1.event_id == s2.event_id          # same transport id
    assert s1.semantic_digest != s2.semantic_digest  # different content


def test_subject_refuses_event_id_reused_as_digest():
    import pytest

    from capsule_emit_buzz.record import EvidenceRecordSubject

    val = "4" * 64
    with pytest.raises(ValueError):
        EvidenceRecordSubject(
            event_id=val,
            semantic_digest=val,  # the foot-gun the invariant forbids
            principal_ref="nostr-pubkey:" + PUBKEY,
        )
