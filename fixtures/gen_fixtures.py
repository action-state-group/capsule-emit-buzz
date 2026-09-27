# SPDX-License-Identifier: Apache-2.0
"""Generate the two-language parity fixtures from the Python reference.

Python is the REFERENCE language: this script produces the canonical fixture
files, and the Go parity harness (parity/go/) asserts byte-for-byte-equal
results against these same files. Regenerate with:

    python fixtures/gen_fixtures.py

Each fixture pairs an input Buzz event (fixtures/events/<name>.json) with the
expected record subject the reference derives (fixtures/records/<name>.json).
The record files carry ONLY digests and references — never message text.

The three positive fixtures exercise the three Buzz profiles by name
(buzz.agent-job/v1, buzz.moderation/v1, buzz.release/v1 — owned by
capsule-registry, referenced not redefined here). The two negative fixtures
capture the invariants a validator must reject.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict

from capsule_emit_buzz.event import BuzzEvent
from capsule_emit_buzz.record import record_subject

HERE = Path(__file__).parent
EVENTS = HERE / "events"
RECORDS = HERE / "records"


def _canon(obj: object) -> str:
    """Deterministic JSON: sorted keys, compact, trailing newline."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n"


# (name, profile, event) — content bytes are ASCII JSON for fixture legibility;
# the digest is over these exact bytes.
POSITIVES = [
    (
        "agent_job",
        "buzz.agent-job/v1",
        BuzzEvent(
            event_id="a1" + "0" * 62,
            pubkey="11" + "f" * 62,
            kind=1,
            content_bytes=b'{"job":"summarize","status":"closed"}',
            relay_hint="wss://relay.example",
        ),
    ),
    (
        "moderation",
        "buzz.moderation/v1",
        BuzzEvent(
            event_id="b2" + "0" * 62,
            pubkey="22" + "e" * 62,
            kind=30_078,  # provisional effect kind
            content_bytes=b'{"disposition":"labeled"}',
        ),
    ),
    (
        "release",
        "buzz.release/v1",
        BuzzEvent(
            event_id="c3" + "0" * 62,
            pubkey="33" + "d" * 62,
            kind=30_079,  # provisional effect kind
            content_bytes=b'{"gate":"review-approved","live":true}',
        ),
    ),
]


class _EventFixtureRequired(TypedDict):
    profile: str
    event_id: str
    pubkey: str
    kind: int
    content_hex: str


class EventFixture(_EventFixtureRequired, total=False):
    relay_hint: str


class SubjectFixture(TypedDict):
    event_id: str
    semantic_digest: str


class _RecordFixtureRequired(TypedDict):
    profile: str
    subject: SubjectFixture
    principal_ref: str


class RecordFixture(_RecordFixtureRequired, total=False):
    principal_ref_relay_hint: str


def _event_json(profile: str, ev: BuzzEvent) -> EventFixture:
    d: EventFixture = {
        "profile": profile,
        "event_id": ev.event_id,
        "pubkey": ev.pubkey,
        "kind": ev.kind,
        # content is given as its exact bytes' hex so a second language digests
        # identical input; the fixture never carries decoded message text as a
        # field the record would keep.
        "content_hex": ev.content_bytes.hex(),
    }
    if ev.relay_hint is not None:
        d["relay_hint"] = ev.relay_hint
    return d


def _record_json(profile: str, ev: BuzzEvent) -> RecordFixture:
    s = record_subject(ev)
    d: RecordFixture = {
        "profile": profile,
        "subject": {
            "event_id": s.event_id,
            "semantic_digest": s.semantic_digest,
        },
        "principal_ref": s.principal_ref,
    }
    if s.principal_ref_relay_hint is not None:
        d["principal_ref_relay_hint"] = s.principal_ref_relay_hint
    return d


def main() -> None:
    EVENTS.mkdir(parents=True, exist_ok=True)
    RECORDS.mkdir(parents=True, exist_ok=True)

    for name, profile, ev in POSITIVES:
        (EVENTS / f"{name}.json").write_text(_canon(_event_json(profile, ev)))
        (RECORDS / f"{name}.json").write_text(_canon(_record_json(profile, ev)))

    # Negatives: inputs a conforming validator must reject. Stored as
    # descriptions (not derived records — they cannot be derived) so the Go
    # harness asserts the same rejection reasons.
    negatives = {
        "neg_event_id_as_digest": {
            "reason": "event_id reused as semantic_digest (two fields collapsed into one)",
        },
        "neg_message_text_present": {
            "reason": "a record field carried message text; records are digests only",
        },
        "neg_score_present": {
            "reason": "a record field carried a score value; no scores anywhere",
        },
    }
    for name, body in negatives.items():
        (RECORDS / f"{name}.json").write_text(_canon(body))

    print(f"wrote {len(POSITIVES)} positive + {len(negatives)} negative fixtures")


if __name__ == "__main__":
    main()
