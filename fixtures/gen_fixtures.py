# SPDX-License-Identifier: Apache-2.0
"""Generate the two-language parity fixtures from the Python reference.

Python is the REFERENCE language: this script produces the fixture files, and
the Go parity harness (parity/go/) asserts the same results against them.
Regenerate with:

    python fixtures/gen_fixtures.py

Each positive fixture is a signed Nostr event, exactly as a relay would carry
it (fixtures/events/<name>.json), its metadata (<name>.meta.json: the profile
and an optional relay hint), and the record subject the reference derives
from it (fixtures/records/<name>.json). The events are signed with a public
test key (the BIP-340 test vectors' secret key 3), with zero auxiliary
randomness, so the files are reproducible byte for byte.

The record files carry only the event id, digests and references, never
message text. fixtures/nip01-vectors/ holds real signed events from another
implementation; the Go harness recomputes their ids too.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from coincurve import PrivateKey

from capsule_emit_buzz.event import BuzzEvent
from capsule_emit_buzz.nip01 import compute_event_id
from capsule_emit_buzz.record import record_subject

HERE = Path(__file__).parent
EVENTS = HERE / "events"
RECORDS = HERE / "records"

#: A public test key: the BIP-340 test vectors' secret key 3. Never a real key.
TEST_KEY = PrivateKey((3).to_bytes(32, "big"))
TEST_PUBKEY = TEST_KEY.public_key_xonly.format().hex()


def _canon(obj: object) -> str:
    """Deterministic JSON: sorted keys, compact, trailing newline."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def signed_event(created_at: int, kind: int, tags: list[list[str]], content: str) -> bytes:
    """A signed NIP-01 event's JSON bytes."""
    event_id = compute_event_id(TEST_PUBKEY, created_at, kind, tags, content)
    sig = TEST_KEY.sign_schnorr(bytes.fromhex(event_id), aux_randomness=b"\x00" * 32).hex()
    event = {"id": event_id, "pubkey": TEST_PUBKEY, "created_at": created_at, "kind": kind,
             "tags": tags, "content": content, "sig": sig}
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


POSITIVES = [
    ("agent_job", "buzz.agent-job/v1", "wss://relay.example",
     signed_event(1727280000, 1, [["t", "job"], ["e", "a" * 64, "", "root"]],
                  'status "closed"\nnext\\step\ttab é 😀  end')),
    ("moderation", "buzz.moderation/v1", None,
     signed_event(1727280060, 30_078, [["d", "decision-1"]], '{"disposition":"labeled"}')),
    ("release", "buzz.release/v1", None,
     signed_event(1727280120, 30_079, [], '{"gate":"review-approved","live":true}')),
]


def main() -> None:
    EVENTS.mkdir(exist_ok=True)
    RECORDS.mkdir(exist_ok=True)
    for name, profile, relay_hint, raw in POSITIVES:
        (EVENTS / f"{name}.json").write_bytes(raw)
        meta = {"profile": profile}
        if relay_hint:
            meta["relay_hint"] = relay_hint
        (EVENTS / f"{name}.meta.json").write_text(_canon(meta), encoding="utf-8")
        subject = record_subject(BuzzEvent(raw, relay_hint=relay_hint))
        record = {"profile": profile,
                  "subject": {"event_id": subject.event_id, "semantic_digest": subject.semantic_digest},
                  "principal_ref": subject.principal_ref}
        if subject.principal_ref_relay_hint is not None:
            record["principal_ref_relay_hint"] = subject.principal_ref_relay_hint
        assert record["subject"]["semantic_digest"] == hashlib.sha256(raw).hexdigest()
        (RECORDS / f"{name}.json").write_text(_canon(record), encoding="utf-8")

    # Negatives: records a conforming validator must reject. Stored as
    # descriptions (they cannot be derived records).
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
        (RECORDS / f"{name}.json").write_text(_canon(body), encoding="utf-8")

    print(f"wrote {len(POSITIVES)} positive + {len(negatives)} negative fixtures")


if __name__ == "__main__":
    main()
