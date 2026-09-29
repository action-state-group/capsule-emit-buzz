# SPDX-License-Identifier: Apache-2.0
"""Signed Nostr events for the tests, made with public test keys (the BIP-340
test vectors' secret keys 3 and 5; never real keys)."""
from __future__ import annotations

import json

from coincurve import PrivateKey

from capsule_emit_buzz.nip01 import compute_event_id

KEY = PrivateKey((3).to_bytes(32, "big"))
OTHER_KEY = PrivateKey((5).to_bytes(32, "big"))
PUBKEY = KEY.public_key_xonly.format().hex()


def signed(content: str = "hello", *, kind: int = 1, created_at: int = 1727280000,
           tags: list[list[str]] | None = None, key: PrivateKey = KEY) -> bytes:
    """A signed NIP-01 event's JSON bytes."""
    tags = tags or []
    pubkey = key.public_key_xonly.format().hex()
    event_id = compute_event_id(pubkey, created_at, kind, tags, content)
    sig = key.sign_schnorr(bytes.fromhex(event_id), aux_randomness=b"\x00" * 32).hex()
    event = {"id": event_id, "pubkey": pubkey, "created_at": created_at, "kind": kind,
             "tags": tags, "content": content, "sig": sig}
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def edited(raw: bytes, **changes: object) -> bytes:
    """The same event JSON with fields changed and nothing re-signed."""
    event = json.loads(raw)
    event.update(changes)
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
