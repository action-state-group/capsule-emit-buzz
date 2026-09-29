# SPDX-License-Identifier: Apache-2.0
"""Verify a signed Nostr event (NIP-01) before anything else touches it.

A Buzz event is a Nostr event: ``{id, pubkey, created_at, kind, tags,
content, sig}``, signed by its author. This module checks one, exactly as
NIP-01 defines it:

- ``id`` must be the SHA-256 of the event's serialization
  ``[0, pubkey, created_at, kind, tags, content]``. That serialization is JSON
  with no whitespace, UTF-8, and the NIP-01 escaping rules: inside strings,
  line feed, double quote, backslash, carriage return, tab, backspace and form
  feed are escaped; every other character is written as is.
- ``sig`` must be a BIP-340 Schnorr signature by ``pubkey`` over ``id``. It is
  verified with coincurve (libsecp256k1; MIT OR Apache-2.0).

Any failure raises :class:`NostrEventError` with a reason code. The error never
carries the event's content.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from coincurve import PublicKeyXOnly

__all__ = [
    "NostrEventError",
    "compute_event_id",
    "serialize_for_id",
    "verify_event",
]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")

_ESCAPES = {
    "\n": "\\n",
    '"': '\\"',
    "\\": "\\\\",
    "\r": "\\r",
    "\t": "\\t",
    "\b": "\\b",
    "\f": "\\f",
}


class NostrEventError(ValueError):
    """A Nostr event that is malformed, unsigned, or fails its id or signature
    check. ``reason`` is one of ``malformed``, ``unsigned``, ``id_mismatch``,
    ``bad_signature``. The message never includes the event's content."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


def _string(value: str) -> str:
    return '"' + "".join(_ESCAPES.get(c, c) for c in value) + '"'


def _serialize(value: Any) -> str:
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, bool):
        raise TypeError("a boolean has no place in the NIP-01 serialization")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    raise TypeError(f"unexpected {type(value).__name__} in the NIP-01 serialization")


def serialize_for_id(pubkey: str, created_at: int, kind: int, tags: list[list[str]], content: str) -> bytes:
    """The UTF-8 bytes NIP-01 hashes into an event's id."""
    return _serialize([0, pubkey, created_at, kind, tags, content]).encode("utf-8")


def compute_event_id(pubkey: str, created_at: int, kind: int, tags: list[list[str]], content: str) -> str:
    return hashlib.sha256(serialize_for_id(pubkey, created_at, kind, tags, content)).hexdigest()


def _field(event: dict[str, Any], name: str, kind: type) -> Any:
    value = event.get(name)
    if isinstance(value, bool) or not isinstance(value, kind):
        raise NostrEventError("malformed", f"{name} is missing or not a {kind.__name__}")
    return value


def verify_event(raw: bytes | str) -> dict[str, Any]:
    """Parse *raw* (the event's JSON, as received) and verify it. Returns the
    parsed event; raises :class:`NostrEventError` on any failure."""
    try:
        event = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise NostrEventError("malformed", "the event is not JSON") from None
    if not isinstance(event, dict):
        raise NostrEventError("malformed", "the event is not a JSON object")
    if not event.get("sig"):
        raise NostrEventError("unsigned", "the event has no signature")
    event_id = _field(event, "id", str)
    pubkey = _field(event, "pubkey", str)
    sig = _field(event, "sig", str)
    created_at = _field(event, "created_at", int)
    kind = _field(event, "kind", int)
    tags = _field(event, "tags", list)
    content = _field(event, "content", str)
    if not _HEX64.match(event_id) or not _HEX64.match(pubkey):
        raise NostrEventError("malformed", "id and pubkey are 64 lowercase hex")
    if not _HEX128.match(sig):
        raise NostrEventError("malformed", "sig is 128 lowercase hex")
    if created_at < 0 or not 0 <= kind <= 65535:
        raise NostrEventError("malformed", "created_at or kind is out of range")
    if not all(isinstance(t, list) and all(isinstance(x, str) for x in t) for t in tags):
        raise NostrEventError("malformed", "tags is a list of lists of strings")
    if compute_event_id(pubkey, created_at, kind, tags, content) != event_id:
        raise NostrEventError("id_mismatch", "the id is not the hash of the event")
    try:
        ok = PublicKeyXOnly(bytes.fromhex(pubkey)).verify(bytes.fromhex(sig), bytes.fromhex(event_id))
    except ValueError:
        ok = False
    if not ok:
        raise NostrEventError("bad_signature", "the signature does not verify under pubkey")
    return event
