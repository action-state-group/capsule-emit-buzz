# SPDX-License-Identifier: Apache-2.0
"""``BuzzEvent`` — one observed Buzz event: a signed Nostr event, verified on
arrival, plus the host-principal derivation.

A Buzz event is a Nostr event, already signed by its author's Nostr key before
this adapter sees it. A ``BuzzEvent`` is made only from the event's exact JSON
bytes as received, and only when those bytes verify (``nip01.verify_event``):
the id is the NIP-01 hash of the event and the BIP-340 signature is the
pubkey's. There is no way to build one from fields, so an unsigned or altered
event never becomes a record.

Boundary (enforced by construction here, and by the neutrality gate at CI):
  * NO TEXT IS KEPT. The event's bytes are held only to verify them and to
    commit to them by digest. No record field carries message text.
  * event_id is the Nostr event id. It is NOT the semantic digest (see
    record.py).
  * No per-user history, no score or rating field. This type carries one
    event; nothing aggregates across events.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .nip01 import NostrEventError, verify_event

__all__ = ["BuzzEvent", "NostrEventError", "host_principal_ref", "NOSTR_PUBKEY_PROFILE"]

#: The host-principal profile id this adapter derives a principal_ref under.
#: OWNED by capsule-registry (the `nostr-pubkey` host-principal profile),
#: NOT here — this constant only NAMES it so record.py can stamp the scheme.
NOSTR_PUBKEY_PROFILE = "nostr-pubkey"



@dataclass(frozen=True)
class BuzzEvent:
    """One observed Buzz (Nostr) event, verified.

    Attributes:
        event_bytes: The event's JSON exactly as received. It must verify as a
            signed NIP-01 event, or construction raises
            :class:`~capsule_emit_buzz.nip01.NostrEventError`.
        relay_hint: Optional relay URL where events signed by this key are
            commonly found. Strictly informational; never load-bearing for
            identity, verification, or authority.

    Derived from the verified event (not settable): ``event_id``, ``pubkey``,
    ``created_at``, ``kind``.
    """

    event_bytes: bytes
    relay_hint: str | None = None
    event_id: str = field(init=False)
    pubkey: str = field(init=False)
    created_at: int = field(init=False)
    kind: int = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.event_bytes, (bytes, bytearray)):
            raise TypeError("BuzzEvent.event_bytes must be the event's JSON bytes")
        event = verify_event(bytes(self.event_bytes))
        object.__setattr__(self, "event_bytes", bytes(self.event_bytes))
        object.__setattr__(self, "event_id", event["id"])
        object.__setattr__(self, "pubkey", event["pubkey"])
        object.__setattr__(self, "created_at", event["created_at"])
        object.__setattr__(self, "kind", event["kind"])

    @classmethod
    def from_nip01(cls, raw: bytes | str, *, relay_hint: str | None = None) -> BuzzEvent:
        """A verified event from its JSON as received."""
        return cls(raw.encode("utf-8") if isinstance(raw, str) else raw, relay_hint=relay_hint)

    def semantic_digest(self) -> str:
        """SHA-256 of the full signed event, exactly as received, lowercase hex.

        It is bound to this one event: the bytes include its id and signature,
        so two events with the same content still have different digests, and
        the digest of a short message can't be confirmed by hashing a guessed
        text. The same event received twice has the same digest.
        """
        return hashlib.sha256(self.event_bytes).hexdigest()

    def is_effect_kind(self) -> bool:
        """Whether this event kind represents an effect (vs an observation).

        Buzz-native mapping used by the adapter's classify():
          * a moderation DECISION and a RELEASE going live are effects — they
            cross a boundary carrying a write (content removed/labeled; a
            change made live).
          * agent-job PROGRESS is an observation — a read on how a job is going.

        Concrete kind numbers are provisional and belong to the Buzz profiles,
        not here; see BUZZ_EFFECT_KINDS below.
        """
        return self.kind in BUZZ_EFFECT_KINDS


# Provisional kind mapping. The authoritative kind numbers are a property of
# the buzz.moderation/v1 and buzz.release/v1 profiles (owned by
# capsule-registry), NOT of this repo. These placeholders exist so classify()
# and its tests run; re-point them when those profiles register kind numbers.
#: Buzz event kinds that map to Classification.EFFECT (moderation decision,
#: release-went-live). Everything else (e.g. agent-job progress) is an
#: OBSERVATION.
BUZZ_EFFECT_KINDS = frozenset({30_078, 30_079})  # provisional


def host_principal_ref(event: BuzzEvent) -> str:
    """Derive the host principal_ref from the event's Nostr pubkey.

    Returns the ``scheme:value`` form Evidence Contract v3 §3.1 uses:
    ``"nostr-pubkey:<64-hex>"``. The relay hint, if present, is carried
    separately (see record.py's ``principal_ref_relay_hint``) and is never
    folded into this string — the scheme's ``scheme:value`` shape stays clean.

    This asserts NOTHING about authority. It records that the signer controlled
    the named key at signing time; whether that holder was entitled to act in
    any community or role is a separate, host-managed binding the profile
    deliberately refuses to infer.
    """
    return f"{NOSTR_PUBKEY_PROFILE}:{event.pubkey}"
