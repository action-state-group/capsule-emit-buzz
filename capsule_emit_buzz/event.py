# SPDX-License-Identifier: Apache-2.0
"""``BuzzEvent`` — the minimal shape of one observed Buzz/Nostr event, plus the
host-principal derivation.

A Buzz event is a Nostr event: it is already signed by its author's Nostr key
before this adapter ever sees it. This module models only what the adapter
needs to (a) derive a host principal from the event's Nostr pubkey and (b)
compute the two distinct subject fields (``event_id`` and ``semantic_digest``)
in :mod:`capsule_emit_buzz.record`.

Boundary (enforced by construction here, and by the neutrality gate at CI):
  * DIGESTS ONLY. This type deliberately has no field for message text /
    moderated content / job output / release-note prose. The caller passes the
    canonical *bytes* it wants committed; we digest them and never retain them.
  * event_id is the Nostr transport id (a specific transmission). It is NOT a
    content digest and is never reused as one — see record.py.
  * No per-user history, no score or rating field. This type carries one
    event; nothing aggregates across events, and there is no numeric rating
    field anywhere.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

__all__ = ["BuzzEvent", "host_principal_ref", "NOSTR_PUBKEY_PROFILE"]

#: The host-principal profile id this adapter derives a principal_ref under.
#: OWNED by capsule-registry (the `nostr-pubkey` host-principal profile),
#: NOT here — this constant only NAMES it so record.py can stamp the scheme.
NOSTR_PUBKEY_PROFILE = "nostr-pubkey"

#: A Nostr public key's wire form: 64-char lowercase hex (the raw x-only
#: secp256k1/BIP-340 key). A bech32 ``npub`` is a display encoding only and is
#: never the wire value the profile registers.
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class BuzzEvent:
    """One observed Buzz (Nostr) event, reduced to what the adapter needs.

    Attributes:
        event_id: The Nostr event id — a 64-char lowercase-hex transport
            reference identifying this specific transmission. NOT a content
            digest (two different transmissions of identical content have
            different event ids); never reused as ``semantic_digest``.
        pubkey: The author's Nostr public key (64-char lowercase hex). The
            host principal is derived from this via the ``nostr-pubkey``
            profile. Key control is never authority (see the profile) — this
            records who signed, not what they were entitled to do.
        kind: The Nostr event kind, used only to classify the event as an
            observation or an effect. See :meth:`is_effect_kind`.
        content_bytes: The canonical bytes of the content/decision/gate this
            event carries — digested into ``semantic_digest`` by record.py and
            then discarded. NEVER stored on any record (digests only).
        relay_hint: Optional relay URL where events signed by this key are
            commonly found. Strictly informational; never load-bearing for
            identity, verification, or authority. Its absence, staleness, or
            falsity never changes what the record establishes.
    """

    event_id: str
    pubkey: str
    kind: int
    content_bytes: bytes
    relay_hint: str | None = None

    def __post_init__(self) -> None:
        if not _HEX64.match(self.event_id):
            raise ValueError(
                "BuzzEvent.event_id must be a 64-char lowercase-hex Nostr event id"
            )
        if not _HEX64.match(self.pubkey):
            raise ValueError(
                "BuzzEvent.pubkey must be a 64-char lowercase-hex Nostr public key "
                "(the raw x-only key; a bech32 npub is a display encoding, not the wire value)"
            )
        if not isinstance(self.content_bytes, (bytes, bytearray)):
            raise TypeError("BuzzEvent.content_bytes must be bytes")

    def semantic_digest(self) -> str:
        """SHA-256 over the event's canonical content bytes, lowercase hex.

        This is CONTENT identity: it is recomputable from the same bytes and is
        therefore identical for two events with identical content, regardless of
        their (distinct) Nostr event ids. That property is exactly what the
        distinct-id test in the tests/ dir proves. The bytes are digested and
        not retained — no message text ever lands on a record.
        """
        return hashlib.sha256(bytes(self.content_bytes)).hexdigest()

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
