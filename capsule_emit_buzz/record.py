# SPDX-License-Identifier: Apache-2.0
"""The EvidenceRecord subject and the record <-> Buzz-event round-trip.

The one invariant this module exists to make un-collapsible:

    subject = {event_id, semantic_digest}

``event_id`` and ``semantic_digest`` are TWO SEPARATE FIELDS. ``event_id`` is
the Nostr transport reference (a specific transmission, not recomputable from
bytes). ``semantic_digest`` is the content digest (recomputable, identical for
identical content). A conforming producer MUST NOT emit a record where one
field stands in for the other; a conforming validator MUST reject one that
does. This mirrors the ``buzz.*`` profiles' two-field distinctness rule
(owned by capsule-registry, referenced not redefined here).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict

from .event import BuzzEvent, host_principal_ref

__all__ = ["BuzzEventShape", "EvidenceRecordSubject", "record_subject", "record_to_event"]


class _BuzzEventShapeRequired(TypedDict):
    event_id: str
    pubkey: str


class BuzzEventShape(_BuzzEventShapeRequired, total=False):
    """The fields a Buzz event owns, as :func:`record_to_event` returns them."""

    relay_hint: str


@dataclass(frozen=True)
class EvidenceRecordSubject:
    """The subject portion of an EvidenceRecord for one Buzz event.

    Two distinct fields, never conflated:

    Attributes:
        event_id: Nostr transport reference (64-hex). Owned by the event.
        semantic_digest: SHA-256 content digest (64-hex). Owned by the event.
        principal_ref: ``nostr-pubkey:<hex>`` derived from the event pubkey.
        principal_ref_relay_hint: Optional, informational relay URL. Never
            load-bearing; carried separately from ``principal_ref``.

    There is deliberately no content field, no per-user history field, and no
    score/rating field.
    """

    event_id: str
    semantic_digest: str
    principal_ref: str
    principal_ref_relay_hint: str | None = None

    def __post_init__(self) -> None:
        # Belt-and-braces: the whole point of the two fields is that they differ
        # in kind. They MAY coincide by astronomically-unlikely accident, but a
        # producer must never *assign* one from the other. We can at least
        # refuse the obvious foot-gun of literally copying the id in as digest.
        if self.event_id == self.semantic_digest:
            raise ValueError(
                "EvidenceRecordSubject: event_id and semantic_digest must be two "
                "distinct fields — the event id was reused as the semantic digest"
            )


def record_subject(event: BuzzEvent) -> EvidenceRecordSubject:
    """Build the subject for an event, keeping the two fields distinct."""
    return EvidenceRecordSubject(
        event_id=event.event_id,
        semantic_digest=event.semantic_digest(),
        principal_ref=host_principal_ref(event),
        principal_ref_relay_hint=event.relay_hint,
    )


def record_to_event(subject: EvidenceRecordSubject) -> BuzzEventShape:
    """Round-trip: project a record subject back to the Buzz-event shape.

    Returns the fields the *event* owns, byte-identical to what came in:
    ``event_id`` (the transport id) and ``pubkey`` (recovered from the
    ``nostr-pubkey:<hex>`` principal_ref), plus the optional ``relay_hint``.

    NOT recoverable — by design, not omission: ``content_bytes``. The record
    stores only ``semantic_digest``; the bytes were never retained (digests
    only). So the round-trip is byte-identical on the fields the event owns and
    the record legitimately carries, and is silent on the content it must not.
    """
    scheme, _, pubkey = subject.principal_ref.partition(":")
    if scheme != "nostr-pubkey" or not pubkey:
        raise ValueError(
            f"record_to_event: principal_ref is not a nostr-pubkey ref: {subject.principal_ref!r}"
        )
    event_shape: BuzzEventShape = {
        "event_id": subject.event_id,
        "pubkey": pubkey,
    }
    if subject.principal_ref_relay_hint is not None:
        event_shape["relay_hint"] = subject.principal_ref_relay_hint
    return event_shape
