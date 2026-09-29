# SPDX-License-Identifier: Apache-2.0
"""capsule-emit-buzz — Buzz-side event -> EvidenceRecord adapter and fixtures.

Apache-2.0. This package consumes capsule-emit's public
``ConnectorPort`` contract and adds nothing to the neutral substrate: the
Buzz Evidence Contract profiles it references (``nostr-pubkey`` host-principal
profile; ``buzz.agent-job/v1``, ``buzz.moderation/v1``, ``buzz.release/v1``)
belong to the capsule-registry / agent-action-capsule repositories, never
here.

Public surface:

    from capsule_emit_buzz import (
        BuzzEvent,
        BuzzConnector,
        EvidenceRecordSubject,
        host_principal_ref,
        record_to_event,
    )

``BuzzConnector`` is imported lazily (via module ``__getattr__``) because it
depends on capsule-emit's ``ConnectorPort``; the event/record modules and the
fixtures they generate work standalone, so importing this package never
requires capsule-emit to be installed.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .event import BuzzEvent, host_principal_ref
from .record import BuzzEventShape, EvidenceRecordSubject, record_to_event

if TYPE_CHECKING:
    from .adapter import BuzzConnector

__all__ = [
    "BuzzConnector",
    "BuzzEventShape",
    "BuzzEvent",
    "EvidenceRecordSubject",
    "host_principal_ref",
    "record_to_event",
]


def __getattr__(name: str) -> type[BuzzConnector]:
    if name == "BuzzConnector":
        from .adapter import BuzzConnector

        return BuzzConnector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
