# SPDX-License-Identifier: Apache-2.0
"""``BuzzConnector`` — a :class:`capsule_emit.connector.ConnectorPort` over
Buzz (Nostr) events.

This adapter implements capsule-emit's public ConnectorPort contract, matched
verbatim from capsule-emit's ``connector.py`` (exported at package top level
since capsule-emit 0.8.4):

    boundary_class: str
    def classify(self, event: ConnectorEvent) -> Classification: ...
    def capture(self, event: ConnectorEvent) -> Capsule: ...      # Capsule = EmitResult

Two Buzz-specific decisions the contract leaves to the adapter:

1.  capture() ALWAYS carries via ``received()``, never ``seal()``.
    A Buzz event we observed is a FOREIGN, ALREADY-SIGNED artifact: the Nostr
    author signed it with their own key before this adapter ever saw it. Under
    surface.py's dispatch rule, foreign already-signed bytes are ``received()``
    (a carry, brought in as-transmitted under their declared type) — sealing
    them would falsely assert this adapter's operator authored content someone
    else signed. So ``BuzzEvent`` always maps to a foreign ConnectorEvent and
    ``capture()`` always takes the ``received()`` branch. The carried bytes are
    the event's exact JSON, and ``capture()`` verifies them (NIP-01 id and
    BIP-340 signature) before anything is logged.

2.  classify() maps the Buzz event kind, not raw HTTP/MCP signals.
    A moderation DECISION and a RELEASE going live are effects (a write crossed
    a boundary — content removed/labeled; a change made live). Agent-job
    PROGRESS is an observation (a read). We express this by setting the
    ConnectorEvent signals so capsule-emit's own ``classify_signal_1`` returns
    the right class, keeping Signal-1 semantics identical to every other
    adapter rather than re-deriving them here.

Boundary class: LISTENER. This adapter is a passive tap on Buzz's event stream
(the relay feed / firehose), not a gateway on live traffic, a developer
decorator at a call site, or the engine that knows resource classifications.
It sees every event the stream carries; it declares no Signal-2 knowledge.
"""
from __future__ import annotations

from capsule_emit.connector import (
    BoundaryClass,
    Capsule,
    Classification,
    ConnectorEvent,
    ConnectorPort,
    classify_signal_1,
)
from capsule_emit.surface import received

from .event import BuzzEvent, host_principal_ref
from .record import EvidenceRecordSubject, record_subject

__all__ = ["BuzzConnector"]

#: Registered CPB type under which a carried Buzz/Nostr event enters the log.
#: Provisional: the authoritative foreign type string is a property of the
#: buzz.* profiles (capsule-registry), not this repo; re-point it when those
#: profiles register one.
_BUZZ_FOREIGN_TYPE = "application/buzz-nostr-event"  # provisional


class BuzzConnector:
    """A ConnectorPort over Buzz (Nostr) events. See module docstring.

    Conforms structurally to :class:`capsule_emit.connector.ConnectorPort`
    (checked with ``isinstance(BuzzConnector(...), ConnectorPort)`` in the
    tests) without inheriting from it — the contract is a runtime-checkable
    Protocol, and conformance is having ``boundary_class`` + ``classify()`` +
    ``capture()``, exactly as the two in-tree capsule-emit adapters do it.
    """

    #: Declared, not inferred — a passive tap on Buzz's event stream.
    boundary_class: str = BoundaryClass.LISTENER.value

    def __init__(
        self,
        *,
        operator: str,
        developer: str,
        ledger: str = "ledger.jsonl",
        witness: bool | None = None,
    ) -> None:
        """``witness`` follows capsule-emit when left ``None``: witnessing is
        on (unless ``CAPSULE_WITNESS=off``), and what leaves the process is a
        signed checkpoint of this log (its size, a root hash and a time),
        never a record's content, once 100 records have accumulated or 900
        seconds have passed. ``witness=False`` turns it off for this
        connector."""
        self._operator = operator
        self._developer = developer
        self._ledger = ledger
        self._witness = witness

    # -- ConnectorPort ------------------------------------------------------

    def classify(self, event: ConnectorEvent) -> Classification:
        """Signal-1 classification via capsule-emit's own rule.

        We map the Buzz kind into ``ConnectorEvent`` signals in
        :meth:`_to_connector_event`, so the shared ``classify_signal_1`` returns
        EFFECT for a moderation decision / release and OBSERVATION for agent-job
        progress. Using the shared rule (rather than a bespoke one) keeps this
        adapter's Signal-1 semantics identical to every other adapter's.
        """
        return classify_signal_1(event)

    def capture(self, event: ConnectorEvent) -> Capsule:
        """Carry the foreign, already-signed Buzz event via ``received()``.

        ``event.foreign`` is always ``True`` for a Buzz event (see module
        docstring), so this always takes the ``received()`` branch — never
        ``seal()``. Returns the already-logged capsule (``EmitResult``).
        """
        if not event.foreign:
            raise ValueError(
                "BuzzConnector.capture: a Buzz event is a foreign, already-signed "
                "artifact and must be carried via received(), never sealed"
            )
        raw = event.foreign_bytes
        # The carried bytes must be a signed Nostr event that verifies, however
        # the ConnectorEvent was built: NostrEventError otherwise, and nothing
        # is logged.
        buzz = BuzzEvent(raw.encode("utf-8") if isinstance(raw, str) else bytes(raw))
        return received(
            buzz.event_bytes,
            type=event.foreign_type,
            operator=self._operator,
            developer=self._developer,
            ledger=self._ledger,
            witness=self._witness,
            # The record names the event it carries: its Nostr id, its
            # author's key, and the digest of the full signed event.
            extra_compute={
                "buzz_event": {
                    "event_id": buzz.event_id,
                    "pubkey": buzz.pubkey,
                    "semantic_digest": buzz.semantic_digest(),
                }
            },
        )

    # -- Buzz-side convenience ---------------------------------------------

    def to_connector_event(self, event: BuzzEvent) -> ConnectorEvent:
        """Map a :class:`BuzzEvent` to the ConnectorPort's ConnectorEvent.

        Sets ``foreign=True`` (Buzz events are always carried) and encodes the
        effect/observation decision as an ``mcp_read_only_hint`` so the shared
        ``classify_signal_1`` yields the Buzz-native class:
          * effect kind  -> read_only_hint False -> EFFECT
          * otherwise    -> read_only_hint True  -> OBSERVATION
        """
        return ConnectorEvent(
            name=f"buzz.event.{event.kind}",
            http_method=None,
            mcp_read_only_hint=not event.is_effect_kind(),
            foreign=True,
            foreign_bytes=event.event_bytes,
            foreign_type=_BUZZ_FOREIGN_TYPE,
        )

    def subject_for(self, event: BuzzEvent) -> EvidenceRecordSubject:
        """The two-field subject ({event_id, semantic_digest} + principal_ref)."""
        return record_subject(event)

    def principal_for(self, event: BuzzEvent) -> str:
        """The ``nostr-pubkey:<hex>`` host principal_ref for the event."""
        return host_principal_ref(event)


# Structural conformance is asserted in tests/test_connector_conformance.py:
#   assert isinstance(BuzzConnector(...), ConnectorPort)
_ = ConnectorPort  # referenced so the import is obviously intentional
