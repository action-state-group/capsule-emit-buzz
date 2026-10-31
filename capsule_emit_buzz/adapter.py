# SPDX-License-Identifier: Apache-2.0
"""``BuzzConnector`` — a :class:`capsule_emit.connector.ConnectorPort` over
Buzz (Nostr) events.

The connector has the members of capsule-emit's ConnectorPort
(``capsule_emit.connector``):

    boundary_class: str
    def classify(self, event: ConnectorEvent) -> Classification: ...
    def capture(self, event: ConnectorEvent) -> Capsule: ...      # Capsule = EmitResult

with one departure: ``capture()`` returns a ``capsule_emit.produce.Result``,
not the ``EmitResult`` the port declares. The port itself moves out of
capsule-emit later.

Two Buzz-specific decisions:

1.  capture() builds with ``capsule_emit.produce.received()``, never a seal.
    A Buzz event we observed is a FOREIGN, ALREADY-SIGNED artifact: the Nostr
    author signed it with their own key before this adapter ever saw it.
    Sealing it would falsely assert this adapter's operator authored content
    someone else signed, so it is carried as received, under its declared
    type, as transmitted. The carried bytes are
    the event's exact JSON, and ``capture()`` verifies them (NIP-01 id and
    BIP-340 signature) before anything is written.

    The record is built and signed in memory with the ``SigningIdentity`` the
    caller gives the connector, then written in two steps: ``put`` into the
    caller's artifact store (``capsule_emit.artifact``), then ``append`` of its
    Capsule ID to the caller's CLL entry log (``cll.log``), which is the commit.
    Checkpointing and witnessing that log are the caller's.

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

import json
from datetime import datetime, timezone

from capsule_emit.connector import (
    BoundaryClass,
    Classification,
    ConnectorEvent,
    ConnectorPort,
    classify_signal_1,
)
from capsule_emit.artifact import Record
from capsule_emit.artifact import Store as ArtifactStore
from capsule_emit.produce import ActionType, Extension, Input, Result, SigningIdentity, received, sign
from cll.log import AppendInput, EntryStore

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

    Has the members of :class:`capsule_emit.connector.ConnectorPort`, a
    runtime-checkable Protocol (``isinstance(BuzzConnector(...),
    ConnectorPort)`` holds in the tests), without inheriting from it.
    ``capture()`` returns a ``capsule_emit.produce.Result``, not the
    ``EmitResult`` the port declares.
    """

    #: Declared, not inferred — a passive tap on Buzz's event stream.
    boundary_class: str = BoundaryClass.LISTENER.value

    def __init__(
        self,
        *,
        operator: str,
        developer: str,
        identity: SigningIdentity,
        artifacts: ArtifactStore,
        log: EntryStore,
    ) -> None:
        """``identity`` signs each record's Producer Envelope; ``artifacts``
        holds the record and its envelope; ``log`` commits its Capsule ID.
        The caller owns all three (opening, trusting the identity's public
        key in the artifact store, checkpointing and closing)."""
        self._operator = operator
        self._developer = developer
        self._identity = identity
        self._artifacts = artifacts
        self._log = log

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

    def capture(self, event: ConnectorEvent) -> Result:
        """Carry the foreign, already-signed Buzz event: build it with
        ``produce.received()``, never a seal, and write it.

        A non-foreign event is refused. Returns the written record as a
        ``capsule_emit.produce.Result`` (Capsule ID, Capsule bytes, Producer
        Envelope), not the ``EmitResult`` ConnectorPort declares.
        """
        if not event.foreign:
            raise ValueError(
                "BuzzConnector.capture: a Buzz event is a foreign, already-signed "
                "artifact and must be carried via received(), never sealed"
            )
        raw = event.foreign_bytes
        # The carried bytes must be a signed Nostr event that verifies, however
        # the ConnectorEvent was built: NostrEventError otherwise, and nothing
        # is written.
        buzz = BuzzEvent(raw.encode("utf-8") if isinstance(raw, str) else bytes(raw))
        # The record names the event it carries: its Nostr id, its author's
        # key, and the digest of the full signed event.
        link = {"event_id": buzz.event_id, "pubkey": buzz.pubkey, "semantic_digest": buzz.semantic_digest()}
        built = received(
            Input(
                action_id=f"buzz.event/{buzz.event_id}",
                action_type=ActionType.FYI,
                operator=self._operator,
                developer=self._developer,
                # When this connector received the event, not the author's
                # created_at (which the carried bytes already hold).
                timestamp=datetime.now(timezone.utc),
                extensions=(Extension(name="buzz_event", value=json.dumps(link, separators=(",", ":"))),),
            ),
            buzz.event_bytes,
            event.foreign_type,
        )
        envelope = sign(built, self._identity)
        self._artifacts.put(Record(capsule_id=built.capsule_id, capsule=built.json, producer_envelope=envelope))
        self._log.append(AppendInput(value=bytes.fromhex(built.capsule_id), appended_at=datetime.now(timezone.utc)))
        return Result(capsule_id=built.capsule_id, payload=built.json, envelope=envelope)

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
