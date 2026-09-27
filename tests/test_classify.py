# SPDX-License-Identifier: Apache-2.0
"""classify(event) -> observation | effect.

Moderation decision and release = effect; agent-job progress = observation.
These tests exercise BuzzConnector against capsule-emit's ConnectorPort; they
are skipped if capsule-emit is not installed (the structural tests
still run standalone).
"""
from __future__ import annotations

import pytest

pytest.importorskip(
    "capsule_emit.connector",
    reason="capsule-emit>=0.8.4 (ConnectorPort) not installed in this env",
)

from capsule_emit.connector import Classification  # noqa: E402

from capsule_emit_buzz.adapter import BuzzConnector  # noqa: E402
from capsule_emit_buzz.event import BUZZ_EFFECT_KINDS, BuzzEvent  # noqa: E402

PUBKEY = "c" * 64
EVENT_ID = "6" * 64


def _conn() -> BuzzConnector:
    return BuzzConnector(operator="op", developer="dev/0.0.1", ledger="/tmp/never.jsonl")


def test_effect_kind_classifies_as_effect():
    conn = _conn()
    effect_kind = next(iter(BUZZ_EFFECT_KINDS))
    ev = BuzzEvent(event_id=EVENT_ID, pubkey=PUBKEY, kind=effect_kind, content_bytes=b"x")
    ce = conn.to_connector_event(ev)
    assert conn.classify(ce) is Classification.EFFECT


def test_agent_job_progress_classifies_as_observation():
    conn = _conn()
    # A non-effect kind stands in for agent-job progress (a read).
    ev = BuzzEvent(event_id=EVENT_ID, pubkey=PUBKEY, kind=1, content_bytes=b"x")
    ce = conn.to_connector_event(ev)
    assert conn.classify(ce) is Classification.OBSERVATION
