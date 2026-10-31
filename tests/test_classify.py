# SPDX-License-Identifier: Apache-2.0
"""classify(event) -> observation | effect: a moderation decision or a release
is an effect; agent-job progress is an observation."""
from __future__ import annotations

from capsule_emit.connector import Classification

from capsule_emit_buzz.event import BUZZ_EFFECT_KINDS, BuzzEvent
from nostr_helpers import signed
from stores import connector


def _conn():
    return connector()[0]


def test_effect_kind_classifies_as_effect():
    conn = _conn()
    ev = BuzzEvent(signed("x", kind=next(iter(BUZZ_EFFECT_KINDS))))
    assert conn.classify(conn.to_connector_event(ev)) is Classification.EFFECT


def test_agent_job_progress_classifies_as_observation():
    conn = _conn()
    ev = BuzzEvent(signed("x", kind=1))
    assert conn.classify(conn.to_connector_event(ev)) is Classification.OBSERVATION
