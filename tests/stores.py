# SPDX-License-Identifier: Apache-2.0
"""Stores and a signing identity for the connector under test: in memory, or
an artifact JSONL file plus a CLL JSONL log under a directory."""
from __future__ import annotations

from pathlib import Path

from capsule_emit.artifact.jsonl import JsonlArtifactStore
from capsule_emit.artifact.memory import MemoryArtifactStore
from capsule_emit.produce import generate_signing_identity
from cll.log import jsonl as cll_jsonl
from cll.log.memory import MemoryStore

from capsule_emit_buzz.adapter import BuzzConnector

NAMESPACE = "capsule-emit-buzz-tests"


def connector(directory: Path | None = None):
    """A connector and the (artifact store, log) it writes to."""
    identity = generate_signing_identity()
    if directory is None:
        artifacts = MemoryArtifactStore(NAMESPACE, [identity.public_key])
        log = MemoryStore()
    else:
        artifacts = JsonlArtifactStore(directory / "artifacts.jsonl", NAMESPACE, [identity.public_key])
        cll_jsonl.init(directory / "log.jsonl")
        log = cll_jsonl.open(directory / "log.jsonl")
    artifacts.init()
    conn = BuzzConnector(operator="op", developer="dev/0.0.1", identity=identity, artifacts=artifacts, log=log)
    return conn, artifacts, log


def committed(artifacts, log) -> list[dict]:
    """Every record the log commits, read from the artifact store, in order."""
    import json

    return [json.loads(artifacts.get(bytes(e.value).hex()).capsule) for e in log.scan_entries(0, 100)]
