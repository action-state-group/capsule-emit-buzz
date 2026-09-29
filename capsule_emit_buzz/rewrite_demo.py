# SPDX-License-Identifier: Apache-2.0
"""Demo: a database-level rewrite of a keyless audit chain, caught by a
signed export manifest. Offline; run ``python -m capsule_emit_buzz.rewrite_demo``.

The table and the entry hash here are a stand-in written for this demo. They
are **not** Buzz's schema or Buzz's hash, and no Buzz code is used. The point
holds for any keyless hash chain: whoever can write the table can recompute
every hash after the one they changed, and a check that only recomputes
hashes still passes.

The steps:

1. Three entries are appended. The operator exports them and signs a manifest
   (M1) with a key that is not in the database, then logs M1.
2. Someone with write access to the database rewrites entry 2 and recomputes
   every later hash. The keyless chain check still passes.
3. Two more entries are appended. The operator exports all five, signs M2 and
   logs it. The log is consistent: M1 is still in it.
4. M1 is checked against the second export, and the rewrite is caught: the
   chain at seq 3 no longer has M1's signed final hash.

No witness is contacted. See ``manifest_log.witness_receipt`` for the opt-in
witness call.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .export_manifest import (
    ExportError,
    ExportManifest,
    sign_manifest,
    signing_key_from_hex,
    unsigned_manifest,
    verify_extends,
)
from .manifest_log import LogReceipt, ManifestLog, verify_log_extends, verify_log_receipt

__all__ = ["DemoResult", "run"]

#: Public demo values, not secrets: the operator's seed and the community.
DEMO_OPERATOR_SEED = "11" * 32
DEMO_COMMUNITY = "0e0e0e0e-0000-4000-8000-00000000d3a0"


def _entry_hash(seq: int, action: str, detail: str, prev_hash: str | None) -> str:
    """The demo's keyless entry hash (a stand-in, not Buzz's)."""
    body = json.dumps([seq, action, detail, prev_hash], separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _open() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE audit (seq INTEGER PRIMARY KEY, action TEXT, detail TEXT, prev_hash TEXT, hash TEXT)")
    return db


def _append(db: sqlite3.Connection, action: str, detail: str) -> None:
    last = db.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    seq, prev = (last[0] + 1, last[1]) if last else (1, None)
    db.execute("INSERT INTO audit VALUES (?, ?, ?, ?, ?)", (seq, action, detail, prev, _entry_hash(seq, action, detail, prev)))


def keyless_check(db: sqlite3.Connection) -> bool:
    """What a keyless chain verifier can do: recompute every hash and link."""
    prev = None
    for seq, action, detail, prev_hash, h in db.execute("SELECT * FROM audit ORDER BY seq"):
        if prev_hash != prev or h != _entry_hash(seq, action, detail, prev_hash):
            return False
        prev = h
    return True


def _rewrite(db: sqlite3.Connection, seq: int, detail: str) -> None:
    """The attack: change one entry, then recompute every hash from it on."""
    db.execute("UPDATE audit SET detail = ? WHERE seq = ?", (detail, seq))
    prev = db.execute("SELECT prev_hash FROM audit WHERE seq = ?", (seq,)).fetchone()[0]
    for s, action, d in db.execute("SELECT seq, action, detail FROM audit WHERE seq >= ? ORDER BY seq", (seq,)).fetchall():
        h = _entry_hash(s, action, d, prev)
        db.execute("UPDATE audit SET prev_hash = ?, hash = ? WHERE seq = ?", (prev, h, s))
        prev = h


def _export(db: sqlite3.Connection) -> list[dict[str, Any]]:
    cols = ("seq", "action", "detail", "prev_hash", "hash")
    return [dict(zip(cols, row)) for row in db.execute("SELECT * FROM audit ORDER BY seq")]


@dataclass(frozen=True)
class DemoResult:
    keyless_check_after_rewrite: bool
    caught: bool
    reason: str
    m1: ExportManifest
    m2: ExportManifest
    r1: LogReceipt
    r2: LogReceipt


def run(*, rewrite: bool = True, say: Callable[[str], None] = lambda _line: None) -> DemoResult:
    """Run the four steps. With ``rewrite=False`` step 2 is skipped, and the
    same checks pass: the control case."""
    from capsule_emit.signing import LocalKeypairSigner

    operator = signing_key_from_hex(DEMO_OPERATOR_SEED)
    when = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)
    db = _open()
    with tempfile.TemporaryDirectory() as tmp:
        log = ManifestLog(Path(tmp) / "manifests.jsonl", LocalKeypairSigner(Path(tmp) / "log-key.pem"))

        for action, detail in (("demo", "a"), ("demo", "b"), ("demo", "c")):
            _append(db, action, detail)
        export1 = _export(db)
        m1 = sign_manifest(unsigned_manifest(DEMO_COMMUNITY, export1, when), operator)
        r1 = log.append(m1, timestamp="2026-09-29T12:00:00Z")
        say(f"1. exported seq 1..3, signed M1 (final hash {m1.final_hash[:16]}...), logged it as leaf {r1.leaf_seq}")

        if rewrite:
            _rewrite(db, 2, "b, rewritten in the database")
            say("2. rewrote seq 2 in the database and recomputed every later hash")
        after = keyless_check(db)
        say(f"   keyless chain check: {'passes' if after else 'fails'}")

        _append(db, "demo", "d")
        _append(db, "demo", "e")
        export2 = _export(db)
        m2 = sign_manifest(unsigned_manifest(DEMO_COMMUNITY, export2, when), operator)
        r2 = log.append(m2, timestamp="2026-09-29T13:00:00Z")
        verify_log_receipt(r1, m1, expected_log_key=log.key_id)
        verify_log_receipt(r2, m2, expected_log_key=log.key_id)
        verify_log_extends(r1, r2)
        say("3. exported seq 1..5, signed M2, logged it; the log at M2 extends the log at M1")

    try:
        # A demo shortcut: the pin is read from M1 itself. A real verifier pins
        # the operator's public key from a source it trusts, never the manifest.
        verify_extends(m1, m2, export2, expected_key_id=m1.exporter_key_id)
        caught, reason = False, "the second export is consistent with M1"
    except ExportError as exc:
        caught, reason = True, str(exc)
    say(f"4. M1 against the second export: {'CAUGHT: ' + reason if caught else reason}")
    return DemoResult(after, caught, reason, m1, m2, r1, r2)


if __name__ == "__main__":
    print("With the rewrite:")
    run(say=print)
    print("\nWithout it (control):")
    run(rewrite=False, say=print)
