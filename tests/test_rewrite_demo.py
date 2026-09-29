# SPDX-License-Identifier: Apache-2.0
"""The gap the signed manifest closes, end to end (``rewrite_demo.py``): a
database-level rewrite of a keyless audit chain, with every later hash
recomputed, passes a keyless check and is caught by the signed manifest."""
from __future__ import annotations

from capsule_emit_buzz import rewrite_demo


def test_a_recomputed_database_rewrite_passes_the_keyless_check_and_is_caught():
    lines: list[str] = []
    result = rewrite_demo.run(say=lines.append)
    assert result.keyless_check_after_rewrite, "the gap: a keyless check cannot see the rewrite"
    assert result.caught
    assert "earlier signed final hash at seq 3" in result.reason
    assert result.r2.consistency is not None, "the log still holds M1: the rewrite is in the chain, not the log"
    assert any(line.startswith("4. ") and "CAUGHT" in line for line in lines)


def test_without_the_rewrite_the_same_checks_pass():
    result = rewrite_demo.run(rewrite=False)
    assert result.keyless_check_after_rewrite
    assert not result.caught, result.reason


def test_the_demo_hash_is_keyless_so_anyone_with_the_table_can_recompute_it():
    db = rewrite_demo._open()
    for label in "abc":
        rewrite_demo._append(db, "demo", label)
    assert rewrite_demo.keyless_check(db)
    db.execute("UPDATE audit SET detail = 'x' WHERE seq = 2")
    assert not rewrite_demo.keyless_check(db), "a rewrite without recomputing is visible"
    rewrite_demo._rewrite(db, 2, "x")
    assert rewrite_demo.keyless_check(db), "a rewrite with recomputing is not"
