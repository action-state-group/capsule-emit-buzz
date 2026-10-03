# SPDX-License-Identifier: Apache-2.0
"""The signed audit-export manifest (``export_manifest.py``)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from capsule_emit_buzz.export_manifest import (
    UNPINNED_EXIT,
    ExportError,
    ExportManifest,
    check_links,
    load_export,
    main,
    sign_manifest,
    signing_key_from_hex,
    unsigned_manifest,
    verify_against_export,
    verify_extends,
)

VECTOR = json.loads((Path(__file__).parent / "vectors" / "audit-export-manifest-v1.json").read_text())
SEED = "07" * 32  # the vector's public test key
COMMUNITY = "f1cb11e0-0000-0000-0000-000000000001"
WHEN = datetime(2026, 9, 25, 18, 4, 11, tzinfo=timezone.utc)


def _h(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _chain(labels: list[str], start: int = 1) -> list[dict]:
    entries, prev = [], None
    for n, label in enumerate(labels, start):
        h = _h(f"{label}|{prev}")
        entries.append({"seq": n, "hash": h, "prev_hash": prev, "action": "event_created",
                        "detail": {"reason": f"moderation note {label}"}})
        prev = h
    return entries


def test_the_rust_signing_path_is_reproduced_byte_for_byte():
    m = VECTOR["manifest"]
    unsigned = ExportManifest(**{**m, "exporter_key_id": "", "signature": ""})
    signed = sign_manifest(unsigned, signing_key_from_hex(SEED))
    assert signed.signing_body() == VECTOR["signing_body"]
    assert signed.digest_hex() == VECTOR["digest_hex"]
    assert signed.exporter_key_id == m["exporter_key_id"]
    assert signed.signature == m["signature"], "Ed25519 is deterministic: the same signature"


def test_a_manifest_signed_in_rust_verifies_here():
    assert ExportManifest.from_json(VECTOR["manifest"]).verify_signature_offline()


def test_sign_then_verify_against_the_export():
    entries = _chain(["a", "b", "c"])
    manifest = sign_manifest(unsigned_manifest(COMMUNITY, entries, WHEN), signing_key_from_hex(SEED))
    assert (manifest.from_seq, manifest.to_seq, manifest.entry_count) == (1, 3, 3)
    assert manifest.final_hash == entries[-1]["hash"]
    assert manifest.exported_at == "2026-09-25T18:04:11Z"
    verify_against_export(manifest, entries)


@pytest.mark.parametrize("field, value", [
    ("community_id", "f1cb11e0-0000-0000-0000-000000000002"),
    ("from_seq", 2), ("to_seq", 4), ("entry_count", 4),
    ("final_hash", "0" * 64), ("exported_at", "2026-09-25T18:04:12Z"),
])
def test_changing_any_signed_field_breaks_the_signature(field, value):
    signed = ExportManifest.from_json(VECTOR["manifest"])
    assert not replace(signed, **{field: value}).verify_signature_offline()


def test_relabelling_under_another_key_breaks_the_signature():
    signed = ExportManifest.from_json(VECTOR["manifest"])
    other = sign_manifest(replace(signed, signature=""), signing_key_from_hex("08" * 32))
    assert not replace(signed, exporter_key_id=other.exporter_key_id).verify_signature_offline()


@pytest.mark.parametrize("change", [{"signature": "zz"}, {"signature": "ab" * 10}, {"exporter_key_id": "nothex"}])
def test_malformed_fields_do_not_verify_and_do_not_raise(change):
    assert not replace(ExportManifest.from_json(VECTOR["manifest"]), **change).verify_signature_offline()


def test_a_recomputed_rewrite_keeps_its_links_but_fails_the_signed_final_hash():
    """Rewrite entry 2 after the manifest was signed and recompute every later
    hash: the export still links up, but no longer matches the manifest."""
    original = _chain(["a", "b", "c"])
    manifest = sign_manifest(unsigned_manifest(COMMUNITY, original, WHEN), signing_key_from_hex(SEED))
    rewritten = _chain(["a", "B-rewritten", "c"])
    check_links(rewritten)
    with pytest.raises(ExportError, match="final hash"):
        verify_against_export(manifest, rewritten)


def test_a_broken_export_is_never_signed():
    entries = _chain(["a", "b", "c"])
    entries[2]["prev_hash"] = "f" * 64
    with pytest.raises(ExportError, match="does not link"):
        unsigned_manifest(COMMUNITY, entries, WHEN)
    gap = _chain(["a", "b"]) + _chain(["c"], start=4)
    with pytest.raises(ExportError):
        check_links(gap)


def test_the_manifest_carries_no_entry_content():
    entries = _chain(["a", "b", "c"])
    manifest = sign_manifest(unsigned_manifest(COMMUNITY, entries, WHEN), signing_key_from_hex(SEED))
    text = json.dumps(manifest.to_json())
    assert "moderation note" not in text and "event_created" not in text


def test_the_command_line_signs_and_verifies_without_printing_the_key(tmp_path, capsys):
    export = tmp_path / "export.jsonl"
    export.write_text("".join(json.dumps(e) + "\n" for e in _chain(["a", "b", "c"])))
    key = tmp_path / "key.hex"
    key.write_text(SEED)
    out = tmp_path / "manifest.json"
    assert main(["sign", "--export", str(export), "--community-id", COMMUNITY, "--key-file", str(key), "--out", str(out)]) == 0
    pinned = json.loads(out.read_text())["exporter_key_id"]
    assert main(["verify", "--manifest", str(out), "--export", str(export), "--expect-key", pinned]) == 0
    assert "links and final hash match" in capsys.readouterr().out
    assert main(["verify", "--manifest", str(out), "--export", str(export)]) == UNPINNED_EXIT
    assert "UNPINNED" in capsys.readouterr().out, "never plain ok without a pinned key"
    tampered = _chain(["a", "B", "c"])
    export.write_text("".join(json.dumps(e) + "\n" for e in tampered))
    assert main(["verify", "--manifest", str(out), "--export", str(export), "--expect-key", pinned]) == 1
    printed = capsys.readouterr()
    assert SEED not in printed.out + printed.err
    assert SEED not in out.read_text()


def test_load_export_refuses_malformed_lines():
    with pytest.raises(ExportError):
        load_export(['{"seq": 1, "hash": "nothex", "prev_hash": null}'])
    with pytest.raises(ExportError):
        load_export([])


def test_a_manifest_re_signed_with_a_fresh_key_fails_against_the_pinned_key():
    """The attack the pin stops: rewrite the export, then sign a new manifest
    for it with a fresh key. Its signature is valid; only the pin refuses it."""
    original = _chain(["a", "b", "c"])
    operator = signing_key_from_hex(SEED)
    genuine = sign_manifest(unsigned_manifest(COMMUNITY, original, WHEN), operator)
    rewritten = _chain(["a", "B-rewritten", "c"])
    forged = sign_manifest(unsigned_manifest(COMMUNITY, rewritten, WHEN), signing_key_from_hex("09" * 32))
    assert forged.verify_signature_offline(), "the forged manifest's own signature is valid"
    verify_against_export(forged, rewritten)  # unpinned: nothing catches it
    with pytest.raises(ExportError, match="pinned"):
        verify_against_export(forged, rewritten, expected_key_id=genuine.exporter_key_id)


def test_the_operators_manifest_passes_against_its_pinned_key():
    entries = _chain(["a", "b", "c"])
    manifest = sign_manifest(unsigned_manifest(COMMUNITY, entries, WHEN), signing_key_from_hex(SEED))
    verify_against_export(manifest, entries, expected_key_id=manifest.exporter_key_id.upper())


def _signed(entries):
    return sign_manifest(unsigned_manifest(COMMUNITY, entries, WHEN), signing_key_from_hex(SEED))


def test_a_later_export_that_covers_the_earlier_range_extends_it():
    earlier, later_entries = _chain(["a", "b", "c"]), _chain(["a", "b", "c", "d", "e"])
    m1, m2 = _signed(earlier), _signed(later_entries)
    verify_extends(m1, m2, later_entries, expected_key_id=m1.exporter_key_id)


def test_a_rewrite_between_two_exports_is_caught_even_with_the_hashes_recomputed():
    m1 = _signed(_chain(["a", "b", "c"]))
    rewritten = _chain(["a", "B-rewritten", "c", "d", "e"])
    m2 = _signed(rewritten)  # the operator signs what is there now
    with pytest.raises(ExportError, match="earlier signed final hash"):
        verify_extends(m1, m2, rewritten, expected_key_id=m1.exporter_key_id)


def test_an_incremental_export_must_link_to_the_earlier_final_hash():
    full = _chain(["a", "b", "c", "d", "e"])
    m1, tail = _signed(full[:3]), full[3:]
    verify_extends(m1, _signed(tail), tail, expected_key_id=m1.exporter_key_id)
    other_tail = _chain(["a", "B", "c", "d", "e"])[3:]
    with pytest.raises(ExportError, match="does not link"):
        verify_extends(m1, _signed(other_tail), other_tail, expected_key_id=m1.exporter_key_id)


def test_extends_refuses_another_key_another_community_or_a_gap():
    earlier, later = _chain(["a", "b", "c"]), _chain(["a", "b", "c", "d"])
    m1, m2 = _signed(earlier), _signed(later)
    other = sign_manifest(unsigned_manifest(COMMUNITY, earlier, WHEN), signing_key_from_hex("09" * 32))
    with pytest.raises(ExportError, match="pinned"):
        verify_extends(other, m2, later, expected_key_id=m1.exporter_key_id)
    elsewhere = sign_manifest(unsigned_manifest("f1cb11e0-0000-0000-0000-000000000002", later, WHEN),
                              signing_key_from_hex(SEED))
    with pytest.raises(ExportError, match="different communities"):
        verify_extends(m1, elsewhere, later, expected_key_id=m1.exporter_key_id)
    gap = _chain(["x", "y"], start=5)
    with pytest.raises(ExportError, match="neither covers nor follows"):
        verify_extends(m1, _signed(gap), gap, expected_key_id=m1.exporter_key_id)


def test_a_later_export_that_starts_before_its_from_seq_is_indexed_by_seq():
    """The export may hold entries before the later manifest's from_seq; the
    link to the earlier manifest is read at from_seq, never at the first line."""
    full = _chain(["a", "b", "c", "d", "e"])
    m1 = _signed(full[:3])
    m2 = _signed(full[3:])  # signs seq 4..5
    verify_extends(m1, m2, full, expected_key_id=m1.exporter_key_id)  # export starts at seq 1
    rewritten = _chain(["a", "B", "c", "d", "e"])
    with pytest.raises(ExportError, match="does not link"):
        verify_extends(m1, _signed(rewritten[3:]), rewritten, expected_key_id=m1.exporter_key_id)


def test_a_later_export_missing_its_from_seq_entry_fails_clearly():
    """A signed manifest whose from_seq is not in the export (its count agrees
    with what is there) is refused by name, not with a KeyError."""
    full = _chain(["a", "b", "c", "d", "e"])
    m1 = _signed(full[:3])
    claims_4_to_5 = replace(unsigned_manifest(COMMUNITY, full[4:], WHEN), from_seq=4)
    m2 = sign_manifest(claims_4_to_5, signing_key_from_hex(SEED))
    with pytest.raises(ExportError, match="no entry at its from_seq 4"):
        verify_extends(m1, m2, full[4:], expected_key_id=m1.exporter_key_id)
