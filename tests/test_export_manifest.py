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
    ExportError,
    ExportManifest,
    check_links,
    load_export,
    main,
    sign_manifest,
    signing_key_from_hex,
    unsigned_manifest,
    verify_against_export,
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
    assert main(["verify", "--manifest", str(out), "--export", str(export)]) == 0
    tampered = _chain(["a", "B", "c"])
    export.write_text("".join(json.dumps(e) + "\n" for e in tampered))
    assert main(["verify", "--manifest", str(out), "--export", str(export)]) == 1
    printed = capsys.readouterr()
    assert SEED not in printed.out + printed.err
    assert SEED not in out.read_text()


def test_load_export_refuses_malformed_lines():
    with pytest.raises(ExportError):
        load_export(['{"seq": 1, "hash": "nothex", "prev_hash": null}'])
    with pytest.raises(ExportError):
        load_export([])
