# SPDX-License-Identifier: Apache-2.0
"""The manifest log (``manifest_log.py``): inclusion, consistency between two
exports, and the optional witness. No test uses the network: the witness is a
local test key minting a real COSE Receipt, injected as the transport."""
from __future__ import annotations

import base64
import hashlib
import json
import socket
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from capsule_emit.signing import LocalKeypairSigner
from cll.checkpoint import WitnessRecord, verify_checkpoint_cose_offline
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose.receipt import build_receipt

from capsule_emit_buzz.export_manifest import (
    ExportError,
    sign_manifest,
    signing_key_from_hex,
    unsigned_manifest,
    verify_extends,
)
from capsule_emit_buzz.manifest_log import (
    LogReceipt,
    ManifestLog,
    main,
    manifest_leaf_digest,
    verify_log_extends,
    verify_log_receipt,
    verify_witnesses,
    witness_receipt,
)

SEED = "07" * 32
COMMUNITY = "f1cb11e0-0000-0000-0000-000000000001"
WHEN = datetime(2026, 9, 25, 18, 4, 11, tzinfo=timezone.utc)


def _chain(labels: str) -> list[dict]:
    entries, prev = [], None
    for n, label in enumerate(labels, 1):
        h = hashlib.sha256(f"{label}|{prev}".encode()).hexdigest()
        entries.append({"seq": n, "hash": h, "prev_hash": prev})
        prev = h
    return entries


def _manifest(labels: str, seed: str = SEED):
    return sign_manifest(unsigned_manifest(COMMUNITY, _chain(labels), WHEN), signing_key_from_hex(seed))


@pytest.fixture
def log_key(tmp_path: Path) -> LocalKeypairSigner:
    return LocalKeypairSigner(tmp_path / "log-key.pem")


@pytest.fixture
def log(tmp_path: Path, log_key: LocalKeypairSigner) -> ManifestLog:
    return ManifestLog(tmp_path / "manifests.jsonl", log_key)


class LocalWitness:
    """A test witness: checks the checkpoint statement, then mints a real
    RFC 9162 COSE Receipt over its entry hash with a local test key."""

    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.calls: list[tuple[bytes, str]] = []
        self.entries: list[str] = []

    def pem(self, private: bool = False) -> bytes:
        if private:
            return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
        return self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)

    def register(self, cose: bytes, url: str) -> WitnessRecord:
        self.calls.append((cose, url))
        checked = verify_checkpoint_cose_offline(cose)
        assert checked.ok, checked.errors
        cp = checked.decoded.to_checkpoint_record()
        entry = hashlib.sha256(bytes.fromhex(cp.digest())).hexdigest()
        self.entries.append(entry)
        receipt = build_receipt(leaf_entry_hex=entry, leaf_index=len(self.entries) - 1,
                                tree_entries_hex=list(self.entries), alg="EdDSA", log_private_key_pem=self.pem(True))
        return WitnessRecord(ts_url=url, entry_hash=entry, receipt_b64=base64.b64encode(receipt).decode(),
                             leaf_index=len(self.entries) - 1, tree_size=len(self.entries))


def test_a_logged_manifest_has_a_verifying_inclusion_receipt(log, log_key):
    m1 = _manifest("abc")
    r1 = log.append(m1)
    assert r1.leaf_seq == 1 and r1.consistency is None and r1.witnesses == ()
    verify_log_receipt(r1, m1, expected_log_key=log_key.key_id)


def test_the_receipt_is_for_that_manifest_only(log, log_key):
    m1 = _manifest("abc")
    r1 = log.append(m1)
    with pytest.raises(ExportError, match="different manifest"):
        verify_log_receipt(r1, _manifest("abd"), expected_log_key=log_key.key_id)
    other = ManifestLog(log._path.with_name("other.jsonl"), LocalKeypairSigner(log._path.with_name("other.pem")))
    forged = other.append(m1)
    with pytest.raises(ExportError, match="pinned log key"):
        verify_log_receipt(forged, m1, expected_log_key=log_key.key_id)


def test_a_tampered_inclusion_proof_or_root_fails(log, log_key):
    m1, m2 = _manifest("abc"), _manifest("abcde")
    log.append(m1)
    r2 = log.append(m2)
    bad_proof = replace(r2.inclusion, peaks_left=("00" * 32,))
    with pytest.raises(ExportError, match="not included"):
        verify_log_receipt(replace(r2, inclusion=bad_proof), m2, expected_log_key=log_key.key_id)
    bad_root = replace(r2.checkpoint, root="00" * 32)
    with pytest.raises(ExportError, match="signature"):
        verify_log_receipt(replace(r2, checkpoint=bad_root), m2, expected_log_key=log_key.key_id)


def test_two_exports_the_later_log_extends_the_earlier_one_across_a_reopen(tmp_path, log_key):
    path = tmp_path / "manifests.jsonl"
    m1, m2 = _manifest("abc"), _manifest("abcde")
    r1 = ManifestLog(path, log_key).append(m1)
    r2 = ManifestLog(path, LocalKeypairSigner(tmp_path / "log-key.pem")).append(m2)  # a later process
    verify_log_receipt(r1, m1, expected_log_key=log_key.key_id)
    verify_log_receipt(r2, m2, expected_log_key=log_key.key_id)
    verify_log_extends(r1, r2)
    verify_extends(m1, m2, _chain("abcde"), expected_key_id=m1.exporter_key_id)


def test_a_log_that_dropped_the_first_manifest_does_not_extend_it(tmp_path, log_key):
    m1, m2 = _manifest("abc"), _manifest("abcde")
    r1 = ManifestLog(tmp_path / "kept.jsonl", log_key).append(m1)
    rebuilt = ManifestLog(tmp_path / "rebuilt.jsonl", log_key)  # same key, M1 left out
    rebuilt.append(_manifest("xyz"))
    r2 = rebuilt.append(m2)
    with pytest.raises(ExportError, match="does not follow"):
        verify_log_extends(r1, r2)
    forged = replace(r2, checkpoint=replace(r2.checkpoint, prev_root=r1.checkpoint.root))
    with pytest.raises(ExportError, match="does not extend"):
        verify_log_extends(r1, forged)


def test_an_unsigned_manifest_is_never_logged(log):
    with pytest.raises(ExportError, match="not logged"):
        log.append(replace(_manifest("abc"), signature="00" * 64))


def test_the_log_holds_no_entry_content(log):
    entries = [dict(e, detail={"reason": "moderation note"}) for e in _chain("abc")]
    log.append(sign_manifest(unsigned_manifest(COMMUNITY, entries, WHEN), signing_key_from_hex(SEED)))
    assert "moderation note" not in log._path.read_text()


def test_the_receipt_round_trips_through_json(log, log_key):
    m1, m2 = _manifest("abc"), _manifest("abcde")
    r1, r2 = log.append(m1), log.append(m2)
    back = LogReceipt.from_json(json.loads(json.dumps(r2.to_json())))
    verify_log_receipt(back, m2, expected_log_key=log_key.key_id)
    verify_log_extends(LogReceipt.from_json(r1.to_json()), back)
    with pytest.raises(ExportError):
        LogReceipt.from_json({"v": 1, "kind": "something else"})


def test_appending_never_touches_the_network(log):
    """The autouse fixture makes any connection fail; appending, checkpointing
    and verifying all run under it."""
    with pytest.raises(AssertionError, match="no network"):
        socket.create_connection(("192.0.2.1", 443))
    log.append(_manifest("abc"))
    log.append(_manifest("abcde"))


def test_the_witness_is_called_only_when_asked_and_only_with_the_checkpoint(log, log_key):
    witness = LocalWitness()
    m1, m2 = _manifest("abc"), _manifest("abcde")
    r1 = log.append(m1)
    r2 = log.append(m2)
    assert witness.calls == [], "logging alone calls no witness"
    w2 = witness_receipt(log, r2, "https://witness.test", register=witness.register)
    assert len(witness.calls) == 1
    sent, url = witness.calls[0]
    assert url == "https://witness.test"
    assert m2.final_hash.encode() not in sent and bytes.fromhex(m2.final_hash) not in sent
    assert r2.manifest_digest.encode() not in sent, "only the checkpoint is sent"
    verify_log_receipt(w2, m2, expected_log_key=log_key.key_id)
    verify_log_extends(r1, w2)
    [(ts_url, ok, reasons)] = verify_witnesses(w2, ts_pubkey_pem=witness.pem())
    assert (ts_url, ok) == ("https://witness.test", True), reasons


def test_a_witness_receipt_under_another_key_or_checkpoint_fails(log):
    witness, impostor = LocalWitness(), LocalWitness()
    log.append(_manifest("abc"))
    r2 = log.append(_manifest("abcde"))
    w2 = witness_receipt(log, r2, "https://witness.test", register=impostor.register)
    [(_url, ok, _reasons)] = verify_witnesses(w2, ts_pubkey_pem=witness.pem())
    assert not ok, "a receipt signed by another witness key does not verify under the pinned one"
    genuine = witness_receipt(log, r2, "https://witness.test", register=witness.register)
    [(_url, ok, _reasons)] = verify_witnesses(genuine, ts_pubkey_pem=witness.pem())
    assert ok
    moved = replace(genuine, checkpoint=replace(r2.checkpoint, timestamp="2000-01-01T00:00:00Z"))
    [(_url, ok, _reasons)] = verify_witnesses(moved, ts_pubkey_pem=witness.pem())
    assert not ok, "a receipt is bound to its checkpoint"


def test_an_unwitnessed_receipt_has_no_witness_results(log):
    assert verify_witnesses(log.append(_manifest("abc"))) == []


def test_the_command_line_appends_and_verifies_offline(tmp_path, capsys):
    m1, m2 = _manifest("abc"), _manifest("abcde")
    for name, m in (("m1.json", m1), ("m2.json", m2)):
        (tmp_path / name).write_text(json.dumps(m.to_json()))
    common = ["--log", str(tmp_path / "log.jsonl"), "--log-key", str(tmp_path / "log.pem")]
    assert main(["append", "--manifest", str(tmp_path / "m1.json"), *common, "--out", str(tmp_path / "r1.json")]) == 0
    assert "not witnessed" in capsys.readouterr().out
    assert main(["append", "--manifest", str(tmp_path / "m2.json"), *common, "--out", str(tmp_path / "r2.json")]) == 0
    key = LocalKeypairSigner(tmp_path / "log.pem").key_id
    args = ["verify", "--receipt", str(tmp_path / "r2.json"), "--manifest", str(tmp_path / "m2.json"),
            "--expect-log-key", key, "--earlier", str(tmp_path / "r1.json")]
    assert main(args) == 0
    assert "extends the earlier" in capsys.readouterr().out
    assert main([*args[:-2]]) == 0
    wrong = ["verify", "--receipt", str(tmp_path / "r2.json"), "--manifest", str(tmp_path / "m1.json"),
             "--expect-log-key", key]
    assert main(wrong) == 1


def test_leaf_digest_covers_the_signature():
    m1 = _manifest("abc")
    assert manifest_leaf_digest(m1) != manifest_leaf_digest(replace(m1, signature="00" * 64))
