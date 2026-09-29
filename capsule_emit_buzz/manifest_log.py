# SPDX-License-Identifier: Apache-2.0
"""An append-only log of signed audit-export manifests, with inclusion and
consistency proofs, and an optional witness.

A signed manifest (``export_manifest.py``) catches a rewrite for whoever kept
it. This log adds two things on top, both checkable offline:

- **Inclusion.** Each manifest is a leaf in a Merkle Mountain Range, and each
  append produces a checkpoint signed by the log's key. A receipt proves the
  manifest is in the log at that checkpoint.
- **Consistency.** The checkpoint for a second export carries a proof that the
  log it covers extends the log at the first one. So a first manifest cannot
  be dropped or replaced later without the proof failing.

The MMR, the checkpoints and the proofs are the ``cll`` package's
(checkpointed-local-log), used as published. The log stores manifests only:
a range, a count and a final hash per export, never an entry's content.

**Witnessing is off by default.** Nothing here makes a network call on its own.
:func:`witness_receipt` is the one function that does, and only when called
with a witness URL. What it sends is the checkpoint (the log's size, a root
hash, a time and the log key), never a manifest or an entry.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from cll.checkpoint import (
    CheckpointRecord,
    ConsistencyProof,
    InclusionProof,
    MmrLedger,
    WitnessRecord,
    checkpoint_to_cose,
    emit_checkpoint,
    register_checkpoint,
    verify_checkpoint_signature_offline,
    verify_consistency,
    verify_inclusion,
    verify_witness_stamp_offline,
)

from .export_manifest import ExportError, ExportManifest

__all__ = [
    "LOG_RECEIPT_KIND",
    "LogReceipt",
    "ManifestLog",
    "manifest_leaf_digest",
    "verify_log_extends",
    "verify_log_receipt",
    "verify_witnesses",
    "witness_receipt",
]

LOG_RECEIPT_KIND = "buzz_audit_manifest_log_receipt"


def manifest_leaf_digest(manifest: ExportManifest) -> str:
    """The log leaf for a manifest: SHA-256 of the whole signed manifest
    (signature included), as JSON with sorted keys and no whitespace."""
    body = json.dumps(manifest.to_json(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Leaf:
    seq: int
    capsule_id: str


class _LeafSource:
    """The ``LogSource`` shape ``cll``'s ``MmrLedger`` indexes: gapless,
    1-indexed leaves, each named by its hex digest."""

    def __init__(self) -> None:
        self._leaves: list[_Leaf] = []

    def append(self, capsule: dict, *, consequential: bool = True) -> _Leaf:
        leaf = _Leaf(seq=len(self._leaves) + 1, capsule_id=capsule["digest"])
        self._leaves.append(leaf)
        return leaf

    def scan(self, query: Any = None) -> Iterator[_Leaf]:
        return iter(list(self._leaves))

    def fetch(self, capsule_id: str) -> Optional[_Leaf]:
        return next((leaf for leaf in self._leaves if leaf.capsule_id == capsule_id), None)

    def verify(self, capsule_id: str) -> Optional[_Leaf]:
        return self.fetch(capsule_id)

    def find_gaps(self) -> list:
        return []


class _CheckpointSigner:
    """Adapts a ``capsule_emit.signing.LocalKeypairSigner`` (``sign(bytes) ->
    (signature, key_id)``) to the checkpoint signer shape (``key_id`` plus
    ``sign(digest_hex) -> signature``): Ed25519 over the checkpoint digest's
    ASCII bytes, which is what ``verify_checkpoint_signature_offline`` checks.
    The COSE statement for a witness passes straight through."""

    def __init__(self, signer: Any) -> None:
        self._signer = signer
        self.key_id: str = signer.key_id

    def sign(self, digest_hex: str) -> str:
        signature, _key_id = self._signer.sign(digest_hex.encode("ascii"))
        return signature

    def sign_cose_statement(self, payload: bytes, **claims: Any) -> bytes:
        return self._signer.sign_cose_statement(payload, **claims)


@dataclass(frozen=True)
class LogReceipt:
    """What one append to the log proves: the manifest with this digest is
    leaf ``leaf_seq`` under ``checkpoint``, and (from the second append on)
    the log at ``checkpoint`` extends the log at the previous checkpoint."""

    manifest_digest: str
    leaf_seq: int
    checkpoint: CheckpointRecord
    inclusion: InclusionProof
    consistency: Optional[ConsistencyProof] = None
    witnesses: tuple[WitnessRecord, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "v": 1,
            "kind": LOG_RECEIPT_KIND,
            "manifest_digest": self.manifest_digest,
            "leaf_seq": self.leaf_seq,
            "checkpoint": self.checkpoint.to_dict(),
            "inclusion": asdict(self.inclusion),
            "consistency": asdict(self.consistency) if self.consistency else None,
            "witnesses": [w.to_dict() for w in self.witnesses],
        }

    @classmethod
    def from_json(cls, data: Any) -> LogReceipt:
        if not isinstance(data, dict) or data.get("v") != 1 or data.get("kind") != LOG_RECEIPT_KIND:
            raise ExportError("not a version-1 manifest log receipt")
        try:
            inc = data["inclusion"]
            inclusion = InclusionProof(
                v=inc["v"], kind=inc["kind"], size=inc["size"], leaf_index=inc["leaf_index"],
                witness=tuple(inc["witness"]), peaks_left=tuple(inc["peaks_left"]),
                peaks_right=tuple(inc["peaks_right"]),
            )
            con = data["consistency"]
            consistency = None if con is None else ConsistencyProof(
                v=con["v"], kind=con["kind"], size_a=con["size_a"], size_b=con["size_b"],
                old_peaks=tuple(con["old_peaks"]), witness=tuple(tuple(w) for w in con["witness"]),
                new_peaks=tuple(con["new_peaks"]),
            )
            return cls(
                manifest_digest=data["manifest_digest"],
                leaf_seq=data["leaf_seq"],
                checkpoint=CheckpointRecord.from_dict(data["checkpoint"]),
                inclusion=inclusion,
                consistency=consistency,
                witnesses=tuple(WitnessRecord.from_dict(w) for w in data["witnesses"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ExportError(f"malformed manifest log receipt: {exc}") from exc


class ManifestLog:
    """An append-only file of manifest leaves and the checkpoints over them.

    *signer* is a ``capsule_emit.signing.LocalKeypairSigner`` (or anything
    with its ``key_id``, ``sign`` and ``sign_cose_statement``). Its public key
    is the log key a verifier pins. The file holds one JSON object per line:
    ``{"leaf": <digest>}`` or ``{"checkpoint": {...}}``. Reopening the file
    replays it, so a second export's receipt is consistent with the first's.
    """

    def __init__(self, path: str | Path, signer: Any) -> None:
        self._path = Path(path)
        self._signer = _CheckpointSigner(signer)
        self.log_id = f"buzz-audit-manifest-log:{self._signer.key_id}"
        self._mmr = MmrLedger(_LeafSource())
        self._checkpoints: list[CheckpointRecord] = []
        if self._path.exists():
            for n, line in enumerate(self._path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if "leaf" in row:
                    self._mmr.append({"digest": row["leaf"]})
                elif "checkpoint" in row:
                    cp = CheckpointRecord.from_dict(row["checkpoint"])
                    if cp.log_id != self.log_id:
                        raise ExportError(f"line {n}: a checkpoint of another log ({cp.log_id})")
                    self._checkpoints.append(cp)
                else:
                    raise ExportError(f"line {n} of the manifest log is neither a leaf nor a checkpoint")

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    def append(self, manifest: ExportManifest, *, timestamp: str | None = None) -> LogReceipt:
        """Log a signed manifest and checkpoint the log. A manifest whose own
        signature does not verify is never logged. No network call."""
        if not manifest.verify_signature_offline():
            raise ExportError("the manifest's signature does not verify; it is not logged")
        digest = manifest_leaf_digest(manifest)
        prev = self._checkpoints[-1] if self._checkpoints else None
        self._mmr.append({"digest": digest})
        seq = self._mmr.leaf_count()
        cp = emit_checkpoint(self._mmr, self._signer, log_id=self.log_id, prev=prev, timestamp=timestamp)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"leaf": digest}) + "\n")
            fh.write(json.dumps({"checkpoint": cp.to_dict()}, sort_keys=True) + "\n")
        self._checkpoints.append(cp)
        return LogReceipt(
            manifest_digest=digest,
            leaf_seq=seq,
            checkpoint=cp,
            inclusion=self._mmr.inclusion_proof(seq, size=cp.mmr_size),
            consistency=self._mmr.consistency_proof(prev.mmr_size, cp.mmr_size) if prev else None,
        )

    def checkpoint_cose(self, cp: CheckpointRecord) -> bytes:
        """The checkpoint as the COSE_Sign1 statement a witness accepts."""
        prev_peaks = self._mmr.peak_hashes_at(cp.prev_size) if cp.prev_size else None
        consistency = self._mmr.consistency_proof(cp.prev_size, cp.mmr_size) if cp.prev_size else None
        return checkpoint_to_cose(
            cp, self._signer, self._mmr.peak_hashes_at(cp.mmr_size),
            prev_peak_hashes=prev_peaks, consistency_proof=consistency,
        )


def witness_receipt(
    log: ManifestLog,
    receipt: LogReceipt,
    ts_url: str,
    *,
    register: Callable[[bytes, str], WitnessRecord] = register_checkpoint,
) -> LogReceipt:
    """Send *receipt*'s checkpoint to the witness at *ts_url* and return the
    receipt with the witness's record added. **This is the only network call
    in this module, and it happens only when this function is called.** Only
    the checkpoint is sent. *register* is the transport (``cll``'s
    ``register_checkpoint`` by default)."""
    record = register(log.checkpoint_cose(receipt.checkpoint), ts_url)
    return replace(receipt, witnesses=receipt.witnesses + (record,))


def verify_log_receipt(receipt: LogReceipt, manifest: ExportManifest, *, expected_log_key: str) -> None:
    """Raise unless *receipt* proves *manifest* is in the log at its
    checkpoint, and that checkpoint is signed by the pinned log key. Offline.
    As with the manifest itself, the pin is what makes it the operator's log."""
    cp = receipt.checkpoint
    if not verify_checkpoint_signature_offline(cp):
        raise ExportError("the log checkpoint's signature does not verify")
    if cp.key_id != expected_log_key.strip().lower():
        raise ExportError("the log checkpoint is signed by a key other than the pinned log key")
    if manifest_leaf_digest(manifest) != receipt.manifest_digest:
        raise ExportError("the receipt is for a different manifest")
    index = receipt.leaf_seq - 1
    proof = receipt.inclusion
    if proof.size != cp.mmr_size or proof.leaf_index != index:
        raise ExportError("the inclusion proof is not for this leaf at this checkpoint")
    if not verify_inclusion(bytes.fromhex(cp.root), cp.mmr_size, index, bytes.fromhex(receipt.manifest_digest), proof):
        raise ExportError("the manifest is not included in the log at this checkpoint")


def verify_log_extends(earlier: LogReceipt, later: LogReceipt) -> None:
    """Raise unless the log at *later*'s checkpoint extends the log at
    *earlier*'s: same log, the next checkpoint, and a consistency proof that
    verifies. A log from which the earlier manifest was dropped or replaced
    fails here. Offline."""
    a, b = earlier.checkpoint, later.checkpoint
    if a.log_id != b.log_id:
        raise ExportError("the two receipts are from different logs")
    if b.prev_size != a.mmr_size or b.prev_root != a.root:
        raise ExportError("the later checkpoint does not follow the earlier one")
    proof = later.consistency
    if proof is None or (proof.size_a, proof.size_b) != (a.mmr_size, b.mmr_size):
        raise ExportError("the later receipt has no consistency proof from the earlier checkpoint")
    if not verify_consistency(bytes.fromhex(a.root), a.mmr_size, bytes.fromhex(b.root), b.mmr_size, proof):
        raise ExportError("the later log does not extend the earlier one")


def verify_witnesses(receipt: LogReceipt, *, ts_pubkey_pem: bytes | str | None = None) -> list[tuple[str, bool, list[str]]]:
    """Each witness record on *receipt*, checked offline against its
    checkpoint: ``(ts_url, ok, reasons)``. An empty list means the receipt was
    never witnessed, which is the default."""
    results = []
    for record in receipt.witnesses:
        ok, reasons = verify_witness_stamp_offline(receipt.checkpoint, record, ts_pubkey_pem=ts_pubkey_pem)
        results.append((record.ts_url, ok, reasons))
    return results


def main(argv: list[str] | None = None) -> int:
    """``append``: log a signed manifest and write its receipt. No network
    call unless ``--witness URL`` is given. ``verify``: check a receipt
    offline against its manifest and the pinned log key, and optionally that
    it extends an earlier receipt."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="capsule-emit-buzz-log", description=main.__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("append", help="log a signed manifest and write its receipt")
    a.add_argument("--manifest", required=True)
    a.add_argument("--log", required=True, help="the log file (created if missing)")
    a.add_argument("--log-key", required=True, help="the log's Ed25519 key, PEM (created if missing)")
    a.add_argument("--out", required=True, help="where to write the receipt")
    a.add_argument(
        "--witness", metavar="URL",
        help="also send the checkpoint (never the manifest) to this witness. Off unless given",
    )
    v = sub.add_parser("verify", help="check a receipt offline")
    v.add_argument("--receipt", required=True)
    v.add_argument("--manifest", required=True)
    v.add_argument("--expect-log-key", required=True, help="the log's public key (hex), pinned")
    v.add_argument("--earlier", help="an earlier receipt from the same log that this one must extend")
    v.add_argument("--witness-key", help="a witness's public key (PEM file) to check its receipt under")
    args = parser.parse_args(argv)

    try:
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = ExportManifest.from_json(json.load(fh))
        if args.command == "append":
            from capsule_emit.signing import LocalKeypairSigner

            created = not Path(args.log_key).exists()
            log = ManifestLog(args.log, LocalKeypairSigner(args.log_key))
            receipt = log.append(manifest)
            if args.witness:
                receipt = witness_receipt(log, receipt, args.witness)
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(receipt.to_json(), fh, indent=2)
                fh.write("\n")
            print(f"logged as leaf {receipt.leaf_seq}; checkpoint size {receipt.checkpoint.mmr_size}; "
                  f"log key {log.key_id}{' (created)' if created else ''}; "
                  f"{'witnessed by ' + args.witness if args.witness else 'not witnessed'}")
        else:
            with open(args.receipt, encoding="utf-8") as fh:
                receipt = LogReceipt.from_json(json.load(fh))
            verify_log_receipt(receipt, manifest, expected_log_key=args.expect_log_key)
            print(f"ok: the manifest is leaf {receipt.leaf_seq} of the log at size {receipt.checkpoint.mmr_size}, "
                  "signed by the pinned log key")
            if args.earlier:
                with open(args.earlier, encoding="utf-8") as fh:
                    verify_log_extends(LogReceipt.from_json(json.load(fh)), receipt)
                print("ok: the log extends the earlier receipt's log")
            pem = Path(args.witness_key).read_bytes() if args.witness_key else None
            results = verify_witnesses(receipt, ts_pubkey_pem=pem)
            for url, ok, reasons in results:
                print(f"witness {url}: {'ok' if ok else 'NOT verified: ' + '; '.join(reasons)}")
            if any(not ok for _url, ok, _reasons in results):
                return 1
    except (ExportError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
