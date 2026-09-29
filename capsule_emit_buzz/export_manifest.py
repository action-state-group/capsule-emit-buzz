# SPDX-License-Identifier: Apache-2.0
"""A signed manifest for an export of Buzz's community audit chain, made and
checked outside Buzz.

Buzz keeps a per-community, append-only hash chain of audit entries. The chain
is tamper-evident but keyless: someone with write access to the database can
rewrite an entry and recompute every later hash, and the rewritten chain still
checks out. A manifest signed with an operator-held key that never lives in the
database closes that gap for anyone who saved it: a later export of the same
range that was rewritten no longer matches the signed final hash.

This module signs and verifies such manifests from an existing export (one
JSON object per entry, as Buzz's operator export writes them: ``seq``,
``hash``, ``prev_hash``, ... with byte fields hex-encoded). It changes nothing
in Buzz and needs no access to its database.

The manifest format is the one proposed for Buzz's own audit export
(``buzz_audit_export_manifest``, version 1), byte-compatible in both
directions:

- the signed body is every field but ``signature``, as JSON with sorted keys
  and no whitespace;
- the signature is Ed25519 over the ASCII bytes of that body's SHA-256 hex
  digest;
- ``exporter_key_id`` is the raw Ed25519 public key, hex, inside the signed
  body, so a verifier needs no key lookup and a manifest cannot be re-labelled
  under another key.

What it checks about the export itself is the linkage: each entry's
``prev_hash`` is the previous entry's ``hash``, and ``seq`` counts up by one.
Recomputing each entry's hash stays with Buzz's own chain verifier.

Only the range and the final hash are ever written: no entry's content, actor
or detail is copied into the manifest.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

__all__ = [
    "MANIFEST_KIND",
    "MANIFEST_VERSION",
    "ExportError",
    "ExportManifest",
    "check_links",
    "load_export",
    "sign_manifest",
    "signing_key_from_hex",
    "unsigned_manifest",
    "verify_against_export",
]

MANIFEST_KIND = "buzz_audit_export_manifest"
MANIFEST_VERSION = 1

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ExportError(ValueError):
    """The export or the manifest is malformed, or they do not agree."""


@dataclass(frozen=True)
class ExportManifest:
    v: int
    kind: str
    community_id: str
    from_seq: int
    to_seq: int
    entry_count: int
    final_hash: str
    #: Kept exactly as written, so a manifest made elsewhere re-verifies
    #: byte-for-byte (a fractional-second time stays fractional).
    exported_at: str
    exporter_key_id: str = ""
    signature: str = ""

    def signing_body(self) -> str:
        fields = {
            "v": self.v,
            "kind": self.kind,
            "community_id": self.community_id,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "entry_count": self.entry_count,
            "final_hash": self.final_hash,
            "exported_at": self.exported_at,
            "exporter_key_id": self.exporter_key_id,
        }
        return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def digest_hex(self) -> str:
        return hashlib.sha256(self.signing_body().encode("utf-8")).hexdigest()

    def verify_signature_offline(self) -> bool:
        """True when ``signature`` is the ``exporter_key_id`` key's signature
        over this manifest. Never raises on malformed fields."""
        try:
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.exporter_key_id))
            signature = bytes.fromhex(self.signature)
            if len(signature) != 64:
                return False
            key.verify(signature, self.digest_hex().encode("ascii"))
            return True
        except (ValueError, InvalidSignature):
            return False

    def to_json(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "kind": self.kind,
            "community_id": self.community_id,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "entry_count": self.entry_count,
            "final_hash": self.final_hash,
            "exported_at": self.exported_at,
            "exporter_key_id": self.exporter_key_id,
            "signature": self.signature,
        }

    @classmethod
    def from_json(cls, data: Any) -> ExportManifest:
        if not isinstance(data, dict):
            raise ExportError("a manifest is a JSON object")
        want = {"v", "kind", "community_id", "from_seq", "to_seq", "entry_count", "final_hash",
                "exported_at", "exporter_key_id", "signature"}
        if set(data) != want:
            raise ExportError(f"manifest fields differ: missing {sorted(want - set(data))}, extra {sorted(set(data) - want)}")
        ints = ("v", "from_seq", "to_seq", "entry_count")
        if any(isinstance(data[k], bool) or not isinstance(data[k], int) for k in ints):
            raise ExportError("v, from_seq, to_seq and entry_count are integers")
        if any(not isinstance(data[k], str) for k in want - set(ints)):
            raise ExportError("the other manifest fields are strings")
        if data["v"] != MANIFEST_VERSION or data["kind"] != MANIFEST_KIND:
            raise ExportError("not a version-1 audit export manifest")
        return cls(**data)


def signing_key_from_hex(seed_hex: str) -> Ed25519PrivateKey:
    """The Ed25519 key for a 32-byte seed given as hex (the form Buzz's own
    export takes its signing key in)."""
    seed = bytes.fromhex(seed_hex.strip())
    if len(seed) != 32:
        raise ExportError("a signing key is 32 bytes of hex")
    return Ed25519PrivateKey.from_private_bytes(seed)


def load_export(lines: Iterable[str]) -> list[dict[str, Any]]:
    """The entries of an export, one JSON object per line."""
    entries = []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ExportError(f"line {n} is not JSON") from exc
        if not isinstance(entry, dict):
            raise ExportError(f"line {n} is not an entry")
        seq, h, prev = entry.get("seq"), entry.get("hash"), entry.get("prev_hash")
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise ExportError(f"line {n}: seq is not an integer")
        if not isinstance(h, str) or not _HEX64.match(h):
            raise ExportError(f"line {n}: hash is not 64 lowercase hex")
        if prev is not None and (not isinstance(prev, str) or not _HEX64.match(prev)):
            raise ExportError(f"line {n}: prev_hash is not 64 lowercase hex or null")
        entries.append(entry)
    if not entries:
        raise ExportError("the export has no entries")
    return entries


def check_links(entries: list[dict[str, Any]]) -> None:
    """Raise unless ``seq`` counts up by one and each ``prev_hash`` is the
    previous entry's ``hash``."""
    for before, after in zip(entries, entries[1:]):
        if after["seq"] != before["seq"] + 1:
            raise ExportError(f"seq {after['seq']} does not follow {before['seq']}")
        if after["prev_hash"] != before["hash"]:
            raise ExportError(f"entry {after['seq']} does not link to entry {before['seq']}")


def unsigned_manifest(community_id: str, entries: list[dict[str, Any]], exported_at: datetime | None = None) -> ExportManifest:
    """The manifest for *entries*, not yet signed. The links are checked first:
    a broken export is never signed."""
    check_links(entries)
    community = str(uuid.UUID(community_id))
    when = (exported_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return ExportManifest(
        v=MANIFEST_VERSION,
        kind=MANIFEST_KIND,
        community_id=community,
        from_seq=entries[0]["seq"],
        to_seq=entries[-1]["seq"],
        entry_count=len(entries),
        final_hash=entries[-1]["hash"],
        exported_at=when.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def sign_manifest(manifest: ExportManifest, key: Ed25519PrivateKey) -> ExportManifest:
    key_id = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    unsigned = replace(manifest, exporter_key_id=key_id, signature="")
    signature = key.sign(unsigned.digest_hex().encode("ascii"))
    return replace(unsigned, signature=signature.hex())


def verify_against_export(manifest: ExportManifest, entries: list[dict[str, Any]]) -> None:
    """Raise unless *manifest* is validly signed and describes *entries*: the
    same range, count and final hash, over an export whose links hold. A range
    that was rewritten and recomputed after the manifest was signed passes the
    link check but fails the final-hash comparison."""
    if not manifest.verify_signature_offline():
        raise ExportError("the manifest's signature does not verify")
    check_links(entries)
    by_seq = {e["seq"]: e for e in entries}
    in_range = [e for e in entries if manifest.from_seq <= e["seq"] <= manifest.to_seq]
    if len(in_range) != manifest.entry_count or manifest.to_seq not in by_seq:
        raise ExportError("the export does not cover the manifest's range")
    if by_seq[manifest.to_seq]["hash"] != manifest.final_hash:
        raise ExportError("the chain at to_seq no longer has the signed final hash")


def main(argv: list[str] | None = None) -> int:
    """``sign``: write a signed manifest for an export. ``verify``: check a
    manifest's signature and that an export still matches it. The signing key
    is read from ``--key-file`` or ``BUZZ_AUDIT_SIGNING_KEY`` (32-byte seed,
    hex) and never printed."""
    import argparse
    import os
    import sys

    parser = argparse.ArgumentParser(prog="capsule-emit-buzz-export", description=main.__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sign", help="write a signed manifest for an export")
    s.add_argument("--export", required=True, help="the export: one JSON entry per line")
    s.add_argument("--community-id", required=True, help="the community the export belongs to (UUID)")
    s.add_argument("--key-file", help="file holding the signing key seed (hex); else BUZZ_AUDIT_SIGNING_KEY")
    s.add_argument("--out", required=True, help="where to write the manifest")
    v = sub.add_parser("verify", help="check a manifest against an export")
    v.add_argument("--manifest", required=True)
    v.add_argument("--export", required=True)
    args = parser.parse_args(argv)

    try:
        with open(args.export, encoding="utf-8") as fh:
            entries = load_export(fh)
        if args.command == "sign":
            if args.key_file:
                with open(args.key_file, encoding="ascii") as fh:
                    seed = fh.read()
            else:
                seed = os.environ.get("BUZZ_AUDIT_SIGNING_KEY", "")
            if not seed.strip():
                raise ExportError("no signing key: pass --key-file or set BUZZ_AUDIT_SIGNING_KEY")
            manifest = sign_manifest(unsigned_manifest(args.community_id, entries), signing_key_from_hex(seed))
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(manifest.to_json(), fh, indent=2)
                fh.write("\n")
            print(f"signed seq {manifest.from_seq}..{manifest.to_seq} ({manifest.entry_count} entries), "
                  f"final hash {manifest.final_hash}, key {manifest.exporter_key_id}")
        else:
            with open(args.manifest, encoding="utf-8") as fh:
                manifest = ExportManifest.from_json(json.load(fh))
            verify_against_export(manifest, entries)
            print(f"ok: signed by {manifest.exporter_key_id}; seq {manifest.from_seq}..{manifest.to_seq} unchanged")
    except (ExportError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
