# capsule-emit-buzz

Buzz-side **event → EvidenceRecord** adapter and parity fixtures.
Apache-2.0.

**An independent connector.** It is not made, endorsed or supported by the
[Buzz](https://github.com/block/buzz) project, its maintainers, or Block, and
this repository claims no affiliation with them. It reads Buzz's public event
format and changes nothing in Buzz.

This repository turns an observed **Buzz** event (a signed Nostr event) into an
EvidenceRecord subject, keeping the event's transport id distinct from its
content digest, and derives the host principal from the event's Nostr public
key. It implements the neutral **`ConnectorPort`** contract published by
[capsule-emit](https://github.com/action-state-group/capsule-emit) — it consumes
that substrate, it does not fork or extend it.

```
python -m pytest              # verification, the distinct-id / round-trip tests
python fixtures/gen_fixtures.py   # regenerate the two-language parity fixtures
( cd parity/go && go test ./... ) # Go asserts the same fixtures byte-for-byte
```

## What it is

- A `ConnectorPort` implementation, `BuzzConnector`:
  - `classify(event) -> observation | effect` — a **moderation decision** and a
    **release going live** are *effects*; **agent-job progress** is an
    *observation*. The decision runs through capsule-emit's own
    `classify_signal_1`, so Signal-1 semantics are identical to every other
    adapter.
  - `capture(event) -> received()` — a Buzz event we observed is a **foreign,
    already-signed artifact** (the Nostr author signed it before we saw it), so
    it is `received()` (a carry), **never `seal()`**. Sealing would falsely
    claim this operator authored content someone else signed. Before anything
    is logged, the event's exact JSON is verified as a signed NIP-01 event:
    its `id` must be the hash of its serialization, and its BIP-340 signature
    must verify under its `pubkey` (coincurve, over libsecp256k1). An
    unsigned or altered event raises `NostrEventError` (a reason code, never
    the content) and nothing is logged.
  - declared **boundary class `listener`** — a passive tap on Buzz's event
    stream, not a gateway, decorator, or engine.
- The **host principal** is derived from the event's Nostr pubkey via the
  `nostr-pubkey` host-principal profile: `principal_ref = "nostr-pubkey:<hex>"`.
  An optional **relay hint** is carried separately and is purely informational.
- The **subject** is `{event_id, semantic_digest}` — two separate fields
  (see below).
- **Round-trip**: a record subject projects back to the Buzz-event shape
  (`event_id`, `pubkey`, optional `relay_hint`), byte-identical on the fields the
  event owns.
- **Two-language parity fixtures**: Python (reference) generates them; **Go**
  asserts the same files. See [`fixtures/REGISTRY.md`](fixtures/REGISTRY.md).

## How it consumes capsule-emit's `ConnectorPort`

`ConnectorPort` is a runtime-checkable `typing.Protocol` in
`capsule_emit.connector`. `BuzzConnector` conforms by *having* the members —
`boundary_class`, `classify()`, `capture()` — exactly as the two in-tree
capsule-emit adapters (`MCPCapsuleEmitter`, `LangChainCapsuleListener`) do,
without inheriting from a base class. `capture()` dispatches through
capsule-emit's `received()` under surface.py's foreign-bytes rule. This
repository adds **no** capsule-emit primitive of its own; it maps Buzz events
onto the neutral one.

## The one invariant: `event_id` != `semantic_digest`

`event_id` is the **Nostr event id**: the hash of the event's NIP-01
serialization, which its author signed. `semantic_digest` is the **SHA-256 of
the full signed event exactly as received**, and the carried artifact is those
same bytes. They are **two separate fields and are never conflated**. Each
record also names its event: `{event_id, pubkey, semantic_digest}` under
`buzz_event` in the record body.

The digest is bound to one event. Two events with the same text have different
ids and different digests; the same event received twice has the same digest.
(The `buzz.*` profile drafts describe `semantic_digest` as the content identity
of the payload; this connector binds it to the full event for the reason in
the next section. This is provisional until those profiles settle it.)

## No message text is stored

A record never holds an event's text, and it never holds a bare hash of the
text either. A bare `sha256(text)` of a short message ("yes", "approved") could
be confirmed by hashing guessed texts. The record's digest covers the whole
signed event: its id, signature, author, time, tags and text. So the record
alone doesn't confirm a guessed text. Linking a record to its text takes the
event itself.

## Boundary (this is neutral, donatable OSS)

- **Digests only.** No record stores message text, moderated content, job
  output, or release-note prose (see *No message text is stored*).
- **No per-user history.** Nothing aggregates a principal's activity across
  records.
- **No score or rating field**, anywhere.
- **Key control is not authority.** The `nostr-pubkey` principal records *who
  signed*, never what they were entitled to do; authority-context bindings are
  host-managed and never inferred from the key.
- **Profiles are consumed, not defined here.** The `nostr-pubkey` host-principal
  profile and the `buzz.agent-job/v1`, `buzz.moderation/v1`, `buzz.release/v1`
  Evidence Contract profiles belong to
  [capsule-registry](https://github.com/action-state-group/capsule-registry) /
  [agent-action-capsule](https://github.com/action-state-group/agent-action-capsule).
  This repo only references their names.
- **No Buzz code is modified.** This repository only observes and adapts Buzz
  events; it changes nothing upstream.
- "Buzz" is used only as a public project name. A fail-closed neutrality
  gate (`.github/workflows/neutrality.yml`) checks this repository's
  vocabulary at CI.

## Witnessing

`BuzzConnector(..., witness=None)` follows capsule-emit's default: witnessing
is on, pointed at the public witness. What leaves the process is a signed
checkpoint of this connector's log (its size, a root hash and a time), never a
record's content. It goes once 100 records have accumulated or 900 seconds have
passed. Turn it off with `witness=False`, or `CAPSULE_WITNESS=off` in the
environment.

## Signed audit-export manifest (a sidecar for a proposed export)

**Independent, and about a proposal.** This part of the repository proposes a
signed-manifest format for the audit export discussed in
[block/buzz#3228](https://github.com/block/buzz/issues/3228). That issue is an
open proposal. **Nothing in it is merged into Buzz, and Buzz has no such export
today.** Everything below works on an export file in the shape #3228 proposes.
It is not made or endorsed by the Buzz project, and no Buzz code is copied here:
the only Buzz-derived material is a test vector.

Buzz keeps a per-community, append-only hash chain of audit entries. The chain
is tamper-evident but keyless: someone with write access to its database can
rewrite an entry and recompute every later hash, and the rewritten chain still
checks out. `capsule_emit_buzz.export_manifest` signs a small manifest over an
export of that chain with a key that never lives in the database. A later
export of the same range that was rewritten keeps its links but no longer
matches the signed final hash.

```
capsule-emit-buzz-export sign --export entries.jsonl --community-id <uuid> \
    --key-file signing-key.hex --out manifest.json
capsule-emit-buzz-export verify --manifest manifest.json --export entries.jsonl \
    --expect-key <the operator's public key, hex>
```

- **The pinned key is the security property.** Anyone can sign a manifest for
  a rewritten export with a fresh key, and that signature verifies too. What
  ties an export to the operator is a manifest signed by the operator's key,
  checked against that key pinned by whoever verifies. `verify` without
  `--expect-key` reports "signature valid under an UNPINNED key" and exits 3,
  never 0.
- The input is the export #3228 proposes: one JSON entry per line, with `seq`,
  `hash` and `prev_hash` hex-encoded. It needs no access to Buzz's database and
  changes nothing in Buzz.
- The manifest is the `buzz_audit_export_manifest` version-1 format proposed
  for #3228. `tests/vectors/` holds a manifest signed outside this repository
  with a public test key: it verifies here, and this signer reproduces it byte
  for byte.
- The manifest records the range, the entry count and the final hash only. No
  entry's content, actor or detail is copied into it.
- The export's links are checked (`prev_hash` and `seq`), and its final hash
  is compared with the signed one. **Entry hashes are not recomputed here.** An
  edit that leaves the stored hashes as they were (so the hash no longer
  matches the entry) is for Buzz's own chain verifier to catch. This tool
  catches the other case: an edit with every hash recomputed.
- The signing key is read from `--key-file` or `BUZZ_AUDIT_SIGNING_KEY` (a
  32-byte seed, hex) and is never printed or written.

### What this adds to #3228

#3228 proposes an export that anyone can check link by link. That check can't
catch a rewrite by someone who can write the database, because they can
recompute every hash. This adds four things:

1. **A signature from a key outside the database.** The operator signs each
   export's range and final hash. A rewrite made after that no longer matches,
   even with every hash recomputed. Whoever checks pins the operator's public
   key.
2. **A check between two exports.** `verify_extends` takes an earlier signed
   manifest and a later export. It passes only if the later export still has
   the earlier final hash at the same `seq`, or starts right after it and links
   to it. So the second export exposes a rewrite of the range the first one
   covered.
3. **A log of manifests, with proofs.** `capsule-emit-buzz-log append` adds
   each signed manifest to an append-only log and signs a checkpoint. The
   receipt proves the manifest is in the log (inclusion). The second receipt
   also proves the log extends the first one (consistency), so an earlier
   manifest can't be dropped or swapped later. The log, checkpoints and proofs
   come from [`cll`](https://github.com/action-state-group/checkpointed-local-log),
   used as published.
4. **An optional witness, off by default.** `--witness URL` sends the log's
   checkpoint (its size, a root hash, a time and the log key) to a witness and
   stores the witness's receipt. It never sends a manifest or an entry.
   Without `--witness`, nothing leaves the machine.

See it caught, offline:

```
python -m capsule_emit_buzz.rewrite_demo
```

The demo keeps a keyless hash chain in SQLite. It exports three entries,
signs and logs the manifest, then rewrites entry 2 in the database and
recomputes every later hash. The keyless check still passes. A second export
is signed and logged, and the log is consistent. The first manifest, checked
against the second export, catches the rewrite. The demo's table and hash are
stand-ins written for it, not Buzz's schema or hash.
`tests/test_rewrite_demo.py` runs the same steps, and a control without the
rewrite passes.

```
capsule-emit-buzz-log append --manifest m2.json --log manifests.jsonl \
    --log-key log-key.pem --out r2.json            # add --witness URL to opt in
capsule-emit-buzz-log verify --receipt r2.json --manifest m2.json \
    --expect-log-key <the log's public key, hex> --earlier r1.json
```

No test uses the network. Every test runs with sockets blocked. The witness
tests use a local test key that mints real COSE Receipts, and they pass it in
as the transport.

## Licensing

Apache-2.0 (see [`LICENSE`](LICENSE)). `capsule-emit` is Apache-2.0. See
[`NOTICE`](NOTICE).
