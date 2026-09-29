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

## Licensing

Apache-2.0 (see [`LICENSE`](LICENSE)). `capsule-emit` is Apache-2.0. See
[`NOTICE`](NOTICE).
