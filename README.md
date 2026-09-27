# capsule-emit-buzz

Buzz-side **event → EvidenceRecord** adapter and parity fixtures.
Apache-2.0.

This repository turns an observed **Buzz** event (a signed Nostr event) into an
EvidenceRecord subject, keeping the event's transport id distinct from its
content digest, and derives the host principal from the event's Nostr public
key. It implements the neutral **`ConnectorPort`** contract published by
[capsule-emit](https://github.com/action-state-group/capsule-emit) — it consumes
that substrate, it does not fork or extend it.

```
python -m pytest              # Python reference + the distinct-id / round-trip tests
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
    claim this operator authored content someone else signed.
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

`event_id` is the **Nostr transport reference** — a specific transmission, not
recomputable from bytes. `semantic_digest` is the **content digest** —
recomputable, identical for identical content. They are **two separate fields
and are never conflated**. The proof is a real test: two events with identical
content and different ids produce **different** records with the **same**
semantic digest (`tests/test_distinct_id_same_digest.py`).

## Boundary (this is neutral, donatable OSS)

- **Digests only.** No record stores message text, moderated content, job
  output, or release-note prose. Every content reference is a digest.
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

## Licensing

Apache-2.0 (see [`LICENSE`](LICENSE)). `capsule-emit` is Apache-2.0. See
[`NOTICE`](NOTICE).
