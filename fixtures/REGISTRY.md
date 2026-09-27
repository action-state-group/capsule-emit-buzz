# Fixtures — provenance and parity

These fixtures are the contract between the two language implementations in this
repository: **Python is the reference**, and the **Go** parity harness
(`parity/go/`) asserts byte-for-byte-equal results against the same files. Go
was chosen to match the sibling adapter `capsule-emit-dapr`, which is a Go repo.

## Layout

```
fixtures/
  gen_fixtures.py          Python reference generator (source of record files)
  events/<name>.json       input Buzz (Nostr) events
  records/<name>.json      expected EvidenceRecord subject the reference derives
  REGISTRY.md              this file
```

## Regenerating

```
python fixtures/gen_fixtures.py     # rewrites events/ and records/
```

The record files are **generated, never hand-edited**. To change a fixture,
change `gen_fixtures.py` and regenerate, so Python and Go can never silently
disagree about what the reference produces.

## What each fixture proves

Positives (one per Buzz profile; profiles are OWNED by capsule-registry /
agent-action-capsule, only NAMED here):

| name        | profile             | classification | shows |
|-------------|---------------------|----------------|-------|
| agent_job   | `buzz.agent-job/v1` | observation    | distinct `event_id` + `semantic_digest`; optional relay hint carried separately |
| moderation  | `buzz.moderation/v1`| effect         | a moderation decision is an effect; content digested, never stored |
| release     | `buzz.release/v1`   | effect         | a release going live is an effect |

Negatives (`records/neg_*.json`) — inputs a conforming validator MUST reject.
They are stored as rejection reasons (they cannot be *derived* records):

| name                    | rejected because |
|-------------------------|------------------|
| neg_event_id_as_digest  | `event_id` reused as `semantic_digest` (two fields collapsed) |
| neg_message_text_present| a record field carried message text (records are digests only) |
| neg_score_present       | a record field carried a score value (none allowed) |

## Boundary the fixtures observe

- **Digests only.** No fixture record carries message text, moderated content,
  job output, or release-note prose. Content appears only in the *event* inputs,
  as `content_hex` (exact bytes to digest), and is never copied onto a record.
- **`event_id` != `semantic_digest`.** Two distinct fields on every subject.
- **No per-user history, no scores.** No field aggregates across events; no
  numeric score or rating field exists.

## Profile provenance

The profile names above and the `nostr-pubkey` host-principal profile are
owned by capsule-registry. Every profile uses the same subject shape,
`{event_id, semantic_digest}` — there are no per-profile digest field names;
the profile id carries "what kind". The effect kind numbers (`30078`/`30079`)
and the foreign CPB type string in the adapter are provisional until those
profiles register values; they are re-pointed here when they do.
