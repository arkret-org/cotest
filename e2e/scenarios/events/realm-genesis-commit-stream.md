# Realm Genesis Commit Stream

## Intent

Prove that Realm genesis is ordered by the governance Station's commit stream
and by nothing the producer authors. Replaces the retired
`events/batch-realm-bootstrap` scenario, whose entire subject — the
`(realm_id, actor_id)` authoring frontier and the client-side batch that
extended it — the authority-commit protocol deleted.

## Strand

1. Register Alice and issue a dev session.
2. Confirm the retired producer-frontier surface no longer answers: a producer
   must not be able to read, synthesize or extend an authoring frontier.
3. Create a Realm. Each founding Event — `ak.realm.create`, profile, policy
   bundle, conditional plaintext-visible services, creator membership — is
   submitted on its own and answered with the `RealmCommit` that admitted it.
4. Scan the Realm's own stream and assert the commits occupy positions
   `0..n-1`, each naming its predecessor commit and the exact Event it admits,
   all inside `CommitStreamRef::Realm` for this Realm. There is no
   Realm-global chain and no Realm-global position to compare against.
5. Assert every accepted producer Event carries none of the retired envelope
   members (`actor_seq`, `prev_refs`, `preconditions`, `hlc`, `seal_ref`,
   `cell_writes`, `basis`).
6. Assert the genesis payload is the closed `realm-genesis.schema.json` object:
   display and visibility facets are separate Events, and v1 has no founding
   `ak.capability.grant` slot at all.
7. Resubmit a byte-identical clone of the genesis Event. Assert the Station
   answers `duplicate` with the original commit and the stream is unchanged.
8. Resolve the absent default discussion Strand through the normal helper.
   Assert `ak.strand.create`, `ak.realm.set_default_strand` and
   `ak.message.create` continue the same Realm stream with no gap.

## Acceptance

- A producer Event carries no position, predecessor, precondition or coverage;
  the `RealmCommit` supplies all ordering.
- The founding unit is a contiguous prefix of one Realm stream, not a batch
  admitted as a unit by the client.
- An exact retry is a `duplicate` that replays the original commit and consumes
  no second stream position.
- Ordinary writes continue the same stream; no second ordering authority
  (actor frontier, Seal, CBS basis) is consulted anywhere in the strand.
- The scenario is tagged `@fully-implemented` so `joint-smoke` covers it.
