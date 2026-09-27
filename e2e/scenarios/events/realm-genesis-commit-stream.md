# Realm Genesis Commit Stream

## Intent

Prove that Realm genesis is ordered by the governance Station's commit stream
and by nothing the producer authors. Replaces the retired
`events/batch-realm-bootstrap` scenario, whose entire subject — the
`(realm_id, actor_id)` authoring frontier and the client-side batch that
extended it — the authority-commit protocol deleted.

## Strand

1. Register Alice and issue a dev session.
2. Create a Realm through one `ordinary_realm_bootstrap` self-submit unit with
   a UUIDv7 idempotency key. Its ordered slots are create, profile, policy
   bundle, join rule, history access, discovery, conditional plaintext-visible
   services, and creator membership. The optional alias retains registry order.
3. Require an indivisible accepted outcome containing one RealmCommit for each
   submitted Event; no standalone founding write or partial acceptance counts.
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
7. Resubmit the byte-identical complete unit with the same idempotency key.
   Assert `duplicate` with the original ordered commits and no stream changes.
8. Resolve the absent default discussion Strand through the normal helper.
   Assert `ak.strand.create`, `ak.realm.set_default_strand` and
   `ak.message.create` continue the same Realm stream with no gap.

## Acceptance

- A producer Event carries no position, predecessor, precondition or coverage;
  the `RealmCommit` supplies all ordering.
- The registered founding unit is accepted atomically as a contiguous prefix
  of one Realm stream, with an individual Commit per Event.
- An exact unit retry is a `duplicate` that replays the original commits and consumes
  no second stream position.
- Ordinary writes continue the same stream; no second ordering authority
  (actor frontier, Seal, CBS basis) is consulted anywhere in the strand.
- The scenario is tagged `@fully-implemented` so `joint-smoke` covers it.
