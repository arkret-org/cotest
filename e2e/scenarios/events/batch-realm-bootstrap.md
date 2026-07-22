# Events Submit Batch Realm Bootstrap

## Intent

Prove the registered Realm genesis transaction is authored without a synthetic
frontier for a not-yet-created Realm and establishes the exact actor chain used
by subsequent owner writes.

## Strand

1. Register Alice and issue a dev session.
2. Confirm combined `(realm_id, actor_id)` frontier lookup returns `not_found`
   before the Realm exists.
3. Submit the registered `[ak.realm.create, ak.capability.grant]` founding unit.
4. Query accepted history and assert the chain is `0/[] -> 1/[create_id]`.
5. Query the combined frontier and assert `next_actor_seq=2` with the founding
   grant as its only head.
6. Submit `ak.message.create` as Alice and assert it authors as
   `2/[founding_grant_id]`.

## Acceptance

- A producer does not need, synthesize, or infer an empty remote frontier for a
  not-yet-created Realm.
- Realm bootstrap is the atomic create + founding-grant unit required by spec.
- The owner write immediately continues the exact accepted bootstrap chain.
- The scenario is tagged `@fully-implemented` so `joint-smoke` covers it.
