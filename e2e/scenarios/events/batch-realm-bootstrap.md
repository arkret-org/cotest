# Events Submit Batch Realm Bootstrap

## Intent

Prove the registered Realm genesis transaction is authored without a synthetic
frontier for a not-yet-created Realm and establishes the exact actor chain used
by subsequent owner writes.

## Strand

1. Register Alice and issue a dev session.
2. Confirm combined `(realm_id, actor_id)` frontier lookup returns `not_found`
   before the Realm exists.
3. Submit the complete registered founding unit: `ak.realm.create`, profile,
   policy bundle, join rule, history visibility, discovery, conditional
   plaintext-visible services, delivery binding policy, and creator membership. The create
   object carries the create-locked `capability_action_registry_digest`; v1 has
   **no** founding `ak.capability.grant` slot.
4. Query accepted history and assert every registered slot forms one exact
   `actor_seq / prev_refs` chain, with no `ak.capability.grant` at all.
5. Resubmit a byte-identical clone of the signed unit. Assert every Event is a
   duplicate, every ingress receipt is byte-identical to the stored first receipt,
   and accepted history still contains each Event exactly once.
6. Query the combined frontier and assert its next sequence and only head are
   the complete unit's creator-membership tail.
7. Submit `ak.message.create` as Alice and assert it continues from that tail.

## Acceptance

- A producer does not need, synthesize, or infer an empty remote frontier for a
  not-yet-created Realm.
- Realm bootstrap is the atomic `ak.realm.create` + closed follow-up facet unit
  required by spec; the creator's root authority is the
  `ak.component.realm.authority_root.v1` cell the create Event's registered
  reducer contract writes, never a self-issued genesis grant.
- The create object's `capability_action_registry_digest` is the basis the
  reducer seeds that cell with, so it MUST equal the SDK's current digest.
- The owner write immediately continues the exact accepted bootstrap chain.
- An exact retry returns the original receipts and creates no second Event or
  Realm-side state transition.
- The scenario is tagged `@fully-implemented` so `joint-smoke` covers it.
