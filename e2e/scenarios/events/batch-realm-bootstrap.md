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
   plaintext-visible services, delivery binding policy, and creator membership. v1 has
   **no** founding `ak.capability.grant` slot.
4. Query accepted history and assert every registered slot forms one exact
   `actor_seq / prev_refs` chain, with no `ak.capability.grant` at all.
5. Resubmit a byte-identical clone of the signed unit. Assert every Event is a
   duplicate, every ingress receipt is byte-identical to the stored first receipt,
   and accepted history still contains each Event exactly once.
6. Query the combined frontier and assert its next sequence and only head are
   the complete unit's creator-membership tail.
7. Resolve the absent default discussion Strand through the normal helper. Assert
   its explicit `ak.strand.create`, `ak.realm.set_default_strand`, and final
   `ak.message.create` continue one exact actor chain from the bootstrap tail.

## Acceptance

- A producer does not need, synthesize, or infer an empty remote frontier for a
  not-yet-created Realm.
- Realm bootstrap is the atomic `ak.realm.create` + closed follow-up facet unit
  required by spec; the creator's root authority is the
  `ak.component.realm.authority_root.v1` cell the create Event's registered
  reducer contract writes, never a self-issued genesis grant.
- The explicit default-Strand setup and owner Message continue the exact
  accepted bootstrap chain without a synthetic or skipped actor sequence.
- An exact retry returns the original receipts and creates no second Event or
  Realm-side state transition.
- The scenario is tagged `@fully-implemented` so `joint-smoke` covers it.
