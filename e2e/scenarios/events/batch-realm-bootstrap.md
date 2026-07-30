# Events Submit Batch Realm Bootstrap

## Intent

Prove the registered Realm genesis transaction is authored without a synthetic
frontier for a not-yet-created Realm and establishes the exact actor chain used
by subsequent owner writes.

## Strand

1. Register Alice and issue a dev session.
2. Confirm combined `(realm_id, actor_id)` frontier lookup returns `not_found`
   before the Realm exists.
3. Submit the registered founding unit
   `[ak.realm.create, ak.realm.plaintext_visible_services]` — `ak.realm.create`
   plus the closed bootstrap follow-up facets the Realm declares. The create
   object carries the create-locked `capability_action_registry_digest`; v1 has
   **no** founding `ak.capability.grant` slot.
4. Query accepted history and assert the chain is `0/[] -> 1/[create_id]`, and
   that the batch contains no `ak.capability.grant` at all.
5. Query the combined frontier and assert `next_actor_seq=2` with the
   plaintext-visible-services facet as its only head.
6. Submit `ak.message.create` as Alice and assert it authors as
   `2/[plaintext_visible_services_id]`.

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
- The scenario is tagged `@fully-implemented` so `joint-smoke` covers it.
