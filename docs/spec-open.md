# Spec-open findings

Open items found while realigning the joint-e2e harness with
`arkret-spec/spec/v1/artifacts` on 2026-08-30. Each entry names the normative
artifact it was checked against.

Re-verified against `origin/main` of every repository on 2026-08-30:

| Repository | Commit | Subject |
| --- | --- | --- |
| `arkret-spec` | `04de08e9` | fix(identity): close DID document digest naming |
| `arkret-rust-sdk` | `fcfa4634` | fix(identity): align DID document digest fields |
| `soland` | `1fb82be8` | fix: align protocol consumers and clean orphan tests |
| `cotest` | `857524f8` | test: align DID document digest consumers |
| `inkson` | `1a962cdd` | fix: align delivery binding document digest |

Every finding below still reproduces on those commits.

`service-operation-dtos.schema.json` declares itself the canonical DTO source
("OpenAPI components reference this artifact so SDK and conformance tooling use
one schema source"), and `arkret-service-api.openapi.yaml` `$ref`s it — so where
that artifact and an implementation disagree, the artifact wins and the harness
asserts the artifact.

## 1. Response DTO field names: fixed in the current working tree

`arkret-rust-sdk` commit `7983d0b0` ("Refactor field names for clarity and
consistency across various structs", 2026-08-29) renamed a batch of response
list fields. `soland` followed the SDK. The spec artifacts were not changed, so
a spec-conformant client read an absent field and saw an empty result.

| Operation / DTO | Normative artifact | Spec field | Former SDK + soland field |
| --- | --- | --- | --- |
| `ak.self.strand.read.list` → `ProjectionStrandList` | `service-operation-dtos.schema.json` | `strands` (required) | `projection_strand_rows` |
| `ak.self.space.read.list` → `ProjectionSpaceList` | `service-operation-dtos.schema.json` | `spaces` (required) | `projection_space_rows` |
| `ProjectionMorphList` | `service-operation-dtos.schema.json` | `morphs` (required) | `projection_morph_rows` |
| `EventsSubmitOutcome` | `service-operation-dtos.schema.json` | `rejections` | `events_submit_rejected_rows` |
| `EventsSubmitOutcome` | `service-operation-dtos.schema.json` | `frontiers` | `realm_actor_frontier_views` |
| `ak.self.contact.read.list` → `ContactList` | `contact-operations.schema.json#/$defs/contact_list` | `contacts` (required) | `contact_list_rows` |
| realm links list → `RealmLinkList` | `realm-link-operations.schema.json#/$defs/realm_link_list` | `links` (required) | `realm_link_entries` |

Same batch renamed `EventsQueryOutcome.events` to `event_read_rows`; the SDK has
since reverted that one to `events`, which is what the spec says. That partial
revert is the clearest evidence the batch was applied without a spec gate.

**Resolution.** The current working tree directly renames the public Rust fields
to the spec spelling, updates soland and all local Rust consumers, and keeps
`e2e/` strict. It does not use `serde(rename)` or accept the implementation's
former private spelling. It also removes the non-schema
`EventsSubmitOutcome.realm_frontiers` field and fixes the separately missed
`ActorAggregateFrontierView.frontiers` container.

### 1a. The schema-struct gate blind spot is fixed

`arkret-rust-sdk` commit `fcef0cbc` ("feat: gate SDK wire structs against spec
schemas") added `tools/schema_struct_gate.py` plus a registry of 202 mappings and
79 exemptions, and wired it into CI. At the referenced commit none of the six
containers above was in either list:

| Rust type | In `mappings` | In `exemptions` |
| --- | --- | --- |
| `ProjectionStrandList` | no | no |
| `ProjectionSpaceList` | no | no |
| `ProjectionMorphList` | no | no |
| `EventsSubmitOutcome` | no | no |
| `ContactList` | no | no |
| `RealmLinkList` | no | no |

The registry does map `ContactListRow` (the element) to
`contact-operations.schema.json#/$defs/contact_list_row`, so the gate checks the
row and never the wrapper that names the array. That is why a commit whose whole
purpose was gating structs against spec schemas shipped with this drift intact.

**Resolution.** The current working tree adds exact schema pointers and mappings
for all six containers plus `ActorAggregateFrontierView`. The gate now passes
with 209 exact mappings and 79 exemptions, and a serialization regression test
asserts the canonical keys while rejecting the former names.

## 2. `ak.realm.policy_bundle` Bottom is unrecoverable for the whole Realm

`event-kind-registry.json` gives `ak.realm.policy_bundle` `lattice: cas_register`
with `bottom: "reject"`. `soland/crates/http/.../governance_proof.rs` resolves
every governance cell on the read path, so once that one cell reaches Bottom,
**every** later authorization and Seal read in that Realm returns
`409 state_mismatch`. Observed in a joint run: one Realm out of 86 took a second,
partial `policy_bundle` revision and then produced 290 consecutive 409s;
nothing in the protocol lets the Realm recover.

The same file already carries the counter-argument in a comment for the
non-reject path: "Rejecting every Bottom here lets one ambiguous, unrelated
selector poison all later controller-PCR authorization and Seal material."

**Question for the spec:** should `policy_bundle` be `bottom: expose` like the
cells that comment protects, or does the spec intend a recovery move
(`event-auth-state-resolution.md` §9.5 reset) that no operation currently
exposes? Today a single malformed revision is a permanent Realm-level DoS.

## 3. Realm genesis `trust_domain` is never validated

`realm-genesis.schema.json` requires `trust_domain`, but soland accepts a genesis
whose trust domain differs from its own configured `SOLAND_TRUST_DOMAIN`. The
harness has been sending `ak:trust_domain:soland.local` against a server running
`ak:trust_domain:local.host` for an unknown number of releases without a single
rejection.

**Question:** is a genesis `trust_domain` that does not match the admitting
Principal Server's trust domain valid? If not, the check is missing. (The stale
harness literal is tracked separately below; it is only visible because nothing
enforces the field.)

## 4. `directory_service` has no binding in the single-server topology

`GET /_arkret/describe?service_kind=directory_service` returns
`400 param_invalid` ("service_kind ... is not available on this binding"):
`soland/crates/http/src/routing/system/describe.rs` accepts only
`ServiceKind::PrincipalServer`. `ak.profile.directory_service.v1` is a required
profile in the conformance coverage gate.

**Question:** is `directory_service` expected to be co-hosted on the principal
server binding, or is a separate deployment required? If separate, the joint
topology needs that service and the coverage gate needs to say so.

## 5. MIMI room binding rejection code

`extensions/mimi-federation.spec.ts` asserts `mimi_room_binding_event_invalid`
for an invalid room binding event; soland answers
`mimi_room_state_incompatible`. Both are registered codes. Needs a ruling on
which one the invalid-binding-event path owns.

---

## Fixed in this pass (recorded for traceability, not open)

These were implementation bugs against a clear spec statement and are already
corrected:

- **soland** `projection_circles_join_rule_check` allowed `invite|request|open`;
  `circle.schema.json` `join_rule` enum is `invite|knock|public`. A
  `join_rule="public"` Circle failed durable write-through, so the Circle read
  back with no `member_ids`.
- **soland** `routing/events/operations/policy/governance.rs` moderation actor
  gate read `appellant` / `reviewer` / `closer`; `moderation-appeal.schema.json`
  and soland's own reducer (`apply_moderation.rs`) use `appellant_id` /
  `reviewer_id` / `closer_id`. A spec-conformant appeal submit was rejected with
  `403 moderation_appeal_actor_missing`.
- **cotest** peer/self events QUERY bodies sent `actors`;
  `EventsQueryPostRequestBody` names it `actor_ids` (soland reads
  `body.actor_ids`).
- **cotest** read `EventsSubmitOutcome.rejected` (spec: `rejections`) behind
  `?? []`, so 9 assertions across `models/realm-links.spec.ts` and
  `kanban/end-to-end.spec.ts` had been passing vacuously. `x.field ?? []`
  against a renamed field cannot fail — a renamed wire field turns the whole
  assertion into a no-op instead of a red test. Worth a lint.
- **inkson** `views/login.rs` fed `ActiveAccountContext::principal_id()` (an
  `ak:did_core:` core id) to `returning_sign_in_principal`, which requires a
  resolvable `did:` DID. Returning login and passkey login failed closed. The
  account already carries the accepted resolution DID via `did()`.

## Harness debt left open

Test-side, not spec-side. Listed so they are not mistaken for product bugs:

- `helpers/soland-api.ts` `createRealmApi` hard-codes
  `trust_domain: "ak:trust_domain:soland.local"`, which no longer matches the
  harness's `SOLAND_TRUST_DOMAIN`. Only invisible because of finding 3.
- `invites/third-party.spec.ts` writes a partial `ak.realm.policy_bundle`
  revision (only `allowed_third_party_invite_verification_ids`), dropping
  `federation_policy` and both encryption floors. `writeJoinPolicyApi`'s own doc
  comment states every `cas_register` revision is a complete replacement. This
  is what triggers finding 2 in practice.
- `identity/multi-device.spec.ts` submits a bare `ak.device.authorize` event for
  the accepted-device branch; soland requires the registered
  `ak.gate.account.command.pair_device.v1` gate and answers `412`. The operation
  is in `operation-registry.json` — the test needs rewriting onto it.
- `governance/moderation-appeal.spec.ts` submits `ak.moderation.appeal.review`
  before the preceding submit has projected, yielding
  `moderation_appeal_invalid_transition:none->under_review`. Needs a wait on the
  appeal state, not a retry.
