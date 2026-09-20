# Authority-Commit Capability Migration — cotest

cotest is the cross-repository conformance and end-to-end suite. It ships no
product surface of its own, so this matrix reads the other way round from a
product repository's: the capability column is the **protocol invariant under
acceptance**, and the question this file has to answer is *which invariants
currently have a test watching them, and which do not*.

Deleting a test here removes a piece of acceptance evidence. Every removal below
names the vector or fixture that was withdrawn from `arkret-spec`, and the
runner that still covers the same product capability.

Round 3 of 3. Rounds 1 and 2 are `d67b7a3c` and `77137f6c`.

---

## Protocol invariants

The list this round was accepted against. A checked box means a test in this
repository executes it; the coverage matrix below names which one.

- [x] A producer signs the Event; the current governance Station validates it and
  signs a `RealmCommit`.
- [x] The producer Event carries **no** previous-event, ordering, basis,
  frontier, Seal or Cell field.
- [x] Only `RealmCommit` carries `previous_commit_ref`, and it links only to the
  previous commit of the **same** stream.
- [x] `CommitStreamRef` is closed to `Realm{realm_id}` /
  `Circle{realm_id,circle_id}` / `Sidecar{realm_id,sidecar_id}`. There is no
  Realm-global chain and no Realm-global position.
- [x] The three streams are independent: breaking one does not reset a sibling.
- [x] One `RealmCommit` accepts exactly one Event (single `event_ref` +
  `stream_position`). Multi-Event atomicity is a server transaction.
- [x] `EventCommitSubmission { event }` is the only Event submission DTO;
  `MlsCommitSubmission { commit_event, welcomes[], idempotency_key }` is the MLS
  one.
- [x] A Welcome is a producer-signed `MlsWelcomeDelivery`
  (`ak:mls_welcome_delivery:<uuidv7>`), not an Event; the Welcome enqueue and the
  MLS Commit complete in one Station transaction.
- [x] Join/bootstrap authenticates the **current** governance Station through
  genesis + a continuous dual-signed handoff chain + the current DID route.
  Neither the inviter's server nor the original governance server is a default
  bootstrap authority.
- [x] A Station change is only the planned dual-signed handoff
  (`RealmAuthorityHandoff` / `RealmAuthorityBundle`, two signatures under
  different `DetachedSignatureContext` domains). A lost old Station has no
  election and no takeover.
- [x] MLS shared Events are only MLS Genesis and MLS Commit; Proposals are
  inlined; KeyPackages go through their own ledger; MLS keys stay client-side.
- [x] MLS activation: a scope is plaintext until its own `ak.mls.genesis` is
  accepted, and activation is irreversible
  (`mls_activation_required` / `mls_activation_irreversible`).
- [x] A recovery transaction completes on **two consecutive `CommittedEventRef`
  values in the same PCR Realm stream** — two different commits: different
  `commit_id`, different `event_id`, positions differing by one, same
  `stream_ref`, and that `stream_ref` must be `CommitStreamRef::Realm`.
- [x] Removed entirely: Seal, Cell, CBS, ControlProposal, frontier, history
  exporter, RHRK, organization recovery key, audited-E2EE core, full/relaxed
  governance profile, security frontier, `policy_root`, `state_root`.

---

## Consistency coverage matrix

`src/conformance/authority_commit.rs` (`ak.suite.authority_commit.v1`,
1 679 lines, written in round 2) is the primary evidence for most of the list.
Each row names the function that executes the invariant.

| Protocol invariant | Covering test | Case / function | Status |
|---|---|---|---|
| Three streams independent, no Realm-global position | `src/conformance/authority_commit.rs` | `verify_streams_have_no_global_position`, `verify_scan_walks_one_stream_only` | present, **not executed this round** (see blockers) |
| Same, executed end-to-end through a real commit store | `src/conformance/sync.rs` | `verify_stream_ref_is_closed_to_three_streams`, `verify_broken_tail_stops_only_its_own_stream` | **passing** |
| One chain per stream, position strictly `+1` | `src/conformance/authority_commit.rs` | `verify_declared_single_chain_per_stream`, `verify_broken_chain_is_rejected`, `verify_forked_position_is_rejected`, `verify_cross_stream_predecessor_is_rejected` | present, not executed |
| Same, replayed through `MemoryAuthorityCommitStore` | `src/conformance/sync.rs` | `verify_tails_commit_exactly_when_continuous` | **passing** |
| Producer Event carries no ordering or linkage | `src/conformance/authority_commit.rs` | `verify_producer_event_carries_no_commit_ordering` | present, not executed |
| Same, on the live wire | `e2e/tests/events/realm-genesis-commit-stream.spec.ts` | `RETIRED_ENVELOPE_MEMBERS` loop | present, **blocked** (live e2e) |
| `RealmCommit` declares no global/Realm position member | `src/conformance/sync.rs` | `verify_commit_carries_no_global_or_realm_position` | **passing** |
| `EventCommitSubmission` is the only Event DTO | `src/conformance/authority_commit.rs` | `verify_event_commit_submission_is_the_only_event_dto` | present, not executed |
| Station handoff dual-signed chain; old Station cannot write after | `src/conformance/authority_commit.rs` | `verify_handoff`, `verify_old_authority_writes_are_rejected`, `verify_new_generation_continues_imported_heads`, `commit_generation_is_current` | present, not executed |
| Bootstrap authenticates the **current** governance Station | `src/conformance/authority_commit.rs` | `verify_join_bootstrap`, `verify_snapshot_and_tails_are_complete` | present, not executed |
| MLS Commit + Welcome deliveries are one transaction | `src/conformance/authority_commit.rs` | `verify_mls_atomic_submission`, `verify_invalid_welcome_writes_nothing`, `submit_mls_commit` | present, not executed |
| Welcome is not an Event and carries no recipient ack | `src/conformance/authority_commit.rs` | `verify_welcome_is_not_an_event`, `verify_welcome_carries_no_recipient_ack` | present, not executed |
| MLS activation is irreversible | `src/conformance/authority_commit.rs` | `verify_mls_activation_is_irreversible` | present, not executed |
| Recovery completes on two **different** consecutive PCR Realm commits | `src/conformance/authority_commit.rs` | `verify_recovery_completion_is_two_consecutive_commits`, driving `arkret_wire::validate_recovery_commit_pair` | present, not executed |
| Own-Station account stream: tail continuity, checkpoint ordering, reconnect, delivery cancellation | `src/conformance/sync.rs` (`ak.vector.sync.client_account_stream.v1`) | whole suite, entrypoint `tests/client_account_stream.rs` | **passing** |
| Account Authority issuer ledger: identity, CAS chain, replica classification, idempotency, bounded fanout | `src/conformance/account_status_issuer_ledger.rs` (`ak.vector.account_status.issuer_ledger.v1`) | whole suite | **passing** |
| Realm genesis takes Realm stream positions `0..n-1`; exact retry is a duplicate | `e2e/tests/events/realm-genesis-commit-stream.spec.ts` | 3 tests | present, **blocked** (live e2e) |
| Submission returns a commit that admits the exact Event in its scope's stream | `e2e/helpers/soland-api.ts` | `assertAuthoritySubmitOutcome`, called from every submit | present, **blocked** (live e2e) |
| Concurrent edits converge by commit order | `e2e/tests/kanban/end-to-end.spec.ts` | "two moves of one card commit in order and the later commit wins" | present, **blocked** (live e2e) |

### The five invariants singled out for this round

| Invariant | Has a test? | Executed this round? |
|---|---|---|
| Realm / Circle / Sidecar independent, no Realm-global chain | **yes**, two independent suites (`authority_commit.rs`, `sync.rs`) | **yes** — `sync.rs` replays a broken Circle tail against a store already holding the Realm and Sidecar streams, asserts their heads do not move, and then appends to both to show they are still writable |
| Station handoff dual-signed chain | **yes**, `authority_commit.rs::verify_handoff` | **no** — blocked on the root package not compiling |
| Bootstrap authenticates the current governance Station | **yes**, `authority_commit.rs::verify_join_bootstrap` | **no** — same blocker |
| MLS Commit ↔ Welcome delivery transaction atomicity | **yes**, `authority_commit.rs::verify_mls_atomic_submission` + `verify_invalid_welcome_writes_nothing` | **no** — same blocker |
| Recovery = two **different** consecutive `CommittedEventRef` on one PCR Realm stream | **yes**, `authority_commit.rs::verify_recovery_completion_is_two_consecutive_commits`, which drives the SDK's own `validate_recovery_commit_pair` rather than restating it | **no** — same blocker |

**Not covered by any test in this repository.** These are honest gaps, not
oversights hidden by a passing suite:

- **A Realm-global `position` or chain appearing on the wire.** The suites prove
  it cannot be *constructed* (`CommitStreamRef` has three variants and
  `RealmCommit` has no such member) and cannot be *deserialized* (a
  `"kind": "realm_global"` stream ref is rejected). Nothing asserts that a real
  server never emits one, because the live e2e cannot run.
- **A lost old Station.** The spec says there is no election and no takeover.
  No test drives a Station loss, because there is no wire object for the absent
  behaviour to produce — a negative of this shape needs a live two-Station
  harness, which is currently blocked.
- **The authorization-lease rail.** `ak.vector.authz.authorization_lease_issuance.v1`
  is still an active vector with a live fixture, but
  `registry/operation-registry.json` no longer registers any lease HTTP
  operation. `e2e/helpers/soland-api.ts` still posts to
  `/_arkret/self/authorization-leases`. Either the endpoint should return to the
  registry or the TypeScript rail should go; this round did not guess.

---

## Removed as complete old-protocol units

Each entry names what it covered and where that capability still has a runner.

### Rust

- **`tests/station_cas_account_data.rs`** — entrypoint for
  `ak.vector.sync.station_cas_account_data.v1`. The vector is no longer in
  `registry/vector-registry.json` and `sync-fixture.json`, its only fixture, was
  deleted from `spec/v1/artifacts/fixtures/`. The Station-CAS account-data
  capability keeps its runner in `src/conformance/decision_0017_vectors.rs`,
  which consumes `account-data-cas-convergence-fixture.json`.
- **`tests/timeline_window_completion.rs`** — entrypoint for
  `ak.vector.sync.timeline_window_completion.v1`, likewise withdrawn.
  Window-start state is now `ak.vector.sync.state_at_window_start.v1` in
  `protocol-edge-cases-fixture.json`.
- **`tests/realm_detail_baseline_singletons.rs`** — entrypoint for
  `ak.vector.sync.realm_detail_baseline_singletons.v1`, likewise withdrawn. The
  baseline-versus-incremental merge rule it guarded is now the
  `checkpoint_ordering` section of `client-sync-fixture.json`, executed by
  `src/conformance/sync.rs::verify_checkpoint_never_outruns_projection`.
- **The snapshot half of `src/conformance/sync.rs`** — Realm-state-snapshot
  frontier recovery, the inclusion challenge, `state_digest` and the covered
  event-set Merkle tree. `arkret_state::realm_state_snapshot` no longer exports
  any of `CoveredEventSet`, `EventSetCommitmentAlgorithm`, `event_set_root` or
  `state_digest_from_items`; the snapshot that survives is
  `arkret_wire::RealmStateSnapshot`, whose completeness is checked by
  `authority_commit.rs::verify_snapshot_and_tails_are_complete`.
- **The stream-trace frame validator half of `src/conformance/sync.rs`** —
  `arkret_models_collaboration::sync_frames::stream_trace` no longer exists. The
  surviving frame contract is `AccountSubscribeFrame`, and the client-side
  reconnect semantics it carried are the `reconnect` section of the new fixture.

### TypeScript

- **`e2e/tests/events/batch-realm-bootstrap.spec.ts`** and
  `e2e/scenarios/events/batch-realm-bootstrap.md` — the entire subject of the
  spec was the `(realm_id, actor_id)` authoring frontier and the client-side
  batch that extended it. Rewritten, not dropped: see below.
- **`advanceEnvelopeToActorFrontier`, `alignSignedEventToActorFrontierApi`,
  `requiresActorFrontierRefresh`, `refreshBatchActorChain`,
  `batchFrontierEventIds`, `peerEventFrontierApi`, `nextActorSeq`,
  `nextEnvelopeHlc`** — the producer envelope has no `actor_seq`, `prev_refs` or
  `hlc` to stamp, and `QUERY /_arkret/self/events/frontier` is not in the
  operation registry.
- **`applyRegisteredCbsPlane`, `prepareSignedEventCbsApi`,
  `forceConformanceCbsBasis`, `eventAuthContext`, `seedConformanceRealmBasisApi`** —
  CBS is removed; there is no ordinary/control plane split and no `auth_context`
  whose `authority_refs` are Seal ids.
- **`submitPrincipalSuccessorSealApi`, `readDirectoryJoinCandidateSealBasis`,
  the invite-accept Seal-basis gate** — `/_arkret/self/seals`,
  `/seals/prepare` and `/seals/frontier` are gone. An Event is final when the
  Station returns its commit, which `submitSignedEventApi` already awaits, so
  every one of these calls was a step with nothing behind it.
- **`compositeCellSubject`, `inviteLiveTargetCell`,
  `inviteLiveTargetPreconditions`, `serviceNotaryPublicKey`,
  `realmRootMayAuthorEventKind`** — Cell subjects, `head_eq null` preconditions
  and the frozen-notary / authority-root-cell model they addressed are removed.
- **`submitSignedEventBatchApi`** — one `RealmCommit` accepts exactly one Event.
  `createRealmApi` now submits the founding unit Event by Event and asserts the
  commits take positions `0..n-1`, which is a **stronger** claim than the batch
  accept-list it replaced.

No test module was deleted to make a build green. The three Rust entrypoints
above are one-line `#[test]` shims for vectors the specification withdrew; the
TypeScript spec was replaced file-for-file.

---

## Rewritten, not deleted

| Was | Is | What changed |
|---|---|---|
| `src/conformance/sync.rs` (1 923 lines, `sync-fixture.json`) | `src/conformance/sync.rs` (`client-sync-fixture.json`, `ak.vector.sync.client_account_stream.v1`), entrypoint `tests/client_account_stream.rs` | Every declared `stream_ref` is parsed into `CommitStreamRef` and every `commit_id` into `RealmCommitId`; each tail is replayed through `MemoryAuthorityCommitStore`, the store a governance Station commits with, so "accepted" means a real commit log took it. The discontinuous tail is replayed against a store already holding the sibling streams. |
| `src/conformance/account_status_issuer_ledger.rs` (1 291 lines, importing a deleted `security_closure` module) | same path, driving the rewritten `account-status-issuer-ledger-fixture.json` | Each record's canonical core bytes, digest and content-addressed id are re-derived with `UnsignedAccountStatusRecord`; the declared proof is re-bound with the SDK's proof-binding bytes and a tampered digest is proven to be refused; every classification row runs through soland's own `classify_account_status_replica_append` and is cross-checked against `registry/account-status-replica-decision-table.json`, with a check that no table row goes unexecuted. |
| `e2e/tests/events/batch-realm-bootstrap.spec.ts` | `e2e/tests/events/realm-genesis-commit-stream.spec.ts` + `e2e/scenarios/events/realm-genesis-commit-stream.md` | Three tests: the founding unit takes consecutive Realm stream positions from zero with each commit naming its predecessor; an exact retry is a `duplicate` that replays the original commit and takes no new position; an ordinary write continues the same stream. Also asserts the retired frontier surface no longer answers and that no accepted Event carries a retired envelope member. |
| kanban "stale actor branch … `cas_conflict`" | kanban "two moves of one card commit in order and the later commit wins" | A producer Event has no stamp to go stale against. Both moves are admissible; convergence is decided by the order the Station commits them, read off the Realm stream. |
| `queryRealmEventsApi` (`QUERY /_arkret/self/events`) | `scanRealmStreamApi` (`POST /_arkret/self/streams/scan`, `ak.self.committed_event.read.scan.v1`) | Returns committed-event views so a caller can assert the order the Station assigned, not just the payloads. `queryRealmEventsApi` is kept as a thin projection so ~30 specs keep their shape. |
| `submitSignedEventApi` (CBS stamp → frontier advance → lease → batch → 3-attempt retry) | one POST plus `assertAuthoritySubmitOutcome` | Checks the returned commit admits the exact Event into the one stream its `scope_ref` selects, that the stream kind is one of the three closed variants, that position zero has no predecessor and every successor does, and that no `global_position` / `realm_position` / `seal_ref` / `frontier` came back. |
| `prepareSignedEventSubmissionApi` / `…BatchSubmissionsApi` | return `{ event }` | `EventCommitSubmission { event }` is the only Event submission DTO. |
| prepared-message assertions on `actor_seq` / `prev_refs` / `preconditions` | a loop asserting none of the retired members is present, plus an exact-replay check that the duplicate returns the original `commit_id` at the original `stream_position` | |
| `crates/test-support/src/wire.rs` PCR genesis packaging | `arkret_wire::PcrGenesisUnit::new(create, authorize)` | `IdentityCreationEvents` / `build_identity_creation_events` were replaced by a type that validates the ordered pair itself and is what `garth::identity_binding_challenge_request` already takes. |

---

## A gap the rewrite found — now closed

`client-sync-fixture.json` declared a reconnect `server_outcome` of
`stream_tail_missing` that, at the time of the rewrite, appeared in no
error-code registry, no normative prose and no generated SDK constant. It was
carried in `sync.rs` as one named constant, `UNREGISTERED_RECONNECT_OUTCOME`,
guarded by a check that failed as soon as the spec registered it — so the
allowance would be deleted rather than quietly outlive the gap.

The spec took the first of the two options: the code is registered, as
`ReasonCode::StreamTailMissing`, with a descriptor row in
`REASON_CODE_DESCRIPTORS`. It is deliberately a reason code and not an
`ErrorCode`: a missing stream tail is a condition the client resumes from, not
an HTTP error.

The allowance is therefore gone and the guard is inverted. `sync.rs` now carries
`REASON_CODE_RECONNECT_OUTCOME`, and
`verify_reason_code_outcome_is_registered` asserts the registration positively
(the descriptor must be present) while still failing if the code additionally
becomes an `ErrorCode`, in which case the reason-code branch in
`reconnect_verdict` is redundant and must go.

---

## False green: how `check:wire-types` hid a broken `typecheck`

`e2e/helpers/generated/spec-wire-objects.ts` is generated from the closed
`arkret-spec` object schemas and is what makes an unregistered member in a
hand-built wire literal a `tsc` error. The failure mode on record is that
`scripts/generate-wire-types.mjs` crashed, so `npm run check:wire-types` never
reported drift, and `npm run typecheck` passed against a stale generated file —
green with nothing behind it.

Both gates were re-verified by deliberate negative probe before any of this
round's numbers were trusted:

```
$ echo 'const _cotestGateProbe: number = "not a number";' >> tests/sync/offline-conflict.spec.ts
$ npm run typecheck        # -> reports the injected error, exit 2
$ printf '\nexport type CotestGateProbe = never;\n' >> helpers/generated/spec-wire-objects.ts
$ npm run check:wire-types # -> "spec wire types are stale: …", exit 1
```

Both fail as they should, so neither is currently false green. Two further
checks on the same suspicion:

- `tsc --listFiles` covers **66 of 66** files under `e2e/tests` and **37 of 37**
  under `e2e/helpers` — the include globs really reach the specs.
- 16 of the 18 generated wire types are referenced by at least one spec or
  helper. `MembershipPayload` and `SpaceObject` are generated but annotate
  nothing, so those two shapes are generated-but-unenforced. That is a smaller
  version of the same failure and is recorded here rather than left implicit.

The same probe was applied to the two rewritten Rust suites, because a
fixture-driven suite can pass by reading nothing. The spec artifacts were copied
to a scratch directory, corrupted, and the suites re-run against
`COTEST_SPEC_ARTIFACTS_ROOT`:

| Injected corruption | Result |
|---|---|
| Circle tail position jumps `0 → 5` while still declaring `expected: "accepted"` | `client_account_stream_vector_runs_clean` FAILED — *"circle_stream_tail_is_independent: the fixture says accepted but the commit store refused it: stream head changed"* |
| Ledger record `status` edited from `locked` to `suspended` without re-deriving its id | `account_status_issuer_ledger_vector_runs_clean` FAILED — *"records[1]: record failed its own shape validator: account_status_record_id mismatch"* |

---

## Verification gates

Run at the end of the round. Exact commands and outputs.

| Gate | Result |
|---|---|
| `cd e2e && npm run typecheck` (`tsc --noEmit`) | **pass**, exit 0 |
| `cd e2e && npm run check:wire-types` | **pass**, exit 0 — *"spec wire types are up to date"* |
| `cd e2e && npm run check:fixme` | **pass**, exit 0 — *"5 executable, fully attributed fixme tests"* |
| `cd e2e && npm run check:provisioning-cache` | **pass**, exit 0 — 11 passed, 0 failed |
| `cargo fmt -p cotest -- --check` / `-p cotest-test-support` | clean. `cargo fmt --all` is **not** used: it reaches into the sibling path-dependency checkouts. |
| Focused suite execution (see blocker 1 for why the oracle is needed) | **2 passed, 0 failed** — `client_account_stream_vector_runs_clean`, `account_status_issuer_ledger_vector_runs_clean` |
| `cargo check --workspace --all-targets --no-default-features` | **fail**, exit 101 — see blocker 1 |
| `cargo test --workspace --no-fail-fast` | **not runnable** — the workspace does not compile |

### Legacy-residue counts

Counted with
`Seal|seal_ref|seal_id|seals|\bCell\b|\bCBS\b|ControlProposal|control_proposal|frontier|Frontier|RHRK|audited|governance_profile|policy_root|state_root|previous_event|prev_event|global_position|commit_batch`.

| Tree | Start | End | Δ |
|---|---|---|---|
| `src/`, `tests/`, `crates/` (Rust) | 745 | 696 | −49 |
| `e2e/` (TypeScript + scenario docs) | 350 | 266 | −84 |

Some of the remaining matches are deliberate: the new suites name the retired
carriers in forbidden-member lists (`FORBIDDEN_RECORD_MEMBERS`,
`RETIRED_ENVELOPE_MEMBERS`, the `verify_commit_carries_no_global_or_realm_position`
list) precisely so a regression is caught. Most are not: the concentrations
below are untouched work.

| File | Count | Nature |
|---|---|---|
| `src/harness/client.rs` | 107 | Seal frontier polling, `SealResolveOutcome`, CBS effect plane, `REALM_AUTHORITY_ROOT_CELL` |
| `src/scenarios/fanout_route_miss_live.rs` | 85 | federation batch + Control-proposal Ack carrier |
| `src/scenarios/calendar_rsvp_convergence.rs` | 55 | frontier waits (also inkson-coupled) |
| `src/harness/event_builder.rs` | 42 | `EventInitialSubmission`, Cell preconditions, `realm_bootstrap_event_batch` |
| `src/scenarios/account_subscribe_long_poll.rs` | 30 | frontier frames |
| `e2e/helpers/soland-api.ts` | 25 | federation transport wrapper (`membership_frontier`, `service_binding_ref`) + the lease rail |
| `e2e/tests/joint/joint-inkson-smoke.spec.ts` | 27 | `actor_seq` / `prev_refs` bootstrap assertions |

---

## External blockers

Everything below is a sibling repository mid-migration by another agent. Nothing
here was worked around by deleting or disabling a test.

### 1. The root package cannot be compiled — `inkson` and `soland-services`

```
$ cargo check --workspace --all-targets --no-default-features
error: could not compile `soland-services` (lib) due to 167 previous errors
error: could not compile `inkson` (lib) due to 284 previous errors; 7 warnings emitted
exit 101
```

- **Command:** `cargo check --workspace --all-targets --no-default-features`
- **Pass:** 0 · **Fail:** exit 101, 459 error lines
- **Cause:** `cotest`'s root package takes `inkson` and `soland-*` as path
  dependencies. Both are mid-migration in their own checkouts and neither
  compiles, so cargo never reaches cotest's own code. This is not a cotest
  failure: at the opening baseline the same command failed with 580 error lines
  split 363 (`inkson`) / 215 (`soland-services`), and every one of those lines
  is in a sibling repository.
- **`cargo test --workspace --no-fail-fast` therefore has no pass/fail count to
  report.** Reporting one would be fabrication.

**How the two rewritten suites were executed anyway.** A throwaway harness in
the session scratchpad re-hosts `conformance::sync`,
`conformance::account_status_issuer_ledger` and the shared fixture DSL through
`#[path]` against the same SDK and `soland-storage` the real package uses,
dropping only the dependencies that do not compile. It is a measurement tool,
not a deliverable, and is not committed. Result:

```
test account_status_issuer_ledger_vector_runs_clean ... ok
test client_account_stream_vector_runs_clean ... ok
test result: ok. 2 passed; 0 failed; 0 ignored
```

### 2. The SDK moved under the round, repeatedly

`arkret-rust-sdk` was edited continuously during this work. Observed, in order,
each blocking a full check for minutes at a time:

- `crates/wire/src/notary.rs` renamed to `realm_authority_signer.rs`
  (`NotarySignerDescriptor` → `RealmAuthoritySignerDescriptor`), mid-session.
- `arkret-signatures`: `verify_ed25519_raw_transcript_signature` missing.
- `arkret-http-client`: `expected u16, found u32`.
- `arkret-event-draft`: `PolicySetStatePayload` unresolved.
- `arkret-models-collaboration`: four `validate_websocket_*` imports unresolved.
- `arkret-auth`: `expected EventId, found String`.
- `garth`: `AccountBaselineSegment`, `RealmInvalidation`, `RealmListChanges`,
  `RealmListPage` became private in the SDK.

A 20-attempt poll at 60-second intervals never observed a window in which the
whole dependency graph was green. Two consequences to plan around:

- the residue counts above are a snapshot, and some remaining Rust residue is
  *unreachable* rather than *wrong* — it cannot be judged until the package
  compiles;
- `crates/test-support/src/wire.rs` needed a fix this round purely because the
  SDK dropped `IdentityCreationEvents` underneath it. Expect more of these.

### 3. The SDK dropped the security-transaction resilience runner

`src/conformance/security_transaction_resilience.rs` calls
`arkret_models_crypto::run_security_transaction_resilience_fixture`. That symbol
no longer exists:

```
$ grep -rn "run_security_transaction_resilience_fixture" --include=*.rs arkret-rust-sdk/
(no matches outside target/)
$ grep -rn "resilience" --include=*.rs arkret-rust-sdk/crates/
(no matches)
```

`crates/models-crypto/src/security_transaction.rs` still carries the data model
— including the renamed `SecurityTransactionTerminalOutcome` — but the
fixture-runner entry point is gone, so the joint gate has no SDK side to compare
against and the root package would not compile even with blocker 1 cleared.

- **This is a capability gap, not a naming one.** It was *not* worked around:
  the gate is neither stubbed nor deleted, and the independent reference runner
  beside it was brought fully up to date with the fixture instead.
- **The reference half is verified green on its own.** It holds the module's
  no-SDK-dependency fence, so a scratch crate carrying only `serde`,
  `serde_json` and `sha2` re-hosts it against the live
  `arkret-spec` fixture: 55 projections, and the module's own unit test passes.
- **Next round:** either the SDK re-exposes a runner over
  `fixtures/security-transaction-resilience-fixture.json`, or the gate is
  restated as a single-runner fixture check and `equivalence_output`'s
  `minimum_independent_runners: 2` is raised against `arkret-spec`.

### 4. Live end-to-end and joint end-to-end cannot run

- **Commands:** `cd e2e && npm test` (Playwright), `scripts/run-joint-e2e.ps1`
- **Pass:** 0 · **Fail:** 0 · **Not started.**
- **Cause:** the live suite drives a prebuilt `soland.exe`. soland is mid-migration
  in another agent's hands, so a binary built now would not implement the
  submission surface these specs were just rewritten against, and a stale binary
  would test the retired behaviour. Building it is also known to collide with a
  running dev `coauth.exe`.
- **Consequence for this file:** every row in the coverage matrix marked
  *blocked (live e2e)* is written and type-checked but has never executed. That
  includes the whole `realm-genesis-commit-stream` spec and
  `assertAuthoritySubmitOutcome`.

### 5. Server conformance needs a database variable the script does not export

- **Commands:** `scripts/run-server-conformance.ps1`, and any
  `soland-services` / cotest conformance test that opens a database.
- **Pass:** 0 · **Fail:** blocked upstream of the database by blocker 1.
- **Cause:** the script exports `COTEST_SOLAND_DATABASE_URL` but the tests read
  `SOLAND_TEST_DATABASE_URL`. In a clean shell that is 7 red in `soland-services`
  plus 1 in cotest before anything else runs.
- **Local environment is otherwise fine** — verified this round:
  `PGPASSWORD=root psql -h 127.0.0.1 -U postgres -c "select version();"` →
  *PostgreSQL 18.1 on x86_64-windows*. Setting
  `SOLAND_TEST_DATABASE_URL=postgres://postgres:root@127.0.0.1:5432/…` is
  sufficient once the workspace compiles. `psql` must carry `PGPASSWORD` or it
  blocks on a password prompt.

### 6. Measured baseline, 2026-09-17 — 555 errors, and where they are

The handoff carried "约 650 条残留，根 package 从未编译到" forward from an
estimate. It was re-measured personally after the SDK went green at `2293a1fa`,
and the second clause is the one that matters: cotest's root package is blocked
by **sibling path dependencies**, not by an earlier package in its own
workspace. `cargo check --workspace --all-targets --message-format short`:

| crate | errors |
| --- | --- |
| `inkson` (lib) | 271 |
| `soland-services` (lib) | 167 |
| `garth`, `soland-domain`, `soland-storage`, `soland-storage-postgres` | 0 |
| `cotest-test-support` (`crates/test-support`) | 0 |
| **`cotest` (lib)** | **never reached — 0 files type-checked** |

So there was never a trustworthy cotest number to compare against. To get one,
the §8 oracle technique was applied at whole-package scale: a scratch crate
carrying cotest's real `src/` with the 14 inkson-importing modules removed, and
`inkson` / `soland-services` dropped from the dependency list.

| reading | cotest lib errors | files |
| --- | --- | --- |
| baseline (HEAD `5b074180`) | 555 | 70 |
| after this round | 542 | 61 |

Five of the 555 are oracle artefacts (`conformance/privacy.rs` × 4 referencing
the dropped `super::privacy_security`, `scenarios/protocol_payloads/mod.rs` × 1
referencing the dropped `push`), so the real figures are ≈550 → ≈537. The 14
dropped modules are still unmeasured and are in neither number.

**Nine files went red → clean:** `conformance/auth_session_proof.rs`,
`conformance/member_roster_vectors.rs`, `conformance/mimi_provider_directory.rs`,
`conformance/schema_validation_fixture.rs`, `conformance/wire/multisig.rs`,
`scenarios/_helpers/bridge.rs`, `scenarios/delivery_media.rs`,
`scenarios/protocol_payloads/device_messages.rs`,
`scenarios/to_device_offline_ordering.rs`.

The drop is small on purpose. Every error fixed this round was a **module move**
— a type that still exists in the SDK under a new parent — and those are the
only ones fixable from here while `arkret-rust-sdk` is off-limits. The moves
found and followed:

| was | is now |
| --- | --- |
| `session_grant_bodies::{SessionGrantOutcome, SessionGrant*RequestBody, human_session_grant_intent_digest}` | `session_grants::…` |
| `sync_frames::account_sync::{DeviceMessage*, DeviceMessages*}` | `device_messages::…` |
| `sync_frames::account_sync::{NotificationDelta, NotificationDeltaAction}` | `sync_frames::account_subscribe::…` |
| `sync_frames::account_sync::{MemberRosterEntry, MembershipState}` | `account_subscribe_projections::{MemberRosterEntry, MemberRosterMembership}` |
| `account_lifecycle::{ConsentCellView, Consent*RequestBody}` | `consent_operations::{ConsentView, Consent*RequestBody}` |
| `account_lifecycle::AccountView` | `account_operations::AccountView` |
| `agent_operations::{agent_requested_scope_digest, agent_runtime_key_binding_digest, AgentRuntimeKeyPossessionProof}` | `agent_scope::…` |
| `events_payloads::PolicySetStatePayload` | `governance::operation_wire::PolicySetStatePayload` |
| `http_bodies::{DevicePairing*, AccountDevicePair*, UnsignedDevicePairingTargetProof}` | `device_pairing::…` |
| `arkret_signatures::signer::verify_ed25519_payload_signature` | `arkret_signatures::verify_…` (module made private, item re-exported at crate root) |

Two semantic follow-ons were required and are **not** compatibility shims:

- `MemberRosterEntry.identity_events` is now `Option<Vec<Event>>`. The four
  roster fixtures assert that an empty inline identity-event list MUST be
  omitted from the wire, so `vec![]` became `None` — the exact statement of the
  invariant, not a silencer.
- `DeviceMessagesSendOutcome.delivered` is now keyed by `DeviceId` and carries a
  `DeviceMessageDeliveredRow`. Three assertions had been comparing
  `delivered[&actor][0]` against a device-id literal. They are replaced by
  `assert_delivered_to()` in `scenarios/protocol_payloads/device_messages.rs`,
  which names the device it expects, reads back the row's
  `DeviceMessageDeliveredStatus` and `device_message_id`, and asserts
  `unknown_devices` is empty. That is strictly more checking than before.

**Why the number did not fall further.** Fixing an import lets the compiler see
the type drift behind it for the first time, so each pass trades import errors
for deeper real ones: pass 1 removed 25 and revealed 29 (555 → 559), pass 2
removed 17 and revealed 0 (559 → 542), pass 3 removed 2 and revealed 2 (542 →
542). The count is a poor progress metric here; the composition is the real one,
and it has shifted from "stale module path" to "capability absent".

### 7. Blocked on the typed current-result family registry (handoff §4)

31 errors in 11 files are waiting on the same missing thing: `result_writes[]`
contracts and the `ak.component.*` identifiers that replace the Cell model.
`CellRef`, `CellFamilyId`, `LatticeOp`, `LatticeOpType`, `EventCellValueShape`,
`state_model`, `cell_writes`, `cell_family` and the whole
`arkret_lattice_registry` crate were removed with nothing in their place.
**These were deliberately left untouched** — anything written against them now
would have to be rewritten when §4 lands.

| file:line | waiting on |
| --- | --- |
| `src/harness/event_builder.rs:426` | `arkret_wire::CellRef` |
| `src/harness/event_builder.rs:557,562,567,572,577,583,591,607` | `arkret_wire::CellFamilyId` |
| `src/harness/event_builder.rs:612` | `arkret_schema::validate_registered_cell_writes_in_context` |
| `src/publication.rs:28` | `arkret_schema::project_registered_cell_writes` |
| `src/conformance/encoding.rs:101` | `EventKindDescriptor.cell_writes` |
| `src/conformance/encoding.rs:105` | `arkret_wire::CellFamilyId` |
| `src/conformance/encoding.rs:214,248` | `arkret_wire::CellRef` |
| `src/conformance/encoding.rs:232,233` | `arkret_schema::validate_registered_cell_writes` |
| `src/conformance/call_state_core.rs:14` | `arkret_identifiers::CellRef` |
| `src/conformance/call_state_core.rs:19` | `arkret_state::state_model` |
| `src/conformance/call_state_core.rs:22` | `arkret_wire::{EventCellValueShape, LatticeOp, LatticeOpType}` |
| `src/conformance/agent_vectors.rs:723` | `EventKindDescriptor.cell_writes` |
| `src/conformance/agent_vectors.rs:727` | `arkret_wire::CellFamilyId` |
| `src/conformance/wire/mimi.rs:514,515` | `EventKindDescriptor.{cell_family, cell_writes}` |
| `src/conformance/profile_matrix.rs:555` | `arkret_identifiers::CellRef` |
| `src/conformance/push_route_revision.rs:6` | the `arkret_lattice_registry` crate |
| `src/scenarios/consent_pairwise_isolation_live.rs:137,157` | `ConsentView.{active_grant_dots, cell_id}` |
| `src/scenarios/invite_service_fanout_live.rs:370,386,640` | `ConsentView.active_grant_dots` |

### 8. SDK surfaces cotest needs back

Not naming rules — symbols the SDK deleted and did not replace. Grouped by what
they gate, counted from the 542-error oracle reading.

- **Seal / frontier polling (19 sites).** `arkret_wire::SealId`,
  `EventInitialSubmission`, `http_bodies::{SealResolveOutcome,
  SealResolveSelection, SelfSealResolveRequestBody, EventSealSubmitOutcome}`,
  `SealFrontierState`, `EventsFrontierState`, `event_sync::EventsFrontierView`,
  `SignalEnvelope.seal_ref`,
  `DeviceRevocationGateDecisionReceipt.covering_seal_id`. Most of these should
  stay deleted; the callers need rewriting onto `CommitStreamHead`, which is a
  cotest job for a later round, not an SDK one. `EventInitialSubmission` is the
  exception — it has no successor named anywhere.
- **`arkret_wire::Notary*` (19 sites).** `NotarySignerDescriptor`,
  `NotaryValue`, `NotaryKeyKind`, `NotaryJoseAlgorithm`. The first was renamed
  to `RealmAuthoritySignerDescriptor` mid-round; the other three have no
  observed successor.
- **`arkret_models_collaboration::http_bodies` (6 sites left).** The module is
  gone. Device-pairing and mimi bodies were relocated and are followed above;
  `EventDelivery*`, `EventsResolve*`, `EventsSubmitOutcome`,
  `PeerEventsResolveRequestBody`, `MimiIdentifierQueryRequestBody` and
  `MimiKeyMaterial{Outcome,RequestBody}` are absent entirely.
- **`arkret::AgentSidecar*` (≈18 symbols, 72 errors in
  `src/conformance/sidecar_vectors.rs` alone).** The largest single hole.
- **`arkret_wire::cbs` (8), `arkret_wire::null_subject_cell` (7).** CBS was
  removed by design; the vectors asserting its absence still import it.
- **`arkret::{reaction_routing_tag_from_root,
  derive_content_key_from_history_secret,
  decrypt_content_exporter_aead_standalone}` (14).** The RFC 9420 exporter
  primitives kept for RTC/Signal/reaction labels are no longer exported.
- **`arkret_models_collaboration::{poll, direct_conversation_ops,
  governance_dependencies}` (11).** Modules absent.
- **`arkret_models_collaboration::sync_frames::{websocket_binding,
  websocket_session}`.** Merged into `sync_frames::websocket`, but
  `WebSocketConsumerHandoff`, `WebSocketConsumerOwner`, `WebSocketFallbackPolicy`,
  `WebSocketFrameCodec`, `WebSocketHandshakeFailure`, `WebSocketOpenAdmission`,
  `WebSocketServerEvent` and `WebSocketTransportDecision` did not survive the
  merge, so `src/conformance/websocket_binding.rs` cannot simply follow the move.
- **`arkret_models_crypto::run_security_transaction_resilience_fixture`.** See
  blocker 3.
- **`arkret_wire::run_authorization_lease_issuance_fixture`**
  (`src/conformance/authorization_lease_issuance.rs:23`). Same shape as
  blocker 3: the fixture runner is gone, the data model is not.
- **`ProfileId::{MLS_GOVERNANCE_BINDING_FULL_V1, ATTESTED_AUDIT_E2EE_V1,
  DISCLOSED_AUDIT_E2EE_V1}`.** Profiles retired; the conformance vectors that
  assert their behaviour have not been retired with them, and should be, by
  whoever retired the profiles.

### 9. `soland-services` is a dead dependency of cotest

`Cargo.toml` declares it. `grep -rw soland_services src/ tests/ crates/` returns
nothing. Its 167 errors are therefore 167 errors of compile-blocking that buy
cotest nothing.

It was **not** removed this round: doing so unilaterally is churn against a repo
another agent is mid-migration in, and `inkson`'s 271 would keep the root
package red regardless. Recorded so the decision gets made deliberately once
`inkson` clears.

---

## What the next round has to do

1. Re-run `cargo check --workspace --all-targets --no-default-features` once
   `inkson` and `soland-services` are green, and treat the resulting cotest
   error list as the real work queue. The current reading through the scratch
   oracle is 542 errors across 61 files (section 6), concentrated in
   `src/conformance/sidecar_vectors.rs` (72),
   `src/harness/event_builder.rs` (50) and `src/harness/client.rs` (45).
   Of those, 31 are blocked on handoff §4 (section 7) and the large majority of
   the rest are absent SDK surfaces (section 8), not cotest bugs.
2. Migrate `src/harness/event_builder.rs` and `src/harness/client.rs`. These are
   the root of most remaining Rust residue: `realm_bootstrap_event_batch` still
   authors a multi-Event Cell-precondition unit, and `client.rs` still polls a
   Seal frontier. Realm genesis is now one `ak.realm.create` Event whose
   `RealmGenesis` payload carries the initial policy inline.
3. Decide the authorization-lease question (see the coverage matrix gap) and
   finish `e2e/helpers/soland-api.ts` accordingly — the federation transport
   wrapper still sends `service_binding_ref` / `membership_frontier`, while
   `ak.peer.events.command.submit.v1` now takes the same `{ event }` body as the
   self endpoint.
4. Annotate `MembershipPayload` and `SpaceObject` literals with their generated
   types, or drop them from the generator's target list.
