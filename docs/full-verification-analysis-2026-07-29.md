# Full verification analysis — 2026-07-29

## Scope

- Joint Playwright profile: `joint-full`
- Managed services: Coauth, two isolated Soland instances, Inkson, and all local mocks
- Agent journey: `federated-team-incident`, four persistent browser profiles, twelve checkpoints
- Evidence root: `artifacts/runs/`

This is a living report. Findings are recorded and classified before repair.

## Run 1 — joint-full baseline

- Run: `artifacts/runs/20260729-042314/joint-e2e`
- Result: blocked during preflight; no Playwright test executed
- Collection result: 0 tests in 0 files

### Blockers

| ID | Category | Severity | Evidence | Root cause | Repair |
| --- | --- | --- | --- | --- | --- |
| JF-H01 | Test drift | Blocking | Four suites import `withBroadcastEphemeralProof`, but `e2e/helpers/webrtc.ts` no longer exports it. Playwright reports four ESM `SyntaxError`s. | Commit `1be45252` removed the broadcast-ephemeral helper while migrating the distinct call Signal envelope contract. Existing presence, directory, discussion, and read-receipt consumers still use the broadcast contract. | Restore the broadcast-specific helper and its registered signer integration; keep the new encrypted Signal helper unchanged. Add collection validation by rerunning preflight. |
| JF-H02 | Harness/build consistency | Blocking | Coauth binary timestamp `2026-07-28T20:34:37.647Z`; tracked input `crates/storage-postgres/src/schema.rs` timestamp `2026-07-28T20:35:30.955Z`. | Coauth commit `b181c7f` landed while the parallel preparation build was in flight. The freshness gate correctly rejected an artifact that cannot prove it includes the new input. This is not a freshness-algorithm false positive. | Rebuild Coauth from the stable current HEAD, then rerun the unchanged freshness gate. |

### Non-blocking harness observations

| ID | Category | Evidence | Follow-up |
| --- | --- | --- | --- |
| JF-O01 | Harness efficiency | Parallel Rust builds repeatedly waited on the shared Cargo package-cache lock; preparation took about 14 minutes before preflight. | Measure after functional repair. Consider dependency-aware serialization or one workspace preparation phase only if the complete run shows material repeat cost. |
| JF-O02 | Harness observability | Playwright output is buffered by the runner, so live progress is unavailable after collection starts. | Keep as a separate harness improvement; do not mix it into product repairs. |
| JF-O03 | Toolchain warning | Node 26 reports that `module.register()` is deprecated while Playwright loads TypeScript. | Non-failing dependency warning; track separately from product behavior. |

## Repair batches

1. Restore test collection without reverting the encrypted Signal migration.
2. Rebuild Coauth after repositories stop changing and rerun `joint-full`.
3. Classify executed-test failures into harness/environment, test drift, implementation regression, and design/spec gap.
4. Register any confirmed design/spec gap as a separate large item under `arkret-spec/review/spec-open` before implementation.
5. Rerun `joint-full` to a stable report.
6. Execute and classify all twelve Agent Journey checkpoints, preserving screenshots and hard-check evidence.

## Run 2 — joint-full executed baseline

- Run: `artifacts/runs/20260729-043955/joint-e2e`
- Result: failure after 26 minutes
- Executed result: 160 passed, 69 failed, 22 skipped, 207 not run after the failure limit
- Managed service crashes: none

### Failure fingerprint aggregation

| Count | Fingerprint | Category | Root cause |
| ---: | --- | --- | --- |
| 34 | `quorum_unreachable: this service cannot issue the current authority set's proposal receipt` | Implementation regression | The durable control-seal coordinator revalidates a Realm anchor unit with the SDK `AnchorUnit` structural gate. That gate incorrectly requires `preconditions[]` to be empty, so valid genesis Control Moves with CAS preconditions are rejected after their atomic submit was accepted. The Realm never obtains a usable genesis Seal. |
| 26 | UI bootstrap waits for completion, screenshot says `no authorization lease is held ... first publication is blocked until the account is re-authorized` | Design/spec gap | Inkson correctly refuses to mint an authority lease locally, but the protocol registers no operation through which the authenticated client obtains an authority-issued `AuthorizationLease`. The real first-publication flow is therefore not executable. |
| 2 | `frontier_unavailable: accepted Control Events are still awaiting the durable control-seal coordinator` | Consequence | Same control-seal rejection as the 34-item group. |
| 1 | `Control Move requires seal_basis.leaves` | Test drift | A policy-server test submits a post-genesis Control Move without using the shared CBA preparation path. |
| 1 | Federation request contains retired top-level `actor_id` | Design/spec-gap consequence | The shared helper submits locally through Soland's legacy raw-Event compatibility branch. That branch cannot mint/store publication evidence, so the helper only has a bare Event when the now-strict federation surface requires `EventFederationSubmission {event, authorization_lease, ingress_receipts}`. This is another observable consequence of SG-01, not safely repairable with fabricated evidence. |
| 1 | MIMI admission lacks `ak.message.create` at `seal_ref` | Pending analysis | Isolated capability/basis mismatch; inspect after the control-seal repair removes shared noise. |
| 1 | DPoP hard-login equality assertion | Pending analysis | Isolated value mismatch; inspect the actual values after shared bootstrap repair. |
| 3 | Other visibility/value assertions | Pending analysis | Inspect individually after common blockers are removed. |

### Root-cause decision

The Realm anchor-unit failure is not a spec gap. `event-auth-state-resolution.md` §5 allows the
closed bootstrap unit to omit `seal_basis` and defines `preconditions[]` as part of a Control Move.
No clause requires anchor-unit preconditions to be empty. The SDK added that extra restriction,
while Soland's initial batch admission already accepts the same closed unit. Repair the shared SDK
validator and add an executable regression test.

The authorization-lease path is a confirmed design gap. Inkson's authority-lease module documents
the same missing operation and deliberately has no production caller for `install_lease`. A client
must not manufacture the lease because its proofs belong to the accepted authority set. This must
be registered and resolved in the canonical spec/operation/schema/OpenAPI stack before product code
can implement it.

The federation failure initially looked like a stale request-body helper, but inspection moved it
into the same large item. The peer endpoint is correctly strict. The source Event entered through
Soland's explicitly legacy raw-Event branch, which supplies no `AuthorizationLease` and therefore
causes no original `IngressReceipt` to be persisted. Rewrapping that Event in cotest would require
inventing both authority and ingress signatures and would invalidate the test. SG-01 must close the
first-publication path; the federation helper can then transport the actual evidence returned by
the origin.

## Large items / spec gaps

### SG-01 — No client acquisition path for first-publication authorization leases

- Status: confirmed; must be registered under `arkret-spec/review/spec-open`
- Impact: blocks real Principal bootstrap, all UI authoring, and the Agent Journey at its first
  durable publication checkpoint
- Required design closure:
  - select the issuing authority and trust surface;
  - register a typed operation and HTTP binding;
  - bind actor, device, exact scope/action, accepted basis, authority set, expiry, holder proof,
    audience, challenge, and replay protection;
  - define renewal/re-authorization, revocation, uncertain-outcome, and offline behavior;
  - add conformance vectors and profile obligations;
  - implement the shared SDK DTO/client, authority issuer, Inkson install/refresh lifecycle, and
    Soland verification.

Run 1's two collection/build blockers were covered by existing contracts and remain non-spec items.

## Existing FIXME audit

Commit `7926d785` already completed the requested value audit before this run:

- 41 Playwright `test.fixme` definitions were reviewed;
- 21 empty prose-only placeholders were deleted;
- 3 promises for unpublished extension operations were deleted;
- 17 executable, metadata-complete fixmes were retained;
- `e2e/scripts/check-fixme-quality.mjs` now rejects empty callbacks and missing
  `@blocking-on`, `@user-promise`, or `@expected-live-by` metadata.

The retained groups and rationale are recorded in `docs/playwright-fixme-audit.md`. They should not
be deleted merely to lower debt: each contains executable assertions against a concrete
cross-repository implementation gap.

## Final result

Pending.
