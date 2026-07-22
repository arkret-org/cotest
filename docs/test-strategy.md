# cotest Test Strategy

`cotest` is a black-box Arkret server conformance suite. Each scenario starts
the server processes it needs, creates test actors through public APIs, and
asserts only public HTTP behavior plus limited `arkret-rust-sdk` smoke paths.

## Harness Model

- Single-server scenarios start one real server process and verify local
  account, space, repo, sync, media, and policy behavior.
- Multi-server scenarios start two or more real server processes and verify
  federation-facing behavior through public endpoints.
- Shared lifecycle and actor helpers live in `src/harness.rs`.
- Reusable fixture builders live in `src/fixtures/`. See the
  [Fixture builders](#fixture-builders) section below for the
  `TestActorBuilder` fluent API that replaces the per-scenario
  `register_account` + `dev_login` + `create_realm` boilerplate.
- The same module hosts [`EventTimeline`](#failure-event-timeline) — a
  rendered view of the harness's `transcript.ndjson` that panic hooks dump to
  stderr when a scenario assertion fails.
- Scenario logic lives in `src/scenarios/`; `tests/` stays as thin wrappers so
  the project remains the test harness, not a pile of ad hoc integration files.
- The harness now supports both local process spawning and Docker-backed SUT
  spawning from the same scenario code.
- `ArkretServer` is the one-instance lifecycle unit; `TestServerGroup` is the
  multi-instance lifecycle unit.
- In Docker mode, `TestServerGroup::multi` creates one isolated network per
  scenario group so federated tests exercise real cross-container addressing
  instead of host-local shortcuts.
- Result presentation is part of the harness contract now: the scripted runner
  writes a stable Markdown/JSON report surface plus a redacted HTTP transcript
  under `artifacts/`.

## Current Suite Map

### Single-Server

- `service_surface`: health, service description, sync/directory/index describe
  endpoints, and required operation advertisement.
- `api_contracts_auth`: error envelopes, invalid JSON, account register/login,
  logout, and contact edge cases.
- `collaboration_workflow`: account bootstrap, space lifecycle, member add,
  message send, sync, and index projection.
- `delivery_media`: device key upload/query/claim, to-device delivery, blob
  upload/download, range, hash validation, anti-enumeration, and query-string
  auth rejection.
- `events_backfill`: event creation, timeline reads,
  and missing-event recovery surfaces.
- `identity_directory_index`: identity describe/resolve/document/log/receipt,
  directory discoverability/privacy, export, audit, notifications, and inbox
  behavior.
- `authz_policy_presence`: grant lifecycle, policy check contract, presence,
  push device registration, and ICE config behavior.
- `interaction_models`: message revision/redaction, reactions, read markers,
  subscriptions, entity CRUD, relations, and view projections.
- `schema_policy_realtime`: schema registry, policy documents, typing
  ephemerals, push rules, and WebRTC signaling sessions.
- `extension_surface_gaps`: executable checks for current applet/agent surface
  gaps so missing routes are tracked by tests instead of ignored placeholders.
- `protocol_payloads`: payload envelope, encrypted content, receipts, and
  protocol object acceptance.
- `space_permissions`: membership, owner-only mutation, deleted-space behavior,
  non-member denial, and private visibility policy checks.
- `conformance_fixtures`: offline spec-owned artifact suites for Event
  Envelope, encoding, redaction, capability, state resolution, sync,
  federation, registry drift, OpenAPI operation IDs, non-HTTP bindings, and
  privacy/security semantics.

### Multi-Server

- `federation_readiness`: remote service discovery and basic cross-instance
  wiring checks.
- `federation_contract`: transaction/push/pull/actor signature verification style contract and
  invalid-input behavior.
- `federation_collaboration`: cross-server membership, remote message
  propagation, sync visibility, and federated projection behavior.

## SDK Usage Policy

- Use `arkret-rust-sdk` for typed protocol objects, commit construction, and
  generic client smoke coverage.
- Prefer raw HTTP assertions for authoritative server-contract checks when the
  current SDK wire model lags the server's live JSON surface.

## Execution

```powershell
$env:COTEST_SUT_MANIFEST = "..\soland\Cargo.toml"
cargo test --tests -- --nocapture
```

Recommended scripted entrypoints:

```powershell
.\scripts\run-cotest.ps1 -Runtime process
.\scripts\run-cotest.ps1 -Runtime process -Profile fast-smoke
.\scripts\run-cotest.ps1 -Runtime process -Profile release-gate
.\scripts\run-cotest.ps1 -Runtime process -Profile full-nightly
.\scripts\run-cotest.ps1 -Runtime process -Profile dual-soland
.\scripts\run-cotest.ps1 -Runtime docker -BuildImage
```

The runner stores raw logs, a redacted request/response transcript, and
Markdown/JSON summaries under `artifacts/`. `artifacts/latest/summary.md` is
the primary result view for a completed run.
`artifacts/latest/coverage-matrix.json` and
`artifacts/latest/unresolved-gaps.json` are the machine-readable release-gate
artifacts.

CI profile selection lives in `config/ci-profiles.json`. `fast-smoke` runs a
small local feedback set, `release-gate` is the local milestone gate, and
`full-nightly` runs all tests. Coverage is grouped by conformance profiles such
as `ak.profile.core_event_store.v1`, `ak.profile.chat_mvp.v1`, and
`ak.profile.principal_server_events_api.v1`. The runner emits `ci-profile.*`,
`coverage-gate.*`, `release-gate.*`, `spec-sync-gate.*`, and
`secret-scan.*` artifacts and can fail on coverage regressions with
`-FailOnCoverageRegression`.

Selective profiles use structured `cargo_tests` entries with both `target` and
`filter`. The runner emits `cargo test --test <target> ...` for those entries;
it never expands a selective profile to `cargo test <filter> --tests`.
An opt-in ignored case sets `include_ignored: true` on its own entry; quarantine
entries use the exact `test_target` plus `test_filter` pair.
`all` and `full-nightly` intentionally remain one `--tests` invocation. Run
`scripts/test-cotest-planner.ps1` for the no-build planner regression gate,
`run-cotest.ps1 -Profile <profile> -PlanOnly` to inspect commands, or add
`-ValidateProfile` to require each filter to match exactly one listed test.

`dual-soland` is a local matrix profile, not a remote workflow. It delegates to
`run-joint-e2e.ps1 -DualSoland -RunProfile joint-full -Grep "cross-server.federation"`,
starts alpha/beta soland on separate ports, starts alpha/beta inkson when the
runner owns the web servers, and injects `COTEST_SOLAND_ALPHA_*`,
`COTEST_SOLAND_BETA_*`, `COTEST_INKSON_ALPHA_BASE_URL`, and
`COTEST_INKSON_BETA_BASE_URL` for federation specs.

The local hygiene gate is `scripts/run-hygiene.ps1`. It runs `cargo deny check`,
`typos`, and `cargo audit`, then records `raw.log`, `summary.json`,
`summary.md`, and per-tool stdout/stderr logs under
`artifacts/hygiene/<timestamp>/`. This is intentionally local-only; it does not
publish packages, tags, releases, or remote workflow artifacts.

The latest recorded local protocol release gate is
`artifacts/runs/20260525-055932`: 28 passed, 0 failed, coverage gate passed,
secret scan passed, and `mock-parity-allowlist.json` remained empty. The
human-readable evidence is tracked in `docs/release-evidence-0.9.0.md`.

## Joint UI E2E

The Rust suites above remain the authoritative API/protocol conformance layer.
Browser-level user simulation is intentionally separate and lives under
`e2e/`, with `scripts/run-joint-e2e.ps1` as the local entrypoint.

The joint E2E runner currently targets the first live-product slice:

- start or attach `soland`
- optionally start `soland` from a built Docker image with
  `-SolandRuntime docker`; this is the preferred release-quality joint e2e
  path because Playwright drives the packaged server shape instead of a local
  `cargo run` child
- start or attach `inkson` web
- start or attach `coauth`; `scripts/run-cotest.ps1 -Profile joint` enables
  `-StartCoauth` by default so the local promoted profile always exercises the
  soland + coauth + inkson topology. Direct `run-joint-e2e.ps1` runs may still
  omit coauth for targeted soland-only debugging. `-StartCoauth` generates a
  fresh coauth YAML config, starts ephemeral Docker PostgreSQL, runs migrations,
  and wires soland's OAuth/session-grant introspection URLs and static service
  bearers
- run Playwright tests with multiple isolated browser contexts
- save step screenshots, traces, videos, HAR, console/network JSONL, JUnit,
  HTML report, and service logs under
  `artifacts/runs/<timestamp>/joint-e2e/`
- copy the latest run to `artifacts/latest/joint-e2e/`

The smoke spec covers environment health, invalid server URL UI handling,
coauth discovery/topology, coauth metadata failure UI handling, live invalid
session-grant rejection, generated-user registration through the product
account form, Alice/Bob isolated dev-login sessions, contact request/acceptance,
private Space lifecycle administration, bidirectional timeline messages with
edit/redaction, permission-denied UI/API paths, session refresh/logout/revoked
bearer behavior, and Alice creating a live Space and persisting a message.

Phase 5 adds focused product-surface specs that target inkson UI features
that the smoke matrix does not exercise:

- `onboarding.spec.ts` walks `/onboarding` through DID method, handle, device,
  and recovery steps, exercises the `onboarding-progress` tabs, and asserts
  `onboarding-finish` routes to the dashboard.
- `directory-tabs.spec.ts` covers the protocol-objects, spaces, organizations,
  actors, and handles directory tabs plus the four-axis search policy banner
  and contact tooling form.
- `consent-strand.spec.ts` drives the `consent-grant-demo` card in
  `/settings/privacy`, validating empty-input feedback and the Move submission
  status for both `consent-grant-submit` and `consent-revoke-submit`.
- `quarantine-smoke.spec.ts` renders `/quarantine`, exercises
  `quarantine-refresh-button`, asserts `quarantine-status` or
  `quarantine-empty` is present, and fills the reject-reason input.
- `chat-interactions.spec.ts` exercises the `/chat/:space_id` view: send,
  open the reaction picker, render `chat-reactions`, open the reply banner,
  and post a reply that renders `chat-reply-indicator`.
- `failure-paths.spec.ts` route-mocks `POST /_arkret/self/events` to return 500,
  asserts `chat-message-error` and `chat-retry-button` appear, clears the
  mock, and confirms `chat-retry-button` recovers the send.
- `notifications-smoke.spec.ts` renders `/notifications`, cycles the grouping
  segmented control, exercises `toggle-archived`, `refresh-notifications`,
  `mark-all-read`, and asserts the muted/empty state.
- `mobile-core.spec.ts` adds a mobile login error path and a mobile nav-drawer
  tour covering `mobile-directory-nav-button`, `mobile-settings-nav-button`,
  `mobile-topbar-notifications-button`, and `mobile-theme-toggle`.
- `visual-baseline.spec.ts` adds desktop baselines for `dashboard-panel`,
  `directory-panel`, `settings-panel`, `notifications-panel`, and 390x844
  mobile baselines for `mobile-shellbar` and `mobile-nav-drawer`.

The mobile spec is tagged `@mobile` and runs only under the `mobile-chrome`
project. It validates the mobile shell navigation, authenticated connect state,
Space creation, timeline message send, and a Space Admin screenshot path.

The visual baseline spec is tagged `@visual` and runs only under the
`visual-chrome` project. It captures controlled baseline images for the login
panel, timeline message state, permission-denied Space lifecycle state, and
Space Admin. The runner writes these files under
`artifacts/runs/<timestamp>/joint-e2e/visual-baselines/` with
`visual-baselines.md` and a hash manifest.

The coauth/soland test mapping is fixed by the runner:

- soland audience/service DID: `did:webvh:z6mkfixture:soland.joint-e2e.local`
- coauth service/issuer DID: `did:webvh:z6mkfixture:coauth.joint-e2e.local`
- coauth publishes soland under `arkret.principal_servers`
- soland introspects OAuth bearer tokens at `<coauth>/oauth/introspect`
- soland introspects session grants at
  `<coauth>/_arkret/gate/account/session-grants/introspect`
- the static bearer values are local E2E-only defaults and never exposed to the
  browser
- event proof mode: `COTEST_EVENT_PROOF_MODE` selects the envelope proof the
  helpers sign with (`detached-jws` default = real detached-JWS fixture;
  `dev-proof` = legacy development placeholder, dev builds only), and
  `COTEST_FORBID_DEV_PROOF=1` hard-fails any dev-proof selection so
  production-shaped runs cannot regress onto the placeholder (implementation:
  `e2e/helpers/soland-api.ts` `eventProofMode()`)

Recommended local run:

```powershell
.\scripts\run-cotest.ps1 -Profile joint
.\scripts\run-cotest.ps1 -Runtime docker -BuildImage -Profile joint
.\scripts\run-joint-e2e.ps1 -SkipNpmInstall
.\scripts\run-joint-e2e.ps1 -SolandRuntime docker -BuildSolandImage -RunProfile joint-smoke
.\scripts\run-joint-e2e.ps1 -SolandRuntime docker -BuildSolandImage -SkipInkson -RunProfile joint-smoke -PlaywrightProject chromium -Grep "soland /_arkret/describe"
.\scripts\run-joint-e2e.ps1 -StartCoauth -SkipNpmInstall
.\scripts\run-joint-e2e.ps1 -StartCoauth -RunProfile joint-smoke -SkipNpmInstall
.\scripts\run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall
.\scripts\run-joint-e2e.ps1 -PreflightOnly -StartCoauth -CoauthPostgresUrl <dsn>
.\scripts\run-joint-e2e.ps1 -RunnerSelfTest
.\scripts\run-cotest.ps1 -Profile dual-soland
.\scripts\run-joint-e2e.ps1 -StartMockMimiFacade -Grep "mock-mimi-facade"
```

Omit `-SkipNpmInstall` on a fresh checkout so the script installs the local
Playwright dependencies in `e2e/`.

The runner performs a preflight before starting services: Node/npm/npx,
Playwright config/package/browser registry, default cargo/dx startup tools,
Docker daemon/image availability when `-SolandRuntime docker` is used, and
Docker/coauth/PostgreSQL image availability when `-StartCoauth` is used.
Prebuilt Coauth, Starid, and Teabay binaries must be at least as new as the
tracked Rust/build inputs in their repository and `arkret-rust-sdk` dependency;
stale binaries fail before any service starts. `-PreflightOnly` runs these
checks without starting the stack. `-RunnerSelfTest` exercises stale/fresh
classification and managed-process exit reporting without starting the stack.
The preflight is written to `preflight.json` and `preflight.md`.

`joint-smoke` and `joint-full` currently run the Chrome project; scenario tags
and profiles select the coverage after the separate mobile/visual smoke projects
were retired. Release gate integration calls the joint smoke through the Chrome
project so CI can use Playwright-managed browser installation.

At the end of a run, the harness checks every managed process and container
before cleanup. An early exit forces the run to fail and is reported once in
`managed-service-failures.json` and `managed-service-failures.md`, including the
service name, exit code, and log paths. This distinguishes an infrastructure
crash from the downstream Playwright `ECONNREFUSED` failures it may cause.

`joint-smoke` defaults to `--grep @fully-implemented` so fixme-tagged
placeholders pending server-side feature work do not block the smoke
profile. An explicit `-Grep ...` overrides the auto-filter. Use the tag
`@fully-implemented` on `test.describe(...)` (or individual tests) once a
spec is wired end-to-end against real services.

`scripts/run-cotest.ps1 -Profile release-gate` now invokes joint smoke as an
additional release-gate check and writes `joint-smoke-gate.*`. Use
`-SkipJointSmokeGate` only for local protocol-only release-gate debugging.

Dual-soland runs write both `service-gaps.md` and `service-traces.md` under the
joint artifact directory. `service-traces.md` indexes each alpha/beta soland
trace file plus stdout/stderr and command logs, so projection and federation
failures can be debugged without reconstructing paths from HAR files.

### Mock services

`run-joint-e2e.ps1` can spin up nine in-process mock services under
`e2e/mocks/` to cover spec sections that depend on external infrastructure.
Toggle them individually (`-StartMockIdp`, `-StartMockEmail`,
`-StartMockWitness`, `-StartMockAuditAgent`, `-StartMockPolicyServer`,
`-StartMockPushGateway`, `-StartMockAppletRegistry`, `-StartMockTspEndpoint`,
`-StartMockMimiFacade`) or all at once with
`-StartMocks`. Specs read the live base URLs via the helpers in
`e2e/helpers/env.ts` (`mockIdpBaseUrl()`, `mockEmailBaseUrl()`,
`mockWitnessBaseUrl()`, `mockAuditAgentBaseUrl()`, and the matching helpers
for policy, push, applet, TSP, and MIMI).

When `-StartCoauth -StartMockEmail` are both enabled, the generated Coauth
config uses the `email.http_webhook` provider with the mock email
`/mock/email/verification/send` endpoint. This keeps joint runs local-only and
prevents SMTP/sendmail providers from being exercised by email verification
paths. The mock endpoint accepts both its native token payload and Coauth's
generic outbound email webhook payload.

Witness quorum specs can pass extra witness DIDs with
`-MockWitnessExtraDids "did:webvh:z6mkfixture:witness-b.local,did:webvh:z6mkfixture:witness-c.local"`.
The runner starts one mock witness process per DID and exports both the primary
single-witness env vars and the quorum lists
`COTEST_MOCK_WITNESS_QUORUM_BASE_URLS` /
`COTEST_MOCK_WITNESS_QUORUM_DIDS`. Specs should use
`mockWitnessQuorumBaseUrls()` and `mockWitnessQuorumDids()` when `quorum > 1`.

| mock | covers spec sections | key endpoints |
|------|---------------------|---------------|
| `mock-idp.mjs` | S4/S7 OIDC onboarding | `/.well-known/openid-configuration`, `/jwks`, `/authorize` (PKCE), `/token`, `/scenarios` (bind sub/email or force OIDC error), `/inspect` |
| `mock-email.mjs` | S3 third-party invite, S7 email onboarding | `/mock/email/verification/send` (with `ttl_seconds` + `body_html`), `/mock/email/verification/inbox?to=`, `/mock/email/verification/claim` (returns 410 on expiry, 409 on double-consume), `/inspect` |
| `mock-witness.mjs` | S9 did:webvh rotation | `/mock/witness/sign` (enforces `prev_entry_hash` chain, entry-number monotonicity, `entry_timestamp` staleness vs `MOCK_WITNESS_STALE_SECONDS`), `/mock/witness/policy`, `/mock/witness/health` test hook, `/inspect` |
| `mock-audit-agent.mjs` | S25 audited E2EE / `ak.audit.accessed` | `/_arkret/self/audit-agent/identity` (DID + MLS KeyPackage stub), `/events`, `/invite` (auto-acks with signed `ak.audit.accessed`), `/accessed`, `/inspect`, `/jwks` (Ed25519) |
| `mock-policy-server.mjs` | authz policy server / obligation transcript | `/_arkret/self/policy/check`, `/_arkret/self/policy/health`, `/scenarios`, `/inspect`, `/jwks` |
| `mock-push-gateway.mjs` | notification push / blind wake | `/_arkret/edge/push/register-device`, `/_arkret/edge/push/notify`, `/mock/push/inbox`, `/scenarios`, `/jwks` |
| `mock-applet-registry.mjs` | applet manifest / bot DID / ghost actor | `/_arkret/edge/applet/register`, `/_arkret/edge/applet/:id/ghost-actor`, `/identity`, `/inspect`, `/jwks` |
| `mock-tsp-endpoint.mjs` | TSP relationship bootstrap / message ACK | `/tsp/relationship-bootstrap`, `/tsp/message`, `/tsp/inbox`, `/tsp/outbox`, `/identity`, `/inspect` |
| `mock-mimi-facade.mjs` | MIMI facade join / pairwise DID / fallback / quarantine | `/mock/mimi/join-requests`, `/mock/mimi/approve`, `/mock/mimi/outbound`, `/mock/mimi/inbound`, `/identity`, `/inspect` |

`e2e/tests/harness/mocks-selftest.spec.ts` is the contract pin for these
mocks. It is tagged `@fully-implemented` so the `joint-smoke` profile runs
it automatically; each case skips itself when the corresponding mock is
not started for the current run.

`scripts/promote-fixme.ps1` promotes a placeholder after the backing feature is
implemented and now requires `-FeatureId`, `-PassedSpecCommand`, and
`-EvidencePath` per `docs/fixme-promotion-checklist.md`.
`scripts/demote-test.ps1` is the reverse shim: it turns a specific
Playwright `test(...)` line into `test.fixme(...)` and inserts a FIXME reason
comment for temporary local regression containment.

## Per-test state isolation

CT-12 (2026-05-18): cotest already gives each scenario complete state
isolation through the per-spawn lifecycle in `ArkretServer`:

- `ArkretServer::spawn*` allocates a fresh `127.0.0.1:<free-port>`, a
  fresh `temp_dir().join("cotest-{name}-{port}-blobs")` blob root, and a
  fresh `did:web:{name}.cotest.local` service DID per call.
- `soland` keeps `AccountRecord`, `SpaceMetaRecord`, and
  `ProjectionState` in process-local memory — there is no shared database
  or filesystem anchor that survives the per-test process drop.
- `Drop for ArkretServer` kills the spawned child (or removes the docker
  container) and deletes the blob root.
- `TestServerGroup::multi` extends the same per-process isolation across
  every node in a federation scenario.

That means a fresh `ArkretServer::spawn(label)` is already equivalent to
"per-test fresh DB / state snapshot" — there is no shared `AccountRecord`
or `SpaceMetaRecord` to snapshot and restore because the records never
outlive the spawned process. The only process-global state cotest itself
owns is the monotonic `NEXT_EVENT_SEQ` counter (correct under
concurrency), the OnceLock-installed tracing subscriber in
`src/transcripts.rs` (one-time global init; per-thread scenario binding),
and the artifact `transcript.ndjson` referenced by
`COTEST_TRANSCRIPT_PATH` / `COTEST_ARTIFACT_DIR` (line-atomic appends,
interleaved when several tests run in parallel).

`src/fixtures/scaffold.rs` ships `TestScaffold::fresh(label)` and
`TestScaffold::fresh_multi(label, count)`, ergonomic wrappers over
`ArkretServer::spawn` / `TestServerGroup::multi` that suffix the label
with a `p<pid>-<seq>` token. The suffix guarantees that two parallel
runs of the same scenario produce distinct service DIDs, transcript
files, per-service log files, and on-disk blob roots without the
scenario author having to coordinate names.

Recommended migration cadence: when a scenario is touched for any other
reason, swap `ArkretServer::spawn(label)` →
`TestScaffold::fresh(label).server()`. Drop the surrounding
`#[serial]` only after auditing that the test does not depend on the
process-shared `transcript.ndjson` ordering — most scenarios do not.

### Running in parallel

```powershell
cargo test --test federation_readiness --test conformance_fixtures `
    --test transcript_smoke -- --test-threads=4
```

The three test binaries above currently run clean under
`--test-threads=4` (verified 3x on 2026-05-18: 71 tests, 0 failures, 0
flakes). The conformance suites are offline so they would parallelise
even without CT-12; `federation_readiness` is included because its
`TestScaffold::fresh_multi("federation-ready", 2)` exercises the
multi-node scaffold and proves the unique-label suffix prevents service
DID collisions when multiple parallel test threads ask for the same
label.

Scenarios that have NOT yet been migrated keep their `#[serial]` mark
because their integration test wrappers in `tests/` use
`serial_test::serial` to gate against the historical assumption of a
single SUT per `cargo test` process. Once `TestScaffold::fresh` becomes
the default entry point, the `#[serial]` mark can be removed at the
wrapper level as well.

## Fixture builders

`src/fixtures/builders.rs` exposes `TestActorBuilder`, a fluent fixture for
the common "register actor + login + pre-seed spaces" preamble. Replaces:

```rust
let bob = server
    .register_client("did:web:bob.example", "@bob", "dev_bob")
    .await?;
let bob_realm = bob.create_realm("Some Space").await?;
```

with:

```rust
let bob = TestActorBuilder::new(&server, "@bob")
    .with_did("did:web:bob.example")
    .with_device("dev_bob")
    .with_realm("Some Space")
    .create()
    .await?;
let bob_realm = bob.first_realm().expect("seeded realm");
let bob_client = bob.client(); // reuse existing TestActorClient API
```

Defaults the builder applies when fields are omitted:

- DID: `did:web:<bare-handle>.example` (handle's leading `@` stripped)
- primary device id: `dev_<bare-handle>`
- spaces: none (`with_realm` is opt-in)
- `with_key_package(n)` records the requested KeyPackage count on the
  returned `TestActor` for scenarios that want to assert provisioning shape;
  the harness does not yet expose a publish endpoint, so no MLS key material
  is produced.

`with_device` can be called multiple times: the first call sets the primary
device id, additional calls populate `TestActor.additional_devices` for
scenarios that want to drive multi-device strands. Scenarios that need a
working second-device client should call
`server.demo_client(&actor.did, &device_label)` against the recorded labels.

Two scenarios currently use the builder as a worked example:
`src/scenarios/events_backfill.rs` and `src/scenarios/interaction_models.rs`.
Other scenarios continue to use `register_client` / `demo_client` directly —
migration is incremental and orthogonal to scenario logic.

## Failure event timeline

`src/fixtures/timeline.rs` exposes `EventTimeline`, a pretty-printable view
of the redacted ndjson transcript the harness writes via
`COTEST_TRANSCRIPT_PATH` / `COTEST_ARTIFACT_DIR`. Each row renders sender,
op_id (event_id or fallback HTTP request line), kind, status, depends-on
frontier (the `prev_refs` array on the event envelope), and payload digest.

`install_failure_dump_hook()` chains a panic hook that loads the transcript
from the env vars above and writes the rendered timeline to stderr before
delegating to the previously-installed hook. The hook is idempotent; scenario
entry points can call it unconditionally without leaking handlers.

When the harness is not configured with a transcript path the hook is a
no-op — the install still succeeds but no timeline is rendered, since there
is nothing on disk to read. Scripts that already set
`COTEST_ARTIFACT_DIR=artifacts/runs/<timestamp>` (e.g. `run-cotest.ps1`) pick
up the timeline automatically.

## R3 spec-coverage matrix

R3 introduced new wire surfaces (agent runtime, media token exchange,
recovery policy/receipt, handle canonicalization). The matrix below maps
each spec section to the cotest vectors that cover it, and identifies the
gap-coverage gaps deferred to R4.

| Spec section | Subject | cotest vector(s) | Stage |
|---|---|---|---|
| **§7 media binding** — `ak.realm.media_service.foci[]` shape | Realm declares a foci array | `e2e/realm/media_service_foci_round_trip.rs` | Active |
| **§8 handles** — RFC 8265 preparation + UTS #46 domains + authority-local UTS #39 collision index | Internationalized canonical handles are accepted; rewritable wire values are rejected; skeleton collisions are scoped by authority and namespace | `privacy-security-fixture.json` via `run_privacy_security_fixture_suite` | Active |
| **§9 agent** — FSM (Active/Paused/Deactivated) + pairing | Pause/resume/deactivate transitions; pairing window expiry; proof verification | `e2e/agent/fsm_transitions.rs`, `e2e/agent/pairing_window_expires.rs`, `e2e/agent/pairing_proof_invalid.rs`, `e2e/agent/verification_method_principal_mismatch.rs` | Active |
| **§9 agent** — actor-private event kinds | `ak.agent.draft.propose`, `ak.agent.action_request`, `ak.agent.action_{approve,reject}` are reducer_input=false | `e2e/agent/actor_private_events_not_reducer_input.rs` | Active |
| **§10 call.media** — token exchange | `ak.self.call.media.exchange.issue_token` round-trip; TTL gate; backend type enum reject | `e2e/call_media/token_exchange_round_trip.rs`, `e2e/call_media/token_ttl_exceeded.rs`, `e2e/call_media/unknown_focus_type_rejects.rs` | Active |
| **§10 call.media** — participant_binding | Canonical-bytes round-trip; issuer_kid validation; identity-string canonical form | `e2e/call_media/participant_binding_canonical.rs`, `e2e/call_media/token_issuer_unauthorised.rs`, `e2e/call_media/participant_identity_unrecognised.rs` | Active |
| **§11 media binding** — focus/session commit invariants | `session_focus_already_committed` reject; `e2ee_key_source_unauthorised` reject | `e2e/call_media/session_focus_already_committed.rs`, `e2e/call_media/e2ee_key_source_unauthorised.rs` | Active (some stubbed — see below) |
| **§13 recovery** — policy + receipt | Policy version monotonicity; receipt completeness; proof_kinds dispatch | `e2e/recovery/policy_round_trip.rs`, `e2e/recovery/receipt_emitted_on_complete.rs`, `e2e/recovery/policy_version_monotone.rs` | Active |
| **§13 recovery** — witness freshness | `recovery_witness_revoke_lagging` reject; per-arm proof verifier | `e2e/recovery/witness_revoke_lagging.rs` (basic shape), `e2e/recovery/per_arm_proof_verifier.rs` (stubbed) | Stubbed |
| **§14 errors** — strict-reject profile | `accountable_principals.strict_reject` toggle + reject behavior | `e2e/profile/strict_reject_toggle.rs`, `e2e/profile/strict_reject_audit_row.rs` | Active |

### Coverage gaps (deferred)

- **Per-arm recovery proof verification** — `RecoveryProofKind`
  arms (`DeviceQuorum`, `RecoveryUnlock`, `TrustedRecoveryService`,
  `PrincipalSigning`) are exercised at the structural level only. The
  cryptographic verifier per arm is stubbed in cotest because the SDK's
  verifier is itself a TODO(R3.1). When the SDK verifier lands, the
  stubbed vectors flip to active.
- **Live media-backend conformance** — call_media vectors cover protocol
  shapes and harness-facing behavior, but LiveKit / Mediasoup / Janus /
  Arkret-native media backend conformance remains gated on R4 and is
  documented through the current process/compose/docker runtime workflow.

### Vector ↔ error-code map

For each new error code introduced in R3, the canonical vector is:

| Error code | Vector |
|---|---|
| `pairing_request_expired` | `e2e/agent/pairing_window_expires.rs` |
| `proof_invalid` | `e2e/agent/pairing_proof_invalid.rs` |
| `verification_method_principal_mismatch` | `e2e/agent/verification_method_principal_mismatch.rs` |
| `agent_paused` | `e2e/agent/fsm_transitions.rs` (subtest: paused_rejects_write) |
| `agent_deactivated` | `e2e/agent/fsm_transitions.rs` (subtest: deactivated_terminal) |
| `approval_already_consumed` | `e2e/agent/approval_double_consume.rs` |
| `sidecar_create_denied` | `e2e/agent/sidecar_denied.rs` |
| `actor_kind_reducer_managed` | `e2e/agent/actor_kind_reducer_managed.rs` |
| `focus_mismatch` | `e2e/call_media/focus_mismatch.rs` |
| `unknown_focus_type` | `e2e/call_media/unknown_focus_type_rejects.rs` |
| `token_issuer_unauthorised` | `e2e/call_media/token_issuer_unauthorised.rs` |
| `participant_binding_invalid` | `e2e/call_media/participant_binding_canonical.rs` (negative branch) |
| `participant_identity_unrecognised` | `e2e/call_media/participant_identity_unrecognised.rs` |
| `session_focus_already_committed` | `e2e/call_media/session_focus_already_committed.rs` |
| `e2ee_key_source_unauthorised` | `e2e/call_media/e2ee_key_source_unauthorised.rs` |
| `recording_artifact_pipeline_bypassed` | `e2e/call_media/recording_pipeline_bypassed.rs` |
| `focus_unavailable_for_client` | `e2e/call_media/focus_unavailable_for_client.rs` |
| `recovery_witness_revoke_lagging` | `e2e/recovery/witness_revoke_lagging.rs` |
| `handle_homograph_forbidden` | `ak.vector.identity.authority_local_skeleton_collision.v1` in `privacy-security-fixture.json` |
