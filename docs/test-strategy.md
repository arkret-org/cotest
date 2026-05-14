# cotest Test Strategy

`cotest` is a black-box Contrix server conformance suite. Each scenario starts
the server processes it needs, creates test actors through public APIs, and
asserts only public HTTP behavior plus limited `contrix-rust-sdk` smoke paths.

## Harness Model

- Single-server scenarios start one real server process and verify local
  account, space, repo, sync, media, and policy behavior.
- Multi-server scenarios start two or more real server processes and verify
  federation-facing behavior through public endpoints.
- Shared lifecycle and actor helpers live in `src/harness.rs`.
- Scenario logic lives in `src/scenarios/`; `tests/` stays as thin wrappers so
  the project remains the test harness, not a pile of ad hoc integration files.
- The harness now supports both local process spawning and Docker-backed SUT
  spawning from the same scenario code.
- `ContrixServer` is the one-instance lifecycle unit; `TestServerGroup` is the
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
- `federation_contract`: transaction/push/pull/verify-actor style contract and
  invalid-input behavior.
- `federation_collaboration`: cross-server membership, remote message
  propagation, sync visibility, and federated projection behavior.

## SDK Usage Policy

- Use `contrix-rust-sdk` for typed protocol objects, commit construction, and
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
.\scripts\run-cotest.ps1 -Runtime docker -BuildImage
```

The runner stores raw logs, a redacted request/response transcript, and
Markdown/JSON summaries under `artifacts/`. `artifacts/latest/summary.md` is
the primary result view for a completed run.
`artifacts/latest/coverage-matrix.json` and
`artifacts/latest/unresolved-gaps.json` are the machine-readable release-gate
artifacts.

CI profile selection lives in `config/ci-profiles.json`. `fast-smoke` runs a
small PR feedback set, while `full-nightly` runs all tests. Coverage is grouped
by conformance profiles such as `cx.profile.core_event_store.v1`,
`cx.profile.chat_mvp.v1`, and `cx.profile.principal_server_events_api.v1`. The
runner emits `ci-profile.*`, `coverage-gate.*`, and `secret-scan.*` artifacts
and can fail on coverage regressions with `-FailOnCoverageRegression`.

## Joint UI E2E

The Rust suites above remain the authoritative API/protocol conformance layer.
Browser-level user simulation is intentionally separate and lives under
`e2e/`, with `scripts/run-joint-e2e.ps1` as the local entrypoint.

The joint E2E runner currently targets the first live-product slice:

- start or attach `soland`
- start or attach `yougen` web
- optionally start or attach `coauth`; `-StartCoauth` generates a fresh coauth
  YAML config, starts ephemeral Docker PostgreSQL, runs migrations, and wires
  soland's OAuth/session-grant introspection URLs and static service bearers
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

Phase 5 adds focused product-surface specs that target yougen UI features
that the smoke matrix does not exercise:

- `onboarding.spec.ts` walks `/onboarding` through DID method, handle, device,
  and recovery steps, exercises the `onboarding-progress` tabs, and asserts
  `onboarding-finish` routes to the dashboard.
- `directory-tabs.spec.ts` covers the protocol-objects, spaces, organizations,
  actors, and handles directory tabs plus the four-axis search policy banner
  and contact tooling form.
- `consent-flow.spec.ts` drives the `consent-grant-demo` card in
  `/settings/privacy`, validating empty-input feedback and the Move submission
  status for both `consent-grant-submit` and `consent-revoke-submit`.
- `quarantine-smoke.spec.ts` renders `/quarantine`, exercises
  `quarantine-refresh-button`, asserts `quarantine-status` or
  `quarantine-empty` is present, and fills the reject-reason input.
- `chat-interactions.spec.ts` exercises the `/chat/:space_id` view: send,
  open the reaction picker, render `chat-reactions`, open the reply banner,
  and post a reply that renders `chat-reply-indicator`.
- `failure-paths.spec.ts` route-mocks `POST /api/v1/events` to return 500,
  asserts `chat-message-error` and `chat-retry-button` appear, clears the
  mock, and confirms `chat-retry-button` recovers the send.
- `notifications-smoke.spec.ts` renders `/notifications`, cycles the grouping
  segmented control, exercises `toggle-archived`, `refresh-notifications`,
  `mark-all-read`, and asserts the muted/empty fallback state.
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

- soland audience/service DID: `did:web:soland.joint-e2e.local`
- coauth service/issuer DID: `did:web:coauth.joint-e2e.local`
- coauth publishes soland under `contrix.principal_servers`
- soland introspects OAuth bearer tokens at `<coauth>/oauth2/introspect`
- soland introspects legacy session grants at
  `<coauth>/api/v1/session-grants/introspect`
- the static bearer values are local E2E-only defaults and never exposed to the
  browser

Recommended local run:

```powershell
.\scripts\run-joint-e2e.ps1 -SkipNpmInstall
.\scripts\run-joint-e2e.ps1 -StartCoauth -SkipNpmInstall
.\scripts\run-joint-e2e.ps1 -StartCoauth -RunProfile joint-smoke -SkipNpmInstall
.\scripts\run-joint-e2e.ps1 -StartCoauth -RunProfile joint-full -SkipNpmInstall
```

Omit `-SkipNpmInstall` on a fresh checkout so the script installs the local
Playwright dependencies in `e2e/`.

The runner performs a preflight before starting services: Node/npm/npx,
Playwright config/package/browser registry, default cargo/dx startup tools,
and Docker/coauth/PostgreSQL image availability when `-StartCoauth` is used.
The preflight is written to `preflight.json` and `preflight.md`.

`joint-smoke` currently runs the desktop smoke matrix. `joint-full` runs
desktop Chrome, mobile Chrome, and visual Chrome projects in the same artifact
run. Release gate integration calls the joint smoke through the Chromium
project so CI can use Playwright-managed browser installation.

`scripts/run-cotest.ps1 -Profile release-gate` now invokes joint smoke as an
additional release-gate check and writes `joint-smoke-gate.*`. Use
`-SkipJointSmokeGate` only for local protocol-only release-gate debugging.
