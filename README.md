# cotest

> **Spec target**: the sibling [cokret-spec](../cokret-spec) checkout used by
> the current run; cotest does not pin a stale README hash.

`cotest` is an out-of-repository black-box Cokret server test harness modeled
after Complement. It starts real server processes or real server containers,
drives public HTTP endpoints, and uses `cokret-rust-sdk` where typed protocol
helpers and client smoke coverage are useful.

## Pre-commit hook setup

After cloning, enable the project's pre-commit hooks:

```sh
git config core.hooksPath .githooks
```

The hook runs `cargo fmt --all -- --check` and `cargo clippy --no-deps -- -D
warnings` on staged Rust changes. If `.githooks/pre-commit` is missing on
a branch, copy it from
[`cokret-rust-sdk`](https://github.com/cokret/cokret-rust-sdk) and
adapt to your local toolchain.

The current default server under test is the sibling
`../soland/Cargo.toml` checkout.

## Realm vs Space

- **Realm:** security boundary — membership, capability, E2EE, federation.
- **Space:** navigation container — board, list, section, calendar bucket.

The harness constructs fixtures with current v1 wire names only:
`ck.realm.*` for boundary events and `ck.space.*` for container events.

## Protocol Review Closures

The current harness tracks the sibling `cokret-spec` checkout and includes:

- **12 new security-closure vectors** (`ck.vector.*` from
  `security-closure-vectors.json`) driven through a runner contract
  `{given_state, operation}` → assertions on
  `{transcript, expected_state_transition, expected_external_response,
  expected_audit_reason}`.
- **schema-validation-fixture runner** — positive and negative cases
  exercised against `schema_ref`.
- **Round R4 literal-scanner rules** — bad DID method segments,
  string-payload `ck.self.events.stream.subscribe` usage, `ck.cross_signing.publish`
  without `expected_previous_generation`, and
  `compute_audit_policy_version_digest` calls with fewer than 4 arguments.
- **Drift-validator allowlists extended** for the new capability action
  `ck.morph.create`, the three new error codes
  (`delivery_binding_stale` / `_handed_over` / `historical_only`), the
  `ck:space:` id-kind in `object_ref`, and the new schema `$defs`
  (`EventsSubscribeFrame`, `SnapshotBootstrap`, the three
  `EventsFrontier*Response` variants, `PolicyCheck{Request,Response}`,
  `FederationServiceBindingRef`, `EventsSubmit{Batch,Federation}Request`,
  and the `third_party_invite` / `space_state_transition_payload` /
  `space_object_tombstone_payload` payloads).

See [docs/test-strategy.md](./docs/test-strategy.md) and
[docs/complement-map.md](./docs/complement-map.md) for the harness plan and
Complement mapping.

## Quick Start

Recommended entrypoints:

```powershell
.\scripts\run-cotest.ps1 -Runtime process
.\scripts\run-cotest.ps1 -Runtime process -Profile fast-smoke
.\scripts\run-cotest.ps1 -Runtime process -Profile dual-soland
.\scripts\run-hygiene.ps1
.\scripts\demote-test.ps1 -SpecPath e2e\tests\path\spec.ts:42 -Reason "GAP-Px-yyy blocked by backing feature"
.\scripts\promote-fixme.ps1 -SpecPath e2e\tests\path\spec.ts:42 -FeatureId cotest#local-feature `
  -PassedSpecCommand "npx playwright test --config playwright.config.ts --project chromium --grep name" `
  -EvidencePath artifacts\latest\joint-e2e\playwright-report -NewBody $body
.\scripts\run-compose.ps1
.\scripts\build-soland-image.ps1
.\scripts\run-cotest.ps1 -Runtime docker -SutImage cotest-soland:latest
.\scripts\run-cotest.ps1 -Runtime docker -BuildImage -Profile joint
.\scripts\run-joint-e2e.ps1 -SolandRuntime docker -BuildSolandImage -SkipYougen `
  -RunProfile joint-smoke -PlaywrightProject chromium -Grep "soland /_cokret/describe"
```

- `process` mode is the fast local path and spawns the SUT with `cargo run`.
- `.\scripts\run-compose.ps1` runs the process-mode `compose` profile and can
  attach live `coauth`, `floria`, `sodmin`, `yougen`, or `teabay` services
  through base URLs or managed service commands.
- `docker` mode is the Complement-style path and spawns the SUT with
  `docker run` while Rust tests stay host-side.
- Joint Playwright e2e can also run soland from the built image with
  `run-joint-e2e.ps1 -SolandRuntime docker`, including a `-SkipYougen` mode for
  soland-only wire/API probes.
- `.\scripts\build-soland-image.ps1` builds the default SUT image from
  `soland` plus the sibling `cokret-rust-sdk` checkout using the workspace
  root as Docker build context.
- Each scripted run writes `raw.log`, `transcript.ndjson`, `summary.json`,
  `summary.md`, `summary.html`, `junit.xml`, coverage/gap reports, and
  CI profile, coverage gate, secret scan, and per-service logs to
  `artifacts/runs/<timestamp>/`, then copies the latest set to
  `artifacts/latest/`.
- `.\scripts\run-hygiene.ps1` is the local hygiene gate for dependency
  advisories/licensing (`cargo deny check`), spelling drift (`typos`), and
  RustSec vulnerabilities (`cargo audit`). It writes `raw.log`, `summary.json`,
  `summary.md`, and per-tool stdout/stderr logs to
  `artifacts/hygiene/<timestamp>/`.
- `.\scripts\demote-test.ps1` is the inverse of `promote-fixme.ps1`: it
  temporarily converts a concrete Playwright `test(...)` line into
  `test.fixme(...)` and inserts the reason comment required by the local
  fixme debt discipline.
- `.\scripts\promote-fixme.ps1` refuses to remove `.fixme` without a backing
  feature id, one local single-spec pass command, and one screenshot/HAR/trace
  artifact path. See `docs/fixme-promotion-checklist.md`.

The primary human-readable report is
`artifacts/latest/summary.md`.

The local hygiene report is `artifacts/hygiene/<timestamp>/summary.md`.

## Recording manual flows into one-key replay (codegen → smoke)

If you keep hand-driving the same browser flow (register → login → create a
Realm → …) to verify a change, stop repeating it by hand. Record it **once** as
a Playwright spec, then replay it with one command and keep the screenshots/trace
as evidence. This is the highest-ROI automation step: the recorder emits
maintainable TypeScript over `getByTestId`/`getByRole`, not a brittle pixel
recording, and the resulting spec doubles as a regression gate the AI-driven
exploratory tools can never be.

### 1. Bring the stack up, then record

`playwright codegen` needs a running yougen (and the soland/coauth it talks to).
Start the stack the usual way, then point the recorder at it:

```powershell
# Terminal A — start soland + coauth + yougen and leave them running.
& "D:\Works\cokret\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -KeepAlive

# Terminal B — record. Default yougen URL is http://127.0.0.1:4527; override
# with YOUGEN_BASE_URL if your run prints a different one.
cd D:\Works\cokret\cotest\e2e
npx playwright codegen http://127.0.0.1:4527
```

Drive the flow by hand in the popup browser. The Inspector writes the
corresponding TypeScript live; copy it out when you are done.

> If `-KeepAlive` is not available on your branch, start the services with your
> usual local commands (or `run-compose.ps1`) and codegen against the printed
> yougen URL — codegen only needs a reachable base URL.

### 2. Save it as a spec, following the e2e conventions

Drop the recording under the matching domain in `e2e/tests/<domain>/` (e.g.
`identity/`), or under `e2e/tests/smoke/` for a fast cross-cutting happy-path.
Then refit the raw recording onto the harness conventions
(see [`e2e/scenarios/README.md`](./e2e/scenarios/README.md)):

- Replace any hardcoded handle/email with `uniqueUser("smoke-register")` so the
  spec is re-runnable and does not collide across runs (helpers in
  [`e2e/helpers/users.ts`](./e2e/helpers/users.ts)).
- Open the page via `openUserPage(browser, user)` instead of a bare
  `browser.newPage()` when you want the harness's diagnostics (console + network
  HAR) captured automatically.
- Prefer `getByTestId(...)` selectors (the recorder picks these up from yougen's
  `data-testid`s); fall back to `getByRole`. Avoid nth/CSS positional selectors.
- `test.describe.configure({ mode: "serial" })` when later steps depend on
  earlier ones.
- Capture key views with `stepShot(page, testInfo, "after-register")` at each
  meaningful phase (helper in
  [`e2e/helpers/screenshots.ts`](./e2e/helpers/screenshots.ts)); it writes a
  full-page PNG under the run's `screenshots/` and attaches it to the report.

```ts
import { expect, test } from "@playwright/test";
import { openUserPage, uniqueUser } from "../../helpers/users";
import { stepShot } from "../../helpers/screenshots";

test.describe.configure({ mode: "serial" });

test("register → create realm smoke", async ({ browser }, testInfo) => {
  const user = uniqueUser("smoke-register");
  const session = await openUserPage(browser, user);
  try {
    // …codegen-recorded steps, with literals swapped for `user.*`…
    await stepShot(session.page, testInfo, "after-register");
    // …create a Realm…
    await stepShot(session.page, testInfo, "realm-created");
  } finally {
    await session.close();
  }
});
```

### 3. Replay with one command + collect evidence

```powershell
# Whole suite (or a domain / single spec via -Grep), with services managed for you.
& "D:\Works\cokret\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -RunProfile joint-full
& "D:\Works\cokret\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -Grep "smoke/"

# Or directly against an already-running stack:
cd D:\Works\cokret\cotest\e2e
npm test                 # headless
npm run test:headed      # watch it click
```

Evidence lands in `artifacts/runs/<ts>/joint-e2e/`:
`playwright-report/` (HTML with trace/video/failure screenshot),
`screenshots/` (your `stepShot` captures), and `diagnostics/` (console +
network HAR). Open a failure's trace for a step-by-step replay of DOM, network,
and screenshots:

```powershell
npx playwright show-trace artifacts\latest\joint-e2e\playwright-report\<...>\trace.zip
```

### 4. (Optional) pin the visual with a screenshot assertion

To also catch visual regressions, assert against a committed baseline:

```ts
await expect(session.page).toHaveScreenshot("realm-created.png");
```

First run writes the baseline; later runs diff against it. Update intentionally
with `npx playwright test --update-snapshots`.

> A recorded happy-path smoke is a normal **live** `test(...)` — it is not a
> `test.fixme` and is not subject to the promotion checklist. Only use
> `test.fixme` (with `@blocking-on` / `@user-promise` / `@expected-live-by`) when
> you are asserting a spec contract the running stack cannot yet satisfy.

## Direct Cargo Run

```powershell
$env:COTEST_SUT_MANIFEST = "..\soland\Cargo.toml"
cargo test --tests -- --nocapture
```

If `COTEST_SUT_MANIFEST` is not set, the harness falls back to the bundled
default `soland` checkout.

The teabay Directory Service bridge is optional in normal runs. Set
`TEABAY_BASE_URL=http://127.0.0.1:7781` to attach an already running Directory,
or build `../teabay` and provide `DATABASE_URL` so cotest can spawn it through
the `TEABAY_BIN`/sibling-binary convention.

## Runtime Modes

- `process`: spawn the SUT with local `cargo run` against a checkout manifest.
- `compose`: run process-mode bridge-contract tests through
  `scripts/run-compose.ps1`; spawned `soland` remains under cotest lifecycle,
  while external service URLs are passed through `COAUTH_BASE_URL`,
  `FLORIA_BASE_URL`, `SODMIN_BASE_URL`, and `YOUGEN_BASE_URL`.
- `docker`: spawn the SUT from `COTEST_SUT_IMAGE` with Docker while the Rust
  tests remain host-side, similar to Complement.

See [docs/runtime-workflow.md](./docs/runtime-workflow.md)
for the full startup model, Docker image contract, and result artifacts.

## Layout

- `src/harness/`: process lifecycle, test actor helpers, and shared HTTP
  assertion utilities.
- `src/conformance/`: artifact-driven offline conformance runner wired to
  `cokret-spec/spec/v1/artifacts` schemas, registries, profiles, OpenAPI, non-HTTP
  bindings, and fixtures.
- `src/scenarios/*.rs`: executable protocol and business-domain scenarios.
- `tests/*.rs`: thin integration wrappers around scenario modules.
- `config/coverage-profiles.json`: machine-readable profile-to-suite coverage
  mapping used by the runner.
- `docs/test-strategy.md`: harness model and suite grouping.
- `docs/complement-map.md`: how Complement concepts map onto Cokret.
- `docs/runtime-workflow.md`: runtime modes, Docker image strand, runner scripts,
  and result presentation.

## Coverage Groups

- Single-server surface: service description, auth, collaboration, repo, sync,
  index, identity/authz, schema/policy, realtime signaling, delivery/media,
  permissions, payload contracts, and extension surface gaps.
- Offline conformance surface: Event Envelope, encoding, redaction,
  capability, sync, federation, privacy/security, and state-resolution fixtures
  loaded from `cokret-spec/spec/v1/artifacts`.
- Multi-server surface: federation readiness, contract validation, and
  cross-server collaboration strands.

## Result Artifacts

The runner script writes:

- `artifacts/runs/<timestamp>/raw.log`
- `artifacts/runs/<timestamp>/transcript.ndjson`
- `artifacts/runs/<timestamp>/summary.json`
- `artifacts/runs/<timestamp>/summary.md`
- `artifacts/runs/<timestamp>/summary.html`
- `artifacts/runs/<timestamp>/junit.xml`
- `artifacts/runs/<timestamp>/metadata.json`
- `artifacts/runs/<timestamp>/coverage-matrix.json`
- `artifacts/runs/<timestamp>/coverage-matrix.md`
- `artifacts/runs/<timestamp>/coverage-gate.json`
- `artifacts/runs/<timestamp>/coverage-gate.md`
- `artifacts/runs/<timestamp>/unresolved-gaps.json`
- `artifacts/runs/<timestamp>/unresolved-gaps.md`
- `artifacts/runs/<timestamp>/ci-profile.json`
- `artifacts/runs/<timestamp>/ci-profile.md`
- `artifacts/runs/<timestamp>/secret-scan.json`
- `artifacts/runs/<timestamp>/secret-scan.md`
- `artifacts/runs/<timestamp>/services/`
- `artifacts/latest/` as a copy of the latest run

This gives `cotest` an explicit result surface instead of relying only on
scrolling terminal output.

`-Profile fast-smoke` runs a small PR-oriented set from
`config/ci-profiles.json`; `-Profile dual-soland` starts alpha/beta soland
and alpha/beta yougen locally, then runs the federation Playwright matrix;
`-Profile full-nightly` runs the complete suite.
`scripts/run-hygiene.ps1` is run separately from scenario profiles so
dependency policy, typo checks, and advisory scans can fail fast without
starting services.
`scripts/run-joint-e2e.ps1 -StartMockWitness -MockWitnessExtraDids "did:web:witness-b.local,did:web:witness-c.local"`
starts a mock witness quorum and exports the list helpers consumed by E2E
specs.
`scripts/run-joint-e2e.ps1 -StartMockMimiFacade` starts the local MIMI facade
mock and exports `COTEST_MOCK_MIMI_FACADE_BASE_URL` /
`COTEST_MOCK_MIMI_FACADE_DID`; `-StartMocks` includes it with the other mocks.
`-FailOnCoverageRegression` compares required coverage profiles against
`-CoverageBaselinePath` or the previous `artifacts/latest/coverage-matrix.json`.
Secret-shaped fields in raw logs, transcripts, and service logs fail the run
unless `-AllowSecretLeaks` is supplied.

### Secret scan patterns (P5.1)

`scripts/run-cotest.ps1` (`Find-SecretLeaks`) flags three categories of
unredacted secret-shaped fields when scanning `raw.log`, `transcript.ndjson`,
and `services/*.log`. Each is matched case-insensitively.

**Positive examples (these MUST be flagged):**

```
Authorization: Bearer eyJhbGciOiJI...                       # authorization_header
"access_token":"4f0e1a8b-09e4-4f10-..."                     # json_secret_field
"push_key":"BEL5N6h..."                                     # json_secret_field
"private_key":"-----BEGIN EC PRIVATE KEY-----..."            # json_secret_field + raw PEM
?access_token=4f0e1a8b-09e4-4f10-...                        # query_secret_field
?signed_link=https%3A%2F%2F...%26sig%3Dabc                  # query_secret_field
```

**Negative examples (these MUST NOT trip the scanner):**

```
Authorization: Bearer [redacted]                            # post-redaction placeholder
"access_token":"[redacted]"                                 # post-redaction placeholder
"token":"<masked-by-test-harness>"                          # no `[redacted]` prefix but
                                                            # only matches the explicit
                                                            # `[redacted]` allow form;
                                                            # if you need a custom mask
                                                            # rewrite it to `[redacted]`
"token_kind":"oauth_bearer"                                 # field name does not match
"token_count":42                                            # value is not a quoted string
"token_refresh_url":"https://..."                           # field name does not match
                                                            # the closed allowlist
"public_key":"MFkwEwYHKoZIzj0..."                           # `public_key` is not in the
                                                            # secret-field allowlist
```

**Redaction defaults:**

| Field shape                                          | Redaction               |
|------------------------------------------------------|-------------------------|
| `Authorization: Bearer <token>`                      | `Authorization: Bearer [redacted]` |
| JSON `"<allowed>":"<value>"`                         | `"<allowed>":"[redacted]"` |
| Query `<allowed>=<value>`                            | `<allowed>=[redacted]`  |
| PEM `-----BEGIN [RSA\|EC\|OPENSSH ]PRIVATE KEY-----` | `[redacted-private-key]` |

The closed allowlist of secret-shaped field names is: `authorization`,
`access_token`, `token`, `push_key`, `invite_token`, `signed_link`, `jws`,
`sig`, `password`, `secret`, `private_key`, `seed`. Adding a new
secret-shaped field anywhere in the harness or in a service log MUST be
accompanied by:

1. Adding the field name to all three patterns in `Find-SecretLeaks` and to
   the redaction pass in `ConvertTo-SecretPreview`.
2. Adding a positive and negative example to the table above.
3. Re-running `.\scripts\run-cotest.ps1` and confirming `secret-scan.md`
   reports `status: passed` with the redacted preview rendered as
   `[redacted]`.

**Failure example:**

A run that fails the gate emits `artifacts/runs/<ts>/secret-scan.md`
similar to:

```
# secret scan
- status: failed
- scanned_files: 142
- leaks: 1

| path | line | pattern | preview |
|---|---|---|---|
| artifacts/runs/.../raw.log | 8821 | json_secret_field | `"access_token":"[redacted]"` |
```

The preview is always rendered post-redaction so the report itself never
re-leaks the offending value; the original line+file pointer is what the
on-call engineer chases.

For the runtime model comparison against Complement, including image creation,
Docker networking, host-side execution, and result formatting, see
[docs/complement-map.md](./docs/complement-map.md).

The suite is organized by protocol and behavior, not milestone folders.

---

<!-- circle-rollout milestone pointer -->
> **Active milestone tracking** (local-only, gitignored): see
> `_cotest_todos.md` in the parent `cokret/` directory for the
> circle-rollout (CKP-0007) work item list and per-stage checkpoints.
