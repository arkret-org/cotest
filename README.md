# cotest

> **Spec target**: the sibling [arkret-spec](../arkret-spec) checkout used by
> the current run; cotest does not pin a stale README hash.

`cotest` is an out-of-repository black-box Arkret server test harness modeled
after Complement. It starts real server processes or real server containers,
drives public HTTP endpoints, and uses `arkret-rust-sdk` where typed protocol
helpers and client smoke coverage are useful.

## Pre-commit hook setup

After cloning, enable the project's pre-commit hooks:

```sh
git config core.hooksPath .githooks
```

The hook runs `cargo fmt --all -- --check` and `cargo clippy --no-deps -- -D
warnings` on staged Rust changes. If `.githooks/pre-commit` is missing on
a branch, copy it from
[`arkret-rust-sdk`](https://github.com/arkret-org/arkret-rust-sdk) and
adapt to your local toolchain.

The current default server under test is the sibling
`../soland/Cargo.toml` checkout.

## Realm vs Space

- **Realm:** security boundary — membership, capability, E2EE, federation.
- **Space:** navigation container — board, list, section, calendar bucket.

The harness constructs fixtures with current v1 wire names only:
`ak.realm.*` for boundary events and `ak.space.*` for container events.

## Protocol Review Closures

The current harness tracks the sibling `arkret-spec` checkout and includes:

- **12 new security-closure vectors** (`ak.vector.*` from
  `security-closure-fixture.json`) driven through a runner contract
  `{given_state, operation}` → assertions on
  `{transcript, expected_state_transition, expected_external_response,
  expected_audit_reason}`.
- **schema-validation-fixture runner** — positive and negative cases
  exercised against `schema_ref`.
- **Round R4 literal-scanner rules** — bad DID method segments,
  string-payload `ak.self.events.stream.subscribe` usage, `ak.cross_signing.publish`
  without `expected_previous_generation`, and
  `compute_audit_policy_version_digest` calls with fewer than 4 arguments.
- **Drift-validator allowlists extended** for the new capability action
  `ak.morph.create`, the three new error codes
  (`delivery_binding_stale` / `_handed_over` / `historical_only`), the
  `ak:space:` id-kind in `object_ref`, and the new schema `$defs`
  (`EventsSubscribeFrame`, `SnapshotBootstrap`, the three
  `EventsFrontier*Response` variants, `PolicyCheck{Request,Response}`,
  `FederationServiceBindingRef`, `EventsSubmit{Batch,Federation}Request`,
  and the `third_party_invite` / `space_state_transition_payload` /
  `space_object_tombstone_payload` payloads).

See [docs/test-strategy.md](./docs/test-strategy.md) and
[docs/complement-map.md](./docs/complement-map.md) for the harness plan and
Complement mapping.
Server startup precedence and hermetic joint-test configuration are documented
in [docs/server-config-contract.md](./docs/server-config-contract.md).

## Quick Start

Recommended entrypoints:

```powershell
.\scripts\run-cotest.ps1 -Runtime process
.\scripts\run-cotest.ps1 -Runtime process -Profile fast-smoke
.\scripts\run-cotest.ps1 -Profile fast-smoke -PlanOnly
.\scripts\test-cotest-planner.ps1
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
.\scripts\run-joint-e2e.ps1 -SolandRuntime docker -BuildSolandImage -SkipInkson `
  -RunProfile joint-smoke -PlaywrightProject chromium -Grep "soland /_arkret/describe"
```

- `process` mode is the fast local path and spawns the SUT with `cargo run`.
- `.\scripts\run-compose.ps1` runs the process-mode `compose` profile and can
  attach live `coauth`, `floria`, `sodmin`, `inkson`, or `teabay` services
  through base URLs or managed service commands.
- `docker` mode is the Complement-style path and spawns the SUT with
  `docker run` while Rust tests stay host-side.
- Joint Playwright e2e can also run soland from the built image with
  `run-joint-e2e.ps1 -SolandRuntime docker`, including a `-SkipInkson` mode for
  soland-only wire/API probes.
- `.\scripts\build-soland-image.ps1` builds the default SUT image from
  `soland` plus the sibling `arkret-rust-sdk` checkout using the workspace
  root as Docker build context.
- Each scripted run writes `raw.log`, `transcript.ndjson`, `summary.json`,
  `summary.md`, `summary.html`, `junit.xml`, coverage/gap reports, and
  CI profile, coverage gate, secret scan, and per-service logs to
  its timestamped directory under `artifacts/runs/cotest/` or
  `artifacts/runs/joint-e2e/`, then publishes eligible stable mirrors under
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

The latest complete cotest report is `artifacts/latest/full/summary.md`.
The latest unfiltered standalone joint-e2e report is
`artifacts/latest/joint-e2e/summary.md`. Targeted runs never replace either
stable result.

The local hygiene report is `artifacts/hygiene/<timestamp>/summary.md`.

## Artifacts layout

Everything generated by test runs lives under `cotest/artifacts/`. Timestamped
run directories are authoritative; stable mirrors make important run classes
easy to find:

```
artifacts/
  runs/
    cotest/<timestamp>-<profile>[-selection]/ # run-cotest.ps1 authoritative outputs
      summary.*, junit.xml, ...
      services/
      joint-smoke/ | joint/ | ...   # embedded joint gate outputs
    joint-e2e/<timestamp>-<profile>/ # standalone run-joint-e2e.ps1 outputs
    joint-e2e-adhoc/<timestamp>/    # direct `npx playwright test`
    cargo-adhoc/                    # bare `cargo test` reports
  latest/
    README.md                       # generated index of stable channels
    full/                           # latest unfiltered complete cotest run
    joint-e2e/                      # latest non-targeted joint suite
  hygiene/<timestamp>/              # run-hygiene.ps1 (separate gate, own family)
  compose/                          # run-compose.ps1 live-stack service logs
```

Rules:

- `latest/full/` changes only after a profile with `include_all_tests: true`
  completes without `-CargoTestTarget` or `-CargoTestFilter`.
- `latest/joint-e2e/` changes after `run-cotest.ps1 -Profile joint` or a
  standalone suite run without `-Grep`, `-ExternalDriverScript`, or
  `-PreflightOnly`.
- Targeted cotest and joint selections remain only in their timestamped run
  directories and never modify a stable `latest/` channel. Each stable mirror
  contains `run-location.json` pointing to its authoritative run.
- Embedded joint gates place their outputs directly in
  `runs/cotest/<timestamp>-<profile>/<gate-name>/`; they do not replace the
  stable joint result except for the dedicated `run-cotest.ps1 -Profile joint`
  suite. The targeted `dual-soland` and `release-gate` legs never replace it.
- Both scripts keep the newest 20 runs in their own family (`-KeepRuns`, `0`
  disables), so cotest and joint-e2e retention cannot prune one another.
- CI sets `COTEST_JOINT_RUN_DIR` to fixed names under `runs/` (e.g.
  `runs/integration-playwright/joint-e2e`).

## Agent-driven user journeys

`agent-journeys/` is a separate goal-driven acceptance layer. It reuses the
joint runner's real service lifecycle, but an agent operates Inkson through
isolated agent-browser sessions instead of replaying a predefined locator
sequence. Required checkpoints retain screenshots, hard checks, action
transcripts, and explicit product/agent/harness failure classification.

The federated topology starts two isolated principal servers on one physical
machine with distinct service identities, ports, state/object roots, and
Inkson origins:

```powershell
$run = .\scripts\run-agent-journey.ps1 `
  -Action Prepare `
  -Scenario federated-team-incident `
  -Topology federated

# The agent now uses agent-journeys/scripts/invoke-agent-browser.ps1,
# records all required checkpoints, and then releases the stack:
.\scripts\run-agent-journey.ps1 -Action Finalize -RunDir $run.run_dir
```

Use `-SolandRuntime docker` when container isolation is preferred. See
[`agent-journeys/README.md`](./agent-journeys/README.md).

## Recording manual flows into one-key replay (codegen → smoke)

If you keep hand-driving the same browser flow (register → login → create a
Realm → …) to verify a change, stop repeating it by hand. Record it **once** as
a Playwright spec, then replay it with one command and keep the screenshots/trace
as evidence. This is the highest-ROI automation step: the recorder emits
maintainable TypeScript over `getByTestId`/`getByRole`, not a brittle pixel
recording, and the resulting spec doubles as a regression gate the AI-driven
exploratory tools can never be.

### 1. Bring the stack up, then record

`playwright codegen` needs a running inkson (and the soland/coauth it talks to).
Start the stack the usual way, then point the recorder at it:

```powershell
# Terminal A — start soland + coauth + inkson and leave them running.
& "D:\Works\arkret\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -KeepAlive

# Terminal B — record. Default inkson URL is http://127.0.0.1:4527; override
# with INKSON_BASE_URL if your run prints a different one.
cd D:\Works\arkret\cotest\e2e
npx playwright codegen http://127.0.0.1:4527
```

Drive the flow by hand in the popup browser. The Inspector writes the
corresponding TypeScript live; copy it out when you are done.

> If `-KeepAlive` is not available on your branch, start the services with your
> usual local commands (or `run-compose.ps1`) and codegen against the printed
> inkson URL — codegen only needs a reachable base URL.

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
- Prefer `getByTestId(...)` selectors (the recorder picks these up from inkson's
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
& "D:\Works\arkret\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -RunProfile joint-full
& "D:\Works\arkret\cotest\scripts\run-joint-e2e.ps1" -StartCoauth -Grep "smoke/"

# Or directly against an already-running stack (outputs land in a fresh
# artifacts/runs/joint-e2e-adhoc/<ts>/ directory):
cd D:\Works\arkret\cotest\e2e
npm test                 # headless
npm run test:headed      # watch it click
```

Evidence lands in `artifacts/runs/joint-e2e/<ts>-<profile>/`:
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

## Event proof mode (Playwright harness)

The e2e helpers sign every submitted event envelope
(`e2e/helpers/soland-api.ts` `eventProof`). Two environment variables control
the proof shape:

- `COTEST_EVENT_PROOF_MODE` — `detached-jws` (default) emits the
  `cotest.detached_jws.fixture.v1` detached-JWS proof that soland verifies
  cryptographically; `dev-proof` emits the legacy development placeholder
  proof, accepted only by soland development builds. Any other value throws.
- `COTEST_FORBID_DEV_PROOF=1` — hard-fails the run if anything selects
  `dev-proof`, so production-shaped runs cannot silently fall back to the
  placeholder (see `.github/workflows/integration.yml`
  `production_rejects_placeholder_proof_e2e`).

## Test Tiers (ARC-0002)

Every test belongs to exactly one tier; the tier decides which CI lane runs it:

- `contract` — deterministic cross-project contract/conformance checks. Default
  tier for every non-`#[ignore]` cargo test and runs in the PR lane.
- `live` — needs real service binaries, Docker, or a multi-service stack.
  Nightly lane (`integration.yml`). All Playwright e2e specs are `live` by
  construction (they target a real soland).
- `mls-data-plane` — needs real MLS group state, epoch secrets, and application
  ciphertext (CT-002 harness). Controlled-environment lane. Playwright tests in
  this tier carry the `@mls-data-plane` tag.
- `platform-live` — provider credential/webhook smoke tests. They run only from
  `controlled.yml` and carry the `@platform-live` tag.

Rust: every `#[ignore]` must carry `/// Tier: contract|live|mls-data-plane`
plus the existing `/// Issue:`/`/// Gating:` reason —
`scripts/check_ignore_comments.sh` enforces both in CI. Playwright: a missing
prerequisite must be an explicit `test.skip(cond, "reason")` / `test.fixme`
with a machine-readable reason string, never a silent pass.

CI mapping is fail-closed: `ci.yml` is the PR contract/deterministic lane,
`integration.yml` is the nightly live lane, and `controlled.yml` is manually
dispatched through a protected environment for `mls-data-plane` or
`platform-live`. Controlled runs must declare `component@version/ref` values in
`COTEST_SERVICE_VERSIONS`; `scripts/check_tier_preconditions.sh` exits with a
`PRECONDITION_*` record when an endpoint, credential, harness version, adapter
version, or component version is missing. Missing controlled prerequisites are
not converted into test skips.

The platform lane sends a captured authentic provider delivery to a deployed
bridge. The protected environment supplies the bridge URL, webhook path,
base64 body, and signature headers; secrets are never committed as fixtures.

The MLS lane first runs inkson's real OpenMLS vector as a wasm test inside
headless Chrome, distinguishing never-joined, removed-member, wrong-key, and
damaged-ciphertext outcomes. It then runs the paired device-revoke control-plane
sentinel against the declared soland/inkson versions, so cryptographic and
server `device_revoked` evidence are retained separately. The former Playwright
scenario that fabricated commit/tree digests was deleted rather than retained
as a second, misleading `mls-data-plane` test.

## Runtime Modes

- `process`: spawn the SUT with local `cargo run` against a checkout manifest.
- `compose`: run process-mode bridge-contract tests through
  `scripts/run-compose.ps1`; spawned `soland` remains under cotest lifecycle,
  while external service URLs are passed through `COAUTH_BASE_URL`,
  `FLORIA_BASE_URL`, `SODMIN_BASE_URL`, and `INKSON_BASE_URL`.
- `docker`: spawn the SUT from `COTEST_SUT_IMAGE` with Docker while the Rust
  tests remain host-side, similar to Complement.

See [docs/runtime-workflow.md](./docs/runtime-workflow.md)
for the full startup model, Docker image contract, and result artifacts.

## Layout

- `src/harness/`: process lifecycle, test actor helpers, and shared HTTP
  assertion utilities.
- `src/conformance/`: artifact-driven offline conformance runner wired to
  `arkret-spec/spec/v1/artifacts` schemas, registries, profiles, OpenAPI, non-HTTP
  bindings, and fixtures.
- `src/scenarios/*.rs`: executable protocol and business-domain scenarios.
- `tests/*.rs`: thin integration wrappers around scenario modules.
- `config/coverage-profiles.json`: machine-readable profile-to-suite coverage
  mapping used by the runner.
- `docs/test-strategy.md`: harness model and suite grouping.
- `docs/complement-map.md`: how Complement concepts map onto Arkret.
- `docs/runtime-workflow.md`: runtime modes, Docker image strand, runner scripts,
  and result presentation.

## Coverage Groups

- Single-server surface: service description, auth, collaboration, repo, sync,
  index, identity/authz, schema/policy, realtime signaling, delivery/media,
  permissions, payload contracts, and extension surface gaps.
- Offline conformance surface: Event Envelope, encoding, redaction,
  capability, sync, federation, privacy/security, and state-resolution fixtures
  loaded from `arkret-spec/spec/v1/artifacts`.
- Multi-server surface: federation readiness, contract validation, and
  cross-server collaboration strands.

## Result Artifacts

The runner script writes under
`artifacts/runs/cotest/<timestamp>-<profile>/`:

- `raw.log` and `transcript.ndjson`
- `summary.json`, `summary.md`, and `summary.html`
- `junit.xml` and `metadata.json`
- coverage, gate, gap, CI-profile, and secret-scan JSON/Markdown reports
- `services/`

Stable mirrors are `artifacts/latest/full/` and
`artifacts/latest/joint-e2e/`.

This gives `cotest` an explicit result surface instead of relying only on
scrolling terminal output.

`-Profile fast-smoke` runs a small PR-oriented set from
`config/ci-profiles.json`; `-Profile dual-soland` starts alpha/beta soland
and alpha/beta inkson locally, then runs the federation Playwright matrix;
`-Profile full-nightly` runs the complete suite.
Selective profiles declare both the Cargo integration-test `target` and the
test-name `filter`, so the runner builds and starts only the selected target.
Target/filter entries also use libtest `--exact`, preventing one configured
name from selecting longer tests that merely contain it as a substring.
Use `-PlanOnly` to inspect the exact Cargo arguments without compiling or
starting services, and `-ValidateProfile` to compile each selected target once
and require every configured filter to match exactly one listed test.
`scripts/run-hygiene.ps1` is run separately from scenario profiles so
dependency policy, typo checks, and advisory scans can fail fast without
starting services.
`scripts/run-joint-e2e.ps1 -StartMockWitness -MockWitnessExtraDids "did:webvh:z6mkfixture:witness-b.local,did:webvh:z6mkfixture:witness-c.local"`
starts a mock witness quorum and exports the list helpers consumed by E2E
specs.
`scripts/run-joint-e2e.ps1 -StartMockMimiFacade` starts the local MIMI facade
mock and exports `COTEST_MOCK_MIMI_FACADE_BASE_URL` /
`COTEST_MOCK_MIMI_FACADE_DID`; `-StartMocks` includes it with the other mocks.
`-FailOnCoverageRegression` compares required coverage profiles against
`-CoverageBaselinePath` or the previous
`artifacts/latest/full/coverage-matrix.json`.
Secret-shaped fields in raw logs, transcripts, and service logs fail the run
unless `-AllowSecretLeaks` is supplied. That switch permits reported log hits
only; it never bypasses a failed scanner self-test.

### Secret scan patterns (P5.1)

`scripts/lib/secret-scan.ps1` (dot-sourced by `scripts/run-cotest.ps1` and
`scripts/run-joint-e2e.ps1`) defines `Find-SecretLeaks`, which flags unredacted
secret-shaped content when scanning `raw.log`, `transcript.ndjson`, and
`services/*.log`. Field patterns are matched case-insensitively. Before every
scan, the runner executes the synthetic-secret regression
`scripts/tests/secret-scan.tests.ps1`; a self-test failure fails the secret gate
even when the logs themselves are clean.

#### Categories and artifact classes

A finding is not automatically a leak — it depends on what the artifact is.
Every finding carries a `category`, every scan root declares an
`artifact_class`, and the pair decides the `verdict`. Only `fail` rows gate the
run.

| category | `log_or_telemetry` | `durable_protocol_store` |
|---|---|---|
| `recovery_private_material` | fail | fail |
| `credential_exposure` | fail | `allowed_by_artifact_class` |

`recovery_private_material` — mnemonics, seeds, PRKs, private JWK members,
plaintext keybags, MLS private state — is never legitimate anywhere.
`credential_exposure` — bearer tokens, JWS, signed links — is a leak in a log,
but in a durable protocol store it is frequently the signed evidence the spec
requires the server to persist. A PostgreSQL dump legitimately contains dozens
of JWS and authorization fields; failing on those would train everyone to
ignore the gate, or push someone to allowlist the whole scan, which would also
hide a real recovery-material leak.

A bare path passed as a scan root takes the strict `log_or_telemetry` class, so
a root added without thought fails closed. An unrecognised class is a startup
error, not a silent default.

#### Post-scan artifact redaction

Playwright writes the full received value into stdout and `error-context.md`
whenever a matcher fails, so a secret-bearing response reaches the retained
artifacts without any test asking for it. The runner therefore scans first and
redacts afterwards: `secret-scan.json` keeps the file, line, pattern and
category of every finding as evidence, while `Protect-SecretBearingArtifacts`
rewrites the offending artifacts so the retained copies carry no plaintext.

Redaction follows the verdict, not the finding count — an
`allowed_by_artifact_class` store is left byte-identical, because blanking the
JWS fields in a dump destroys the record the store exists to hold. Archive
members are reported under `not_redacted` rather than silently skipped; a
secret inside a retained archive needs the archive dropped.

Tests should not rely on the redactor. `e2e/helpers/secret-safe.ts` provides
`expectStructurallyIdentical`, `publicProjection` and `secretPresence` so a
business assertion never receives a secret-bearing object in the first place.

**Positive examples (these MUST be flagged):**

```
Authorization: Bearer eyJhbGciOiJI...                       # authorization_header
"access_token":"4f0e1a8b-09e4-4f10-..."                     # json_secret_field
"push_key":"BEL5N6h..."                                     # json_secret_field
"mnemonic":"abandon ability able ..."                       # json_secret_field
"private_key":"-----BEGIN EC PRIVATE KEY-----..."            # json_secret_field + raw PEM
?access_token=4f0e1a8b-09e4-4f10-...                        # query_secret_field
?signed_link=https%3A%2F%2F...%26sig%3Dabc                  # query_secret_field
?root_seed=deadbeef...                                      # query_secret_field
{"kty":"OKP","crv":"Ed25519","d":"c3ludGhldGlj..."}         # jwk_private_member
                                                            # (a JWK's `d` member is the
                                                            # private scalar; bound to a
                                                            # `kty` member on the same
                                                            # line so it does not match
                                                            # every unrelated `d` field)
{"keybag":{"entries":1,"k":"c3ludGhldGlj..."}}              # plaintext_keybag_object
"abandon ability able about ... actual"                     # bip39_mnemonic_sequence
                                                            # (12+ consecutive words
                                                            # from the BIP-39 English
                                                            # wordlist inside quotes;
                                                            # surrounding text and
                                                            # punctuation are allowed)
"credential":"did:webvh:..."                                # did_in_token_field
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
"the server logs show that retry loops kept firing ..."     # 12+ short lowercase words
                                                            # that are NOT 12 consecutive
                                                            # BIP-39 wordlist entries
```

**Redaction defaults:**

| Field shape                                          | Redaction               |
|------------------------------------------------------|-------------------------|
| `Authorization: Bearer <token>`                      | `Authorization: Bearer [redacted]` |
| JSON `"<allowed>":"<value>"`                         | `"<allowed>":"[redacted]"` |
| Query `<allowed>=<value>`                            | `<allowed>=[redacted]`  |
| Quoted string containing 12+ short-word run         | `"[redacted-mnemonic]"` |
| JSON `"d"`/`"k"` member of 16+ key-shaped chars      | `"d":"[redacted]"` |
| PEM `-----BEGIN [RSA\|EC\|OPENSSH\|ENCRYPTED ]PRIVATE KEY-----` | `[redacted-private-key]` |

The closed allowlist of secret-shaped field names is: `authorization`,
`access_token`, `token`, `push_key`, `invite_token`, `signed_link`, `jws`,
`sig`, `password`, `secret`, `secret_b64u`, `private_key`, `seed`,
`mnemonic`, `recovery_key`, `recovery_phrase`, `recovery_secret`,
`root_seed`, `root_private_key`, `hkdf_prk`, `prk`, `credential`,
`plaintext_keybag`, `keybag_secret`, `mls_secret`, `epoch_secret`,
`application_secret`, `confirmation_key`, `membership_key`, `init_secret`,
`joiner_secret`, `welcome_secret`, `private_state`. Everything from
`private_key` onward is also in the `recovery_private_material` list, which is
what makes those findings fail in every artifact class.

The `"d"`/`"k"` redaction is deliberately broader than its detector: detection
requires the JWK or keybag envelope, redaction blanks any member of that shape.
A preview that loses an unrelated `d` field costs a diagnostic; one that keeps a
private JWK scalar costs a key.

The BIP-39 detector validates candidates against the standard 2048-word English
wordlist (`scripts/lib/bip39-english.txt`); a quoted run only counts when it
contains 12 consecutive wordlist entries. Adding a new secret-shaped field
anywhere in the harness or in a service log MUST be accompanied by:

1. Adding the field name to the shared field-name variables in
   `scripts/lib/secret-scan.ps1` (detection and redaction consume the same
   variables, so one edit keeps them consistent). Private key material also goes
   into `RecoveryPrivateMaterialFieldNames`, or it will be tolerated inside a
   durable protocol store.
2. Adding a planted vector to `scripts/tests/secret-scan.tests.ps1` plus a
   positive and negative example to the table above. The self-test asserts each
   detector's category, so a new pattern without a category assertion fails.
3. Re-running `.\scripts\run-cotest.ps1` and confirming `secret-scan.md`
   reports `status: passed`, `self_test: passed`, with the redacted preview
   rendered as `[redacted]`.

**Failure example:**

A run that fails the gate emits
`artifacts/runs/cotest/<ts>-<profile>/secret-scan.md`
similar to:

```
# secret scan
- status: failed
- self_test: passed
- scanned_files: 142
- findings: 2
- failing: 1
- allowed_by_artifact_class: 1
- recovery_private_material: 0
- credential_exposure: 2
- redacted_files: 1

| File | Line | Pattern | Category | Artifact class | Verdict | Preview |
|---|---|---|---|---|---|---|
| artifacts/runs/.../raw.log | 8821 | json_secret_field | credential_exposure | log_or_telemetry | fail | `"access_token":"[redacted]"` |
| artifacts/runs/.../dump.sql | 12 | json_secret_field | credential_exposure | durable_protocol_store | allowed_by_artifact_class | `"jws":"[redacted]"` |
```

The preview is always rendered post-redaction so the report itself never
re-leaks the offending value; the file+line pointer is what the on-call engineer
chases. Note that the second row does not gate the run and its artifact is left
byte-identical — the store is supposed to hold that evidence.

For the runtime model comparison against Complement, including image creation,
Docker networking, host-side execution, and result formatting, see
[docs/complement-map.md](./docs/complement-map.md).

The suite is organized by protocol and behavior, not milestone folders.

---

<!-- circle-rollout milestone pointer -->
> **Active milestone tracking** (local-only, gitignored): see
> `_cotest_todos.md` in the parent `arkret/` directory for the
> circle-rollout (AKP-0007) work item list and per-stage checkpoints.
