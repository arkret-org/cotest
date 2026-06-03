# cotest

> **Spec target**: [cokret-spec @ c2848a4](../cokret-spec) (R3.4 sync 2026-05-31)

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

The harness uses the Phase 1–4 inverted vocabulary when constructing
fixtures and assertions:

- **Realm:** security boundary — membership, capability, E2EE, federation.
  Old wire name: `Space`.
- **Space:** navigation container — board, list, section, calendar bucket.
  Old wire name: `Place`.

Both legacy and new wire shapes are exercised so the soland reducer's
back-compat aliases stay covered.

## Round R4 (protocol review closures)

Spec round 4 (`cokret-spec` range `2a4d39b..a77b995`, 8 commits) adds:

- **12 new security-closure vectors** (`cx.vector.*` from
  `security-closure-vectors.json`) driven through a runner contract
  `{given_state, operation}` → assertions on
  `{transcript, expected_state_transition, expected_external_response,
  expected_audit_reason}`.
- **schema-validation-fixture runner** — positive and negative cases
  exercised against `schema_ref`.
- **Round R4 literal-scanner rules** — bad DID method segments,
  string-payload `cx.events.subscribe` usage, `cx.cross_signing.publish`
  without `expected_previous_generation`, and
  `compute_audit_policy_version_digest` calls with fewer than 4 arguments.
- **Drift-validator allowlists extended** for the new capability action
  `cx.morph.create`, the three new error codes
  (`delivery_binding_stale` / `_handed_over` / `historical_only`), the
  `ck:space:` id-kind in `object_ref`, and the new schema `$defs`
  (`EventsSubscribeFrame`, `SnapshotBootstrap`, the three
  `EventsFrontier*Response` variants, `PolicyCheck{Request,Response}`,
  `FederationServiceBindingRef`, `EventsSubmit{Batch,Federation}Request`,
  and the `third_party_invite` / `space_state_transition_payload` /
  `space_object_tombstone_payload` payloads).

See [`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` and
[`../_todos.md`](../_todos.md) for the canonical wire-breaking list.

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
```

- `process` mode is the fast local path and spawns the SUT with `cargo run`.
- `.\scripts\run-compose.ps1` runs the process-mode `compose` profile and can
  attach live `coauth`, `floria`, `sodmin`, `yougen`, or `teabay` services
  through base URLs or managed service commands.
- `docker` mode is the Complement-style path and spawns the SUT with
  `docker run` while Rust tests stay host-side.
- `.\scripts\build-soland-image.ps1` builds the default SUT image from
  `soland` plus the sibling `cokret-rust-sdk` checkout using the workspace
  root as Docker build context.
- Each scripted run writes `raw.log`, `transcript.ndjson`, `summary.json`,
  `summary.md`, `summary.html`, `junit.xml`, coverage/gap reports, and
  CI profile, coverage gate, secret scan, and per-service logs to
  `artifacts/runs/<timestamp>/`, then copies the latest set to
  `artifacts/latest/`.
- `.\scripts\run-hygiene.ps1` is the local hygiene gate for dependency
  advisories/licensing (`cargo deny check`), spelling drift (`typos`),
  RustSec vulnerabilities (`cargo audit`), and Playwright fixme debt metadata
  (`fixme-debt-report.mjs --strict`). It writes `raw.log`,
  `summary.json`, `summary.md`, and per-tool stdout/stderr logs to
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

See [docs/runtime-workflow.md](/E:/Works/cokret/cotest/docs/runtime-workflow.md:1)
for the full startup model, Docker image contract, and result artifacts.

## Layout

- `src/harness.rs`: process lifecycle, test actor helpers, and shared HTTP
  assertion utilities.
- `src/conformance.rs`: artifact-driven offline conformance runner wired to
  `cokret-spec/spec/v1/artifacts` schemas, registries, profiles, OpenAPI, non-HTTP
  bindings, and fixtures.
- `src/scenarios/*.rs`: executable protocol and business-domain scenarios.
- `tests/*.rs`: thin integration wrappers around scenario modules.
- `../_todos.md`: Complement-derived plan and the current single-server /
  multi-server coverage matrix.
- `config/coverage-profiles.json`: machine-readable profile-to-suite coverage
  mapping used by the runner.
- `docs/test-strategy.md`: harness model and suite grouping.
- `docs/complement-map.md`: how Complement concepts map onto Cokret.
- `docs/runtime-workflow.md`: runtime modes, Docker image flow, runner scripts,
  and result presentation.

## Coverage Groups

- Single-server surface: service description, auth, collaboration, repo, sync,
  index, identity/authz, schema/policy, realtime signaling, delivery/media,
  permissions, payload contracts, and extension surface gaps.
- Offline conformance surface: Event Envelope, encoding, redaction,
  capability, sync, federation, privacy/security, and state-resolution fixtures
  loaded from `cokret-spec/spec/v1/artifacts`.
- Multi-server surface: federation readiness, contract validation, and
  cross-server collaboration flows.

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
"refresh_token_url":"https://..."                           # field name does not match
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
[docs/complement-map.md](/E:/Works/cokret/cotest/docs/complement-map.md:1).

The suite is organized by protocol and behavior, not milestone folders.

## Literal Scanner (Protocol Drift Detection)

`cotest` ships a repo-level literal scanner that reads the canonical
drift-detection artifacts shipped under
`cokret-spec/spec/v1/artifacts/registry/`:

- `removed-event-kinds.json`
- `deprecated-profile-ids.json`
- `removed-operation-ids.json`
- `forbidden-wire-fields.json`
- `forbidden-model-terms.json`
- `renames.json`

and walks a downstream Rust / TypeScript / JSON / Markdown tree looking for
literal occurrences of `cx.*` event-kind / operation-id strings, deprecated
profile ids, forbidden wire field names, and forbidden model terms. Each
finding carries the originating artifact, rejection level, suggested
replacement, and whether the file context is allowlisted.

### Library entrypoint

```rust
use cotest::literal_scanner::{scan_default, ScanReport};

let report: ScanReport = scan_default(std::path::Path::new("../yougen"))?;
for f in report.violations() {
    eprintln!(
        "{}:{}:{} {} (artifact={}, level={})",
        f.path.display(), f.line, f.column,
        f.matched_token, f.artifact_source, f.rejection_level
    );
}
```

The spec directory is resolved in this order:

1. `COKRET_SPEC_DIR` env var (points at the `cokret-spec` checkout root).
2. `<cotest crate root>/../cokret-spec` (default sibling layout).

### CLI

A standalone binary is provided as `src/bin/literal_scanner.rs`:

```powershell
cargo run --bin literal_scanner -- --root ..\yougen --format text
cargo run --bin literal_scanner -- --root ..\soland --format json --fail-on-violation
cargo run --bin literal_scanner -- --root ..\yougen --registry-dir ..\cokret-spec\spec\v1\artifacts\registry
```

Exit codes: `0` clean, `1` violations found (only with `--fail-on-violation`),
`2` scanner error.

### Allowlists

A finding is marked `allowed_context_match = true` when **either**:

1. The file path falls under one of the canonical compliant directories —
   `**/compat/**`, `**/interop/**`, `**/interop_matrix/**`,
   `**/legacy_negative/**`, `**/legacy_migration/**`, `**/migrations/**`,
   `**/changelog/**`, or any file whose name starts with `CHANGELOG`.
2. The file contains a magic comment that exempts the artifact id:

   ```rust
   // cokret-allow: cx.flow.track.member
   // cokret-allow: cx.flow.track.member, flow_branch
   // cokret-allow: *      // exempt every artifact in this file
   ```

   `#`, `<!-- -->`, and `/* */` comment forms are all recognized so the same
   directive works in shell, Markdown, and block-comment contexts.

The path-glob check additionally verifies the artifact's own
`allowed_contexts` field permits the inferred context (e.g. an entry that
only allows `negative_test` will *not* be silenced by a `legacy_migration/`
path).

### Scope today

The scanner is intentionally a tool — it is **not** wired into CI to fail
the build yet. The plan is to land the tool now (this milestone) and wire
it into per-downstream pipelines incrementally as each repo cleans up its
backlog of legacy literals.

---

<!-- circle-rollout milestone pointer -->
> **Active milestone tracking** (local-only, gitignored): see
> `_cotest_todos.md` in the parent `cokret/` directory for the
> circle-rollout (CXP-0007) work item list and per-stage checkpoints.
