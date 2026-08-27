# cotest Runtime Workflow

## Why this exists

`cotest` now has two execution paths:

- `process` mode for local protocol debugging against a checked-out Rust server.
- `docker` mode for reproducible, Complement-style black-box runs against a built
  SUT image.

This closes the gap between the earlier ad hoc `cargo run` harness and the
deployment model used by Complement (the Matrix homeserver black-box
integration test suite).

## What Complement does

Complement is organized around a few explicit runtime pieces:

- a base homeserver image selected with `COMPLEMENT_BASE_IMAGE`
- Docker build/deploy helpers in `internal/docker/`
- runtime-specific hooks in `runtime/`
- host-side test execution with Go while homeservers run in containers
- optional pretty result formatting via `go test -json` plus `gotestfmt`
- per-deployment Docker networks and container lifecycle management in
  `internal/docker/deployer.go`

In practice, Complement treats the homeserver as an external appliance:

1. build or provide a Docker image
2. start one or more containers per test package or deployment
3. drive them only through public APIs
4. collect logs and summarize test output on the host

## What cotest does

`cotest` follows the same broad pattern, but keeps a fast local path for day to
day Rust work.

### Runtime modes

- `process`:
  `src/harness/` starts the SUT with `cargo run --manifest-path <manifest>`.
  This is the default mode for local development.
- `docker`:
  `src/harness/` starts the SUT with `docker run` from `COTEST_SUT_IMAGE`.
  Multi-server tests create an isolated Docker network so the spawned servers
  share a runtime boundary instead of pretending everything is localhost. This
  is the direct analogue of Complement standing up multiple homeserver
  containers inside one deployment network.
- `joint e2e docker`:
  `scripts/run-joint-e2e.ps1 -SolandRuntime docker` starts the Playwright
  target soland from the same built SUT image while keeping Playwright and
  optional side services host-side. This is the release-quality browser/API
  path because the server under test is the packaged appliance, not a fresh
  `cargo run` child.

### Runtime switch

The harness reads these environment variables:

- `COTEST_SUT_MODE=process|docker`
- `COTEST_SUT_MANIFEST=<path to Cargo.toml>` for process mode
- `COTEST_SUT_IMAGE=<tag>` for docker mode
- `COTEST_SUT_CONTAINER_PORT=<port>` if the image exposes a non-default
  internal port. Default is `8008`.
- `scripts/run-joint-e2e.ps1 -SolandRuntime process|docker`
- `scripts/run-joint-e2e.ps1 -SolandImage <tag>` for Playwright runs backed by
  a soland image.

### Docker image contract

The default image asset is [docker/soland.Dockerfile](../docker/soland.Dockerfile).
It is built from the workspace root one level above `cotest`, because `soland`
depends on the sibling checkout `arkret-rust-sdk`. The workspace root
`.dockerignore` trims the build context so Docker only receives the `soland`,
`arkret-rust-sdk`, and `cotest/docker` trees instead of the whole workspace.

The image contract is intentionally simple:

- start `soland` as the entrypoint
- listen on `SOLAND_BIND`
- honor `SOLAND_PUBLIC_BASE_URL`, `SOLAND_FIRST_PROVISIONING`,
  `SOLAND_DEVELOPMENT_MODE`, and `SOLAND_BLOB_ROOT`; the service DID is
  resolved from durable service-identity state and never injected
- expose port `8008`

The current implementation source-builds `soland` inside Docker:

- build stage: `rust:1.97-bookworm`
- runtime stage: `debian:bookworm-slim` with `ca-certificates` and `libssl3`
- copied source trees: `soland` and `arkret-rust-sdk`
- build command: `cargo build --release --locked`

The image does not define an in-container `HEALTHCHECK`. Instead, the harness
waits on `GET /health` from the host side, which keeps the SUT contract
identical between `process` and `docker` modes.

## Build and run

### Build the default Docker SUT image

```powershell
.\scripts\build-soland-image.ps1
```

This script:

- uses `E:\Works\arkret` as the Docker build context by default
- reads [docker/soland.Dockerfile](../docker/soland.Dockerfile)
- expects sibling `soland` and `arkret-rust-sdk` checkouts to exist
- produces `cotest-soland:latest` unless `-ImageTag` overrides it
- accepts Docker cache controls through `-CacheFrom`, `-CacheTo`, `-Pull`, and
  `-NoCache`

The first Docker build is slower than `process` mode because it compiles
`soland` inside the image and resolves crates in the container build context.

To build with a custom tag:

```powershell
.\scripts\build-soland-image.ps1 -ImageTag cotest-soland:dev
```

### Run in local process mode

```powershell
.\scripts\run-server-conformance.ps1 -Runtime process
```

To point at a different checkout:

```powershell
.\scripts\run-server-conformance.ps1 -Runtime process -SutManifest E:\path\to\server\Cargo.toml
```

To run the PR-sized smoke profile:

```powershell
.\scripts\run-server-conformance.ps1 -Runtime process -Profile fast-smoke
```

### Run the compose profile

```powershell
.\scripts\run-compose.ps1
```

The compose entrypoint runs the process-mode `compose` profile. `soland`
instances are still spawned by cotest for each scenario. Live side services can
be attached with base URLs:

```powershell
.\scripts\run-compose.ps1 `
  -CoauthBaseUrl http://127.0.0.1:8080 `
  -FloriaBaseUrl http://127.0.0.1:5000
```

For locally managed side services, pass a command and a base URL. The script
waits on `<base>/health` unless a service-specific `*HealthUrl` is supplied,
then stops those processes after the run:

```powershell
.\scripts\run-compose.ps1 `
  -FloriaBaseUrl http://127.0.0.1:5000 `
  -FloriaCommand '$env:FLORIA_CONF="D:\Works\arkret\floria\floria.sample.kdl"; cargo run --manifest-path D:\Works\arkret\floria\Cargo.toml'
```

### Run in Docker mode

```powershell
.\scripts\run-server-conformance.ps1 -Runtime docker -BuildImage
```

With BuildKit cache wiring:

```powershell
.\scripts\run-server-conformance.ps1 -Runtime docker -BuildImage `
  -DockerCacheFrom type=registry,ref=registry.example/cotest-soland:buildcache `
  -DockerCacheTo type=registry,ref=registry.example/cotest-soland:buildcache,mode=max
```

If the image already exists:

```powershell
.\scripts\run-server-conformance.ps1 -Runtime docker -SutImage cotest-soland:latest
```

### Run a filtered subset

```powershell
.\scripts\run-server-conformance.ps1 -Runtime docker `
  -CargoTestTarget federation_contract `
  -CargoTestFilter federation_replay_snapshot_and_redaction_contracts_work
```

Always pass `-CargoTestTarget` with `-CargoTestFilter` for target-aware
scheduling. Filter-only calls remain available temporarily as an explicitly
reported `broad-scan` and scan every integration target.

Inspect or validate a profile without starting the SUT:

```powershell
.\scripts\run-server-conformance.ps1 -Profile fast-smoke -PlanOnly
.\scripts\run-server-conformance.ps1 -Profile release-gate -ValidateProfile
.\scripts\test-cotest-planner.ps1
```

`-PlanOnly` uses `cargo metadata --no-deps` but does not compile tests.
`-ValidateProfile` runs `cargo test --test <target> -- --list` once per selected
target and fails zero-match or ambiguous filter entries.

### Run joint Playwright against the Docker image

For the PR-sized soland service-surface probe:

```powershell
.\scripts\run-joint-e2e.ps1 `
  -SolandRuntime docker `
  -BuildSolandImage `
  -SkipInkson `
  -RunProfile joint-smoke `
  -PlaywrightProject chromium `
  -Grep "soland /_arkret/describe"
```

For the full product topology, keep Inkson and coauth enabled:

```powershell
.\scripts\run-joint-e2e.ps1 `
  -SolandRuntime docker `
  -BuildSolandImage `
  -StartCoauth `
  -RunProfile joint-smoke
```

When soland runs in Docker and coauth/teabay/mocks run on the host, the
runner rewrites soland's outbound localhost URLs to `host.docker.internal`
inside the container. Public URLs exposed to Playwright stay as
`http://127.0.0.1:<port>` so browser behavior remains identical to process
mode.

### Coverage gate

```powershell
.\scripts\run-server-conformance.ps1 -Profile full-nightly -FailOnCoverageRegression
```

When `-CoverageBaselinePath` is omitted, the runner compares against the
previous `artifacts/latest/server-conformance/coverage-matrix.json` if it exists. Targeted
runs therefore cannot silently become the next complete-suite baseline. The
comparison is limited to the selected profile's `required_coverage_profiles`, unless
`-RequiredCoverageProfiles` is supplied.

### Verified-profile promotion (manual)

`e2e/scripts/write-verified-profiles.mjs` turns a finished run's `junit.xml`
into the `verified-profiles.json` artifact that soland and coauth read at
startup (`SOLAND_VERIFIED_PROFILES_ARTIFACT` /
`COAUTH_VERIFIED_PROFILES_ARTIFACT`, parsed by
`arkret_models_discovery::parse_verified_profiles_artifact`).

It is a manual operator tool and is intentionally not called by any runner.
`run-joint-e2e.ps1` starts the services with `*_DEVELOPMENT_MODE=true`, and
`sync/service-surface.md` §3.0 requires `verified_profiles=[]` in that posture,
so a joint run can never promote. Signing also requires the neutral Conformance
Verifier key (`conformance/conformance-suite.md` §6.2).

Promotion is two-phase and deliberately operator-driven:

```powershell
# 1. run the profile suites, then point the tool at that run directory
$env:COTEST_VERIFIED_PROFILES_VERIFIER_SERVICE_ID = "ak:did_core:web:<verifier>"
$env:COTEST_VERIFIED_PROFILES_SIGNING_KEY_PATH    = "<ed25519 private key PEM>"
node e2e\scripts\write-verified-profiles.mjs artifacts\runs\joint-e2e\<ts>-<profile>

# 2. restart the services WITHOUT development mode, pointing at the artifact
$env:SOLAND_VERIFIED_PROFILES_ARTIFACT = "<...>\verified-profiles.json"
```

Refresh it whenever `PROFILE_SUITE_MAP` inside the script or the profile suites
it names change.

## Startup and shutdown model

- `ArkretServer` is the single entrypoint for one SUT instance.
- `TestServerGroup` is the single entrypoint for multi-server scenarios.
- In `process` mode, each server is a child `cargo run` process with its own
  temp blob root.
- In `compose` profile runs, `run-compose.ps1` owns optional side-service
  processes and exports their URLs to the scenario layer; cotest still owns
  SUT process lifecycle.
- In `docker` mode, each server is a detached `docker run --rm` container with
  its own mapped host port, temp blob root, and `SOLAND_*` runtime env.
- In joint Playwright Docker mode, the runner keeps soland containers until
  teardown so `docker logs` can be copied into the joint e2e artifact directory
  even when startup or a test assertion fails.
- Multi-server Docker scenarios create one unique bridge network per test group
  and remove it on drop, mirroring Complement's deployment scoping.
- Both runtimes use the same host-side health polling and the same actor/test
  client code, so scenario behavior does not diverge by runtime.

## How results are shown

`run-server-conformance.ps1` does three things:

1. streams the normal `cargo test` output to the terminal
2. saves the full raw log
3. writes machine-readable and human-readable summaries

Artifacts are written to
`artifacts/runs/server-conformance/<timestamp>-<profile>/`, including `raw.log`,
`transcript.ndjson`, summaries, JUnit, metadata, coverage/gate/gap reports,
CI-profile reports, secret-scan reports, and `services/<service>.log`.

Stable mirrors are:

- `artifacts/latest/server-conformance/` for the most recent unfiltered complete run
- `artifacts/latest/joint-e2e/` for the most recent non-targeted joint-e2e
  suite, including the dedicated `run-server-conformance.ps1 -Profile joint` entrypoint

The Markdown summary is the primary “show me the result” artifact. It includes:

- runtime mode
- selected SUT
- start and finish timestamps
- duration
- pass/fail/ignored counts
- failing test list when present
- per-test status table

This is the `cotest` equivalent of Complement's `go test -json | gotestfmt`
story, except the formatting is emitted directly as saved Markdown and JSON
artifacts rather than depending on an external pretty-printer.

The runner now also emits:

- JUnit XML for CI systems
- HTML for a quick human-readable report outside the terminal
- a redacted request/response transcript for HTTP debugging without leaking
  bearer tokens or invite/push secrets
- profile coverage matrix JSON/Markdown derived from
  `config/coverage-profiles.json`
- unresolved remaining tasks derived from `_todos.md`
- per-run SUT/spec metadata including local git revision and fixture fingerprint
- per-service logs captured by the harness
- selected CI profile and any quarantined test filters
- coverage regression gate output
- no-secret-in-log scan over raw logs, transcripts, and service logs

## Recommended usage

- Use `process` mode while iterating on server code and test logic.
- Use `docker` mode when you need a shareable, reproducible black-box run closer
  to how Complement validates homeserver images.
- Use `run-joint-e2e.ps1 -SolandRuntime docker` for release-quality browser/API
  verification, especially when checking that the built image still exposes the
  expected `/_arkret/*` service surface.
- Use `artifacts/latest/server-conformance/summary.md` for the latest complete result.
  Targeted/profile runs remain in their timestamped authoritative directories.
- `process` mode is the authoritative path for validating the current local
  `soland` checkout.
- `docker` mode should be preceded by
  `.\scripts\build-soland-image.ps1 -ImageTag cotest-soland:latest` so the SUT
  image reflects the current `soland` tree rather than an older cached build.
