# Complement-Inspired Cokret Test Map

Complement treats a homeserver as a black box: deploy real instances, create
high-level test clients, and validate protocol behavior by domain. `cotest`
applies the same pattern to Cokret.

## Concept Mapping

- Complement deployment helpers map to `CokretServer` and `TestServerGroup`.
  `cotest` now supports both host-spawned local processes and Docker-backed SUT
  instances under the same harness.
- Complement client helpers map to `TestActorClient`, shared HTTP assertions,
  and selected `cokret-rust-sdk` helpers.
- Complement's domain-oriented test packages map to `src/scenarios/*.rs`.
- Complement federation coverage maps to `federation_readiness`,
  `federation_contract`, and `federation_collaboration`.
- Complement's out-of-repo discipline maps to keeping reusable logic in `src/`
  and leaving `tests/` as wrappers only.
- Complement's base-image workflow maps to `COTEST_SUT_IMAGE` plus
  [docker/soland.Dockerfile](/E:/Works/cokret-dev/cotest/docker/soland.Dockerfile:1)
  and [scripts/build-soland-image.ps1](/E:/Works/cokret-dev/cotest/scripts/build-soland-image.ps1:1),
  including Docker cache controls for CI builds.
- Complement's result-formatting story maps to
  [scripts/run-cotest.ps1](/E:/Works/cokret-dev/cotest/scripts/run-cotest.ps1:1),
  which emits raw logs, redacted HTTP transcripts, and Markdown/JSON summaries
  under `artifacts/`.

## Image and runtime model

Complement typically expects a prebuilt homeserver image selected through
`COMPLEMENT_BASE_IMAGE`, then uses `internal/docker/builder.go` and
`internal/docker/deployer.go` to create deployment-scoped Docker resources.

`cotest` now mirrors that model like this:

- Image build entrypoint:
  [scripts/build-soland-image.ps1](/E:/Works/cokret-dev/cotest/scripts/build-soland-image.ps1:1)
  builds `cotest-soland:latest`.
- Image source:
  [docker/soland.Dockerfile](/E:/Works/cokret-dev/cotest/docker/soland.Dockerfile:1)
  compiles `soland` together with the sibling `cokret-rust-sdk` checkout.
- Build context control:
  `E:\Works\cokret-dev\.dockerignore` limits Docker context to the trees needed
  for the SUT image, instead of sending the entire workspace.
- Runtime selector:
  `COTEST_SUT_MODE=process|docker` chooses either local `cargo run` or
  container-backed execution.
- Multi-server deployment:
  `TestServerGroup::multi` creates an isolated Docker bridge network in
  `docker` mode so federated scenarios run in one controlled runtime boundary.

This is intentionally simpler than Complement's blueprint-image machinery:
`cotest` currently builds one source-based `soland` image and uses runtime
configuration plus host-side actor setup to shape each test.

## Startup, run, and result display

Complement runs Go tests on the host while homeservers live in containers, and
optionally pretty-prints `go test -json` output with `gotestfmt`.

`cotest` now has the same separation of concerns:

- host-side `cargo test`
- SUT spawned as either child process or Docker container
- one script entrypoint for execution:
  [scripts/run-cotest.ps1](/E:/Works/cokret-dev/cotest/scripts/run-cotest.ps1:1)
- persisted result artifacts:
  `artifacts/runs/<timestamp>/raw.log`,
  `artifacts/runs/<timestamp>/transcript.ndjson`,
  `artifacts/runs/<timestamp>/summary.json`,
  `artifacts/runs/<timestamp>/summary.md`,
  `artifacts/runs/<timestamp>/summary.html`,
  `artifacts/runs/<timestamp>/junit.xml`,
  `artifacts/runs/<timestamp>/coverage-matrix.json`,
  `artifacts/runs/<timestamp>/coverage-gate.json`,
  `artifacts/runs/<timestamp>/unresolved-gaps.json`,
  `artifacts/runs/<timestamp>/ci-profile.json`,
  `artifacts/runs/<timestamp>/secret-scan.json`,
  `artifacts/runs/<timestamp>/services/`,
  and `artifacts/latest/`

The Markdown summary is the primary human-readable report. That gives `cotest`
an explicit result surface comparable to Complement's formatter pipeline,
without making users reconstruct the run from terminal scrollback.

In addition to runtime results, `cotest` now has an offline fixture-driven
conformance surface in [src/conformance.rs](/E:/Works/cokret-dev/cotest/src/conformance.rs:1),
which consumes the spec-owned machine-readable artifacts under
`cokret-spec/spec/v1/artifacts`: schemas, registries, profiles, OpenAPI, non-HTTP
bindings, and fixtures. Complement does not need this exact layer because
Matrix homeserver behavior is mostly expressed directly through networked
black-box tests; Cokret benefits from keeping protocol vectors and server
scenarios side by side.

## Coverage Translation

- Service and framework surface:
  health, server description, supported operations, unknown routes, bad JSON,
  wrong methods, and standard error envelopes.
- Account and social graph:
  register, login, logout, session checks, duplicate handling, and contact
  edge cases.
- Collaboration and policy:
  space lifecycle, membership, permissions, sync projection, and private
  plaintext policy enforcement.
- Events and sync:
  event submission, idempotency, dependency conflicts, read paths, event sync,
  directory/index parameter handling, and expanded event reads.
- Identity, authz, and realtime:
  identity resolution/log/receipts, grant and policy document lifecycle,
  presence/typing, push rules, and WebRTC signaling.
- Delivery and media:
  keys, to-device delivery, blob upload/download, range requests,
  anti-enumeration/privacy guards, and payload preservation.
- Federation:
  readiness checks, public contract validation, and end-to-end cross-server
  collaboration behavior.
- Extension gaps:
  executable coverage for missing applet/agent route surfaces so gaps remain
  visible without leaving ignored placeholder tests behind.
