# Exact Rust SDK type-axis acceptance

`ak.suite.sdk.event_type_axes.v1` runs the nine canonical compile/serialize cases.
It also compiles generic-write bypass probes. A successful API inventory program
and all three positive executable cases must pass; compiler diagnostics are never
assertions or protocol error codes.

Supply `COTEST_SDK_ARTIFACT_MANIFEST` when running the named audit or
`exact_sdk_artifact_executes_every_canonical_type_axis_case`. The runner executes
`scripts/sdk_event_type_axes.py` against that artifact, without invoking Cargo or
rebuilding the SDK. Missing artifacts, changed hashes, absent client/MLS/signer
features and incomplete cases fail closed. `COTEST_SDK_TYPE_AXES_OUTPUT_ROOT`
optionally selects the ignored local evidence directory.

The local artifact manifest records:

- `sdk`: exact rlib path, SHA-256, package id, actual Cargo features and publication
  status; use `unpublished_candidate` for a development candidate.
- `dependencies`: same-build dependency artifact paths and SHA-256 values.
- `externs`: exact `arkret`, `chrono`, `serde`, `serde_json` and `ed25519_dalek`
  paths, all included in the hashed inventory. The Ed25519 crate must be the one
  used by the SDK signature API, including when another MLS dependency also uses
  a different crate release.
- `dependency_search`: the corresponding rustc dependency search directories.

Capture these paths from Cargo's compiler-artifact JSON, after asking Cargo for
its target directory. Preserve the exact SDK artifact rather than replacing it
with a later build. The adapter hashes inputs before and after execution and
archives compiler commands, generated fragments, compile exits and executable
results. Raw binaries and local paths stay in ignored evidence; public reports
can publish hashes and safe source fragments.

The adapter reads the canonical contract registry, generated Event kind registry
and payload schemas, then reconciles them with the actual SDK's public type
bindings. Message creation supports both protection slots: the negative protected
case passes a plaintext wrapper to the registered encrypted slot. It does not
invent a classification in which every Message Event must be encrypted.

A passing candidate run is engineering evidence. It is not a published artifact
or a signed conformance claim; issuer authorization and release configuration are
verified separately for the final claim.

The inventory also covers deferred security transaction creation. Its prepared
Event unit reuses `EventsSubmitBatchRequestBody`, retaining the complete Event
admission slots and their approval signatures. A real approval signature and
canonical round-trip control reject sidecar loss. Each adapter assertion count
records the observed compile verdict and, for positive programs, the process
exit verdict; the executable source contains its canonical byte assertions.
