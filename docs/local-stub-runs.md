# Local Stub Runs

cotest's primary mode is "run vectors against the SDK's typed builders and
a local soland-stub backend". This document is the source of truth for
that mode: how to invoke it, what it does and doesn't exercise, and which
tests are gated on R4 live integration.

For the spec-coverage matrix see
[`test-strategy.md` → R3 spec-coverage matrix](./test-strategy.md#r3-spec-coverage-matrix).

## What a stub run is

A "stub run" exercises cotest's e2e vectors against:

- **SDK builders, in-process** — every wire shape goes through
  `cokret-rust-sdk`'s typed builders and codecs.
- **soland-stub** — a minimal in-process soland-shaped backend that
  implements just enough of the wire surface (reducer, FSM lattices,
  audit projection) for vectors to assert.
- **floria-stub** — an in-process push-gateway shim that records inbound
  notify calls without dispatching to a real provider.

A stub run does **not** exercise:

- Real APNS / FCM / OEM push providers.
- Real LiveKit / Mediasoup / Janus / Cokret-native media backends.
- Real network transports (everything is in-process; transport-layer
  failures must be injected via the test harness).
- Cross-region replication latency or partition behavior.
- Real disk-backed Postgres (soland-stub uses an in-memory event store).

The trade-off: stub runs are deterministic, fast (typical full suite
runs in ~30s on a developer laptop), and detect protocol-level
regressions. They do NOT detect integration regressions with real
backends; for those, see the R4 live-integration section below.

## Running a stub-only suite

The default `cargo test --workspace` runs stub mode. Explicit invocations:

```sh
# Full stub suite, with transcripts captured to artifacts/runs/<ts>:
COTEST_ARTIFACT_DIR="artifacts/runs/$(date -u +%Y%m%dT%H%M%SZ)" \
    cargo test --workspace --release

# Single vector:
cargo test --workspace --release \
    --test e2e -- call_media::token_exchange_round_trip

# A spec section's worth of vectors:
cargo test --workspace --release --test e2e -- agent::
```

PowerShell equivalent (Windows):

```powershell
$env:COTEST_ARTIFACT_DIR = "artifacts/runs/$(Get-Date -Format yyyyMMddTHHmmssZ)"
cargo test --workspace --release
```

The `run-cotest.ps1` and `run-cotest.sh` wrapper scripts under
`scripts/` apply the canonical environment and capture transcripts; use
these in CI and when filing bugs.

## What stub mode covers per surface

| Surface | Stub mode covers | Stub mode does NOT cover |
|---|---|---|
| Agent FSM | All transitions, all reject paths, audit row shape | Reducer-on-real-Postgres write contention; replica lag |
| Recovery policy/receipt | Schema round-trip, policy version monotonicity, receipt emission | Cryptographic proof verification (SDK side stubbed; see test-strategy R3.1 deferred) |
| `ck.self.call.media.token_exchange` | Token shape, TTL gate, participant_binding canonical bytes, all reject paths | Live backend handshake (LiveKit / Mediasoup / etc.) |
| Handle normalization | NFC, minimal UTS#39 skeleton, mixed-script reject | Full UTS#39 confusable set (R3.1) |
| Strict-reject profile | Toggle event, reject behavior, audit row | Federation peer interaction under strict-reject |
| Push (chime ↔ floria) | Wakeup payload shape, blind/visible profile selection, nonce window | Real provider 4xx, real provider rate-limit |

## R4 live-integration `#[ignore]` tests

The following tests are present in the suite but gated behind `#[ignore]`
because they require a real backend that the stub does not provide. They
will be opened up as part of R4. To see the canonical list at any time:

```sh
cargo test --workspace --release -- --list --ignored
```

The current set:

| Test | Gate reason |
|---|---|
| `e2e::call_media::live_livekit_token_join` | Requires a live LiveKit pool; not provisionable from cotest. |
| `e2e::call_media::live_mediasoup_token_join` | Same; requires a Mediasoup pool. |
| `e2e::call_media::live_janus_token_join` | Same; requires a Janus instance. |
| `e2e::call_media::live_cokret_native_token_join` | Requires a built and running Cokret-native SFU. |
| `e2e::call_media::live_sframe_key_derivation` | Requires a real MLS group across at least two participating yougen clients to exercise the exporter handoff to SFrame. |
| `e2e::push::live_apns_dispatch` | Requires APNS credentials + a real device or sandbox-registered token. |
| `e2e::push::live_fcm_dispatch` | Requires Firebase service account + a real device. |
| `e2e::recovery::cross_replica_witness_revoke` | Requires multi-replica soland to exercise revocation-replication-lag. |
| `e2e::federation::strict_reject_peer_rollout` | Requires a second realm with a configurable accountability shape. |

These tests are run only in the R4 live-integration CI pipeline (not yet
implemented; tracked separately under R4). They are deliberately allowed
to exist in the main suite with `#[ignore]` so that:

1. The test code lives close to the rest of cotest and gets refactored
   alongside it.
2. A developer with a local backend can run a specific live test by
   name (`cargo test --release -- --ignored e2e::call_media::live_livekit_token_join`).
3. The `--list --ignored` output is the authoritative inventory of what
   R4 will need to wire up.

Do not flip an `#[ignore]` to running-by-default unless the
corresponding live backend is unconditionally available in CI. The
stub mode is the contract for what `cargo test --workspace` exercises.

## Troubleshooting stub runs

| Symptom | Likely cause | Action |
|---|---|---|
| Tests pass locally, fail in CI | env var drift (`COTEST_ARTIFACT_DIR`, `COTEST_TRANSCRIPT_PATH`) | Compare CI env to `scripts/run-cotest.*`; mirror exactly. |
| Suite hangs on a single vector | Stub deadlock in the reducer | Check if the vector uses a non-default deterministic clock; reproduce with `RUST_LOG=cotest=trace`. |
| Canonical-hash divergence on a fixture | SDK builder shape changed but fixture didn't | Regenerate the fixture via `cargo run -p cotest --bin refresh-fixtures -- <fixture-name>`; review the diff. |
| Transcript timeline shows the wrong sender for a step | Vector mis-wired its actor handles | The transcript is authoritative — re-read the vector's setup; the failure dump hook output is the ground truth. |
