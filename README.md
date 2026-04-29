# cotest

`cotest` is an out-of-repository black-box Contrix server test harness modeled
after Complement. It starts real server processes, drives public HTTP
endpoints, and uses `contrix-rust-sdk` where typed protocol helpers and client
smoke coverage are useful.

The current default server under test is
`E:\Works\contrix-dev\soland\Cargo.toml`.

## Run

```powershell
$env:COTEST_SUT_MANIFEST = "E:\Works\contrix-dev\soland\Cargo.toml"
cargo test --tests -- --nocapture
```

If `COTEST_SUT_MANIFEST` is not set, the harness falls back to the bundled
default `soland` checkout. `SERVERX_MANIFEST` is still accepted as a legacy
override to avoid breaking older local workflows.

## Layout

- `src/harness.rs`: process lifecycle, test actor helpers, and shared HTTP
  assertion utilities.
- `src/scenarios/*.rs`: executable protocol and business-domain scenarios.
- `tests/*.rs`: thin integration wrappers around scenario modules.
- `_todos.md`: Complement-derived plan and the current single-server /
  multi-server coverage matrix.
- `docs/test-strategy.md`: harness model and suite grouping.
- `docs/complement-map.md`: how Complement concepts map onto Contrix.

## Coverage Groups

- Single-server surface: service description, auth, collaboration, repo, sync,
  index, identity/authz, schema/policy, realtime signaling, delivery/media,
  permissions, payload contracts, and extension surface gaps.
- Multi-server surface: federation readiness, contract validation, and
  cross-server collaboration flows.

The suite is organized by protocol and behavior, not milestone folders.
