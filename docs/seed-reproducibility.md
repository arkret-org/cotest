# Failed fuzz case replay (P5.2)

Generated: 2026-05-27 — pairs with `cotest/fuzz/` (the cargo-fuzz
sub-crate added in P5.1) and the in-process smoke test at
`tests/fuzz_envelope_smoke.rs`.

This page is the operator runbook for reproducing a fuzz finding from
either CI or a local run.

## Where findings land

### From the CI `fuzz` job (`.github/workflows/ci.yml`)

When `cargo fuzz run <target> -- -max_total_time=60` finds a crash, it
writes the minimised reproducer into
`cotest/fuzz/artifacts/<target>/crash-<sha1>` and re-prints the input as
base64 to stdout. The job uploads `cotest/fuzz/artifacts/` as a CI
artifact (`fuzz-artifacts`) so the on-call engineer can download the
reproducer without re-running the search.

The CI job uses these libFuzzer defaults (set inside `cargo fuzz run` —
do not override unless reproducing a CI finding locally):

| Setting                | Value           | Note                                                          |
|------------------------|-----------------|---------------------------------------------------------------|
| `-max_total_time`      | `60` seconds    | Per-target wall-clock budget.                                 |
| `-rss_limit_mb`        | `2048` (default)| libFuzzer default; cotest fuzz harness is bounded well below. |
| `-timeout`             | `25` (default)  | Per-input deadline; raised only for the deep-anchor target.   |
| `-print_final_stats`   | `1`             | Forces the corpus/coverage summary to land in CI logs.        |

### From the local smoke test (`tests/fuzz_envelope_smoke.rs`)

The smoke test uses a deterministic xorshift-derived PRNG seeded from
`iter_index`. When the smoke test panics, the failing iteration index is
the seed; together with the constants `ITERATIONS=1000` /
`INPUT_BYTES=256` in `tests/fuzz_envelope_smoke.rs`, the input is
exactly reproducible without storing the bytes.

## Seed format

The reproducer is stored in two equivalent forms:

### A. libFuzzer minimised crash file

```
cotest/fuzz/artifacts/<target>/crash-<sha1-of-input>
```

This is the raw input bytes — feed it back into `cargo fuzz run`:

```powershell
cd cotest
cargo fuzz run <target> fuzz/artifacts/<target>/crash-<sha1>
```

The target reproduces the crash deterministically against the *same*
toolchain version. If the toolchain has bumped between the CI finding
and the local repro, pin to the CI-recorded `rustc -V` (printed in the
job's "Setup Rust" step output).

### B. Smoke-test seed line

For panics surfaced by `tests/fuzz_envelope_smoke.rs`, the panic
message contains a line like:

```
iter 471 panicked: validator: <reason>
```

That `471` is the only seed you need. Reproduce with:

```rust
// in a one-off Rust scratch file
let seed: u64 = 471;
let mut buffer = vec![0u8; 256];     // INPUT_BYTES from the smoke test
fill_random(seed, &mut buffer);      // copy fill_random verbatim from the smoke test
cotest::fuzz::envelope_fuzz::fuzz_event_envelope(&buffer)
    .expect_err("expected the original panic");
```

`fill_random` is the xorshift64* helper at the top of
`tests/fuzz_envelope_smoke.rs`. It is stdlib-only on purpose so the seed
format never depends on a `rand` version pin.

## Promoting a finding into the corpus

Once a finding is reproduced and root-caused, drop the minimised input
into the matching seed corpus under `cotest/fuzz/corpus/<target>/` so
the next fuzz run starts with the regression already covered:

| Target           | Corpus directory                          |
|------------------|-------------------------------------------|
| `envelope_fuzz`  | `cotest/fuzz/corpus/event_envelope/`      |
| `snapshot_fuzz`  | `cotest/fuzz/corpus/snapshot_manifest/` and `.../realm_state_snapshot_chunk_header/` |
| `seal_fuzz`      | `cotest/fuzz/corpus/seal_deep/`           |

The seed filename should be `regression-<issue-id>` so reviewers can
trace it back to the originating bug. Reference the seed from the
regression's Rust test (a new `#[test]` under
`tests/fuzz_envelope_smoke.rs` or a sibling regression test) so the
guard stays in CI even if the libFuzzer corpus is later pruned.

## Replay flowchart

```
                ┌──────────────────────┐
                │ fuzz finding observed │
                └─────────┬────────────┘
                          │
            ┌─────────────┴─────────────┐
            │                            │
            ▼                            ▼
  ┌──────────────────┐         ┌────────────────────┐
  │ CI cargo-fuzz job │         │ local smoke_test   │
  └────────┬─────────┘         └──────────┬─────────┘
           │                              │
           ▼                              ▼
 download `fuzz-artifacts`       record `iter N panicked`
 from the failed CI run          from the panic message
           │                              │
           ▼                              ▼
 cd cotest && cargo fuzz run    rebuild input via xorshift64*
   <target> fuzz/artifacts/      with seed = N (see snippet above)
   <target>/crash-<sha1>
           │                              │
           └──────────────┬───────────────┘
                          ▼
                 root-cause + fix
                          │
                          ▼
                drop seed into
        cotest/fuzz/corpus/<target>/regression-<id>
                          │
                          ▼
                add explicit #[test] in
              tests/fuzz_envelope_smoke.rs
                so CI guards the regression
```

## Source of truth

- `cotest/fuzz/Cargo.toml` — cargo-fuzz crate definition.
- `cotest/fuzz/fuzz_targets/{envelope,snapshot,anchor}_fuzz.rs` —
  libFuzzer entry points.
- `cotest/src/fuzz/{envelope,snapshot,anchor}_fuzz.rs` — the
  arbitrary-derived input types and validator wiring shared between the
  smoke test and the libFuzzer targets.
- `cotest/tests/fuzz_envelope_smoke.rs` — deterministic in-process
  regression guard.
- `.github/workflows/ci.yml` job `fuzz` — CI runner (60s per target,
  5 min wall-clock cap).
