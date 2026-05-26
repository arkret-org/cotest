# Fuzz corpus

C.8 — Seed corpora for the cotest fuzz harnesses under
`src/fuzz/`. Each subdirectory pairs to one fuzz entry point:

| Directory                          | Entry point                                    |
| ---------------------------------- | ---------------------------------------------- |
| `event_envelope/`                  | `cotest::fuzz::envelope_fuzz::fuzz_event_envelope`     |
| `anchor_deep/`                     | `cotest::fuzz::anchor_fuzz::fuzz_anchor_deep`          |
| `snapshot_manifest/`               | `cotest::fuzz::snapshot_fuzz::fuzz_snapshot_manifest`  |
| `snapshot_chunk_header/`           | `cotest::fuzz::snapshot_fuzz::fuzz_snapshot_chunk_header` |

Each directory starts empty (`.gitkeep` only) — the full libFuzzer
corpus is *not* committed to the repository. When promoting a finding
from the smoke test or a cargo-fuzz run, drop the minimised reproducer
into the matching directory and reference it from the failing scenario.

The smoke test in `cotest/tests/fuzz_envelope_smoke.rs` exercises the
harnesses against canonical vectors regardless of corpus state, so the
corpus directories can stay empty in CI without breaking the gate.
