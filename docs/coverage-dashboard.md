# cotest Local Coverage Dashboard

Generated from `artifacts/runs/20260525-055932/journey-coverage.md`.

## Release-Gate Coverage

| Metric | Value |
|---|---:|
| Promised checks | 395 |
| Verified checks | 171 |
| Verified ratio | 43.3% |
| Verified-only gate | passed |
| Blocking fixmes | 163 |

## Journey Coverage

| Journey | Verified | Promised | Coverage | Blocking |
|---|---:|---:|---:|---:|
| UJ-A - First login and multi-device recovery | 20 | 79 | 25.3% | 59 |
| UJ-B - Workspace creation, invites, and archive visibility | 14 | 32 | 43.8% | 18 |
| UJ-C - Daily messaging, edits, reactions, receipts, and mentions | 30 | 45 | 66.7% | 15 |
| UJ-D - Encrypted realm lifecycle and cross-device decrypt | 13 | 36 | 36.1% | 23 |
| UJ-E - Federation and cross-domain collaboration | 10 | 20 | 50.0% | 10 |
| UJ-F - Kanban collaboration and concurrent work | 18 | 43 | 41.9% | 25 |
| UJ-G - Privacy rights, governance, appeal, and GDPR | 20 | 37 | 54.1% | 17 |
| UJ-H - Calls, push, and cross-platform sync | 9 | 25 | 36.0% | 16 |

## Interpretation

The local `release-gate` profile is green and has no coverage regressions, but
the master-plan 70% journey target is not yet met. Keep the UJ-A, UJ-D, UJ-F,
and UJ-H burn-down tasks open until their fixme counts are reduced by live
scenario coverage rather than by lowering promised coverage.
