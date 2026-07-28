# Playwright fixme audit

Audit date: 2026-07-29.

The audit started with 41 `test.fixme` definitions in 13 files. A fixme is
allowed only when it already contains meaningful executable assertions and
names a concrete implementation gap, user promise, and expected delivery
window. Scenario prose and empty callback bodies are not executable evidence.

## Disposition

| Disposition | Count | Rationale |
|---|---:|---|
| Deleted empty placeholders | 21 | They executed no checks and duplicated scenario/spec prose. |
| Deleted tests for unpublished extension operations | 3 | WebSocket/TSP negotiation and relay-inner operations are not registered v1 interoperability surfaces. |
| Promoted to live test | 0 | The only candidate, Strand Move CAS, exposed a real sealing-path gap during live verification. |
| Retained executable fixme | 17 | Each has real assertions and a current cross-repository implementation gap. |

The deleted placeholder groups were:

- policy-server allow-path cache TTL;
- encrypted DND restore on a fresh device;
- MIMI end-to-end business-chain promises;
- account/device authorization prose promises;
- cross-server account suspension prose promise;
- four recovery/re-anchor prose promises;
- eight identity root-custody/re-anchor prose promises.

The three removed transport promises required unregistered
`ak.transport.negotiate`, WebSocket binding, or relay-inner interoperability
operations. The v1 HTTP federation tests in the same spec remain live.

## Retained fixme groups

| Area | Count | Blocking implementation |
|---|---:|---|
| Verified organization badge | 3 | Soland/Teabay relationship projection and revocation |
| Realm Recovery Key durability | 4 | Soland durability projection plus Inkson seal/open and retry evidence |
| Organization statement bootstrap | 3 | Coauth delegation issuance and Soland statement verification |
| Organization policy inheritance | 4 | Soland statement reducer, effective policy, badge, and revocation |
| Core object invariants | 3 | Accepted Control Move sealing, Space lifecycle/spec convergence, and View projection materializer |

Every retained item has:

- non-empty executable assertions;
- `@blocking-on`;
- `@user-promise`;
- `@expected-live-by`.

`npm run check:fixme` enforces this policy and prevents empty fixme callbacks
from re-entering the suite.

## Promotion rule

A retained fixme may become `test(...)` only after its implementation lands,
the focused live command passes, and a trace/HAR/screenshot artifact is
retained. A repeatable Agent Journey discovery should follow the same path:
first classify and reproduce it, then add or promote a deterministic
Playwright regression.
