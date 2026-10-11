# Canonical principal provisioning — operation inventory

What `ensureRegistered`'s canonical branch actually does, step by step, so the
Rust provisioning module in [1725](../../arkret-work/tasks/impl-active/2026-09-06-1725-joint-e2e-inkson-decoupling-and-provisioning-convergence.md)'s
P2 is written against the real chain rather than a reconstruction of it.

Read this before moving any step: the split between **Coauth's private product
API** and **Arkret's standard gate operations** is the boundary P2 must keep —
standard DTOs, clients and signing belong in the SDK, the private account
product surface belongs in a Cotest-side Coauth adapter.

Source: `e2e/helpers/coauth-register.ts` and `e2e/helpers/users.ts` at cotest
`bc7086a8`. Entry point is `users.ts::ensureRegistered`, which takes this branch
whenever a Coauth base URL is configured and falls back to `ensureRegisteredRaw`
otherwise.

## The chain

| # | Call | Surface | Notes |
|---|---|---|---|
| 1 | `POST {coauth}/_coauth/account/auth/register` | Coauth private | Starts account-first registration; returns a registration id and a `next_step`. |
| 1a | `POST {coauth}/_coauth/account/auth/register/{id}/verify-email` | Coauth private | Only when `next_step == "verify_email"`. The code comes from the mock email inbox (`GET {mockEmail}/mock/email/verification/inbox`). Managed `-StartCoauth` runs start this one required mock automatically; `-StartMocks` is only needed when scenarios also require the other optional mocks. |
| 1b | `POST …/{id}/display-name`, `POST …/{id}/finish` | Coauth private | Completes the unbound account. |
| 2 | `GET {coland}/_arkret/describe` | Arkret standard | Supplies `trust_domain` and `service_id`; the latter becomes the grant audience. |
| 3 | `POST {coauth}/_arkret/gate/account/authentication-handoffs` | Arkret standard — `ak.gate.account.exchange.create_handoff.v1` | Must come back `identity_creation_active` with an `identity_creation_lease`. |
| 4 | `cotest-wire principal-registration-fixture` | **Rust, already** | Builds the DID operation, PCR genesis unit, 24-word recovery key and initial session from the lease + trust domain + device key. No HTTP. |
| 5 | `POST {coauth}/_arkret/gate/account/identity-binding-challenges` | Arkret standard — `ak.gate.account.command.issue_identity_binding_challenge.v1` | Authorized by the handoff grant + a matching DPoP proof over this exact method/URL. |
| 6 | `cotest-wire identity-creation-register-request` | **Rust, already** | Assembles the register body from the challenge, DID operation, PCR genesis unit, initial session and recovery key. No HTTP. |
| 7 | `POST {coauth}/_arkret/gate/account/register` | Arkret standard — `ak.gate.account.command.register.v1` | Returns `binding_receipt`, the two `pcr_genesis_commits`, and `session_grant_outcome` — the initial DPoP-bound grant, its audience, `dpop_jkt`, scopes and the founding event signing key. |
| 8 | `POST {coland}/_coland/gate/account/project` | Coland deployment-private | An idempotent replay, not a required step. Coauth already performs this projection inside the canonical register saga (`crates/backend/src/handlers/arkret/account_register.rs:546`, before any usable grant leaves it), and `ensureRegisteredRaw` accepts the 409 that comes back. What the caller actually wants here is its other half, the local `registerEventSigner`. |

Second devices do not repeat this chain: `createDpopUserSessionForAccount`
fails closed on a second call for the same account, because reusing the founding
handoff would author a second founding transaction. Sibling devices go through
the pairing ceremony instead.

## What this means for P2

**Steps 4 and 6 are already in Rust.** The protocol material — DID operations,
PCR genesis, recovery key, register body — is built by `cotest-wire`, and the
TypeScript side only passes it along. So the work is not "port the protocol
construction"; it is "move the HTTP orchestration to where the construction
already lives", which is a much smaller and much less error-prone change.

**Steps 1, 1a and 1b are Coauth product API**, not protocol. They belong in a
named Coauth adapter on the Cotest side, typed against Coauth's own types. They
must not be dressed up as spec operations.

**Steps 2, 3, 5 and 7 are standard operations** with registered operation ids.
Each needs a strongly typed SDK client method; where one is missing it is filed
per R03 batch C rather than hand-rolled here.

**Step 8 is a packaging problem, not a service gap.** `ensureRegisteredRaw` does
two unrelated things — the private projection call and a local
`registerEventSigner` — and the canonical path calls it for the second while
paying for the first. Split them, and the canonical chain stops touching a
deployment-private endpoint at all.
