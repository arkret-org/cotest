//! P4-B — `conformance-vectors.md` §11 (personal agent + sidecar).
//!
//! 9 new conformance vectors that cover the cross-server invariants
//! introduced by CKP-0008 / CKP-0009. Each vector is a single
//! happy-path scenario that exercises (a) the relevant soland endpoint
//! (when live) and (b) the SDK envelope shape (always). Deep
//! cryptographic assertions are marked `TODO(P4-impl)`.
//!
//! Vectors:
//!
//!   1. [`provisioning_pairing_grant_order`] — provisioning + pairing
//!      + capability grant MUST land in spec order; out-of-order events
//!      MUST be rejected by the reducer.
//!   2. [`pairing_expiry_auto_revoke`] — once a pairing's `expires_at` elapses, the agent_session
//!      is auto-revoked and the `ck.session.grant_revoke` event MUST carry the reason
//!      `pairing_expired`.
//!   3. [`session_grant_replay_guard`] — replay of a session_grant with the same nonce MUST be
//!      rejected by the reducer's replay guard.
//!   4. [`controller_deactivate_cascade`] — controller deactivate cascades to: (a)
//!      `ck.self.agent.deactivate` (per agent), (b) `ck.agent.key.revoke`, (c)
//!      `ck.capability.revoke`, and (d) runtime endpoint revocation. fan-out is deterministic.
//!   5. [`act_on_behalf_attribution`] — every event executed by an agent on behalf of the
//!      controller MUST carry (`executed_by`, `authorization_ref`, `actor_kind`).
//!   6. [`sidecar_circle_idempotent_ensure`] — calling `ck.self.agent.sidecar_thread.ensure` twice
//!      with the same (controller, agent) pair MUST return the same `sidecar_circle_id`.
//!   7. [`existence_privacy`] — a non-controller cannot probe for the existence of an
//!      agent_principal; the answer is indistinguishable from a not-found scope.
//!   8. [`eligibility_tristate_and_revocation`] — a capability grant's eligibility tri-state
//!      (`active` / `paused` / `revoked`) and the revocation closes the loop on capability cache
//!      invalidation.
//!   9. [`multi_agent_publish_attribution`] — when two agents (or one agent + the controller)
//!      publish into the same Realm, attribution is per-event; consumers can render distinct author
//!      panes without cross-contamination.

pub mod act_on_behalf_attribution;
pub mod controller_deactivate_cascade;
pub mod eligibility_tristate_and_revocation;
pub mod existence_privacy;
pub mod multi_agent_publish_attribution;
pub mod pairing_expiry_auto_revoke;
pub mod provisioning_pairing_grant_order;
pub mod session_grant_replay_guard;
pub mod sidecar_circle_idempotent_ensure;
