//! P4-A.1 — `ck.profile.personal_agent_provisioning.v1` coverage.
//!
//! Spec (CKP-0008 + spec head 37ce729) gates: provisioning emits a
//! `ck.self.agent.provision` event that materializes (a) an `agent_principal`
//! typed-id, (b) a controller DID binding, (c) a freshly authorized
//! `agent_key`, and (d) the first `accountability_grant` attaching the
//! agent runtime to the controller's capability surface.
//!
//! This module pins the SDK-side contract surface ahead of soland's
//! reducer impl: typed-id prefixes are well-formed, the 11 operation IDs
//! the controller cycles through are registered, and the envelope shape
//! for `ck.self.agent.provision` rejects client-supplied `actor_kind` per the
//! reducer-stamping invariant (§1.1).
//!
//! Live-server runs (against soland's 11 new agent endpoints) live in
//! `tests/agent_profile_scenarios.rs`; the SDK-pure scaffold here is the
//! gate that runs under `cargo test --workspace` without bootstrapping a
//! live SUT.

pub mod scaffold;
