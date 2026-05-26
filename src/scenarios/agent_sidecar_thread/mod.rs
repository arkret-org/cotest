//! P4-A.4 — `cx.profile.agent_sidecar_thread.v1` coverage.
//!
//! Spec (CXP-0009 + spec head 37ce729 §B-F): the sidecar thread is a
//! 1:1 Circle between the controller and the agent runtime; ensure is
//! idempotent; home-realm policy is "context realm preferred"
//! (`AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED`).

pub mod scaffold;
