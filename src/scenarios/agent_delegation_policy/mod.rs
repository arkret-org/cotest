//! P4-A.3 — `ck.profile.agent_delegation_policy.v1` coverage.
//!
//! Spec (CKP-0008 §1.4 + `capability-action-registry.json`):
//! the personal-agent surface carries 14 capability actions (11 base +
//! 3 aggregate publish/write/ensure with `migration_group` metadata).
//! Each action MUST be addressable via `ck.agent.*` and the aggregate
//! actions MUST resolve through `target_event_kinds`.

pub mod scaffold;
