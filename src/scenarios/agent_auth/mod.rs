//! P4-A.2 — `ck.profile.agent_auth.v1` coverage.
//!
//! Spec (CKP-0008 §1.2 + `event-payload.schema.json` `agent_key_authorize_payload`):
//! agent runtime authn uses a dedicated `agent_key_proof` branch of
//! `SessionGrantRequest`. The `agent_key_authorize_payload` carries an
//! optional `runtime_attestation` whose v1 baseline `kind` is
//! `self_asserted`; unknown kinds MUST fail-closed.

pub mod scaffold;
