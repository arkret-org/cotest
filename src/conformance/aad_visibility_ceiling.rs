//! `ak.vector.aad_visibility.policy_ceiling.v1` — the Realm ceiling on
//! encrypted-envelope `aad_visibility_event_id`
//! (`crypto-media/encryption-and-audit.md` §§2.3.2 / 2.8).
//!
//! The rule is cross-object: it compares the `aad_visibility.event_id`
//! component of the accepted `ak.realm.policy_bundle` against the
//! `aad_visibility_event_id` discriminator of an encrypted envelope. JSON
//! Schema cannot express that, which is why it is a conformance vector rather
//! than a schema case.
//!
//! Three properties, all of which this suite drives through the SDK's shared
//! [`AadVisibilityCeiling`] — the same judgement entry the service ingest path
//! and the client sealing path call, so a divergence here is a real divergence
//! and not a test-local reimplementation:
//!
//! 1. the order is a **ceiling**, not an equality: `hidden < routing_digest < opaque_id`, and an
//!    envelope at or below the declared value is admissible;
//! 2. a wider envelope is rejected with `aad_visibility_policy_violation` and MUST NOT be silently
//!    downgraded to `hidden`;
//! 3. an **absent** component is the `hidden` ceiling — fail-closed — not an absent constraint.
//!
//! Property 3 is the one worth spelling out: reading "the Realm did not declare
//! a ceiling" as "do not check" would turn §2.3.2's "MUST declare" back into
//! dead prose, and would let every `routing_digest` envelope through on a Realm
//! that never opted in.

use anyhow::{Result, bail};
use arkret_models_crypto::{AadVisibilityCeiling, EncryptedEnvelopeAadVisibility};
use serde_json::Value;

use super::security_closure::SecurityClosureFixture;

pub const VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING: &str =
    "ak.vector.aad_visibility.policy_ceiling.v1";

/// Reason code a receiver reports for an over-wide envelope. It is a sub-reason
/// of `failed_precondition`, never a `schema_violation`: the envelope is
/// well-formed, it is the Realm policy it fails.
pub const REASON_AAD_VISIBILITY_POLICY_VIOLATION: &str = "aad_visibility_policy_violation";

/// Decide one `(policy, envelope)` pair exactly as an implementation must.
///
/// `declared` is `None` when the Realm's accepted bundle carries no
/// `aad_visibility` component.
fn decide(
    declared: Option<EncryptedEnvelopeAadVisibility>,
    envelope: EncryptedEnvelopeAadVisibility,
) -> std::result::Result<(), String> {
    AadVisibilityCeiling::from_declared(declared)
        .check(envelope)
        .map_err(|error| error.to_string())
}

fn visibility(value: &str) -> Result<EncryptedEnvelopeAadVisibility> {
    Ok(serde_json::from_value(Value::String(value.to_owned()))?)
}

/// Run the four fixture steps against the shared ceiling entry.
///
/// The expectations are read out of the spec fixture rather than restated here,
/// so a spec-side edit that changes an outcome fails this vector instead of
/// silently agreeing with a stale copy.
pub fn run_aad_visibility_policy_ceiling_vector() -> Result<()> {
    let fixture = SecurityClosureFixture::load()?;
    let vector = fixture.vector(VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING)?;
    if vector.steps.len() != 4 {
        bail!(
            "{VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING} expects 4 steps, fixture has {}",
            vector.steps.len()
        );
    }

    let mut saw_absent_component = false;
    for step in &vector.steps {
        let input = &step.input;
        // A step either declares a component value or explicitly declares the
        // component absent. Anything else means the fixture shape drifted.
        let declared = match (
            input
                .get("policy_aad_visibility_event_id")
                .and_then(Value::as_str),
            input
                .get("policy_aad_visibility_component_present")
                .and_then(Value::as_bool),
        ) {
            (Some(value), None) => Some(visibility(value)?),
            (None, Some(false)) => {
                saw_absent_component = true;
                None
            }
            _ => bail!(
                "{VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING} step `{}` does not state the policy \
                 component",
                step.name
            ),
        };
        let envelope = visibility(
            input
                .get("envelope_aad_visibility_event_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING} step `{}` has no envelope \
                         discriminator",
                        step.name
                    )
                })?,
        )?;

        let observed = decide(declared, envelope);
        match (step.expected.outcome.as_str(), &observed) {
            ("accepted", Ok(())) => {}
            ("rejected", Err(error)) => {
                let expected_reason = step
                    .expected
                    .reason_code
                    .as_deref()
                    .unwrap_or(REASON_AAD_VISIBILITY_POLICY_VIOLATION);
                if !error.contains(expected_reason) {
                    bail!(
                        "{VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING} step `{}` rejected with `{error}`, \
                         expected reason `{expected_reason}`",
                        step.name
                    );
                }
            }
            ("accepted", Err(error)) => bail!(
                "{VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING} step `{}` must be accepted, got `{error}`",
                step.name
            ),
            ("rejected", Ok(())) => bail!(
                "{VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING} step `{}` must be rejected; accepting it \
                 is the silent-downgrade failure the vector exists to catch",
                step.name
            ),
            (other, _) => bail!(
                "{VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING} step `{}` has unknown outcome `{other}`",
                step.name
            ),
        }
    }

    if !saw_absent_component {
        bail!(
            "{VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING} lost its absent-component case; without it \
             nothing proves an undeclared ceiling is `hidden` rather than unchecked"
        );
    }

    // Independent of the fixture: the disclosure order itself. A reshuffle here
    // would silently widen every ceiling, and the fixture only exercises the
    // pairs it happens to list.
    use EncryptedEnvelopeAadVisibility::{Hidden, OpaqueId, RoutingDigest};
    if !(Hidden < RoutingDigest && RoutingDigest < OpaqueId) {
        bail!(
            "{VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING}: disclosure order must be \
             hidden < routing_digest < opaque_id"
        );
    }
    // A rejection must never be recoverable by rewriting the envelope: the
    // decision entry returns an error, it does not return a downgraded value.
    if decide(Some(Hidden), OpaqueId).is_ok() {
        bail!(
            "{VECTOR_ID_AAD_VISIBILITY_POLICY_CEILING}: an over-wide envelope was admitted under \
             the hidden ceiling"
        );
    }
    Ok(())
}
