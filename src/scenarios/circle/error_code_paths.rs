//! P2F.3 — every AKP-0007 reason code is reachable from the Wire registry.
//!
//! Eight of the nine AKP-0007 error codes are `failed_precondition` /
//! `schema_violation` sub-reasons; the ninth (`delivery_binding_handed_over`)
//! is a top-level wire error code introduced in AKP-0006 and re-used by the
//! Circle delivery binding migration path. This scenario pins:
//!
//!   - the sub-reason set [`KNOWN_REASON_CODES_CKP_0007`] is exactly 10,
//!   - each sub-reason string is non-empty, lowercase, snake_case, and does not duplicate a known
//!     reason from another release,
//!   - the top-level `arkret_wire::ErrorCode::DELIVERY_BINDING_HANDED_OVER` is registered via
//!     [`is_known_error_code`] and resolves to a non-`None` HTTP status binding.
//!
//! Together this protects the wire-error surface the moderation /
//! anti-enumeration scenarios will fire in P2F.4.

use anyhow::{Result, anyhow};
use arkret_wire::{error_code_http_status, is_known_error_code};

const KNOWN_REASON_CODES_CKP_0007: [&str; 10] = [
    arkret_wire::ReasonCode::CIRCLE_REALM_MISMATCH,
    arkret_wire::ReasonCode::CIRCLE_NOT_ACTIVE,
    arkret_wire::ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER,
    arkret_wire::ReasonCode::CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR,
    arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_VIOLATION,
    arkret_wire::ReasonCode::SCOPE_REBIND_FORBIDDEN,
    arkret_wire::ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED,
    arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_VIOLATION,
    arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_DOWNGRADE,
    arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_DOWNGRADE,
];

fn is_snake_case_lowercase(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !s.starts_with('_')
        && !s.ends_with('_')
        && !s.contains("__")
}

pub async fn error_code_paths_run() -> Result<()> {
    if KNOWN_REASON_CODES_CKP_0007.len() != 10 {
        return Err(anyhow!(
            "AKP-0007 reason-code set MUST be exactly 10; got {} ({:?})",
            KNOWN_REASON_CODES_CKP_0007.len(),
            KNOWN_REASON_CODES_CKP_0007
        ));
    }

    // Spot-pin every AKP-0007 reason code spelling against the constant.
    for (constant, expected) in [
        (
            arkret_wire::ReasonCode::CIRCLE_REALM_MISMATCH,
            "circle_realm_mismatch",
        ),
        (
            arkret_wire::ReasonCode::CIRCLE_NOT_ACTIVE,
            "circle_not_active",
        ),
        (
            arkret_wire::ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER,
            "circle_member_must_be_realm_member",
        ),
        (
            arkret_wire::ReasonCode::CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR,
            "circle_encryption_below_realm_floor",
        ),
        (
            arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_VIOLATION,
            "content_encryption_floor_violation",
        ),
        (
            arkret_wire::ReasonCode::SCOPE_REBIND_FORBIDDEN,
            "scope_rebind_forbidden",
        ),
        (
            arkret_wire::ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED,
            "effective_scope_reducer_managed",
        ),
        (
            arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_VIOLATION,
            "metadata_encryption_floor_violation",
        ),
        (
            arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_DOWNGRADE,
            "content_encryption_floor_downgrade",
        ),
        (
            arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_DOWNGRADE,
            "metadata_encryption_floor_downgrade",
        ),
    ] {
        if constant != expected {
            return Err(anyhow!(
                "AKP-0007 reason code spelling drifted: constant=`{constant}` expected=`{expected}`"
            ));
        }
        if !is_snake_case_lowercase(constant) {
            return Err(anyhow!(
                "AKP-0007 reason code `{constant}` is not snake_case lowercase"
            ));
        }
    }
    // The whole array MUST also contain each spotted code.
    for code in [
        arkret_wire::ReasonCode::CIRCLE_REALM_MISMATCH,
        arkret_wire::ReasonCode::CIRCLE_NOT_ACTIVE,
        arkret_wire::ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER,
        arkret_wire::ReasonCode::CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR,
        arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_VIOLATION,
        arkret_wire::ReasonCode::SCOPE_REBIND_FORBIDDEN,
        arkret_wire::ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED,
        arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_VIOLATION,
        arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_DOWNGRADE,
        arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_DOWNGRADE,
    ] {
        if !KNOWN_REASON_CODES_CKP_0007.contains(&code) {
            return Err(anyhow!("KNOWN_REASON_CODES_CKP_0007 missing `{code}`"));
        }
    }

    // Sixth AKP-0007 code is a top-level wire error.
    if !is_known_error_code(arkret_wire::ErrorCode::DELIVERY_BINDING_HANDED_OVER) {
        return Err(anyhow!(
            "arkret_wire::ErrorCode::DELIVERY_BINDING_HANDED_OVER (`delivery_binding_handed_over`) \
             not registered with is_known_error_code"
        ));
    }
    let status = error_code_http_status(arkret_wire::ErrorCode::DELIVERY_BINDING_HANDED_OVER);
    if status.is_none() {
        return Err(anyhow!(
            "arkret_wire::ErrorCode::DELIVERY_BINDING_HANDED_OVER has no HTTP status binding; \
             error-code-registry.json must list one"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ckp_0007_reason_codes_well_formed_and_registered() {
        error_code_paths_run().await.unwrap();
    }
}
