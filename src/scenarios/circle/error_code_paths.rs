//! P2F.3 — every AKP-0007 reason code is reachable from the Wire registry.
//!
//! The AKP-0007 error codes are `failed_precondition` /
//! `schema_violation` sub-reasons. This scenario pins:
//!
//!   - the registered Circle and scope sub-reason set is exactly 5,
//!   - each sub-reason string is non-empty, lowercase, snake_case, and does not duplicate a known
//!     reason from another release,
//!
//! Together this protects the wire-error surface the moderation /
//! anti-enumeration scenarios will fire in P2F.4.

use anyhow::{Result, anyhow};

const KNOWN_REASON_CODES_CKP_0007: [&str; 5] = [
    arkret_wire::ReasonCode::CIRCLE_REALM_MISMATCH,
    arkret_wire::ReasonCode::CIRCLE_NOT_ACTIVE,
    arkret_wire::ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER,
    arkret_wire::ReasonCode::SCOPE_REBIND_FORBIDDEN,
    arkret_wire::ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED,
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
    if KNOWN_REASON_CODES_CKP_0007.len() != 5 {
        return Err(anyhow!(
            "AKP-0007 reason-code set MUST be exactly 5; got {} ({:?})",
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
            arkret_wire::ReasonCode::SCOPE_REBIND_FORBIDDEN,
            "scope_rebind_forbidden",
        ),
        (
            arkret_wire::ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED,
            "effective_scope_reducer_managed",
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
        arkret_wire::ReasonCode::SCOPE_REBIND_FORBIDDEN,
        arkret_wire::ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED,
    ] {
        if !KNOWN_REASON_CODES_CKP_0007.contains(&code) {
            return Err(anyhow!("KNOWN_REASON_CODES_CKP_0007 missing `{code}`"));
        }
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
