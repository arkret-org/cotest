//! P2F.3 — Space `child_scope_policy` reducer-pure enforcement (CXP-0007 §3.4.2).
//!
//! Spec §3.4.2 normative rules:
//!
//! - `allow_any` — no additional constraint on the child's `effective_scope` / `scope_circle_id`.
//! - `require_e2ee` — child's `effective_scope` MUST be MLS-backed: it MUST be a Circle scope, or
//!   the Realm-default MLS scope when the parent Realm declares
//!   `Realm.encryption_profile=mls_rfc9420`.
//! - `require_same_scope` — child's `scope_circle_id` MUST equal the parent Space's
//!   `scope_circle_id` (including both being `None`).
//! - `require_scope_circle_id` — child's `scope_circle_id` MUST equal the named Circle in the
//!   policy.
//!
//! The SDK exposes the [`ChildScopePolicy`] enum but no reducer-pure
//! `enforce_child_scope_policy` helper; this scenario defines the
//! reducer-pure predicate locally and exercises ≥ 2 cases per branch
//! (satisfies + violates).

use anyhow::{Result, anyhow};
use contrix_core::{ChildScopePolicy, CircleId, EncryptionProfile};

/// Reducer-pure predicate for `Space.child_scope_policy` enforcement.
///
/// `policy`              the Space's policy.
/// `child_scope`         the child Flow / Space's `scope_circle_id`.
/// `parent_space_scope`  the parent Space's `scope_circle_id` (only used
///                       by `require_same_scope`).
/// `realm_encryption_profile`
///                       the parent Realm's `encryption_profile` — used by
///                       `require_e2ee` to determine whether the
///                       Realm-default scope counts as MLS-backed.
///
/// Returns `Ok(())` when the child satisfies the policy, `Err` otherwise.
fn enforce_child_scope_policy(
    policy: &ChildScopePolicy,
    child_scope: Option<&CircleId>,
    parent_space_scope: Option<&CircleId>,
    realm_encryption_profile: EncryptionProfile,
) -> Result<()> {
    match policy {
        ChildScopePolicy::AllowAny { .. } => Ok(()),
        ChildScopePolicy::RequireE2ee { .. } => match child_scope {
            Some(_) => Ok(()), // Circle scope is always MLS-backed.
            None => match realm_encryption_profile {
                EncryptionProfile::MlsRfc9420 => Ok(()),
                _ => Err(anyhow!(
                    "child_scope_policy=require_e2ee but child is Realm-default \
                     and Realm.encryption_profile=`{realm_encryption_profile:?}` is \
                     not MLS-backed (CXP-0007 §3.4.2)"
                )),
            },
        },
        ChildScopePolicy::RequireSameScope { .. } => {
            let child_s = child_scope.map(|c| c.as_str());
            let parent_s = parent_space_scope.map(|c| c.as_str());
            if child_s == parent_s {
                Ok(())
            } else {
                Err(anyhow!(
                    "child_scope_policy=require_same_scope: child scope={child_s:?} \
                     differs from parent Space scope={parent_s:?} (CXP-0007 §3.4.2)"
                ))
            }
        }
        ChildScopePolicy::RequireScopeCircleId {
            scope_circle_id, ..
        } => match child_scope {
            Some(child) if child.as_str() == scope_circle_id.as_str() => Ok(()),
            Some(child) => Err(anyhow!(
                "child_scope_policy=require_scope_circle_id (required={}) \
                 but child scope_circle_id={} (CXP-0007 §3.4.2)",
                scope_circle_id.as_str(),
                child.as_str()
            )),
            None => Err(anyhow!(
                "child_scope_policy=require_scope_circle_id (required={}) \
                 but child has no scope_circle_id (CXP-0007 §3.4.2)",
                scope_circle_id.as_str()
            )),
        },
    }
}

fn circle_a() -> Result<CircleId> {
    CircleId::new("cx:circle:0196419b-0000-7000-8000-000000000701".to_owned())
        .map_err(|e| anyhow!("circle a: {e}"))
}

fn circle_b() -> Result<CircleId> {
    CircleId::new("cx:circle:0196419b-0000-7000-8000-000000000702".to_owned())
        .map_err(|e| anyhow!("circle b: {e}"))
}

/// Serialize a `ChildScopePolicy` and confirm the canonical wire shape
/// (tag-based with `"kind"` discriminator).
fn wire_round_trip(policy: &ChildScopePolicy, expected_kind: &str) -> Result<()> {
    let json = serde_json::to_value(policy).map_err(|e| anyhow!("serialise: {e}"))?;
    let kind = json
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("policy JSON missing kind; got {json:?}"))?;
    if kind != expected_kind {
        return Err(anyhow!(
            "child_scope_policy kind drifted: expected `{expected_kind}`, got `{kind}`"
        ));
    }
    let _round: ChildScopePolicy =
        serde_json::from_value(json).map_err(|e| anyhow!("parse: {e}"))?;
    Ok(())
}

pub async fn child_scope_policy_run() -> Result<()> {
    // ── Wire shape pin for each variant.
    wire_round_trip(
        &ChildScopePolicy::AllowAny {
            metadata_encryption_floor: None,
        },
        "allow_any",
    )?;
    wire_round_trip(
        &ChildScopePolicy::RequireE2ee {
            metadata_encryption_floor: None,
        },
        "require_e2ee",
    )?;
    wire_round_trip(
        &ChildScopePolicy::RequireSameScope {
            metadata_encryption_floor: None,
        },
        "require_same_scope",
    )?;
    wire_round_trip(
        &ChildScopePolicy::RequireScopeCircleId {
            scope_circle_id: circle_a()?,
            metadata_encryption_floor: None,
        },
        "require_scope_circle_id",
    )?;

    // ── allow_any: accepts both unscoped and any Circle scope.
    let allow_any = ChildScopePolicy::AllowAny {
        metadata_encryption_floor: None,
    };
    enforce_child_scope_policy(&allow_any, None, None, EncryptionProfile::None)
        .map_err(|e| anyhow!("allow_any MUST accept unscoped child; got: {e}"))?;
    enforce_child_scope_policy(
        &allow_any,
        Some(&circle_a()?),
        None,
        EncryptionProfile::None,
    )
    .map_err(|e| anyhow!("allow_any MUST accept circle_a child; got: {e}"))?;

    // ── require_e2ee:
    //    accept: child has a Circle scope (regardless of Realm profile).
    //    accept: child is Realm-default AND Realm.encryption_profile=MlsRfc9420.
    //    reject: child is Realm-default AND Realm.encryption_profile=None.
    let require_e2ee = ChildScopePolicy::RequireE2ee {
        metadata_encryption_floor: None,
    };
    enforce_child_scope_policy(
        &require_e2ee,
        Some(&circle_a()?),
        None,
        EncryptionProfile::None,
    )
    .map_err(|e| anyhow!("require_e2ee MUST accept Circle-scoped child; got: {e}"))?;
    enforce_child_scope_policy(&require_e2ee, None, None, EncryptionProfile::MlsRfc9420).map_err(
        |e| anyhow!("require_e2ee MUST accept Realm-default child under MLS Realm; got: {e}"),
    )?;
    match enforce_child_scope_policy(&require_e2ee, None, None, EncryptionProfile::None) {
        Ok(()) => {
            return Err(anyhow!(
                "require_e2ee MUST reject Realm-default child under non-MLS Realm; got accept"
            ));
        }
        Err(e) => {
            if !e.to_string().contains("require_e2ee") {
                return Err(anyhow!("expected error to mention require_e2ee; got: {e}"));
            }
        }
    }

    // ── require_same_scope:
    //    accept: parent_space=circle_a, child=circle_a.
    //    accept: parent_space=None,     child=None.
    //    reject: parent_space=circle_a, child=circle_b.
    //    reject: parent_space=circle_a, child=None.
    let require_same = ChildScopePolicy::RequireSameScope {
        metadata_encryption_floor: None,
    };
    enforce_child_scope_policy(
        &require_same,
        Some(&circle_a()?),
        Some(&circle_a()?),
        EncryptionProfile::None,
    )
    .map_err(|e| anyhow!("require_same_scope MUST accept matching scopes; got: {e}"))?;
    enforce_child_scope_policy(&require_same, None, None, EncryptionProfile::None)
        .map_err(|e| anyhow!("require_same_scope MUST accept None == None; got: {e}"))?;
    if enforce_child_scope_policy(
        &require_same,
        Some(&circle_b()?),
        Some(&circle_a()?),
        EncryptionProfile::None,
    )
    .is_ok()
    {
        return Err(anyhow!(
            "require_same_scope MUST reject mismatched scopes (a vs b); got accept"
        ));
    }
    if enforce_child_scope_policy(
        &require_same,
        None,
        Some(&circle_a()?),
        EncryptionProfile::None,
    )
    .is_ok()
    {
        return Err(anyhow!(
            "require_same_scope MUST reject None child vs circle_a parent; got accept"
        ));
    }

    // ── require_scope_circle_id:
    //    accept: child=circle_a (the required circle).
    //    reject: child=circle_b.
    //    reject: child=None.
    let require_id = ChildScopePolicy::RequireScopeCircleId {
        scope_circle_id: circle_a()?,
        metadata_encryption_floor: None,
    };
    enforce_child_scope_policy(
        &require_id,
        Some(&circle_a()?),
        None,
        EncryptionProfile::None,
    )
    .map_err(|e| anyhow!("require_scope_circle_id MUST accept matching circle; got: {e}"))?;
    if enforce_child_scope_policy(
        &require_id,
        Some(&circle_b()?),
        None,
        EncryptionProfile::None,
    )
    .is_ok()
    {
        return Err(anyhow!(
            "require_scope_circle_id MUST reject wrong circle; got accept"
        ));
    }
    if enforce_child_scope_policy(&require_id, None, None, EncryptionProfile::None).is_ok() {
        return Err(anyhow!(
            "require_scope_circle_id MUST reject None child; got accept"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn child_scope_policy_enforces_each_mode() {
        child_scope_policy_run().await.unwrap();
    }
}
