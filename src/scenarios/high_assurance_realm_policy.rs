//! R3.4 — `security_class=high_assurance` Realm federation policy
//! contract scenario.
//!
//! Spec: a Realm declared with `security_class=high_assurance` MUST
//! keep `federation_policy ∈ {closed, restricted, quarantine}`. The
//! SDK exposes this as a struct invariant on `cokret_core::Realm`'s
//! [`validate_kind_invariants`](cokret_core::Realm::validate_kind_invariants)
//! and soland enforces it at the reducer with the canonical reason
//! code `high_assurance_federation_policy_invalid`.
//!
//! This scenario verifies the SDK side of the contract; the soland
//! integration test lives at `soland/tests/high_assurance_policy.rs`.

use anyhow::{Result, anyhow};
use cokret_core::{
    Did, Discoverability, EncryptionFloor, EncryptionProfile, FederationPolicy, HistoryVisibility,
    JoinRule, Realm, RealmId, SecurityClass, TypedTrustDomainId,
};

const REALM_ID: &str = "ck:realm:01904100-0000-7000-8000-000000000aa1";

fn realm_id() -> Result<RealmId> {
    RealmId::new(REALM_ID.to_owned()).map_err(|err| anyhow!("invalid realm id: {err}"))
}

fn principal_id() -> Result<Did> {
    Did::new("did:web:alice.example".to_owned())
        .map_err(|err| anyhow!("invalid principal id: {err}"))
}

fn build_realm(
    security_class: Option<SecurityClass>,
    federation_policy: Option<FederationPolicy>,
) -> Result<Realm> {
    let id = realm_id()?;
    let principal = principal_id()?;
    // TODO(sdk-trust-domain-dep): A1 added required `trust_domain` to Realm.
    // Cotest uses a fixed canonical trust domain id here so the high-assurance
    // policy scenario stays representative.
    let trust_domain = TypedTrustDomainId::new("ck:trust_domain:example.net".to_owned())
        .map_err(|err| anyhow!("invalid trust_domain literal: {err}"))?;
    Ok(Realm {
        schema: "ck.profile.realm.v1".to_owned(),
        id,
        title: "Compliance Vault".to_owned(),
        trust_domain,
        summary: None,
        security_class,
        created_by: principal,
        owning_organizations: Vec::new(),
        schema_refs: vec!["ck.profile.realm.v1".to_owned()],
        policy_id: None,
        default_discoverability: Discoverability::InviteOnly,
        default_join_rule: JoinRule::Invite,
        history_visibility: HistoryVisibility::Joined,
        encryption_profile: EncryptionProfile::None,
        content_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
        metadata_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
        federation_policy,
        retention_policy_id: None,
        avatar_blob_ref: None,
        created_at: chrono::Utc::now(),
        updated_at: None,
        labels: Vec::new(),
        metadata: std::collections::BTreeMap::new(),
        relation_profiles: Vec::new(),
        notary_profile: None,
        notary: None,
        // `max_anchor_staleness_ms` 已随双平面拆分退役且无直接后继字段
        // (renames.json: replacement=null);revocation 滞后由
        // `revocation_freshness_window_ms` 治理。
        revocation_freshness_window_ms: None,
        cell_lattices: Vec::new(),
        co_write_policy: None,
        extra: std::collections::BTreeMap::new(),
    })
}

/// R3.4 — a high_assurance Realm + federation_policy=open MUST be
/// rejected by the SDK invariant validator. The reason code is plain
/// text per SDK style; soland's wire counterpart returns the canonical
/// `high_assurance_federation_policy_invalid`.
pub fn run_high_assurance_rejects_open_federation() -> Result<()> {
    let realm = build_realm(
        Some(SecurityClass::HighAssurance),
        Some(FederationPolicy::Open),
    )?;
    match realm.validate_kind_invariants() {
        Err(err) => {
            // The error message is informational; the contract is that
            // the validator MUST reject this combination.
            let s = err.to_string();
            if !s.contains("high_assurance") || !s.contains("federation_policy") {
                return Err(anyhow!(
                    "expected rejection mentioning high_assurance + federation_policy, got: {s}"
                ));
            }
            Ok(())
        }
        Ok(()) => Err(anyhow!(
            "SDK accepted security_class=high_assurance + federation_policy=open — contract violated"
        )),
    }
}

/// R3.4 — the three other `federation_policy` values are accepted on a
/// high_assurance Realm. These mirror the reducer-side positive cases
/// in `soland/tests/high_assurance_policy.
/// rs::high_assurance_accepts_closed_restricted_and_quarantine`.
pub fn run_high_assurance_accepts_closed_restricted_quarantine() -> Result<()> {
    for fp in [
        FederationPolicy::Closed,
        FederationPolicy::Restricted,
        FederationPolicy::Quarantine,
    ] {
        let realm = build_realm(Some(SecurityClass::HighAssurance), Some(fp.clone()))?;
        realm.validate_kind_invariants().map_err(|err| {
            anyhow!("high_assurance + federation_policy={fp:?} should validate, got: {err}")
        })?;
    }
    Ok(())
}

/// R3.4 — a standard Realm (no security_class set, or
/// `SecurityClass::Standard`) freely accepts `federation_policy=open`.
pub fn run_standard_realm_accepts_open_federation() -> Result<()> {
    for sc in [None, Some(SecurityClass::Standard)] {
        let realm = build_realm(sc, Some(FederationPolicy::Open))?;
        realm
            .validate_kind_invariants()
            .map_err(|err| anyhow!("standard realm + open federation must validate, got: {err}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_assurance_rejects_open_federation() {
        run_high_assurance_rejects_open_federation()
            .expect("high_assurance + open MUST be rejected by SDK invariant");
    }

    #[test]
    fn high_assurance_accepts_closed_restricted_quarantine() {
        run_high_assurance_accepts_closed_restricted_quarantine()
            .expect("high_assurance + {closed,restricted,quarantine} MUST validate");
    }

    #[test]
    fn standard_realm_accepts_open_federation() {
        run_standard_realm_accepts_open_federation()
            .expect("standard realm + open federation MUST validate");
    }
}
