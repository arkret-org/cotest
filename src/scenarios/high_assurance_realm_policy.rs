//! R3.4 — `security_class=high_assurance` Realm federation policy
//! contract scenario.
//!
//! Spec: a Realm declared with `security_class=high_assurance` MUST
//! keep `federation_policy ∈ {closed, restricted, quarantine}`. The
//! SDK exposes this as a struct invariant on `arkret_models_collaboration::objects::realm::Realm`'s
//! [`validate_kind_invariants`](arkret_models_collaboration::objects::realm::Realm::validate_kind_invariants)
//! and soland enforces it at the reducer with the canonical reason
//! code `high_assurance_federation_policy_invalid`.
//!
//! This scenario verifies the SDK side of the contract; the soland
//! integration test lives at `soland/tests/high_assurance_policy.rs`.

use anyhow::{Result, anyhow};
use arkret_identifiers::{DidCoreId, RealmId, TrustDomainId};
use arkret_models_collaboration::governance::circle::EncryptionFloor;
use arkret_models_collaboration::objects::realm::Realm;
use arkret_wire::{
    AccountId, ActorId, Discoverability, EncryptionProfile, FederationPolicy, HistoryAccess,
    JoinRule, SecurityClass,
};

const REALM_ID: &str = "ak:realm:AWdkiR5jlnGgdx6sVlaEmGK5CATkDmi21Mn8gxnUmrZe";

fn realm_id() -> Result<RealmId> {
    RealmId::new(REALM_ID.to_owned()).map_err(|err| anyhow!("invalid realm id: {err}"))
}

fn principal_id() -> Result<DidCoreId> {
    DidCoreId::new("ak:did_core:web:alice.example")
        .map_err(|err| anyhow!("invalid principal id: {err}"))
}

fn build_realm(
    security_class: Option<SecurityClass>,
    federation_policy: Option<FederationPolicy>,
) -> Result<Realm> {
    let id = realm_id()?;
    let principal = principal_id()?;
    // `trust_domain` is a required Realm binding
    // (arkret_models_collaboration::objects::realm::Realm). Cotest uses a fixed canonical trust
    // domain id here so the high-assurance policy scenario stays representative.
    let trust_domain = TrustDomainId::new("ak:trust_domain:example.net".to_owned())
        .map_err(|err| anyhow!("invalid trust_domain literal: {err}"))?;
    Ok(Realm {
        schema: "ak.schema.realm.v1".to_owned(),
        // Materialised-object fixture, so it carries an id; a create payload
        // would leave this `None` (spec realm-and-space.md section 2.5.0).
        id: Some(id),
        title: "Compliance Vault".to_owned(),
        trust_domain,
        summary: None,
        security_class,
        created_by: ActorId::account(AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:station.example")?,
        )),
        owning_organization_ids: Vec::new(),
        schema_refs: vec!["ak.profile.realm.v1".to_owned()],
        policy_id: None,
        preview_policy_id: None,
        default_strand_id: None,
        default_discoverability: Discoverability::InviteOnly,
        default_join_rule: JoinRule::Invite,
        history_access: HistoryAccess::SinceJoin,
        reducer_profile: arkret_wire::CORE_REDUCER_PROFILE.to_owned(),
        encryption_profile: EncryptionProfile::None,
        content_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
        metadata_encryption_floor: Some(EncryptionFloor::AllowPlaintext),
        agent_participation: None,
        content_scheme: None,
        durability_policy: None,
        federation_policy,
        digest_algorithm: arkret_canonical::DigestSuite::Sha256,
        retention_policy_id: None,
        avatar_blob_ref: None,
        created_at: chrono::Utc::now(),
        updated_by: None,
        updated_at: None,
        availability_policy: None,
        audit_policy: None,
        notary: crate::fixture_notary_configuration(principal.clone()),
        fields: Default::default(),
        // `max_anchor_staleness_ms` was retired by the dual-plane split
        // without a direct replacement.
        proposal_intake_sla_ms: None,
        proposal_decision_window_ms: None,
        proposal_absolute_deadline_ms: None,
        max_proposal_defers: None,
        seal_compaction_max_interval_ms: None,
        max_authority_lifetime_ms: 86_400_000,
        bottom_escalation_after_ms: None,
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
