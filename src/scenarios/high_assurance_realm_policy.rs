//! R3.4 — `security_class=high_assurance` Realm federation policy
//! contract scenario.
//!
//! Spec: a Realm declared with `security_class=high_assurance` MUST
//! keep `federation_policy ∈ {closed, restricted, quarantine}`. The
//! SDK exposes this as a struct invariant on `arkret_models_collaboration::objects::realm::Realm`'s
//! [`validate_kind_invariants`](arkret_models_collaboration::objects::realm::Realm::validate_kind_invariants)
//! and coland enforces it at the reducer with the canonical reason
//! code `high_assurance_federation_policy_invalid`.
//!
//! This scenario verifies the SDK side of the contract; the coland
//! integration test lives at `coland/tests/high_assurance_policy.rs`.

use anyhow::{Result, anyhow};
use arkret_identifiers::{DidCoreId, RealmId, TrustDomainId};
use arkret_models_collaboration::objects::realm::Realm;
use arkret_wire::{AccountId, ActorId, FederationPolicy, SecurityClass};

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
    let station_id = DidCoreId::new("ak:did_core:web:station.example")?;
    let mut realm = Realm::new(
        id,
        "Compliance Vault",
        ActorId::account(AccountId::new(principal, station_id.clone())),
        trust_domain,
        station_id,
    );
    realm.security_class = security_class;
    realm.federation_policy = federation_policy;
    Ok(realm)
}

/// R3.4 — a high_assurance Realm + federation_policy=open MUST be
/// rejected by the SDK invariant validator.
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
/// in `coland/tests/high_assurance_policy.
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
