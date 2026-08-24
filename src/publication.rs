//! Shared publication-evidence construction for cotest.
//!
//! `zh/authz/offline-publication.md` §2.1: the [`AuthorizationLease`] is not
//! an Event field and never enters the Event digest. It travels beside the
//! Event in the submit wrappers, so every cotest submit path builds it here
//! rather than inventing a per-scenario shape.
//!
//! This module also owns the single registry projection evaluator cotest uses.
//! v1 deleted the producer-supplied effect array precisely so that only the
//! reducer contract answers what an Event writes; routing every derivation
//! through one evaluator is what keeps a harness branch from re-growing a
//! private table of it.

use anyhow::{Context, Result};
use arkret_canonical::DigestSuite;
use arkret_wire::{
    AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole, AuthoritySetPolicy,
    AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind,
    AuthorizationLease, AuthorizationLeaseId, DeviceId, DidUrl, Event, EventInitialSubmission,
    Hash, LeaseBasisRef, PayloadProof, ProjectedCellWrite, RiskTier, SchemaId, SealId, proof_kind,
};
use chrono::{Duration, Utc};
/// The one registry projection evaluator cotest uses.
///
/// Injected wherever the SDK asks for a `CellWriteProjector`, so a bootstrap or
/// reducer branch cannot substitute a private notion of what an Event writes.
pub fn project_cells(event: &Event) -> std::result::Result<Vec<ProjectedCellWrite>, String> {
    arkret_schema::project_registered_cell_writes(event, DigestSuite::Sha256)
        .map_err(|error| error.to_string())
}

fn issuer_proof(
    verification_method: DidUrl,
    payload_digest: Hash,
    created_at: chrono::DateTime<Utc>,
) -> PayloadProof {
    PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        payload_digest,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "a..b".to_owned(),
    }
}

/// Mint the lease that authorizes `event`'s first publication.
///
/// Bound to the Event's own `actor_id` and signed `scope_ref`, which is what
/// [`EventInitialSubmission::validate_structural`] checks. `action` is the
/// capability action the lease narrows — deliberately *not* the Event kind:
/// capability actions and Event kinds are separate namespaces, so the wire
/// layer never compares them.
pub fn authorization_lease_for(
    event: &Event,
    action: &str,
    risk_tier: RiskTier,
) -> Result<AuthorizationLease> {
    authorization_lease_for_basis(
        event,
        action,
        risk_tier,
        LeaseBasisRef::Seal(
            SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))
                .context("static harness lease basis Seal id is typed")?,
        ),
    )
}

fn authorization_lease_for_basis(
    event: &Event,
    action: &str,
    risk_tier: RiskTier,
    basis_ref: LeaseBasisRef,
) -> Result<AuthorizationLease> {
    let issued_at = event.created_at - Duration::minutes(5);
    let actor_id = event.actor_id.clone();
    let authorization_rule_id = "realm_admission";
    let authority_set_policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
        policy_kind: AuthoritySetPolicyKind::RealmAdmission,
        scope_ref: event.scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::RealmControl,
            source_ref: format!("{}#harness-authority", event.realm_id),
            source_digest: Hash::new(format!("sha256:{}", "e".repeat(64)))
                .context("static harness source digest is a valid Hash")?,
            generation_ref: "1".to_owned(),
        },
        authorization_rules: vec![AuthoritySetAuthorizationRule {
            rule_id: authorization_rule_id.to_owned(),
            issuer_role: AuthoritySetIssuerRole::RealmAdmission,
            allowed_actions: vec![action.to_owned()],
            issuers: vec![AuthoritySetIssuer {
                verification_method: DidUrl::new("did:webvh:z6mkfixture:authority.example#key-1")
                    .map_err(anyhow::Error::msg)?,
            }],
            threshold: 1,
        }],
    };
    let authority_set_ref = AuthoritySetRef {
        authority_set_id: authority_set_policy.authority_set_id.clone(),
        authority_set_digest: authority_set_policy
            .digest()
            .context("harness authority-set policy is canonicalizable")?,
    };
    let mut lease = AuthorizationLease {
        authorization_lease_id: AuthorizationLeaseId::new(
            "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
        )
        .context("static harness lease id is typed")?,
        basis_ref,
        actor_id,
        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb")
            .context("static harness lease device id is typed")?,
        scope_ref: event.scope_ref.clone(),
        action: action.to_owned(),
        authorization_rule_id: authorization_rule_id.to_owned(),
        risk_tier,
        issued_at,
        expires_at: issued_at + risk_tier.max_lease_ttl(),
        authority_set_ref,
        authority_set_policy,
        proofs: Vec::new(),
    };
    let digest = lease
        .lease_digest()
        .context("harness lease is canonicalizable")?;
    lease.proofs = vec![issuer_proof(
        DidUrl::new("did:webvh:z6mkfixture:authority.example#key-1").map_err(anyhow::Error::msg)?,
        digest,
        issued_at,
    )];
    Ok(lease)
}

/// Package `event` as the initial publication the self submit rail accepts.
pub fn initial_submission(event: Event, _action: &str) -> Result<EventInitialSubmission> {
    Ok(EventInitialSubmission::online(event))
}
