//! Shared publication-evidence construction for cotest.
//!
//! `zh/authz/offline-publication.md` §2.1: neither the [`AuthorizationLease`]
//! nor the [`IngressReceipt`] is an Event field, and neither enters the Event
//! digest. They travel beside the Event in the submit wrappers, so every
//! cotest submit path builds them here rather than inventing a per-scenario
//! shape.
//!
//! This module also owns the single registry projection evaluator cotest uses.
//! v1 deleted the producer-supplied effect array precisely so that only the
//! reducer contract answers what an Event writes; routing every derivation
//! through one evaluator is what keeps a harness branch from re-growing a
//! private table of it.

use anyhow::{Context, Result};
use arkret_canonical::DigestSuite;
use arkret_wire::{
    AUTHORITY_SET_POLICY_SCHEMA, AuthoritySetAuthorizationRule, AuthoritySetIssuer,
    AuthoritySetIssuerRole, AuthoritySetPolicy, AuthoritySetPolicyKind, AuthoritySetPolicySource,
    AuthoritySetRef, AuthoritySetSourceKind, AuthorizationLease, AuthorizationLeaseId,
    ControlProposalDecisionPolicy, ControlProposalReceipt, ControlProposalReceiptKind, DeviceId,
    Did, DidUrl, Event, EventFederationSubmission, EventInitialSubmission, Hash, IngressReceipt,
    LeaseBasisRef, PayloadProof, PayloadSignature, ProjectedCellWrite, ProposalMemberReceipt,
    ReceiptId, RiskTier, SealId, proof_kind,
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

fn harness_authority_set(id: &str) -> AuthoritySetRef {
    AuthoritySetRef {
        authority_set_id: id.to_owned(),
        authority_set_digest: Hash::new(format!("sha256:{}", "e".repeat(64)))
            .expect("static harness authority-set digest is a valid Hash"),
    }
}

fn issuer_proof(
    verification_method: &str,
    payload_digest: Hash,
    created_at: chrono::DateTime<Utc>,
) -> PayloadProof {
    PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: verification_method.to_owned(),
        payload_digest,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "a..b".to_owned(),
    }
}

fn control_proposal_receipt_for(event: &Event) -> Result<Option<ControlProposalReceipt>> {
    if event.seal_basis.is_none() {
        return Ok(None);
    }
    let received_at = event.created_at;
    let policy = ControlProposalDecisionPolicy::default();
    let proposal_digest = Hash::new(event.event_digest().context("Event is canonicalizable")?)
        .context("Event digest is a valid Hash")?;
    let authority_set_ref =
        harness_authority_set("ak.authority_set.realm_admission.v1").authority_set_digest;
    let mut member_receipt = ProposalMemberReceipt {
        realm_id: event.realm_id.clone(),
        proposal_digest: proposal_digest.clone(),
        received_at,
        decision_due_at: received_at + policy.decision_window,
        absolute_due_at: received_at + policy.absolute_horizon,
        authority_set_ref: authority_set_ref.clone(),
        signature: PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:authority.example#key-1".to_owned(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .context("static placeholder member receipt digest is valid")?,
            created_at: received_at,
            jws: "a..b".to_owned(),
        },
    };
    member_receipt.signature.payload_digest = member_receipt
        .member_receipt_digest()
        .context("harness proposal member receipt is canonicalizable")?;
    let receipt = ControlProposalReceipt {
        kind: ControlProposalReceiptKind::ProposalReceipt,
        realm_id: event.realm_id.clone(),
        proposal_digest,
        received_at,
        decision_due_at: received_at + policy.decision_window,
        absolute_due_at: received_at + policy.absolute_horizon,
        defer_count: 0,
        authority_set_ref,
        member_receipts: vec![member_receipt],
    };
    receipt
        .validate_structural(policy)
        .context("harness proposal receipt is structurally valid")?;
    Ok(Some(receipt))
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
    let issued_at = event.created_at - Duration::minutes(5);
    let authorization_rule_id = "realm_admission";
    let authority_set_policy = AuthoritySetPolicy {
        schema: AUTHORITY_SET_POLICY_SCHEMA.to_owned(),
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
        basis_ref: LeaseBasisRef::Seal(
            SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))
                .context("static harness lease basis Seal id is typed")?,
        ),
        actor_id: event.actor_id.clone(),
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
        "did:webvh:z6mkfixture:authority.example#key-1",
        digest,
        issued_at,
    )];
    Ok(lease)
}

/// Package `event` as the initial publication the self submit rail accepts.
pub fn initial_submission(event: Event, action: &str) -> Result<EventInitialSubmission> {
    let authorization_lease = authorization_lease_for(&event, action, RiskTier::Low)?;
    let control_proposal_receipt = control_proposal_receipt_for(&event)?;
    Ok(EventInitialSubmission {
        event,
        authorization_lease,
        cba_proof_bundles: Vec::new(),
        control_proposal_receipt,
    })
}

/// The receipt a policy-accepted ingress issues for `event` under `lease`.
///
/// `received_at` sits inside the lease window, which is the revocation
/// boundary a receiving peer re-checks (`offline-publication.md` §2).
pub fn ingress_receipt_for(event: &Event, lease: &AuthorizationLease) -> Result<IngressReceipt> {
    let received_at = lease.issued_at + Duration::minutes(1);
    let mut receipt = IngressReceipt {
        receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-cccccccccccc")
            .context("static harness receipt id is typed")?,
        event_digest: Hash::new(event.event_digest().context("Event is canonicalizable")?)
            .context("Event digest is a valid Hash")?,
        authorization_lease_id: lease.authorization_lease_id.clone(),
        received_at,
        service_id: Did::new("did:webvh:z6mkfixture:ingress.example")
            .context("static harness ingress DID is typed")?,
        authority_set_ref: harness_authority_set("ak.authority_set.realm_ingress.v1"),
        proofs: Vec::new(),
    };
    let digest = receipt
        .receipt_digest()
        .context("harness receipt is canonicalizable")?;
    receipt.proofs = vec![issuer_proof(
        "did:webvh:z6mkfixture:ingress.example#key-1",
        digest,
        received_at,
    )];
    Ok(receipt)
}

/// Package `event` as previously receipted evidence for a peer push.
pub fn federation_submission(event: Event, action: &str) -> Result<EventFederationSubmission> {
    let authorization_lease = authorization_lease_for(&event, action, RiskTier::Low)?;
    let receipt = ingress_receipt_for(&event, &authorization_lease)?;
    let control_proposal_receipt = control_proposal_receipt_for(&event)?;
    Ok(EventFederationSubmission {
        event,
        authorization_lease,
        ingress_receipts: vec![receipt],
        control_proposal_receipt,
    })
}
