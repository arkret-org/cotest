//! COT-ORG-03 — `ak.realm.organization` organization-side proof sign/verify
//! cycle (model B/C) regression gate.
//!
//! This is the positive counterpart to `realm_organization_statement_negative`.
//! It drives the *shared* arkret-rust-sdk surfaces end to end so cotest never
//! re-implements the organization-side crypto:
//!
//!   * `arkret_signatures::realm_organization_statement_sign` signs the canonical transcript with
//!     the organization's control key (the same key a verifier resolves from the organization's own
//!     DID document).
//!   * the verification mirrors soland's `verify_realm_organization_proof_signature` exactly:
//!     base64url-decode `authorization.proof`, re-derive
//!     `realm_organization_statement_signing_bytes`, and `verify_strict`.
//!
//! Security anchor (model B/C): the signature MUST verify against the key named
//! by `authorization.verification_method`, whose DID MUST equal
//! `organization_id` — only a holder of the organization's own DID key can
//! produce an accepted statement. A different key (forgery) or any post-signing
//! field tamper MUST fail verification.

use arkret_canonical::base64url::base64url_decode;
use arkret_identifiers::{Did, DidCoreId, RealmId, project_did_to_core_id};
use arkret_models_collaboration::{
    RealmOrganizationAuthorization, RealmOrganizationControlScope, RealmOrganizationIssuerRole,
    RealmOrganizationPayload, RealmOrganizationRelationship, RealmOrganizationStatus,
    SignatureMaterial, realm_organization_statement_signing_bytes,
};
use arkret_signatures::realm_organization_statement_sign;
use arkret_wire::{DidUrl, NonEmptyString};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

const ORG_DID: &str = "ak:did_core:webvh:z6mkfixtureorg";
/// Verification method = the organization's own genesis key in its DID document.
const ORG_VERIFICATION_METHOD: &str = "did:webvh:z6mkfixtureorg:org.example#did-key-1";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
}

fn org_control_key() -> SigningKey {
    // Stands in for the organization control key minted by
    // `arkret_signatures::webvh::prepare_inception` (`did_key_seed`); the webvh
    // crate's own tests cover the minting + document-proof path.
    SigningKey::from_bytes(&[0x2au8; 32])
}

fn active_statement() -> RealmOrganizationPayload {
    RealmOrganizationPayload {
        statement_id: "org-stmt-cot-org-03".to_owned(),
        realm_id: RealmId::new("ak:realm:AaucqKYsYtNwus16IgXDBl88-LWNZZVtRpZ-CqgnPQoi").unwrap(),
        organization_id: DidCoreId::new(ORG_DID).unwrap(),
        relationship: RealmOrganizationRelationship::Owner,
        status: RealmOrganizationStatus::Active,
        control_scopes: vec![
            RealmOrganizationControlScope::OfficialBadge,
            RealmOrganizationControlScope::RealmAdmin,
        ],
        issued_at: now(),
        not_before: None,
        expires_at: None,
        supersedes_statement_id: None,
        revokes_statement_id: None,
        realm_frontier_digest: None,
        organization_policy_ref: None,
        authorization: RealmOrganizationAuthorization {
            issuer_id: DidCoreId::new(ORG_DID).unwrap(),
            issuer_role: RealmOrganizationIssuerRole::Organization,
            verification_method: DidUrl::new(ORG_VERIFICATION_METHOD).unwrap(),
            delegation_ref: None,
            executed_by: None,
            signed_at: now(),
            // Placeholder; replaced by the signer.
            proof: SignatureMaterial::NonEmptyString(NonEmptyString::new("placeholder").unwrap()),
        },
    }
}

/// Run the exact verification soland performs in
/// `verify_realm_organization_proof_signature`: decode the detached base64url
/// proof, re-derive the canonical signing bytes, and `verify_strict`.
fn verify_like_soland(
    payload: &RealmOrganizationPayload,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    let proof_b64 = match &payload.authorization.proof {
        SignatureMaterial::NonEmptyString(value) => value.clone(),
        SignatureMaterial::Variant1(_) => return Err("proof must be a detached signature".into()),
    };
    let sig_bytes = base64url_decode(proof_b64.trim()).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let signing_bytes =
        realm_organization_statement_signing_bytes(payload).map_err(|e| e.to_string())?;
    verifying_key
        .verify_strict(&signing_bytes, &signature)
        .map_err(|e| e.to_string())
}

/// The organization's own control key signs; the statement then verifies through
/// the exact soland verifier shape. The verification method's DID equals the
/// organization_id (the model B/C security anchor).
#[test]
fn organization_signed_statement_verifies_through_soland_shape() {
    let key = org_control_key();
    let statement = active_statement();

    // Anchor: the verification method is controlled by organization_id.
    let vm_did = Did::new(
        statement
            .authorization
            .verification_method
            .split('#')
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        project_did_to_core_id(&vm_did).unwrap(),
        statement.organization_id,
        "verification-method DID must equal organization_id (security anchor)"
    );

    let signed = realm_organization_statement_sign(&statement, &key).expect("sign ok");
    verify_like_soland(&signed, &key.verifying_key())
        .expect("organization-signed statement must verify through the soland verifier shape");
}

/// A statement signed by any key other than the organization's control key MUST
/// fail verification — an external party (even a Realm admin) cannot forge
/// organization consent.
#[test]
fn statement_signed_by_a_foreign_key_is_rejected() {
    let org_key = org_control_key();
    let foreign_key = SigningKey::from_bytes(&[0x99u8; 32]);

    let signed =
        realm_organization_statement_sign(&active_statement(), &foreign_key).expect("sign ok");
    // The verifier resolves the organization's own key, which did NOT sign this.
    let result = verify_like_soland(&signed, &org_key.verifying_key());
    assert!(
        result.is_err(),
        "a statement signed by a foreign key must not verify against the organization key"
    );
}

/// Any post-signing tamper of a covered field changes the canonical signing
/// bytes and MUST fail verification.
#[test]
fn post_signing_field_tamper_is_rejected() {
    let key = org_control_key();
    let mut signed = realm_organization_statement_sign(&active_statement(), &key).expect("sign ok");

    // Verifies before tamper.
    verify_like_soland(&signed, &key.verifying_key()).expect("must verify before tamper");

    // Tamper a covered field while keeping the original proof.
    signed.relationship = RealmOrganizationRelationship::Governance;
    let result = verify_like_soland(&signed, &key.verifying_key());
    assert!(
        result.is_err(),
        "tampering a covered field after signing must invalidate the proof"
    );
}
