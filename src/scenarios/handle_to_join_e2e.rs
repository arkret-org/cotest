//! Exact-account Handle → Join conformance.
//!
//! A handle resolves to an `AccountId`, and Realm membership carries that same
//! account as an `ActorId`. The Station coordinate is part of identity and is
//! also the routing source of truth; no delivery-binding policy or handover
//! object participates in either step.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::membership_invite::MembershipPayload;
use arkret_models_identity::{Handle, HandleBindingState, HandleClaim, HandleClaimKind};
use arkret_wire::{AccountId, ActorId, Audience, DidCoreId, DidUrl, Hash, PayloadProof, RealmId};
use chrono::{DateTime, Duration, Utc};

const PRINCIPAL_ID: &str = "ak:did_core:web:alice.acme.example";
const STATION_A: &str = "ak:did_core:web:station-a.acme.example";
const STATION_B: &str = "ak:did_core:web:station-b.acme.example";
const ISSUER_ID: &str = "ak:did_core:web:directory.acme.example";
const TARGET_REALM_ID: &str = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
const HANDLE: &str = "alice:acme.example";

pub async fn handle_to_join_e2e_run() -> Result<()> {
    let now = timestamp("2026-08-31T00:00:00.000Z")?;
    let account_a = account(STATION_A)?;
    let account_b = account(STATION_B)?;
    let claim = verified_claim(account_a.clone(), now)?;

    claim
        .validate_remote_resolution(Some(TARGET_REALM_ID), Some(&account_a), now)
        .context("exact Station account must resolve")?;
    ensure!(
        claim
            .validate_remote_resolution(Some(TARGET_REALM_ID), Some(&account_b), now)
            .is_err(),
        "same principal at another Station must not resolve as the same account"
    );

    let payload = MembershipPayload::join(
        RealmId::new(TARGET_REALM_ID)?,
        ActorId::account(account_a.clone()),
        "resolved exact account",
    )
    .to_value()?;
    ensure!(
        payload["member_id"] == serde_json::json!({"kind": "account", "account_id": account_a}),
        "membership must carry the complete account actor"
    );
    ensure!(
        payload.get("delivery_status").is_none() && payload.get("delivery_binding").is_none(),
        "membership routing must not be duplicated in delivery-binding fields"
    );

    let actor: ActorId = serde_json::from_value(payload["member_id"].clone())?;
    ensure!(actor.route_service_id().as_str() == STATION_A);
    ensure!(actor.signing_principal_id().as_str() == PRINCIPAL_ID);

    // Clean-break evidence: a retired member-routing field is rejected by the
    // closed membership payload model rather than silently ignored.
    let mut legacy = payload;
    legacy["member_delivery_binding"] = serde_json::json!({"recipient_id": STATION_B});
    ensure!(serde_json::from_value::<MembershipPayload>(legacy).is_err());
    Ok(())
}

fn account(station_id: &str) -> Result<AccountId> {
    Ok(AccountId::new(
        DidCoreId::new(PRINCIPAL_ID)?,
        DidCoreId::new(station_id)?,
    ))
}

fn verified_claim(subject_account_id: AccountId, now: DateTime<Utc>) -> Result<HandleClaim> {
    Ok(HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        handle: Handle::parse(HANDLE)?,
        handle_aliases: vec!["acct:alice@acme.example".to_owned()],
        subject_account_id,
        issuer_id: DidCoreId::new(ISSUER_ID)?,
        vouching_id: None,
        binding_state: HandleBindingState::Verified,
        claim_kind: Some(HandleClaimKind::HandleBinding),
        visibility: None,
        audience: Some(TARGET_REALM_ID.to_owned()),
        challenge: None,
        claim_scope: BTreeMap::new(),
        claims: Vec::new(),
        created_at: now - Duration::minutes(1),
        expires_at: Some(now + Duration::hours(1)),
        verified_at: Some(now - Duration::minutes(1)),
        source_refs: vec!["ak:event:AccVsThCMukcEF5tfolTyrO1SoKc5W7qAlVm_mDWvfuw".to_owned()],
        proofs: vec![PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:web:directory.acme.example#key-1")
                .map_err(anyhow::Error::msg)?,
            payload_digest: Hash::new(format!("sha256:{}", "1".repeat(64)))?,
            created_at: now - Duration::minutes(1),
            domain: None,
            audience: Some(Audience::Single(TARGET_REALM_ID.to_owned())),
            proof_purpose: None,
            jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
        }],
    })
}

fn timestamp(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}
