//! Accepted Account actors, real DID-key organization consent and durable projection.
//! The organization is an external did:key controller; this does not invent a
//! native Principal root-key purpose or pretend a human Account is an organization.
use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::realm_governance::{
    RealmOrganizationLifecyclePhase, RealmOrganizationRelationshipList,
};
use arkret_models_collaboration::{
    RealmOrganizationPayload, realm_organization_statement_signing_bytes,
};
use arkret_wire::{ActorId, EventAdmissionSubmission, EventKind};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, membership_payload, standard_client, station_env,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::peer_semantic_union_live::{
    realm_business_footprint, submit_and_expect_commit,
};
const OWNER: &str = "ak:device:01904100-0000-7000-8000-000000003431";
const MEMBER: &str = "ak:device:01904100-0000-7000-8000-000000003432";

pub async fn run() -> Result<()> {
    let db = database("organization-account-consumer-live")?
        .context("organization consumer requires PostgreSQL")?;
    let authority = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut group = TestServerGroup::try_multi_external_with_node_envs(
        "organization-account-consumer-live",
        &[station_env(&db.connect_url, &authority)],
    )
    .await?
    .context("organization consumer requires production Coland")?;
    let (owner, account) = standard_client(
        group.server(0),
        &authority,
        "organization-realm-controller",
        OWNER,
    )
    .await?;
    let (member, member_account) = standard_client(
        group.server(0),
        &authority,
        "organization-unprivileged-member",
        MEMBER,
    )
    .await?;
    let realm = create_realm_with_join_rule(
        &owner,
        "Independent organization consent",
        "public",
        &[group.server(0)],
    )
    .await?;
    let join=member.author_event(&realm,EventKind::MemberState.as_str(),membership_payload(&realm,member_account.clone(),
        arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,"organization read only member")?).await?;
    submit_and_expect_commit(&member, &member_account, MEMBER, &join).await?;
    // Genuine, independently controlled external organization DID; SDK derives
    // its complete method and the production receiver resolves its DID document.
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x43; 32]);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes());
    let did = arkret_wire::Did::new(format!("did:key:{multibase}"))?;
    let organization = arkret_wire::project_did_to_core_id(&did)?;
    let time = arkret_canonical::format_timestamp_canonical(chrono::Utc::now());
    let statement: RealmOrganizationPayload = serde_json::from_value(json!({
        "statement_id":"organization-account-positive","realm_id":realm,"organization_id":organization,
        "relationship":"owner","status":"active","control_scopes":["official_badge"],"issued_at":time,
        "authorization":{"issuer_id":organization,"issuer_role":"organization",
        "verification_method":format!("{did}#{multibase}"),"signed_at":time,"proof":"placeholder"}}))?;
    let signed = arkret_signatures::realm_organization_statement_sign(&statement, &key)?;
    ensure!(
        !realm_organization_statement_signing_bytes(&signed)?.is_empty(),
        "SDK transcript absent"
    );
    // Organization consent cannot substitute for target Realm write capability.
    let unauthorized = member
        .author_event(
            &realm,
            EventKind::RealmOrganization.as_str(),
            serde_json::to_value(&signed)?,
        )
        .await?;
    ensure!(
        unauthorized.actor_id == ActorId::account(member_account.clone()),
        "organization event did not retain full Account actor"
    );
    let before = realm_business_footprint(&db.connect_url, &realm).await?;
    let response = member
        .post("/_arkret/self/events")
        .header("content-type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &EventAdmissionSubmission::new(unauthorized),
        )?)
        .send()
        .await?;
    let status = response.status();
    let problem: Value = response.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            && problem["type"] == "https://arkret.org/problems/capability_denied",
        "organization consent replaced Realm capability: {status} {problem}"
    );
    ensure!(
        realm_business_footprint(&db.connect_url, &realm).await? == before,
        "unprivileged Account wrote organization rows"
    );
    let event = owner
        .author_event(
            &realm,
            EventKind::RealmOrganization.as_str(),
            serde_json::to_value(&signed)?,
        )
        .await?;
    ensure!(
        event.actor_id == ActorId::account(account.clone()),
        "organization write actor was collapsed to principal"
    );
    let accepted = submit_and_expect_commit(&owner, &account, OWNER, &event).await?;
    let rows: RealmOrganizationRelationshipList = serde_json::from_value(
        expect_json(
            member.get(&format!("/_arkret/self/realms/{realm}/organizations")),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        rows.realm_id == event.realm_id
            && rows.relationships.len() == 1
            && rows.relationships[0].organization_id == organization
            && rows.relationships[0].lifecycle_phase
                == RealmOrganizationLifecyclePhase::VerifiedActive,
        "verified organization did not reach typed reader"
    );
    let snapshot = realm_business_footprint(&db.connect_url, &realm).await?;
    let projection = &snapshot["realm_organization_current_results"][0];
    ensure!(
        projection["current_commit_id"] == accepted.commit_id.as_str()
            && projection["value"] == serde_json::to_value(&signed)?,
        "organization durable projection was not anchored to original signed Event and Commit"
    );
    // Cold service read consumes the same durable accepted statement and key.
    group.server_mut(0).restart_external_process().await?;
    let rows: RealmOrganizationRelationshipList = serde_json::from_value(
        expect_json(
            member.get(&format!("/_arkret/self/realms/{realm}/organizations")),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        rows.relationships.len() == 1
            && rows.relationships[0].lifecycle_phase
                == RealmOrganizationLifecyclePhase::VerifiedActive,
        "cold organization projection lost the accepted statement"
    );
    ensure!(
        realm_business_footprint(&db.connect_url, &realm).await? == snapshot,
        "service reopen reinterpreted organization business state"
    );
    Ok(())
}
