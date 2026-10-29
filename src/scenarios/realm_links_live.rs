//! Realm links remain explicit local relationships across real HTTP and PostgreSQL.
use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::realm_governance::{
    RealmLinkKind, RealmLinkList, RealmLinkStatus,
};
use arkret_wire::{AccountId, EventAdmissionSubmission, EventKind};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestActorClient, expect_json};
use crate::scenarios::agent_runtime_live::coauth_session_evidence::{
    actual_agent_deployment, additional_controller,
};
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, grant_realm_actions, membership_payload,
};
use crate::scenarios::peer_semantic_union_live::{
    realm_business_footprint, submit_and_expect_commit,
};

const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000003411";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000003412";

fn policy(
    footprint: &Value,
) -> Result<arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload> {
    serde_json::from_value(footprint["realm_policy_bundle_current_states"][0]["value"].clone())
        .context("read exact accepted local policy bundle")
}

async fn schema_refusal(client: &TestActorClient, body: &Value) -> Result<()> {
    let response = client
        .post("/_arkret/self/events")
        .header("content-type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?)
        .send()
        .await?;
    let status = response.status();
    let problem: Value = response.json().await?;
    ensure!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "retired carrier returned {status}: {problem}"
    );
    ensure!(
        problem["type"]
            .as_str()
            .is_some_and(|s| s.ends_with("/schema_violation")),
        "retired carrier did not reach the schema boundary: {problem}"
    );
    Ok(())
}

pub async fn run() -> Result<()> {
    // Listing links verifies live Account Authority status in addition to the
    // Station's accepted Realm facts; a session-introspection-only mock cannot
    // supply that current source.
    let mut deployment = actual_agent_deployment("realm-links-live").await?;
    let station = &deployment.station;
    let database_url = station
        .owned_database_url()
        .context("Realm links runner requires PostgreSQL")?
        .to_owned();
    let alice = additional_controller(&deployment, "links-source-owner", ALICE_DEVICE).await?;
    let bob = additional_controller(&deployment, "links-target-owner", BOB_DEVICE).await?;
    let account = |client: &TestActorClient| -> Result<AccountId> {
        Ok(AccountId::new(
            client
                .principal
                .as_ref()
                .context("normally onboarded Realm link principal")?
                .core_id
                .clone(),
            station.service_id().clone(),
        ))
    };
    let alice_account = account(&alice)?;
    let bob_account = account(&bob)?;
    let source =
        create_realm_with_join_rule(&alice, "Source independent Realm", "public", &[station])
            .await?;
    let target =
        create_realm_with_join_rule(&bob, "Target independent Realm", "public", &[station]).await?;
    // A: the link is accepted and served through the registered relation operation.
    let link = bob
        .author_event(
            &target,
            EventKind::RealmLink.as_str(),
            json!({"target_realm_id":source,"link_kind":"governed_by","status":"active"}),
        )
        .await?;
    submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &link).await?;
    let listed: RealmLinkList = serde_json::from_value(
        expect_json(
            bob.get(&format!("/_arkret/self/realms/{target}/links")),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        listed.realm_id.as_str() == target
            && listed
                .links
                .iter()
                .any(|link| link.realm_id.as_str() == target
                    && link.target_realm_id.as_str() == source
                    && link.link_kind == RealmLinkKind::GovernedBy
                    && link.status == RealmLinkStatus::Active),
        "accepted relation was not listed"
    );
    let mut target_before = realm_business_footprint(&database_url, &target).await?;
    let carol_device = "ak:device:01904100-0000-7000-8000-000000003413";
    let carol =
        additional_controller(&deployment, "links-unrelated-applicant", carol_device).await?;
    let carol_account = account(&carol)?;
    // B/D: a real source policy write cannot alter target policy, grants,
    // notification projections, quotas, Events or Commits.
    let source_before = realm_business_footprint(&database_url, &source).await?;
    let current = policy(&source_before)?;
    let mut next = current.restate(current.policy_revision + 1);
    next.federation_policy = Some(serde_json::from_value(json!("closed"))?);
    next.join_policy = Some(serde_json::from_value(json!({"gates":[{
        "gate_id":"source-local-deny","kind":"principal_admission","denied_account_ids":[carol_account]
    }],"combinator":"all"}))?);
    let change = alice
        .author_event(
            &source,
            EventKind::RealmPolicyBundle.as_str(),
            serde_json::to_value(next)?,
        )
        .await?;
    submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &change).await?;
    ensure!(
        realm_business_footprint(&database_url, &target).await? == target_before,
        "source policy cascaded across a link"
    );
    let source_cut = realm_business_footprint(&database_url, &source).await?;
    let denied_join = carol.author_event(&source, EventKind::MemberState.as_str(), membership_payload(
        &source, carol_account.clone(), arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join, "same applicant source admission")?).await?;
    let response = carol
        .post("/_arkret/self/events")
        .header("content-type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &EventAdmissionSubmission::new(denied_join),
        )?)
        .send()
        .await?;
    let status = response.status();
    let problem: Value = response.json().await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            && problem["type"] == "https://arkret.org/problems/capability_denied"
            && problem["reason_code"] == "gate_check_failed",
        "source local predicate was not enforced: {status} {problem}"
    );
    ensure!(
        realm_business_footprint(&database_url, &source).await? == source_cut,
        "source denied admission left durable effects"
    );
    let allowed_join = carol.author_event(&target, EventKind::MemberState.as_str(), membership_payload(
        &target, carol_account.clone(), arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join, "same applicant target admission")?).await?;
    submit_and_expect_commit(&carol, &carol_account, carol_device, &allowed_join).await?;
    target_before = realm_business_footprint(&database_url, &target).await?;
    // C: source ownership does not authorize an otherwise well-formed target update.
    let target_policy = policy(&target_before)?;
    let unauthorized = alice
        .author_event(
            &target,
            EventKind::RealmPolicyBundle.as_str(),
            serde_json::to_value(target_policy.restate(target_policy.policy_revision + 1))?,
        )
        .await?;
    let response = alice
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
        "source controller authorized at target: {status} {problem}"
    );
    ensure!(
        realm_business_footprint(&database_url, &target).await? == target_before,
        "denied source controller wrote target business state"
    );
    // An explicit target-local join and grant authorizes the target update;
    // the source root grant never substitutes for either accepted target fact.
    let alice_join = alice.author_event(&target, EventKind::MemberState.as_str(), membership_payload(
        &target, alice_account.clone(), arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join, "target local member")?).await?;
    submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &alice_join).await?;
    grant_realm_actions(&bob, station, &target, &alice_account, &["ak.realm.admin"]).await?;
    let local_update = alice
        .author_event(
            &target,
            EventKind::RealmPolicyBundle.as_str(),
            serde_json::to_value(target_policy.restate(target_policy.policy_revision + 1))?,
        )
        .await?;
    submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &local_update).await?;
    target_before = realm_business_footprint(&database_url, &target).await?;
    // Old event kinds and old link payloads reach the HTTP schema boundary;
    // no fake Event kind is accepted by the production authoring API.
    let valid = serde_json::to_value(EventAdmissionSubmission::new(link.clone()))?;
    for old_kind in ["ak.realm.inheritance_policy", "ak.capability.derived"] {
        let mut body = valid.clone();
        body["event"]["kind"] = json!(old_kind);
        schema_refusal(&bob, &body).await?;
        ensure!(
            realm_business_footprint(&database_url, &target).await? == target_before,
            "retired kind mutated target"
        );
    }
    for field in [
        "notification_defaults",
        "inherits",
        "policy_rules",
        "capability_bundles",
    ] {
        let mut body = valid.clone();
        body["event"]["payload"][field] = json!({});
        schema_refusal(&bob, &body).await?;
        ensure!(
            realm_business_footprint(&database_url, &target).await? == target_before,
            "retired {field} mutated target"
        );
    }
    let old_alias = bob
        .get(&format!("/_arkret/self/realms/{target}/effective-policy"))
        .send()
        .await?;
    ensure!(
        old_alias.status() == StatusCode::NOT_FOUND,
        "retired effective-policy endpoint still exposes an alias"
    );
    // Local link lifecycle never derives target policy/grant/notification state.
    for state in ["rejected", "tombstoned"] {
        let before = realm_business_footprint(&database_url, &target).await?;
        let event = bob
            .author_event(
                &target,
                EventKind::RealmLink.as_str(),
                json!({"target_realm_id":source,"link_kind":"governed_by","status":state}),
            )
            .await?;
        submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &event).await?;
        let after = realm_business_footprint(&database_url, &target).await?;
        for (table, rows) in before.as_object().context("footprint object")? {
            if !matches!(
                table.as_str(),
                "canonical_events" | "realm_commits" | "realm_link_current_states"
            ) {
                ensure!(
                    after[table] == *rows,
                    "link {state} changed unrelated local {table}"
                );
            }
        }
    }
    // E: service restart consumes only accepted current-v1 local rows. Historical
    // legacy-row quarantine requires an actual historical schema (never invented here).
    let before_restart = realm_business_footprint(&database_url, &target).await?;
    deployment.station.restart_external_process().await?;
    ensure!(
        realm_business_footprint(&database_url, &target).await? == before_restart,
        "restart reinterpreted local target state"
    );
    let listed: RealmLinkList = serde_json::from_value(
        expect_json(
            bob.get(&format!("/_arkret/self/realms/{target}/links")),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        listed.realm_id.as_str() == target
            && listed
                .links
                .iter()
                .any(|link| link.realm_id.as_str() == target
                    && link.target_realm_id.as_str() == source
                    && link.link_kind == RealmLinkKind::GovernedBy
                    && link.status == RealmLinkStatus::Tombstoned),
        "restart lost explicit link lifecycle"
    );
    Ok(())
}
