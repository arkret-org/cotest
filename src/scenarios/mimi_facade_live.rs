//! Real facade Service identity, provider HTTP signatures and rejection effects.
use anyhow::{Context as _, Result, ensure};
use arkret_wire::EventKind;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::conformance::CaseExecutionResult;
use crate::harness::{
    ArkretServer, CanonicalJsonBody as _, TestServerGroup, expect_json, test_service_signing_key,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, station_env, submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::mls_lifecycle_live::Member;
const GROUP: &str = "mimi-facade-live";
const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002881";

async fn signed_post(
    server: &ArkretServer,
    path: &str,
    room: &str,
    provider: &str,
    body: &Value,
) -> Result<(StatusCode, Value)> {
    use arkret_signatures::http_signature::{
        Component, ContentDigest, ContentDigestAlgorithm, SignedRequestParts, canonical_message,
        format_signature_input_component_list, parse_signature_input, sign_message,
    };
    let body = arkret_canonical::canonical_json_bytes(body)?;
    let target = server.url(path);
    let url = reqwest::Url::parse(&target)?;
    let authority = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().context("host")?),
        None => url.host_str().context("host")?.to_owned(),
    };
    let digest = ContentDigest::compute(&body, ContentDigestAlgorithm::Sha256).wire_value;
    let operation = arkret_wire::ServiceOperationId::from_http_request("POST", path)
        .context("MIMI operation")?;
    let headers = vec![
        ("arkret-operation".into(), operation.as_str().to_owned()),
        ("content-type".into(), "application/json".into()),
        ("content-digest".into(), digest.clone()),
        ("provider-id".into(), provider.to_owned()),
        ("source-service-id".into(), server.service_id().to_string()),
        (
            "destination-service-id".into(),
            server.service_id().to_string(),
        ),
        ("mimi-room-uri".into(), room.to_owned()),
    ];
    let covered = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header("arkret-operation".into()),
        Component::Header("content-digest".into()),
        Component::Header("provider-id".into()),
        Component::Header("source-service-id".into()),
        Component::Header("destination-service-id".into()),
        Component::Header("mimi-room-uri".into()),
    ];
    let now = chrono::Utc::now().timestamp();
    let keyid = format!("{}#notary-key", server.service_did());
    let input = format!(
        "{};created={now};expires={};keyid=\"{keyid}\";alg=\"ed25519\"",
        format_signature_input_component_list("sig1", &covered)?,
        now + 300
    );
    let parsed = parse_signature_input(&input)?;
    let transcript = canonical_message(
        &SignedRequestParts {
            method: "POST".into(),
            target_uri: target.clone(),
            authority,
            path: String::new(),
            headers: headers.clone(),
            body_digest: Some(digest),
        },
        &parsed,
    )?;
    let (_, seed) = test_service_signing_key(&format!("{GROUP}-0"));
    let signature = sign_message(&transcript, &ed25519_dalek::SigningKey::from_bytes(&seed));
    let mut request = server.http().post(target).body(body);
    for (name, value) in headers {
        // The operation-selecting client already installs the signed selector.
        if name == "arkret-operation" {
            continue;
        }
        request = request.header(name, value);
    }
    let response = request
        .header("signature-input", input)
        .header("signature", format!("sig1=:{signature}:"))
        .send()
        .await?;
    let status = response.status();
    Ok((status, response.json().await?))
}
async fn counts(url: &str, realm: &str) -> Result<Vec<i64>> {
    let url = url.to_owned();
    let realm = realm.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_>{
        let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
        let row=db.query_one("SELECT (SELECT count(*) FROM canonical_events WHERE realm_id=$1),(SELECT count(*) FROM realm_commits WHERE realm_id=$1),(SELECT count(*) FROM message_revision_current_results WHERE realm_id=$1),(SELECT count(*) FROM federation_outbox),(SELECT count(*) FROM event_federation_outbox),(SELECT count(*) FROM idempotency_keys),(SELECT count(*) FROM audit_logs WHERE action='mimi.content_mapping'),(SELECT count(*) FROM mimi_room_binding_current_results WHERE realm_id=$1)",&[&realm])?;
        Ok((0..8).map(|i|row.get(i)).collect())
    }).await?
}

pub async fn run() -> Result<()> {
    run_evidence().await.map(|_| ())
}

pub async fn run_evidence() -> Result<Option<(Vec<CaseExecutionResult>, Vec<CaseExecutionResult>)>>
{
    let mut admission = Vec::new();
    let Some(db) = database(GROUP)? else {
        return Ok(None);
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[station_env(&db.connect_url, &coauth)],
    )
    .await?
    else {
        skip_or_fail(GROUP, "prebuilt Soland unavailable")?;
        return Ok(None);
    };
    let server = group.server(0);
    let member = Member::provision(server, &coauth, "mimi-facade-owner", DEVICE).await?;
    let realm =
        create_realm_with_join_rule(&member.client, "MIMI facade live", "public", &[server])
            .await?;
    let strand = member.client.default_strand_id(&realm)?;
    let directory: Value = server
        .http()
        .get(server.url("/_arkret/open/mimi/provider-directory"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let provider = directory
        .pointer("/mimi/provider_id")
        .and_then(Value::as_str)
        .context("MIMI directory provider_id")?;
    let room = format!("{provider}/rooms/{strand}");
    let path = format!("/_arkret/open/mimi/strands/{strand}/messages");
    let content = arkret_canonical::canonical_json_bytes(
        &json!({"content":{"kind":"m.text","body":"from actual facade"},"thread_id":strand}),
    )?;
    let body = json!({"sender_actor_id":member.actor,"device_id":member.device,
        "ciphertext":{"content_type":"application/mimi-content","payload":arkret_canonical::base64url_encode(&content),"ciphertext_digest":arkret_canonical::sha256_digest(&content)}});
    let migration = migration_matrix(&member, &db.connect_url, &realm, &strand, provider).await?;
    let mut accepted_ref = None;
    let mut migrating_ref = None;
    for role in ["observer", "hub"] {
        let binding=member.client.author_event(&realm,EventKind::MimiRoomBinding.as_str(),json!({
            "profile":"ak.profile.mimi_interop.v1","mimi_room_uri":room,
            "binding_scope":{"realm_id":realm,"strand_id":strand},"hub_provider_id":server.service_id(),
            "local_provider_role":role,"status":if role=="observer"{"accepted"}else{"migrating"},
        })).await?;
        let commit =
            submit_and_expect_commit(&member.client, &member.account, DEVICE, &binding).await?;
        if role == "hub" {
            migrating_ref = Some(commit);
            break;
        }
        accepted_ref = Some(commit);
        let before = counts(&db.connect_url, &realm).await?;
        let (status, result) = signed_post(server, &path, &room, provider, &body).await?;
        ensure!(!status.is_success(), "observer message accepted");
        ensure!(
            result["reason_code"] == "mimi_observer_write_forbidden",
            "observer refusal identity: {result}"
        );
        ensure!(
            counts(&db.connect_url, &realm).await? == before,
            "observer rejection wrote durable effects"
        );
        record(&mut admission, "observer_binding_rejects_before_effects", 3);
    }
    let previous = accepted_ref.context("accepted binding")?;
    let migrating = migrating_ref.context("migrating binding")?;
    let resolved = member.client.author_event(&realm,EventKind::MimiRoomBinding.as_str(),json!({
        "profile":"ak.profile.mimi_interop.v1","mimi_room_uri":room,
        "binding_scope":{"realm_id":realm,"strand_id":strand},"hub_provider_id":server.service_id(),
        "local_provider_role":"hub","status":"accepted","migration_outcome":"completed",
        "migration_proof":{"previous_accepted_event_id":previous.event_ref,"previous_accepted_commit_id":previous.commit_id,
            "migrating_event_id":migrating.event_ref,"migrating_commit_id":migrating.commit_id},
    })).await?;
    submit_and_expect_commit(&member.client, &member.account, DEVICE, &resolved).await?;
    let (status, result) = signed_post(server, &path, &room, provider, &body).await?;
    ensure!(
        status.is_success(),
        "real service-authored MIMI message refused: {status}: {result}"
    );
    record(&mut admission, "hub_binding_passes_observer_guard", 1);
    let follower_room_id = format!("{strand}-follower");
    let follower_room = format!("{provider}/rooms/{follower_room_id}");
    let follower = member.client.author_event(&realm, EventKind::MimiRoomBinding.as_str(), json!({
        "profile":"ak.profile.mimi_interop.v1", "mimi_room_uri":follower_room,
        "binding_scope":{"realm_id":realm,"strand_id":strand}, "hub_provider_id":server.service_id(),
        "local_provider_role":"follower","status":"accepted"
    })).await?;
    submit_and_expect_commit(&member.client, &member.account, DEVICE, &follower).await?;
    let (follower_status, follower_result) = signed_post(
        server,
        &format!("/_arkret/open/mimi/strands/{follower_room_id}/messages"),
        &follower_room,
        provider,
        &body,
    )
    .await?;
    ensure!(
        follower_status.is_success(),
        "follower facade refused: {follower_result}"
    );
    record(&mut admission, "follower_binding_passes_observer_guard", 1);
    let event_ref = result["event_ref"]
        .as_str()
        .context("MIMI service Event id")?;
    let url = db.connect_url.clone();
    let event_ref = event_ref.to_owned();
    let service = server.service_id().clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
        let row=db.query_one("SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.commit_json->>'event_ref'=$1 AND e.state='committed'",&[&event_ref])?;
        let envelope:Value=row.get(0);
        ensure!(envelope["actor_id"]==serde_json::to_value(arkret_wire::ActorId::service(service))?,"facade relabeled its service actor");
        ensure!(envelope.get("executed_by").is_none(),"facade forged delegated actor");
        ensure!(envelope["producer_proof"]["verification_method"].is_string(),"Service Event lacks its real proof");
        Ok(())
    }).await??;
    // A claim authenticated by the exact current PCR device becomes a local
    // Service-authored report; a byte-identical provider retry returns its first receipt.
    let db_url = db.connect_url.clone();
    let realm_copy = realm.clone();
    let actor = member.actor.to_string();
    let room_copy = room.clone();
    let (membership,binding)=tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db=postgres::Client::connect(&db_url,postgres::NoTls)?;
        let member=db.query_one("SELECT c.commit_json FROM member_state_current_results m JOIN realm_commits c ON c.commit_id=m.current_commit_id WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join'",&[&realm_copy,&actor])?;
        let binding=db.query_one("SELECT c.commit_json FROM mimi_room_binding_current_results m JOIN realm_commits c ON c.commit_id=m.current_commit_id WHERE m.mimi_room_uri=$1",&[&room_copy])?;
        Ok((member.get::<_,Value>(0),binding.get::<_,Value>(0)))
    }).await??;
    let committed_ref = |value: Value| -> Result<Value> {
        let c: arkret_wire::RealmCommit = serde_json::from_value(value)?;
        Ok(
            json!({"event_id":c.event_ref,"commit_id":c.commit_id,"stream_ref":c.stream_ref,"stream_position":c.stream_position}),
        )
    };
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut report: arkret_models_collaboration::mimi_operations::MimiReportAbuseRequestBody =
        serde_json::from_value(json!({
            "reporter_authority":{"actor_id":member.actor,"membership_ref":committed_ref(membership)?,"room_binding_ref":committed_ref(binding)?,
                "expires_at":arkret_canonical::format_timestamp_canonical(now+chrono::Duration::seconds(240)),
                "proof":{"kind":"detached_jws","verification_method":member.method,"payload_digest":format!("sha256:{}","0".repeat(64)),
                    "created_at":arkret_canonical::format_timestamp_canonical(now),"domain":"ak.mimi_reporter_authority_proof.v1",
                    "audience":server.service_id(),"jws":"placeholder"}},
            "report_claim":{"realm_id":realm,"scope_ref":{"kind":"realm","realm_id":realm},"target_ref":realm,"report_reason_code":"spam"}
        }))?;
    report.reporter_authority.proof.payload_digest = report.payload_digest()?;
    report.reporter_authority.proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &report.reporter_authority_binding_bytes()?,
        &member.key,
    )
    .map_err(anyhow::Error::msg)?;
    let report = serde_json::to_value(report)?;
    let before = counts(&db.connect_url, &realm).await?;
    let (status, first) = signed_post(
        server,
        "/_arkret/open/mimi/report-abuse",
        &room,
        provider,
        &report,
    )
    .await?;
    ensure!(
        status.is_success(),
        "real facade report refused: {status}: {first}"
    );
    let after = counts(&db.connect_url, &realm).await?;
    ensure!(
        after[0] == before[0] + 1 && after[1] == before[1] + 1 && after[5] == before[5] + 1,
        "report Event/Commit/idempotency were not one accepting effect"
    );
    let report_database = db.connect_url.clone();
    let report_realm = realm.clone();
    let report_commit: arkret_wire::RealmCommit =
        tokio::task::spawn_blocking(move || -> Result<_> {
            let mut database = postgres::Client::connect(&report_database, postgres::NoTls)?;
            let row = database.query_one(
            "SELECT c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
             WHERE c.realm_id=$1 AND e.kind=$2 ORDER BY c.stream_position DESC LIMIT 1",
            &[&report_realm, &EventKind::SelfModerationReport.as_str()],
        )?;
            Ok(serde_json::from_value(row.get::<_, Value>(0))?)
        })
        .await??;
    ensure!(
        first["report_id"]
            == serde_json::to_value(arkret_wire::ReportId::from_event_id(
                &report_commit.event_ref
            ))?,
        "MIMI receipt report id is not derived from its actual committed Event"
    );
    let (status, replay) = signed_post(
        server,
        "/_arkret/open/mimi/report-abuse",
        &room,
        provider,
        &report,
    )
    .await?;
    ensure!(
        status.is_success() && replay == first,
        "MIMI report replay changed its first receipt"
    );
    ensure!(
        counts(&db.connect_url, &realm).await? == after,
        "MIMI report replay appended another Event or delivery"
    );

    // An E2EE migration reuses a GroupInfo that the native MLS unit has
    // authenticated and committed, instead of trusting claimed group strings.
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: arkret_wire::RealmId::new(realm.clone())?,
    };
    let governance = arkret::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut mls = member
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &governance)?;
    let leaf = crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority(
        &mut mls, &member,
    )?;
    let (info, tree) = mls.public_group_state_bytes()?;
    let info_ref = crate::scenarios::mls_lifecycle_live::upload_public_blob(
        &member.client,
        scope.realm_id(),
        &info,
    )
    .await?;
    let tree_ref = crate::scenarios::mls_lifecycle_live::upload_public_blob(
        &member.client,
        scope.realm_id(),
        &tree,
    )
    .await?;
    let genesis=member.client.author_event(&realm,EventKind::MlsGenesis.as_str(),json!({
        "cipher_suite":crate::scenarios::mls_lifecycle_live::ACTIVE_SUITE,"group_info_ref":info_ref,"ratchet_tree_ref":tree_ref,
        "governance_binding":governance,"creator_leaf_authority":leaf,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    })).await?;
    submit_and_expect_commit(&member.client, &member.account, DEVICE, &genesis).await?;
    let group_id = scope.canonical_mls_group_id()?;
    let mut native_binding = json!({"profile":"ak.profile.mimi_interop.v1","mimi_room_uri":room,
        "binding_scope":{"realm_id":realm,"strand_id":strand},"hub_provider_id":server.service_id(),
        "local_provider_role":"hub","status":"migrating","mls_group_id":group_id});
    let migrating = member
        .client
        .author_event(
            &realm,
            EventKind::MimiRoomBinding.as_str(),
            native_binding.clone(),
        )
        .await?;
    let migrating_commit =
        submit_and_expect_commit(&member.client, &member.account, DEVICE, &migrating).await?;
    native_binding["status"] = json!("accepted");
    native_binding["migration_outcome"] = json!("completed");
    // Read the exact accepted Commit; arbitrary lineage IDs cannot authorize migration.
    let accepted_commit_url = db.connect_url.clone();
    let accepted_event_id = resolved.event_id.to_string();
    let previous_accepted_commit_id = tokio::task::spawn_blocking(move || -> Result<String> {
        let mut db = postgres::Client::connect(&accepted_commit_url, postgres::NoTls)?;
        Ok(db
            .query_one(
                "SELECT commit_id FROM realm_commits WHERE commit_json->>'event_ref'=$1",
                &[&accepted_event_id],
            )?
            .get(0))
    })
    .await??;
    native_binding["migration_proof"] = json!({
        "previous_accepted_event_id":resolved.event_id,
        "previous_accepted_commit_id":previous_accepted_commit_id,
        "migrating_event_id":migrating.event_id,
        "migrating_commit_id":migrating_commit.commit_id
    });
    let native = member
        .client
        .author_event(&realm, EventKind::MimiRoomBinding.as_str(), native_binding)
        .await?;
    submit_and_expect_commit(&member.client, &member.account, DEVICE, &native).await?;
    for mutation in ["verified_group_info", "binding_group", "current_scope"] {
        let message = json!({"content":{"kind":"m.text","body":"must reject"},"thread_id":strand,"governance_binding":governance});
        let other_scope = arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::from_event_id(&genesis.event_id),
        };
        let other_group = other_scope.canonical_mls_group_id()?;
        let claimed_group = group_id.clone();
        // Exercise a real authenticated GroupInfo with the wrong group, and
        // an independent current scope mismatch. Test-only storage injection
        // models a drifted read frontier; the signed Realm history stays intact.
        let saved_frontier = if mutation == "verified_group_info" || mutation == "current_scope" {
            let replacement_state = if mutation == "verified_group_info" {
                let governance =
                    arkret::MlsGovernanceBindingPayload::new(other_scope.clone(), None, 0, 0, 0)?;
                let other = member
                    .mls_identity()?
                    .create_group_with_governance_binding(&other_scope, &governance)?;
                let (info, tree) = other.public_group_state_bytes()?;
                Some(
                    arkret_mls::MlsPublicGroupTracker::from_external(
                        &info,
                        &tree,
                        other_group.as_str(),
                        0,
                    )?
                    .export_state()?,
                )
            } else {
                None
            };
            let url = db.connect_url.clone();
            let realm_copy = realm.clone();
            let mutation = mutation.to_owned();
            let replacement_scope = serde_json::to_value(arkret_wire::ScopeRef::Circle {
                realm_id: scope.realm_id().clone(),
                circle_id: arkret_wire::CircleId::from_event_id(&genesis.event_id),
            })?;
            Some(tokio::task::spawn_blocking(move || -> Result<(Value,Vec<u8>)> {
                let mut db = postgres::Client::connect(&url,postgres::NoTls)?;
                let row = db.query_one("SELECT value,public_state FROM mls_group_current_results WHERE realm_id=$1", &[&realm_copy])?;
                let value:Value=row.get(0);let public_state:Vec<u8>=row.get(1);
                if mutation == "verified_group_info" {
                    db.execute("UPDATE mls_group_current_results SET public_state=$2 WHERE realm_id=$1", &[&realm_copy,&replacement_state.context("replacement public state")?])?;
                } else {
                    let mut replacement=value.clone();replacement["effective_scope"]=replacement_scope;
                    db.execute("UPDATE mls_group_current_results SET value=$2 WHERE realm_id=$1", &[&realm_copy,&replacement])?;
                }
                Ok((value,public_state))
            }).await??)
        } else {
            None
        };
        let room_id = if mutation == "binding_group" {
            format!("{strand}-wrong-group")
        } else {
            strand.clone()
        };
        let addressed_room = format!("{provider}/rooms/{room_id}");
        if mutation == "binding_group" {
            let wrong=member.client.author_event(&realm,EventKind::MimiRoomBinding.as_str(),json!({
                "profile":"ak.profile.mimi_interop.v1","mimi_room_uri":addressed_room,"binding_scope":{"realm_id":realm,"strand_id":strand},
                "hub_provider_id":server.service_id(),"local_provider_role":"hub","status":"accepted","mls_group_id":other_group})).await?;
            submit_and_expect_commit(&member.client, &member.account, DEVICE, &wrong).await?;
        }
        let encoded = arkret_canonical::canonical_json_bytes(&message)?;
        let rejected = json!({"sender_actor_id":member.actor,"device_id":member.device,"mls_group_id":claimed_group,"epoch":0,
            "ciphertext":{"content_type":"application/mimi-content","payload":arkret_canonical::base64url_encode(&encoded),"ciphertext_digest":arkret_canonical::sha256_digest(&encoded)}});
        let before = counts(&db.connect_url, &realm).await?;
        let (status, result) = signed_post(
            server,
            &format!("/_arkret/open/mimi/strands/{room_id}/messages"),
            &addressed_room,
            provider,
            &rejected,
        )
        .await?;
        ensure!(
            !status.is_success() && result["reason_code"] == "mimi_governance_binding_mismatch",
            "{mutation} escaped group guard: {result}"
        );
        ensure!(
            counts(&db.connect_url, &realm).await? == before,
            "{mutation} wrote Event/Commit/current/outbox/receipt"
        );
        if let Some((value, public_state)) = saved_frontier {
            let url = db.connect_url.clone();
            let realm_copy = realm.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
                db.execute("UPDATE mls_group_current_results SET value=$2,public_state=$3 WHERE realm_id=$1", &[&realm_copy,&value,&public_state])?;
                Ok(())
            }).await??;
        }
        record(
            &mut admission,
            match mutation {
                "verified_group_info" => "verified_group_info_group_id_mismatch",
                "binding_group" => "room_binding_group_id_mismatch",
                _ => "current_scope_derived_group_id_mismatch",
            },
            2,
        );
    }
    // A real standard Bearer session still has to authenticate the Provider.
    let consent = json!({"requester_actor_id":member.actor,"holder_account_id":member.account,"purpose":"voice_call","proofs":[]});
    let result = expect_json(
        member
            .client
            .post("/_arkret/open/mimi/consent/request")
            .canonical_json(&consent)?,
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    ensure!(
        result["type"]
            .as_str()
            .is_some_and(|kind| kind.ends_with("http_signature_required")),
        "Bearer shortcut survived: {result}"
    );
    Ok(Some((admission, migration)))
}

fn record(results: &mut Vec<CaseExecutionResult>, case: &str, assertions: usize) {
    results.push(CaseExecutionResult {
        case_id: case.into(),
        assertions,
    });
}

async fn reject_binding(
    member: &Member,
    database: &str,
    realm: &str,
    payload: Value,
    reason: &str,
) -> Result<()> {
    let before = counts(database, realm).await?;
    let event = member
        .client
        .author_event(realm, EventKind::MimiRoomBinding.as_str(), payload)
        .await?;
    let response = member
        .client
        .post("/_arkret/self/events")
        .canonical_json(&crate::publication::initial_submission(event, "")?)?
        .send()
        .await?;
    let status = response.status();
    let problem: Value = response.json().await?;
    ensure!(
        !status.is_success() && problem.to_string().contains(reason),
        "binding refusal: {status}: {problem}"
    );
    ensure!(
        before == counts(database, realm).await?,
        "rejected binding wrote durable effects"
    );
    Ok(())
}

async fn migration_matrix(
    member: &Member,
    database: &str,
    realm: &str,
    strand: &str,
    provider: &str,
) -> Result<Vec<CaseExecutionResult>> {
    let mut results = Vec::new();
    let binding = |room: &str, status: &str, role: &str| {
        json!({
            "profile":"ak.profile.mimi_interop.v1", "mimi_room_uri":format!("{provider}/rooms/{room}"),
            "binding_scope":{"realm_id":realm,"strand_id":strand},"hub_provider_id":member.actor.route_service_id(),
            "local_provider_role":role,"status":status
        })
    };
    let author = |payload| {
        member
            .client
            .author_event(realm, EventKind::MimiRoomBinding.as_str(), payload)
    };
    let other = author(binding("matrix-other", "accepted", "hub")).await?;
    let other_commit =
        submit_and_expect_commit(&member.client, &member.account, DEVICE, &other).await?;
    for outcome in ["completed", "rolled_back"] {
        let room = format!("matrix-{outcome}");
        let original = binding(&room, "accepted", "observer");
        let first = author(original.clone()).await?;
        let first_commit =
            submit_and_expect_commit(&member.client, &member.account, DEVICE, &first).await?;
        let candidate = binding(&room, "migrating", "hub");
        let first_migrating = author(candidate.clone()).await?;
        let first_migrating_commit =
            submit_and_expect_commit(&member.client, &member.account, DEVICE, &first_migrating)
                .await?;
        let proof = |accepted: &arkret_wire::RealmCommit, migrating: &arkret_wire::RealmCommit| {
            json!({
                "previous_accepted_event_id":accepted.event_ref,"previous_accepted_commit_id":accepted.commit_id,
                "migrating_event_id":migrating.event_ref,"migrating_commit_id":migrating.commit_id
            })
        };
        // Install a real superseded accepted binding; non-adjacency is tested
        // against accepted history, rather than a nonexistent or forged ID.
        let mut rollback = original.clone();
        rollback["migration_outcome"] = json!("rolled_back");
        rollback["migration_proof"] = proof(&first_commit, &first_migrating_commit);
        let rollback = author(rollback).await?;
        let accepted =
            submit_and_expect_commit(&member.client, &member.account, DEVICE, &rollback).await?;
        let migrating = author(candidate.clone()).await?;
        let migrating =
            submit_and_expect_commit(&member.client, &member.account, DEVICE, &migrating).await?;
        let mut resolved = if outcome == "completed" {
            candidate.clone()
        } else {
            original.clone()
        };
        resolved["status"] = json!("accepted");
        resolved["migration_outcome"] = json!(outcome);
        resolved["migration_proof"] = proof(&accepted, &migrating);
        if outcome == "completed" {
            for case in [
                "outcome_without_proof",
                "proof_without_outcome",
                "both_migration_fields_missing",
                "stale_migrating_commit",
                "cross_room_previous_event",
                "non_adjacent_previous_event",
                "completed_with_previous_topology",
                "rolled_back_with_candidate_topology",
            ] {
                let mut bad = resolved.clone();
                match case {
                    "outcome_without_proof" => {
                        bad.as_object_mut().unwrap().remove("migration_proof");
                    }
                    "proof_without_outcome" => {
                        bad.as_object_mut().unwrap().remove("migration_outcome");
                    }
                    "both_migration_fields_missing" => {
                        bad.as_object_mut().unwrap().remove("migration_proof");
                        bad.as_object_mut().unwrap().remove("migration_outcome");
                    }
                    "stale_migrating_commit" => {
                        bad["migration_proof"]["migrating_commit_id"] =
                            json!(first_migrating_commit.commit_id)
                    }
                    "cross_room_previous_event" => {
                        bad["migration_proof"]["previous_accepted_event_id"] =
                            json!(other_commit.event_ref);
                        bad["migration_proof"]["previous_accepted_commit_id"] =
                            json!(other_commit.commit_id);
                    }
                    "non_adjacent_previous_event" => {
                        bad["migration_proof"]["previous_accepted_event_id"] =
                            json!(first_commit.event_ref);
                        bad["migration_proof"]["previous_accepted_commit_id"] =
                            json!(first_commit.commit_id);
                    }
                    "completed_with_previous_topology" => {
                        bad["local_provider_role"] = json!("observer")
                    }
                    _ => bad["migration_outcome"] = json!("rolled_back"),
                }
                if matches!(case, "outcome_without_proof" | "proof_without_outcome") {
                    let before = counts(database, realm).await?;
                    let decoded: Result<
                        arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingPayload,
                        _,
                    > = serde_json::from_value(bad);
                    ensure!(
                        decoded
                            .map(|value| value.validate_shape().is_err())
                            .unwrap_or(true),
                        "{case} passed production shape validation"
                    );
                    ensure!(
                        before == counts(database, realm).await?,
                        "schema refusal wrote effects"
                    );
                } else {
                    reject_binding(
                        member,
                        database,
                        realm,
                        bad,
                        "mimi_room_binding_migration_proof_invalid",
                    )
                    .await?;
                }
                record(&mut results, case, 2);
            }
        }
        let resolved_event = author(resolved.clone()).await?;
        submit_and_expect_commit(&member.client, &member.account, DEVICE, &resolved_event).await?;
        record(
            &mut results,
            if outcome == "completed" {
                "completed_candidate_topology"
            } else {
                "rolled_back_previous_topology"
            },
            2,
        );
        if outcome == "completed" {
            let proposed = binding("matrix-proposed", "proposed", "hub");
            let proposed_event = author(proposed.clone()).await?;
            submit_and_expect_commit(&member.client, &member.account, DEVICE, &proposed_event)
                .await?;
            let mut bad = proposed;
            bad["status"] = json!("accepted");
            bad["migration_outcome"] = json!("completed");
            bad["migration_proof"] = proof(&accepted, &migrating);
            reject_binding(
                member,
                database,
                realm,
                bad,
                "mimi_room_binding_migration_proof_invalid",
            )
            .await?;
            record(&mut results, "migration_fields_on_other_transition", 2);
        }
    }
    // Selected topology itself claims a scope-derived group, but no native MLS
    // GroupInfo has been accepted for that scope at this cut.
    let room = "matrix-unaccepted-group";
    let initial = author(binding(room, "accepted", "hub")).await?;
    let initial =
        submit_and_expect_commit(&member.client, &member.account, DEVICE, &initial).await?;
    let mut candidate = binding(room, "migrating", "hub");
    candidate["mls_group_id"] = json!(
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret_wire::RealmId::new(realm.to_owned())?
        }
        .canonical_mls_group_id()?
    );
    let event = author(candidate.clone()).await?;
    let migrating =
        submit_and_expect_commit(&member.client, &member.account, DEVICE, &event).await?;
    candidate["status"] = json!("accepted");
    candidate["migration_outcome"] = json!("completed");
    candidate["migration_proof"] = json!({"previous_accepted_event_id":initial.event_ref,"previous_accepted_commit_id":initial.commit_id,"migrating_event_id":migrating.event_ref,"migrating_commit_id":migrating.commit_id});
    reject_binding(
        member,
        database,
        realm,
        candidate,
        "mimi_room_binding_migration_proof_invalid",
    )
    .await?;
    record(&mut results, "target_mls_group_not_current", 2);
    // Stateful refusals must run before the accepting transition. Return
    // their evidence in the normative fixture order for the completeness gate.
    // Unknown, duplicate or missing cases still fail that gate.
    let fixture_order = [
        "completed_candidate_topology",
        "rolled_back_previous_topology",
        "outcome_without_proof",
        "proof_without_outcome",
        "both_migration_fields_missing",
        "stale_migrating_commit",
        "cross_room_previous_event",
        "non_adjacent_previous_event",
        "completed_with_previous_topology",
        "rolled_back_with_candidate_topology",
        "target_mls_group_not_current",
        "migration_fields_on_other_transition",
    ];
    results.sort_by_key(|result| {
        fixture_order
            .iter()
            .position(|case| *case == result.case_id)
            .unwrap_or(usize::MAX)
    });
    Ok(results)
}
