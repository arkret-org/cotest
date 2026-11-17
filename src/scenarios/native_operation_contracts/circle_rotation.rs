//! Real Circle Add/Welcome and zero-Welcome leaf rotation through the registered route.
use std::io::Write as _;

use arkret::ArkretMlsGroup;
use arkret_models_collaboration::device_messages::DeviceMessagesAcknowledgementRequestBody;
use arkret_models_crypto::{KeyPackagesClaimResponseBody, KeyPackagesUploadResponseBody};
use arkret_wire::{
    AuthorityCommitStatus, AuthoritySubmitRequestBody, AuthoritySubmitResponseBody,
    CommittedEventFullView, Event, EventKind, MlsCommitSubmission, MlsGroupValue, RealmId,
    ScopeRef,
};

use super::*;
use crate::harness::{ArkretServer, CanonicalClientRequest, expect_json};
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

const SCOPE: [&str; 1] = ["ak.self.circle.command.rotate_scope.v1"];

async fn current(station: &ArkretServer, scope: &ScopeRef) -> Result<MlsGroupValue> {
    let database = station
        .owned_database_url()
        .context("owned Circle database")?
        .to_owned();
    let scope = serde_json::to_value(scope)?;
    tokio::task::spawn_blocking(move || -> Result<MlsGroupValue> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let rows = db.query(
            "SELECT value FROM mls_group_current_states WHERE value->'effective_scope'=$1::jsonb",
            &[&scope],
        )?;
        ensure!(
            rows.len() == 1,
            "exact scope has no unique accepted MLS current"
        );
        Ok(serde_json::from_value(rows[0].get(0))?)
    })
    .await?
}

// These are source observations, never an admission or authority oracle.
async fn footprint(station: &ArkretServer, realm: &RealmId) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("owned Circle database")?
        .to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let mut result = serde_json::Map::new();
        for table in ["canonical_events", "realm_commits", "mls_group_current_states", "mls_endpoint_current_bindings", "mls_welcome_provenance", "mls_welcome_deliveries"] {
            let query = format!("SELECT coalesce(jsonb_agg(v ORDER BY v::text),'[]'::jsonb) FROM (SELECT to_jsonb(r) AS v FROM {table} r) q WHERE v->>'realm_id'=$1 OR v->'envelope'->>'realm_id'=$1 OR v->>'scope_key' IN (SELECT scope_key FROM mls_group_current_states WHERE realm_id=$1)");
            result.insert(table.to_owned(), db.query_one(&query, &[&realm])?.get(0));
        }
        result.insert("keypackage_claim_welcome_bindings".into(), db.query_one("SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY to_jsonb(b)::text),'[]'::jsonb) FROM keypackage_claim_welcome_bindings b JOIN mls_welcome_deliveries w ON w.welcome_id=b.welcome_id WHERE w.realm_id=$1", &[&realm])?.get(0));
        result.insert("peer_keypackage_claims".into(), db.query_one("SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY to_jsonb(p)::text),'[]'::jsonb) FROM peer_keypackage_claims p JOIN keypackage_claim_welcome_bindings b ON b.source_id=p.source_id AND b.claim_request_id=p.claim_request_id JOIN mls_welcome_deliveries w ON w.welcome_id=b.welcome_id WHERE w.realm_id=$1", &[&realm])?.get(0));
        result.insert("idempotency_keys".into(), db.query_one("SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY to_jsonb(i)::text),'[]'::jsonb) FROM idempotency_keys i WHERE i.source_event_pk IN (SELECT pk FROM canonical_events WHERE realm_id=$1) OR i.authenticated_actor IN (SELECT DISTINCT envelope->'actor_id' FROM canonical_events WHERE realm_id=$1)", &[&realm])?.get(0));
        Ok(Value::Object(result))
    }).await?
}

async fn scoped_event(
    owner: &Member,
    scope: &ScopeRef,
    kind: EventKind,
    payload: Value,
) -> Result<Event> {
    let mut event = owner
        .client
        .author_event(scope.realm_id().as_str(), kind.as_str(), payload)
        .await?;
    event.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof_with_signing_seed(&mut event, owner.key.to_bytes())?;
    Ok(event)
}

async fn genesis(
    station: &ArkretServer,
    owner: &Member,
    scope: &ScopeRef,
) -> Result<(ArkretMlsGroup, CommittedEventFullView, MlsGroupValue)> {
    let binding = arkret::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut group = owner
        .mls_identity()?
        .create_group_with_governance_binding(scope, &binding)?;
    let creator = crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority(
        &mut group, owner,
    )?;
    let (info, tree) = group.public_group_state_bytes()?;
    let event = scoped_event(
        owner,
        scope,
        EventKind::MlsGenesis,
        json!({
            "cipher_suite":mls::ACTIVE_SUITE,
            "group_info_ref":mls::upload_public_blob(&owner.client,scope.realm_id(),&info).await?,
            "ratchet_tree_ref":mls::upload_public_blob(&owner.client,scope.realm_id(),&tree).await?,
            "governance_binding":binding,"creator_leaf_authority":creator,
            "created_at":arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
        }),
    )
    .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &owner.client,
        &owner.account,
        owner.device.as_str(),
        &event,
    )
    .await?;
    let accepted = mls::accepted_full_view(&owner.client, &event.event_id).await?;
    let value = current(station, scope).await?;
    ensure!(
        value.epoch == 0
            && value.genesis_event_ref == event.event_id
            && value.current_mls_commit_event_ref == event.event_id
            && value.effective_scope == *scope,
        "Genesis readback differs from the actual accepted group"
    );
    crate::scenarios::message_mls_cross_station_live::install_bindings(&mut group, &[owner])
        .await?;
    Ok((group, accepted, value))
}

async fn send_exact(owner: &Member, path: &str, bytes: &[u8]) -> Result<(u16, Vec<u8>)> {
    let request = owner
        .client
        .post(path)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(bytes.to_vec());
    let frozen = cotest_test_support::operation_observation::freeze_request(&request)?;
    let response = request.send().await?;
    let status = response.status().as_u16();
    let body = response.bytes().await?.to_vec();
    cotest_test_support::operation_observation::record_response(frozen.as_ref(), status, &body)?;
    Ok((status, body))
}

fn authority_outcome(
    bytes: &[u8],
    request: &MlsCommitSubmission,
) -> Result<AuthoritySubmitResponseBody> {
    let outcome: AuthoritySubmitResponseBody = serde_json::from_slice(bytes)?;
    outcome.validate_for_request(&AuthoritySubmitRequestBody::MlsCommit(request.clone()))?;
    ensure!(
        matches!(
            &outcome,
            AuthoritySubmitResponseBody::Accepted {
                status: AuthorityCommitStatus::Committed,
                ..
            }
        ),
        "first Circle rotation has no real committed outcome"
    );
    Ok(outcome)
}

async fn retry(
    owner: &Member,
    station: &ArkretServer,
    realm: &RealmId,
    path: &str,
    bytes: &[u8],
    original: &[u8],
) -> Result<Value> {
    let before = footprint(station, realm).await?;
    let (status, body) = send_exact(owner, path, bytes).await?;
    ensure!(
        status == 200 && body == original,
        "complete Circle retry changed its original authority outcome"
    );
    let after = footprint(station, realm).await?;
    ensure!(
        before == after,
        "exact Circle retry created another result, Commit, current or Welcome"
    );
    Ok(
        json!({"status":status,"body_base64url":arkret_canonical::base64url_encode(&body),"before":before,"after":after}),
    )
}

async fn refused(
    owner: &Member,
    station: &ArkretServer,
    realm: &RealmId,
    path: &str,
    request: &MlsCommitSubmission,
    code: arkret_wire::ErrorCode,
) -> Result<Value> {
    let before = footprint(station, realm).await?;
    let bytes = arkret_canonical::canonical_json_bytes(request)?;
    let (actual, raw) = send_exact(owner, path, &bytes).await?;
    let body: Value = serde_json::from_slice(&raw)?;
    let problem: arkret_wire::Problem = serde_json::from_slice(&raw)?;
    ensure!(
        actual == code.http_status()
            && problem.status == actual
            && problem.error_code() == Some(code),
        "Circle negative differs from its registered refusal: {actual} {body}"
    );
    let after = footprint(station, realm).await?;
    ensure!(
        before == after,
        "refused Circle request left admission or recipient effects"
    );
    Ok(
        json!({"request":request,"status":actual,"body":body,"body_base64url":arkret_canonical::base64url_encode(&raw),"before":before,"after":after}),
    )
}

async fn scenario() -> Result<Value> {
    let deployment =
        crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
            "native-circle-rotation",
        )
        .await?;
    let ca = deployment
        .station
        .tls_ca_path()
        .context("owned Circle Station CA")?;
    let bob_http = reqwest::Client::builder()
        .tls_backend_rustls()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)?)
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let bob_device = arkret_identifiers::new_prefixed_uuid7("ak:device:");
    let bob_client = deployment
        .station
        .canonical_client(CanonicalClientRequest {
            http: &bob_http,
            endpoints: &deployment.endpoints,
            oidc_client_id: &deployment.oidc_client_id,
            handle: "bob",
            password: "1amTester!",
            device_id: &bob_device,
            display_name: "Circle MLS recipient",
        })
        .await?;
    let bob = super::mls_interop::member(bob_client, deployment.station.service_id())?;
    let alice = super::mls_interop::member(deployment.controller, deployment.station.service_id())?;
    let station = &deployment.station;
    let realm: RealmId = crate::scenarios::human_device_producer_live::create_realm_with_join_rule(
        &alice.client,
        "Native independent Circle rotation",
        "public",
        &[station],
    )
    .await?
    .parse()?;
    let realm_genesis = mls::accepted_full_view(
        &alice.client,
        &arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            realm.digest_bytes(),
        ),
    )
    .await?;
    let join = bob.client.author_event(realm.as_str(),EventKind::MemberState.as_str(),crate::scenarios::human_device_producer_live::membership_payload(realm.as_str(),bob.account.clone(),arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,"Circle rotation recipient")?).await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &bob.client,
        &bob.account,
        bob.device.as_str(),
        &join,
    )
    .await?;
    let parent_scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let (_parent_group, parent_genesis, parent_current) =
        genesis(station, &alice, &parent_scope).await?;
    let circle = crate::scenarios::circle_poll_scope_live::circle_create(
        &alice.client,
        realm.as_str(),
        &alice.actor,
        "Native rotating Circle",
        "Rotate",
    )
    .await?;
    for member in [&alice, &bob] {
        crate::scenarios::circle_poll_scope_live::join_circle(
            &member.client,
            realm.as_str(),
            &circle,
            &member.actor,
        )
        .await?;
    }
    let scope = ScopeRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    let (mut sender, circle_genesis, base) = genesis(station, &alice, &scope).await?;
    let circle_create = mls::accepted_full_view(
        &alice.client,
        &arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            circle.digest_bytes(),
        ),
    )
    .await?;
    let strand = crate::scenarios::circle_poll_scope_live::circle_event(&alice.client,realm.as_str(),&circle,EventKind::StrandCreate,json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":circle,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Native rotation ciphertext"},"state":"active","created_by":alice.actor}})).await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &alice.client,
        &alice.account,
        alice.device.as_str(),
        &strand,
    )
    .await?;
    let strand_view = mls::accepted_full_view(&alice.client, &strand.event_id).await?;
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.event_id);

    let bob_identity = bob.mls_identity()?;
    let package = bob_identity.key_package_record()?;
    let upload =
        bob_identity.signed_key_packages_upload_request(&[package], bob.method.as_str())?;
    let uploaded: KeyPackagesUploadResponseBody = serde_json::from_value(
        expect_json(
            bob.client
                .post("/_arkret/self/keys/keypackages/upload")
                .json(&upload),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        uploaded.accepted_count == 1 && uploaded.rejections.is_empty(),
        "Circle recipient package not accepted"
    );
    let mut claim_nonce = [0u8; 16];
    getrandom::fill(&mut claim_nonce).context("native Circle claim entropy")?;
    let claim_request = mls::claim_request_between_scoped(
        &alice,
        station,
        station,
        &bob,
        &scope,
        claim_nonce,
        chrono::Duration::minutes(4),
    )?;
    let claim: KeyPackagesClaimResponseBody = serde_json::from_value(
        expect_json(
            alice
                .client
                .post("/_arkret/self/keys/keypackages/claim")
                .header("Idempotency-Key", claim_request.claim_request_id.as_str())
                .json(&claim_request),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    claim.validate_shape().map_err(anyhow::Error::msg)?;
    ensure!(
        claim.claims.len() == 1
            && serde_json::to_value(&claim.claim_receipt.request)?
                == serde_json::to_value(claim_request.unsigned_request())?,
        "Circle claim lost its exact request or recipient"
    );
    let group_id = scope.canonical_mls_group_id()?;
    let binding = arkret::MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(base.current_mls_commit_event_ref.clone()),
        base.epoch,
        base.epoch + 1,
        base.current_key_access_revision,
    )?;
    let add = sender.add_member_with_governance_binding(
        &mls::claimed_keypackage_record(&claim.claims[0], &bob)?,
        &binding,
    )?;
    let add_payload = mls::commit_payload_with_public_material(
        &alice.client,
        &sender,
        base.current_mls_commit_event_ref.clone(),
        base.current_key_access_revision,
        &add.commit,
        binding,
    )
    .await?;
    arkret_mls::require_public_commit_update_path(
        &arkret_canonical::base64url_decode(add.commit.commit.as_str())?,
        group_id.as_str(),
        base.epoch,
    )?;
    let add_event = scoped_event(
        &alice,
        &scope,
        EventKind::MlsCommit,
        serde_json::to_value(add_payload)?,
    )
    .await?;
    let welcome = mls::signed_welcome(&alice, &add_event, &bob, &add.welcome)?;
    let add_request = MlsCommitSubmission {
        recovery_source: None,
        commit_event: add_event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7())?,
    };
    let add_bytes = arkret_canonical::canonical_json_bytes(&add_request)?;
    let path = format!("/_arkret/self/circles/{circle}/scope-rotate");
    let (add_status, add_raw) = send_exact(&alice, &path, &add_bytes).await?;
    ensure!(
        add_status == 200,
        "native Circle Add rotation refused: {add_status} {}",
        String::from_utf8_lossy(&add_raw)
    );
    let add_outcome = authority_outcome(&add_raw, &add_request)?;
    let add_committed = mls::accepted_full_view(&alice.client, &add_event.event_id).await?;
    ensure!(
        add_committed.event == add_event
            && sender.install_accepted_commit(&add_committed, &base)? == base.epoch + 1,
        "sender did not install the actual Circle Add"
    );
    let (queued, ack) = mls::recipient_welcomes(&bob.client).await?;
    ensure!(
        queued == vec![welcome.clone()],
        "Circle recipient queue changed or duplicated the original Welcome"
    );
    let recipient_commit = mls::accepted_full_view(&bob.client, &add_event.event_id).await?;
    ensure!(
        recipient_commit == add_committed,
        "recipient read another Circle Add original"
    );
    let mut receiver = ArkretMlsGroup::join_from_verified_welcome_delivery(
        bob_identity,
        &welcome,
        &recipient_commit,
    )?;
    crate::scenarios::message_mls_cross_station_live::install_bindings(
        &mut sender,
        &[&alice, &bob],
    )
    .await?;
    crate::scenarios::message_mls_cross_station_live::install_bindings(
        &mut receiver,
        &[&alice, &bob],
    )
    .await?;
    let after_add = current(station, &scope).await?;
    ensure!(
        after_add.epoch == 1
            && after_add.current_mls_commit_event_ref == add_event.event_id
            && sender.epoch() == 1
            && receiver.epoch() == 1
            && sender.group_id() == group_id
            && receiver.group_id() == group_id,
        "actual Circle Add did not establish epoch one"
    );
    let old_record = receiver.export_state_record()?;
    let old_bytes = serde_json::to_vec(&old_record)?;
    let mut checkpoint = tempfile::NamedTempFile::new()?;
    checkpoint.write_all(&old_bytes)?;
    checkpoint.as_file().sync_all()?;
    let mut old_receiver = ArkretMlsGroup::restore_from_state_record(&serde_json::from_slice(
        &std::fs::read(checkpoint.path())?,
    )?)?;
    let binding = arkret::MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(after_add.current_mls_commit_event_ref.clone()),
        after_add.epoch,
        after_add.epoch + 1,
        after_add.current_key_access_revision,
    )?;
    let update = sender.self_update_commit_with_governance_binding(&binding)?;
    arkret_mls::require_public_commit_update_path(
        &arkret_canonical::base64url_decode(update.commit.as_str())?,
        group_id.as_str(),
        after_add.epoch,
    )?;
    let update_payload = mls::commit_payload_with_public_material(
        &alice.client,
        &sender,
        after_add.current_mls_commit_event_ref.clone(),
        after_add.current_key_access_revision,
        &update,
        binding,
    )
    .await?;
    let update_event = scoped_event(
        &alice,
        &scope,
        EventKind::MlsCommit,
        serde_json::to_value(update_payload)?,
    )
    .await?;
    let update_request = MlsCommitSubmission {
        recovery_source: None,
        commit_event: update_event.clone(),
        welcomes: vec![],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7())?,
    };
    let update_bytes = arkret_canonical::canonical_json_bytes(&update_request)?;
    let (update_status, update_raw) = send_exact(&alice, &path, &update_bytes).await?;
    ensure!(
        update_status == 200,
        "native zero-Welcome Circle rotation refused: {update_status} {}",
        String::from_utf8_lossy(&update_raw)
    );
    let update_outcome = authority_outcome(&update_raw, &update_request)?;
    let update_committed = mls::accepted_full_view(&alice.client, &update_event.event_id).await?;
    ensure!(
        update_committed.event == update_event
            && sender.install_accepted_commit(&update_committed, &after_add)? == 2,
        "sender did not install actual zero-Welcome Circle rotation"
    );
    crate::scenarios::message_mls_cross_station_live::install_bindings(
        &mut sender,
        &[&alice, &bob],
    )
    .await?;
    let after_update = current(station, &scope).await?;
    ensure!(
        after_update.epoch == 2
            && after_update.current_mls_commit_event_ref == update_event.event_id
            && after_update.genesis_event_ref == circle_genesis.event.event_id
            && after_update.effective_scope == scope,
        "Circle current lost its exact original transition"
    );
    ensure!(
        current(station, &parent_scope).await? == parent_current,
        "Circle rotation changed its parent MLS group"
    );

    let add_retry = retry(&alice, station, &realm, &path, &add_bytes, &add_raw).await?;
    let update_retry = retry(&alice, station, &realm, &path, &update_bytes, &update_raw).await?;
    let originals = footprint(station, &realm).await?;
    let canonical = originals["canonical_events"]
        .as_array()
        .context("native canonical originals")?;
    let ledger = originals["idempotency_keys"]
        .as_array()
        .context("native original retry rows")?;
    for (request, outcome) in [
        (&add_request, &add_outcome),
        (&update_request, &update_outcome),
    ] {
        let key = request.idempotency_key.as_uuid().to_string();
        let rows = ledger
            .iter()
            .filter(|row| {
                row["idempotency_key"] == key
                    && row["operation_id"] == "ak.self.events.command.submit.v1"
            })
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1,
            "native Circle complete unit has no unique original retry row"
        );
        let events = canonical
            .iter()
            .filter(|row| row["envelope"]["event_id"] == request.commit_event.event_id.as_str())
            .collect::<Vec<_>>();
        ensure!(
            events.len() == 1 && events[0]["state"] == "committed",
            "native Circle Commit has no unique committed source Event"
        );
        let expected_hash = arkret_canonical::sha256_digest(&arkret_canonical::canonical_json_bytes(&arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::MlsCommit(request.clone()))?);
        ensure!(
            rows[0]["source_event_pk"] == events[0]["pk"]
                && rows[0]["request_hash"] == expected_hash
                && rows[0]["response_status"] == 200
                && rows[0]["response_body"] == serde_json::to_value(outcome)?,
            "native Circle retry did not retain its exact source/hash/original authority outcome"
        );
    }
    let welcome_rows = originals["mls_welcome_deliveries"]
        .as_array()
        .context("actual Welcome source")?
        .iter()
        .filter(|row| row["welcome_id"] == welcome.welcome_id.as_str())
        .collect::<Vec<_>>();
    let binding_rows = originals["keypackage_claim_welcome_bindings"]
        .as_array()
        .context("actual Welcome claim binding")?
        .iter()
        .filter(|row| row["welcome_id"] == welcome.welcome_id.as_str())
        .collect::<Vec<_>>();
    ensure!(
        welcome_rows.len() == 1
            && welcome_rows[0]["delivery_json"] == serde_json::to_value(&welcome)?
            && binding_rows.len() == 1
            && binding_rows[0]["claim_id"] == claim.claims[0].claim_id
            && binding_rows[0]["commit_event_ref"] == add_event.event_id.as_str(),
        "native Circle source lacks its one exact original Welcome and claimed Add"
    );
    let mut changed_body = add_request.clone();
    changed_body.welcomes.clear();
    let changed_body = refused(
        &alice,
        station,
        &realm,
        &path,
        &changed_body,
        arkret_wire::ErrorCode::DuplicateConflict,
    )
    .await?;
    let mut changed_key = add_request.clone();
    changed_key.idempotency_key = arkret_wire::UuidV7::new(uuid::Uuid::now_v7())?;
    let changed_key = refused(
        &alice,
        station,
        &realm,
        &path,
        &changed_key,
        arkret_wire::ErrorCode::DuplicateConflict,
    )
    .await?;
    let other_circle = crate::scenarios::circle_poll_scope_live::circle_create(
        &alice.client,
        realm.as_str(),
        &alice.actor,
        "Other accepted Circle",
        "Other",
    )
    .await?;
    let wrong_path = refused(
        &alice,
        station,
        &realm,
        &format!("/_arkret/self/circles/{other_circle}/scope-rotate"),
        &add_request,
        arkret_wire::ErrorCode::SchemaViolation,
    )
    .await?;
    let (same_queue, _) = mls::recipient_welcomes(&bob.client).await?;
    ensure!(
        same_queue == queued,
        "Circle replay or refusal requeued its Welcome"
    );

    let plaintext =
        arkret::ContentBlock::text("Only the actual rotated Circle epoch decrypts this original");
    let original = scoped_event(
        &alice,
        &scope,
        EventKind::MessageCreate,
        json!({"strand_id":strand_id,"track_name":"discussion","content":plaintext}),
    )
    .await?;
    let (message, encrypted) = crate::harness::content::seal_device_message(
        &alice.client,
        &mut sender,
        &update_event.event_id,
        original,
    )
    .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &alice.client,
        &alice.account,
        alice.device.as_str(),
        &message,
    )
    .await?;
    let message_committed = mls::accepted_full_view(&bob.client, &message.event_id).await?;
    let envelope = encrypted.to_envelope()?;
    ensure!(
        message_committed.event == message
            && message.payload.get("encrypted_content") == Some(&serde_json::to_value(&envelope)?),
        "native read changed the actual epoch-two ciphertext"
    );
    let old_before = serde_json::to_vec(&old_receiver.export_state_record()?)?;
    ensure!(
        old_receiver.decrypt_payload(&encrypted).is_err(),
        "epoch-one private state opened the new Circle payload"
    );
    let old_after = serde_json::to_vec(&old_receiver.export_state_record()?)?;
    ensure!(
        old_before == old_after && std::fs::read(checkpoint.path())? == old_bytes,
        "failed old-epoch decrypt changed private or durable state"
    );
    let recipient_update = mls::accepted_full_view(&bob.client, &update_event.event_id).await?;
    ensure!(
        recipient_update == update_committed
            && old_receiver.install_accepted_commit(&recipient_update, &after_add)? == 2,
        "recipient could not install the exact accepted Circle update"
    );
    crate::scenarios::message_mls_cross_station_live::install_bindings(
        &mut old_receiver,
        &[&alice, &bob],
    )
    .await?;
    let opened = old_receiver.decrypt_payload(&encrypted)?;
    ensure!(
        opened == arkret_canonical::canonical_json_bytes(&plaintext)?,
        "actual rotated Circle private state did not open the original ciphertext"
    );
    let final_current = current(station, &scope).await?;
    ensure!(
        final_current == after_update && current(station, &parent_scope).await? == parent_current,
        "Message processing or exact retry changed independent MLS current"
    );
    let circle_read = expect_json(
        alice.client.get(&format!("/_arkret/self/circles/{circle}")),
        reqwest::StatusCode::OK,
    )
    .await?;
    let read_view: arkret_models_collaboration::governance::circle::CircleReadView =
        serde_json::from_value(circle_read.clone())?;
    let arkret_models_collaboration::governance::circle::CircleReadView::Full(read_view) =
        read_view
    else {
        anyhow::bail!("accepted Circle member received only a preview")
    };
    ensure!(
        read_view.circle_id == circle
            && read_view.realm_id == realm
            && read_view.mls_group_id.as_deref() == Some(group_id.as_str()),
        "native Circle view borrowed another group's MLS identity"
    );
    let (final_queue, _) = mls::recipient_welcomes(&bob.client).await?;
    ensure!(
        final_queue == queued,
        "zero-Welcome rotation or Message produced another Welcome"
    );
    bob.client
        .post("/_arkret/self/device-messages/ack")
        .json(&DeviceMessagesAcknowledgementRequestBody {
            acknowledgement_token: ack,
        })
        .send()
        .await?
        .error_for_status()?;
    Ok(
        json!({"realm_id":realm,"circle_id":circle,"scope_ref":scope,"group_id":group_id,"realm_genesis":realm_genesis,"parent_genesis":parent_genesis,"circle_creation":circle_create,"circle_genesis":circle_genesis,"strand":strand_view,"claim_request":claim_request,"claim":claim,"parent_current":parent_current,"before":base,"after_add":after_add,"after_update":after_update,"final_current":final_current,"circle_read":circle_read,"add_request":add_request,"add_request_base64url":arkret_canonical::base64url_encode(&add_bytes),"add_outcome":add_outcome,"add_response_base64url":arkret_canonical::base64url_encode(&add_raw),"add_committed":add_committed,"welcome":welcome,"recipient_commit":recipient_commit,"queue":queued,"update_request":update_request,"update_request_base64url":arkret_canonical::base64url_encode(&update_bytes),"update_outcome":update_outcome,"update_response_base64url":arkret_canonical::base64url_encode(&update_raw),"update_committed":update_committed,"recipient_update":recipient_update,"add_retry":add_retry,"update_retry":update_retry,"originals":originals,"changed_body":changed_body,"changed_key":changed_key,"wrong_path":wrong_path,"message_committed":message_committed,"encrypted":encrypted,"opened_base64url":arkret_canonical::base64url_encode(&opened),"expected_plaintext_base64url":arkret_canonical::base64url_encode(&arkret_canonical::canonical_json_bytes(&plaintext)?),"old_state_before_digest":arkret_canonical::sha256_digest(&old_before),"old_state_after_digest":arkret_canonical::sha256_digest(&old_after),"old_checkpoint_digest":arkret_canonical::sha256_digest(&old_bytes),"old_checkpoint_after_digest":arkret_canonical::sha256_digest(&std::fs::read(checkpoint.path())?),"processes":[deployment.coauth.server.native_process_identity()?,station.native_process_identity()?]}),
    )
}

pub(super) async fn run() -> Result<()> {
    let (result, observations) = observe(crate::harness::heap_future(scenario)).await;
    retain_attempt("circle-rotation", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let claim: KeyPackagesClaimResponseBody = serde_json::from_value(artifact["claim"].clone())?;
    verify_native_station_keypackage_signature(
        &observations,
        &claim.claim_receipt.signature,
        claim.claim_receipt.claimed_at,
        &arkret_models_crypto::peer_keypackage_claim_receipt_signing_bytes(&claim.claim_receipt)?,
    )?;
    let views = [
        "realm_genesis",
        "parent_genesis",
        "circle_creation",
        "circle_genesis",
        "strand",
        "add_committed",
        "update_committed",
        "message_committed",
    ]
    .into_iter()
    .map(|name| serde_json::from_value(artifact[name].clone()))
    .collect::<std::result::Result<Vec<CommittedEventFullView>, _>>()?;
    verify_native_station_commits(&observations, &views)?;
    for view in &views {
        ensure!(
            view.commit.governance_generation == 0
                && view.commit.authority_ref
                    == arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                        views[0].event.event_id.clone()
                    ),
            "Circle native original changed its actual Realm governor"
        );
    }
    artifact["case"] = json!("circle_rotation");
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("circle-rotation.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    println!("native operation contract passed: {}", SCOPE[0]);
    Ok(())
}
