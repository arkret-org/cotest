//! Real C peer lookup and A self submission, before/after the native Gov handoff.
//! AA introspection is the enclosing fixture's explicit mock; Human PCR,
//! Device, peer HTTP, C's signed observation and Gov Commit are actual SUTs.
use std::time::{Duration, Instant};

use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_models_crypto::realm_owner_transfer::{
    RealmOwnerTransferAcceptance, RealmOwnerTransferAcceptanceIntent, RealmOwnerTransferPatch,
    RealmOwnerTransferUnsignedPayload,
};
use arkret_models_crypto::{
    PeerKeysQueryPurpose, PeerKeysQueryRequestBody, PeerKeysQueryResponseBody,
    PeerKeysRelationshipBasis, QueryAccountDeviceSelector,
};
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_signatures::realm_owner_transfer::sign_realm_owner_transfer_acceptance;
use arkret_wire::{
    AccountId, Base64UrlString, CurrentSelector, CurrentState, DidCoreId, DidUrl, Hash,
    RealmAuthorityRootValue, RequestId, ScopeRef,
};
use coland_storage::AuthorityCommitStore as _;
use coland_storage_postgres::{Db, PgAuthorityCommitStore, PoolTuning};
use serde_json::{Value, json};

use super::*;
use crate::harness::{ArkretServer, CanonicalJsonBody as _};
use crate::scenarios::peer_semantic_union_live::realm_business_footprint;

fn now() -> chrono::DateTime<chrono::Utc> {
    arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
}

fn account(client: &TestActorClient) -> Result<AccountId> {
    Ok(AccountId::new(
        client
            .principal
            .as_ref()
            .context("actual Human principal")?
            .core_id
            .clone(),
        client.service_id().parse()?,
    ))
}

async fn root(
    client: &TestActorClient,
    governor: &DidCoreId,
    realm: &RealmId,
    minimum: Option<&RealmCommit>,
) -> Result<RealmAuthorityRootValue> {
    let http = client.sdk();
    let source = http
        .own_station_result_client()?
        .context("bound own-Station session")?;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let response = match source.snapshot_head(realm).await {
            Ok(response) => response,
            Err(arkret_http_client::Error::Api { status: 503, .. })
                if Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let snapshot = response.value()?;
        snapshot.require_full_recovery()?;
        let signer = arkret_identity::verification_method_did(
            snapshot.signature.verification_method.as_str(),
        )?;
        let reached = arkret_wire::project_did_to_core_id(&signer)? == *governor
            && minimum.is_none_or(|commit| {
                snapshot.visible_stream_heads.iter().any(|head| {
                    head.stream_ref == commit.stream_ref
                        && (head.stream_position > commit.stream_position
                            || head.stream_position == commit.stream_position
                                && head.commit_id == commit.commit_id)
                })
            });
        if !reached {
            ensure!(
                Instant::now() < deadline,
                "own Station did not reach the actual Gov cut"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        // Verify the real Gov's original signature, even when this response is
        // delivered by A. describe(A) must never be substituted for Gov G.
        let resolution = http.open_service_resolution(governor).await?;
        let document = arkret_identity::authenticated_service_document_at(
            &resolution,
            governor,
            snapshot.signature.created_at,
        )?;
        arkret_identity::validate_verification_method_relationship(
            &document,
            &snapshot.signature.verification_method,
            &signer,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )?;
        let key = arkret_identity::resolve_verification_method_key_from_document(
            &document,
            snapshot.signature.verification_method.as_str(),
        )?
        .public_key;
        arkret_signatures::detached_object::verify_detached_object_signature(
            &snapshot.signature,
            &arkret_canonical::unsigned_value(snapshot, &["signature"])?,
            arkret_wire::DetachedSignatureContext::RealmSnapshot,
            &key,
        )?;
        let values: Vec<_> = snapshot
            .current_state_entries
            .iter()
            .filter_map(|entry| {
                let CurrentState::Value {
                    selector, value, ..
                } = entry;
                matches!(selector, CurrentSelector::RealmAuthorityRoot).then_some(value)
            })
            .collect();
        ensure!(
            values.len() == 1,
            "whole Snapshot has no unique authority root"
        );
        let value = values[0];
        ensure!(
            value["authority_generation"].is_string(),
            "root uses a noncanonical generation"
        );
        let root: RealmAuthorityRootValue = serde_json::from_value(value.clone())?;
        root.validate()?;
        ensure!(
            arkret_canonical::canonical_json_bytes(value)?
                == arkret_canonical::canonical_json_bytes(&root)?,
            "root was reconstructed or normalized instead of using the actual complete row"
        );
        source.check_session()?;
        return Ok(root);
    }
}

fn consent(
    author: &TestActorClient,
    successor: &TestActorClient,
    realm: &RealmId,
    digest: Hash,
) -> Result<RealmOwnerTransferAcceptance> {
    let principal = successor
        .principal
        .as_ref()
        .context("successor founding Device")?;
    ensure!(
        principal.device_id.as_str() == successor.device_id,
        "Device custody differs"
    );
    let intent = RealmOwnerTransferAcceptanceIntent {
        scope_ref: ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        actor_id: ActorId::account(account(author)?),
        payload_without_successor_acceptance: RealmOwnerTransferUnsignedPayload {
            realm_id: realm.clone(),
            expected_state_digest: digest,
            patch: RealmOwnerTransferPatch {
                controller_actor_id: ActorId::account(account(successor)?),
            },
        },
    };
    let acceptance = sign_realm_owner_transfer_acceptance(
        &intent,
        DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?,
        now(),
        &principal.device_signing_key,
    )?;
    let component = RealmOwnerTransferAcceptance { intent, acceptance };
    component.validate()?;
    Ok(component)
}

fn query(component: &RealmOwnerTransferAcceptance) -> Result<PeerKeysQueryRequestBody> {
    Ok(PeerKeysQueryRequestBody {
        request_id: RequestId::new_v7_at(now().timestamp_millis() as u64),
        requester_account_id: Some(
            component
                .intent
                .actor_id
                .as_account_id()
                .context("author Account")?
                .clone(),
        ),
        requester_actor_id: None,
        purpose: PeerKeysQueryPurpose::RealmOwnerTransferAcceptance,
        relationship_basis: PeerKeysRelationshipBasis::RealmMembership {
            realm_id: component
                .intent
                .payload_without_successor_acceptance
                .realm_id
                .clone(),
        },
        device_keys: vec![QueryAccountDeviceSelector {
            account_id: component.intent.successor_account()?.clone(),
            device_ids: vec![component.intent.successor_device(&component.acceptance)?],
        }],
        owner_transfer_acceptance: Some(component.clone()),
    })
}

async fn peer(
    source: &ArkretServer,
    c: &ArkretServer,
    body: &Value,
) -> Result<(StatusCode, Vec<u8>)> {
    c.signed_peer_post(
        source,
        "/_arkret/peer/keys/query",
        &arkret_canonical::canonical_json_bytes(body)?,
        c.service_id(),
    )
    .await
}

async fn witness(
    a: &ArkretServer,
    c: &ArkretServer,
    author: &TestActorClient,
    successor: &TestActorClient,
    component: &RealmOwnerTransferAcceptance,
) -> Result<AccountDeviceSignerEvidence> {
    let request = query(component)?;
    request.validate()?;
    let (status, bytes) = peer(a, c, &serde_json::to_value(&request)?).await?;
    ensure!(
        status == StatusCode::OK,
        "C peer lookup failed: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    let answer: PeerKeysQueryResponseBody = serde_json::from_slice(&bytes)?;
    answer.validate_for_request(&request)?;
    ensure!(
        answer.failures.is_empty() && answer.device_keys.len() == 1,
        "C omitted actual successor"
    );
    let device = component.intent.successor_device(&component.acceptance)?;
    let row = answer.device_keys[0]
        .device_keys
        .get(&device)
        .context("C's exact Device row")?;
    let successor_account = component.intent.successor_account()?;
    let generation = answer
        .device_generations
        .iter()
        .find(|entry| entry.account_id == *successor_account)
        .map(|entry| &entry.generation_state);
    ensure!(
        row.is_usable_in_generation(generation),
        "C returned a fenced or noncurrent Device generation"
    );
    ensure!(
        row.algorithms.is_empty(),
        "finite consent disclosed prekeys"
    );
    // This independently fetched, method-native history verifies C's original
    // core/signature; do not turn C's opaque row address into A's wrapper ref.
    let evidence = AccountDeviceSignerEvidence {
        device_projection_attestation: row.device_projection_attestation.clone(),
        service_resolution: author.sdk().open_service_resolution(c.service_id()).await?,
    };
    arkret_identity::account_device_signer_evidence::verify_owner_transfer_successor_evidence(
        &evidence,
        &component.intent,
        &component.acceptance,
        now(),
    )?;
    let core = &evidence.device_projection_attestation.attestation;
    ensure!(
        core.expires_at > core.attested_at
            && core.expires_at <= core.attested_at + chrono::Duration::seconds(30)
            && core.owner_transfer_acceptance_intent_digest == Some(component.intent.digest()?),
        "C observation is not the finite exact intent"
    );
    let principal = successor
        .principal
        .as_ref()
        .context("actual accepted Device")?;
    ensure!(
        core.account_id == account(successor)?
            && core.device_id == principal.device_id
            && core.device_authorize_event_id == principal.founding_authorize_event_id,
        "C substituted the successor's native source"
    );
    let original = successor
        .sdk()
        .committed_event_get(&principal.founding_authorize_event_id)
        .await?;
    let CommittedEventView::Full(original) = original else {
        bail!("successor's own native authorization was not full")
    };
    ensure!(
        original.event.kind == EventKind::DeviceAuthorize
            && original.event.event_id == core.device_authorize_event_id
            && original.event.actor_id == ActorId::account(account(successor)?)
            && original.event.realm_id == principal.pcr_realm_id,
        "public native authorization lookup substituted its original"
    );
    let payload: DeviceAuthorizePayload = serde_json::from_value(json!(original.event.payload))?;
    ensure!(
        payload.device_id == core.device_id
            && payload.device_public_key_did.as_str() == core.device_signing_key_did.as_str()
            && payload.hpke_key == core.hpke_key
            && payload.authorized_generation_ref == core.authorized_generation_ref
            && payload.not_before == core.authorization_window.not_before
            && payload.expires_at.flatten() == core.authorization_window.expires_at,
        "C projection changed the exact raw accepted Device material/window"
    );
    let mut algorithms = payload.algorithms;
    algorithms.sort_by(|a, b| a.as_str().as_bytes().cmp(b.as_str().as_bytes()));
    algorithms.dedup_by(|a, b| a.as_str() == b.as_str());
    ensure!(
        row.trust_algorithms == algorithms,
        "C erased or invented public native trust algorithms"
    );
    Ok(evidence)
}

async fn rejected_queries(
    a: &ArkretServer,
    c: &ArkretServer,
    component: &RealmOwnerTransferAcceptance,
) -> Result<()> {
    let original = serde_json::to_value(query(component)?)?;
    let mut cases = Vec::new();
    let mut bad = original.clone();
    bad["owner_transfer_acceptance"]["acceptance"]["signature"] = json!(
        Base64UrlString::new(arkret_canonical::base64url_encode([0u8; 64]))
            .map_err(anyhow::Error::msg)?
    );
    cases.push(("invalid B signature", bad));
    let mut bad = original.clone();
    bad["owner_transfer_acceptance"]["intent"]["payload_without_successor_acceptance"]["expected_state_digest"] =
        json!(format!("sha256:{}", "f".repeat(64)));
    cases.push(("tampered B transcript", bad));
    let mut bad = original.clone();
    bad["relationship_basis"] = json!(PeerKeysRelationshipBasis::Contact {});
    cases.push(("Contact has no finite consent purpose", bad));
    let mut bad = original.clone();
    bad["purpose"] = json!(PeerKeysQueryPurpose::MlsGroupAdmission);
    cases.push(("ordinary purpose smuggles finite consent", bad));
    let mut bad = original.clone();
    bad.as_object_mut()
        .context("request object")?
        .remove("owner_transfer_acceptance");
    cases.push(("new purpose lacks B acceptance", bad));
    let mut bad = original.clone();
    bad["requester_account_id"]["station_id"] = json!(c.service_id());
    cases.push(("Source-Service differs from requester Station", bad));
    let mut bad = original.clone();
    let mut extra = original["device_keys"][0].clone();
    extra["account_id"]["principal_id"] = json!(
        component
            .intent
            .actor_id
            .as_account_id()
            .context("author Account")?
            .principal_id
    );
    bad["device_keys"]
        .as_array_mut()
        .context("selectors")?
        .push(extra);
    cases.push(("more than one selector", bad));
    let mut bad = original;
    bad["device_keys"][0]["device_ids"]
        .as_array_mut()
        .context("Devices")?
        .push(json!(ALICE_DEVICE));
    cases.push(("more than one Device", bad));
    for (label, mut body) in cases {
        body["request_id"] = json!(RequestId::new_v7_at(now().timestamp_millis() as u64));
        let (status, bytes) = peer(a, c, &body).await?;
        if status == StatusCode::OK {
            let answer: PeerKeysQueryResponseBody = serde_json::from_slice(&bytes)?;
            ensure!(
                answer.device_keys.is_empty(),
                "{label} disclosed a signed C row"
            );
        } else {
            ensure!(
                status.is_client_error(),
                "{label} failed for a server/transport reason: {status} {}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }
    Ok(())
}

async fn event(
    author: &TestActorClient,
    component: &RealmOwnerTransferAcceptance,
) -> Result<Event> {
    let mut payload = serde_json::to_value(&component.intent.payload_without_successor_acceptance)?;
    payload["successor_acceptance"] = serde_json::to_value(&component.acceptance)?;
    author
        .author_event(
            component
                .intent
                .payload_without_successor_acceptance
                .realm_id
                .as_str(),
            EventKind::RealmOwnerTransfer.as_str(),
            payload,
        )
        .await
}

async fn stored_witness(database: &str, event: &Event) -> Result<AccountDeviceSignerEvidence> {
    let database = database.to_owned();
    let id = event.event_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let value: Value = db.query_one(
            "SELECT successor_device_evidence_json FROM canonical_events WHERE envelope->>'event_id'=$1 AND state='committed'", &[&id],
        )?.get(0);
        Ok(serde_json::from_value(value)?)
    }).await?
}

pub(super) async fn run(
    group: &mut TestServerGroup,
    author: &TestActorClient,
    successor: &TestActorClient,
    realm: &str,
    governor_index: usize,
    governor_database: &str,
) -> Result<()> {
    let a = group.server(1);
    let c = group.server(0);
    let governor = group.server(governor_index).service_id().clone();
    let a_id = a.service_id().clone();
    let c_id = c.service_id().clone();
    ensure!(
        a_id != c_id && (governor_index == 1 || governor != a_id && governor != c_id),
        "Owner topology does not have the claimed independent Stations"
    );
    ensure!(
        account(author)?.station_id == a_id && account(successor)?.station_id == c_id,
        "native Accounts have another own Station"
    );
    let realm_id: RealmId = realm.parse()?;
    let previous = root(author, &governor, &realm_id, None).await?;
    ensure!(
        previous.controller_actor_id == ActorId::account(account(author)?),
        "A is not actual root"
    );
    let component = consent(
        author,
        successor,
        &realm_id,
        Hash::new(arkret_canonical::canonical_sha256(&previous)?)?,
    )?;
    witness(a, c, author, successor, &component).await?;
    let before = realm_business_footprint(governor_database, realm).await?;
    rejected_queries(a, c, &component).await?;
    ensure!(
        realm_business_footprint(governor_database, realm).await? == before,
        "C peer rejection changed Gov business state"
    );

    // A/B legitimately sign the wrong current digest. C can authenticate this
    // consent, while only the real Gov can reject its stale root precondition.
    let wrong = consent(
        author,
        successor,
        &realm_id,
        Hash::new(format!("sha256:{}", "0".repeat(64)))?,
    )?;
    witness(a, c, author, successor, &wrong).await?;
    let refused = event(author, &wrong).await?;
    let submission = crate::publication::initial_submission(refused.clone(), "")?;
    let response = author
        .post("/_arkret/self/events")
        .canonical_json(&submission)?
        .send()
        .await?;
    let status = response.status();
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        status.as_u16() == arkret_wire::ErrorCode::FailedPrecondition.http_status()
            && problem.error_code() == Some(arkret_wire::ErrorCode::FailedPrecondition),
        "wrong root did not reach the registered Gov precondition: {status} {problem:?}"
    );
    ensure!(
        realm_business_footprint(governor_database, realm).await? == before,
        "refused root transfer produced durable business effects"
    );

    // Start this separate first-admission operation with one fresh B signature;
    // do not age it while the preceding negative network matrix is executing.
    // Once authored, the Event and this exact inner proof stay immutable.
    let component = consent(
        author,
        successor,
        &realm_id,
        Hash::new(arkret_canonical::canonical_sha256(&previous)?)?,
    )?;
    let accepted = event(author, &component).await?;
    let commit =
        submit_and_expect_commit(author, &account(author)?, &author.device_id, &accepted).await?;
    ensure!(
        commit.governance_generation == u64::from(governor_index == 2),
        "wrong accepting tenure"
    );
    let after = root(author, &governor, &realm_id, Some(&commit)).await?;
    ensure!(
        after.controller_actor_id == ActorId::account(account(successor)?)
            && after.controller_epoch
                == previous
                    .controller_epoch
                    .checked_add(1)
                    .context("epoch overflow")?
            && after.authority_generation == previous.authority_generation,
        "actual Gov did not make the exact root transition"
    );
    let retained = stored_witness(governor_database, &accepted).await?;
    arkret_identity::account_device_signer_evidence::verify_owner_transfer_successor_evidence(
        &retained,
        &component.intent,
        &component.acceptance,
        commit.committed_at,
    )?;
    let c_method = arkret_identity::verification_method_did(
        retained
            .device_projection_attestation
            .proof
            .verification_method
            .as_str(),
    )?;
    ensure!(
        arkret_wire::project_did_to_core_id(&c_method)? == c_id,
        "Gov archived A/G evidence instead of C's original consent observation"
    );
    let db = Db::connect(Some(governor_database), PoolTuning::default()).await?;
    let store = PgAuthorityCommitStore {
        pool: db.pool.context("Gov database pool")?,
    };
    let full = store
        .committed_event(&accepted.event_id)
        .await?
        .context("Gov's full accepted original")?;
    let full = arkret_wire::CommittedEventFullView {
        event: full.event,
        commit: full.commit,
    };
    full.validate_shape()?;
    ensure!(
        full.commit == commit
            && arkret_canonical::canonical_json_bytes(&full.event)?
                == arkret_canonical::canonical_json_bytes(&accepted)?,
        "Gov rewrote the original A Event or B acceptance"
    );
    let fact = store
        .producer_signer_fact(&accepted, &commit)
        .await?
        .context("actual A producer fact")?;
    let a_fact = fact
        .as_account_device()
        .context("actual Human A producer")?;
    let a_principal = author
        .principal
        .as_ref()
        .context("A's actual founding Device")?;
    fact.validate_commit_binding(&full, arkret_canonical::DigestSuite::Sha256)?;
    ensure!(
        a_fact.actor == ActorId::account(account(author)?)
            && a_fact.device_id.as_str() == author.device_id
            && a_fact.key.authorization_ref.event_id == a_principal.founding_authorize_event_id
            && a_fact.key.authorization_ref.stream_ref.realm_id() == &a_principal.pcr_realm_id
            && a_fact.key.public_key_base64url.as_str()
                == arkret_canonical::base64url_encode(
                    a_principal.device_signing_key.verifying_key().as_bytes()
                )
            && Some(fact.digest()?) == commit.producer_signer_fact_digest,
        "B's consent replaced A's independent original producer source"
    );

    if governor_index == 2 {
        // Historical accepted replay must not acquire a second current W1.
        // Cross the actual signed deadline, then stop C's real process.
        let expiry = retained
            .device_projection_attestation
            .attestation
            .expires_at;
        while now() <= expiry {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        group.server_mut(0).stop_external_process().await?;
    }
    let replay =
        submit_and_expect_commit(author, &account(author)?, &author.device_id, &accepted).await?;
    ensure!(
        replay == commit,
        "exact self replay created a new Gov outcome"
    );
    ensure!(
        serde_json::to_value(stored_witness(governor_database, &accepted).await?)?
            == serde_json::to_value(&retained)?,
        "accepted replay replaced immutable W1"
    );
    println!(
        "[owner-transfer-peer] {}",
        json!({
            "aa_introspection":"explicit mock", "a":a_id, "c":c_id, "gov":governor,
            "actual_native_human_pcr":true, "peer_lookup":"standard RFC9421 + original C attestation + native history",
            "negative_queries":8, "wrong_root_zero_business_effects":true,
            "event":accepted.event_id, "commit":commit.commit_id, "root":after,
            "accepted_w1_expired_and_c_process_stopped":governor_index==2,
            "exact_replay_same_commit_and_w1":true,
        })
    );
    Ok(())
}
