//! Native peer reads bind actual membership, current disclosure and device custody.
use arkret_models_collaboration::governance::realm_join_intake::*;
use arkret_models_crypto::*;
use arkret_wire::{EventKind, RealmId};

use super::*;
use crate::harness::ArkretServer;
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

const SCOPE: [&str; 3] = [
    "ak.peer.realm_join.read.bootstrap.v1",
    "ak.peer.realm_join.read.preview.v1",
    "ak.peer.keys.read.lookup.v1",
];

async fn peer(station: &ArkretServer, path: &str, body: &impl serde::Serialize) -> Result<Value> {
    let bytes = arkret_canonical::canonical_json_bytes(body)?;
    let request = station.signed_peer_post_request_with_idempotency_key(
        station,
        path,
        &bytes,
        station.service_id(),
        None,
    )?;
    let original = request.try_clone().context("buffered native peer read")?;
    let response = station.http().execute(request).await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    cotest_test_support::operation_observation::record_response(
        Some(&original),
        status.as_u16(),
        &bytes,
    )?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "native peer {path}: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) async fn exercise(
    station: &ArkretServer,
    alice: &Member,
    bob: &Member,
    realm: &RealmId,
    membership: &arkret_wire::CommittedEventFullView,
) -> Result<Value> {
    use arkret_models_collaboration::events_payloads::preview::{
        PreviewPolicyPayload, PreviewPolicyPayloadValue,
    };
    let policy = PreviewPolicyPayload {
        value: PreviewPolicyPayloadValue {
            mode: "directory_card".into(),
            audiences: vec!["realm_member".into()],
            fields: vec!["title".into(), "join_rule".into(), "history_access".into()],
            history: None,
            token: None,
        },
        reason: None,
    };
    let event = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::RealmPreviewPolicy.as_str(),
            serde_json::to_value(policy)?,
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &alice.client,
        &alice.account,
        alice.device.as_str(),
        &event,
    )
    .await?;
    let accepted_policy = mls::accepted_full_view(&alice.client, &event.event_id).await?;
    let preview_request = PeerRealmJoinPreviewRequestBody {
        request_id: arkret_wire::RequestId::new(arkret_identifiers::new_prefixed_uuid7(
            "ak:request:",
        ))?,
        realm_id: realm.clone(),
        requester_account_id: bob.account.clone(),
        invite_id: None,

        realm_invite_link_id: None,
        link_proof: None,
    };
    let preview = peer(
        station,
        "/_arkret/peer/realm-joins/preview",
        &preview_request,
    )
    .await?;
    let shown: PeerRealmJoinPreviewResponseBody = serde_json::from_value(preview.clone())?;
    shown.validate_for_request(&preview_request)?;
    let bootstrap_request = PeerRealmJoinBootstrapRequestBody {
        request_id: arkret_wire::RequestId::new(arkret_identifiers::new_prefixed_uuid7(
            "ak:request:",
        ))?,
        realm_id: realm.clone(),
        member_account_id: bob.account.clone(),
        membership_commit_id: membership.commit.commit_id.clone(),
        history_stream_ref: None,
    };
    let bootstrap = peer(
        station,
        "/_arkret/peer/realm-joins/bootstrap",
        &bootstrap_request,
    )
    .await?;
    let bootstrap_received_at = chrono::Utc::now();
    let answer: PeerRealmJoinBootstrapResponseBody = serde_json::from_value(bootstrap.clone())?;
    ensure!(
        answer.request_id == bootstrap_request.request_id
            && answer.snapshot.realm_id == *realm
            && !answer.visible_stream_heads.is_empty(),
        "bootstrap lost its admitted member or actual stream heads"
    );
    let request = PeerKeysQueryRequestBody {
        request_id: arkret_wire::RequestId::new(arkret_identifiers::new_prefixed_uuid7(
            "ak:request:",
        ))?,
        requester_account_id: Some(alice.account.clone()),
        requester_actor_id: None,
        purpose: PeerKeysQueryPurpose::MlsGroupAdmission,
        relationship_basis: PeerKeysRelationshipBasis::RealmMembership {
            realm_id: realm.clone(),
        },
        device_keys: vec![QueryAccountDeviceSelector {
            account_id: bob.account.clone(),
            device_ids: vec![bob.device.clone()],
        }],
    };
    request.validate()?;
    let keys = peer(station, "/_arkret/peer/keys/query", &request).await?;
    let response: PeerKeysQueryResponseBody = serde_json::from_value(keys.clone())?;
    response.validate_for_request(&request)?;
    ensure!(
        response.failures.is_empty()
            && response.device_keys.len() == 1
            && response.device_generations.len() == 1,
        "peer device read did not disclose the actual selected accepted device"
    );
    let row = response.device_keys[0]
        .device_keys
        .get(&bob.device)
        .context("actual selected device absent")?;
    row.validate_attestation_binding(&bob.account, &bob.device)?;
    let generation = &response.device_generations[0];
    ensure!(
        generation.account_id == bob.account
            && row.is_usable_in_generation(Some(&generation.generation_state)),
        "peer read changed the actual authorization generation"
    );
    Ok(
        json!({"preview_policy":accepted_policy,"preview_request":preview_request,"preview":preview,"bootstrap_request":bootstrap_request,"bootstrap":bootstrap,"bootstrap_received_at":bootstrap_received_at,"keys_request":request,"keys":keys,"expected_device_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(&bob.key.verifying_key().to_bytes()),"member_account_id":bob.account,"member_device_id":bob.device,"membership":membership,"member_authorize_event_id":bob.authorize_event_id}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, artifact: &Value) -> Result<()> {
    let bootstrap: PeerRealmJoinBootstrapResponseBody =
        serde_json::from_value(artifact["bootstrap"].clone())?;
    let request: PeerRealmJoinBootstrapRequestBody =
        serde_json::from_value(artifact["bootstrap_request"].clone())?;
    let membership: arkret_wire::CommittedEventFullView =
        serde_json::from_value(artifact["membership"].clone())?;
    let policy: arkret_wire::CommittedEventFullView =
        serde_json::from_value(artifact["preview_policy"].clone())?;
    verify_native_station_commits(observations, &[membership.clone(), policy])?;
    let bundle = &bootstrap.authority_bundle;
    let at = bundle.current_assertion.signature.created_at;
    let nonce = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
        arkret_canonical::sha256_bytes(request.request_id.as_str().as_bytes()),
    ))
    .map_err(anyhow::Error::msg)?;
    let authority_request = arkret_wire::RealmAuthorityBundleRequestBody {
        realm_id: request.realm_id.clone(),
        nonce: nonce.clone(),
    };
    // The nonce-bound bundle precedes snapshot creation. Freshness uses the
    // actual local receive cut, never an earlier remote signature timestamp.
    let received_at = serde_json::from_value(artifact["bootstrap_received_at"].clone())?;
    bundle.validate_for_request(&authority_request, received_at)?;
    ensure!(
        bundle.current_generation == 0
            && bundle.authority_transitions.is_empty()
            && bundle.genesis_event.realm_id == request.realm_id
            && membership.commit.commit_id == request.membership_commit_id,
        "native member bootstrap substituted its actual authority closure"
    );
    let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
    for (method, signed_at) in [
        (
            &bundle.genesis_commit.signature.verification_method,
            bundle.genesis_commit.signature.created_at,
        ),
        (&bundle.current_assertion.signature.verification_method, at),
        (
            &bootstrap.snapshot.signature.verification_method,
            bootstrap.snapshot.signature.created_at,
        ),
    ] {
        keys.insert_at(
            method,
            signed_at,
            native_station_key(observations, method, signed_at)?,
        );
    }
    let freshness = arkret_identity::RealmAuthorityFreshness::new(received_at, nonce);
    let mut replica = garth::RealmReplica::new(request.realm_id.clone());
    replica.install_verified_authority(&authority_request, bundle.clone(), &freshness, &keys)?;
    replica.install_verified_current_snapshot_heads(&bootstrap.snapshot, &freshness, &keys)?;
    ensure!(
        bootstrap
            .snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == membership.commit.stream_ref
                && head.stream_position >= membership.commit.stream_position),
        "native bootstrap excludes the membership cut"
    );
    let response: PeerKeysQueryResponseBody = serde_json::from_value(artifact["keys"].clone())?;
    let query: PeerKeysQueryRequestBody = serde_json::from_value(artifact["keys_request"].clone())?;
    response.validate_for_request(&query)?;
    for account in &response.device_keys {
        for (device, row) in &account.device_keys {
            row.validate_attestation_binding(&account.account_id, device)?;
            ensure!(
                row.device_projection_attestation
                    .attestation
                    .device_signing_key_did
                    .as_str()
                    == format!(
                        "did:key:{}",
                        artifact["expected_device_key"]
                            .as_str()
                            .context("actual device public key")?
                    )
                    && row
                        .device_projection_attestation
                        .attestation
                        .device_authorize_event_id
                        .as_str()
                        == artifact["member_authorize_event_id"]
                            .as_str()
                            .context("actual founding Device authorize Event")?,
                "peer response changed the actual admitted Device key or original authorization"
            );
            let attestation = &row.device_projection_attestation;
            let key = native_station_key(
                observations,
                &attestation.proof.verification_method,
                attestation.proof.created_at,
            )?;
            arkret_signatures::device_projection::verify_device_projection_attestation(
                attestation,
                &ed25519_dalek::VerifyingKey::from_bytes(&key.ed25519_bytes()?)?,
                attestation.proof.created_at,
            )?;
        }
    }
    for exchange in &observations.exchanges {
        if SCOPE.contains(&exchange.operation_id.as_str()) {
            verify_native_station_http_request(observations, exchange, &[])?;
        }
    }
    Ok(())
}
