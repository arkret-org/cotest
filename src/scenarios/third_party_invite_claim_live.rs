//! Production two-Station 3PID claim: external verifier signature plus historical subject root.
use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::membership_invite::{
    InviteClaimBindingProof, InviteClaimPayload, InviteSubjectProof, InviteSubjectProofBody,
    invite_binding_proof_transcript_bytes,
};
use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_wire::{EventKind, InviteId, RealmId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

use crate::harness::{CanonicalJsonBody, TestActorClient, TestServerGroup};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    database, ensure_same_commit, prepare_join, standard_client, station_env,
    submit_and_expect_commit, wait_for_committed,
};
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, test_principal_root_signing_authority,
};

const GROUP: &str = "third-party-invite-claim";
async fn submit_raw(
    client: &TestActorClient,
    event: &arkret_wire::Event,
) -> Result<(reqwest::StatusCode, Value)> {
    let response = client
        .post("/_arkret/self/events")
        .canonical_json(&crate::publication::initial_submission(event.clone(), "")?)?
        .send()
        .await?;
    let status = response.status();
    Ok((status, response.json().await.unwrap_or(Value::Null)))
}
async fn observation(url: &str, realm: &str) -> Result<(i64, i64, i64, i64)> {
    let url = url.to_owned();
    let realm = realm.to_owned();
    tokio::task::spawn_blocking(move||->Result<_>{
        let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
        let row=db.query_one("SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1),(SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1),(SELECT COUNT(*) FROM invite_lifecycle_current_results WHERE realm_id=$1 AND value='\"claimed\"'::jsonb),(SELECT COUNT(*) FROM member_state_current_results WHERE realm_id=$1 AND membership='join')",&[&realm])?;
        Ok((row.get(0),row.get(1),row.get(2),row.get(3)))
    }).await?
}

async fn replica_observation(url: &str, realm: &str) -> Result<(i64, i64, i64, i64, i64, i64)> {
    let url = url.to_owned();
    let realm = realm.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        let row = db.query_one("SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1 AND state='accepted'),(SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1),(SELECT COUNT(*) FROM invite_lifecycle_current_results WHERE realm_id=$1 AND value='\"claimed\"'::jsonb),(SELECT COUNT(*) FROM member_state_current_results WHERE realm_id=$1 AND membership='join'),(SELECT COUNT(*) FROM replica_stream_anchors WHERE realm_id=$1),(SELECT COUNT(*) FROM replica_authorization_cuts WHERE realm_id=$1)", &[&realm])?;
        Ok((row.get(0), row.get(1), row.get(2), row.get(3), row.get(4), row.get(5)))
    }).await?
}

pub async fn third_party_invite_claim_run() -> Result<()> {
    let Some(governance_db) = database(GROUP)? else {
        return Ok(());
    };
    let Some(subject_db) = database(GROUP)? else {
        return Ok(());
    };
    ensure!(
        governance_db.connect_url != subject_db.connect_url,
        "claim requires independent Station databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&governance_db.connect_url, &coauth),
            station_env(&subject_db.connect_url, &coauth),
        ],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let (alice, _) = standard_client(
        group.server(0),
        &coauth,
        "claim-alice",
        "ak:device:01904100-0000-7000-8000-000000002161",
    )
    .await?;
    let (bob, account) = standard_client(
        group.server(1),
        &coauth,
        "claim-bob",
        "ak:device:01904100-0000-7000-8000-000000002162",
    )
    .await?;
    let verifier = SigningKey::from_bytes(&[0x62; 32]);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(verifier.verifying_key().as_bytes());
    let verifier_did = arkret_wire::Did::new(format!("did:key:{multibase}"))?;
    let verifier_id = arkret_wire::project_did_to_core_id(&verifier_did)?;
    let verifier_method = arkret_wire::DidUrl::new(format!("{verifier_did}#{multibase}"))
        .map_err(|error| anyhow::anyhow!(error))?;
    let created=alice.create_realm_with(json!({"title":"3PID claim admission","public":false,"join_rule":"invite","allowed_third_party_invite_verification_ids":[verifier_id],"plaintext_visible_services":[group.server(0).service_id(),group.server(1).service_id()]})).await?;
    let realm = created["realm_id"]
        .as_str()
        .context("Realm create outcome lacks realm_id")?;
    let expires_at = arkret_canonical::format_timestamp_canonical(
        chrono::Utc::now() + chrono::TimeDelta::hours(1),
    );
    let material = json!({"oob_code_kind":"offline_token","token_commitment":format!("sha256:{}","a".repeat(64)),"token_salt_id":"cotest-2162-salt","token_entropy_bits":128,"max_claims":1,"verification_id":verifier_id,"verification_public_key":multibase});
    let create = alice
        .author_event(
            realm,
            EventKind::InviteThirdParty.as_str(),
            json!({"third_party_invite":material,"expires_at":expires_at}),
        )
        .await?;
    let alice_account = create
        .actor_id
        .as_account_id()
        .context("create actor is an Account")?;
    submit_and_expect_commit(&alice, alice_account, &alice.device_id, &create).await?;
    let invite_id = InviteId::from_event_id(&create.event_id);
    prepare_join(
        &bob,
        realm,
        group.server(0),
        "ak:request:019b0000-0000-7000-8000-000000002162",
        RealmJoinIntent::InviteAccept {
            invite_id: invite_id.clone(),
        },
    )
    .await?;
    let token = arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64)))?;
    let nonce = "cotest-2162-external-proof-nonce";
    let invite_digest = arkret_canonical::canonical_sha256(
        &json!({"invite_id":invite_id,"realm_id":realm,"expires_at":expires_at,"third_party_invite":material}),
    )?;
    let mut binding = InviteClaimBindingProof::new(
        verifier_id,
        account.clone(),
        RealmId::new(realm)?,
        nonce,
        expires_at,
        verifier_method,
        "placeholder",
    );
    binding.signature = URL_SAFE_NO_PAD.encode(
        verifier
            .sign(&invite_binding_proof_transcript_bytes(
                &binding,
                invite_id.as_str(),
                token.as_str(),
                &invite_digest,
            )?)
            .to_bytes(),
    );
    let subject_body = InviteSubjectProofBody::from_wire_parts(
        account.clone(),
        invite_id.as_str(),
        realm,
        token.as_str(),
        nonce,
        binding.verification_id.as_str(),
        binding.canonical_digest()?.as_str(),
    )?;
    let (root_method, root_seed) = test_principal_root_signing_authority(&bob.actor)?;
    let root = SigningKey::from_bytes(&root_seed);
    let subject = InviteSubjectProof::new(
        root_method,
        subject_body.transcript_digest()?,
        URL_SAFE_NO_PAD.encode(root.sign(&subject_body.canonical_bytes()?).to_bytes()),
    );
    let payload = InviteClaimPayload {
        invite_id: invite_id.clone(),
        subject_account_id: account.clone(),
        token_commitment: token,
        claim_nonce: nonce.to_owned(),
        binding_proof: binding,
        subject_proof: subject,
        extensions: Default::default(),
    };
    let before = observation(&governance_db.connect_url, realm).await?;
    let mut rejection_shape = None;
    for case in ["binding_signature", "subject_signature", "pcr_device"] {
        let mut bad = serde_json::to_value(&payload)?;
        match case {
            "binding_signature" => {
                bad["binding_proof"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]))
            }
            "subject_signature" => {
                bad["subject_proof"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]))
            }
            "pcr_device" => {
                bad["subject_proof"]["verification_method"] =
                    json!(format!("{}#{}", bob.actor, bob.device_id))
            }
            _ => unreachable!(),
        }
        let event = bob
            .author_event(realm, EventKind::InviteClaim.as_str(), bad)
            .await?;
        let (status, body) = submit_raw(&bob, &event).await?;
        ensure!(
            status == reqwest::StatusCode::NOT_FOUND,
            "invalid {case} did not use the private refusal: {status} {body}"
        );
        ensure!(
            body["type"]
                .as_str()
                .is_some_and(|value| value.ends_with("/not_found")),
            "invalid {case} returned unrelated failure: {body}"
        );
        let shape = (
            status,
            body["type"].clone(),
            body["detail"].clone(),
            body["reason_code"].clone(),
        );
        if let Some(expected) = &rejection_shape {
            ensure!(
                &shape == expected,
                "invalid claims leaked a distinct failure shape: {body}"
            );
        } else {
            rejection_shape = Some(shape);
        }
        ensure!(
            observation(&governance_db.connect_url, realm).await? == before,
            "invalid {case} wrote canonical/current state"
        );
    }
    let claim = bob
        .author_event(
            realm,
            EventKind::InviteClaim.as_str(),
            serde_json::to_value(payload)?,
        )
        .await?;
    let subject_before = replica_observation(&subject_db.connect_url, realm).await?;
    let claim_result = submit_and_expect_commit(&bob, &account, &bob.device_id, &claim).await;
    if claim_result.is_err() {
        match observation(&governance_db.connect_url, realm).await {
            Ok(after) => eprintln!(
                "2162 failed claim submission: governance (events, commits, claimed, joined) before={before:?} after={after:?}"
            ),
            Err(error) => eprintln!("2162 failed claim observation: {error:#}"),
        }
    }
    let claim_commit = claim_result?;
    let claimed = observation(&governance_db.connect_url, realm).await?;
    ensure!(
        claimed.2 == before.2 + 1 && claimed.3 == before.3,
        "claim must establish the exact proposal without joining its subject"
    );
    ensure!(
        replica_observation(&subject_db.connect_url, realm).await? == subject_before,
        "bound claim result must not install canonical/current replica state"
    );
    ensure!(
        bob.sdk()
            .committed_event_get(&claim.event_id)
            .await
            .is_err(),
        "claim must not grant ordinary committed Event reads"
    );
    let realm_id = RealmId::new(realm.to_owned())?;
    ensure!(
        bob.sdk()
            .scan_commit_stream_to_head(
                realm_id.clone(),
                arkret_wire::CommitStreamRef::Realm { realm_id },
                None,
                1000,
            )
            .await
            .is_err(),
        "claim must not grant a member stream scan"
    );
    eprintln!(
        "2162 third-party claim verified and committed: {}",
        claim_commit.event_ref
    );
    let (replay_status, replay_body) = submit_raw(&bob, &claim).await?;
    ensure!(
        replay_status == reqwest::StatusCode::OK,
        "exact claim replay refused: {replay_body}"
    );
    let replay: arkret_wire::AuthoritySubmitOutcome = serde_json::from_value(replay_body)?;
    ensure!(
        matches!(replay, arkret_wire::AuthoritySubmitOutcome::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Duplicate, commit
        } if commit == claim_commit),
        "exact claim replay must return duplicate with the original complete signed Commit"
    );
    ensure!(
        observation(&governance_db.connect_url, realm).await? == claimed,
        "exact claim replay changed canonical/current state"
    );
    ensure!(
        replica_observation(&subject_db.connect_url, realm).await? == subject_before,
        "exact claim replay installed a member replica"
    );
    let accept = bob
        .author_event(
            realm,
            EventKind::InviteAccept.as_str(),
            json!({"invite_id":invite_id,"previous_state":"claimed"}),
        )
        .await?;
    let accept_commit = submit_and_expect_commit(&bob, &account, &bob.device_id, &accept).await?;
    ensure_same_commit(
        &accept_commit,
        &wait_for_committed(&alice, &accept.event_id).await?,
    )?;
    ensure_same_commit(
        &accept_commit,
        &wait_for_committed(&bob, &accept.event_id).await?,
    )?;
    let frames =
        crate::scenarios::protocol_payloads::account_summary::account_frames(&bob, None).await?;
    let listed = crate::scenarios::protocol_payloads::account_summary::listed_row(&frames, realm)?;
    ensure!(
        listed.membership
            == arkret_models_collaboration::sync_frames::demand_sync::RealmListMembership::Join,
        "accepted claimant was not listed as joined"
    );
    Ok(())
}
