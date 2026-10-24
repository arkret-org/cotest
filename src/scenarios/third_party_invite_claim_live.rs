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
    HARNESS_INTERNAL_AUTHORITY_SECRET, prepared_test_principal_inception,
    test_principal_next_root_seed, test_principal_root_signing_authority,
};

const GROUP: &str = "third-party-invite-claim";

fn migrated_claim(
    template: &InviteClaimPayload,
    invite_digest: &str,
    nonce: &str,
    verifier: &SigningKey,
    root_method: arkret_wire::DidUrl,
    root_seed: &[u8; 32],
) -> Result<InviteClaimPayload> {
    let mut payload = template.clone();
    payload.claim_nonce = nonce.to_owned();
    payload.binding_proof.claim_nonce = nonce.to_owned();
    payload.binding_proof.signature = URL_SAFE_NO_PAD.encode(
        verifier
            .sign(&invite_binding_proof_transcript_bytes(
                &payload.binding_proof,
                payload.invite_id.as_str(),
                payload.token_commitment.as_str(),
                invite_digest,
            )?)
            .to_bytes(),
    );
    let subject = InviteSubjectProofBody::from_wire_parts(
        payload.subject_account_id.clone(),
        payload.invite_id.as_str(),
        payload.binding_proof.realm_id.as_str(),
        payload.token_commitment.as_str(),
        nonce,
        payload.binding_proof.verification_id.as_str(),
        payload.binding_proof.canonical_digest()?.as_str(),
    )?;
    payload.subject_proof = InviteSubjectProof::new(
        root_method,
        subject.transcript_digest()?,
        URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(root_seed)
                .sign(&subject.canonical_bytes()?)
                .to_bytes(),
        ),
    );
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
async fn migrated_preclaim_negatives(
    alice: &TestActorClient,
    bob: &TestActorClient,
    governance: &crate::harness::ArkretServer,
    subject_station: &crate::harness::ArkretServer,
    issuer: &MockCoauthIntrospectionServer,
    template: &InviteClaimPayload,
    material: &Value,
    verifier: &SigningKey,
    database_url: &str,
) -> Result<()> {
    let realm = template.binding_proof.realm_id.as_str();
    let (root_method, root_seed) = test_principal_root_signing_authority(&bob.actor)?;
    let mut private_material = material.clone();
    private_material["token_commitment"] = json!(format!("sha256:{}", "b".repeat(64)));
    let expires = arkret_canonical::format_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(5),
    );
    let create = alice
        .author_event(
            realm,
            EventKind::InviteThirdParty.as_str(),
            json!({"third_party_invite":private_material,"expires_at":expires}),
        )
        .await?;
    submit_and_expect_commit(
        alice,
        create
            .actor_id
            .as_account_id()
            .context("invite creator Account")?,
        &alice.device_id,
        &create,
    )
    .await?;
    let expired_id = InviteId::from_event_id(&create.event_id);
    prepare_join(
        bob,
        realm,
        governance,
        &arkret_identifiers::new_prefixed_uuid7("ak:request:"),
        RealmJoinIntent::InviteAccept {
            invite_id: expired_id.clone(),
        },
    )
    .await?;
    let mut expired = template.clone();
    expired.invite_id = expired_id.clone();
    expired.token_commitment = arkret_wire::Hash::new(format!("sha256:{}", "b".repeat(64)))?;
    expired.binding_proof.expires_at = expires.clone();
    let expired_digest = arkret_canonical::canonical_sha256(
        &json!({"invite_id":expired_id,"realm_id":realm,"expires_at":expires,"third_party_invite":private_material}),
    )?;
    expired = migrated_claim(
        &expired,
        &expired_digest,
        "expired-invite-claim",
        verifier,
        root_method,
        &root_seed,
    )?;
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    let before = observation(database_url, realm).await?;
    let event = bob
        .author_event(
            realm,
            EventKind::InviteClaim.as_str(),
            serde_json::to_value(expired)?,
        )
        .await?;
    let (status, expired_problem) = submit_raw(bob, &event).await?;
    ensure!(
        status == reqwest::StatusCode::NOT_FOUND
            && expired_problem["type"] == "https://arkret.org/problems/not_found",
        "expired invite claim disclosed an unrelated refusal"
    );
    ensure!(
        observation(database_url, realm).await? == before,
        "expired claim changed durable Events, Commits or lifecycle rows"
    );
    let (mallory, mallory_account) = standard_client(
        subject_station,
        issuer,
        "migration-wrong-claim-subject",
        &arkret_identifiers::new_prefixed_uuid7("ak:device:"),
    )
    .await?;
    prepare_join(
        &mallory,
        realm,
        governance,
        &arkret_identifiers::new_prefixed_uuid7("ak:request:"),
        RealmJoinIntent::InviteAccept {
            invite_id: template.invite_id.clone(),
        },
    )
    .await?;
    let (method, seed) = test_principal_root_signing_authority(&mallory.actor)?;
    let mut mismatch = template.clone();
    mismatch.subject_account_id = mallory_account;
    let digest = arkret_canonical::canonical_sha256(
        &json!({"invite_id":template.invite_id,"realm_id":realm,"expires_at":template.binding_proof.expires_at,"third_party_invite":material}),
    )?;
    mismatch = migrated_claim(
        &mismatch,
        &digest,
        "different-binding-subject",
        verifier,
        method,
        &seed,
    )?;
    let event = mallory
        .author_event(
            realm,
            EventKind::InviteClaim.as_str(),
            serde_json::to_value(mismatch)?,
        )
        .await?;
    let (status, mismatch_problem) = submit_raw(&mallory, &event).await?;
    ensure!(
        status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
            && mismatch_problem["type"] == "https://arkret.org/problems/schema_violation",
        "inconsistent binding and claimant did not fail the closed payload contract: {status} {mismatch_problem}"
    );
    let public = serde_json::to_string(&mismatch_problem)?;
    for secret in [
        bob.actor.as_str(),
        mallory.actor.as_str(),
        template.token_commitment.as_str(),
    ] {
        ensure!(
            !public.contains(secret),
            "malformed claim disclosed a private subject or commitment"
        );
    }
    ensure!(
        observation(database_url, realm).await? == before,
        "wrong binding subject changed durable state"
    );
    Ok(())
}

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
        let row=db.query_one("SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1),(SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1),(SELECT COUNT(*) FROM invite_lifecycle_current_states WHERE realm_id=$1 AND value='\"claimed\"'::jsonb),(SELECT COUNT(*) FROM member_state_current_states WHERE realm_id=$1 AND membership='join')",&[&realm])?;
        Ok((row.get(0),row.get(1),row.get(2),row.get(3)))
    }).await?
}

async fn replica_observation(url: &str, realm: &str) -> Result<(i64, i64, i64, i64, i64, i64)> {
    let url = url.to_owned();
    let realm = realm.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        let row = db.query_one("SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1 AND state='accepted'),(SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1),(SELECT COUNT(*) FROM invite_lifecycle_current_states WHERE realm_id=$1 AND value='\"claimed\"'::jsonb),(SELECT COUNT(*) FROM member_state_current_states WHERE realm_id=$1 AND membership='join'),(SELECT COUNT(*) FROM replica_stream_anchors WHERE realm_id=$1),(SELECT COUNT(*) FROM replica_authorization_cuts WHERE realm_id=$1)", &[&realm])?;
        Ok((row.get(0), row.get(1), row.get(2), row.get(3), row.get(4), row.get(5)))
    }).await?
}

async fn fault_origin_source(
    url: &str,
    event: &arkret_wire::Event,
    fault: &str,
) -> Result<(String, String, String)> {
    let url = url.to_owned();
    let event_id = event.event_id.to_string();
    let fault = fault.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        let roots = db.query(
            "SELECT evidence_ref,evidence_json::text FROM account_device_signer_evidence \
             WHERE evidence_json #>> '{device_projection_attestation,attestation,event_authorization,event_id}'=$1",
            &[&event_id],
        )?;
        ensure!(roots.len() == 1, "Claim fixture must have exactly one original root");
        let original_ref: String = roots[0].get(0);
        let original_body: String = roots[0].get(1);
        let mut body: Value = serde_json::from_str(&original_body)?;
        match fault.as_str() {
            "missing" => body["device_projection_attestation"]["attestation"]["event_authorization"]["event_id"] = json!("unavailable"),
            "signature" => {
                let jws = body["device_projection_attestation"]["proof"]["jws"].as_str().context("original JWS")?;
                let header = jws.split('.').next().context("original JWS header")?;
                body["device_projection_attestation"]["proof"]["jws"] = json!(format!("{header}..{}", URL_SAFE_NO_PAD.encode([0u8;64])));
            }
            _ => anyhow::bail!("unknown origin source fault"),
        }
        // Recompute the archive address: the signature fault must be rejected
        // by real proof verification, not merely by a stale content address.
        let altered_ref = format!("ak:signer_evidence:sha256:{}",arkret_canonical::sha256_hex(arkret_canonical::canonical_json_bytes(&body)?));
        ensure!(db.execute("UPDATE account_device_signer_evidence SET evidence_ref=$2,evidence_json=CAST($3 AS text)::jsonb WHERE evidence_ref=$1",&[&original_ref,&altered_ref,&body.to_string()])? == 1);
        Ok((altered_ref,original_ref,original_body))
    }).await?
}

async fn restore_origin_source(url: &str, root: (String, String, String)) -> Result<()> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        ensure!(db.execute("UPDATE account_device_signer_evidence SET evidence_ref=$2,evidence_json=CAST($3 AS text)::jsonb WHERE evidence_ref=$1",&[&root.0,&root.1,&root.2])? == 1);
        Ok(())
    }).await?
}

pub async fn third_party_invite_claim_run() -> Result<()> {
    run(false).await
}

pub async fn third_party_invite_api_migration() -> Result<()> {
    super::third_party_invite_create_live::third_party_invite_create_requires_current_allowlist()
        .await?;
    run(true).await
}

async fn run(api_migration: bool) -> Result<()> {
    let Some(governance_db) = database(GROUP)? else {
        ensure!(
            !api_migration,
            "3PID API migration requires an isolated governance PostgreSQL database"
        );
        return Ok(());
    };
    let Some(subject_db) = database(GROUP)? else {
        ensure!(
            !api_migration,
            "3PID API migration requires an isolated subject PostgreSQL database"
        );
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
    let Some(mut group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&governance_db.connect_url, &coauth),
            station_env(&subject_db.connect_url, &coauth),
        ],
    )
    .await?
    else {
        ensure!(
            !api_migration,
            "3PID API migration requires the prebuilt real Station"
        );
        return skip_or_fail(GROUP, "prebuilt Coland unavailable");
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
    let material = json!({"oob_code_kind":"offline_token","token_commitment":format!("sha256:{}","a".repeat(64)),"token_salt_id":"cotest-2162-salt","token_entropy_bits":128,"max_claim_count":1,"verification_id":verifier_id,"verification_public_key":multibase});
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
    let mut payload = InviteClaimPayload {
        invite_id: invite_id.clone(),
        subject_account_id: account.clone(),
        token_commitment: token,
        claim_nonce: nonce.to_owned(),
        binding_proof: binding,
        subject_proof: subject,
        extensions: Default::default(),
    };
    if api_migration {
        migrated_preclaim_negatives(
            &alice,
            &bob,
            group.server(0),
            group.server(1),
            &coauth,
            &payload,
            &material,
            &verifier,
            &governance_db.connect_url,
        )
        .await?;
        let wire = serde_json::to_string(&create)?;
        for private in [
            "@example.com",
            "token_salt\"",
            "delivery_target",
            "pepper",
            "ephemeral_private_key",
        ] {
            ensure!(
                !wire.contains(private),
                "durable 3PID Event disclosed private verifier material"
            );
        }
    }
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
    let inception = prepared_test_principal_inception(&bob.actor)?;
    let next_root_seed = test_principal_next_root_seed(&bob.actor)?;
    let next_root = SigningKey::from_bytes(&next_root_seed);
    let third_root_seed = [0x73; 32];
    let third_root = SigningKey::from_bytes(&third_root_seed);
    let third_root_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        third_root.verifying_key().as_bytes(),
    );
    let rotation = arkret_signatures::webvh::prepare_principal_rotation(
        &arkret_signatures::webvh::PrincipalRotationInput {
            did: &bob.actor,
            local_id: &inception.local_id,
            previous_entries: std::slice::from_ref(&inception.log_entry),
            version_created_at: chrono::Utc::now(),
            current_root_seed: &next_root_seed,
            next_root_public_key_multibase: &third_root_key,
            state: &inception.log_entry["state"],
        },
    )?;
    let rotated = crate::harness::expect_json(
        group
            .server(1)
            .http()
            .post(
                group
                    .server(1)
                    .url("/_arkret/root/identity/submit-did-operation"),
            )
            .canonical_json(&rotation.submit_body)?,
        reqwest::StatusCode::OK,
    )
    .await?;
    ensure!(
        rotated["status"] == "accepted",
        "root rotation was not accepted: {rotated}"
    );
    let future_proof = InviteSubjectProof::new(
        arkret_wire::DidUrl::new(format!("did:key:{third_root_key}#{third_root_key}"))
            .map_err(|error| anyhow::anyhow!(error))?,
        subject_body.transcript_digest()?,
        URL_SAFE_NO_PAD.encode(third_root.sign(&subject_body.canonical_bytes()?).to_bytes()),
    );
    for (case, proof) in [
        ("rotated_out_root", payload.subject_proof.clone()),
        ("not_yet_active_root", future_proof),
    ] {
        let mut bad = payload.clone();
        bad.subject_proof = proof;
        let rejected = bob
            .author_event(
                realm,
                EventKind::InviteClaim.as_str(),
                serde_json::to_value(bad)?,
            )
            .await?;
        let (status, body) = submit_raw(&bob, &rejected).await?;
        let shape = (
            status,
            body["type"].clone(),
            body["detail"].clone(),
            body["reason_code"].clone(),
        );
        ensure!(
            Some(&shape) == rejection_shape.as_ref(),
            "{case} disclosed a distinct refusal: {status} {body}"
        );
        ensure!(
            observation(&governance_db.connect_url, realm).await? == before,
            "{case} wrote canonical/current state"
        );
    }
    payload.subject_proof = InviteSubjectProof::new(
        arkret_wire::DidUrl::new(rotation.current_root_verification_method.clone())
            .map_err(|error| anyhow::anyhow!(error))?,
        subject_body.transcript_digest()?,
        URL_SAFE_NO_PAD.encode(next_root.sign(&subject_body.canonical_bytes()?).to_bytes()),
    );
    let claim = bob
        .author_event(
            realm,
            EventKind::InviteClaim.as_str(),
            serde_json::to_value(&payload)?,
        )
        .await?;
    let before_replica = replica_observation(&subject_db.connect_url, realm).await?;
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
    if api_migration {
        let late = migrated_claim(
            &payload,
            &invite_digest,
            "different-second-claim",
            &verifier,
            arkret_wire::DidUrl::new(rotation.current_root_verification_method.clone())
                .map_err(anyhow::Error::msg)?,
            &next_root_seed,
        )?;
        let event = bob
            .author_event(
                realm,
                EventKind::InviteClaim.as_str(),
                serde_json::to_value(late)?,
            )
            .await?;
        let (status, body) = submit_raw(&bob, &event).await?;
        ensure!(
            status == reqwest::StatusCode::NOT_FOUND
                && body["type"] == "https://arkret.org/problems/not_found",
            "different second claim disclosed a non-uniform refusal"
        );
        ensure!(
            observation(&governance_db.connect_url, realm).await? == claimed,
            "different second claim changed durable lifecycle state"
        );
    }
    ensure!(
        claimed.2 == before.2 + 1 && claimed.3 == before.3,
        "claim must establish the exact proposal without joining its subject"
    );
    eprintln!(
        "2162 third-party claim verified and committed: {}",
        claim_commit.event_ref
    );
    ensure!(
        replica_observation(&subject_db.connect_url, realm).await? == before_replica,
        "bound Claim result installed a replica, stream anchor, or committed local Event"
    );
    ensure!(
        bob.sdk()
            .committed_event_get(&claim.event_id)
            .await
            .is_err(),
        "bound Claim result must not grant a member read before InviteAccept"
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
    let fourth_root_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[0x74; 32])
            .verifying_key()
            .as_bytes(),
    );
    let after_claim = arkret_signatures::webvh::prepare_principal_rotation(
        &arkret_signatures::webvh::PrincipalRotationInput {
            did: &bob.actor,
            local_id: &inception.local_id,
            previous_entries: &[inception.log_entry, rotation.log_entry],
            version_created_at: chrono::Utc::now(),
            current_root_seed: &third_root_seed,
            next_root_public_key_multibase: &fourth_root_key,
            state: &inception.submit_body.operation["state"],
        },
    )?;
    let rotated_again = crate::harness::expect_json(
        group
            .server(1)
            .http()
            .post(
                group
                    .server(1)
                    .url("/_arkret/root/identity/submit-did-operation"),
            )
            .canonical_json(&after_claim.submit_body)?,
        reqwest::StatusCode::OK,
    )
    .await?;
    ensure!(
        rotated_again["status"] == "accepted",
        "post-claim root rotation was not accepted: {rotated_again}"
    );
    group.server_mut(1).restart_external_process().await?;
    for fault in ["missing", "signature"] {
        let root = fault_origin_source(&subject_db.connect_url, &claim, fault).await?;
        let response = submit_raw(&bob, &claim).await;
        restore_origin_source(&subject_db.connect_url, root).await?;
        let (status, body) = response?;
        ensure!(
            status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                && body["type"]
                    .as_str()
                    .is_some_and(|value| value.ends_with("/temporarily_unavailable")),
            "{fault} original proof returned an unverified Claim result: {status} {body}"
        );
        ensure!(
            observation(&governance_db.connect_url, realm).await? == claimed
                && replica_observation(&subject_db.connect_url, realm).await? == before_replica,
            "{fault} original proof changed governance state or installed a replica"
        );
    }
    let (replay_status, replay_body) = submit_raw(&bob, &claim).await?;
    ensure!(
        replay_status == reqwest::StatusCode::OK,
        "exact claim replay refused: {replay_body}"
    );
    let replay: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(replay_body)?;
    ensure!(
        matches!(replay, arkret_wire::AuthoritySubmitResponseBody::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Duplicate, commit
        } if commit == claim_commit),
        "exact claim replay must return duplicate with the original complete signed Commit"
    );
    ensure!(
        observation(&governance_db.connect_url, realm).await? == claimed,
        "exact claim replay changed canonical/current state"
    );
    ensure!(
        replica_observation(&subject_db.connect_url, realm).await? == before_replica,
        "exact Claim replay opened a member stream"
    );
    let (first, second) = tokio::try_join!(submit_raw(&bob, &claim), submit_raw(&bob, &claim))?;
    for (status, body) in [first, second] {
        ensure!(
            status == reqwest::StatusCode::OK,
            "concurrent exact Claim replay refused: {status} {body}"
        );
        let outcome: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(body)?;
        ensure!(
            matches!(outcome, arkret_wire::AuthoritySubmitResponseBody::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Duplicate, commit
        } if commit == claim_commit),
            "concurrent Claim replay changed its original Commit"
        );
    }
    ensure!(
        observation(&governance_db.connect_url, realm).await? == claimed
            && replica_observation(&subject_db.connect_url, realm).await? == before_replica,
        "concurrent Claim replay changed canonical/current state or installed a replica"
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
    let accepted_state = observation(&governance_db.connect_url, realm).await?;
    let (status, body) = submit_raw(&bob, &claim).await?;
    let outcome: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(body)?;
    ensure!(
        status == reqwest::StatusCode::OK
            && matches!(outcome,
        arkret_wire::AuthoritySubmitResponseBody::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Duplicate, commit
        } if commit == claim_commit),
        "post-accept Claim replay lost its original outcome"
    );
    ensure!(
        observation(&governance_db.connect_url, realm).await? == accepted_state,
        "post-accept Claim replay changed the final lifecycle or membership"
    );
    Ok(())
}
