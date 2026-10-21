//! Shared provider SDK against the actual TLS receiver and durable Consent.
use arkret_models_collaboration::mimi_operations::{
    MimiConsentDecision, MimiKeyMaterialRequestBody, MimiNotifyRequestBody,
    MimiRequestConsentRequestBody, MimiRoomUpdateRequestBody, MimiUpdateConsentRequestBody,
};
use arkret_models_collaboration::objects::mimi::MimiConsentPurpose;
use arkret_wire::{EventAdmissionSubmission, PayloadProof, RealmId, ScopeRef, StrandId};

use super::*;

fn proof(server: &ArkretServer, method: &arkret_wire::DidUrl) -> Result<PayloadProof> {
    Ok(serde_json::from_value(
        json!({"kind":"detached_jws", "verification_method":method,
        "payload_digest":format!("sha256:{}", "0".repeat(64)),
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        "domain":server.trust_domain(),"audience":server.service_id(),"jws":"pending"}),
    )?)
}
fn sign(bytes: &[u8], key: &ed25519_dalek::SigningKey) -> Result<String> {
    arkret_signatures::jws::sign_jws_ed25519(bytes, key).map_err(anyhow::Error::msg)
}
async fn correlations(url: &str) -> Result<i64> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(db
            .query_one("SELECT count(*) FROM mimi_consent_correlations", &[])?
            .get(0))
    })
    .await?
}

pub(super) async fn run(
    server: &ArkretServer,
    holder: &Member,
    coauth: &MockCoauthIntrospectionServer,
    database: &str,
    realm: &str,
    strand: &str,
    provider: &str,
) -> Result<()> {
    let room = format!("{provider}/rooms/{strand}");
    let path = format!("/_arkret/open/mimi/strands/{strand}/notify");
    let notify = json!({"notification":{"kind":"delivery"}});
    let before = counts(database, realm).await?;
    for mutation in [
        "body",
        "mimi-room-uri",
        "provider-id",
        "source-service-id",
        "destination-service-id",
    ] {
        let (status, problem) = signed_post_with_mutation(
            server,
            &path,
            Some(&room),
            provider,
            &notify,
            None,
            Some(mutation),
        )
        .await?;
        ensure!(
            status == StatusCode::UNAUTHORIZED
                && problem["type"]
                    .as_str()
                    .is_some_and(|value| value.ends_with("/http_signature_invalid")),
            "{mutation} signature substitution: {status} {problem}"
        );
        ensure!(
            counts(database, realm).await? == before,
            "{mutation} substitution changed durable state"
        );
    }
    for (mutation, expected) in [
        ("wire-whitespace-stale-digest", "http_signature_invalid"),
        ("wire-whitespace-resigned", "http_signature_invalid"),
        ("wire-duplicate-key-resigned", "http_signature_invalid"),
        ("wire-bad-json-resigned", "http_signature_invalid"),
        ("missing_signature", "http_signature_required"),
        ("missing_digest", "http_signature_invalid"),
        ("duplicate_digest", "http_signature_invalid"),
        ("missing-header:arkret-operation", "http_signature_invalid"),
        ("missing-header:source-service-id", "http_signature_invalid"),
        (
            "missing-header:destination-service-id",
            "http_signature_invalid",
        ),
        ("missing-header:provider-id", "http_signature_invalid"),
        ("missing-header:mimi-room-uri", "http_signature_invalid"),
        ("expired_window", "signature_window_invalid"),
        ("future_window", "signature_window_invalid"),
    ] {
        let (status, problem) = signed_post_with_mutation(
            server,
            &path,
            Some(&room),
            provider,
            &notify,
            None,
            Some(mutation),
        )
        .await?;
        ensure!(
            status == StatusCode::UNAUTHORIZED
                && problem["type"] == format!("https://arkret.org/problems/{expected}"),
            "MIMI ingress {mutation}: {status} {problem}"
        );
        ensure!(
            counts(database, realm).await? == before,
            "MIMI ingress {mutation} changed durable state"
        );
    }
    eprintln!(
        "MIMI ingress: 14 exact wire/header/window refusals; zero durable effects; 5 signed component substitutions preserved"
    );
    let requester = Member::provision(
        server,
        coauth,
        "mimi-provider-sdk-requester",
        "ak:device:01904100-0000-7000-8000-000000002883",
    )
    .await?;
    let sdk = provider_sdk(server, provider)?;
    let mut request = MimiRequestConsentRequestBody {
        requester_actor_id: requester.actor.clone(),
        holder_account_id: holder.account.clone(),
        purpose: MimiConsentPurpose::VoiceCall,
        strand_id: Some(StrandId::new(strand.to_owned())?),
        expires_at: None,
        proofs: vec![proof(server, &requester.method)?],
    };
    request.proofs[0].payload_digest = request.payload_digest()?;
    request.proofs[0].jws = sign(
        &request.unsigned_proof_binding_bytes(&request.proofs[0].unsigned())?,
        &requester.key,
    )?;
    let before = correlations(database).await?;
    let first = sdk.mimi_request_consent(&request).await?;
    ensure!(
        correlations(database).await? == before + 1,
        "one SDK request did not create one private correlation"
    );
    let second = sdk.mimi_request_consent(&request).await?;
    ensure!(
        first.consent_id != second.consent_id && correlations(database).await? == before + 2,
        "a new explicit request was incorrectly treated as exact correlation recovery"
    );

    let pcr = &holder
        .client
        .principal
        .as_ref()
        .context("actual holder PCR")?
        .pcr_realm_id;
    let peer = arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor {
        actor_id: requester.actor.clone(),
    };
    let (expected_current, mut permissions) =
        crate::scenarios::invite_service_fanout_live::read_consent_set(&holder.client, &peer)
            .await?;
    permissions.retain(|p| p.consent_scope != arkret_wire::ConsentScope::VoiceCall);
    permissions.push(
        arkret_models_collaboration::events_payloads::consent::ConsentPermission {
            consent_scope: arkret_wire::ConsentScope::VoiceCall,
            not_before: None,
            expires_at: None,
            constraints: None,
            evidence_ref: None,
            reason: None,
        },
    );
    permissions.sort_by_key(|p| p.consent_scope);
    let event = holder
        .client
        .author_event(
            pcr.as_str(),
            EventKind::ConsentReplace.as_str(),
            serde_json::to_value(
                arkret_models_collaboration::events_payloads::consent::ConsentReplacePayload {
                    peer,
                    expected_current,
                    permissions,
                },
            )?,
        )
        .await?;
    let mut update = MimiUpdateConsentRequestBody {
        consent_id: first.consent_id.clone(),
        decision: MimiConsentDecision::Accept,
        actor_id: holder.actor.clone(),
        consent_event: EventAdmissionSubmission::new(event.clone()),
        signature: proof(server, &holder.method)?,
        reason: None,
        expires_at: None,
    };
    update.signature.payload_digest = update.payload_digest()?;
    let bytes = update.unsigned_signature_binding_bytes(&update.signature.unsigned())?;
    update.signature.jws = sign(&bytes, &requester.key)?;
    let before = counts(database, pcr.as_str()).await?;
    let failure = sdk.mimi_update_consent(&update).await.unwrap_err();
    let arkret_http_client::Error::Api { error, .. } = failure else {
        anyhow::bail!("expected actor proof refusal, got {failure:?}")
    };
    ensure!(
        error.code() == "param_invalid"
            && error.extensions.get("reason_code") == Some(&json!("proof_invalid")),
        "wrong key refusal: {error:?}"
    );
    ensure!(
        counts(database, pcr.as_str()).await? == before,
        "wrong actor proof changed durable state"
    );
    update.signature.jws = sign(&bytes, &holder.key)?;
    // Persist before transport; a later local recovery reuses this exact Event.
    let frozen_dir = tempfile::tempdir()?;
    let frozen_path = frozen_dir.path().join("consent-update.json");
    std::fs::write(
        &frozen_path,
        arkret_canonical::canonical_json_bytes(&update)?,
    )?;
    let accepted = sdk.mimi_update_consent(&update).await?;
    ensure!(
        accepted.event_ref == event.event_id && accepted.consent_id == first.consent_id,
        "SDK accepted substituted Consent result"
    );
    let committed = counts(database, pcr.as_str()).await?;
    ensure!(
        committed[0] == before[0] + 1 && committed[1] == before[1] + 1,
        "Consent did not admit one Event and Commit"
    );
    // Recover from the durable original after a distinct native replacement.
    super::super::invite_service_fanout_live::grant_scoped_consent(
        &holder.client,
        &requester.client,
        arkret_wire::ConsentScope::Presence,
    )
    .await?;
    let later = counts(database, pcr.as_str()).await?;
    ensure!(
        later[0] == committed[0] + 1,
        "distinct peer scope edit was not accepted"
    );
    let recovered: MimiUpdateConsentRequestBody =
        serde_json::from_slice(&std::fs::read(&frozen_path)?)?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&recovered.consent_event)?
            == arkret_canonical::canonical_json_bytes(&update.consent_event)?,
        "recovery rebuilt the Event"
    );
    let replay = sdk.mimi_update_consent(&recovered).await?;
    ensure!(
        replay.event_ref == accepted.event_ref
            && replay.updated_at == accepted.updated_at
            && counts(database, pcr.as_str()).await? == later,
        "frozen Consent retry lost its original outcome or changed later current"
    );
    let (revision, permissions) = super::super::invite_service_fanout_live::read_consent_set(
        &holder.client,
        &arkret::ConsentPeer::Actor {
            actor_id: requester.actor.clone(),
        },
    )
    .await?;
    ensure!(
        permissions.len() == 2
            && permissions
                .iter()
                .any(|p| p.consent_scope == arkret_wire::ConsentScope::Presence),
        "accepted retry rolled back the other scope"
    );
    let mut other_correlation = recovered.clone();
    other_correlation.consent_id = second.consent_id;
    other_correlation.signature.payload_digest = other_correlation.payload_digest()?;
    other_correlation.signature.jws = sign(
        &other_correlation
            .unsigned_signature_binding_bytes(&other_correlation.signature.unsigned())?,
        &holder.key,
    )?;
    let failure = sdk
        .mimi_update_consent(&other_correlation)
        .await
        .unwrap_err();
    ensure!(
        matches!(failure,arkret_http_client::Error::Api { ref error,.. } if error.code()=="not_found"),
        "accepted original was reused in another correlation: {failure:?}"
    );
    ensure!(
        counts(database, pcr.as_str()).await? == later,
        "correlation substitution wrote native state"
    );

    // Repeat actual HTTP recovery without manufacturing a facade terminal row.
    let replay = sdk.mimi_update_consent(&recovered).await?;
    ensure!(
        replay.event_ref == accepted.event_ref && replay.updated_at == accepted.updated_at,
        "durable exact retry did not recover original result"
    );
    ensure!(
        super::super::invite_service_fanout_live::read_consent_set(
            &holder.client,
            &arkret::ConsentPeer::Actor {
                actor_id: requester.actor.clone()
            }
        )
        .await?
        .0 == revision,
        "exact recovery rewrote peer current"
    );
    eprintln!(
        "SC MIMI: durable original recovery; later other-scope edit preserved; cross-correlation Event reuse refused; repeated exact native replay"
    );

    let peer = arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor {
        actor_id: requester.actor.clone(),
    };
    let (expected_current, mut permissions) =
        crate::scenarios::invite_service_fanout_live::read_consent_set(&holder.client, &peer)
            .await?;
    permissions.retain(|p| p.consent_scope != arkret_wire::ConsentScope::VoiceCall);
    let (cleared, _) = crate::scenarios::invite_service_fanout_live::submit_consent_set(
        &holder.client,
        arkret_models_collaboration::events_payloads::consent::ConsentReplacePayload {
            peer: peer.clone(),
            expected_current,
            permissions,
        },
    )
    .await?;
    let after_clear = counts(database, pcr.as_str()).await?;
    let replay_after_change = sdk.mimi_update_consent(&update).await?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&replay_after_change)?
            == arkret_canonical::canonical_json_bytes(&accepted)?
            && counts(database, pcr.as_str()).await? == after_clear,
        "an old facade decision was reexecuted after a native replacement"
    );
    let (_, current) =
        crate::scenarios::invite_service_fanout_live::read_consent_set(&holder.client, &peer)
            .await?;
    ensure!(
        current
            .iter()
            .all(|p| p.consent_scope != arkret_wire::ConsentScope::VoiceCall)
            && !cleared
                .permission_scopes
                .contains(&arkret_wire::ConsentScope::VoiceCall),
        "exact facade retry restored a removed permission"
    );
    crate::harness::heap_future(|| {
        revoke_expired_voice(server, holder, &requester, database, &sdk, &request)
    })
    .await?;

    let room = arkret_wire::MimiRoomUri::new(format!("{provider}/rooms/{strand}"))
        .map_err(anyhow::Error::msg)?;
    let room_sdk = sdk.clone().with_mimi_room(room)?;
    let group = ScopeRef::Realm {
        realm_id: RealmId::new(realm.to_owned())?,
    }
    .canonical_mls_group_id()?;
    let payload = arkret_canonical::canonical_json_bytes(
        &json!({"kind":"m.room.name","name":"typed provider receipt"}),
    )?;
    let room_request: MimiRoomUpdateRequestBody = serde_json::from_value(
        json!({"mls_group_id":group,"update":{
            "kind":"m.room.name","payload":{"content_type":"application/json","payload_digest":arkret_canonical::sha256_digest(&payload),"payload":arkret_canonical::base64url_encode(&payload)}
        }}),
    )?;
    let before = counts(database, realm).await?;
    let result = room_sdk.mimi_update_room(strand, &room_request).await?;
    ensure!(
        result.accepted && result.room_state_ref.is_none(),
        "receipt-only room update claimed a native Event"
    );
    let notify: MimiNotifyRequestBody =
        serde_json::from_value(json!({"notification":{"kind":"delivery"}}))?;
    ensure!(
        room_sdk.mimi_notify(strand, &notify).await?.accepted,
        "typed notify rejected"
    );
    ensure!(
        counts(database, realm).await? == before,
        "receipt-only room/notify emitted native writes"
    );

    let mut key_request: MimiKeyMaterialRequestBody = serde_json::from_value(json!({
        "requester_id":server.service_id(),"strand_id":strand,"device_id":requester.device,
        "realm_id":realm,"mls_group_id":group
    }))?;
    key_request.proofs.push(proof(
        server,
        &arkret_wire::DidUrl::new(format!("{}#notary-key", server.service_did()))
            .map_err(anyhow::Error::msg)?,
    )?);
    key_request.proofs[0].payload_digest = key_request.payload_digest()?;
    key_request.proofs[0].jws = sign(
        &key_request.unsigned_proof_binding_bytes(&key_request.proofs[0].unsigned())?,
        &server.federation_signing_key()?,
    )?;
    let failure = sdk
        .mimi_request_key_material(&key_request)
        .await
        .unwrap_err();
    let arkret_http_client::Error::Api { error, .. } = failure else {
        anyhow::bail!("expected closed key claim refusal, got {failure:?}")
    };
    ensure!(
        error.code() == "claim_failed",
        "signed no-material key claim: {error:?}"
    );
    ensure!(
        counts(database, realm).await? == before,
        "failed key claim emitted native writes"
    );
    eprintln!(
        "MIMI provider SDK: request correlations=3; Consent accepted/exact replay=2; expired-scope removal=1; wrong-key zero-write=1; room receipt/notify=2; signed no-material claim refusal=1; external-provider-live=0"
    );
    Ok(())
}

async fn revoke_expired_voice(
    server: &ArkretServer,
    holder: &Member,
    requester: &Member,
    database: &str,
    sdk: &arkret_http_client::Client,
    original_request: &MimiRequestConsentRequestBody,
) -> Result<()> {
    use arkret_models_collaboration::events_payloads::consent::{
        ConsentPeer, ConsentPermission, ConsentReplacePayload,
    };

    use crate::scenarios::invite_service_fanout_live::{read_consent_set, submit_consent_set};

    let peer = ConsentPeer::Actor {
        actor_id: requester.actor.clone(),
    };
    let (expected_current, original_permissions) = read_consent_set(&holder.client, &peer).await?;
    ensure!(
        original_permissions.len() == 1
            && original_permissions[0].consent_scope == arkret_wire::ConsentScope::Presence,
        "expired-removal fixture lost its actual unrelated Presence prestate"
    );
    let expired: ConsentPermission = serde_json::from_value(json!({
        "consent_scope":"voice_call","expires_at":"2020-01-01T00:00:00.000Z",
        "constraints":[],"evidence_ref":"cotest_expired_voice","reason":""
    }))?;
    ensure!(expired.expires_at.is_some_and(|at| at < chrono::Utc::now()));
    let mut with_expired = original_permissions.clone();
    with_expired.push(expired);
    with_expired.sort_by_key(|permission| permission.consent_scope);
    submit_consent_set(
        &holder.client,
        ConsentReplacePayload {
            peer: peer.clone(),
            expected_current,
            permissions: with_expired.clone(),
        },
    )
    .await?;
    let (expired_current, complete) = read_consent_set(&holder.client, &peer).await?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&complete)?
            == arkret_canonical::canonical_json_bytes(&with_expired)?,
        "actual native current discarded the expired permission or optional members"
    );

    let mut request = original_request.clone();
    request.proofs = vec![proof(server, &requester.method)?];
    request.proofs[0].payload_digest = request.payload_digest()?;
    request.proofs[0].jws = sign(
        &request.unsigned_proof_binding_bytes(&request.proofs[0].unsigned())?,
        &requester.key,
    )?;
    let correlation_count = correlations(database).await?;
    let correlation = sdk.mimi_request_consent(&request).await?;
    ensure!(correlations(database).await? == correlation_count + 1);
    let pcr = &holder
        .client
        .principal
        .as_ref()
        .context("actual holder PCR")?
        .pcr_realm_id;
    let event = holder
        .client
        .author_event(
            pcr.as_str(),
            EventKind::ConsentReplace.as_str(),
            serde_json::to_value(ConsentReplacePayload {
                peer: peer.clone(),
                expected_current: expired_current.clone(),
                permissions: original_permissions.clone(),
            })?,
        )
        .await?;
    let mut revoke = MimiUpdateConsentRequestBody {
        consent_id: correlation.consent_id,
        decision: MimiConsentDecision::Revoke,
        actor_id: holder.actor.clone(),
        consent_event: EventAdmissionSubmission::new(event.clone()),
        signature: proof(server, &holder.method)?,
        reason: None,
        expires_at: None,
    };
    revoke.signature.payload_digest = revoke.payload_digest()?;
    revoke.signature.jws = sign(
        &revoke.unsigned_signature_binding_bytes(&revoke.signature.unsigned())?,
        &holder.key,
    )?;
    let before = counts(database, pcr.as_str()).await?;
    let accepted = sdk.mimi_update_consent(&revoke).await?;
    let after = counts(database, pcr.as_str()).await?;
    ensure!(accepted.event_ref == event.event_id && accepted.consent_id == revoke.consent_id);
    ensure!(
        after[0] == before[0] + 1 && after[1] == before[1] + 1,
        "expired permission removal did not accept exactly one original Event/Commit"
    );
    let (removed_current, remaining) = read_consent_set(&holder.client, &peer).await?;
    ensure!(
        removed_current != expired_current
            && arkret_canonical::canonical_json_bytes(&remaining)?
                == arkret_canonical::canonical_json_bytes(&original_permissions)?,
        "MIMI expired permission removal changed an unrelated complete entry or kept the old cut"
    );
    let replay = sdk.mimi_update_consent(&revoke).await?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&replay)?
            == arkret_canonical::canonical_json_bytes(&accepted)?
            && counts(database, pcr.as_str()).await? == after,
        "expired permission exact retry did not preserve the original outcome without writes"
    );
    let (replayed_current, replayed_permissions) = read_consent_set(&holder.client, &peer).await?;
    ensure!(
        replayed_current == removed_current && replayed_permissions == remaining,
        "expired permission exact retry changed the complete peer current"
    );
    eprintln!(
        "[SC-C3 MIMI] expired_permission_removed=1 unrelated_complete_presence_preserved=1 accepted_original_replay_zero_writes=1"
    );
    Ok(())
}
