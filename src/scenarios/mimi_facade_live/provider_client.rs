//! Shared provider SDK against the actual TLS receiver and durable Consent.
use arkret_models_collaboration::mimi_operations::{
    MimiConsentDecision, MimiNotifyRequestBody, MimiRequestConsentRequestBody,
    MimiRoomUpdateRequestBody, MimiUpdateConsentRequestBody,
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
    let undisclosed_never_written = crate::harness::heap_future(|| {
        reject_nonholder_current_reads(server, holder, &requester, database, false)
    })
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
    let undisclosed_present = crate::harness::heap_future(|| {
        reject_nonholder_current_reads(server, holder, &requester, database, true)
    })
    .await?;
    ensure!(
        undisclosed_present == undisclosed_never_written,
        "a nonholder distinguished present Consent from never-written Consent"
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
    other_correlation.consent_id = second.consent_id.clone();
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

    // A second correlation signs a new complete target while preserving the
    // unrelated permission and the first correlation's immutable retry unit.
    let current =
        crate::scenarios::consent_call_context::read_peer_current(&holder.client, &peer).await?;
    let mut permissions = current
        .current_permissions()
        .context("complete peer pre-state")?
        .to_vec();
    permissions.retain(|item| item.consent_scope != arkret_wire::ConsentScope::VoiceCall);
    let preserved = permissions.clone();
    ensure!(
        preserved
            .iter()
            .any(|item| item.consent_scope == arkret_wire::ConsentScope::Presence)
    );
    permissions.push(
        arkret_models_collaboration::events_payloads::consent::ConsentPermission {
            consent_scope: arkret_wire::ConsentScope::VoiceCall,
            not_before: None,
            expires_at: Some(
                chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00.000Z")?
                    .with_timezone(&chrono::Utc),
            ),
            constraints: Some(vec![]),
            evidence_ref: None,
            reason: Some("second explicit correlation".into()),
        },
    );
    permissions.sort_by_key(|item| item.consent_scope);
    let later_event = holder.client.author_event(pcr.as_str(), EventKind::ConsentReplace.as_str(), json!({
        "peer":peer, "expected_current":current.expected_current(), "permissions":permissions
    })).await?;
    let mut later = update.clone();
    later.consent_id = second.consent_id.clone();
    later.consent_event = EventAdmissionSubmission::new(later_event.clone());
    later.signature = proof(server, &holder.method)?;
    later.signature.payload_digest = later.payload_digest()?;
    later.signature.jws = sign(
        &later.unsigned_signature_binding_bytes(&later.signature.unsigned())?,
        &holder.key,
    )?;
    ensure!(sdk.mimi_update_consent(&later).await?.event_ref == later_event.event_id);
    let before_replay = counts(database, pcr.as_str()).await?;
    let replay = sdk.mimi_update_consent(&update).await?;
    ensure!(
        replay.event_ref == accepted.event_ref
            && replay.updated_at == accepted.updated_at
            && counts(database, pcr.as_str()).await? == before_replay,
        "original correlation replay changed a later peer revision"
    );
    let current =
        crate::scenarios::consent_call_context::read_peer_current(&holder.client, &peer).await?;
    ensure!(
        current
            .current_permissions()
            .context("second correlation current")?
            == permissions.as_slice()
    );
    let mut relabeled = update.clone();
    relabeled.consent_id = second.consent_id.clone();
    relabeled.signature = proof(server, &holder.method)?;
    relabeled.signature.payload_digest = relabeled.payload_digest()?;
    relabeled.signature.jws = sign(
        &relabeled.unsigned_signature_binding_bytes(&relabeled.signature.unsigned())?,
        &holder.key,
    )?;
    let failure = sdk.mimi_update_consent(&relabeled).await.unwrap_err();
    ensure!(
        matches!(failure, arkret_http_client::Error::Api { ref error, .. } if error.code() == "not_found"),
        "accepted Event was relabeled onto another correlation: {failure:?}"
    );
    ensure!(counts(database, pcr.as_str()).await? == before_replay);

    // Each new decision gets its own explicit request correlation. An unknown
    // or accepted correlation cannot be relabeled to another Event or decision.
    let mut removal_request = request.clone();
    removal_request.proofs = vec![proof(server, &requester.method)?];
    removal_request.proofs[0].payload_digest = removal_request.payload_digest()?;
    removal_request.proofs[0].jws = sign(
        &removal_request.unsigned_proof_binding_bytes(&removal_request.proofs[0].unsigned())?,
        &requester.key,
    )?;
    let removal_correlation = sdk.mimi_request_consent(&removal_request).await?;
    ensure!(removal_correlation.consent_id != second.consent_id);
    let remove = holder
        .client
        .author_event(
            pcr.as_str(),
            EventKind::ConsentReplace.as_str(),
            json!({
                "peer":peer, "expected_current":current.expected_current(), "permissions":preserved
            }),
        )
        .await?;
    let mut deny = later;
    deny.consent_id = removal_correlation.consent_id;
    deny.decision = MimiConsentDecision::Deny;
    deny.consent_event = EventAdmissionSubmission::new(remove.clone());
    deny.signature = proof(server, &holder.method)?;
    deny.signature.payload_digest = deny.payload_digest()?;
    deny.signature.jws = sign(
        &deny.unsigned_signature_binding_bytes(&deny.signature.unsigned())?,
        &holder.key,
    )?;
    ensure!(sdk.mimi_update_consent(&deny).await?.event_ref == remove.event_id);
    let current =
        crate::scenarios::consent_call_context::read_peer_current(&holder.client, &peer).await?;
    ensure!(
        current
            .current_permissions()
            .context("remaining accepted revision")?
            == preserved.as_slice(),
        "removing an expired correlated permission changed an unrelated entry"
    );

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

    let mut native = crate::scenarios::mls_lifecycle_live::claim_request_between(
        &requester,
        server,
        server,
        holder,
        &RealmId::new(realm.to_owned())?,
        group.as_str(),
        [218; 16],
        chrono::Duration::minutes(5),
    )?;
    native.required_capabilities =
        vec![arkret_wire::NonEmptyString::new("mimi.content.v1").map_err(anyhow::Error::msg)?];
    native.strand_id = Some(StrandId::new(strand.to_owned())?);
    crate::scenarios::mls_lifecycle_live::resign_claim(&requester, &mut native)?;
    let key_request = native.clone();
    let failure = room_sdk
        .mimi_request_key_material(&key_request, server.trust_domain(), server.trust_domain())
        .await?;
    ensure!(
        failure.state == arkret_models_crypto::PeerKeyPackagesClaimQueryState::ClaimFailed
            && failure.claim_outcome.is_none()
            && failure.terminal_receipt.is_some(),
        "signed no-material key claim: {failure:?}"
    );
    let retained = crate::scenarios::mls_lifecycle_live::upload_durable_cut(database).await?;
    let retry = room_sdk
        .mimi_request_key_material(&key_request, server.trust_domain(), server.trust_domain())
        .await?;
    ensure!(
        serde_json::to_value(retry)? == serde_json::to_value(failure)?
            && crate::scenarios::mls_lifecycle_live::upload_durable_cut(database).await?
                == retained,
        "no-material recovery changed its original closed result"
    );
    ensure!(
        counts(database, realm).await? == before,
        "failed key claim emitted native Events or MIMI receipts"
    );
    eprintln!(
        "MIMI provider SDK: request correlations=3; Consent accepted/exact replay=2; expired-scope removal=1; requester-self/private-current refusals=2; hosting-provider-peer/Human-private-current refusals=2; wrong-key zero-write=1; room receipt/notify=2; signed no-material claim refusal=1; external-provider-live=0"
    );
    Ok(())
}

/// The existing provider uses this Station's real service signer. Its valid
/// peer signature still cannot open a Human holder's editing surface.
async fn reject_nonholder_current_reads(
    server: &ArkretServer,
    holder: &Member,
    requester: &Member,
    database: &str,
    present: bool,
) -> Result<Vec<Value>> {
    use arkret_models_collaboration::call_invitation::ConsentCurrentReadRequestBody;
    use arkret_models_collaboration::events_payloads::consent::{
        ConsentExpectedCurrent, ConsentPeer,
    };

    use crate::scenarios::invite_service_fanout_live::read_consent_set;

    let peer = ConsentPeer::Actor {
        actor_id: requester.actor.clone(),
    };
    let original = read_consent_set(&holder.client, &peer).await?;
    ensure!(
        matches!(&original.0, ConsentExpectedCurrent::Present { .. }) == present,
        "privacy probe did not use the intended actual holder current"
    );
    let nonce = || -> Result<String> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(anyhow::Error::msg)?;
        Ok(arkret_canonical::base64url_encode(bytes))
    };
    let mut request = ConsentCurrentReadRequestBody {
        holder_account_id: holder.account.clone(),
        peer,
        audience_actor_id: arkret_wire::ActorId::service(holder.account.station_id.clone()),
        nonce: nonce()?,
    };
    let before = private_current_footprint(database, holder).await?;
    // Use the authenticated request builder, not SDK input validation: this
    // must reach the receiver's exact holder comparison after session/DPoP.
    let response = requester
        .client
        .post("/_arkret/self/consent/current")
        .canonical_json(&request)?
        .send()
        .await?;
    ensure!(response.status() == StatusCode::FORBIDDEN);
    let requester_problem: Value = response.json().await?;
    let requester_problem = private_current_refusal(
        requester_problem,
        StatusCode::FORBIDDEN,
        "capability_denied",
    )?;
    ensure!(
        private_current_footprint(database, holder).await? == before,
        "requester private-current refusal changed accepted or pending business state"
    );

    request.nonce = nonce()?;
    let (status, body) = server
        .signed_peer_post(
            server,
            "/_arkret/peer/consent/current",
            &arkret_canonical::canonical_json_bytes(&request)?,
            server.service_id(),
        )
        .await?;
    // This is the already authenticated hosting service, also the provider
    // signer in this fixture. Human PCR forbids the peer read even for it.
    ensure!(status == StatusCode::CONFLICT);
    let provider_problem = private_current_refusal(
        serde_json::from_slice(&body)?,
        StatusCode::CONFLICT,
        "failed_precondition",
    )?;
    ensure!(
        private_current_footprint(database, holder).await? == before,
        "hosting-provider private-current refusal changed business state"
    );
    // Verify a fresh proof at the independent holder anchor, then compare the
    // actual source revision and complete permissions, never fresh proof bytes.
    ensure!(
        read_consent_set(&holder.client, &request.peer).await? == original,
        "private-current probes changed the holder's complete current"
    );
    Ok(vec![requester_problem, provider_problem])
}

fn private_current_refusal(mut problem: Value, status: StatusCode, code: &str) -> Result<Value> {
    ensure!(
        problem["type"] == format!("https://arkret.org/problems/{code}")
            && problem["status"] == status.as_u16(),
        "private-current refusal has the wrong registered error: {problem}"
    );
    fn contains_private_result(value: &Value) -> bool {
        match value {
            Value::Object(object) => object.iter().any(|(key, value)| {
                matches!(
                    key.as_str(),
                    "current"
                        | "result"
                        | "value"
                        | "state"
                        | "revision"
                        | "permissions"
                        | "commit_id"
                        | "stream_position"
                        | "effective_stream_head"
                        | "realm_id"
                        | "proof"
                        | "request_digest"
                ) || contains_private_result(value)
            }),
            Value::Array(values) => values.iter().any(contains_private_result),
            _ => false,
        }
    }
    ensure!(
        !contains_private_result(&problem),
        "private-current refusal disclosed a complete result or state: {problem}"
    );
    problem
        .as_object_mut()
        .context("private-current problem must be an object")?
        .remove("instance");
    Ok(problem)
}

async fn private_current_footprint(database: &str, holder: &Member) -> Result<String> {
    let database = database.to_owned();
    let holder_json = String::from_utf8(arkret_canonical::canonical_json_bytes(&holder.account)?)?;
    let realm = holder
        .client
        .principal
        .as_ref()
        .context("actual holder PCR")?
        .pcr_realm_id
        .to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db.query_one(
            "SELECT jsonb_build_object(\
             'current',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM consent_current_states r WHERE holder_account_id=$1::text::jsonb),\
             'versions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM consent_result_versions r JOIN realm_commits c ON c.commit_id=r.commit_id WHERE c.realm_id=$2),\
             'correlations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM mimi_consent_correlations r WHERE holder_account_id=$1),\
             'decisions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM mimi_consent_decision_attempts r JOIN mimi_consent_correlations c USING(consent_id) WHERE c.holder_account_id=$1),\
             'events',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM canonical_events r WHERE realm_id=$2),\
             'commits',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM realm_commits r WHERE realm_id=$2),\
             'authority',(SELECT to_jsonb(r) FROM realm_authorities r WHERE realm_id=$2)\
             )::text",
            &[&holder_json, &realm],
        )?.get(0))
    })
    .await?
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
