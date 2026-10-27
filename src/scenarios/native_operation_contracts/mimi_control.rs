//! MIMI facade control uses actual accounts, native commits and exact originals.
use arkret_models_collaboration::events_payloads::consent::{
    ConsentPeer, ConsentPermission, ConsentReplacePayload,
};
use arkret_models_collaboration::mimi_operations::*;
use arkret_models_collaboration::objects::mimi::{
    MimiConsentPurpose, MimiIdentifier, MimiIdentifierKind,
};
use arkret_wire::{
    CommittedEventRef, EventAdmissionSubmission, EventKind, Hash, UnsignedPayloadProof,
};

use super::*;
use crate::harness::ArkretServer;
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

pub(super) const SCOPE: [&str; 5] = [
    "ak.open.mimi.command.update_room.v1",
    "ak.open.mimi.command.request_consent.v1",
    "ak.open.mimi.command.update_consent.v1",
    "ak.open.mimi.command.report_abuse.v1",
    "ak.open.mimi.read.identifiers.v1",
];
async fn post<T: serde::Serialize>(
    server: &ArkretServer,
    provider: &str,
    room: Option<&str>,
    path: &str,
    body: &T,
) -> Result<Value> {
    let (status, value) = crate::scenarios::mimi_facade_live::signed_post_inner(
        server,
        path,
        room,
        provider,
        &serde_json::to_value(body)?,
        None,
    )
    .await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "native MIMI {path}: {status} {value}"
    );
    Ok(value)
}
fn unsigned(
    member: &Member,
    station: &ArkretServer,
    digest: Hash,
    domain: &str,
) -> UnsignedPayloadProof {
    UnsignedPayloadProof {
        kind: "detached_jws".into(),
        verification_method: member.method.clone(),
        payload_digest: digest,
        created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        domain: Some(domain.into()),
        audience: Some(arkret_wire::Audience::Single(
            station.service_id().to_string(),
        )),
        proof_purpose: None,
    }
}
fn sign(
    member: &Member,
    proof: UnsignedPayloadProof,
    bytes: &[u8],
) -> Result<arkret_wire::PayloadProof> {
    let jws = arkret_signatures::Ed25519DetachedJwsSigner::new(
        member.key.clone(),
        member.method.to_string(),
    )
    .sign_detached_jws(bytes);
    Ok(proof.finalize(jws)?)
}
fn coordinate(view: &arkret_wire::CommittedEventFullView) -> CommittedEventRef {
    CommittedEventRef {
        event_id: view.event.event_id.clone(),
        commit_id: view.commit.commit_id.clone(),
        stream_ref: view.commit.stream_ref.clone(),
        stream_position: view.commit.stream_position,
    }
}
async fn snapshot(database: &str, realm: &arkret_wire::RealmId) -> Result<Value> {
    let database = database.to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move ||->Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;let mut value=serde_json::Map::new();
        for table in ["mimi_consent_correlations","mimi_consent_decision_attempts"] {
            let rows=db.query(&format!("SELECT to_jsonb(t) FROM {table} t ORDER BY to_jsonb(t)::text"),&[])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();value.insert(table.into(),json!(rows));
        }
        let rows=db.query("SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json) FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.realm_id=$1 AND e.state='committed' ORDER BY c.stream_ref::text,c.stream_position",&[&realm])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();value.insert("committed".into(),json!(rows));
        Ok(Value::Object(value))
    }).await?
}

pub(super) async fn exercise(
    server: &ArkretServer,
    alice: &Member,
    bob: &Member,
    realm: &arkret_wire::RealmId,
    group: &arkret_wire::MlsGroupId,
    joined: &arkret_wire::CommittedEventFullView,
) -> Result<Value> {
    let database = server.owned_database_url().context("owned MIMI database")?;
    let directory = crate::harness::expect_json(
        server
            .http()
            .get(server.url("/_arkret/open/mimi/provider-directory")),
        reqwest::StatusCode::OK,
    )
    .await?;
    let provider = directory["mimi"]["provider_id"]
        .as_str()
        .context("native provider identifier")?;
    let strand = alice.client.default_strand_id(realm.as_str())?;
    let room = format!("{provider}/rooms/{strand}");
    let binding_payload = json!({"profile":"ak.profile.mimi_interop.v1","mimi_room_uri":room,"binding_scope":{"realm_id":realm,"strand_id":strand},"hub_provider_id":server.service_id(),"local_provider_role":"hub","status":"accepted","mls_group_id":group});
    let binding_event = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::MimiRoomBinding.as_str(),
            binding_payload.clone(),
        )
        .await?;
    let bytes = arkret_canonical::canonical_json_bytes(
        &json!({"kind":EventKind::MimiRoomBinding,"payload":binding_payload}),
    )?;
    let binding_request: MimiRoomUpdateRequestBody = serde_json::from_value(
        json!({"mls_group_id":group,"sender_actor_id":alice.actor,"room_binding_event":EventAdmissionSubmission::new(binding_event.clone()),"update":{"kind":EventKind::MimiRoomBinding,"payload":{"content_type":"application/json","payload_digest":arkret_canonical::sha256_digest(&bytes),"payload":arkret_canonical::base64url_encode(&bytes)}}}),
    )?;
    binding_request.validate()?;
    let bound = post(
        server,
        provider,
        Some(&room),
        &format!("/_arkret/open/mimi/strands/{strand}/update"),
        &binding_request,
    )
    .await?;
    ensure!(
        bound["accepted"] == true && bound["room_state_ref"] == json!(binding_event.event_id),
        "MIMI did not admit the exact caller-signed binding"
    );
    let bound_commit = mls::accepted_full_view(&alice.client, &binding_event.event_id).await?;
    ensure!(
        bound_commit.event == binding_event,
        "MIMI rewrote the caller Event"
    );
    let replay = post(
        server,
        provider,
        Some(&room),
        &format!("/_arkret/open/mimi/strands/{strand}/update"),
        &binding_request,
    )
    .await?;
    ensure!(
        replay == bound,
        "room binding exact retry changed its original"
    );
    let claim_material = crate::harness::heap_future(|| {
        super::mimi_claim::exercise(server, alice, bob, realm, group, &room)
    })
    .await?;
    let before_receipt = snapshot(database, realm).await?;
    let bytes = arkret_canonical::canonical_json_bytes(
        &json!({"kind":"m.room.name","name":"native provider room update"}),
    )?;
    let receipt_request: MimiRoomUpdateRequestBody = serde_json::from_value(
        json!({"mls_group_id":group,"update":{"kind":"m.room.name","payload":{"content_type":"application/json","payload_digest":arkret_canonical::sha256_digest(&bytes),"payload":arkret_canonical::base64url_encode(&bytes)}}}),
    )?;
    receipt_request.validate()?;
    let receipt = post(
        server,
        provider,
        Some(&room),
        &format!("/_arkret/open/mimi/strands/{strand}/update"),
        &receipt_request,
    )
    .await?;
    let after_receipt = snapshot(database, realm).await?;
    ensure!(
        receipt["accepted"] == true
            && receipt.get("room_state_ref").is_none()
            && before_receipt == after_receipt,
        "receipt-only room branch wrote a native Event"
    );
    let identifier_values = [
        ("did", alice.account.principal_id.to_string()),
        ("opaque", bob.account.principal_id.to_string()),
    ];
    let identifiers = identifier_values
        .iter()
        .map(|(kind, value)| -> Result<MimiIdentifier> {
            Ok(MimiIdentifier {
                kind: serde_json::from_value::<MimiIdentifierKind>(json!(kind))?,
                identifier_commitment: Hash::new(arkret_canonical::sha256_digest(
                    value.as_bytes(),
                ))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let identifier_request = MimiIdentifierQueryRequestBody {
        identifiers,
        requester_id: None,
        privacy_profile: None,
        proofs: vec![],
    };
    let identifiers = post(
        server,
        provider,
        None,
        "/_arkret/open/mimi/identifiers/query",
        &identifier_request,
    )
    .await?;
    let matched: MimiIdentifierQueryResponseBody = serde_json::from_value(identifiers.clone())?;
    ensure!(
        !matched.has_more
            && matched.proofs.is_empty()
            && matched.matches.len() == identifier_request.identifiers.len(),
        "identifier response changed the closed no-discovery result"
    );
    for (expected, actual) in identifier_request.identifiers.iter().zip(&matched.matches) {
        ensure!(
            actual.identifier_commitment == expected.identifier_commitment
                && !actual.matched
                && actual.subject_id.is_none()
                && actual.mimi_uri.is_none(),
            "MIMI manufactured identity discovery"
        );
    }
    let mut request = MimiRequestConsentRequestBody {
        requester_actor_id: bob.actor.clone(),
        holder_account_id: alice.account.clone(),
        purpose: MimiConsentPurpose::VoiceCall,
        strand_id: Some(strand.parse()?),
        expires_at: None,
        proofs: vec![],
    };
    let proof = unsigned(
        bob,
        server,
        request.payload_digest()?,
        server.trust_domain().as_str(),
    );
    let bytes = request.unsigned_proof_binding_bytes(&proof)?;
    request.proofs.push(sign(bob, proof, &bytes)?);
    request.validate()?;
    let correlation = post(
        server,
        provider,
        None,
        "/_arkret/open/mimi/consent/request",
        &request,
    )
    .await?;
    let first: MimiRequestConsentResponseBody = serde_json::from_value(correlation.clone())?;
    let after_request = snapshot(database, realm).await?;
    let peer = ConsentPeer::Actor {
        actor_id: bob.actor.clone(),
    };
    let current =
        crate::scenarios::consent_call_context::read_peer_current(&alice.client, &peer).await?;
    let event = alice
        .client
        .author_event(
            alice
                .client
                .principal
                .as_ref()
                .context("holder original PCR")?
                .pcr_realm_id
                .as_str(),
            EventKind::ConsentReplace.as_str(),
            serde_json::to_value(ConsentReplacePayload {
                peer: peer.clone(),
                expected_current: current.expected_current(),
                permissions: vec![ConsentPermission {
                    consent_scope: arkret_wire::ConsentScope::VoiceCall,
                    not_before: None,
                    expires_at: None,
                    constraints: None,
                    evidence_ref: None,
                    reason: None,
                }],
            })?,
        )
        .await?;
    let unsigned_body = json!({"consent_id":first.consent_id,"decision":"accept","actor_id":alice.actor,"consent_event":EventAdmissionSubmission::new(event.clone())});
    let proof = unsigned(
        alice,
        server,
        Hash::new(arkret_canonical::canonical_sha256(&unsigned_body)?)?,
        server.trust_domain().as_str(),
    );
    let bytes = arkret_wire::service_operation_proof_binding_bytes(
        arkret_wire::ProofContextId::MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT_V1,
        Some(json!(alice.actor)),
        vec![
            ("consent_id", json!(first.consent_id)),
            ("decision", json!("accept")),
        ],
        &proof.payload_digest,
        &proof,
    )?;
    let mut value = unsigned_body;
    value["signature"] = serde_json::to_value(sign(alice, proof, &bytes)?)?;
    let update: MimiUpdateConsentRequestBody = serde_json::from_value(value)?;
    update.validate_consent_event()?;
    ensure!(
        update.signature_binding_bytes()? == bytes,
        "producer and SDK disagree on Consent transcript"
    );
    let accepted = post(
        server,
        provider,
        None,
        "/_arkret/open/mimi/consent/update",
        &update,
    )
    .await?;
    let replay = post(
        server,
        provider,
        None,
        "/_arkret/open/mimi/consent/update",
        &update,
    )
    .await?;
    ensure!(
        accepted == replay && accepted["event_ref"] == json!(event.event_id),
        "Consent did not retain its exact accepted Event"
    );
    let consent_commit = mls::accepted_full_view(&alice.client, &event.event_id).await?;
    let consent_current =
        crate::scenarios::consent_call_context::read_peer_current(&alice.client, &peer).await?;
    ensure!(
        consent_commit.event == event
            && consent_current
                .current_permissions()
                .context("accepted complete Consent")?
                .len()
                == 1,
        "accepted Consent replacement was not the exact original"
    );
    let after_update = snapshot(database, realm).await?;
    let expires = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::minutes(3),
    );
    let unsigned_report = json!({"reporter_authority":{"actor_id":bob.actor,"membership_ref":coordinate(joined),"room_binding_ref":coordinate(&bound_commit),"expires_at":arkret_canonical::format_timestamp_canonical(expires)},"report_claim":{"realm_id":realm,"scope_ref":{"kind":"realm","realm_id":realm},"target_ref":realm,"report_reason_code":"spam"}});
    let proof = unsigned(
        bob,
        server,
        Hash::new(arkret_canonical::canonical_sha256(&unsigned_report)?)?,
        arkret_wire::DomainSeparationId::MIMI_REPORTER_AUTHORITY_PROOF_V1,
    );
    let bytes = arkret_wire::service_operation_proof_binding_bytes(
        arkret_wire::DomainSeparationId::MIMI_REPORTER_AUTHORITY_PROOF_V1,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_REPORT_ABUSE_V1,
        Some(json!(bob.actor)),
        vec![
            ("report_claim", unsigned_report["report_claim"].clone()),
            ("membership_ref", json!(coordinate(joined))),
            ("room_binding_ref", json!(coordinate(&bound_commit))),
            (
                "expires_at",
                unsigned_report["reporter_authority"]["expires_at"].clone(),
            ),
        ],
        &proof.payload_digest,
        &proof,
    )?;
    let mut value = unsigned_report;
    value["reporter_authority"]["proof"] = serde_json::to_value(sign(bob, proof, &bytes)?)?;
    let report: MimiReportAbuseRequestBody = serde_json::from_value(value)?;
    report.validate()?;
    ensure!(
        report.reporter_authority_binding_bytes()? == bytes,
        "producer and SDK disagree on report transcript"
    );
    let reported = post(
        server,
        provider,
        None,
        "/_arkret/open/mimi/report-abuse",
        &report,
    )
    .await?;
    let report_replay = post(
        server,
        provider,
        None,
        "/_arkret/open/mimi/report-abuse",
        &report,
    )
    .await?;
    ensure!(
        reported == report_replay,
        "report retry changed its accepted original"
    );
    let after_report = snapshot(database, realm).await?;
    let reports = after_report["committed"]
        .as_array()
        .context("actual committed reports")?
        .iter()
        .filter(|row| row["event"]["kind"] == json!(EventKind::SelfModerationReport))
        .collect::<Vec<_>>();
    let [original] = reports.as_slice() else {
        anyhow::bail!("native facade did not commit exactly one report")
    };
    let report_view: arkret_wire::CommittedEventFullView =
        serde_json::from_value((*original).clone())?;
    ensure!(
        reported["report_id"]
            == json!(arkret_wire::ReportId::from_event_id(
                &report_view.event.event_id
            ))
            && report_view.event.actor_id
                == arkret_wire::ActorId::service(server.service_id().clone()),
        "facade report response lacks its real Service-authored accepted Event"
    );
    Ok(
        json!({"claim_material":claim_material,"directory":directory,"binding_request":binding_request,"bound":bound,"binding_commit":bound_commit,"receipt_request":receipt_request,"receipt":receipt,"before_receipt":before_receipt,"after_receipt":after_receipt,"identifier_request":identifier_request,"identifiers":identifiers,"consent_request":request,"correlation":correlation,"after_request":after_request,"consent_update":update,"consent_accepted":accepted,"consent_replay":replay,"consent_commit":consent_commit,"consent_current":consent_current,"after_update":after_update,"report_request":report,"reported":reported,"report_replay":report_replay,"report_commit":report_view,"after_report":after_report}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    use arkret_signatures::http_signature::Component;
    let directory: arkret_models_collaboration::objects::interop::ProviderDirectory =
        serde_json::from_value(evidence["directory"].clone())?;
    directory.validate()?;
    let proof = &directory.proof.0;
    ensure!(
        proof.payload_digest == directory.payload_digest()?,
        "provider directory changed its signed original"
    );
    let key = native_station_key(observations, &proof.verification_method, proof.created_at)?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &proof.jws,
        &directory.proof_binding_bytes()?,
        &key,
    )?;
    for exchange in &observations.exchanges {
        if !SCOPE.contains(&exchange.operation_id.as_str()) {
            continue;
        }
        let input = super::verify_native_station_http_request(
            observations,
            exchange,
            &[Component::Header("provider-id".into())],
        )?;
        let headers = &exchange.explicit_request_headers;
        ensure!(
            headers.get("provider-id").map(String::as_str)
                == Some(directory.mimi.provider_id.as_str())
                && headers.get("source-service-id").map(String::as_str)
                    == Some(directory.service_id.as_str())
                && headers.get("destination-service-id").map(String::as_str)
                    == Some(directory.service_id.as_str()),
            "MIMI changed its actual provider/receiver"
        );
        if exchange
            .url
            .parse::<reqwest::Url>()?
            .path()
            .contains("/strands/")
        {
            ensure!(
                input.covers_all(&[Component::Header("mimi-room-uri".into())])
                    && headers
                        .get("mimi-room-uri")
                        .is_some_and(|room| room.starts_with(directory.mimi.provider_id.as_str())),
                "MIMI transport lost its actual room binding"
            );
        }
    }
    super::mimi_claim::verify(observations, &evidence["claim_material"])?;
    let views = ["binding_commit", "report_commit"]
        .into_iter()
        .map(|name| serde_json::from_value(evidence[name].clone()))
        .collect::<std::result::Result<Vec<arkret_wire::CommittedEventFullView>, _>>()?;
    verify_native_station_commits(observations, &views)?;
    let consent: arkret_wire::CommittedEventFullView =
        serde_json::from_value(evidence["consent_commit"].clone())?;
    verify_native_pcr_commits(observations, &[consent])?;
    Ok(())
}
