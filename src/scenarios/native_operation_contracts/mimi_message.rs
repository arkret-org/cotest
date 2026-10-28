//! Native MIMI content carries an actual encrypted MLS application envelope.
use arkret_models_collaboration::mimi_operations::{
    MimiSubmitMessageRequestBody, MimiSubmitMessageResponseBody,
};

use super::*;
use crate::harness::ArkretServer;
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    station: &ArkretServer,
    alice: &Member,
    bob: &Member,
    sender: &mut arkret::ArkretMlsGroup,
    recipient: &mut arkret::ArkretMlsGroup,
    realm: &arkret_wire::RealmId,
    state_ref: &arkret_wire::EventId,
    binding: &arkret_wire::CommittedEventFullView,
) -> Result<Value> {
    let room = binding
        .event
        .payload
        .get("mimi_room_uri")
        .and_then(Value::as_str)
        .context("actual accepted MIMI room")?;
    let strand = alice.client.default_strand_id(realm.as_str())?;
    let directory = crate::harness::expect_json(
        station
            .http()
            .get(station.url("/_arkret/open/mimi/provider-directory")),
        reqwest::StatusCode::OK,
    )
    .await?;
    let provider = directory["mimi"]["provider_id"]
        .as_str()
        .context("actual native provider")?;
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let plaintext = arkret_canonical::canonical_json_bytes(&arkret::ContentBlock::text(
        "Native MIMI MLS encrypted content",
    ))?;
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        arkret_wire::EventKind::MessageCreate.as_str(),
        sender.epoch(),
        state_ref.clone(),
        sender.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let before = sender.export_state_record()?.serialized_state;
    let sealed = arkret::MessageCrypto::encrypt(sender, mls::fresh_uuid_v7(), header, &plaintext)?;
    ensure!(
        before != sender.export_state_record()?.serialized_state,
        "MIMI producer did not advance its actual MLS ratchet"
    );
    let envelope = sealed.payload.to_envelope()?;
    let container = json!({"encrypted_content":envelope,"thread_id":strand});
    let ciphertext = arkret_canonical::canonical_json_bytes(&container)?;
    ensure!(
        !ciphertext
            .windows(plaintext.len())
            .any(|window| window == plaintext),
        "MIMI container leaked the clear content"
    );
    let state = mls::accepted_full_view(&alice.client, state_ref).await?;
    let governance = state
        .event
        .payload
        .get("governance_binding")
        .context("actual accepted MLS governance binding")?;
    let descriptor =
        arkret_canonical::canonical_json_bytes(&json!({"governance_binding":governance}))?;
    let request: MimiSubmitMessageRequestBody = serde_json::from_value(
        json!({"sender_actor_id":alice.actor,"device_id":alice.device,"ciphertext":{"content_type":"application/vnd.arkret.content+json","ciphertext_digest":arkret_canonical::sha256_digest(&ciphertext),"payload":arkret_canonical::base64url_encode(&ciphertext)},"mls_group_id":scope.canonical_mls_group_id()?,"epoch":sender.epoch().to_string(),"associated_data":{"content_type":"application/json","payload_digest":arkret_canonical::sha256_digest(&descriptor),"payload":arkret_canonical::base64url_encode(&descriptor)}}),
    )?;
    let (status, response) = crate::scenarios::mimi_facade_live::signed_post_inner(
        station,
        &format!("/_arkret/open/mimi/strands/{strand}/messages"),
        Some(room),
        provider,
        &json!(request),
        None,
    )
    .await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "actual encrypted MIMI message refused: {status} {response}"
    );
    let typed: MimiSubmitMessageResponseBody = serde_json::from_value(response.clone())?;
    let event_id = typed
        .event_ref
        .context("actual inbound MIMI mapping omitted its accepted Event")?;
    let committed = mls::accepted_full_view(&bob.client, &event_id).await?;
    ensure!(
        committed.event.actor_id != alice.actor
            && committed.event.actor_id.signing_principal_id() == station.service_id(),
        "facade impersonated the external sender"
    );
    let received: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
        serde_json::from_value(json!(committed.event.payload))?;
    let encrypted = received
        .encrypted_content
        .context("MIMI discarded the actual encrypted envelope")?;
    ensure!(
        json!(encrypted) == json!(envelope) && !committed.event.payload.contains_key("content"),
        "mapping exposed plaintext or rewrote the cryptographic envelope"
    );
    let provenance = committed
        .event
        .payload
        .get("mimi_provenance")
        .context("native MIMI attribution absent")?;
    ensure!(
        provenance["attributed_sender_actor_id"] == json!(alice.actor)
            && provenance["attributed_sender_device_id"] == json!(alice.device)
            && provenance["room_binding_ref"] == json!(binding.event.event_id)
            && provenance["source_envelope_digest"]
                == arkret_canonical::canonical_sha256(&request)?,
        "mapped attribution lost its exact source or accepted binding"
    );
    let sender_domain = String::from_utf8(arkret_models_crypto::mls_basic_credential_identity(
        &alice.actor,
    )?)?;
    let header = encrypted.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope,
        arkret_wire::EventKind::MessageCreate.as_str(),
        sender_domain,
        None,
    )?;
    let payload = arkret::encrypted_envelope_to_payload_with_verified_header(&encrypted, header)?;
    let opened = arkret::MessageCrypto::decrypt(
        recipient,
        &arkret::EncryptedMessage {
            message_id: event_id.to_string(),
            payload,
        },
    )?;
    ensure!(
        opened == plaintext,
        "actual MIMI recipient could not authenticate and decrypt the admitted ciphertext"
    );
    let database = station
        .owned_database_url()
        .context("native mapping receipt database")?
        .to_owned();
    let id = event_id.to_string();
    let receipt=tokio::task::spawn_blocking(move || ->Result<Value> {let mut db=postgres::Client::connect(&database,postgres::NoTls)?;let rows=db.query("SELECT payload FROM audit_logs WHERE action='mimi.content_mapping' AND payload->>'arkret_event_id'=$1",&[&id])?;ensure!(rows.len()==1,"mapping lacked its one durable native receipt");Ok(rows[0].get(0))}).await??;
    Ok(
        json!({"request":request,"response":response,"committed":committed,"mls_state":state,"binding":binding,"mapping_receipt":receipt,"plaintext_base64url":arkret_canonical::base64url_encode(&opened),"directory":directory}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
        .context("native mapping receipt schemas")?;
    let (identifier, document) = operation_schema_document(
        &artifacts,
        "schemas/mimi-interop.schema.json#/$defs/content_mapping_receipt",
    )?;
    let mut registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()?
        .context("native mapping receipt registry")?;
    registry.register(
        document["$id"]
            .as_str()
            .context("receipt document id")?
            .to_owned(),
        document,
    );
    registry.validate_value(&identifier, &evidence["mapping_receipt"])?;
    let view: arkret_wire::CommittedEventFullView =
        serde_json::from_value(evidence["committed"].clone())?;
    verify_native_station_commits(observations, &[view.clone()])?;
    view.event
        .verify_producer_proof_self_consistency(arkret_canonical::DigestSuite::Sha256)?;
    let proof = view
        .event
        .producer_proof
        .as_ref()
        .context("actual native facade producer proof")?;
    let did = arkret_identity::verification_method_did(proof.verification_method.as_str())?;
    let source = arkret_identifiers::project_did_to_core_id(&did)?;
    ensure!(
        view.event.actor_id == arkret_wire::ActorId::service(source.clone()),
        "producer history is not the exact facade service author"
    );
    let key = native_station_key(observations, &proof.verification_method, proof.created_at)?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &proof.jws,
        &proof.canonical_binding_bytes(&view.event.actor_id)?,
        &key,
    )?;
    let mut receipt = evidence["mapping_receipt"].clone();
    let receipt_proof: arkret_wire::PayloadProof = serde_json::from_value(
        receipt
            .as_object_mut()
            .context("actual receipt object")?
            .remove("proof")
            .context("actual receipt proof")?,
    )?;
    let key = native_station_key(
        observations,
        &receipt_proof.verification_method,
        receipt_proof.created_at,
    )?;
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(
        &receipt_proof,
        &arkret_canonical::canonical_json_bytes(&receipt)?,
        &key,
    )?;
    ensure!(
        receipt["arkret_event_id"] == json!(view.event.event_id)
            && receipt["original_envelope_digest"]
                == arkret_canonical::canonical_sha256(&evidence["request"])?,
        "mapping receipt substituted its original or mapped Event"
    );
    let exchange = original_exchange(observations, "ak.open.mimi.command.submit_message.v1")?;
    let input = verify_native_station_http_request(
        observations,
        exchange,
        &[
            arkret_signatures::http_signature::Component::Header("provider-id".into()),
            arkret_signatures::http_signature::Component::Header("mimi-room-uri".into()),
        ],
    )?;
    ensure!(
        input.expires - input.created <= 300
            && exchange.request_body == evidence["request"]
            && exchange.response_body == evidence["response"]
            && exchange.explicit_request_headers.get("source-service-id")
                == Some(&source.to_string()),
        "MIMI evidence does not bind its actual request and native facade"
    );
    Ok(())
}
