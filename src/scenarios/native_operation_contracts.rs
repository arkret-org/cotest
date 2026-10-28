//! Operation-level native contracts. Observations and declarations are not coverage.
use anyhow::{Context as _, Result, ensure};
use cotest_test_support::operation_observation::{NativeOperationObservations, observe};
use serde_json::{Value, json};

mod account_logout;
mod actor_private;
mod media_token;
mod mimi_message;
mod mimi_notify;
mod peer_contacts;
mod peer_events;
mod peer_invite;
mod peer_keypackage_claims;
mod peer_watch;
mod realm_invite_links;
mod watch_audit;

pub async fn realm_invite_links() -> Result<()> {
    crate::harness::heap_future(realm_invite_links::run).await
}

pub async fn peer_contacts() -> Result<()> {
    validate_registered_schema_bindings()?;
    crate::harness::heap_future(peer_contacts::run).await
}

pub async fn peer_keypackage_claims() -> Result<()> {
    validate_registered_schema_bindings()?;
    crate::harness::heap_future(peer_keypackage_claims::run).await
}

mod blob_presign;
mod consent;
mod device_pairing;
mod identity_reservations;
mod mimi_claim;
mod mimi_control;
mod mls_attest_add;
mod mls_interop;

pub async fn blob_presign() -> Result<()> {
    validate_registered_schema_bindings()?;
    blob_presign::run().await
}

mod organization_registrations;
mod peer_membership_reads;
mod peer_signal;
mod policy_recovery;
mod private_storage;
mod service_registrations;

pub async fn organization_registrations() -> Result<()> {
    validate_registered_schema_bindings()?;
    organization_registrations::run().await
}

pub async fn service_registrations() -> Result<()> {
    validate_registered_schema_bindings()?;
    service_registrations::run().await
}

pub async fn identity_reservations() -> Result<()> {
    validate_registered_schema_bindings()?;
    identity_reservations::run().await
}

pub async fn account_consent() -> Result<()> {
    validate_registered_schema_bindings()?;
    consent::run().await
}

pub async fn mls_interop() -> Result<()> {
    validate_registered_schema_bindings()?;
    crate::harness::heap_future(mls_interop::run).await
}

pub async fn account_private_storage() -> Result<()> {
    validate_registered_schema_bindings()?;
    private_storage::run().await
}
mod session_grants;

pub async fn account_policy_recovery() -> Result<()> {
    validate_registered_schema_bindings()?;
    policy_recovery::run().await
}

pub async fn account_device_pairing() -> Result<()> {
    validate_registered_schema_bindings()?;
    device_pairing::run().await
}

pub async fn account_device_sessions() -> Result<()> {
    validate_registered_schema_bindings()?;
    session_grants::run().await
}

const OBLIGATIONS: &str = include_str!("../../tests/fixtures/native-operation-contracts.json");

fn retain_attempt(name: &str, observations: &NativeOperationObservations) -> Result<()> {
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        let name = format!(
            "attempt-{name}-{}.json",
            chrono::Utc::now().timestamp_millis()
        );
        std::fs::write(
            std::path::PathBuf::from(directory).join(name),
            serde_json::to_vec_pretty(
                &json!({"status":"observed_not_verified","observations":observations}),
            )?,
        )?;
    }
    Ok(())
}
fn retain_diagnostic(name: &str, diagnostic: &Value) -> Result<()> {
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join(format!(
                "diagnostic-{name}-{}.json",
                chrono::Utc::now().timestamp_millis()
            )),
            serde_json::to_vec_pretty(diagnostic)?,
        )?;
    }
    Ok(())
}
const ACCOUNT_CREATION: [&str; 4] = [
    "ak.gate.account.exchange.create_handoff.v1",
    "ak.gate.account.command.issue_identity_binding_challenge.v1",
    "ak.gate.account.command.register.v1",
    "ak.gate.account.read.onboarding.v1",
];

fn operation_schema_document(
    artifacts: &std::path::Path,
    reference: &str,
) -> Result<(String, Value)> {
    let (file, fragment) = reference.split_once('#').unwrap_or((reference, ""));
    ensure!(
        file.starts_with("schemas/") && !file.split('/').any(|part| part == ".."),
        "operation schema escapes the normative schema directory"
    );
    let document: Value = serde_json::from_slice(&std::fs::read(artifacts.join(file))?)?;
    let identifier = document["$id"]
        .as_str()
        .context("normative schema document has no $id")?;
    let identifier = if fragment.is_empty() {
        identifier.to_owned()
    } else {
        format!("{identifier}#{fragment}")
    };
    Ok((identifier, document))
}

pub fn validate_registered_schema_bindings() -> Result<()> {
    let obligations: Value = serde_json::from_str(OBLIGATIONS)?;
    let mut registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()?
        .context("schema registry absent")?;
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
        .context("schema artifacts absent")?;
    let mut documents = std::collections::BTreeSet::new();
    for operation in obligations["operations"]
        .as_array()
        .context("native operations absent")?
    {
        let operation_id = arkret_wire::ServiceOperationId::from_wire(
            operation["operation_id"]
                .as_str()
                .context("native operation id absent")?,
        )
        .context("native operation is not registered")?;
        let descriptor = operation_id.descriptor();
        for reference in [
            descriptor.request_schema_ref,
            descriptor.response_schema_ref,
        ]
        .into_iter()
        .flatten()
        {
            let (identifier, document) = operation_schema_document(&artifacts, reference)?;
            let document_id = document["$id"]
                .as_str()
                .context("schema document id absent")?
                .to_owned();
            if documents.insert(document_id.clone()) {
                registry.register(document_id, document);
            }
            ensure!(
                registry.schema(&identifier).is_some(),
                "native operation schema reference did not resolve exactly once: {} {reference}",
                operation_id.as_str()
            );
        }
    }
    Ok(())
}

fn validate_exchange_schemas(
    observations: &NativeOperationObservations,
    required: &[&str],
) -> Result<()> {
    verify_native_issuer_bindings(observations)?;
    let obligations: Value = serde_json::from_str(OBLIGATIONS)?;
    obligations["operations"]
        .as_array()
        .context("native obligations absent")?;
    let mut registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()?
        .context("native operation schemas are unavailable")?;
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir()
        .context("native operation schema artifacts are unavailable")?;
    let mut documents = std::collections::BTreeSet::new();
    // A symbolic registry id can already name one fragment. Validate each
    // operation's exact JSON Pointer using its normative document's own $id.
    let mut validate = |reference: &str, value: &Value| -> Result<()> {
        let (identifier, document) = operation_schema_document(&artifacts, reference)?;
        let document_id = document["$id"]
            .as_str()
            .context("schema document id absent")?
            .to_owned();
        if documents.insert(document_id.clone()) {
            registry.register(document_id, document);
        }
        registry.validate_value(&identifier, value)?;
        Ok(())
    };
    let mut validate_operations = required
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    for exchange in &observations.exchanges {
        if obligations["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["operation_id"] == exchange.operation_id.as_str())
        {
            validate_operations.insert(exchange.operation_id.as_str());
        }
    }
    for identifier in validate_operations {
        obligations["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["operation_id"] == identifier)
            .context("native operation obligation missing")?;
        let descriptor = arkret_wire::ServiceOperationId::from_wire(identifier)
            .context("native operation is not registered")?
            .descriptor();
        let matching = observations
            .exchanges
            .iter()
            .filter(|row| row.operation_id.as_str() == identifier)
            .collect::<Vec<_>>();
        ensure!(
            !matching.is_empty(),
            "no successful actual request for {identifier}"
        );
        for row in matching {
            let request_bytes = arkret_canonical::base64url_decode(&row.request_json_base64url)?;
            if let Some(reference) = descriptor.request_schema_ref {
                validate(reference, &row.request_body)?;
                ensure!(
                    serde_json::from_slice::<Value>(&request_bytes)? == row.request_body,
                    "request bytes differ from observed input"
                );
            } else {
                ensure!(
                    request_bytes.is_empty() && row.request_body.is_null(),
                    "bodyless operation carried invented request JSON"
                );
            }
            if row.operation_id.descriptor().success_shape_kind == "empty_response" {
                ensure!(
                    descriptor.response_schema_ref.is_none()
                        && row.response_body.is_null()
                        && row.decoded_response_bytes_base64url.is_empty(),
                    "empty response carried invented JSON"
                );
            } else {
                validate(
                    descriptor
                        .response_schema_ref
                        .context("typed response schema absent")?,
                    &row.response_body,
                )?;
                ensure!(
                    serde_json::from_slice::<Value>(&arkret_canonical::base64url_decode(
                        &row.decoded_response_bytes_base64url
                    )?)? == row.response_body,
                    "response bytes differ from observed output"
                );
            }
        }
    }
    Ok(())
}

fn original_exchange<'a>(
    observations: &'a NativeOperationObservations,
    operation: &str,
) -> Result<&'a cotest_test_support::operation_observation::ObservedOperationExchange> {
    observations
        .exchanges
        .iter()
        .find(|row| row.operation_id.as_str() == operation)
        .context("native exchange absent")
}

fn native_station_resolution(
    observations: &NativeOperationObservations,
    service: &arkret_wire::DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_models_identity::AuthenticatedServiceResolution> {
    for material in &observations.accepted_identity_material {
        let resolution: arkret_models_identity::AuthenticatedServiceResolution =
            serde_json::from_value(material["station_resolution"].clone())?;
        if resolution.service_id != *service {
            continue;
        }
        ensure!(
            resolution.service_kind == arkret_wire::ServiceKind::Station.as_str(),
            "native authority is not an admitted Station"
        );
        arkret_identity::verify_authenticated_service_resolution_history(&resolution, service, at)?;
        return Ok(resolution);
    }
    anyhow::bail!("native request has no independently admitted exact Station history")
}

fn verify_native_issuer_bindings(observations: &NativeOperationObservations) -> Result<()> {
    let expected = observations
        .accepted_identity_material
        .iter()
        .map(|material| {
            serde_json::from_value::<arkret_models_identity::AuthenticatedServiceResolution>(
                material["station_resolution"].clone(),
            )
            .map(|resolution| resolution.service_id)
        })
        .collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()?;
    ensure!(
        !expected.is_empty() && observations.issuer_bindings.len() == expected.len(),
        "native authority requires one actual AA original binding for every admitted Station"
    );
    let mut actual = std::collections::BTreeSet::new();
    for binding in &observations.issuer_bindings {
        let floor = crate::scenarios::_helpers::native_issuer_binding::verify(binding)?;
        let admitted =
            native_station_resolution(observations, &floor.service_id, chrono::Utc::now())?;
        arkret_identity::verify_service_resolution_floor(&admitted, &floor)?;
        ensure!(
            actual.insert(floor.service_id),
            "duplicate native issuer binding"
        );
    }
    ensure!(
        actual == expected,
        "native AA original binding names a different Station"
    );
    Ok(())
}

fn native_station_key(
    observations: &NativeOperationObservations,
    method: &arkret_wire::DidUrl,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_signatures::PublicKeyMaterial> {
    let did = arkret_identity::verification_method_did(method.as_str())?;
    let service = arkret_identifiers::project_did_to_core_id(&did)?;
    let resolution = native_station_resolution(observations, &service, at)?;
    ensure!(
        resolution.normalized_did_document.id == did,
        "native signer differs from its independently admitted Station"
    );
    for material in &observations.accepted_identity_material {
        let history: arkret_models_identity::IdentityLogListResponseBody =
            serde_json::from_value(material["account_authority_history"].clone())?;
        if history.did != did {
            continue;
        }
        let point =
            arkret_signatures::webvh::validate_webvh_history_at(&did, &history.entries, at)?;
        let document: arkret_identity::DidDocument = serde_json::from_value(point.document)?;
        arkret_identity::validate_verification_method_relationship(
            &document,
            method,
            &did,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )?;
        return Ok(arkret_identity::public_key_material_from_document(
            &document, method,
        )?);
    }
    anyhow::bail!("native signer has no exact admitted historical key source")
}

fn verify_native_station_keypackage_signature(
    observations: &NativeOperationObservations,
    signature: &arkret_models_crypto::KeyOperationSignature,
    at: chrono::DateTime<chrono::Utc>,
    bytes: &[u8],
) -> Result<()> {
    let method =
        arkret_wire::DidUrl::new(signature.kid.as_str().to_owned()).map_err(anyhow::Error::msg)?;
    let arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: key } =
        native_station_key(observations, &method, at)?
    else {
        anyhow::bail!("native receipt requires Ed25519");
    };
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &key.try_into()
            .map_err(|_| anyhow::anyhow!("native receipt key length"))?,
        method.as_str(),
        bytes,
        signature,
    )?;
    Ok(())
}

fn verify_native_station_http_request(
    observations: &NativeOperationObservations,
    exchange: &cotest_test_support::operation_observation::ObservedOperationExchange,
    additional: &[arkret_signatures::http_signature::Component],
) -> Result<arkret_signatures::http_signature::SignatureInput> {
    use arkret_signatures::http_signature::{
        self as http, Component, ContentDigest, SignedRequestParts,
    };
    use base64::Engine as _;
    let headers = &exchange.explicit_request_headers;
    let field = |name: &str| {
        headers
            .get(name)
            .with_context(|| format!("native signed header {name}"))
    };
    let input = http::parse_signature_input(field("signature-input")?)?;
    let required = [
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header("arkret-operation".into()),
        Component::Header("content-digest".into()),
        Component::Header("source-service-id".into()),
        Component::Header("destination-service-id".into()),
    ];
    ensure!(
        input.algorithm == "ed25519" && input.covers_all(&required) && input.covers_all(additional),
        "native request lost its exact signed identity or operation"
    );
    let url: reqwest::Url = exchange.url.parse()?;
    let authority = url.port().map_or_else(
        || url.host_str().unwrap_or_default().to_owned(),
        |port| format!("{}:{port}", url.host_str().unwrap_or_default()),
    );
    let raw = arkret_canonical::base64url_decode(&exchange.request_json_base64url)?;
    let digest = ContentDigest::parse(field("content-digest")?)?;
    http::verify_content_digest(&digest, &raw)?;
    let bytes = http::canonical_message(
        &SignedRequestParts {
            method: exchange.method.clone(),
            target_uri: exchange.url.clone(),
            authority,
            path: url.path().into(),
            headers: headers
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            body_digest: Some(digest.wire_value),
        },
        &input,
    )?;
    let method = arkret_wire::DidUrl::new(&input.key_id).map_err(anyhow::Error::msg)?;
    let did = arkret_identity::verification_method_did(method.as_str())?;
    let source = arkret_identifiers::project_did_to_core_id(&did)?;
    ensure!(
        field("source-service-id")? == source.as_str()
            && field("arkret-operation")? == exchange.operation_id.as_str(),
        "native transport substituted its accepted source or selector"
    );
    let created =
        chrono::DateTime::from_timestamp(input.created, 0).context("native signing time")?;
    let destination = arkret_wire::DidCoreId::new(field("destination-service-id")?)
        .map_err(anyhow::Error::msg)?;
    let receiver = native_station_resolution(observations, &destination, created)?;
    let endpoint: reqwest::Url = receiver.projection()?.base_url.parse()?;
    ensure!(
        url.origin() == endpoint.origin()
            && url
                .path()
                .starts_with(endpoint.path().trim_end_matches('/')),
        "native destination URL is outside its independently verified service route"
    );
    let key = native_station_key(observations, &method, created)?;
    let signature = http::parse_signature_header(field("signature")?, &input.label)?;
    http::verify_signature(
        &bytes,
        &base64::engine::general_purpose::STANDARD.encode(signature),
        &ed25519_dalek::VerifyingKey::from_bytes(&key.ed25519_bytes()?)?,
    )?;
    let observed = chrono::DateTime::parse_from_rfc3339(&exchange.observed_at)?.timestamp();
    ensure!(
        input.expires > input.created
            && input.expires - input.created <= 300
            && observed >= input.created - 1
            && observed <= input.expires,
        "native transport was not fresh at its actual execution"
    );
    Ok(input)
}

fn verify_native_station_commits(
    observations: &NativeOperationObservations,
    views: &[arkret_wire::CommittedEventFullView],
) -> Result<()> {
    let material = observations
        .accepted_identity_material
        .first()
        .context("verified PCR founding material absent")?;
    let history: arkret_models_identity::IdentityLogListResponseBody =
        serde_json::from_value(material["account_authority_history"].clone())?;
    for view in views {
        view.validate_shape()?;
        view.commit.validate_content_address()?;
        view.event
            .verify_event_id_matches_content_with_digest_suite(
                arkret_canonical::DigestSuite::Sha256,
            )?;
        let did = arkret_identity::verification_method_did(
            view.commit.signature.verification_method.as_str(),
        )?;
        ensure!(
            did == history.did,
            "PCR commit signer differs from the verified native history"
        );
        let point = arkret_signatures::webvh::validate_webvh_history_at(
            &did,
            &history.entries,
            view.commit.signature.created_at,
        )?;
        let document: arkret_identity::DidDocument = serde_json::from_value(point.document)?;
        arkret_identity::validate_verification_method_relationship(
            &document,
            &view.commit.signature.verification_method,
            &did,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )?;
        let key = arkret_identity::public_key_material_from_document(
            &document,
            &view.commit.signature.verification_method,
        )?;
        arkret_signatures::detached_object::verify_detached_object_signature(
            &view.commit.signature,
            &arkret_canonical::canonical::unsigned_value(&view.commit, &["signature"])?,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &key,
        )?;
    }
    Ok(())
}

fn verify_native_pcr_commits(
    observations: &NativeOperationObservations,
    views: &[arkret_wire::CommittedEventFullView],
) -> Result<()> {
    let material = observations
        .accepted_identity_material
        .first()
        .context("verified PCR founding material absent")?;
    let registration: arkret_models_collaboration::account_operations::AccountRegisterRequestBody =
        serde_json::from_value(material["register_request"].clone())?;
    let genesis = &registration
        .identity_creation
        .as_ref()
        .context("founding unit absent")?
        .pcr_genesis_unit
        .events[0];
    for view in views {
        ensure!(
            view.commit.realm_id == genesis.realm_id
                && view.commit.governance_generation == 0
                && view.commit.authority_ref
                    == arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                        genesis.event_id.clone()
                    ),
            "Human PCR commit changed its founding authority"
        );
    }
    verify_native_station_commits(observations, views)
}

async fn replay_original(
    deployment: &super::agent_runtime_live::coauth_session_evidence::ActualAgentDeployment,
    original: &cotest_test_support::operation_observation::ObservedOperationExchange,
) -> Result<Value> {
    let crate::harness::ClientSession::Canonical { signing_key, .. } =
        deployment.controller.session()
    else {
        anyhow::bail!("native replay requires the original holder custody");
    };
    let mut proof_request =
        arkret_signatures::dpop::DpopProofRequest::new(&original.method, &original.url);
    let authorization = original.explicit_request_headers.get("authorization");
    if let Some(authorization) = authorization {
        proof_request = proof_request.access_token(
            authorization
                .strip_prefix("DPoP ")
                .context("original handoff auth changed")?,
        );
    }
    let proof = arkret_signatures::dpop::build_dpop_proof(&proof_request, signing_key)?.proof_jwt;
    let mut request = deployment
        .http
        .post(&original.url)
        .header("Arkret-Operation", original.operation_id.as_str())
        .header("Content-Type", "application/json")
        .header("DPoP", proof)
        .body(arkret_canonical::base64url_decode(
            &original.request_json_base64url,
        )?);
    if let Some(authorization) = authorization {
        request = request.header("Authorization", authorization);
    }
    let response = request.send().await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status.is_success(),
        "native exact replay {} refused: {} {}",
        original.operation_id,
        status,
        String::from_utf8_lossy(&bytes)
    );
    let replay: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        replay == original.response_body,
        "native exact replay changed {} original",
        original.operation_id
    );
    Ok(
        json!({"operation_id":original.operation_id,"status":status.as_u16(),"decoded_response_bytes_base64url":arkret_canonical::base64url_encode(&bytes)}),
    )
}

pub async fn account_identity_creation() -> Result<()> {
    validate_registered_schema_bindings()?;
    let (deployment, mut observations) = observe(
        super::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
            "native-operation-account-creation",
        ),
    )
    .await;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory)?;
        let name = format!(
            "attempt-account-identity-creation-{}.json",
            chrono::Utc::now().timestamp_millis()
        );
        std::fs::write(
            directory.join(name),
            serde_json::to_vec_pretty(&json!({
                "status":"observed_not_verified", "observations":observations,
            }))?,
        )?;
    }
    let deployment = deployment?;
    let original_registration = original_exchange(&observations, ACCOUNT_CREATION[2])?;
    let authorization = original_registration.explicit_request_headers["authorization"].clone();
    let crate::harness::ClientSession::Canonical { signing_key, .. } =
        deployment.controller.session()
    else {
        anyhow::bail!("native onboarding requires the founding holder custody");
    };
    let url = format!(
        "{}/_arkret/gate/account/onboarding",
        deployment.coauth.base_url()
    );
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("GET", &url).access_token(
            authorization
                .strip_prefix("DPoP ")
                .context("handoff token absent")?,
        ),
        signing_key,
    )?
    .proof_jwt;
    let (onboarding, observed) = observe(
        cotest_test_support::operation_observation::send_json_exchange(
            ACCOUNT_CREATION[3],
            deployment
                .http
                .get(url)
                .header("Arkret-Operation", ACCOUNT_CREATION[3])
                .header("Authorization", authorization)
                .header("DPoP", proof),
        ),
    )
    .await;
    let onboarding: arkret_models_identity::AccountOnboardingState =
        serde_json::from_value(onboarding?)?;
    onboarding.validate()?;
    let arkret_models_identity::AccountHandoffBinding::Bound { principal_id, did } =
        &onboarding.binding
    else {
        anyhow::bail!("native onboarding did not observe the completed identity binding");
    };
    ensure!(
        *principal_id == deployment.account.principal_id
            && *did
                == deployment
                    .controller
                    .principal
                    .as_ref()
                    .context("accepted principal absent")?
                    .did,
        "native onboarding resolved another principal"
    );
    observations.exchanges.extend(observed.exchanges);
    validate_exchange_schemas(&observations, &ACCOUNT_CREATION)?;
    ensure!(
        !observations.accepted_identity_material.is_empty(),
        "HTTP success alone is not authority evidence"
    );
    let handoff = original_exchange(&observations, ACCOUNT_CREATION[0])?;
    let challenge = original_exchange(&observations, ACCOUNT_CREATION[1])?;
    let registration = original_exchange(&observations, ACCOUNT_CREATION[2])?;
    ensure!(
        json!(onboarding.handoff_request_id) == handoff.request_body["request_id"]
            && json!(onboarding.account_subject) == handoff.response_body["account_subject"],
        "onboarding changed the authenticated handoff binding"
    );
    let accepted: arkret_models_collaboration::account_operations::AccountRegisterResponseBody =
        serde_json::from_value(registration.response_body.clone())?;
    ensure!(
        accepted.issued_session.account_id == deployment.account,
        "issuer returned another account"
    );
    let replays = [
        replay_original(&deployment, handoff).await?,
        replay_original(&deployment, registration).await?,
    ];

    let request_id = handoff.request_body["request_id"]
        .as_str()
        .context("handoff request id absent")?
        .strip_prefix("ak:request:")
        .context("invalid handoff request id")?
        .to_owned();
    let database = deployment.coauth.pg.connect_url.clone();
    let ledger=tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let attempt=db.query_one("SELECT to_jsonb(a), canonical_outcome FROM account_handoff_creation_attempts a WHERE request_id::text=$1 AND state='committed'",&[&request_id])?;
        let original:Vec<u8>=attempt.get(1);
        let grant:Value=db.query_one("SELECT to_jsonb(g) FROM account_handoff_grants g WHERE request_id::text=$1",&[&request_id])?.get(0);
        let lease:Value=db.query_one("SELECT to_jsonb(l) FROM identity_creation_leases l WHERE local_account_id=(SELECT local_account_id FROM account_handoff_grants WHERE request_id::text=$1)",&[&request_id])?.get(0);
        let challenges=db.query("SELECT to_jsonb(c) FROM identity_binding_challenges c WHERE local_account_id=(SELECT local_account_id FROM account_handoff_grants WHERE request_id::text=$1)",&[&request_id])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
        let sessions=db.query("SELECT to_jsonb(g) FROM oauth_session_grants g",&[])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
        Ok(json!({"handoff_attempt":attempt.get::<_,Value>(0),"handoff_original_bytes_base64url":arkret_canonical::base64url_encode(&original),"handoff_original":serde_json::from_slice::<Value>(&original)?,"handoff_grant":grant,"identity_creation_lease":lease,"identity_binding_challenges":challenges,"issued_session_originals":sessions}))
    }).await??;
    ensure!(
        ledger["handoff_original"] == handoff.response_body,
        "handoff response is not the issuer's original durable result"
    );
    ensure!(
        ledger["handoff_grant"]["account_handoff_grant"]
            == handoff.response_body["account_handoff_grant"],
        "handoff credential differs from the issuer ledger"
    );
    ensure!(
        ledger["identity_creation_lease"]["state"] == "completed",
        "identity creation did not complete natively"
    );
    let sessions = ledger["issued_session_originals"]
        .as_array()
        .context("issuer originals absent")?;
    ensure!(
        sessions.len() == 1
            && sessions[0]["grant_jwt"] == json!(accepted.issued_session.session_grant),
        "registration replay minted another credential or lost the issuer original"
    );
    ensure!(
        ledger["identity_creation_lease"]["register_outcome"] == registration.response_body,
        "register response is not the issuer's exact accepted outcome"
    );
    ensure!(
        ledger["identity_creation_lease"]["registry_receipt"].is_object()
            && ledger["identity_creation_lease"]["pcr_genesis_outcome"].is_object(),
        "registry and PCR admission originals absent"
    );
    let challenges = ledger["identity_binding_challenges"]
        .as_array()
        .context("challenge ledger absent")?;
    ensure!(
        challenges.iter().any(
            |row| row["challenge_id"] == challenge.response_body["challenge_id"]
                && row["consumed_at"].is_string()
        ),
        "original challenge was not consumed by registration"
    );
    let audit = deployment
        .controller
        .sdk()
        .principal_resolution_audit(
            &arkret_models_identity::PrincipalResolutionAuditRequestBody::new(
                deployment.account.clone(),
            ),
        )
        .await?;
    let proof = observations
        .accepted_identity_material
        .iter()
        .find(|proof| proof["register_response"] == registration.response_body)
        .context("independently verified registration original absent")?;
    let request: arkret_models_collaboration::account_operations::AccountRegisterRequestBody =
        serde_json::from_value(proof["register_request"].clone())?;
    let creation = request
        .identity_creation
        .as_ref()
        .context("creation unit absent")?;
    ensure!(
        audit.principal_genesis_event == creation.pcr_genesis_unit.events[0]
            && audit.founding_device_authorize_event == creation.pcr_genesis_unit.events[1]
            && audit.genesis_commits == accepted.pcr_genesis_commits,
        "Station readback differs from the issuer's accepted originals"
    );
    let result = json!({"case":"account_identity_creation","scope":ACCOUNT_CREATION,
        "observations":observations,"authority_originals":ledger,"station_readback":audit,"exact_replays":replays,"onboarding":onboarding,
        "processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]});
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        let path = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&path)?;
        std::fs::write(
            path.join("account-identity-creation.json"),
            serde_json::to_vec_pretty(&result)?,
        )?;
    }
    for identifier in ACCOUNT_CREATION {
        println!("native operation contract passed: {identifier}");
    }
    Ok(())
}
