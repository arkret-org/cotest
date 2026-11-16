//! Actual Station handoff, Gateway persistence and provider receipt are all required.
use arkret_models_integration::{
    PushNotifyRequestBody, PushNotifyResponseBody, PushRegisterDeviceRequestBody,
    PushRegistrationHandoffRequestBody, PushRegistrationHandoffResponseBody,
};
use base64::Engine as _;

use super::*;
use crate::harness::ArkretServer;
use crate::scenarios::_helpers::floria_bootstrap::{NativeFloria, NativePushProvider};

const SCOPE: [&str; 2] = [
    "ak.edge.push.command.apply_registration.v1",
    "ak.edge.push.command.notify.v1",
];

async fn footprint(station: &ArkretServer, gateway: &NativeFloria) -> Result<Value> {
    let station = station
        .owned_database_url()
        .context("owned push source database")?
        .to_owned();
    let gateway = gateway.database.connect_url.clone();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut source = postgres::Client::connect(&station, postgres::NoTls)?;
        let mut sink = postgres::Client::connect(&gateway, postgres::NoTls)?;
        let mut result = serde_json::Map::new();
        for table in ["canonical_events","realm_commits","push_devices","push_registration_handoff_intents","pcr_device_authorization_current_states"] {
            let row = source.query_one(&format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM {table} r"),&[])?;
            result.insert(table.into(),row.get(0));
        }
        let row = sink.query_one("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM floria_push_registration_handoffs r", &[])?;
        result.insert("gateway_registrations".into(),row.get(0));
        Ok(Value::Object(result))
    }).await?
}

/// Translate only the raw exchange actually received and forwarded by the
/// TLS ingress. This does not invent a second request or repeat the operation.
fn record_forwarded(gateway: &NativeFloria, cursor: &mut usize) -> Result<Vec<Value>> {
    let evidence = gateway.observations()?;
    let all = evidence["forwarded"]
        .as_array()
        .context("actual Gateway ingress records")?;
    let mut fresh = Vec::new();
    for row in &all[*cursor..] {
        let url: reqwest::Url = row["public_target"]
            .as_str()
            .context("actual Gateway target")?
            .parse()?;
        if !matches!(
            url.path(),
            "/_arkret/edge/push/registrations:apply" | "/_arkret/edge/push/notify"
        ) {
            continue;
        }
        let method = reqwest::Method::from_bytes(
            row["method"]
                .as_str()
                .context("actual Gateway method")?
                .as_bytes(),
        )?;
        let mut request = reqwest::Request::new(method, url);
        for header in row["request_headers"]
            .as_array()
            .context("actual Gateway headers")?
        {
            let name = reqwest::header::HeaderName::from_bytes(
                header[0].as_str().context("actual header name")?.as_bytes(),
            )?;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(header[1].as_str().context("actual header bytes")?)?;
            request
                .headers_mut()
                .append(name, reqwest::header::HeaderValue::from_bytes(&raw)?);
        }
        let raw = base64::engine::general_purpose::STANDARD.decode(
            row["request_body_base64"]
                .as_str()
                .context("actual Gateway body")?,
        )?;
        *request.body_mut() = Some(raw.into());
        let body = base64::engine::general_purpose::STANDARD.decode(
            row["response_body_base64"]
                .as_str()
                .context("actual Gateway response bytes")?,
        )?;
        let status = u16::try_from(
            row["response_status"]
                .as_u64()
                .context("actual Gateway response status")?,
        )?;
        cotest_test_support::operation_observation::record_response(Some(&request), status, &body)?;
        fresh.push(json!({"ingress":row,"request":serde_json::from_slice::<Value>(request.body().context("buffered actual body")?.as_bytes().context("actual body bytes")?)?,"status":status,"response":serde_json::from_slice::<Value>(&body)?}));
    }
    *cursor = all.len();
    Ok(fresh)
}

fn client(source: &ArkretServer, gateway: &NativeFloria) -> Result<arkret_http_client::Client> {
    let transport: reqwest::Client = (*source.http()).clone();
    Ok(
        arkret_http_client::Client::builder(gateway.server.base_url.parse()?)
            .http_client(transport)
            .http_message_signer(arkret_http_client::HttpMessageSigner::new(
                if source.service_id() == &gateway.source_resolution.service_id {
                    gateway.source_http_method.to_string()
                } else {
                    format!("{}#federation-fanout-key", source.service_did())
                },
                source.federation_signing_key()?,
            ))
            .build()?,
    )
}

fn receipt(
    gateway: &NativeFloria,
    source: &ArkretServer,
    request: &PushRegistrationHandoffRequestBody,
    value: &PushRegistrationHandoffResponseBody,
) -> Result<()> {
    let at = value.receipt.stored_at;
    arkret_identity::verify_authenticated_service_resolution_history(
        &gateway.identity.resolution,
        &gateway.identity.service_id,
        at,
    )?;
    let document = &gateway.identity.resolution.normalized_did_document;
    arkret_identity::validate_verification_method_relationship(
        document,
        &value.receipt.proof.verification_method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )?;
    let key = arkret_identity::public_key_material_from_document(
        document,
        &value.receipt.proof.verification_method,
    )?
    .ed25519_bytes()?;
    arkret::verify_push_registration_installation_receipt(
        &value.receipt,
        request,
        source.service_id(),
        &gateway.identity.service_id,
        &ed25519_dalek::VerifyingKey::from_bytes(&key)?,
    )?;
    Ok(())
}

fn verify_gateway_transports(
    artifact: &Value,
    observations: &NativeOperationObservations,
) -> Result<()> {
    use arkret_signatures::http_signature::{
        HttpSignatureScenario, SignatureVerificationPolicy, parse_signature_input,
        verify_signed_canonical_json_message,
    };
    let gateway: arkret_models_identity::AuthenticatedServiceResolution =
        serde_json::from_value(artifact["gateway"]["gateway_resolution"].clone())?;
    let origin: reqwest::Url = gateway.projection()?.base_url.parse()?;
    let source = arkret_wire::DidCoreId::new(
        artifact["source_station"]
            .as_str()
            .context("actual push source")?,
    )
    .map_err(anyhow::Error::msg)?;
    for exchange in &observations.exchanges {
        if !SCOPE.contains(&exchange.operation_id.as_str()) {
            continue;
        }
        let field = |name: &str| {
            exchange
                .explicit_request_headers
                .get(name)
                .context("actual signed push header")
        };
        let input = parse_signature_input(field("signature-input")?)?;
        let created = chrono::DateTime::from_timestamp(input.created, 0)
            .context("actual push signature creation")?;
        let method = arkret_wire::DidUrl::new(input.key_id.clone()).map_err(anyhow::Error::msg)?;
        let key = native_station_key(observations, &method, created)?.ed25519_bytes()?;
        let target: reqwest::Url = exchange.url.parse()?;
        ensure!(
            field("source-service-id")? == source.as_str()
                && field("destination-service-id")? == gateway.service_id.as_str()
                && input.key_id
                    == artifact["gateway"]["onboarded_station_http_method"]
                        .as_str()
                        .context("exact onboarded source method")?
                && target.origin() == origin.origin()
                && target.scheme() == "https",
            "native push transport changed its actual source, destination or public HTTPS origin"
        );
        arkret_identity::verify_authenticated_service_resolution_history(
            &gateway,
            &gateway.service_id,
            created,
        )?;
        let conditional = if exchange.operation_id.as_str() == SCOPE[1] {
            &["content-digest", "idempotency-key"][..]
        } else {
            &["content-digest"][..]
        };
        let policy = SignatureVerificationPolicy::for_scenario(
            HttpSignatureScenario::ServiceToServiceV1,
            conditional,
        )?;
        let raw = arkret_canonical::base64url_decode(&exchange.request_json_base64url)?;
        let observed = chrono::DateTime::parse_from_rfc3339(&exchange.observed_at)?.timestamp();
        verify_signed_canonical_json_message(
            &exchange.method,
            &exchange.url,
            &target[url::Position::BeforeHost..url::Position::AfterPort],
            target.path(),
            exchange
                .explicit_request_headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            exchange
                .explicit_request_headers
                .contains_key("content-encoding"),
            &raw,
            &ed25519_dalek::VerifyingKey::from_bytes(&key)?,
            &policy,
            observed,
        )?;
    }
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let (result,observations) = observe(async {
        let mut source = crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-push-source").await?;
        let wrong = crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-push-other").await?;
        let provider = NativePushProvider::spawn().await?;
        let gateway = NativeFloria::spawn_required(&source.station,provider).await?;
        source.station.restart_with_native_push_gateway(&gateway.identity.resolution,&gateway.identity.verification_method).await?;
        let initial = footprint(&source.station,&gateway).await?;
        let mut cursor = gateway.observations()?["forwarded"].as_array().context("Gateway ingress observations")?.len();
        let push_key = format!("native-push-{}",uuid::Uuid::new_v4().simple());
        let registration = PushRegisterDeviceRequestBody {
            device_id:arkret_wire::DeviceId::new(source.controller.device_id.clone())?,
            push_gateway_url:format!("{}/_arkret/edge/push/notify",gateway.server.base_url),
            push_key:arkret_models_integration::PushKey::new(push_key.clone()).map_err(anyhow::Error::msg)?,
            platform:None,app_id:Some("org.arkret.native-push".into()),display_name:None,visible_notification_opt_in:false,
        };
        let registered = source.controller.sdk().push_register_device(&registration).await?;
        let apply = record_forwarded(&gateway,&mut cursor)?;
        ensure!(apply.len()==1 && apply[0]["status"]==200,"Station did not complete exactly one actual Gateway apply");
        let request:PushRegistrationHandoffRequestBody = serde_json::from_value(apply[0]["request"].clone())?;
        let accepted:PushRegistrationHandoffResponseBody = serde_json::from_value(apply[0]["response"].clone())?;
        receipt(&gateway,&source.station,&request,&accepted)?;
        ensure!(request.registration_id()==&registered.registration_id && request.push_target_id()==&registered.push_target_id && request.device_id()==&registration.device_id,"Gateway request changed the Station-derived registration identity");
        let installed = footprint(&source.station,&gateway).await?;
        let source_client = client(&source.station,&gateway)?;
        let replay = source_client.push_apply_registration(&request,source.station.service_id(),&gateway.identity.service_id).await?;
        let replay_exchange = record_forwarded(&gateway,&mut cursor)?;
        receipt(&gateway,&source.station,&request,&replay)?;
        let after_replay = footprint(&source.station,&gateway).await?;
        ensure!(replay==accepted && installed==after_replay,"exact Gateway replay changed its original receipt or durable footprint");
        let mut changed = request.clone();
        if let PushRegistrationHandoffRequestBody::Active {push_key,..} = &mut changed { *push_key=arkret_models_integration::PushKey::new("changed-provider-token").map_err(anyhow::Error::msg)?; } else { anyhow::bail!("Station registration must be active"); }
        let changed_error = source_client.push_apply_registration(&changed,source.station.service_id(),&gateway.identity.service_id).await.err().context("changed registration body was accepted")?;
        let changed_exchange = record_forwarded(&gateway,&mut cursor)?;
        let after_changed = footprint(&source.station,&gateway).await?;
        ensure!(changed_exchange.len()==1 && changed_exchange[0]["status"]==409 && changed_exchange[0]["response"]["type"]=="https://arkret.org/problems/duplicate_conflict" && installed==after_changed,"changed registration did not fail with exact conflict and zero writes");
        let notify: PushNotifyRequestBody = serde_json::from_value(json!({"notification":{"push_target_id":registered.push_target_id,"wakeup_kind":"message","devices":[{"device_id":registration.device_id}]}}))?;
        let notify_key = format!("native-notify-{}",uuid::Uuid::new_v4().simple());
        let notified:PushNotifyResponseBody = source_client.push_notify(&notify,&notify_key,source.station.service_id(),&gateway.identity.service_id).await?;
        let notify_exchange = record_forwarded(&gateway,&mut cursor)?;
        ensure!(notified.push_target_id==registered.push_target_id && notified.outcomes==vec![arkret_models_integration::PushGatewaySubmissionOutcome::accepted(registration.device_id.clone())],"native notify did not accept the actual installed Device");
        let after_notify = footprint(&source.station,&gateway).await?;
        let provider_after_notify = gateway.observations()?["provider"].clone();
        let received = provider_after_notify["provider_received"].as_array().context("actual provider boundary")?;
        ensure!(received.len()==1 && received[0]["uri"].as_str().context("provider route")?.ends_with(&push_key) && received[0]["body"]["push_target_id"]==json!(registered.push_target_id) && received[0]["body"]["wakeup_kind"]=="message" && received[0]["body"].get("actor_id").is_none() && received[0]["body"].get("account_id").is_none() && received[0]["body"].get("realm_id").is_none(),"provider did not receive the exact opaque installed route and blind wakeup");
        let duplicate = source_client.push_notify(&notify,&notify_key,source.station.service_id(),&gateway.identity.service_id).await?;
        let duplicate_exchange = record_forwarded(&gateway,&mut cursor)?;
        let provider_after_duplicate = gateway.observations()?["provider"].clone();
        ensure!(duplicate==notified && provider_after_duplicate["provider_received"]==provider_after_notify["provider_received"] && footprint(&source.station,&gateway).await?==after_notify,"exact notify retry changed the cached outcome, durable footprint or dispatched twice");
        let wrong_before = footprint(&source.station,&gateway).await?;
        let wrong_client = client(&wrong.station,&gateway)?;
        let wrong_error = wrong_client.push_notify(&notify,&format!("wrong-{notify_key}"),wrong.station.service_id(),&gateway.identity.service_id).await.err().context("another actual Station borrowed the installed tenant route")?;
        let wrong_exchange = record_forwarded(&gateway,&mut cursor)?;
        let wrong_after = footprint(&source.station,&gateway).await?;
        ensure!(wrong_exchange.len()==1 && wrong_exchange[0]["status"]==401 && wrong_before==wrong_after && gateway.observations()?["provider"]["provider_received"]==provider_after_notify["provider_received"],"wrong authenticated Station obtained a tenant dispatch or changed durable state");
        let revoked = PushRegistrationHandoffRequestBody::Revoked {registration_id:request.registration_id().clone(),push_target_id:request.push_target_id().clone(),device_id:request.device_id().clone()};
        let revoked_response = source_client.push_apply_registration(&revoked,source.station.service_id(),&gateway.identity.service_id).await?;
        let revoke_exchange = record_forwarded(&gateway,&mut cursor)?;
        receipt(&gateway,&source.station,&revoked,&revoked_response)?;
        let after_revoke = footprint(&source.station,&gateway).await?;
        let revive_error = source_client.push_apply_registration(&request,source.station.service_id(),&gateway.identity.service_id).await.err().context("revoked registration was revived by its old active request")?;
        let revive_exchange = record_forwarded(&gateway,&mut cursor)?;
        let after_revive = footprint(&source.station,&gateway).await?;
        ensure!(revive_exchange.len()==1 && revive_exchange[0]["status"]==409 && revive_exchange[0]["response"]["type"]=="https://arkret.org/problems/duplicate_conflict" && after_revoke==after_revive,"terminal revoke did not preserve its zero-write active replay refusal");
        let revoked_notify = source_client.push_notify(&notify,&format!("revoked-{notify_key}"),source.station.service_id(),&gateway.identity.service_id).await?;
        let revoked_notify_exchange = record_forwarded(&gateway,&mut cursor)?;
        ensure!(revoked_notify.outcomes==vec![arkret_models_integration::PushGatewaySubmissionOutcome::rejected(registration.device_id.clone(),arkret_models_integration::PushNotifyReasonCode::PushTargetUnknown,None)] && gateway.observations()?["provider"]["provider_received"]==provider_after_notify["provider_received"] && after_revoke==footprint(&source.station,&gateway).await?,"revoked target was dispatched or mutated durable facts");
        ensure!(initial["canonical_events"]==after_revive["canonical_events"] && initial["realm_commits"]==after_revive["realm_commits"],"service-local push effects changed canonical governance originals");
        Ok::<_,anyhow::Error>(json!({"source_station":source.station.service_id(),"other_station":wrong.station.service_id(),"device":registration.device_id,"registration":registration,"registered":registered,"initial":initial,"apply":apply,"accepted_request":request,"accepted":accepted,"installed":installed,"replay":replay,"replay_exchange":replay_exchange,"after_replay":after_replay,"changed_error":changed_error.to_string(),"changed_exchange":changed_exchange,"after_changed":after_changed,"notify":notify,"notify_key":notify_key,"notified":notified,"notify_exchange":notify_exchange,"after_notify":after_notify,"provider_after_notify":provider_after_notify,"duplicate":duplicate,"duplicate_exchange":duplicate_exchange,"provider_after_duplicate":provider_after_duplicate,"wrong_error":wrong_error.to_string(),"wrong_exchange":wrong_exchange,"wrong_before":wrong_before,"wrong_after":wrong_after,"revoked":revoked,"revoked_response":revoked_response,"revoke_exchange":revoke_exchange,"after_revoke":after_revoke,"revive_error":revive_error.to_string(),"revive_exchange":revive_exchange,"after_revive":after_revive,"revoked_notify":revoked_notify,"revoked_notify_exchange":revoked_notify_exchange,"gateway":gateway.observations()?,"processes":[source.coauth.server.native_process_identity()?,source.station.native_process_identity()?,wrong.coauth.server.native_process_identity()?,wrong.station.native_process_identity()?,gateway.server.native_process_identity()?]}))
    }).await;
    retain_attempt("push-gateway", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    verify_native_issuer_bindings(&observations)?;
    verify_gateway_transports(&artifact, &observations)?;
    artifact["case"] = json!("push_gateway");
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("push-gateway.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
