//! Real H operator admission, independent G private commands and worker publication.
use arkret_models_collaboration::call_invitation::{
    ConsentCurrentReadRequestBody, ConsentCurrentReadResponseBody, ConsentCurrentReadState,
};
use arkret_models_collaboration::consent_operations::{
    ConsentRequestRequestBody, ConsentRequestResponseBody,
};
use arkret_models_collaboration::consent_private::*;
use arkret_models_collaboration::events_payloads::consent::ConsentPeer;
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::{ActorId, ConsentRequestScope, DidUrl};

use super::*;
use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::agent_runtime_live::coauth_session_evidence::{
    ActualAgentDeployment, actual_agent_deployment,
};

mod effects;
mod organization;

const SCOPE: [&str; 3] = [
    "ak.peer.consent.read.current.v1",
    "ak.peer.consent.command.proxy.v1",
    "ak.peer.consent.command.publish_effects.v1",
];

async fn inspect(
    hosting: &ArkretServer,
    governor: &ArkretServer,
    org: &organization::Organization,
    requester: &ActorId,
) -> Result<Value> {
    let request = ConsentCurrentReadRequestBody {
        holder_account_id: org.account().clone(),
        peer: ConsentPeer::Actor {
            actor_id: requester.clone(),
        },
        audience_actor_id: ActorId::service(hosting.service_id().clone()),
        nonce: arkret_canonical::base64url_encode(organization::entropy()?),
    };
    let cli = hosting.inspect_organization_consent(&request).await?;
    let response: ConsentCurrentReadResponseBody = serde_json::from_value(cli["report"].clone())?;
    response.validate_for_request(&request, 0, chrono::Utc::now())?;
    ensure!(
        response.realm_id == *org.realm()
            && response.effective_stream_head == org.bundle.realm_stream_head
            && matches!(response.current, ConsentCurrentReadState::NeverWritten),
        "a pending request became an invented Consent grant or another PCR"
    );
    let source = organization::service_resolution(governor).await?;
    let method = &response.proof.verification_method;
    let document = arkret_identity::authenticated_service_document_at(
        &source,
        governor.service_id(),
        response.evaluated_at,
    )?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )?;
    let key = arkret_identity::public_key_material_from_document(&document, method)?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &response.proof.jws,
        &response.signature_input()?,
        &key,
    )?;
    Ok(json!({"request":request,"response":response,"cli":cli,"governor_resolution":source}))
}

async fn exercise(
    hosting: &ActualAgentDeployment,
    governor: &ActualAgentDeployment,
    org: &organization::Organization,
    producer: &str,
) -> Result<Value> {
    let requester = ActorId::account(hosting.account.clone());
    let before = json!({"h":effects::snapshot(&hosting.station,org.account(),org.realm()).await?,
        "g":effects::snapshot(&governor.station,org.account(),org.realm()).await?});
    ensure!(
        before["h"]["h_original"]
            .as_array()
            .is_some_and(|rows| rows.len() == 1)
            && before["h"]["facts"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1)
            && before["h"]["g_sources"] == json!([])
            && before["g"]["g_sources"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1)
            && before["g"]["g_approval_audit"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
        "real H public source and G private approval owner were not independently installed"
    );
    let first = inspect(&hosting.station, &governor.station, org, &requester).await?;
    let request = ConsentRequestRequestBody {
        holder_account_id: org.account().clone(),
        consent_scope: ConsentRequestScope::VoiceCall,
    };
    let accepted: ConsentRequestResponseBody = serde_json::from_value(
        expect_json(
            hosting
                .controller
                .post("/_arkret/self/consent/request")
                .json(&request),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    accepted.validate()?;
    let settled = effects::settle(
        &hosting.station,
        &governor.station,
        org.account(),
        org.realm(),
        &requester,
        request.consent_scope,
    )
    .await?;
    let repeated: ConsentRequestResponseBody = serde_json::from_value(
        expect_json(
            hosting
                .controller
                .post("/_arkret/self/consent/request")
                .json(&request),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    repeated.validate()?;
    ensure!(
        accepted == repeated,
        "opaque consent request response changed on exact repetition"
    );
    let replayed = effects::settle(
        &hosting.station,
        &governor.station,
        org.account(),
        org.realm(),
        &requester,
        request.consent_scope,
    )
    .await?;
    for role in ["h", "g"] {
        effects::unchanged_authority(&before[role], &replayed[role])?;
        ensure!(
            settled[role]["quarantine"] == replayed[role]["quarantine"],
            "exact request replay changed a live quarantine item or revision"
        );
        ensure!(
            replayed[role]["consents"] == json!([]),
            "private request invented a canonical Consent"
        );
    }
    let second = inspect(&hosting.station, &governor.station, org, &requester).await?;
    let accepted_again = hosting
        .station
        .accept_organization_hosting(&org.request)
        .await?;
    ensure!(
        accepted_again["report"]["outcome"] == org.cli["report"]["outcome"],
        "H exact hosting retry did not return its immutable first G outcome"
    );
    let after = json!({"h":effects::snapshot(&hosting.station,org.account(),org.realm()).await?,
        "g":effects::snapshot(&governor.station,org.account(),org.realm()).await?});
    for role in ["h", "g"] {
        effects::unchanged_authority(&before[role], &after[role])?;
    }
    Ok(
        json!({"producer":producer,"original_submission":org.request.event_submission,"bundle":org.bundle,
        "publication":org.publication,"admission_cli":org.cli,"admission_retry_cli":accepted_again,
        "requester":requester,"self_request":request,"accepted":accepted,"repeated":repeated,
        "before":before,"settled":settled,"replayed":replayed,"after":after,"currents":[first,second]}),
    )
}

fn verify_transports(
    observations: &NativeOperationObservations,
    h: &AuthenticatedServiceResolution,
    g: &AuthenticatedServiceResolution,
) -> Result<()> {
    use arkret_signatures::http_signature::{
        HttpSignatureScenario, SignatureVerificationPolicy, parse_signature_input,
        verify_signed_canonical_json_message,
    };
    for exchange in &observations.exchanges {
        if !SCOPE.contains(&exchange.operation_id.as_str()) {
            continue;
        }
        let effects = exchange.operation_id.as_str() == SCOPE[2];
        let (source, destination) = if effects { (g, h) } else { (h, g) };
        let header = |name: &str| {
            exchange
                .explicit_request_headers
                .get(name)
                .context("actual signed peer header")
        };
        let input = parse_signature_input(header("signature-input")?)?;
        let created = chrono::DateTime::from_timestamp(input.created, 0)
            .context("actual peer signature time")?;
        let method = DidUrl::new(input.key_id.clone()).map_err(anyhow::Error::msg)?;
        let document = arkret_identity::authenticated_service_document_at(
            source,
            &source.service_id,
            created,
        )?;
        arkret_identity::validate_verification_method_relationship(
            &document,
            &method,
            &document.id,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )?;
        let key = arkret_identity::public_key_material_from_document(&document, &method)?
            .ed25519_bytes()?;
        let target: reqwest::Url = exchange.url.parse()?;
        let origin: reqwest::Url = destination.projection()?.base_url.parse()?;
        ensure!(
            header("source-service-id")? == source.service_id.as_str()
                && header("destination-service-id")? == destination.service_id.as_str()
                && target.scheme() == "https"
                && target.origin() == origin.origin(),
            "peer observation changed its real source, destination or origin"
        );
        let scenario = if exchange.operation_id.as_str() == SCOPE[0] {
            HttpSignatureScenario::ConsentCurrentReadV1
        } else {
            HttpSignatureScenario::ServiceToServiceV1
        };
        let policy = SignatureVerificationPolicy::for_scenario(scenario, &["content-digest"])?;
        let raw = arkret_canonical::base64url_decode(&exchange.request_json_base64url)?;
        ensure!(
            serde_json::from_slice::<Value>(&raw)? == exchange.request_body,
            "observed request JSON differs from raw bytes"
        );
        let output =
            arkret_canonical::base64url_decode(&exchange.decoded_response_bytes_base64url)?;
        ensure!(
            serde_json::from_slice::<Value>(&output)? == exchange.response_body,
            "observed response JSON differs from raw bytes"
        );
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
            chrono::DateTime::parse_from_rfc3339(&exchange.observed_at)?.timestamp(),
        )?;
        let at = chrono::DateTime::parse_from_rfc3339(&exchange.observed_at)?
            .with_timezone(&chrono::Utc);
        match exchange.operation_id.as_str() {
            op if op == SCOPE[0] => {
                let request: ConsentCurrentReadRequestBody =
                    serde_json::from_value(exchange.request_body.clone())?;
                let response: ConsentCurrentReadResponseBody =
                    serde_json::from_value(exchange.response_body.clone())?;
                response.validate_for_request(&request, 0, at)?;
            }
            op if op == SCOPE[1] => {
                let request: ConsentPrivateProxyRequestBody =
                    serde_json::from_value(exchange.request_body.clone())?;
                request.validate_at(&source.service_id, at)?;
                let response: ConsentPrivateProxyResponseBody =
                    serde_json::from_value(exchange.response_body.clone())?;
                response.validate_for_request(&request, at)?;
            }
            _ => {
                let request: ConsentPrivateEffectsPublishRequestBody =
                    serde_json::from_value(exchange.request_body.clone())?;
                request.validate_for_authority(
                    &source.service_id,
                    &destination.service_id,
                    &request.realm_id,
                    &source.service_id,
                    0,
                    at,
                )?;
                let response: ConsentPrivateEffectsPublishResponseBody =
                    serde_json::from_value(exchange.response_body.clone())?;
                response.validate_for_request(&request)?;
            }
        }
    }
    Ok(())
}

fn verify_domains(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    for case in evidence["organizations"]
        .as_array()
        .context("two actual Organization sources")?
    {
        let holder = &case["self_request"]["holder_account_id"];
        let realm = &case["bundle"]["realm_id"];
        for current in case["currents"]
            .as_array()
            .context("actual CLI current originals")?
        {
            ensure!(
                observations
                    .exchanges
                    .iter()
                    .any(|exchange| exchange.operation_id.as_str() == SCOPE[0]
                        && exchange.request_body == current["request"]
                        && exchange.response_body == current["response"]),
                "current CLI result lacks its exact real peer exchange"
            );
        }
        let proxies = observations
            .exchanges
            .iter()
            .filter(|exchange| {
                exchange.operation_id.as_str() == SCOPE[1]
                    && &exchange.request_body["holder_account_id"] == holder
            })
            .collect::<Vec<_>>();
        ensure!(
            proxies.len() >= 2,
            "both true self requests must execute the exact private proxy"
        );
        for exchange in proxies {
            ensure!(
                &exchange.request_body["realm_id"] == realm
                    && exchange.response_body["effective_stream_head"]
                        == case["bundle"]["realm_stream_head"]
                    && exchange.request_body["command"]["kind"] == "request"
                    && exchange.request_body["command"]["body"]["request"] == case["self_request"]
                    && exchange.request_body["command"]["body"]["requester_actor_id"]
                        == case["requester"]
                    && exchange.request_body["context"]["kind"] == "station"
                    && exchange.response_body["response_body"]["body"]["accepted_for_processing"]
                        == true,
                "an unrelated private request substituted for this exact requester and scope"
            );
        }
        let publications = observations
            .exchanges
            .iter()
            .filter(|exchange| {
                exchange.operation_id.as_str() == SCOPE[2]
                    && &exchange.request_body["holder_account_id"] == holder
            })
            .collect::<Vec<_>>();
        ensure!(
            !publications.is_empty(),
            "no actual G worker publication reached H"
        );
        for exchange in publications {
            let cell = &exchange.request_body["effects"]["holder_quarantine"];
            ensure!(
                &exchange.request_body["realm_id"] == realm
                    && exchange.request_body["effective_stream_head"]
                        == case["bundle"]["realm_stream_head"]
                    && cell["content"] == case["settled"]["h"]["quarantine"][0]["payload"]
                    && cell["revision"]
                        .as_str()
                        .context("wire cell decimal revision")?
                        .parse::<u64>()?
                        == case["settled"]["h"]["quarantine"][0]["revision"]
                            .as_u64()
                            .context("actual PG cell revision")?,
                "worker publication did not carry the actually persisted H/G quarantine cell"
            );
        }
    }
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let (result,mut observations)=observe(crate::harness::heap_future(||async {
        let mut h=actual_agent_deployment("native-peer-consent-H").await?;
        let mut g=actual_agent_deployment("native-peer-consent-G").await?;
        let hrelay=h.station.install_service_route_relay().await?;
        let grelay=g.station.install_service_route_relay().await?;
        h.station.restart_with_federation_mesh(&[g.station.base_url().to_string()]).await?;
        g.station.restart_with_federation_mesh(&[h.station.base_url().to_string()]).await?;
        let service=organization::create(&h,&g,None).await?;
        let member=super::mls_interop::member(h.controller.clone(),h.station.service_id())?;
        let device=organization::create(&h,&g,Some(&member)).await?;
        let mut organizations=Vec::new();
        organizations.push(exercise(&h,&g,&service,"service").await?);
        organizations.push(exercise(&h,&g,&device,"device").await?);
        let processes=json!([h.coauth.server.native_process_identity()?,h.station.native_process_identity()?,
            g.coauth.server.native_process_identity()?,g.station.native_process_identity()?]);
        h.station.restart_external_process().await?;
        g.station.restart_external_process().await?;
        let requester=ActorId::account(h.account.clone());
        for (case,org) in organizations.iter_mut().zip([&service,&device]) {
            let cold=inspect(&h.station,&g.station,org,&requester).await?;
            case["currents"].as_array_mut().context("native current cuts")?.push(cold);
            let state=json!({"h":effects::snapshot(&h.station,org.account(),org.realm()).await?,
                "g":effects::snapshot(&g.station,org.account(),org.realm()).await?});
            for role in ["h","g"] {effects::unchanged_authority(&case["after"][role],&state[role])?;
                ensure!(case["after"][role]["quarantine"]==state[role]["quarantine"],"cold restart changed the private current cell");}
            case["cold"]=state;
        }
        let hsource=organization::service_resolution(&h.station).await?;
        let gsource=organization::service_resolution(&g.station).await?;
        let relay_exchanges=hrelay.operation_observations().exchanges.into_iter()
            .chain(grelay.operation_observations().exchanges).collect::<Vec<_>>();
        Ok::<_,anyhow::Error>((json!({"case":"peer_consent","scope":SCOPE,"hosting_service":h.station.service_id(),
            "governor_service":g.station.service_id(),"hosting_resolution":hsource,"governor_resolution":gsource,
            "organizations":organizations,"processes":processes,
            "cold_processes":[h.station.native_process_identity()?,g.station.native_process_identity()?]}),relay_exchanges))
    })).await;
    let (mut evidence, relay) = match result {
        Ok(result) => result,
        Err(error) => {
            retain_attempt("peer-consent", &observations)?;
            return Err(error);
        }
    };
    observations.exchanges.extend(relay);
    retain_attempt("peer-consent", &observations)?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let h = serde_json::from_value(evidence["hosting_resolution"].clone())?;
    let g = serde_json::from_value(evidence["governor_resolution"].clone())?;
    verify_transports(&observations, &h, &g)?;
    verify_domains(&observations, &evidence)?;
    evidence["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("peer-consent.json"),
            serde_json::to_vec_pretty(&evidence)?,
        )?;
    }
    for op in SCOPE {
        println!("native operation contract passed: {op}");
    }
    Ok(())
}
