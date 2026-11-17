//! Actual AA acceptance, native publication/resolve and physical receipt custody.
mod active_gateway;
mod originals;
mod private_seed;
mod receipts;
mod transport;

use super::*;
use crate::harness::{expect_json, expect_response};

type Deployment =
    crate::scenarios::agent_runtime_live::coauth_session_evidence::ActualAgentDeployment;
const SCOPE: [&str; 5] = [
    "ak.gate.account.command.request_erasure.v1",
    "ak.peer.account_status.command.submit.v1",
    "ak.peer.account_status.read.resolve.v1",
    "ak.peer.erasure_receipt.command.submit.v1",
    "ak.peer.erasure_receipt.resource.get.v1",
];

async fn completed(source: &Deployment) -> Result<Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let state = originals::station(source).await?;
        if state["completions"]
            .as_array()
            .is_some_and(|rows| rows.len() == 1)
        {
            return Ok(state);
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "native physical worker did not produce one durable completion: {state}"
        );
        // Observe durable job completion only. No business HTTP operation is
        // repeated, and no credential/window/TTL is changed to make it pass.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

fn verify_continuity(evidence: &Value) -> Result<()> {
    let mut phases = Vec::new();
    for phase in ["before", "after", "restarted"] {
        let floor = crate::scenarios::_helpers::native_issuer_binding::verify(&evidence[phase])?;
        phases.push((
            floor,
            evidence[phase]["originals"]["enrollments"][0].clone(),
        ));
    }
    ensure!(
        phases[0].0.service_id == phases[1].0.service_id
            && phases[1].0.service_id == phases[2].0.service_id
            && phases[1].0.did == phases[2].0.did
            && phases[1].0.method_history_head == phases[2].0.method_history_head
            && phases[1].0.version_id == phases[2].0.version_id,
        "issuer relocation changed identity or cold native floor"
    );
    ensure!(
        phases[0].0.method_history_head != phases[1].0.method_history_head
            && phases[0].0.version_id != phases[1].0.version_id,
        "native method history did not advance at actual endpoint relocation"
    );
    ensure!(
        phases[0].1["name"] == phases[1].1["name"]
            && phases[0].1["enrolled_at"] == phases[1].1["enrolled_at"]
            && phases[1].1["enrolled_at"] == phases[2].1["enrolled_at"],
        "issuer enrollment was replaced instead of advanced"
    );
    ensure!(
        phases[0].1["canonical_endpoint"] != phases[1].1["canonical_endpoint"]
            && phases[1].1["canonical_endpoint"] == phases[2].1["canonical_endpoint"],
        "issuer endpoint did not actually move or survive restart"
    );
    ensure!(
        evidence["preflight"]["status"] == "preflight"
            && evidence["applied"]["status"] == "migrated",
        "native migration reports are absent"
    );
    let successor: arkret_models_identity::AuthenticatedServiceResolution =
        serde_json::from_value(evidence["after"]["resolution"].clone())?;
    arkret_identity::verify_service_resolution_floor(&successor, &phases[0].0)?;
    let audits = evidence["after"]["originals"]["audits"]
        .as_array()
        .context("actual native relocation audits")?;
    ensure!(
        audits
            .iter()
            .any(|row| row["action"] == "endpoint_relocated"
                && row["service_id"] == json!(phases[1].0.service_id))
            && evidence["after"]["originals"]["audits"]
                == evidence["restarted"]["originals"]["audits"],
        "native endpoint audit was omitted or repeated on cold restart"
    );
    Ok(())
}

async fn exercise() -> Result<Value> {
    let mut source=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_account_erasure_deployment("native-account-erasure-source").await?;
    let mut target =
        crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
            "native-account-erasure-receiver",
        )
        .await?;
    let actual_configuration = std::fs::read(source.coauth.config.path())?;
    let configuration: Value = serde_saphyr::from_reader(actual_configuration.as_slice())?;
    let max_auth_age = configuration["arkret"]["erasure_request_max_auth_age"]
        .as_u64()
        .context("actual explicit sensitive-authentication policy")?;
    ensure!(
        max_auth_age == 300,
        "dedicated native deployment did not retain its configured authentication policy"
    );
    ensure!(
        source.station.service_id() != target.station.service_id(),
        "receipt receiver reused the source authority"
    );
    let original_source_process = source.station.native_process_identity()?;
    let old_route = source.station.install_service_route_relay().await?;
    let retired_describe_url = source.station.url("/_arkret/describe");
    let before =
        crate::scenarios::_helpers::native_issuer_binding::capture(&source.coauth, &source.station)
            .await?;
    let (_new_route, preflight, applied) = source
        .station
        .move_service_endpoint_with_reports(&old_route.control())
        .await?;
    source.controller = source.station.rebind_actor_client(&source.controller)?;
    source
        .coauth
        .bind_station(
            &source.station,
            "cotest-real-agent-session",
            &source.webvh_registration_bearer,
        )
        .await?;
    let after =
        crate::scenarios::_helpers::native_issuer_binding::capture(&source.coauth, &source.station)
            .await?;
    source.coauth.restart_same_config().await?;
    let restarted =
        crate::scenarios::_helpers::native_issuer_binding::capture(&source.coauth, &source.station)
            .await?;
    let continuity = json!({"before":before,"after":after,"restarted":restarted,"preflight":preflight,"applied":applied});
    verify_continuity(&continuity)?;
    ensure!(
        source
            .station
            .http()
            .get(retired_describe_url)
            .send()
            .await?
            .status()
            == reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "retired service API still served the old endpoint"
    );
    source
        .station
        .restart_with_federation_mesh(&[target.station.url("")])
        .await?;
    target
        .station
        .restart_with_federation_mesh(&[source.station.url("")])
        .await?;
    let source_binding =
        crate::scenarios::_helpers::native_issuer_binding::capture(&source.coauth, &source.station)
            .await?;
    let target_binding =
        crate::scenarios::_helpers::native_issuer_binding::capture(&target.coauth, &target.station)
            .await?;
    let source_resolution: arkret_models_identity::AuthenticatedServiceResolution =
        serde_json::from_value(source_binding["resolution"].clone())?;
    let target_resolution: arkret_models_identity::AuthenticatedServiceResolution =
        serde_json::from_value(target_binding["resolution"].clone())?;
    let mut live_gateway = active_gateway::register(&mut source).await?;
    let mut seed = private_seed::seed(&source).await?;
    seed["before"] = originals::station(&source).await?;
    ensure!(
        seed["before"]["canonical_pcr"]["events"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
            && seed["before"]["canonical_pcr"]["commits"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
        "native erasure has no actual canonical PCR originals"
    );
    for class in ["data", "backups", "private_events", "routes"] {
        ensure!(
            seed["before"][class]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
            "no actual native {class} before erasure"
        );
    }
    // Re-authenticate through the existing actual product login after the
    // relocation/seed work. No authentication timestamp is rewritten.
    cotest_test_support::provisioning::coauth_account::login(
        &source.http,
        source.coauth.base_url(),
        "alice",
        "1amTester!",
    )
    .await?;
    let request = arkret_models_identity::AccountRequestErasureRequestBody {
        request_id: arkret_identifiers::new_prefixed_uuid7("ak:request:").parse()?,
    };
    let path = format!(
        "{}/_arkret/gate/account/erasure-requests",
        source.coauth.base_url().trim_end_matches('/')
    );
    live_gateway.hold_revoke(&source).await?;
    let first = expect_response(
        source
            .http
            .post(&path)
            .header("Arkret-Operation", SCOPE[0])
            .json(&request),
        reqwest::StatusCode::OK,
    )
    .await?;
    let accepted: Value = serde_json::from_slice(&first.body)?;
    let accepted_typed: arkret_models_identity::AccountRequestErasureResponseBody =
        serde_json::from_value(accepted.clone())?;
    accepted_typed.validate()?;
    live_gateway
        .await_failed_revoke_and_release(&source)
        .await?;
    ensure!(
        accepted_typed.request_id == request.request_id
            && accepted_typed.principal_id == source.account.principal_id
            && accepted_typed.withdrawal_window_ends_at.is_none(),
        "native acceptance changed the exact request/Account or invented a window"
    );
    let original = originals::issuer(&source, &request).await?;
    ensure!(
        original["authentications"]
            .as_array()
            .context("real issuer authentication facts")?
            .iter()
            .any(|fact| {
                fact["created_at"]
                    .as_str()
                    .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
                    .is_some_and(|at| {
                        let age = accepted_typed.recorded_at.signed_duration_since(at);
                        age >= chrono::TimeDelta::zero() && age <= chrono::TimeDelta::seconds(60)
                    })
            }),
        "native erasure lacks real authentication within sixty seconds of recording"
    );
    ensure!(
        original["canonical_outcome"] == accepted,
        "AA did not persist its exact first canonical outcome"
    );
    use base64::Engine as _;
    ensure!(
        base64::engine::general_purpose::STANDARD.decode(
            original["canonical_outcome_base64"]
                .as_str()
                .context("original outcome bytes")?
        )? == first.body,
        "first HTTP outcome changed actual durable bytes"
    );
    let replay = expect_response(
        source
            .http
            .post(&path)
            .header("Arkret-Operation", SCOPE[0])
            .json(&request),
        reqwest::StatusCode::UNAUTHORIZED,
    )
    .await?;
    let refusal: Value = serde_json::from_slice(&replay.body)?;
    ensure!(
        serde_json::from_value::<arkret_wire::Problem>(refusal.clone())?.code() == "account_erased",
        "signed terminal status did not fence exact HTTP replay"
    );
    let after_refusal = originals::issuer(&source, &request).await?;
    for field in [
        "intent",
        "canonical_outcome_base64",
        "records",
        "intents",
        "bindings",
    ] {
        ensure!(
            after_refusal[field] == original[field],
            "rejected post-issuance replay changed original {field}"
        );
    }
    let completion = completed(&source).await?;
    let package: arkret_models_collaboration::governance::erasure::ErasureReceiptPackage =
        serde_json::from_value(completion["completions"][0]["package"].clone())?;
    ensure!(
        package.receipt.outcome
            == arkret_models_collaboration::governance::erasure::ErasureAttemptOutcome::Completed,
        "worker did not actually complete physical erasure"
    );
    let active_gateway = live_gateway.completed(&source, &package).await?;
    for class in [
        "data",
        "backups",
        "private_events",
        "routes",
        "data_changes",
        "global_versions",
    ] {
        ensure!(
            completion[class] == json!([]),
            "actual Completed retained private {class}"
        );
    }
    ensure!(
        completion["canonical_pcr"] == seed["before"]["canonical_pcr"],
        "physical erasure changed canonical PCR originals"
    );
    let originals = originals::issuer(&source, &request).await?;
    let mut publications = Vec::new();
    for row in originals["records"]
        .as_array()
        .context("actual issuer records")?
    {
        let record: arkret_models_collaboration::account_status::AccountStatusRecord =
            serde_json::from_value(row["record"].clone())?;
        let document = arkret_identity::authenticated_service_document_at(
            &source_resolution,
            &source_resolution.service_id,
            record.issued_at,
        )?;
        arkret_identity::validate_verification_method_relationship(
            &document,
            &record.proof.verification_method,
            &document.id,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )?;
        let public = arkret_identity::public_key_material_from_document(
            &document,
            &record.proof.verification_method,
        )?;
        arkret_signatures::account_status::verify_account_status_record(&record, &public)?;
        let job = originals["jobs"]
            .as_array()
            .context("actual publication jobs")?
            .iter()
            .find(|job| job["payload"]["body"]["publication"]["record"] == row["record"])
            .context("original immutable publication job")?;
        let body:arkret_models_collaboration::account_lifecycle::AccountStatusPublicationRequestBody=serde_json::from_value(job["payload"]["body"].clone())?;
        let key = job["payload"]["idempotency_key"]
            .as_str()
            .context("original publication identity")?;
        let (bytes, published) = transport::post(
            &source.station,
            &source.station,
            "/_arkret/peer/account-status",
            &body,
            key,
        )
        .await?;
        let (replayed, replay) = transport::post(
            &source.station,
            &source.station,
            "/_arkret/peer/account-status",
            &body,
            key,
        )
        .await?;
        ensure!(
            bytes == replayed && published == replay,
            "publication replay changed its frozen receiver original"
        );
        let actual = completion["replica"]
            .as_array()
            .context("actual replica originals")?
            .iter()
            .find(|original| original["record"] == row["record"])
            .context("actual record was not durably published")?;
        ensure!(
            published["receipt"] == actual["receipt"],
            "HTTP publication substituted the original durable receiver receipt"
        );
        let receipt: arkret_models_collaboration::account_status::AccountStatusReceipt =
            serde_json::from_value(actual["receipt"].clone())?;
        receipt.validate_for_record(&record)?;
        let document = arkret_identity::authenticated_service_document_at(
            &source_resolution,
            &source_resolution.service_id,
            receipt.accepted_at,
        )?;
        arkret_identity::validate_verification_method_relationship(
            &document,
            &receipt.proof.verification_method,
            &document.id,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )?;
        let receipt_key = arkret_identity::public_key_material_from_document(
            &document,
            &receipt.proof.verification_method,
        )?;
        arkret_signatures::account_status::verify_account_status_receipt(&receipt, &receipt_key)?;
        publications.push(json!({"body":body,"key":key,"accepted":published,"replay":replay}));
    }
    let resolve_request =
        arkret_models_collaboration::account_lifecycle::AccountStatusResolveRequestBody {
            account_authority_id: source.station.service_id().clone(),
            account_id: source.account.clone(),
            from_status_sequence: 1,
            limit: 128,
        };
    let (_, resolved) = transport::post(
        &source.station,
        &source.station,
        "/_arkret/peer/account-status/resolve",
        &resolve_request,
        &arkret_identifiers::new_prefixed_uuid7("ak:request:"),
    )
    .await?;
    let resolved_typed:arkret_models_collaboration::account_lifecycle::AccountStatusResolveResponseBody=serde_json::from_value(resolved.clone())?;
    resolved_typed.validate_for_request(&resolve_request)?;
    ensure!(
        !resolved_typed.has_more
            && resolved_typed.records.len() == originals["records"].as_array().unwrap().len(),
        "qualified resolve omitted original issuer chain"
    );
    let mut receipt_evidence = receipts::exercise(
        &mut source,
        &mut target,
        &package,
        &source_resolution,
        &target_resolution,
    )
    .await?;
    receipt_evidence["seed"] = seed;
    receipt_evidence["completion"] = json!({"package":package,"after":completion});
    Ok(
        json!({"request":request,"accepted":accepted,"post_issuance_replay":{"status":401,"body":refusal},
        "originals":originals,"originals_after_refusal":after_refusal,"canonical_outcome_before":original["canonical_outcome_base64"],
        "erasure_request_max_auth_age":max_auth_age,"deployment_policy":{"config_sha256":arkret_canonical::sha256_digest(&actual_configuration),"configured_erasure_request_max_auth_age":configuration["arkret"]["erasure_request_max_auth_age"]},"original_pcr":source.controller.principal.as_ref().unwrap().pcr_realm_id,
        "publications":publications,"replica":completion["replica"],"resolved":resolved,"resolve_request":resolve_request,
        "receipt_evidence":receipt_evidence,"active_gateway":active_gateway,"issuer_continuity":continuity,"issuer_bindings":[source_binding,target_binding],
        "processes":[original_source_process,source.coauth.server.native_process_identity()?,source.station.native_process_identity()?,target.coauth.server.native_process_identity()?,target.station.native_process_identity()?]}),
    )
}

pub(super) async fn run() -> Result<()> {
    let (result, observations) = observe(crate::harness::heap_future(exercise)).await;
    retain_attempt("account-erasure-status", &observations)?;
    let mut artifact = result?;
    let gateway_process = artifact["active_gateway"]["gateway"]["process"].clone();
    artifact["processes"]
        .as_array_mut()
        .context("actual process originals")?
        .push(gateway_process);
    validate_exchange_schemas(&observations, &SCOPE)?;
    verify_native_issuer_bindings(&observations)?;
    // Frozen startup observations remain immutable. Current routing proof is
    // the independently verified AA enrollment/complete native successor above.
    let mut current_cut = observations.clone();
    for material in &mut current_cut.accepted_identity_material {
        let service = material["station_resolution"]["service_id"].clone();
        if let Some(binding) = artifact["issuer_bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binding| binding["resolution"]["service_id"] == service)
        {
            crate::scenarios::_helpers::native_issuer_binding::verify(binding)?;
            material["station_resolution"] = binding["resolution"].clone();
        }
    }
    active_gateway::verify_transports(&artifact["active_gateway"], &current_cut)?;
    for exchange in &observations.exchanges {
        if exchange.operation_id.as_str().starts_with("ak.peer.")
            && SCOPE.contains(&exchange.operation_id.as_str())
        {
            verify_native_station_http_request(&current_cut, exchange, &[])?;
        }
    }
    artifact["case"] = json!("account_erasure_status");
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = json!(observations);
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("account-erasure-status.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
