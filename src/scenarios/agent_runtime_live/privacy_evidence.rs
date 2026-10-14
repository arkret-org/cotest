//! Public history and verifier-private disclosure decisions on a real Station.

use arkret_models_collaboration::agent_scope::AgentKeyPairRequestBody;
use serde_json::Value;

use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

fn sign_disclosure(
    controller: &TestActorClient,
    disclosure: &mut AgentRequestedScopeDisclosure,
) -> Result<()> {
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller")?;
    let mut proof = disclosure
        .proofs
        .first()
        .context("controller proof template")?
        .clone();
    disclosure.proofs.clear();
    proof.payload_digest = disclosure.payload_digest()?;
    proof.created_at = disclosure.issued_at;
    proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &principal.device_signing_key,
        &disclosure.canonical_proof_binding_bytes(&proof)?,
    )?;
    disclosure.proofs.push(proof);
    disclosure.validate()?;
    Ok(())
}

async fn refused(
    controller: &TestActorClient,
    database: &str,
    body: &AgentKeyPairRequestBody,
    label: &str,
    detail: &str,
) -> Result<()> {
    let before = acceptance_rows_with_agent_stores(database, true).await?;
    let response = controller
        .post("/_arkret/gate/account/agent-key-pair")
        .header(
            "Idempotency-Key",
            body.authorize_event.event.event_id.as_str(),
        )
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(body)?)
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "{label} was not an actual client refusal: {}",
        response.status()
    );
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem.detail.contains(detail),
        "{label} reached another decision: {problem:?}"
    );
    ensure!(
        acceptance_rows_with_agent_stores(database, true).await? == before,
        "{label} changed full accepted/Agent state"
    );
    println!(
        "[agent-privacy] rejected={label} status={} code={} full_business_footprint_unchanged=1",
        problem.status,
        problem.code()
    );
    Ok(())
}

fn excludes_private_scope(value: &Value, scope: &Value, marker: &str) -> bool {
    if value == scope {
        return false;
    }
    match value {
        Value::Object(map) => {
            !map.contains_key("requested_scope")
                && map
                    .values()
                    .all(|v| excludes_private_scope(v, scope, marker))
        }
        Value::Array(items) => items
            .iter()
            .all(|v| excludes_private_scope(v, scope, marker)),
        Value::String(s) => !s.contains(marker),
        _ => true,
    }
}

async fn public_history(
    station: &ArkretServer,
    agent: &AgentRuntimeSession,
    scope: &AgentKeyScope,
    marker: &str,
) -> Result<()> {
    let url = arkret_identity::DidWebvhResolver::log_url(&agent.agent_did)?;
    let response = station.http().get(url).send().await?;
    ensure!(
        response.status() == StatusCode::OK,
        "public WebVH history unavailable: {}",
        response.status()
    );
    let history = response.text().await?;
    let entries: Vec<Value> = history
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        entries.len() == 2,
        "expected accepted inception and binding history, got {}",
        entries.len()
    );
    let mut forbidden = vec![serde_json::to_value(scope)?];
    for selector in &scope.resources {
        forbidden.push(serde_json::to_value(selector)?);
    }
    for constraint in &scope.constraints {
        forbidden.push(serde_json::to_value(constraint)?);
    }
    ensure!(
        entries.iter().all(|v| forbidden
            .iter()
            .all(|private| excludes_private_scope(v, private, marker))),
        "public DID history disclosed the private scope or constraint marker"
    );
    println!("[agent-privacy] actual_public_history_entries=2 private_scope_and_marker_absent=1");
    Ok(())
}

async fn no_raw_disclosure_persistence(database: &str) -> Result<()> {
    let database = database.to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let mut tx = db
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .start()?;
        let tables = tx.query(
            "SELECT tablename::text FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
            &[],
        )?;
        let pattern = "%ak.schema.agent_requested_scope_disclosure.v1%";
        for row in tables {
            let name: String = row.get(0);
            ensure!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "unsafe catalog table name"
            );
            let query =
                format!("SELECT count(*) FROM public.{name} r WHERE to_jsonb(r)::text LIKE $1");
            let count: i64 = tx.query_one(&query, &[&pattern])?.get(0);
            ensure!(
                count == 0,
                "non-retaining verifier persisted raw disclosure in {name}"
            );
        }
        tx.commit()?;
        Ok(())
    })
    .await??;
    println!(
        "[agent-privacy] raw_disclosure_schema_marker_absent_from_all_public_tables=1 retention_mode=none"
    );
    Ok(())
}

pub async fn run_agent_requested_scope_privacy_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let name = "agent-private-scope-production";
    let database = database(name)?.context("real PostgreSQL required")?;
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        name,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    .context("actual Station required")?;
    let station = group.server(0);
    let (controller, account) = standard_client(
        station,
        &coauth,
        "private-scope-controller",
        CONTROLLER_DEVICE,
    )
    .await?;
    let marker = format!("private_scope_{}", unique_uuid7().replace('-', "_"));
    let mut scope = requested_scope(&runtime_operations())?;
    scope.constraints = vec![serde_json::from_value(json!({
        "constraint_kind": "scope_limitation", "effect": "allow", "allowed_data_labels": [marker],
    }))?];
    let mut agent = AgentRuntimeSession::establish_observed(
        station,
        AgentSessionIssuer::Fixture(&coauth),
        &controller,
        &account,
        "private-scope-agent",
        scope.clone(),
        None,
    )
    .await?;
    ensure!(
        agent
            .runtime
            .get("/_arkret/self/device_messages")
            .send()
            .await?
            .status()
            == StatusCode::OK,
        "the constraint-preserving fixture grant was not consumed by the actual Station"
    );
    public_history(station, &agent, &scope, &marker).await?;
    no_raw_disclosure_persistence(&database.connect_url).await?;
    let material =
        pairing_expiry_evidence::replacement_material(station, &controller, &account, &agent)
            .await?;
    let body = &material.body;
    let supported_payload = AgentKeyAuthorizePayload::try_from(&body.authorize_event.event)?;
    let mut unsupported = supported_payload.clone();
    unsupported.agent_key_scope.constraints[0]
        .allowed_endpoints
        .push("https://private-scope.example".to_owned());
    let rejected = coauth
        .bind_agent_runtime_grant(
            "unrepresented-constraint",
            &body.authorize_event.event.event_id,
            &unsupported,
            &material.key.verifying_key(),
        )
        .expect_err("fixture must reject every unrepresented constraint field");
    ensure!(
        rejected
            .to_string()
            .contains("unrepresented key constraint"),
        "wrong fixture refusal: {rejected}"
    );
    let mut empty_intersection = supported_payload;
    let mut disjoint = empty_intersection.agent_key_scope.constraints[0].clone();
    disjoint.allowed_data_labels = vec!["disjoint_private_label".to_owned()];
    empty_intersection
        .agent_key_scope
        .constraints
        .push(disjoint);
    let rejected = coauth
        .bind_agent_runtime_grant(
            "empty-constraint-intersection",
            &body.authorize_event.event.event_id,
            &empty_intersection,
            &material.key.verifying_key(),
        )
        .expect_err("an empty mandatory intersection cannot become unrestricted");
    ensure!(
        rejected
            .to_string()
            .contains("empty mandatory label intersection"),
        "wrong empty intersection refusal: {rejected}"
    );
    let registry = arkret_schema_conformance::schema_registry_from_spec_artifacts(
        crate::conformance::spec_artifacts_root(),
    )?;
    registry.validate_value(
        "ak.schema.agent_requested_scope_disclosure.v1",
        &serde_json::to_value(&body.requested_scope_disclosure)?,
    )?;
    body.requested_scope_disclosure.validate()?;
    ensure!(
        body.requested_scope_disclosure.proofs[0].payload_digest
            == body.requested_scope_disclosure.payload_digest()?,
        "controller proof does not bind the exact disclosure"
    );

    let mut wrong_audience = body.clone();
    wrong_audience.requested_scope_disclosure.audience =
        NonEmptyString::new(ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1)
            .map_err(anyhow::Error::msg)?;
    sign_disclosure(&controller, &mut wrong_audience.requested_scope_disclosure)?;
    refused(
        &controller,
        &database.connect_url,
        &wrong_audience,
        "wrong_audience",
        "audience",
    )
    .await?;

    let mut wrong_verifier = body.clone();
    wrong_verifier.requested_scope_disclosure.verifier_id = account.principal_id.clone();
    sign_disclosure(&controller, &mut wrong_verifier.requested_scope_disclosure)?;
    refused(
        &controller,
        &database.connect_url,
        &wrong_verifier,
        "wrong_verifier",
        "verifier",
    )
    .await?;

    let mut stale = body.clone();
    stale.requested_scope_disclosure.issued_at -= chrono::Duration::seconds(600);
    stale.requested_scope_disclosure.expires_at -= chrono::Duration::seconds(600);
    sign_disclosure(&controller, &mut stale.requested_scope_disclosure)?;
    refused(
        &controller,
        &database.connect_url,
        &stale,
        "stale_proof",
        "window",
    )
    .await?;

    let mut mismatch = body.clone();
    mismatch
        .requested_scope_disclosure
        .requested_scope
        .actions
        .push("ak.event.read".to_owned());
    sign_disclosure(&controller, &mut mismatch.requested_scope_disclosure)?;
    refused(
        &controller,
        &database.connect_url,
        &mismatch,
        "commitment_mismatch",
        "ceiling",
    )
    .await?;

    let mut bad_digest = body.clone();
    bad_digest.requested_scope_disclosure.proofs[0].payload_digest =
        arkret_wire::Hash::new(format!("sha256:{}", "8".repeat(64))).map_err(anyhow::Error::msg)?;
    refused(
        &controller,
        &database.connect_url,
        &bad_digest,
        "proof_payload_digest_mismatch",
        "digest mismatch",
    )
    .await?;

    let mut bad_signature = body.clone();
    let jws = &mut bad_signature.requested_scope_disclosure.proofs[0].jws;
    let (header, signature) = jws.split_once("..").context("detached JWS")?;
    let changed = if signature.starts_with('A') { 'B' } else { 'A' };
    *jws = format!("{header}..{changed}{}", &signature[1..]);
    refused(
        &controller,
        &database.connect_url,
        &bad_signature,
        "bad_controller_signature",
        "controller proof",
    )
    .await?;

    // Refusal snapshots may exhaust the short live handle. Keep its original
    // TTL and obtain a fresh ordinary pairing instance for the success branch.
    let material =
        pairing_expiry_evidence::replacement_material(station, &controller, &account, &agent)
            .await?;
    let body = &material.body;
    let paired: AgentKeyPairOutcome = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/gate/account/agent-key-pair")
                .header(
                    "Idempotency-Key",
                    body.authorize_event.event.event_id.as_str(),
                )
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(body)?),
            StatusCode::OK,
        )
        .await?,
    )?;
    wait_for_activation(
        station,
        &material.bootstrap,
        &material.bootstrap.pairing_code,
        &agent.agent_account.principal_id,
        &paired.authorize_event_ref,
    )
    .await?;
    let before_retry = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
    let replay: AgentKeyPairOutcome = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/gate/account/agent-key-pair")
                .header(
                    "Idempotency-Key",
                    body.authorize_event.event.event_id.as_str(),
                )
                .header("Content-Type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(body)?),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replay.authorize_event_ref == paired.authorize_event_ref,
        "exact retry created another authorization"
    );
    ensure!(
        acceptance_rows_with_agent_stores(&database.connect_url, true).await? == before_retry,
        "exact retry changed durable accepted/Agent state"
    );

    let old_disclosure = body.requested_scope_disclosure.clone();
    let mut other_intent = body.clone();
    let payload = AgentKeyAuthorizePayload::try_from(&body.authorize_event.event)?;
    let principal = controller.principal.as_ref().context("controller")?;
    let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    other_intent.authorize_event = arkret_wire::EventAdmissionSubmission::new(sign(
        arkret_event_draft::build_agent_key_authorize_intent(
            &payload,
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            ActorId::account(agent.agent_account.clone()),
            ActorId::account(account.clone()),
            agent.delegation.clone(),
            Utc::now(),
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?);
    ensure!(
        other_intent.authorize_event.event.event_id != body.authorize_event.event.event_id,
        "cross-intent replay is not distinct"
    );
    refused(
        &controller,
        &database.connect_url,
        &other_intent,
        "cross_intent_replay",
        "pairing",
    )
    .await?;
    let mut renewed = {
        agent.key_authorization = paired.authorize_event_ref.clone();
        pairing_expiry_evidence::replacement_material(station, &controller, &account, &agent)
            .await?
            .body
    };
    renewed.requested_scope_disclosure = old_disclosure;
    refused(
        &controller,
        &database.connect_url,
        &renewed,
        "consumed_challenge_on_new_request",
        "request or challenge",
    )
    .await?;
    public_history(station, &agent, &scope, &marker).await?;
    no_raw_disclosure_persistence(&database.connect_url).await?;
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "agent_requested_scope_privacy".to_owned(),
            assertions: 4,
        }],
    })
}
