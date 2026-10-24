//! Delegated Agent profiles must use the Agent's actual Principal Control Realm.

use super::*;

async fn refuse_event(
    controller: &TestActorClient,
    database: &str,
    event: Event,
    label: &str,
) -> Result<()> {
    if label == "kind_outside_controller_delegation" {
        let catalogue =
            crate::conformance::load_artifact_json("registry/event-kind-registry.json")?;
        let entry = catalogue["event_kinds"]
            .as_array()
            .context("registered Event kinds")?
            .iter()
            .find(|row| row["event_kind"] == event.kind.as_str())
            .context("unsupported delegated kind is registered")?;
        ensure!(
            entry["admission"] == "self_authored_proof" && event.executed_by.is_some(),
            "the refusal must exercise delegation on a self-authored Event kind"
        );
    }
    let before =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            database, true,
        )
        .await?;
    let response = controller
        .post("/_arkret/self/events")
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &arkret_wire::EventAdmissionSubmission::new(event),
        )?)
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "{label} did not refuse with a client decision: {}",
        response.status()
    );
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem.code() != arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        "{label} stopped at shape validation: {problem:?}"
    );
    match label {
        "foreign_controller_pcr" | "non_pcr_agent_target" => ensure!(
            problem.detail.contains("Principal Control Realm") || problem.detail.contains("PCR"),
            "{label} missed target PCR admission: {problem:?}"
        ),
        "unaccepted_delegation" => ensure!(
            problem.detail.contains("delegation"),
            "{label} missed the delegation binding: {problem:?}"
        ),
        "agent_pcr_governance_change" => ensure!(
            problem.code() == arkret_wire::ErrorCode::FAILED_PRECONDITION
                && problem.detail.contains("Agent PCR"),
            "Agent PCR transfer did not fail at the fixed-Station policy: {problem:?}"
        ),
        "kind_outside_controller_delegation" => ensure!(
            problem.code() == arkret_wire::ErrorCode::CAPABILITY_DENIED,
            "self-authored Event kind accepted an unsupported controller purpose: {problem:?}"
        ),
        _ => {}
    }
    let after =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            database, true,
        )
        .await?;
    if after != before {
        for (table, old) in before.as_object().context("footprint object")? {
            if after.get(table) != Some(old) {
                println!(
                    "[agent-pcr] refusal_state_changed={table} before_rows={} after_rows={}",
                    old.as_array().map_or(0, Vec::len),
                    after[table].as_array().map_or(0, Vec::len)
                );
            }
        }
    }
    ensure!(after == before, "{label} changed full accepted/Agent state");
    println!(
        "[agent-pcr] refused={label} status={} code={} full_business_footprint_unchanged=1 detail={}",
        problem.status,
        problem.code(),
        problem.detail
    );
    Ok(())
}

pub async fn run_agent_pcr_profile_admission() -> Result<crate::conformance::SuiteExecutionResult> {
    let name = "agent-pcr-profile-production";
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
        "pcr-profile-controller",
        CONTROLLER_DEVICE,
    )
    .await?;
    let agent = AgentRuntimeSession::establish(
        station,
        &coauth,
        &controller,
        &account,
        "pcr-profile-agent",
    )
    .await?;
    let principal = controller
        .principal
        .as_ref()
        .context("accepted controller")?;
    let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    ensure!(
        principal.pcr_realm_id != agent.agent_pcr,
        "Agent inherited controller PCR"
    );
    let resolved: arkret_models_identity::identity::IdentityResolveResponseBody =
        serde_json::from_value(
            expect_json(
                station
                    .http()
                    .post(station.url("/_arkret/root/identity/resolve"))
                    .json(
                        &arkret_models_identity::identity::IdentityResolveRequestBody {
                            did: agent.agent_did.clone(),
                            requested_evidence_kinds: Vec::new(),
                        },
                    ),
                StatusCode::OK,
            )
            .await?,
        )?;
    let document = serde_json::to_value(resolved.did_document)?;
    let bindings: Vec<_> = document["service"]
        .as_array()
        .context("Agent DID services")?
        .iter()
        .filter(|service| service["type"] == "ArkretPrincipalControlRealm")
        .collect();
    ensure!(
        bindings.len() == 1
            && bindings[0]["serviceEndpoint"]["realm_id"] == agent.agent_pcr.as_str(),
        "Agent DID has no unique independent PCR pointer"
    );
    let payload = arkret_models_collaboration::events_payloads::ActorProfileCreatePayload {
        object: arkret_models_identity::actor_profile::ActorProfileDefinition {
            principal_id: Some(agent.agent_account.principal_id.clone()),
            actor_id: None,
            actor_kind: arkret_wire::ActorKind::Agent,
            display_name: "Delegated Agent profile".to_owned(),
            handle: None,
            agent_slug: Some("pcr-profile-agent".to_owned()),
            avatar_blob_ref: None,
            accountable_principal_ids: Some(vec![account.principal_id.clone()]),
            profile_fields: std::collections::BTreeMap::new(),
        },
    };
    let intent =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::ProfileCreate>::new(
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            ActorId::account(agent.agent_account.clone()),
            payload,
        )?
        .with_executed_by(ActorId::account(account.clone()))
        .with_authorization_ref(
            arkret_wire::AuthorizationRef::new(agent.delegation.as_str())
                .map_err(anyhow::Error::msg)?,
        )
        .into_intent(Utc::now())?;
    let event = sign(
        intent.author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?;
    let accepted: AuthoritySubmitResponseBody = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/self/events")
                .json(&arkret_wire::EventAdmissionSubmission::new(event.clone())),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(accepted, AuthoritySubmitResponseBody::Accepted { status: AuthorityCommitStatus::Committed, commit } if commit.realm_id == agent.agent_pcr && commit.event_ref == event.event_id),
        "delegated profile did not commit in the Agent PCR"
    );
    let frozen =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &database.connect_url,
            true,
        )
        .await?;
    let retry: AuthoritySubmitResponseBody = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/self/events")
                .json(&arkret_wire::EventAdmissionSubmission::new(event.clone())),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(
            retry,
            AuthoritySubmitResponseBody::Accepted {
                status: AuthorityCommitStatus::Duplicate,
                ..
            }
        ),
        "profile exact retry did not return Duplicate"
    );
    ensure!(
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &database.connect_url,
            true
        )
        .await?
            == frozen,
        "profile exact retry changed durable state"
    );
    let db_url = database.connect_url.clone();
    let realm = agent.agent_pcr.to_string();
    let head: arkret_wire::RealmCommit = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&db_url, postgres::NoTls)?;
        let value: serde_json::Value = db.query_one("SELECT commit_json FROM realm_commits WHERE realm_id=$1 AND stream_ref->>'kind'='realm' ORDER BY stream_position DESC LIMIT 1", &[&realm])?.get(0);
        Ok(serde_json::from_value(value)?)
    }).await??;
    ensure!(
        head.governance_generation == 0,
        "Agent PCR has a nonzero governance tenure"
    );
    let change =
        sign(
            arkret_event_draft::TypedEventDraft::<
                arkret_wire::event_spec::RealmGovernanceStationChange,
            >::new(
                ScopeRef::Realm {
                    realm_id: agent.agent_pcr.clone(),
                },
                ActorId::account(agent.agent_account.clone()),
                arkret_models_collaboration::events_payloads::RealmGovernanceStationChangePayload {
                    expected_governance_generation: 0,
                    expected_realm_stream_commit_id: head.commit_id,
                    new_governance_station_id: DidCoreId::new(
                        "ak:did_core:web:other-station.example",
                    )?,
                },
            )?
            .with_executed_by(ActorId::account(account.clone()))
            .with_authorization_ref(
                arkret_wire::AuthorizationRef::new(agent.delegation.as_str())
                    .map_err(anyhow::Error::msg)?,
            )
            .into_intent(Utc::now())?
            .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
            &method,
            principal.device_signing_key.to_bytes(),
        )?;
    refuse_event(
        &controller,
        &database.connect_url,
        change,
        "agent_pcr_governance_change",
    )
    .await?;
    let mut patch = arkret_wire::Patch::new();
    patch.insert("display_name", "Updated delegated Agent profile")?;
    let current: arkret_models_collaboration::events_payloads::ActorProfileCreatePayload =
        serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    let profile = current.materialize(&event)?;
    let update = arkret_models_collaboration::events_payloads::ActorProfileUpdatePayload {
        expected_revision: None,
        target_ref: arkret_wire::ActorProfileId::from_event_id(&event.event_id),
        patch,
        expected_state_digest: Some(
            arkret_models_collaboration::events_payloads::ActorProfileUpdatePayload::state_digest(
                &profile,
            )?,
        ),
    };
    let updated = sign(
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::ProfileUpdate>::new(
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            ActorId::account(agent.agent_account.clone()),
            update,
        )?
        .with_executed_by(ActorId::account(account.clone()))
        .with_authorization_ref(
            arkret_wire::AuthorizationRef::new(agent.delegation.as_str())
                .map_err(anyhow::Error::msg)?,
        )
        .into_intent(Utc::now())?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?;
    // Fail the final business projection after origin staging and Commit writes.
    let db_url = database.connect_url.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&db_url, postgres::NoTls)?;
        db.batch_execute("CREATE FUNCTION agent_profile_projection_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned Agent profile projection fault'; END $$; CREATE TRIGGER agent_profile_projection_fault BEFORE INSERT OR UPDATE ON actor_profile_current_states FOR EACH ROW EXECUTE FUNCTION agent_profile_projection_fault()")?;
        Ok(())
    }).await??;
    let before_fault =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &database.connect_url,
            true,
        )
        .await?;
    let fault_response = controller
        .post("/_arkret/self/events")
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &arkret_wire::EventAdmissionSubmission::new(updated.clone()),
        )?)
        .send()
        .await?;
    let fault_status = fault_response.status();
    let fault_problem: arkret_wire::Problem = fault_response.json().await?;
    let after_fault =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &database.connect_url,
            true,
        )
        .await?;
    let db_url = database.connect_url.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&db_url, postgres::NoTls)?;
        db.batch_execute("DROP TRIGGER agent_profile_projection_fault ON actor_profile_current_states; DROP FUNCTION agent_profile_projection_fault()")?;
        Ok(())
    }).await??;
    ensure!(
        fault_status == StatusCode::CONFLICT
            && fault_problem.code() == arkret_wire::ErrorCode::FAILED_PRECONDITION
            && fault_problem
                .extensions
                .get("reason_code")
                .and_then(serde_json::Value::as_str)
                == Some(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED)
            && fault_problem
                .detail
                .contains("owned Agent profile projection fault"),
        "projection fault did not reach the actual writer: {fault_problem:?}"
    );
    ensure!(
        after_fault == before_fault,
        "late profile projection failure retained partial origin/Event/Commit/current state"
    );
    println!(
        "[agent-pcr] late_projection_fault_rolled_back_complete_state=1 same_signed_event_retried=1"
    );
    let result: AuthoritySubmitResponseBody = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/self/events")
                .json(&arkret_wire::EventAdmissionSubmission::new(updated.clone())),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(result, AuthoritySubmitResponseBody::Accepted { status: AuthorityCommitStatus::Committed, commit } if commit.realm_id == agent.agent_pcr && commit.event_ref == updated.event_id),
        "Agent profile update did not use its own PCR"
    );
    let db_url = database.connect_url.clone();
    let realm = agent.agent_pcr.to_string();
    let subject = agent.agent_account.principal_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&db_url, postgres::NoTls)?;
        let value: serde_json::Value = db.query_one("SELECT value FROM actor_profile_current_states WHERE realm_id=$1 AND value->>'principal_id'=$2", &[&realm,&subject])?.get(0);
        ensure!(value["display_name"] == "Updated delegated Agent profile" && value["actor_kind"] == "agent", "Agent profile current was not atomically updated");
        Ok(())
    }).await??;
    repairing_evidence::lifecycle(&controller, &agent, "pause").await?;
    repairing_evidence::lifecycle(&controller, &agent, "resume").await?;
    {
        use arkret_models_collaboration::governance::accountability::{
            AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
        };
        use arkret_wire::PayloadSigner as _;
        let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
        let mut grant = AccountabilityGrantPayload::new(
            agent.agent_account.principal_id.clone(),
            account.principal_id.clone(),
            AccountabilityScope::Single(AccountabilityScopeKind::AgentOperator),
            at - chrono::Duration::seconds(1),
            None,
            arkret_wire::PayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: agent.verification_method.clone(),
                payload_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(b""))
                    .map_err(anyhow::Error::msg)?,
                created_at: at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: String::new(),
            },
        );
        grant.proof.payload_digest = grant.payload_digest()?;
        let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            agent.runtime_key.to_bytes(),
            agent.agent_did.clone(),
            agent.verification_method.clone(),
        );
        grant.proof.jws = signer
            .sign_payload(&grant.canonical_proof_binding_bytes()?)?
            .jws;
        let unsupported = sign(
            arkret_event_draft::TypedEventDraft::<
                arkret_wire::event_spec::IdentityAccountabilityGrant,
            >::new(
                ScopeRef::Realm {
                    realm_id: agent.agent_pcr.clone(),
                },
                ActorId::account(agent.agent_account.clone()),
                grant,
            )?
            .with_executed_by(ActorId::account(account.clone()))
            .with_authorization_ref(
                arkret_wire::AuthorizationRef::new(agent.delegation.as_str())
                    .map_err(anyhow::Error::msg)?,
            )
            .into_intent(at)?
            .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
            &method,
            principal.device_signing_key.to_bytes(),
        )?;
        refuse_event(
            &controller,
            &database.connect_url,
            unsupported,
            "kind_outside_controller_delegation",
        )
        .await?;
    }
    let ordinary = crate::scenarios::human_device_producer_live::create_realm_with_join_rule(
        &controller,
        "pcr-separation-ordinary",
        "closed",
        &[],
    )
    .await?;
    let ordinary = RealmId::new(ordinary).map_err(anyhow::Error::msg)?;
    for (label, realm, delegation) in [
        (
            "foreign_controller_pcr",
            principal.pcr_realm_id.clone(),
            agent.delegation.clone(),
        ),
        (
            "non_pcr_agent_target",
            ordinary.clone(),
            agent.delegation.clone(),
        ),
        (
            "unaccepted_delegation",
            agent.agent_pcr.clone(),
            DidUrl::new(format!("{}#unaccepted-controller-purpose", agent.agent_did))
                .map_err(anyhow::Error::msg)?,
        ),
    ] {
        let delta: arkret_models_collaboration::events_payloads::ActorProfileUpdatePayload =
            serde_json::from_value(serde_json::to_value(&updated.payload)?)?;
        let bad = sign(
            arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::ProfileUpdate>::new(
                ScopeRef::Realm { realm_id: realm },
                ActorId::account(agent.agent_account.clone()),
                delta,
            )?
            .with_executed_by(ActorId::account(account.clone()))
            .with_authorization_ref(
                arkret_wire::AuthorizationRef::new(delegation.as_str())
                    .map_err(anyhow::Error::msg)?,
            )
            .into_intent(Utc::now())?
            .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
            &method,
            principal.device_signing_key.to_bytes(),
        )?;
        refuse_event(&controller, &database.connect_url, bad, label).await?;
    }
    let human = arkret_models_collaboration::events_payloads::ActorProfileCreatePayload {
        object: arkret_models_identity::actor_profile::ActorProfileDefinition {
            principal_id: Some(account.principal_id.clone()),
            actor_id: None,
            actor_kind: arkret_wire::ActorKind::User,
            display_name: "Non-PCR controller profile refusal".to_owned(),
            handle: None,
            agent_slug: None,
            avatar_blob_ref: None,
            accountable_principal_ids: None,
            profile_fields: std::collections::BTreeMap::new(),
        },
    };
    let bad_human = sign(
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::ProfileCreate>::new(
            ScopeRef::Realm { realm_id: ordinary },
            ActorId::account(account.clone()),
            human,
        )?
        .into_intent(Utc::now())?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
        &method,
        principal.device_signing_key.to_bytes(),
    )?;
    let frozen =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &database.connect_url,
            true,
        )
        .await?;
    let response = controller
        .post("/_arkret/self/account/profile")
        .header("Content-Type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &arkret_models_collaboration::account_operations::AccountUpdateProfileRequestBody {
                profile_event: arkret_wire::EventAdmissionSubmission::new(bad_human),
            },
        )?)
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "a non-PCR controller target was not refused: {}",
        response.status()
    );
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        problem.code() != arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        "non-PCR controller refusal stopped at shape validation: {problem:?}"
    );
    ensure!(
        problem.detail.contains("PCR") || problem.detail.contains("Principal Control Realm"),
        "controller target refusal missed the PCR gate: {problem:?}"
    );
    ensure!(
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &database.connect_url,
            true
        )
        .await?
            == frozen,
        "non-PCR controller target changed full state"
    );
    println!(
        "[agent-pcr] refused=non_pcr_controller_target status={} code={} full_business_footprint_unchanged=1",
        problem.status,
        problem.code()
    );
    let db_url = database.connect_url.clone();
    let agent_realm = agent.agent_pcr.clone();
    let controller_realm = principal.pcr_realm_id.clone();
    let agent_actor = ActorId::account(agent.agent_account.clone());
    let controller_actor = ActorId::account(account.clone());
    let delegation = agent.delegation.to_string();
    let station_id = station.service_id().clone();
    let agent_id = agent.agent_account.principal_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db = postgres::Client::connect(&db_url, postgres::NoTls)?;
        let rows = db.query("SELECT envelope FROM canonical_events WHERE realm_id=$1", &[&agent_realm.as_str()])?;
        let events: Vec<Event> = rows.into_iter().map(|row| serde_json::from_value(row.get(0))).collect::<std::result::Result<_,_>>()?;
        let genesis = events.iter().find(|event| event.kind == arkret_wire::EventKind::RealmCreate).context("actual Agent genesis")?;
        ensure!(genesis.actor_id == agent_actor && genesis.executed_by.as_ref() == Some(&controller_actor), "genesis creator is not the Agent under controller execution");
        ensure!(events.iter().filter(|event| event.kind == arkret_wire::EventKind::RealmCreate).count() == 1 && genesis.realm_id == RealmId::from_event_id(&genesis.event_id), "Agent PCR lacks one exact event-derived genesis");
        let genesis_commit: arkret_wire::RealmCommit = serde_json::from_value(db.query_one("SELECT commit_json FROM realm_commits WHERE realm_id=$1 AND stream_position=0", &[&agent_realm.as_str()])?.get(0))?;
        ensure!(genesis_commit.event_ref == genesis.event_id && genesis_commit.governance_generation == 0, "genesis lacks its generation-zero covering Commit");
        ensure!(genesis.payload["object"]["governance_station_id"] == station_id.as_str(), "genesis names another generation-zero governance Station");
        ensure!(genesis.payload["object"]["purpose"] == "agent_control" && genesis.payload["object"]["initial_history_access"] == "since_join" && genesis.payload["object"].get("founding_device_descriptor").is_none(), "Agent genesis does not use the shared control Realm policy");
        let history = db.query_one("SELECT value,current_commit_id FROM realm_bootstrap_current_states WHERE realm_id=$1 AND state_family='realm_history_access'", &[&agent_realm.as_str()])?;
        ensure!(history.get::<_,serde_json::Value>(0) == "since_join" && history.get::<_,String>(1) == genesis_commit.commit_id.as_str(), "shared control history current is not derived from the exact Agent genesis");
        ensure!(events.iter().all(|event| event.kind != arkret_wire::EventKind::MlsGenesis), "unexpected MLS genesis before encryption assertion");
        let groups: i64 = db.query_one("SELECT count(*) FROM mls_group_current_states WHERE realm_id=$1", &[&agent_realm.as_str()])?.get(0);
        ensure!(groups == 0, "Agent PCR acquired MLS state before ak.mls.genesis");
        let encryption = db.query("SELECT encryption_profile FROM realm_meta WHERE realm_id=$1", &[&agent_realm.as_str()])?;
        ensure!(encryption.iter().all(|row| row.get::<_,Option<String>>(0).is_none()), "Agent PCR inherited an encryption profile before ak.mls.genesis");
        let policies = db.query("SELECT value FROM realm_bootstrap_current_states WHERE realm_id=$1", &[&agent_realm.as_str()])?;
        ensure!(!policies.is_empty(), "Agent PCR bootstrap currents are absent");
        for policy in policies {
            let value: serde_json::Value = policy.get(0);
            ensure!(!value.as_object().is_some_and(|object| object.contains_key("content_scheme") || object.contains_key("content_encryption_floor") || object.contains_key("metadata_encryption_floor")), "Agent PCR inherited pre-MLS content scheme or floors");
        }
        let profile_rows: i64 = db.query_one("SELECT count(*) FROM actor_profile_current_states WHERE realm_id=$1", &[&agent_realm.as_str()])?.get(0);
        ensure!(profile_rows == 1, "Agent profile landed outside its PCR");
        for kind in [arkret_wire::EventKind::AgentKeyAuthorize, arkret_wire::EventKind::ProfileCreate, arkret_wire::EventKind::ProfileUpdate, arkret_wire::EventKind::SelfAgentPause, arkret_wire::EventKind::SelfAgentResume] {
            let owned: Vec<_> = events.iter().filter(|event| event.kind == kind).collect();
            ensure!(!owned.is_empty() && owned.iter().all(|event| event.actor_id == agent_actor && event.executed_by.as_ref() == Some(&controller_actor) && event.authorization_ref.as_deref() == Some(delegation.as_str())), "Agent control {kind:?} lost its exact actor/executor/delegation/PCR tuple");
        }
        let provisions = db.query("SELECT e.envelope FROM canonical_events e JOIN agent_provisioning_current_states p ON p.realm_id=e.realm_id WHERE p.agent_id=$1 AND e.kind='ak.agent.provision' AND e.envelope->'payload'->>'agent_id'=$1", &[&agent_id])?;
        ensure!(provisions.len() == 1, "Agent has more than one accepted provision");
        let provision: serde_json::Value = provisions[0].get(0);
        let provision: Event = serde_json::from_value(provision)?;
        ensure!(provision.realm_id == controller_realm && provision.actor_id == controller_actor, "provision did not land in controller PCR");
        for (table, predicate) in [("agent_provisioning_current_states", "agent_id=$2"), ("identity_accountability_current_states", "subject_id=$2"), ("agent_selector_claim_current_states", "value->'subject_account_id'->>'principal_id'=$2")] {
            let rows = db.query(&format!("SELECT c.commit_json->>'event_ref' FROM {table} p JOIN realm_commits c ON c.commit_id=p.current_commit_id WHERE p.realm_id=$1 AND {predicate}"), &[&controller_realm.as_str(), &agent_id])?;
            ensure!(rows.len() == 1 && rows[0].get::<_,String>(0) == provision.event_id.as_str(), "{table} is not the exact provision-owned controller PCR result");
        }
        println!("[agent-pcr] independent_binding=1 generation_zero_agent_creator=1 pre_mls_encryption_absent=1 controller_tuple_verified=1 profile_key_lifecycle_in_agent_pcr=1 exact_provision_currents_in_controller_pcr=1");
        Ok(())
    }).await??;
    let before =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &database.connect_url,
            true,
        )
        .await?;
    pairing_expiry_evidence::replacement_material(station, &controller, &account, &agent).await?;
    let after =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &database.connect_url,
            true,
        )
        .await?;
    ensure!(
        before["canonical_events"] == after["canonical_events"]
            && before["realm_commits"] == after["realm_commits"],
        "pairing candidate or approval notification entered PCR history"
    );
    println!("[agent-pcr] pairing_and_notifications_in_neither_pcr=1 assertions=9");
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "agent_pcr_separation".to_owned(),
            assertions: 9,
        }],
    })
}
