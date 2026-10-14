//! Real structured Agent subject grant admission under the provision ceiling.

use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

async fn execute_owned_sql(url: &str, sql: &'static str) -> Result<()> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        postgres::Client::connect(&url, postgres::NoTls)?.batch_execute(sql)?;
        Ok(())
    })
    .await?
}

pub async fn run_agent_provision_grant_ceiling_boundary() -> Result<()> {
    let name = "agent-provision-grant-ceiling-production";
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
    .context("current real Station process required")?;
    let station = group.server(0);
    let (controller, account) = standard_client(
        station,
        &coauth,
        "grant-ceiling-controller",
        CONTROLLER_DEVICE,
    )
    .await?;
    let created = controller
        .create_realm_with(json!({
            "title": "Agent grant ceiling", "public": false, "join_rule": "public",
            "plaintext_visible_services": [station.service_id()]
        }))
        .await?;
    let outside = controller
        .create_realm_with(json!({
            "title": "Outside Agent provision ceiling", "public": false, "join_rule": "public",
            "plaintext_visible_services": [station.service_id()]
        }))
        .await?;
    let realm = RealmId::new(created["realm_id"].as_str().context("grant Realm")?)?;
    let outside_realm = RealmId::new(outside["realm_id"].as_str().context("outside Realm")?)?;
    let mut scope = requested_scope(&runtime_operations())?;
    scope.actions.push("ak.event.read".to_owned());
    scope.resources.push(serde_json::from_value(
        json!({"kind":"realm", "realm_id":realm}),
    )?);
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraint, GrantConstraintEffect, GrantConstraintKind, GrantConstraintSubkind,
    };
    let mut mandatory = GrantConstraint::new(
        GrantConstraintKind::ClaimBased,
        GrantConstraintEffect::Allow,
    );
    mandatory.constraint_subkind = Some(GrantConstraintSubkind::Approval);
    mandatory.controller_approval_required = Some(true);
    scope.constraints.push(mandatory.clone());
    let agent = AgentRuntimeSession::establish_paired_observed(
        station,
        &AgentSessionIssuer::Fixture(&coauth),
        &controller,
        &account,
        "grant-ceiling-agent",
        scope,
        None,
    )
    .await?;
    for (joined_realm, created) in [(&realm, &created), (&outside_realm, &outside)] {
        let generation = EventId::new(
            created["event_response"]["commits"]
                .as_array()
                .and_then(|commits| commits.last())
                .and_then(|commit| commit["event_ref"].as_str())
                .context("controller membership generation")?,
        )?;
        let mut join = MembershipPayload::join(
            joined_realm.clone(),
            ActorId::account(agent.agent_account.clone()),
            "controller joins Agent for actual grant admission",
        );
        join.agent_controller_binding = Some(AgentControllerMembershipBinding {
            controller_account_id: account.clone(),
            controller_membership_generation_ref: generation,
            controller_terminal_event_ref: None,
        });
        controller
            .submit_event(joined_realm.as_str(), "ak.member.state", join.to_value()?)
            .await?;
    }
    for (action, grant_realm, preserve_constraint, wildcard, accepted) in [
        ("ak.message.create", &realm, true, false, false),
        ("ak.event.read", &outside_realm, true, false, false),
        ("ak.event.read", &realm, false, false, false),
        ("ak.event.read", &realm, true, true, false),
        ("ak.event.read", &realm, true, false, true),
    ] {
        let payload = arkret_models_collaboration::events_payloads::CapabilityGrantPayload {
            grant: arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody {
                schema: SchemaId::CAPABILITY_V1.to_owned(),
                realm_id: Some(grant_realm.clone()),
                issuer_id: ActorId::account(account.clone()),
                subject: arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(
                    ActorId::account(agent.agent_account.clone()),
                ),
                actions: vec![action.to_owned()],
                resources: vec![if wildcard {
                    serde_json::from_value(json!({"kind":"*"}))?
                } else {
                    arkret_wire::WireResourceSelector::realm(grant_realm.clone())
                }],
                constraints: if preserve_constraint { vec![mandatory.clone()] } else { Vec::new() },
                issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
                    realm_id: grant_realm.clone(), authority_event_ref: grant_realm.event_id(), authority_generation: 0,
                }],
                issued_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
            },
        };
        let event = controller
            .author_event(
                grant_realm.as_str(),
                "ak.capability.grant",
                serde_json::to_value(payload)?,
            )
            .await?;
        ensure!(
            event.payload["grant"]["subject"].is_object(),
            "grant subject is not the formal structured Actor"
        );
        let bytes = arkret_canonical::canonical_json_bytes(
            &arkret_wire::EventAdmissionSubmission::new(event.clone()),
        )?;
        if accepted {
            let method = event
                .producer_proof
                .as_ref()
                .context("grant controller proof absent")?
                .verification_method
                .clone();
            for label in [
                "service_method",
                "service_key_under_controller_method",
                "dev_proof",
            ] {
                let mut substituted = event.clone();
                if label == "dev_proof" {
                    substituted
                        .producer_proof
                        .as_mut()
                        .context("grant proof absent")?
                        .kind = "dev-proof".to_owned();
                } else {
                    substituted.producer_proof = None;
                    let signing_method = if label == "service_method" {
                        DidUrl::new(format!("{}#federation-fanout-key", station.service_did()))
                            .map_err(anyhow::Error::msg)?
                    } else {
                        method.clone()
                    };
                    substituted = sign(
                        arkret_wire::AuthoredEvent::from_verified_with_digest_suite(
                            substituted,
                            arkret_canonical::DigestSuite::Sha256,
                        )?,
                        &signing_method,
                        station.federation_signing_key()?.to_bytes(),
                    )?;
                }
                let before = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
                let response = controller
                    .post("/_arkret/self/events")
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(arkret_canonical::canonical_json_bytes(
                        &arkret_wire::EventAdmissionSubmission::new(substituted),
                    )?)
                    .send()
                    .await?;
                let status = response.status();
                let problem: arkret_wire::Problem = response.json().await?;
                let expected = if label == "dev_proof" {
                    "schema_violation"
                } else {
                    "signature_invalid"
                };
                ensure!(
                    status.is_client_error() && problem.code() == expected,
                    "ordinary grant {label} reached wrong refusal: {}: {}",
                    problem.code(),
                    problem.detail
                );
                ensure!(
                    acceptance_rows_with_agent_stores(&database.connect_url, true).await? == before,
                    "ordinary grant proof substitute changed full accepted/Agent state"
                );
                println!(
                    "[agent-provision-grant] rejected={label} code={expected} full_footprint_unchanged=1"
                );
            }
            execute_owned_sql(&database.connect_url,
                "CREATE FUNCTION agent_grant_projection_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned Agent grant projection fault'; END $$; CREATE TRIGGER agent_grant_projection_fault BEFORE INSERT OR UPDATE ON capability_grant_current_results FOR EACH ROW EXECUTE FUNCTION agent_grant_projection_fault()").await?;
            let before_fault =
                acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
            let failed = controller
                .post("/_arkret/self/events")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes.clone())
                .send()
                .await?;
            ensure!(
                failed.status() == StatusCode::INTERNAL_SERVER_ERROR,
                "late grant write fault did not reach its writer: {} {}",
                failed.status(),
                failed.text().await?
            );
            ensure!(
                acceptance_rows_with_agent_stores(&database.connect_url, true).await?
                    == before_fault,
                "late grant write fault changed accepted/Agent state"
            );
            execute_owned_sql(&database.connect_url,
                "DROP TRIGGER agent_grant_projection_fault ON capability_grant_current_results; DROP FUNCTION agent_grant_projection_fault()").await?;
        }
        let before = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
        let response = controller
            .post("/_arkret/self/events")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes.clone())
            .send()
            .await?;
        if accepted {
            ensure!(
                response.status() == StatusCode::OK,
                "narrower grant refused: {} {}",
                response.status(),
                response.text().await?
            );
            let outcome: AuthoritySubmitOutcome = response.json().await?;
            let AuthoritySubmitOutcome::Accepted { commit, .. } = outcome else {
                bail!("narrower grant was not accepted")
            };
            ensure!(
                commit.event_ref == event.event_id,
                "grant attach changed the authored Event"
            );
            let stored = controller
                .sdk()
                .committed_event_get(&event.event_id)
                .await?;
            ensure!(
                stored.reducer_input() == Some(&event),
                "grant envelope bytes changed during admission"
            );
            let after = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
            let replay: AuthoritySubmitOutcome = controller
                .post("/_arkret/self/events")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            ensure!(
                matches!(replay, AuthoritySubmitOutcome::Accepted { commit: ref original, .. }
                if original == &commit),
                "exact grant replay changed its Commit"
            );
            ensure!(
                acceptance_rows_with_agent_stores(&database.connect_url, true).await? == after,
                "exact grant replay wrote new state"
            );
            // Revoke through the real controller PCR writer. A fresh Event
            // probes the current gate; the already accepted exact replay must
            // retain its historical outcome independently of this new cut.
            coauth_session_evidence::set_accountability_for_agent(
                &controller, &agent.agent_account.principal_id, &account,
                arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Revoked,
            ).await?;
            let fresh = controller
                .author_event(
                    grant_realm.as_str(),
                    "ak.capability.grant",
                    serde_json::to_value(&event.payload)?,
                )
                .await?;
            ensure!(
                fresh.event_id != event.event_id,
                "missing accountability probe reused an accepted Event"
            );
            let fresh_bytes = arkret_canonical::canonical_json_bytes(
                &arkret_wire::EventAdmissionSubmission::new(fresh.clone()),
            )?;
            let before = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
            let problem = crate::harness::expect_api_error(
                controller
                    .post("/_arkret/self/events")
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(fresh_bytes),
                StatusCode::CONFLICT,
                "failed_precondition",
            )
            .await?;
            ensure!(
                problem
                    .extensions
                    .get("reason_code")
                    .and_then(serde_json::Value::as_str)
                    == Some(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING),
                "revoked accountability did not reach its formal grant gate: {}",
                problem.code()
            );
            ensure!(
                acceptance_rows_with_agent_stores(&database.connect_url, true).await? == before,
                "fresh grant without accountability changed accepted/Agent state"
            );
            coauth_session_evidence::set_accountability_for_agent(
                &controller, &agent.agent_account.principal_id, &account,
                arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Active,
            ).await?;
            println!(
                "[agent-provision-grant] fresh_grant_after_actual_accountability_revoke=accountability_grant_missing full_footprint_unchanged=1"
            );
        } else {
            ensure!(
                !response.status().is_success(),
                "out-of-ceiling structured Agent grant was admitted"
            );
            let problem: arkret_wire::Problem = response.json().await?;
            ensure!(
                serde_json::to_value(&problem)?["reason_code"]
                    == "agent_grant_exceeds_requested_scope",
                "wrong grant ceiling refusal: {problem:?}"
            );
            ensure!(
                acceptance_rows_with_agent_stores(&database.connect_url, true).await? == before,
                "refused grant changed complete accepted/Agent state"
            );
        }
    }
    Ok(())
}
