//! Production observations for the Agent PCR forward-declaration boundary.

use arkret_models_collaboration::agent_operations::{
    AgentList, AgentProvisionAwaitingControllerEvent, AgentProvisionComplete,
};
use arkret_wire::RealmCommit;
use serde_json::Value;

use super::*;
use crate::conformance::{CaseExecutionResult, SuiteExecutionResult};
use crate::harness::CanonicalJsonBody;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

pub(crate) struct ProvisionEvidence {
    database_url: String,
    forward_assertions: usize,
    negative_assertions: usize,
    collision_assertions: usize,
    batch_assertions: usize,
    genesis_cut: Option<Value>,
}

impl ProvisionEvidence {
    async fn snapshot(&self) -> Result<Value> {
        acceptance_rows_with_agent_stores(&self.database_url, true).await
    }

    async fn public_document(server: &ArkretServer, did: &Did) -> Result<Value> {
        let resolved: arkret_models_identity::identity::IdentityResolveOutcome =
            serde_json::from_value(
                expect_json(
                    server
                        .http()
                        .post(server.url("/_arkret/root/identity/resolve"))
                        .json(
                            &arkret_models_identity::identity::IdentityResolveRequestBody {
                                did: did.clone(),
                                requested_evidence_kinds: Vec::new(),
                            },
                        ),
                    StatusCode::OK,
                )
                .await?,
            )?;
        Ok(serde_json::to_value(resolved.did_document)?)
    }

    async fn invisible(&mut self, controller: &TestActorClient, agent: &DidCoreId) -> Result<()> {
        let list: AgentList = serde_json::from_value(
            expect_json(controller.get("/_arkret/self/agents"), StatusCode::OK).await?,
        )?;
        ensure!(
            list.agents.iter().all(|entry| entry.agent_id != *agent),
            "unfinished provision leaked into the Agent list"
        );
        let response = controller
            .get(&format!("/_arkret/self/agents/{agent}"))
            .send()
            .await?;
        ensure!(
            response.status() == StatusCode::NOT_FOUND,
            "unfinished provision leaked into the Agent resource"
        );
        self.forward_assertions += 2;
        Ok(())
    }

    async fn state(&self, realm: &RealmId, agent: &DidCoreId) -> Result<Option<Value>> {
        let url = self.database_url.clone();
        let realm = realm.to_string();
        let agent = agent.to_string();
        tokio::task::spawn_blocking(move || -> Result<_> {
            let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
            Ok(db.query_opt("SELECT value FROM agent_status_current_results WHERE realm_id=$1 AND agent_id=$2",
                &[&realm, &agent])?.map(|row| row.get(0)))
        }).await?
    }

    async fn genesis_cut(&self, realm: &RealmId) -> Result<Value> {
        let url = self.database_url.clone();
        let realm = realm.to_string();
        tokio::task::spawn_blocking(move || -> Result<_> {
            let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
            Ok(db.query_one("SELECT jsonb_build_object('status', (SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.current_key),'[]'::jsonb) FROM agent_status_current_results s WHERE realm_id=$1), 'events', (SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM canonical_events e WHERE realm_id=$1), 'commits', (SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.stream_position),'[]'::jsonb) FROM realm_commits c WHERE realm_id=$1))", &[&realm])?.get(0))
        }).await?
    }

    pub(super) async fn prepared(
        &mut self,
        server: &ArkretServer,
        controller: &TestActorClient,
        prepared: &AgentProvisionAwaitingControllerEvent,
        genesis: &Event,
    ) -> Result<()> {
        ensure!(
            serde_json::to_value(prepared)?
                .get("principal_control_realm_id")
                .is_none(),
            "prepare allocated a PCR before its content-bound genesis"
        );
        ensure!(
            genesis.realm_id == RealmId::from_event_id(&genesis.event_id)
                && genesis.semantic_refs.is_empty(),
            "genesis is not independent and content-bound"
        );
        genesis.verify_event_id_matches_content_with_digest_suite(
            arkret_canonical::DigestSuite::Sha256,
        )?;
        self.forward_assertions += 3;
        let public = Self::public_document(server, &prepared.did).await?;
        ensure!(
            public
                .get("service")
                .and_then(Value::as_array)
                .is_none_or(|services| services
                    .iter()
                    .all(|service| service["type"] != "ArkretPrincipalControlRealm")),
            "accepted inception published a future Agent PCR service"
        );
        self.forward_assertions += 1;
        self.invisible(controller, &prepared.agent_id).await?;

        let before = self.snapshot().await?;
        let problem = crate::harness::expect_api_error(
            controller
                .post("/_arkret/self/events")
                .json(&arkret_wire::EventAdmissionSubmission::new(genesis.clone())),
            StatusCode::CONFLICT,
            "failed_precondition",
        )
        .await?;
        let problem = serde_json::to_value(problem)?;
        ensure!(
            problem["reason_code"] == "agent_pcr_genesis_declaration_missing",
            "undeclared Agent genesis hit the wrong rejection: {problem}"
        );
        ensure!(
            self.snapshot().await? == before,
            "undeclared Agent genesis wrote durable state"
        );
        ensure!(
            self.state(&genesis.realm_id, &prepared.agent_id)
                .await?
                .is_none(),
            "undeclared genesis materialized lifecycle state"
        );
        self.negative_assertions += 4;
        Ok(())
    }

    pub(super) async fn declared(
        &mut self,
        server: &ArkretServer,
        controller: &TestActorClient,
        body: &AgentProvisionRequestBody,
        outcome: &AgentProvisionOutcome,
        genesis: &Event,
        provision_event: &Event,
    ) -> Result<()> {
        let AgentProvisionOutcome::AwaitingPcrGenesis(waiting) = outcome else {
            bail!("provision did not remain at the genesis boundary");
        };
        ensure!(
            waiting.principal_control_realm_id == genesis.realm_id
                && provision_event.payload["principal_control_realm_id"]
                    == genesis.realm_id.as_str(),
            "accepted provision does not declare the exact frozen genesis"
        );
        let wire = serde_json::to_value(outcome)?;
        ensure!(
            wire.get("pairing_request_id").is_none() && wire.get("pairing_code").is_none(),
            "unfounded provision exposed runtime pairing material"
        );
        self.forward_assertions += 2;
        self.invisible(controller, &waiting.agent_id).await?;
        let public = Self::public_document(server, &waiting.did).await?;
        ensure!(
            public
                .get("service")
                .and_then(Value::as_array)
                .is_none_or(|services| services
                    .iter()
                    .all(|service| service["type"] != "ArkretPrincipalControlRealm")),
            "accepted provision published the Agent PCR service before genesis"
        );
        let url = self.database_url.clone();
        let realm = genesis.realm_id.to_string();
        let (agent_id, event_ref): (String, String) = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
            let row = db.query_one("SELECT d.value->>'agent_id',c.commit_json->>'event_ref' FROM agent_pcr_genesis_declaration_current_results d JOIN realm_commits c ON c.commit_id=d.current_commit_id WHERE d.principal_control_realm_id=$1", &[&realm])?;
            Ok((row.get(0), row.get(1)))
        }).await??;
        ensure!(
            agent_id == waiting.agent_id.as_str() && event_ref == provision_event.event_id.as_str(),
            "genesis declaration does not belong to the accepted provision Event"
        );
        self.forward_assertions += 2;

        let AgentProvisionRequestBody::Commit(original) = body else {
            bail!("accepted declaration must retain its exact provision commit request");
        };
        self.reject_second_pcr_claim(server, controller, original, provision_event)
            .await?;

        // Both Events are valid, independently frozen identities. The negative
        // is the unregistered carrier, never a fabricated digest failure.
        genesis.verify_event_id_matches_content_with_digest_suite(
            arkret_canonical::DigestSuite::Sha256,
        )?;
        provision_event.verify_event_id_matches_content_with_digest_suite(
            arkret_canonical::DigestSuite::Sha256,
        )?;
        let batch = arkret_wire::EventsSubmitBatchRequestBody {
            events: vec![
                original.provision_event.clone(),
                arkret_wire::EventAdmissionSubmission::new(genesis.clone()),
            ],
        };
        let before = self.snapshot().await?;
        crate::harness::expect_api_error(
            controller
                .post("/_arkret/self/events")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(arkret_canonical::canonical_json_bytes(&batch)?),
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
        )
        .await?;
        ensure!(
            self.snapshot().await? == before,
            "unsupported Agent batch carrier changed complete accepted/Agent state"
        );
        self.batch_assertions += 3;

        // Reopen the original serialized intent before recovery. The retry
        // cannot mint replacement Event ids, proofs or allocation bindings.
        let frozen = arkret_canonical::canonical_json_bytes(body)?;
        let journal = tempfile::NamedTempFile::new()?;
        std::fs::write(journal.path(), &frozen)?;
        journal.as_file().sync_all()?;
        let recovered: AgentProvisionRequestBody =
            serde_json::from_slice(&std::fs::read(journal.path())?)?;
        ensure!(arkret_canonical::canonical_json_bytes(&recovered)? == frozen);
        let before = self.snapshot().await?;
        let replay = provision(controller, &recovered, StatusCode::OK).await?;
        ensure!(
            serde_json::to_value(replay)? == wire,
            "provision replay changed its first outcome"
        );
        ensure!(
            self.snapshot().await? == before,
            "provision replay added durable accepting effects"
        );
        self.forward_assertions += 3;
        Ok(())
    }

    async fn reject_second_pcr_claim(
        &mut self,
        server: &ArkretServer,
        controller: &TestActorClient,
        original: &AgentProvisionCommitRequestBody,
        provision_event: &Event,
    ) -> Result<()> {
        let ActorId::Account { account_id } = &provision_event.actor_id else {
            bail!("first provision is not authored by its controller Account");
        };
        let principal = controller
            .principal
            .as_ref()
            .context("controller principal")?;
        let method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?;
        let local_id = format!("genesis-claim-collision-{}", unique_uuid7());
        let root_seed = arkret_canonical::sha256_bytes(local_id.as_bytes());
        let next_seed = arkret_canonical::sha256_bytes(format!("{local_id}:next").as_bytes());
        let endpoint = url::Url::parse(&server.url("/"))?;
        let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&next_seed)
                .verifying_key()
                .as_bytes(),
        );
        let inception = arkret_signatures::webvh::prepare_agent_inception(
            &arkret_signatures::webvh::AgentInceptionInput {
                principal_endpoint: &endpoint,
                local_id: &local_id,
                controller_principal_id: &account_id.principal_id,
                version_time: Utc::now() - chrono::Duration::seconds(5),
                root_seed: &root_seed,
                next_root_public_key_multibase: &next_key,
            },
        )?;
        submit_did_operation(server, &inception.submit_body).await?;
        let did = Did::new(inception.did.clone())?;
        let operation_id = ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?;
        let idempotency_key = IdempotencyKey::new(unique_uuid7()).map_err(anyhow::Error::msg)?;
        let slug = "genesis-claim-collision".to_owned();
        let prepared = provision(
            controller,
            &AgentProvisionRequestBody::Prepare(AgentProvisionPrepareRequestBody {
                phase: AgentProvisionPreparePhase::Prepare,
                operation_id: operation_id.clone(),
                idempotency_key: idempotency_key.clone(),
                did: did.clone(),
                slug: slug.clone(),
                requested_scope: original.requested_scope.clone(),
                pairing_ttl_ms: None,
                controller_station_id: account_id.station_id.clone(),
            }),
            StatusCode::OK,
        )
        .await?;
        let AgentProvisionOutcome::AwaitingControllerEvent(prepared) = prepared else {
            bail!("second Agent prepare did not await its controller Event");
        };
        ensure!(
            prepared.agent_id != original.agent_id
                && prepared.initial_resolution.did == did
                && prepared.initial_resolution.version_id == inception.version_id,
            "the collision must use a distinct real accepted Agent inception"
        );
        let scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
            &prepared.agent_id,
            &account_id.principal_id,
            &original.requested_scope,
        )?;
        let candidate = sign(
            arkret_bootstrap::build_agent_provision_intent(
                &account_id.principal_id,
                &prepared.controller_realm_id,
                &prepared.agent_id,
                &original.principal_control_realm_id,
                &prepared.controller_authorization_ref,
                &slug,
                &scope_digest,
                arkret_models_identity::handle::HandleVisibility::Private,
                None,
                arkret_bootstrap::AgentProvisionIntentOptions {
                    controller_station_id: account_id.station_id.clone(),
                    created_at: Utc::now(),
                },
            )?,
            &method,
            principal.device_signing_key.to_bytes(),
        )?;
        candidate.verify_event_id_matches_content_with_digest_suite(
            arkret_canonical::DigestSuite::Sha256,
        )?;
        ensure!(
            candidate.event_id != provision_event.event_id
                && candidate.payload["principal_control_realm_id"]
                    == original.principal_control_realm_id.as_str(),
            "second provision is not a distinct content-bound claim of the same PCR id"
        );
        let request = AgentProvisionRequestBody::Commit(AgentProvisionCommitRequestBody {
            phase: AgentProvisionCommitPhase::Commit,
            operation_id,
            idempotency_key,
            agent_id: prepared.agent_id,
            did,
            principal_control_realm_id: original.principal_control_realm_id.clone(),
            slug,
            requested_scope: original.requested_scope.clone(),
            allocation_handle: prepared.allocation_handle,
            provision_event: arkret_wire::EventAdmissionSubmission::new(candidate),
            pairing_ttl_ms: None,
        });
        let before = self.snapshot().await?;
        let problem = crate::harness::expect_api_error(
            controller
                .post("/_arkret/self/agents")
                .canonical_json(&request)?,
            StatusCode::CONFLICT,
            "failed_precondition",
        )
        .await?;
        ensure!(
            serde_json::to_value(problem)?["reason_code"]
                == "agent_pcr_genesis_declaration_conflict",
            "duplicate PCR declaration did not return its exact registered reason"
        );
        ensure!(
            self.snapshot().await? == before,
            "rejected second declaration changed accepted business or Agent state"
        );
        self.collision_assertions += 6;
        Ok(())
    }

    pub(super) async fn founded(
        &mut self,
        server: &ArkretServer,
        controller: &TestActorClient,
        body: &AgentProvisionRequestBody,
        outcome: &AgentProvisionOutcome,
        genesis: &Event,
        commit: &RealmCommit,
    ) -> Result<()> {
        let AgentProvisionOutcome::AwaitingDidBinding(waiting) = outcome else {
            bail!("genesis did not stop before the continuous DID binding");
        };
        self.invisible(controller, &waiting.agent_id).await?;
        let public = Self::public_document(server, &waiting.did).await?;
        ensure!(
            public
                .get("service")
                .and_then(Value::as_array)
                .is_none_or(|services| services
                    .iter()
                    .all(|service| service["type"] != "ArkretPrincipalControlRealm")),
            "genesis published the Agent PCR service before continuous DID entry 1"
        );
        self.forward_assertions += 1;
        ensure!(
            self.state(&genesis.realm_id, &waiting.agent_id).await? == Some(json!("active")),
            "genesis did not establish the sole initial active current"
        );
        let submission = arkret_wire::EventAdmissionSubmission::new(genesis.clone());
        let frozen = arkret_canonical::canonical_json_bytes(&submission)?;
        let journal = tempfile::NamedTempFile::new()?;
        std::fs::write(journal.path(), &frozen)?;
        journal.as_file().sync_all()?;
        let recovered: arkret_wire::EventAdmissionSubmission =
            serde_json::from_slice(&std::fs::read(journal.path())?)?;
        ensure!(arkret_canonical::canonical_json_bytes(&recovered)? == frozen);
        let before = self.snapshot().await?;
        let replay: AuthoritySubmitOutcome = serde_json::from_value(
            expect_json(
                controller.post("/_arkret/self/events").json(&recovered),
                StatusCode::OK,
            )
            .await?,
        )?;
        ensure!(
            matches!(replay, AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate, commit: ref original
        } if original == commit),
            "genesis replay lost the original accepted Commit"
        );
        ensure!(
            self.snapshot().await? == before,
            "genesis replay changed durable state"
        );
        let replay = provision(controller, body, StatusCode::OK).await?;
        ensure!(
            serde_json::to_value(replay)? == serde_json::to_value(outcome)?,
            "provision recovery changed its awaiting-DID binding"
        );
        self.forward_assertions += 5;

        let before_agent = self.state(&genesis.realm_id, &waiting.agent_id).await?;
        let ordinary = crate::scenarios::human_device_producer_live::create_realm_with_join_rule(
            controller,
            "ordinary-create-does-not-activate-agent",
            "closed",
            &[],
        )
        .await?;
        ensure!(self.state(&genesis.realm_id, &waiting.agent_id).await? == before_agent);
        let url = self.database_url.clone();
        let declarations: i64 = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
            Ok(db.query_one("SELECT count(*) FROM agent_pcr_genesis_declaration_current_results WHERE principal_control_realm_id=$1",
                &[&ordinary])?.get(0))
        }).await??;
        ensure!(
            declarations == 0,
            "ordinary Realm create entered the Agent declaration index"
        );
        self.forward_assertions += 2;
        self.genesis_cut = Some(self.genesis_cut(&genesis.realm_id).await?);
        Ok(())
    }

    pub(super) async fn bound(
        &mut self,
        server: &ArkretServer,
        controller: &TestActorClient,
        outcome: &AgentProvisionComplete,
    ) -> Result<()> {
        ensure!(
            self.state(&outcome.principal_control_realm_id, &outcome.agent_id)
                .await?
                == Some(json!("active")),
            "accepted DID binding did not activate the Agent"
        );
        ensure!(
            Some(
                self.genesis_cut(&outcome.principal_control_realm_id)
                    .await?
            ) == self.genesis_cut,
            "DID binding or provision completion rewrote the accepted genesis lifecycle cut"
        );
        self.forward_assertions += 1;
        ensure!(!outcome.pairing_request_id.as_str().is_empty() && outcome.pairing_code.is_some());
        let public = Self::public_document(server, &outcome.did).await?;
        let services = public
            .get("service")
            .and_then(Value::as_array)
            .context("bound Agent has no DID services")?;
        ensure!(
            services
                .iter()
                .filter(|service| service["type"] == "ArkretPrincipalControlRealm")
                .count()
                == 1,
            "DID entry 1 does not expose exactly one accepted Agent PCR binding"
        );
        self.forward_assertions += 1;
        let view: arkret_models_collaboration::agent_operations::AgentView =
            serde_json::from_value(
                expect_json(
                    controller.get(&format!("/_arkret/self/agents/{}", outcome.agent_id)),
                    StatusCode::OK,
                )
                .await?,
            )?;
        ensure!(
            view.agent.agent_id == outcome.agent_id,
            "complete Agent is not visible"
        );
        self.forward_assertions += 3;
        Ok(())
    }
}

pub async fn run_agent_genesis_production_cases() -> Result<SuiteExecutionResult> {
    let name = "agent-genesis-named-production";
    let database = database(name)?.context("Agent named production cases require PostgreSQL")?;
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        name,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    .context("Agent named production cases require the current Coland binary")?;
    let station = group.server(0);
    let (controller, account) =
        standard_client(station, &coauth, "genesis-controller", CONTROLLER_DEVICE).await?;
    let mut evidence = ProvisionEvidence {
        database_url: database.connect_url.clone(),
        forward_assertions: 0,
        negative_assertions: 0,
        collision_assertions: 0,
        batch_assertions: 0,
        genesis_cut: None,
    };
    AgentRuntimeSession::establish_observed(
        station,
        &coauth,
        &controller,
        &account,
        "genesis-agent",
        &runtime_operations(),
        Some(&mut evidence),
    )
    .await?;
    Ok(SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![
            CaseExecutionResult {
                case_id: "agent_pcr_genesis_forward_declaration".into(),
                assertions: evidence.forward_assertions,
            },
            CaseExecutionResult {
                case_id: "agent_pcr_genesis_without_declaration_rejected".into(),
                assertions: evidence.negative_assertions,
            },
            CaseExecutionResult {
                case_id: "two_provisions_declaring_one_realm_id_rejected".into(),
                assertions: evidence.collision_assertions,
            },
            CaseExecutionResult {
                case_id: "agent_pcr_genesis_same_batch_rejected".into(),
                assertions: evidence.batch_assertions,
            },
        ],
    })
}
