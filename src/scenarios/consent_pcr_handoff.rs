//! Real signed PCR handoff after a scoped native private-state import.
use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::authority_commit::{
    AuthorityHandoffRequest, HistoricalProducerSignerFactEntry, historical_signer_facts_digest,
};
use arkret_wire::{
    AuthorityBundleRequest, Base64UrlString, DetachedSignatureContext, DidUrl, EventKind, Hash,
    RealmAuthorityHandoff, RealmAuthorityHandoffId, RealmAuthorityTransition,
};
use coland_storage::AuthorityCommitStore;
use coland_storage_postgres::{Db, PgAuthorityCommitStore, PoolTuning};

use super::consent_call_context::ConsentCallContext;

pub struct HandoffRecovery {
    before: serde_json::Value,
    from: usize,
    to: usize,
    generation: u64,
}

pub async fn handoff(context: &mut ConsentCallContext, from: usize, to: usize) -> Result<()> {
    let recovery = crate::harness::heap_future(|| activate_handoff(context, from, to)).await?;
    recover_handoff(context, recovery).await
}

pub async fn activate_handoff(
    context: &mut ConsentCallContext,
    from: usize,
    to: usize,
) -> Result<HandoffRecovery> {
    ensure!(from != to, "PCR handoff requires independent Stations");
    let holder = &context.holder;
    let realm = holder
        .client
        .principal
        .as_ref()
        .context("actual holder inception")?
        .pcr_realm_id
        .clone();
    let old = context.stations.server(from);
    let new = context.stations.server(to);
    let mut nonce_bytes = [0u8; 32];
    getrandom::fill(&mut nonce_bytes).map_err(anyhow::Error::msg)?;
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode(nonce_bytes))
        .map_err(anyhow::Error::msg)?;
    let bundle_request = AuthorityBundleRequest {
        realm_id: realm.clone(),
        nonce,
    };
    let bundle = holder
        .client
        .sdk()
        .realm_authority_bundle(&bundle_request)
        .await?;
    ensure!(
        bundle.current_service_id == *old.service_id(),
        "starting PCR governor mismatch"
    );
    let generation = bundle.current_generation;
    let before: serde_json::Value = holder
        .client
        .get("/_arkret/self/consent/results")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let change=holder.client.author_event(realm.as_str(),EventKind::RealmGovernanceStationChange.as_str(),serde_json::json!({"expected_governance_generation":generation,"expected_realm_stream_commit_id":bundle.realm_stream_head.commit_id,"new_governance_station_id":new.service_id()})).await?;
    let changed = super::human_device_producer_live::submit_and_expect_commit(
        &holder.client,
        &holder.account,
        holder.device.as_str(),
        &change,
    )
    .await?;
    let source = Db::connect(
        Some(&context.databases[from].connect_url),
        PoolTuning::default(),
    )
    .await?;
    let target = Db::connect(
        Some(&context.databases[to].connect_url),
        PoolTuning::default(),
    )
    .await?;
    let source = PgAuthorityCommitStore {
        pool: source.pool.context("source native pool")?,
    };
    let target = PgAuthorityCommitStore {
        pool: target.pool.context("target native pool")?,
    };
    let (manifest, private_bytes) = source.export_pcr_private_state(&holder.account).await?;
    let private_bytes = zeroize::Zeroizing::new(private_bytes);
    let mut material = source
        .realm_state_snapshot_material(&realm)
        .await?
        .context("complete private snapshot material")?;
    material
        .visible_stream_heads
        .sort_by(|a, b| a.stream_ref.cmp(&b.stream_ref));
    let old_key = old.federation_signing_key()?;
    let new_key = new.federation_signing_key()?;
    let old_method =
        DidUrl::new(format!("{}#notary-key", old.service_did())).map_err(anyhow::Error::msg)?;
    let new_method =
        DidUrl::new(format!("{}#notary-key", new.service_did())).map_err(anyhow::Error::msg)?;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        old_method.clone(),
        &old_key,
        at,
    )?;
    let originals = source.handoff_originals(&realm).await?;
    let mut facts = Vec::<HistoricalProducerSignerFactEntry>::new();
    for full in &originals {
        if let Some(fact) = source
            .producer_signer_fact(&full.event, &full.commit)
            .await?
        {
            facts.push(HistoricalProducerSignerFactEntry {
                target: arkret_wire::CommittedEventRef {
                    event_id: full.event.event_id.clone(),
                    commit_id: full.commit.commit_id.clone(),
                    stream_ref: full.commit.stream_ref.clone(),
                    stream_position: full.commit.stream_position,
                },
                producer_signer_fact: fact,
            });
        }
    }
    facts.sort_by_key(|entry| {
        (
            arkret_canonical::canonical_json_bytes(&entry.target.stream_ref).unwrap(),
            entry.target.stream_position,
            entry.target.event_id.to_string(),
            entry.target.commit_id.to_string(),
        )
    });
    let heads = material.visible_stream_heads;
    let mut handoff = RealmAuthorityHandoff {
        handoff_id: RealmAuthorityHandoffId::from_digest(arkret_canonical::sha256_bytes(
            change.event_id.as_str().as_bytes(),
        )),
        realm_id: realm.clone(),
        from_generation: generation,
        to_generation: generation + 1,
        from_service_id: old.service_id().clone(),
        to_service_id: new.service_id().clone(),
        change_event_ref: change.event_id.clone(),
        change_commit_id: changed.commit_id.clone(),
        final_stream_heads_digest: Hash::new(arkret_canonical::canonical_sha256(&heads)?)?,
        historical_signer_facts_digest: Some(historical_signer_facts_digest(&facts)?),
        pcr_private_state_digest: Some(manifest.digest()?),
        snapshot_ref: snapshot.snapshot_id.clone(),
        old_authority_signature: changed.signature.clone(),
        new_authority_acceptance_signature: changed.signature.clone(),
    };
    let sign = |value: &serde_json::Value,
                context,
                method: DidUrl,
                key: &ed25519_dalek::SigningKey| {
        arkret_signatures::detached_object::sign_detached_object(value, context, method, at, key)
    };
    let unsigned = arkret_canonical::unsigned_value(
        &handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )?;
    handoff.old_authority_signature = sign(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        old_method,
        &old_key,
    )?;
    handoff.new_authority_acceptance_signature = sign(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        new_method.clone(),
        &new_key,
    )?;
    let mut bundle = holder
        .client
        .sdk()
        .realm_authority_bundle(&bundle_request)
        .await?;
    bundle.authority_transitions.push(RealmAuthorityTransition {
        change_event: change,
        change_commit: changed,
        handoff: handoff.clone(),
    });
    bundle.current_generation = generation + 1;
    bundle.current_service_id = new.service_id().clone();
    bundle.current_route_record =
        serde_json::to_value(new.sdk()?.open_service_resolution(new.service_id()).await?)?;
    bundle.bundle_issued_at = at;
    bundle.current_assertion.current_generation = generation + 1;
    bundle.current_assertion.current_service_id = new.service_id().clone();
    bundle.current_assertion.last_handoff_ref = Some(handoff.handoff_id.clone());
    bundle.current_assertion.expires_at = at + chrono::Duration::seconds(60);
    bundle.current_assertion.signature = sign(
        &arkret_canonical::unsigned_value(&bundle.current_assertion, &["signature"])?,
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        new_method,
        &new_key,
    )?;
    let activation = AuthorityHandoffRequest {
        handoff,
        final_stream_heads: heads,
        snapshot,
        authority_bundle: bundle,
        historical_signer_facts: Some(facts),
        pcr_private_state: Some(manifest.clone()),
    };
    activation.validate_new_handoff()?;
    activation.validate_imported_signer_facts(&originals)?;
    let bytes = arkret_canonical::canonical_json_bytes(&activation)?;
    // Missing private state cannot activate the incoming Station.
    let (status, _) = new
        .signed_peer_post(
            old,
            "/_arkret/peer/realm-authority/handoff",
            &bytes,
            new.service_id(),
        )
        .await?;
    ensure!(
        !status.is_success(),
        "unimported PCR activated from a manifest alone"
    );
    target
        .import_pcr_private_state(&manifest, &private_bytes)
        .await?;
    for (receiver, sender) in [(new, old), (old, new)] {
        let (status, body) = receiver
            .signed_peer_post(
                sender,
                "/_arkret/peer/realm-authority/handoff",
                &bytes,
                receiver.service_id(),
            )
            .await?;
        ensure!(
            status.is_success(),
            "native PCR activation: {status} {}",
            String::from_utf8_lossy(&body)
        );
    }
    let after: serde_json::Value = holder
        .client
        .get("/_arkret/self/consent/results")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        after == before,
        "handoff changed Consent identities or original revisions"
    );
    let authority = target
        .current_authority(&realm)
        .await?
        .context("incoming native authority")?;
    ensure!(
        authority.generation == generation + 1 && authority.service_id == *new.service_id(),
        "incoming authority did not advance exactly once"
    );
    Ok(HandoffRecovery {
        before,
        from,
        to,
        generation,
    })
}

pub async fn recover_handoff(
    context: &mut ConsentCallContext,
    recovery: HandoffRecovery,
) -> Result<()> {
    let HandoffRecovery {
        before,
        from,
        to,
        generation,
    } = recovery;
    for index in [from, to] {
        context
            .stations
            .server_mut(index)
            .restart_external_process()
            .await?;
    }
    let cold: serde_json::Value = context
        .holder
        .client
        .get("/_arkret/self/consent/results")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        cold == before,
        "cold private proxy recovery changed the holder Consent view"
    );
    println!(
        "[2141-pcr-handoff] source_generation={generation} scoped_native_import=1 signed_peer_activation=1 hosting_private_proxy=1 independent_database_recovery=1"
    );
    Ok(())
}

async fn private_cell_revision(database: &str, holder: &arkret_wire::AccountId) -> Result<i64> {
    let database = database.to_owned();
    let actor = arkret_wire::ActorId::account(holder.clone()).to_string();
    tokio::task::spawn_blocking(move ||->Result<i64>{let mut db=postgres::Client::connect(&database,postgres::NoTls)?;Ok(db.query_one("SELECT COALESCE((SELECT revision FROM account_datas WHERE actor_id=$1 AND account_data_key='ak.account.holder_quarantine'),0)::bigint",&[&actor])?.get(0))}).await?
}
async fn private_publication_recovery(
    context: &mut ConsentCallContext,
    current: usize,
    pause_file: &std::path::Path,
) -> Result<()> {
    use arkret_models_collaboration::consent_private::*;
    let holder = context.holder.account.clone();
    let actor = arkret_wire::ActorId::account(context.denied_holder.account.clone());
    let realm = context
        .holder
        .client
        .principal
        .as_ref()
        .context("holder inception")?
        .pcr_realm_id
        .clone();
    let bundle = context
        .holder
        .client
        .sdk()
        .realm_authority_bundle(&AuthorityBundleRequest {
            realm_id: realm.clone(),
            nonce: Base64UrlString::new(arkret_canonical::base64url_encode([88; 32]))
                .map_err(anyhow::Error::msg)?,
        })
        .await?;
    let before = private_cell_revision(&context.databases[1].connect_url, &holder).await?;
    let request = ConsentPrivateProxyRequest {
        holder_account_id: holder.clone(),
        realm_id: realm,
        governance_generation: bundle.current_generation,
        nonce: arkret_canonical::base64url_encode([89; 32]),
        expires_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
            + chrono::Duration::seconds(30),
        context: ConsentPrivateContext::Station(ConsentPrivateStationContext {
            kind: ConsentPrivateStationContextKind::Station,
            actor_id: arkret_wire::ActorId::service(holder.station_id.clone()),
        }),
        command: ConsentPrivateCommand::Request(ConsentPrivateRequestCommand {
            kind: ConsentPrivateRequestCommandKind::Request,
            body: ConsentPrivateRequestBody {
                requester_actor_id: actor,
                request: serde_json::from_value(
                    serde_json::json!({"holder_account_id":holder,"consent_scope":"presence"}),
                )?,
            },
        }),
    };
    tokio::fs::write(pause_file, b"pause").await?;
    let receiver = context.stations.server(current);
    let sender = context.stations.server(1);
    let bytes = arkret_canonical::canonical_json_bytes(&request)?;
    let (status, body) = receiver
        .signed_peer_post(
            sender,
            "/_arkret/peer/consent/proxy",
            &bytes,
            receiver.service_id(),
        )
        .await?;
    ensure!(
        status.is_success(),
        "actual authority did not accept the authenticated hosting command before publication outage: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let outcome: ConsentPrivateProxyOutcome = serde_json::from_slice(&body)?;
    outcome.validate_for_request(&request, chrono::Utc::now())?;
    let committed = private_cell_revision(&context.databases[current].connect_url, &holder).await?;
    ensure!(
        committed > before,
        "private acceptance did not advance its original cell"
    );
    context
        .stations
        .server_mut(1)
        .stop_external_process()
        .await?;
    context
        .stations
        .server_mut(current)
        .restart_external_process()
        .await?;
    context
        .stations
        .server_mut(1)
        .start_external_process()
        .await?;
    ensure!(
        private_cell_revision(&context.databases[1].connect_url, &holder).await? == before,
        "publication escaped the deterministic outage schedule"
    );
    tokio::fs::remove_file(pause_file).await?;
    // No holder GET/pull occurs here: only the production recovery worker can
    // materialize this accepted revision in the independent hosting database.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if private_cell_revision(&context.databases[1].connect_url, &holder).await? == committed {
            break;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "durable authority publication did not recover to the hosting database"
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    ensure!(
        private_cell_revision(&context.databases[1].connect_url, &holder).await? == committed,
        "publication recovery repeated the business revision"
    );
    context
        .stations
        .server_mut(current)
        .stop_external_process()
        .await?;
    let response = context
        .holder
        .client
        .get("/_arkret/self/invite-receive-policy")
        .send()
        .await?;
    ensure!(
        !response.status().is_success(),
        "hosting served a stale policy while the actual PCR authority was unavailable"
    );
    context
        .stations
        .server_mut(current)
        .start_external_process()
        .await?;
    println!(
        "[2141-pcr-handoff] actual_private_acceptance=1 authority_restart=1 hosting_outage=1 durable_publication_recovery=1 no_second_revision=1 unavailable_authority_no_cached_policy=1"
    );
    Ok(())
}

async fn remote_invite_on_current_authority(context: &ConsentCallContext) -> Result<()> {
    let policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy =
        serde_json::from_value(
            crate::harness::expect_json(
                context
                    .holder
                    .client
                    .get("/_arkret/self/invite-receive-policy"),
                reqwest::StatusCode::OK,
            )
            .await?,
        )?;
    crate::harness::expect_json(
        context
            .holder
            .client
            .put("/_arkret/self/invite-receive-policy")
            .json(&policy),
        reqwest::StatusCode::OK,
    )
    .await?;
    use arkret_models_collaboration::governance::invite_addressing::IntroductionEvidence;
    let (grant, event) = super::invite_service_fanout_live::grant_invite_consent(
        &context.holder.client,
        &context.caller.client,
    )
    .await?;
    let prepared = super::invite_service_fanout_live::prepare_invite_with_evidence(
        &context.caller.client,
        &context.holder.client,
        "Private Invite after real PCR handoff",
        IntroductionEvidence::ConsentGrant {
            consent_grant_ref: event.event_id,
            consent_id: Some(grant.consent_id.to_string()),
        },
    )
    .await?;
    let sent = super::invite_service_fanout_live::dispatch_explicit_invite(
        &context.caller.client,
        prepared,
    )
    .await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let result = super::invite_service_fanout_live::account_data_row(
            &context.holder.client,
            arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY,
        )
        .await;
        if let Ok(row) = result {
            let cell: arkret_models_collaboration::governance::invite_addressing::InviteDelivery =
                serde_json::from_value(row.content)?;
            if cell.delivery_entries.iter().any(|entry| {
                entry.invite_id == sent.invite_id
                    && entry.inviter_account_id == context.caller.account
            }) {
                break;
            }
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "actual authority-local Invite did not reach the hosting private cell after handoff"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    println!(
        "[2141-pcr-handoff] remote_holder_session_policy_command=1 original_invite_receipt_at_new_authority=1 actual_remote_private_invite_delivery=1 hosting_original_revision=1"
    );
    Ok(())
}

/// A standalone diagnostic also runs the actual live-to-revoked transition
/// after both a zero and a nonzero tenure handoff.
pub async fn run_planned_handoff_live() -> Result<()> {
    let scheduling = tempfile::tempdir()?;
    let pause_file = scheduling.path().join("private-effects.pause");
    let extra = vec![(
        "COLAND_CONFORMANCE_PRIVATE_EFFECTS_PAUSE_FILE".to_owned(),
        pause_file.to_string_lossy().into_owned(),
    )];
    let environments = [extra.clone(), extra.clone(), extra];
    let mut context = crate::harness::heap_future(|| {
        ConsentCallContext::create_with_node_envs("consent-pcr-handoff", &environments)
    })
    .await?;
    let holder = &context.holder;
    let realm = holder
        .client
        .principal
        .as_ref()
        .context("actual holder PCR")?
        .pcr_realm_id
        .clone();
    let consent_id = arkret_wire::ConsentId::new(crate::harness::next_typed_id("consent"))?;
    let grant=holder.client.author_event(realm.as_str(),EventKind::ConsentGrant.as_str(),serde_json::json!({"consent_id":consent_id,"peer":{"kind":"actor","actor_id":context.caller.actor},"consent_scope":"voice_call"})).await?;
    let original = crate::harness::expect_json(
        holder
            .client
            .post("/_arkret/self/consent/results/grant")
            .json(
                &arkret_models_collaboration::consent_operations::ConsentGrantRequestBody {
                    grant_event: arkret_wire::EventAdmissionSubmission::new(grant.clone()),
                },
            ),
        reqwest::StatusCode::OK,
    )
    .await?;
    let policy=arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy::spec_default(context.holder.account.clone());
    crate::harness::expect_json(
        context
            .holder
            .client
            .put("/_arkret/self/invite-receive-policy")
            .json(&policy),
        reqwest::StatusCode::OK,
    )
    .await?;
    crate::harness::expect_json(context.denied_holder.client.post("/_arkret/self/consent/request").json(&serde_json::json!({"holder_account_id":context.holder.account,"consent_scope":"voice_call"})),reqwest::StatusCode::OK).await?;
    tokio::fs::write(&pause_file, b"pause pending intent across both handoffs").await?;
    let mimi = crate::harness::heap_future(|| prepare_mimi_consent(&context)).await?;
    crate::harness::heap_future(|| handoff(&mut context, 1, 2)).await?;
    crate::harness::heap_future(|| remote_invite_on_current_authority(&context)).await?;
    crate::harness::heap_future(|| handoff(&mut context, 2, 0)).await?;
    crate::harness::heap_future(|| remote_invite_on_current_authority(&context)).await?;
    crate::harness::heap_future(|| revoke_mimi_after_handoff(&context, mimi)).await?;
    crate::harness::heap_future(|| private_publication_recovery(&mut context, 0, &pause_file))
        .await?;
    let replay = crate::harness::expect_json(
        context
            .holder
            .client
            .post("/_arkret/self/consent/results/grant")
            .json(
                &arkret_models_collaboration::consent_operations::ConsentGrantRequestBody {
                    grant_event: arkret_wire::EventAdmissionSubmission::new(grant),
                },
            ),
        reqwest::StatusCode::OK,
    )
    .await?;
    ensure!(
        replay == original,
        "new governor reexecuted the original Grant"
    );
    let view: arkret_models_collaboration::consent_operations::ConsentView =
        serde_json::from_value(original)?;
    let revoke = context
        .holder
        .client
        .author_event(
            realm.as_str(),
            EventKind::ConsentRevoke.as_str(),
            serde_json::json!({"consent_id":consent_id,"expected_revision":view.revision}),
        )
        .await?;
    let revoked = crate::harness::expect_json(
        context
            .holder
            .client
            .post("/_arkret/self/consent/results/revoke")
            .json(
                &arkret_models_collaboration::consent_operations::ConsentRevokeRequestBody {
                    revoke_event: arkret_wire::EventAdmissionSubmission::new(revoke),
                },
            ),
        reqwest::StatusCode::OK,
    )
    .await?;
    ensure!(
        revoked["state"] == "revoked",
        "new authority did not accept the original holder Revoke"
    );
    Ok(())
}

fn mimi_proof(
    member: &super::mls_lifecycle_live::Member,
    server: &crate::harness::ArkretServer,
) -> Result<arkret_wire::PayloadProof> {
    Ok(arkret_wire::PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: member.method.clone(),
        payload_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(b"pending"))?,
        created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        domain: Some(server.trust_domain().to_string()),
        audience: Some(arkret_wire::Audience::Single(
            server.service_id().to_string(),
        )),
        proof_purpose: None,
        jws: String::new(),
    })
}
async fn mimi_update(
    context: &ConsentCallContext,
    provider: &str,
    decision: arkret_models_collaboration::mimi_operations::MimiConsentDecision,
    event: arkret_wire::Event,
) -> Result<serde_json::Value> {
    use arkret_models_collaboration::mimi_operations::MimiUpdateConsentRequestBody;
    let server = context.stations.server(1);
    let holder = &context.holder;
    let mut body = MimiUpdateConsentRequestBody {
        consent_id: serde_json::from_value(
            event
                .payload
                .get("consent_id")
                .context("MIMI exact consent id")?
                .clone(),
        )?,
        decision,
        actor_id: holder.actor.clone(),
        consent_event: arkret_wire::EventAdmissionSubmission::new(event),
        signature: mimi_proof(holder, server)?,
        reason: None,
        expires_at: None,
    };
    body.signature.payload_digest = body.payload_digest()?;
    body.signature.jws = arkret_signatures::sign_ed25519_detached_jws(
        &holder.key,
        &body.unsigned_signature_binding_bytes(&body.signature.unsigned())?,
    )?;
    let (status, outcome) = super::mimi_facade_live::signed_consent_command(
        server,
        "/_arkret/open/mimi/consent/update",
        provider,
        &serde_json::to_value(body)?,
    )
    .await?;
    ensure!(
        status.is_success(),
        "actual MIMI update failed: {status} {outcome}"
    );
    Ok(outcome)
}
async fn prepare_mimi_consent(
    context: &ConsentCallContext,
) -> Result<(
    String,
    arkret_models_collaboration::consent_operations::ConsentView,
    arkret_wire::Event,
)> {
    use arkret_models_collaboration::mimi_operations::{
        MimiConsentDecision, MimiRequestConsentRequestBody,
    };
    let server = context.stations.server(1);
    let requester = &context.denied_holder;
    let directory: serde_json::Value = server
        .http()
        .get(server.url("/_arkret/open/mimi/provider-directory"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let provider = directory
        .pointer("/mimi/provider_id")
        .and_then(serde_json::Value::as_str)
        .context("actual MIMI provider")?
        .to_owned();
    let mut body: MimiRequestConsentRequestBody = serde_json::from_value(
        serde_json::json!({"requester_actor_id":requester.actor,"holder_account_id":context.holder.account,"purpose":"any","proofs":[]}),
    )?;
    let mut proof = mimi_proof(requester, server)?;
    proof.payload_digest = body.payload_digest()?;
    proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &requester.key,
        &body.unsigned_proof_binding_bytes(&proof.unsigned())?,
    )?;
    body.proofs.push(proof);
    let (status, outcome) = super::mimi_facade_live::signed_consent_command(
        server,
        "/_arkret/open/mimi/consent/request",
        &provider,
        &serde_json::to_value(body)?,
    )
    .await?;
    ensure!(
        status.is_success(),
        "actual MIMI correlation failed: {status} {outcome}"
    );
    let id = outcome
        .get("consent_id")
        .context("actual MIMI correlation id")?;
    let realm = &context
        .holder
        .client
        .principal
        .as_ref()
        .context("holder PCR")?
        .pcr_realm_id;
    let event=context.holder.client.author_event(realm.as_str(),EventKind::ConsentGrant.as_str(),serde_json::json!({"consent_id":id,"peer":{"kind":"actor","actor_id":requester.actor},"consent_scope":"any"})).await?;
    mimi_update(
        context,
        &provider,
        MimiConsentDecision::Accept,
        event.clone(),
    )
    .await?;
    let list: arkret_models_collaboration::consent_operations::ConsentList =
        serde_json::from_value(
            crate::harness::expect_json(
                context.holder.client.get("/_arkret/self/consent/results"),
                reqwest::StatusCode::OK,
            )
            .await?,
        )?;
    let view = list
        .consents
        .into_iter()
        .find(|v| serde_json::to_value(&v.consent_id).ok().as_ref() == Some(id))
        .context("MIMI original grant current")?;
    Ok((provider, view, event))
}
async fn revoke_mimi_after_handoff(
    context: &ConsentCallContext,
    original: (
        String,
        arkret_models_collaboration::consent_operations::ConsentView,
        arkret_wire::Event,
    ),
) -> Result<()> {
    use arkret_models_collaboration::mimi_operations::MimiConsentDecision;
    let (provider, view, grant) = original;
    mimi_update(context, &provider, MimiConsentDecision::Accept, grant).await?;
    let realm = &context
        .holder
        .client
        .principal
        .as_ref()
        .context("holder PCR")?
        .pcr_realm_id;
    let event = context
        .holder
        .client
        .author_event(
            realm.as_str(),
            EventKind::ConsentRevoke.as_str(),
            serde_json::json!({"consent_id":view.consent_id,"expected_revision":view.revision}),
        )
        .await?;
    let outcome = mimi_update(
        context,
        &provider,
        MimiConsentDecision::Revoke,
        event.clone(),
    )
    .await?;
    let retried = mimi_update(context, &provider, MimiConsentDecision::Revoke, event).await?;
    ensure!(
        outcome == retried,
        "MIMI exact Revoke changed its original outcome"
    );
    let list: arkret_models_collaboration::consent_operations::ConsentList =
        serde_json::from_value(
            crate::harness::expect_json(
                context.holder.client.get("/_arkret/self/consent/results"),
                reqwest::StatusCode::OK,
            )
            .await?,
        )?;
    ensure!(
        list.consents.iter().any(|v| v.consent_id == view.consent_id
            && v.state == arkret_models_collaboration::consent_operations::ConsentState::Revoked),
        "forwarded MIMI revoke did not close native current"
    );
    println!(
        "[2141-pcr-handoff] actual_mimi_original_proofs=1 migrated_private_correlation=1 native_forwarded_any_revoke=1 exact_mimi_retry=1"
    );
    Ok(())
}
