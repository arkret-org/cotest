//! Destructive native Recovery cases. Each case owns its actual Station,
//! Coauth, process custody and independent PostgreSQL databases.
mod inventory;
mod process;
mod sql;

use std::sync::Arc;

use anyhow::{Context as _, Result, ensure};
use arkret_models_crypto::{
    RecoveryTransactionCompletion, RecoveryTransactionCreateRequestBody, SecurityTransaction,
    SecurityTransactionCreateRequestBody, SecurityTransactionKind,
};
use arkret_models_identity::{IssueRecoveryCompletionGrantResponseBody, SessionGrantMetadata};
use ed25519_dalek::Signer as _;
use process::{HeldResponse, process_evidence};
use serde_json::{Value, json};
use sql::{
    Instrumentation, accepted_completion, database_identity, fault_hits, issuer_footprint, query,
    station_footprint, wait_for_waiters,
};

use crate::harness::{CanonicalJsonBody as _, ClientSession, TestActorClient, expect_json};
use crate::scenarios::_helpers::canonical_api::CanonicalApiFixture;
use crate::scenarios::human_pcr_station_binding::recovery::{self, CompletedCandidate};

fn digest(value: &Value) -> Result<String> {
    Ok(arkret_canonical::sha256_digest(
        arkret_canonical::canonical_json_bytes(value)?,
    ))
}
fn rows(value: &Value, table: &str) -> Result<usize> {
    Ok(value[table]
        .as_array()
        .with_context(|| format!("native {table} footprint absent"))?
        .len())
}
fn issuer_footprint_summary(before: &Value, after: &Value) -> Result<Value> {
    let mut tables = serde_json::Map::new();
    let original_tables = before.as_object().context("issuer footprint tables")?;
    for table in original_tables.keys() {
        tables.insert(
            table.clone(),
            json!({"before_rows":rows(before,table)?,
            "after_rows":rows(after,table)?,"before_digest":digest(&before[table])?,
            "after_digest":digest(&after[table])?}),
        );
    }
    Ok(Value::Object(tables))
}
fn require_single_unit(before: &Value, after: &Value) -> Result<()> {
    for (table, increment) in [
        ("canonical_events", 2),
        ("realm_commits", 2),
        ("security_transactions", 1),
        ("pcr_device_authorization_current_states", 1),
        ("content_recovery_admission", 1),
    ] {
        ensure!(
            rows(after, table)? == rows(before, table)? + increment,
            "native {table} did not contain exactly one whole Recovery unit"
        );
    }
    ensure!(
        rows(after, "recovery_sessions")? == rows(before, "recovery_sessions")?,
        "recovery create unexpectedly added a Session"
    );
    let table = "pcr_device_generation_current_states";
    ensure!(
        rows(before, table)? == rows(after, table)?,
        "Recovery changed the generation row set"
    );
    let mut transitions = 0;
    for old in before[table].as_array().context("prior generation rows")? {
        let new = after[table]
            .as_array()
            .context("current generation rows")?
            .iter()
            .find(|row| row["realm_id"] == old["realm_id"])
            .context("PCR generation row disappeared")?;
        if new != old {
            let generation = old["value"]["current_device_generation_ref"]
                .as_u64()
                .context("positive prior generation")?;
            ensure!(
                generation.checked_add(1) == new["value"]["current_device_generation_ref"].as_u64(),
                "Recovery did not advance exactly one generation"
            );
            transitions += 1;
        }
    }
    ensure!(
        transitions == 1,
        "Recovery did not advance exactly one PCR generation row"
    );
    Ok(())
}
fn require_restarted(before: &Value, after: &Value) -> Result<()> {
    ensure!(
        before["pid"] != after["pid"] || before["os_process"] != after["os_process"],
        "restart retained the same OS process instance"
    );
    for member in ["origin", "executable", "sha256"] {
        ensure!(
            before[member] == after[member],
            "restart changed owned process {member}"
        );
    }
    Ok(())
}

fn issuer_request(
    http: &reqwest::Client,
    origin: &str,
    completed: &CompletedCandidate,
) -> Result<reqwest::RequestBuilder> {
    let url = format!("{origin}/_arkret/gate/account/recovery-session-grants/issue");
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("POST", &url)
            .access_token(&completed.handoff.account_handoff_grant),
        &completed.handoff.device_key.signing_key(),
    )?
    .proof_jwt;
    http.post(url)
        .header(
            "Arkret-Operation",
            "ak.gate.account.command.issue_recovery_completion_grant.v1",
        )
        .header(
            "Authorization",
            format!("DPoP {}", completed.handoff.account_handoff_grant),
        )
        .header("DPoP", proof)
        .canonical_json(&completed.request)
}
async fn issue(
    http: &reqwest::Client,
    origin: &str,
    completed: &CompletedCandidate,
) -> Result<IssueRecoveryCompletionGrantResponseBody> {
    let response = issuer_request(http, origin, completed)?.send().await?;
    read_issuance(response, completed).await
}

async fn read_issuance(
    response: reqwest::Response,
    completed: &CompletedCandidate,
) -> Result<IssueRecoveryCompletionGrantResponseBody> {
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "native completion issuance failed: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    let outcome: IssueRecoveryCompletionGrantResponseBody = serde_json::from_slice(&bytes)?;
    outcome.issued_session.validate_binding(
        &completed
            .request
            .terminal_receipt
            .session_grant_ref
            .issuer_id,
        &completed.request.terminal_receipt.account_id,
        &completed.request.initial_session.audience_id,
        &completed.request.initial_session.session_public_key,
        chrono::Utc::now(),
    )?;
    garth::SessionGrantState::from_initial_registration_outcome(
        &completed.request.initial_session,
        outcome.issued_session.clone(),
        outcome.issued_at,
    )?;
    ensure!(
        outcome.transaction_id == completed.request.terminal_receipt.transaction_id
            && outcome.issued_session.account_id == completed.request.terminal_receipt.account_id,
        "issuer changed Recovery transaction"
    );
    Ok(outcome)
}
fn accepted_client(
    fixture: &CanonicalApiFixture,
    completed: &CompletedCandidate,
    outcome: &IssueRecoveryCompletionGrantResponseBody,
) -> Result<TestActorClient> {
    let mut principal = completed
        .candidate
        .principal
        .clone()
        .context("replacement Device custody absent")?;
    principal.founding_authorize_event_id = completed
        .completion
        .completion_attestation
        .device_authorization_event_ref
        .event_id
        .clone();
    let ClientSession::Canonical { signing_key, .. } = completed.candidate.session() else {
        anyhow::bail!("Recovery used a development session")
    };
    fixture.server.actor_client(
        principal.did.as_str(),
        principal.device_id.as_str(),
        ClientSession::Canonical {
            grant: outcome.issued_session.session_grant.as_str().to_owned(),
            signing_key: signing_key.clone(),
        },
        Some(principal.clone()),
    )
}
async fn assert_public_originals(
    client: &TestActorClient,
    completed: &RecoveryTransactionCompletion,
) -> Result<Value> {
    // Replay uses the independently issued Standard grant's current reader
    // qualification, rather than reusing a consumed restricted recovery grant.
    let request = RecoveryTransactionCreateRequestBody {
        kind: SecurityTransactionKind::Recovery,
        recovery_receipt: completed.recovery_receipt.clone(),
    };
    let replayed: RecoveryTransactionCompletion = serde_json::from_value(
        expect_json(
            client
                .post("/_arkret/self/security-transactions")
                .canonical_json(&SecurityTransactionCreateRequestBody::Recovery(
                    request.clone(),
                ))?,
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replayed == *completed,
        "current reader replay changed original signed R/C"
    );
    let mut changed = request;
    changed.recovery_receipt.signature_proof.signature =
        arkret_wire::Base64UrlString::new("A".repeat(86)).map_err(anyhow::Error::msg)?;
    let refused = client
        .post("/_arkret/self/security-transactions")
        .canonical_json(&SecurityTransactionCreateRequestBody::Recovery(changed))?
        .send()
        .await?;
    let status = refused.status();
    let problem: arkret_wire::Problem = refused.json().await?;
    ensure!(
        status == reqwest::StatusCode::CONFLICT
            && problem.status == status.as_u16()
            && problem.code() == arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
        "changed full signature bytes did not conflict at the accepted identity: {problem:?}"
    );
    let resource: SecurityTransaction = serde_json::from_value(
        expect_json(
            client.get(&format!(
                "/_arkret/self/security-transactions/{}",
                completed.transaction_id
            )),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(&resource,SecurityTransaction::Recovery(original) if original==completed),
        "standard GET C changed the full original R/C"
    );
    let c = &completed.completion_attestation;
    let first = crate::scenarios::mls_lifecycle_live::accepted_full_view(
        client,
        &c.reanchor_event_ref.event_id,
    )
    .await?;
    let second = crate::scenarios::mls_lifecycle_live::accepted_full_view(
        client,
        &c.device_authorization_event_ref.event_id,
    )
    .await?;
    first.validate_shape()?;
    second.validate_shape()?;
    first.commit.validate_content_address()?;
    second.commit.validate_content_address()?;
    second.commit.validate_successor_of(&first.commit)?;
    ensure!(
        first.event == completed.recovery_receipt.recovery_unit.events[0].event
            && second.event == completed.recovery_receipt.recovery_unit.events[1].event,
        "recovered Commits do not retain submitted signed Events"
    );
    ensure!(
        c.reanchor_event_ref
            .matches(&arkret_wire::CommittedEventView::Full(first.clone()))
            && c.device_authorization_event_ref
                .matches(&arkret_wire::CommittedEventView::Full(second.clone())),
        "served originals differ from C's exact two Commit refs"
    );
    Ok(
        json!({"transaction":resource,"reanchor":first,"authorize":second,
        "current_reader_post_replay":true,"changed_signature_status":status.as_u16()}),
    )
}
async fn ordinary_reissue(
    fixture: &CanonicalApiFixture,
    http: &reqwest::Client,
    origin: &str,
    oidc_client_id: &str,
    identity: &TestActorClient,
) -> Result<(
    arkret_models_identity::SessionGrantResponseBody,
    TestActorClient,
)> {
    use cotest_test_support::provisioning::{self, FoundingDeviceKey};
    let principal = identity
        .principal
        .as_ref()
        .context("accepted Device identity custody")?;
    let holder = FoundingDeviceKey::generate("post-recovery-ordinary-holder")?;
    let public =
        arkret_models_identity::CanonicalSessionPublicJwk::new(holder.canonical_public_jwk()?)?;
    let authorization =
        provisioning::authorize_with_current_account(http, origin, oidc_client_id).await?;
    let handoff = provisioning::create_returning_account_handoff(
        http,
        origin,
        fixture.server.service_id().as_str(),
        &authorization,
        holder.clone(),
        &principal.core_id,
        &principal.did,
    )
    .await?;
    let account = arkret_wire::AccountId::new(
        principal.core_id.clone(),
        fixture.server.service_id().clone(),
    );
    let request: arkret_models_collaboration::session_grants::SessionGrantRequestBody =
        serde_json::from_value(cotest_test_support::wire::human_session_grant_request(
            json!({
                "principal_did":principal.did, "account_id":account, "device_id":principal.device_id,
                "holder_jkt":public.thumbprint_sha256()?, "account_subject":handoff.account_subject,
                "account_handoff_grant":handoff.account_handoff_grant, "handoff_expires_at":handoff.expires_at,
                "device_signing_seed_b64url":arkret_canonical::base64url_encode(principal.device_signing_key.to_bytes())
            }),
        )?)?;
    request.validate()?;
    let key = holder.signing_key();
    let gate = arkret_http_client::Client::builder(origin.parse()?)
        .allow_insecure_localhost()
        .http_client(http.clone())
        .auth(arkret_http_client::Auth::Dpop(
            arkret_http_client::DpopAuth::with_dpop_token(
                handoff.account_handoff_grant,
                move |request| {
                    garth::session::dpop::build_http_dpop_proof(request, &key)
                        .map_err(|error| arkret_http_client::Error::Protocol(error.to_string()))
                },
            ),
        ))
        .build()?;
    let grant = gate.auth_issue_session_grant(&request).await?;
    grant.validate_binding(
        fixture.server.service_id(),
        &account,
        fixture.server.service_id(),
        &public,
        chrono::Utc::now(),
    )?;
    ensure!(
        grant.account_id == account,
        "ordinary issuance changed the independently expected full Account"
    );
    let initial = arkret_models_identity::InitialSessionGrantIntent {
        device_id: principal.device_id.clone(),
        session_public_key: public,
        audience_id: fixture.server.service_id().clone(),
    };
    garth::SessionGrantState::from_initial_registration_outcome(
        &initial,
        grant.clone(),
        chrono::Utc::now(),
    )?;
    let client = fixture.server.actor_client(
        principal.did.as_str(),
        principal.device_id.as_str(),
        ClientSession::Canonical {
            grant: grant.session_grant.as_str().to_owned(),
            signing_key: Arc::new(holder.signing_key()),
        },
        Some(principal.clone()),
    )?;
    Ok((grant, client))
}

async fn original_issuance(
    database: &str,
    transaction: &str,
    issuer: &str,
    id: &str,
) -> Result<Value> {
    let (transaction, issuer, id) = (transaction.to_owned(), issuer.to_owned(), id.to_owned());
    query(database,move|db| {
        let issuance:Value=db.query_one("SELECT to_jsonb(i) FROM recovery_completion_grant_issuances i WHERE issuer_id=$1 AND transaction_id=$2",&[&issuer,&transaction])?.get(0);
        let grant:Value=db.query_one("SELECT to_jsonb(g) FROM oauth_session_grants g WHERE issuer_id=$1 AND grant_id::text=$2",&[&issuer,&id])?.get(0);
        Ok(json!({"issuance":issuance,"grant":grant}))
    }).await
}

/// Opt-in actual-process coverage for 2043-M08/M15/M16/M18/M22. No model
/// failure or caught Result is treated as proof of a process crash.
pub fn run_native_recovery_fault_case(
    case: &str,
) -> impl std::future::Future<Output = Result<()>> + '_ {
    crate::harness::heap_future(|| run_owned_native_case(case))
}

async fn run_owned_native_case(case: &str) -> Result<()> {
    ensure!(
        [
            "prepared_inventory",
            "local_rekey",
            "same_session_race",
            "pre_accept_kill",
            "post_accept_response_loss_restart",
            "issuer_rollback_after_native_completion",
            "lost_holder_ordinary_issue"
        ]
        .contains(&case),
        "unknown native Recovery fault case"
    );
    let deployment =
        crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
            &format!("recovery-native-{case}"),
        )
        .await?;
    let http = deployment.http.clone();
    let origin = deployment.coauth.base_url().to_owned();
    let oidc_client_id = deployment.oidc_client_id.clone();
    let issuer_database = deployment.coauth.pg.connect_url.clone();
    let mut fixture = CanonicalApiFixture::from_owned(
        deployment.station,
        deployment.controller,
        deployment.http,
        deployment.endpoints,
        deployment.oidc_client_id,
    );
    let station_database = fixture
        .server
        .configured_database_url()
        .context("owned Station PostgreSQL absent")?
        .to_owned();
    ensure!(
        station_database != issuer_database,
        "native authorities must own independent PostgreSQL databases"
    );
    let station_identity = database_identity(&station_database).await?;
    let issuer_identity = database_identity(&issuer_database).await?;
    ensure!(
        station_identity != issuer_identity,
        "native authorities resolve to the same physical PostgreSQL database"
    );
    let authority = recovery::prepare_recovery_authority(&fixture.client).await?;
    let material = if matches!(case, "prepared_inventory" | "local_rekey") {
        inventory::observe_transitions(&station_database).await?;
        Some(crate::harness::heap_future(|| inventory::provision(&fixture, &authority)).await?)
    } else {
        None
    };
    let old_message = if case == "local_rekey" {
        Some(
            inventory::freeze_old_message(
                material.as_ref().context("missing group")?,
                &fixture.server,
            )
            .await?,
        )
    } else {
        None
    };
    let prepared = recovery::prepare_native(&fixture, &authority.method, authority.seed).await?;
    let request = prepared.create.clone();
    let transaction = request.recovery_receipt.transaction_id.to_string();
    let before = station_footprint(&station_database).await?;
    let initial_processes = json!({"station":process_evidence(fixture.server.native_process_identity()?)?,"coauth":process_evidence(deployment.coauth.server.native_process_identity()?)?});
    let result = match case {
        "prepared_inventory" | "local_rekey" => {
            let completed = prepared.submit_native().await?;
            let grant = issue(&http, &origin, &completed).await?;
            let client = accepted_client(&fixture, &completed, &grant)?;
            let material = material.as_ref().context("missing accepted PCR material")?;
            let first = crate::harness::heap_future(|| {
                inventory::verify(
                    &client,
                    &completed.completion,
                    material,
                    &station_database,
                    &fixture.server,
                )
            })
            .await?;
            fixture.server.restart_external_process().await?;
            let second = crate::harness::heap_future(|| {
                inventory::verify(
                    &client,
                    &completed.completion,
                    material,
                    &station_database,
                    &fixture.server,
                )
            })
            .await?;
            ensure!(
                first == second,
                "restart changed the fixed recovery inventory"
            );
            if case == "local_rekey" {
                crate::harness::heap_future(|| {
                    inventory::rekey(
                        &client,
                        material,
                        &second,
                        &station_database,
                        completed
                            .completion
                            .completion_attestation
                            .new_model_generation_ref,
                        old_message.as_ref().expect("local rekey message"),
                    )
                })
                .await?
            } else {
                second
            }
        }
        "same_session_race" => {
            let mut competing = request.clone();
            competing.recovery_receipt.transaction_id =
                arkret_identifiers::new_prefixed_uuid7("ak:transaction:").parse()?;
            competing.recovery_receipt.receipt_id =
                arkret_identifiers::new_prefixed_uuid7("ak:receipt:").parse()?;
            let custody = prepared
                .candidate
                .principal
                .as_ref()
                .context("replacement identity custody absent")?;
            competing.recovery_receipt.signature_proof.signature =
                arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    custody
                        .device_signing_key
                        .sign(&competing.recovery_receipt.signature_transcript_bytes()?)
                        .to_bytes(),
                ))
                .map_err(anyhow::Error::msg)?;
            competing.validate()?;
            ensure!(
                competing.recovery_receipt.transaction_id
                    != request.recovery_receipt.transaction_id
                    && competing.recovery_receipt.recovery_session_id
                        == request.recovery_receipt.recovery_session_id
                    && competing.recovery_receipt.previous_model_generation_ref
                        == request.recovery_receipt.previous_model_generation_ref,
                "race did not use distinct transactions over one verified Session/generation"
            );
            let barrier = Instrumentation::station_before_insert(&station_database)?;
            let first = prepared
                .candidate
                .post("/_arkret/self/security-transactions")
                .canonical_json(&SecurityTransactionCreateRequestBody::Recovery(
                    request.clone(),
                ))?;
            let second = prepared
                .candidate
                .post("/_arkret/self/security-transactions")
                .canonical_json(&SecurityTransactionCreateRequestBody::Recovery(
                    competing.clone(),
                ))?;
            let first = tokio::spawn(async move { first.send().await });
            let second = tokio::spawn(async move { second.send().await });
            let waiters = wait_for_waiters(&station_database, barrier.backend_pid, 2).await?;
            ensure!(
                station_footprint(&station_database).await? == before,
                "uncommitted racing unit became publicly visible"
            );
            barrier.release()?;
            let (first, second) = (first.await??, second.await??);
            let statuses = [first.status(), second.status()];
            ensure!(
                statuses
                    .iter()
                    .filter(|status| **status == reqwest::StatusCode::OK)
                    .count()
                    == 1
                    && statuses
                        .iter()
                        .filter(|status| status.is_client_error())
                        .count()
                        == 1,
                "two-connection race did not yield exactly one acceptance and one refusal: {statuses:?}"
            );
            let (winner, loser) = if first.status() == reqwest::StatusCode::OK {
                (first, competing.recovery_receipt.transaction_id.to_string())
            } else {
                (second, transaction.clone())
            };
            let completion: RecoveryTransactionCompletion = winner.json().await?;
            let winner_request =
                if completion.transaction_id == request.recovery_receipt.transaction_id {
                    request.clone()
                } else {
                    competing.clone()
                };
            completion.validate_for_request(&winner_request)?;
            ensure!(
                accepted_completion(&station_database, &loser)
                    .await?
                    .is_none(),
                "losing transaction left a terminal row"
            );
            barrier.cleanup()?;
            let after = station_footprint(&station_database).await?;
            require_single_unit(&before, &after)?;
            let sessions = after["recovery_sessions"]
                .as_array()
                .context("native Session rows")?;
            ensure!(
                sessions
                    .iter()
                    .filter(|row| row["state"] == "completed"
                        && row["transaction_id"].as_str()
                            == completion
                                .transaction_id
                                .as_str()
                                .strip_prefix("ak:transaction:"))
                    .count()
                    == 1,
                "Session consumption is not bound to the sole winning transaction"
            );
            let mut winner = prepared;
            winner.create = winner_request;
            let completed = winner.finish(completion)?;
            let outcome = issue(&http, &origin, &completed).await?;
            let client = accepted_client(&fixture, &completed, &outcome)?;
            let originals = assert_public_originals(&client, &completed.completion).await?;
            ensure!(
                station_footprint(&station_database).await? == after,
                "winner's AA completion changed the sole native unit"
            );
            json!({"waiters":waiters,"statuses":statuses.map(|s|s.as_u16()),"originals":originals,"before_digest":digest(&before)?,"after_digest":digest(&after)?,"loser_has_no_terminal_row":true})
        }
        "pre_accept_kill" => {
            let barrier = Instrumentation::station_before_insert(&station_database)?;
            let post = prepared
                .candidate
                .post("/_arkret/self/security-transactions")
                .canonical_json(&SecurityTransactionCreateRequestBody::Recovery(
                    request.clone(),
                ))?;
            let attempt = tokio::spawn(async move { post.send().await });
            let waiters = wait_for_waiters(&station_database, barrier.backend_pid, 1).await?;
            ensure!(
                station_footprint(&station_database).await? == before,
                "pre-acceptance barrier exposed partial effects"
            );
            // This calls Child::kill + wait while retaining the durable DB,
            // key store, blob root, listeners and executable configuration.
            fixture.server.stop_external_process().await?;
            let interrupted = attempt.await?;
            ensure!(
                interrupted.is_err(),
                "pre-acceptance response escaped the actual process kill"
            );
            barrier.release()?;
            barrier.cleanup()?;
            let rolled_back = station_footprint(&station_database).await?;
            ensure!(
                rolled_back == before
                    && accepted_completion(&station_database, &transaction)
                        .await?
                        .is_none(),
                "process death retained an Event, Commit, Device, Session consumption or terminal effect"
            );
            fixture.server.start_external_process().await?;
            let restarted = process_evidence(fixture.server.native_process_identity()?)?;
            require_restarted(&initial_processes["station"], &restarted)?;
            let completed = prepared.submit_native().await?;
            let outcome = issue(&http, &origin, &completed).await?;
            let client = accepted_client(&fixture, &completed, &outcome)?;
            let originals = assert_public_originals(&client, &completed.completion).await?;
            let after = station_footprint(&station_database).await?;
            require_single_unit(&before, &after)?;
            json!({"waiters":waiters,"killed_before_insert":true,"restarted":restarted,"before_digest":digest(&before)?,"rollback_digest":digest(&rolled_back)?,"originals":originals})
        }
        "post_accept_response_loss_restart" => {
            let upstream = prepared
                .candidate
                .post("/_arkret/self/security-transactions")
                .canonical_json(&SecurityTransactionCreateRequestBody::Recovery(
                    request.clone(),
                ))?
                .build()?;
            let (relay, status, response) = HeldResponse::forward(&http, upstream).await?;
            ensure!(
                status == reqwest::StatusCode::OK,
                "upstream Recovery was not accepted"
            );
            let completion: RecoveryTransactionCompletion = serde_json::from_slice(&response)?;
            completion.validate_for_request(&request)?;
            ensure!(
                accepted_completion(&station_database, &transaction).await?
                    == Some(serde_json::to_value(&completion)?),
                "upstream response escaped a durable complete C"
            );
            let accepted = station_footprint(&station_database).await?;
            require_single_unit(&before, &accepted)?;
            fixture.server.stop_external_process().await?;
            let transport = relay.lose_after_kill().await?;
            fixture.server.start_external_process().await?;
            let restarted = process_evidence(fixture.server.native_process_identity()?)?;
            require_restarted(&initial_processes["station"], &restarted)?;
            // C here is the relay's test oracle, never a completion-request
            // input. The request uses only frozen R; AA must retrieve C itself.
            let replayed = prepared.finish(completion.clone())?;
            let outcome = issue(&http, &origin, &replayed).await?;
            let client = accepted_client(&fixture, &replayed, &outcome)?;
            let first = assert_public_originals(&client, &completion).await?;
            // A second real process restart must preserve GET C and both signed
            // Commit originals, independently of the POST replay response.
            fixture.server.restart_external_process().await?;
            let twice_restarted = process_evidence(fixture.server.native_process_identity()?)?;
            require_restarted(&restarted, &twice_restarted)?;
            let second = assert_public_originals(&client, &completion).await?;
            ensure!(
                first == second && station_footprint(&station_database).await? == accepted,
                "restart/replay duplicated or rewrote native recovery effects"
            );
            json!({"transport":transport,"restarted":restarted,"twice_restarted":twice_restarted,"accepted_digest":digest(&accepted)?,"originals":second})
        }
        "issuer_rollback_after_native_completion" => {
            let completed = prepared.submit_native().await?;
            let native = station_footprint(&station_database).await?;
            require_single_unit(&before, &native)?;
            let issuer_before = issuer_footprint(&issuer_database).await?;
            let failure = Instrumentation::issuer_fail_insert(&issuer_database)?;
            let request = issuer_request(&http, &origin, &completed)?.build()?;
            let same_failed_proof = request
                .try_clone()
                .context("failed completion request is not replayable")?;
            // Decode only our own freshly built proof to identify its expected
            // replay-cache effect; this is not an authentication verifier.
            let own_proof = request
                .headers()
                .get("DPoP")
                .context("own DPoP header")?
                .to_str()?;
            let payload = own_proof.split('.').nth(1).context("own DPoP payload")?;
            let claims: Value =
                serde_json::from_slice(&arkret_canonical::base64url_decode(payload)?)?;
            let failed_jti_digest =
                arkret_canonical::sha256_digest(claims["jti"].as_str().context("own DPoP jti")?);
            let refused = http.execute(request).await?;
            let status = refused.status();
            let error = refused.text().await?;
            ensure!(
                status.is_server_error(),
                "issuer transaction instrumentation did not cause a real transaction failure: {status}"
            );
            let trigger_hits = fault_hits(&issuer_database).await?;
            ensure!(
                trigger_hits == 1,
                "native AA failure did not reach the actual completion INSERT trigger exactly once"
            );
            let issuer_failed = issuer_footprint(&issuer_database).await?;
            if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
                std::fs::write(
                    std::path::PathBuf::from(directory)
                        .join("recovery-native-issuer-rollback-footprint-difference.json"),
                    serde_json::to_vec_pretty(
                        &json!({"failed_http_proof_jti_digest":failed_jti_digest,
                        "tables":issuer_footprint_summary(&issuer_before,&issuer_failed)?}),
                    )?,
                )?;
            }
            for table in [
                "oauth_session_grant_operations",
                "oauth_session_grants",
                "recovery_completion_grant_issuances",
            ] {
                ensure!(
                    issuer_failed[table] == issuer_before[table],
                    "failed AA completion retained business effects in {table}"
                );
            }
            let prior_jtis = issuer_before["dpop_jti_replay"]
                .as_array()
                .context("prior replay cache")?;
            let failed_jtis = issuer_failed["dpop_jti_replay"]
                .as_array()
                .context("failed replay cache")?;
            let added = failed_jtis
                .iter()
                .filter(|row| !prior_jtis.contains(row))
                .collect::<Vec<_>>();
            ensure!(
                failed_jtis.len() == prior_jtis.len() + 1
                    && prior_jtis.iter().all(|row| failed_jtis.contains(row))
                    && added.len() == 1
                    && added[0]["jti_digest"].as_str() == Some(failed_jti_digest.as_str()),
                "failed AA request did not retain exactly its authenticated HTTP proof while preserving the prior replay cache"
            );
            ensure!(
                station_footprint(&station_database).await? == native,
                "AA transaction failure changed already-committed native PCR facts"
            );
            let refused = http.execute(same_failed_proof).await?;
            let failed_replay_status = refused.status();
            let problem: arkret_wire::Problem = refused.json().await?;
            ensure!(
                failed_replay_status == reqwest::StatusCode::UNAUTHORIZED
                    && problem.status == failed_replay_status.as_u16()
                    && problem.code() == arkret_wire::ErrorCode::SIGNATURE_INVALID,
                "failed business admission made the authenticated HTTP proof replayable: {problem:?}"
            );
            ensure!(
                issuer_footprint(&issuer_database).await? == issuer_failed
                    && fault_hits(&issuer_database).await? == 1
                    && station_footprint(&station_database).await? == native,
                "reused failed HTTP proof reached business admission or changed issuer/PCR effects"
            );
            failure.cleanup()?;
            let request = issuer_request(&http, &origin, &completed)?.build()?;
            let same_proof = request
                .try_clone()
                .context("completion request is not replayable")?;
            let accepted = read_issuance(http.execute(request).await?, &completed).await?;
            let committed_issuer = issuer_footprint(&issuer_database).await?;
            let refused = http.execute(same_proof).await?;
            let replay_status = refused.status();
            let problem: arkret_wire::Problem = refused.json().await?;
            ensure!(
                replay_status == reqwest::StatusCode::UNAUTHORIZED
                    && problem.status == replay_status.as_u16()
                    && problem.code() == arkret_wire::ErrorCode::SIGNATURE_INVALID
                    && issuer_footprint(&issuer_database).await? == committed_issuer,
                "exact completion body excused a reused HTTP DPoP proof or left issuer residue: {problem:?}"
            );
            // A fresh outer proof must still retrieve the one accepted outcome.
            let replay = issue(&http, &origin, &completed).await?;
            ensure!(
                arkret_canonical::canonical_json_bytes(&accepted)?
                    == arkret_canonical::canonical_json_bytes(&replay)?,
                "AA retry did not recover one exact issuer outcome"
            );
            let client = accepted_client(&fixture, &completed, &accepted)?;
            let originals = assert_public_originals(&client, &completed.completion).await?;
            ensure!(
                station_footprint(&station_database).await? == native,
                "AA-only retry appended another PCR recovery unit"
            );
            let after = issuer_footprint(&issuer_database).await?;
            ensure!(
                rows(&after, "recovery_completion_grant_issuances")?
                    == rows(&issuer_before, "recovery_completion_grant_issuances")? + 1
                    && rows(&after, "oauth_session_grants")?
                        == rows(&issuer_before, "oauth_session_grants")? + 1
                    && rows(&after, "oauth_session_grant_operations")?
                        == rows(&issuer_before, "oauth_session_grant_operations")? + 1,
                "AA retry retained multiple successful outcomes"
            );
            json!({"injected_fault":"independent AA PostgreSQL BEFORE INSERT raises after native completion","failed_http_status":status.as_u16(),"trigger_hits":trigger_hits,"failed_body":error,"failed_http_proof_jti_digest":failed_jti_digest,"failed_dpop_replay_status":failed_replay_status.as_u16(),"same_dpop_replay_status":replay_status.as_u16(),"fresh_dpop_same_outcome":true,"issuer_before_digest":digest(&issuer_before)?,"issuer_after_digest":digest(&after)?,"native_digest":digest(&native)?,"originals":originals})
        }
        "lost_holder_ordinary_issue" => {
            let completed = prepared.submit_native().await?;
            let issued = issue(&http, &origin, &completed).await?;
            let grant = &issued.issued_session;
            let old_ref = grant.grant_ref();
            let old_holder = completed.request.initial_session.session_public_key.clone();
            let original = original_issuance(
                &issuer_database,
                &transaction,
                old_ref.issuer_id.as_str(),
                old_ref.id.as_ref(),
            )
            .await?;
            let native = station_footprint(&station_database).await?;
            let mut principal = completed
                .candidate
                .principal
                .clone()
                .context("accepted replacement identity key absent")?;
            principal.founding_authorize_event_id = completed
                .completion
                .completion_attestation
                .device_authorization_event_ref
                .event_id
                .clone();
            let completion = completed.completion.clone();
            let secret = grant.session_grant.as_str().to_owned();
            // Destroy every fixture-held copy of the old transport private key:
            // the candidate's raw/SDK closures, handoff holder and gate client.
            // Only the independently generated accepted Device identity remains.
            drop(completed);
            let mut entropy = [0u8; 32];
            getrandom::fill(&mut entropy)?;
            let replacement_holder = ed25519_dalek::SigningKey::from_bytes(&entropy);
            let abandoned = fixture.server.actor_client(
                principal.did.as_str(),
                principal.device_id.as_str(),
                ClientSession::Canonical {
                    grant: secret,
                    signing_key: Arc::new(replacement_holder),
                },
                Some(principal.clone()),
            )?;
            let refusal = abandoned.get("/_arkret/self/account/viewer").send().await?;
            ensure!(
                refusal.status() == reqwest::StatusCode::UNAUTHORIZED,
                "lost old holder was replaced under the old credential"
            );
            // Build a new ordinary accepted-Device request from retained
            // identity custody and an independently authenticated fresh handoff.
            // Keep its new holder so successful resource use is also exercised.
            let (fresh, fresh_client) =
                ordinary_reissue(&fixture, &http, &origin, &oidc_client_id, &abandoned).await?;
            let ClientSession::Canonical { signing_key, .. } = fresh_client.session() else {
                anyhow::bail!("ordinary reissue did not retain its actual holder key");
            };
            let fresh_public = arkret_models_identity::CanonicalSessionPublicJwk::new(
                serde_json::to_string(&json!({
                    "crv":"Ed25519", "kty":"OKP",
                    "x":arkret_canonical::base64url_encode(signing_key.verifying_key().to_bytes()),
                }))?,
            )?;
            fresh.validate_binding(
                &old_ref.issuer_id,
                &grant.account_id,
                fixture.server.service_id(),
                &fresh_public,
                chrono::Utc::now(),
            )?;
            ensure!(
                fresh.grant_ref() != old_ref
                    && fresh.account_id == grant.account_id
                    && fresh.device_id.as_ref() == Some(&principal.device_id)
                    && fresh.session_public_key != old_holder,
                "ordinary accepted-Device issue failed to create an independent fresh holder/Ref for the same Account"
            );
            let issuer = old_ref.issuer_id.to_string();
            let fresh_id = fresh.session_grant_id.to_string();
            let metadata:SessionGrantMetadata=query(&issuer_database,move|db| {
                let bytes:Vec<u8>=db.query_one("SELECT canonical_metadata FROM oauth_session_grants WHERE issuer_id=$1 AND grant_id::text=$2",&[&issuer,&fresh_id])?.get(0);
                let metadata:SessionGrantMetadata=serde_json::from_slice(&bytes)?;
                metadata.validate()?; ensure!(arkret_canonical::canonical_json_bytes(&metadata)?==bytes,"new issuer metadata not canonical immutable bytes"); Ok(metadata)
            }).await?;
            ensure!(
                metadata.grant_ref() == fresh.grant_ref()
                    && metadata.audience_id == fresh.audience_id
                    && metadata.scopes == fresh.granted_scope
                    && metadata.account_id == fresh.account_id
                    && metadata.cnf_jkt == fresh.session_public_key.thumbprint_sha256()?
                    && metadata
                        .device_binding
                        .as_ref()
                        .is_some_and(|binding| binding.authorization_event_id
                            == completion
                                .completion_attestation
                                .device_authorization_event_ref
                                .event_id
                            && binding.model_generation_ref
                                == completion.completion_attestation.new_model_generation_ref),
                "ordinary new issue not bound to the actual accepted replacement Device/generation"
            );
            ensure!(
                original_issuance(
                    &issuer_database,
                    &transaction,
                    old_ref.issuer_id.as_str(),
                    old_ref.id.as_ref()
                )
                .await?
                    == original
                    && station_footprint(&station_database).await? == native,
                "ordinary reissue rewrote the accepted completion outcome or PCR recovery unit"
            );
            let originals = assert_public_originals(&fresh_client, &completion).await?;
            json!({"old_grant_ref":old_ref,"new_grant_ref":fresh.grant_ref(),"old_holder_lost":true,"old_credential_with_new_key_status":refusal.status().as_u16(),"original_issuer_record_digest":digest(&original)?,"native_digest":digest(&native)?,"fresh_device_binding":metadata.device_binding,"originals":originals})
        }
        _ => unreachable!(),
    };
    let instrumentation = if matches!(case, "prepared_inventory" | "local_rekey") {
        "case-owned AFTER trigger observes native state writes; read-only checks compare durable originals, root backup and private inventory"
    } else {
        "temporary SQL trigger/lock in the case-owned database only; cleaned before success"
    };
    let artifact = json!({"case":case,"actual_processes":initial_processes,"database_topology":{"station":station_identity,"account_authority":issuer_identity},"test_instrumentation":instrumentation,"observations":result,"execution":"this artifact is written only after the actual native case completed"});
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join(format!("recovery-native-{case}.json")),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    println!("native Recovery fault case passed: {case}");
    // Keep the deployment's private email process and Coauth custody alive until
    // all real ordinary handoffs and native requests above have finished.
    Ok(())
}
