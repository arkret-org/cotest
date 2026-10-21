//! Accepted Human PCRs retain their account Station through rejected transfers.
#[path = "human_pcr_station_binding/recovery.rs"]
mod recovery;

use anyhow::{Context, Result, ensure};
use arkret_wire::{AuthorityBundleRequest, Base64UrlString, EventAdmissionSubmission, EventKind};
use coland_storage::AuthorityCommitStore;
use coland_storage_postgres::{Db, PgAuthorityCommitStore, PoolTuning};

use super::consent_call_context::ConsentCallContext;
use crate::harness::CanonicalJsonBody as _;

pub async fn assert_station_binding(
    context: &ConsentCallContext,
    from: usize,
    to: usize,
) -> Result<()> {
    ensure!(from != to, "transfer target must differ");
    let holder = &context.holder;
    let realm = &holder
        .client
        .principal
        .as_ref()
        .context("accepted holder inception")?
        .pcr_realm_id;
    let source = Db::connect(
        Some(&context.databases[from].connect_url),
        PoolTuning::default(),
    )
    .await?;
    let store = PgAuthorityCommitStore {
        pool: source.pool.context("source pool")?,
    };
    let before = store
        .realm_state_snapshot_material(realm)
        .await?
        .context("accepted PCR material")?;
    let authority = store
        .current_authority(realm)
        .await?
        .context("accepted PCR authority")?;
    ensure!(
        authority.service_id == holder.account.station_id && authority.generation == 0,
        "Human account Station binding differs"
    );
    let head = before
        .visible_stream_heads
        .iter()
        .find(|h| {
            h.stream_ref
                == arkret_wire::CommitStreamRef::Realm {
                    realm_id: realm.clone(),
                }
        })
        .context("PCR Realm head")?;
    let change=holder.client.author_event(realm.as_str(),EventKind::RealmGovernanceStationChange.as_str(),serde_json::json!({"expected_governance_generation":0,"expected_realm_stream_commit_id":head.commit_id,"new_governance_station_id":context.stations.server(to).service_id()})).await?;
    crate::harness::expect_api_error(
        holder
            .client
            .post("/_arkret/self/events")
            .canonical_json(&EventAdmissionSubmission::new(change))?,
        reqwest::StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await?;
    ensure!(
        store
            .export_pcr_private_state(&holder.account)
            .await
            .is_err(),
        "Human private state was exportable"
    );
    let after = store
        .realm_state_snapshot_material(realm)
        .await?
        .context("retained material")?;
    ensure!(
        before == after,
        "rejected Human transfer changed its authority material"
    );
    ensure!(
        store.current_authority(realm).await?.as_ref() == Some(&authority),
        "rejected transfer changed its authority"
    );
    let request = AuthorityBundleRequest {
        realm_id: realm.clone(),
        nonce: Base64UrlString::new(arkret_canonical::base64url_encode([4u8; 32]))
            .map_err(anyhow::Error::msg)?,
    };
    let hidden = holder
        .client
        .post("/_arkret/open/realm-authority/bundle")
        .canonical_json(&request)?
        .send()
        .await?;
    let hidden_status = hidden.status();
    let mut hidden_body: serde_json::Value = hidden.json().await?;
    let unknown = AuthorityBundleRequest {
        realm_id: arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [99; 32],
        )),
        nonce: request.nonce,
    };
    let missing = holder
        .client
        .post("/_arkret/open/realm-authority/bundle")
        .canonical_json(&unknown)?
        .send()
        .await?;
    ensure!(
        hidden_status == reqwest::StatusCode::NOT_FOUND && missing.status() == hidden_status,
        "Human and unknown bundle status differ"
    );
    let mut missing_body: serde_json::Value = missing.json().await?;
    hidden_body
        .as_object_mut()
        .context("problem object")?
        .remove("instance");
    missing_body
        .as_object_mut()
        .context("problem object")?
        .remove("instance");
    ensure!(
        hidden_body == missing_body && hidden_body.to_string().contains("not_found"),
        "Human public bundle discloses its existence"
    );
    Ok(())
}

pub async fn run_station_binding_live() -> Result<()> {
    let context = crate::harness::heap_future(|| {
        ConsentCallContext::create("human-pcr-station-binding", &[])
    })
    .await?;
    let holder = &context.holder;
    let realm = &holder
        .client
        .principal
        .as_ref()
        .context("actual holder PCR")?
        .pcr_realm_id;
    let grant=holder.client.author_event(realm.as_str(),EventKind::ConsentReplace.as_str(),serde_json::json!({"peer":{"kind":"actor","actor_id":context.caller.actor},"expected_current":{"state":"never_written"},"permissions":[{"consent_scope":"voice_call"}]})).await?;
    let body = arkret_models_collaboration::consent_operations::ConsentReplaceRequestBody {
        consent_event: EventAdmissionSubmission::new(grant),
    };
    let original = crate::harness::expect_json(
        holder
            .client
            .post("/_arkret/self/consent/results/replace")
            .json(&body),
        reqwest::StatusCode::OK,
    )
    .await?;
    assert_station_binding(&context, 1, 2).await?;
    let retry = crate::harness::expect_json(
        holder
            .client
            .post("/_arkret/self/consent/results/replace")
            .json(&body),
        reqwest::StatusCode::OK,
    )
    .await?;
    ensure!(
        retry == original,
        "rejected migration reexecuted an accepted Grant"
    );
    let view: arkret_models_collaboration::consent_operations::ConsentView =
        serde_json::from_value(original)?;
    let revoke = holder
        .client
        .author_event(
            realm.as_str(),
            EventKind::ConsentReplace.as_str(),
            serde_json::json!({"peer":view.peer,"expected_current":{"state":"present","revision":view.revision},"permissions":[]}),
        )
        .await?;
    let revoked = crate::harness::expect_json(
        holder
            .client
            .post("/_arkret/self/consent/results/replace")
            .json(
                &arkret_models_collaboration::consent_operations::ConsentReplaceRequestBody {
                    consent_event: EventAdmissionSubmission::new(revoke),
                },
            ),
        reqwest::StatusCode::OK,
    )
    .await?;
    ensure!(
        revoked["permission_scopes"] == serde_json::json!([]),
        "own Station did not accept the original Revoke"
    );
    Ok(())
}

/// Uses owned Coauth and HTTPS Coland processes and normal OIDC registration.
/// No mock issuer ledger or SQL device-state mutation participates in this flow.
pub async fn run_coauth_device_boundary_live() -> Result<()> {
    let deployment = super::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
        "human-fixed-station-coauth",
    )
    .await?;
    let coauth_url = deployment.coauth.base_url().to_owned();
    let account = deployment.account.clone();
    let mut fixture = super::_helpers::canonical_api::CanonicalApiFixture::from_owned(
        deployment.station,
        deployment.controller,
        deployment.http,
        deployment.endpoints,
        deployment.oidc_client_id,
    );
    let sibling = fixture
        .pair_sibling()
        .await
        .context("real Coauth accepted-device pairing")?;
    let initial = fixture
        .issue_for_device(&fixture.client)
        .await
        .context("accepted founding Device can issue a fresh Standard grant")?;
    ensure!(
        initial.account_id == account,
        "fresh issue changed the complete Account"
    );
    let refreshed = fixture
        .refresh_for_device(&fixture.client)
        .await
        .context("accepted founding Device can refresh before revocation")?;
    ensure!(
        refreshed.account_id == account,
        "refresh changed the complete Account"
    );
    let principal = fixture
        .client
        .principal
        .clone()
        .context("founding custody")?;
    let crate::harness::ClientSession::Canonical { signing_key, .. } = fixture.client.session()
    else {
        anyhow::bail!("refresh used a development bearer");
    };
    fixture.client = fixture.server.actor_client(
        principal.did.as_str(),
        principal.device_id.as_str(),
        crate::harness::ClientSession::Canonical {
            grant: refreshed.session_grant,
            signing_key: signing_key.clone(),
        },
        Some(principal.clone()),
    )?;
    let recovery_authority = recovery::prepare_recovery_authority(&fixture.client)
        .await
        .context("founding Device publishes the native recovery policy before revocation")?;
    let (pair_gate, prepared_pair) = fixture
        .prepare_pairing_request()
        .await
        .context("freeze a real pairing approval before revocation")?;
    let principal = fixture
        .client
        .principal
        .as_ref()
        .context("accepted founding custody")?;
    let (author, old, source) =
        super::security_rotation_live::RotationAuthor::prepare_for_client(&sibling).await?;
    let seed = sibling
        .principal
        .as_ref()
        .context("accepted sibling custody")?
        .device_signing_key
        .to_bytes();
    let (request, _) = author.rotation(
        "2343",
        principal.device_id.as_str(),
        seed,
        seed,
        &old,
        &source,
    )?;
    let mut transaction = super::security_rotation_live::create(&sibling, &request).await?;
    ensure!(
        transaction.revoke_proposal.is_some(),
        "actual revoke proposal was not accepted: {transaction:?}"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while transaction.accepted_steps.len() < 4 && transaction.terminal_outcome.is_none() {
        ensure!(
            std::time::Instant::now() < deadline,
            "rotation worker did not complete native steps"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        transaction = serde_json::from_value(
            crate::harness::expect_json(
                sibling.get(&format!(
                    "/_arkret/self/security-transactions/{}",
                    transaction.transaction_id
                )),
                reqwest::StatusCode::OK,
            )
            .await?,
        )?;
    }
    ensure!(
        transaction.accepted_steps.len() == 4,
        "native rotation aborted: {transaction:?}"
    );
    let arkret_models_crypto::SecurityTransactionCreateRequest::SecurityRotation(rotation) =
        &request
    else {
        anyhow::bail!("not a rotation");
    };
    let commit = author.local_commit(&transaction, rotation)?;
    transaction = serde_json::from_value(
        crate::harness::expect_json(
            sibling
                .post(&format!(
                    "/_arkret/self/security-transactions/{}/continue",
                    transaction.transaction_id
                ))
                .json(&commit),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(
            transaction.terminal_outcome,
            Some(arkret_models_crypto::SecurityTransactionTerminalOutcome::Completed { .. })
        ),
        "actual revoke did not reach the local commit: {transaction:?}"
    );
    let issue_denial =
        require_device_denial(fixture.issue_for_device(&fixture.client).await, "issue")?;
    ensure!(
        matches!(
            issue_denial.as_str(),
            "device_revoked" | "device_revocation_pending" | "device_generation_fenced"
        ),
        "fresh account authentication did not reach the revoked-device gate: {issue_denial}"
    );
    let refresh_denial =
        require_device_denial(fixture.refresh_for_device(&fixture.client).await, "refresh")?;
    let pair_denial = require_device_denial(
        pair_gate
            .account_device_pair(&prepared_pair)
            .await
            .map_err(anyhow::Error::from),
        "pair",
    )?;
    let recovered = fixture
        .issue_for_device(&sibling)
        .await
        .context("remaining active accepted sibling issues through the owning Station")?;
    ensure!(
        recovered.account_id == account,
        "sibling continuation changed the complete Account"
    );
    ensure!(
        fixture.server.service_id() == &account.station_id,
        "owning Station identity changed"
    );
    recovery::verify_recovery_generation_boundary(&fixture, &recovery_authority).await?;
    println!(
        "[2343-coauth-denials] issue={issue_denial} refresh={refresh_denial} pair={pair_denial}"
    );
    println!(
        "[2343-coauth] owned_issuer={coauth_url} normal_registration=1 accepted_pair=1 fresh_issue_before_revoke=1 refresh_before_revoke=1 accepted_revoke=1 next_issue_denied=1 next_refresh_denied=1 next_pair_denied=1 active_sibling_issue=1"
    );
    Ok(())
}

fn require_device_denial<T>(result: Result<T>, operation: &str) -> Result<String> {
    let error = match result {
        Ok(_) => anyhow::bail!("revoked Device was allowed to {operation}"),
        Err(error) => error,
    };
    let Some(arkret_http_client::Error::Api { error: problem, .. }) =
        error.downcast_ref::<arkret_http_client::Error>()
    else {
        anyhow::bail!("{operation} failed outside the actual issuer API: {error:#}");
    };
    let code = problem
        .error_code()
        .context("issuer refusal lacks a registered code")?
        .as_str();
    ensure!(
        [
            "device_revoked",
            "device_revocation_pending",
            "device_generation_fenced",
            "session_revoked",
            "unauthenticated",
            "soft_logged_out"
        ]
        .contains(&code),
        "{operation} did not fail on its actual revoked binding: {problem}"
    );
    Ok(code.to_owned())
}
