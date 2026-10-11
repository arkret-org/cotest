//! Actual Station process receipt acceptance stays independent of Realm lifetime.
use arkret_models_collaboration::events_payloads::event_wire::{
    ErasureTrigger, VerificationStub, VerificationStubScope, VerificationStubSubject,
};
use arkret_models_collaboration::governance::erasure::*;

use super::frozen_authority_live::settled;
use super::terminal_restart_live::{fanout, tombstone};
use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows;

async fn rows(url: &str) -> Result<Value> {
    let mut rows = acceptance_rows(url).await?;
    let url = url.to_owned();
    rows["idempotency_keys"] = tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(connection.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY actor_key,operation_id,idempotency_key),'[]'::jsonb) FROM idempotency_keys r", &[])?.get(0))
    }).await??;
    Ok(rows)
}

fn sign(source: &ArkretServer, package: &mut ErasureReceiptPackage) -> Result<()> {
    package.receipt.retained_stub_digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&package.retained_stub)?)?;
    package.receipt.proofs.clear();
    package.receipt.proofs.push(ErasureReceiptProof {
        verification_method: DidUrl::new(format!("{}#notary-key", source.service_did()))?,
        payload_digest: package.receipt.canonical_payload_digest()?,
        signature: arkret_signatures::jws::sign_jws_ed25519(
            &package.receipt.canonical_proof_input()?,
            &source.federation_signing_key()?,
        )
        .map_err(anyhow::Error::msg)?,
        extra: Default::default(),
    });
    package.validate_bindings()?;
    Ok(())
}

fn package(
    source: &ArkretServer,
    message: &Event,
    redaction: &Event,
) -> Result<ErasureReceiptPackage> {
    let id = format!("ak:receipt:{}", uuid::Uuid::now_v7());
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let trigger = ErasureTrigger::Event {
        event_id: redaction.event_id.clone(),
    };
    let scope = ErasureScope {
        storage_boundary: ErasureStorageBoundary::ServiceDefined,
        realm_id: Some(message.realm_id.clone()),
        target_refs: vec![message.event_id.to_string()],
        retention_policy_id: None,
        service_scope: Some("receipt rail process verification".into()),
    };
    let stub = VerificationStub {
        stub_schema: arkret_wire::SchemaId::ERASURE_VERIFICATION_STUB_V1.into(),
        trigger: trigger.clone(),
        subject: VerificationStubSubject {
            kind: "event".into(),
            subject_ref: message.event_id.to_string(),
        },
        scope: VerificationStubScope {
            storage_boundary: "service_defined".into(),
            realm_id: scope.realm_id.clone(),
            target_refs: Some(scope.target_refs.clone()),
            retention_policy_id: None,
            service_scope: scope.service_scope.clone(),
        },
        event_digest: None,
        retained_digests: None,
        commit_ref: None,
        redaction_authorization_ref: Some(redaction.event_id.to_string()),
        legal_hold_ref: None,
        receipt_id: id.clone(),
        completed_at: at,
    };
    let mut package = ErasureReceiptPackage {
        retained_stub: stub,
        receipt: ErasureReceipt {
            receipt_id: id,
            trigger,
            schema: ErasureReceipt::SCHEMA.into(),
            issuer_id: source.service_id().clone(),
            subject: ErasureSubject {
                kind: ErasureSubjectKind::Event,
                subject_ref: message.event_id.to_string(),
            },
            scope,
            outcome: ErasureOutcome::PartiallyCompleted,
            erased_classes: Vec::new(),
            retained_stub_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                b"replaced before signing",
            ))?,
            retained_stub: None,
            legal_hold_ref: None,
            completed_at: at,
            issued_at: Some(at),
            proofs: Vec::new(),
            fanout_status: None,
            peer_receipts: Vec::new(),
        },
    };
    sign(source, &mut package)?;
    Ok(package)
}

pub async fn run(ban: bool) -> Result<()> {
    let name = if ban {
        "erasure-ban-holder"
    } else {
        "erasure-leave-holder"
    };
    let Some(mut fixture) = Box::pin(current_origin_fixture(name)).await? else {
        return Ok(());
    };
    let receiver_url = fixture._member_database.connect_url.clone();
    let source_url = fixture._governance_database.connect_url.clone();
    let (message, message_commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &fixture.alice.default_strand_id(&fixture.realm)?,
        "history held before independent receipt",
    )
    .await?;
    ensure_same_commit(
        &message_commit,
        &wait_held(&fixture.bob, &message.event_id, HELD_WINDOW).await?,
    )?;
    settled(&source_url, &message_commit, "delivered").await?;
    let redaction = fixture
        .alice
        .author_event(
            &fixture.realm,
            EventKind::MessageRedact.as_str(),
            crate::harness::message_redact_payload(
                message.event_id.as_str(),
                Some("independent receipt authorization"),
            )?,
        )
        .await?;
    let redaction_commit = submit_and_expect_commit(
        &fixture.alice,
        &fixture.alice_account,
        ALICE_DEVICE,
        &redaction,
    )
    .await?;
    ensure_same_commit(
        &redaction_commit,
        &wait_held(&fixture.bob, &redaction.event_id, HELD_WINDOW).await?,
    )?;
    settled(&source_url, &redaction_commit, "delivered").await?;
    let principal = fixture.bob.principal.as_ref().context("departing holder")?;
    let account = AccountId::new(
        principal.core_id.clone(),
        fixture.group.server(1).service_id().clone(),
    );
    let departure = fixture
        .alice
        .author_event(
            &fixture.realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &fixture.realm,
                account,
                if ban {
                    MembershipPayloadState::Ban
                } else {
                    MembershipPayloadState::Leave
                },
                "historical erasure holder",
            )?,
        )
        .await?;
    let departure_commit = submit_and_expect_commit(
        &fixture.alice,
        &fixture.alice_account,
        ALICE_DEVICE,
        &departure,
    )
    .await?;
    settled(&source_url, &departure_commit, "delivered").await?;
    let (_, terminal_commit) = tombstone(&fixture).await?;
    ensure!(fanout(&source_url, &terminal_commit).await?.is_empty());
    let before = acceptance_rows(&receiver_url).await?;
    ensure!(
        !before["realm_commits"]
            .as_array()
            .context("held chain")?
            .iter()
            .any(|row| row["commit_id"] == terminal_commit.commit_id.as_str())
    );
    let package = package(fixture.group.server(0), &message, &redaction)?;
    let body = arkret_canonical::canonical_json_bytes(&ErasureReceiptSubmitRequestBody {
        package: package.clone(),
    })?;
    let key = format!("ak:outbox:erasure-receipt:{}", package.receipt.receipt_id);
    let (status, first) = fixture
        .group
        .server(1)
        .signed_peer_post_with_idempotency_key(
            fixture.group.server(0),
            "/_arkret/peer/erasure-receipts",
            &body,
            fixture.group.server(1).service_id(),
            &key,
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "receipt acceptance: {status} {}",
        String::from_utf8_lossy(&first)
    );
    let outcome: ErasureReceiptSubmitOutcome = serde_json::from_slice(&first)?;
    let ErasureReceiptSubmitOutcome::Accepted(acceptance) = outcome else {
        bail!("independent receipt rejected");
    };
    ensure!(
        acceptance.status == ErasureReceiptAcceptanceStatus::Accepted
            && acceptance.receipt_id == package.receipt.receipt_id
            && acceptance.receipt_digest == package.computed_receipt_digest()?
            && acceptance.issuer_id == *fixture.group.server(0).service_id()
            && acceptance.receiver_id == *fixture.group.server(1).service_id()
    );
    let signer =
        arkret_identity::verification_method_did(acceptance.proof.verification_method.as_str())?;
    ensure!(arkret_wire::project_did_to_core_id(&signer)? == *fixture.group.server(1).service_id());
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &acceptance.proof.jws,
        &acceptance.signing_input_bytes()?,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: fixture
                .group
                .server(1)
                .federation_signing_key()?
                .verifying_key()
                .to_bytes()
                .to_vec(),
        },
    )?;
    ensure!(
        acceptance_rows(&receiver_url).await? == before,
        "receipt changed Realm acceptance/live state"
    );
    let accepted = rows(&receiver_url).await?;
    fixture
        .group
        .server_mut(1)
        .restart_external_process()
        .await?;
    ensure!(
        rows(&receiver_url).await? == accepted,
        "receipt resources changed on process restart"
    );
    for _ in 0..2 {
        let (status, replay) = fixture
            .group
            .server(1)
            .signed_peer_post_with_idempotency_key(
                fixture.group.server(0),
                "/_arkret/peer/erasure-receipts",
                &body,
                fixture.group.server(1).service_id(),
                &key,
            )
            .await?;
        ensure!(
            status == StatusCode::OK && replay == first,
            "exact receipt replay changed its original acknowledgement"
        );
        ensure!(rows(&receiver_url).await? == accepted);
    }
    let mut different = package.clone();
    different.receipt.scope.service_scope = Some("different erasure boundary".into());
    different.retained_stub.scope.service_scope = different.receipt.scope.service_scope.clone();
    sign(fixture.group.server(0), &mut different)?;
    let different = arkret_canonical::canonical_json_bytes(&ErasureReceiptSubmitRequestBody {
        package: different,
    })?;
    let (status, answer) = fixture
        .group
        .server(1)
        .signed_peer_post_with_idempotency_key(
            fixture.group.server(0),
            "/_arkret/peer/erasure-receipts",
            &different,
            fixture.group.server(1).service_id(),
            &key,
        )
        .await?;
    ensure!(
        status == StatusCode::CONFLICT,
        "receipt duplicate_conflict: {status} {}",
        String::from_utf8_lossy(&answer)
    );
    ensure!(rows(&receiver_url).await? == accepted);
    let mut invalid = package.clone();
    invalid.receipt.proofs[0].signature = "forged receipt proof".into();
    let invalid = arkret_canonical::canonical_json_bytes(&ErasureReceiptSubmitRequestBody {
        package: invalid,
    })?;
    let (status, answer) = fixture
        .group
        .server(1)
        .signed_peer_post_with_idempotency_key(
            fixture.group.server(0),
            "/_arkret/peer/erasure-receipts",
            &invalid,
            fixture.group.server(1).service_id(),
            "invalid-proof",
        )
        .await?;
    ensure!(
        status == StatusCode::BAD_REQUEST,
        "invalid receipt proof: {status} {}",
        String::from_utf8_lossy(&answer)
    );
    ensure!(rows(&receiver_url).await? == accepted);
    std::fs::create_dir_all("artifacts/hard-erasure-receipt-rail")?;
    std::fs::write(
        format!("artifacts/hard-erasure-receipt-rail/{name}.json"),
        serde_json::to_vec_pretty(&json!({
            "scenario":name,"message_commit":message_commit,"redaction_commit":redaction_commit,"departure_commit":departure_commit,
            "unreplicated_terminal":terminal_commit,"package":package,"key":key,"body":String::from_utf8(body)?,
            "original_acknowledgement":acceptance,"before_receipt":before,"after_restart":accepted,
        }))?,
    )?;
    eprintln!(
        "[erasure-process] departure={} actual_station_processes=2 real_redaction_trigger=1 later_terminal_not_replicated=1 signed_receipt_accepted=1 receiver_ack_signature_verified=1 receiver_process_restart=1 exact_replay_bytes=2 invalid_or_conflicting_package_zero_writes=2 realm_acceptance_rows_unchanged=1 no_live_or_physical_completion_claim=1",
        if ban { "ban" } else { "leave" }
    );
    Ok(())
}
