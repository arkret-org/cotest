//! Recovery completion conformance over the formal single-submit signatures.

use anyhow::{Context as _, Result, ensure};
use arkret_models_crypto::RecoveryTransactionCompletion;
use arkret_models_identity::{
    ACCOUNT_HANDOFF_ALLOWED_OPERATIONS, AccountHandoffBinding, AccountHandoffResponseBody,
    CanonicalSessionPublicJwk, IssueRecoveryCompletionGrantResponseBody,
    RecoveryCompletionGrantRequestBody,
};
use arkret_signatures::PublicKeyMaterial;
use arkret_wire::{Base64UrlString, DidUrl, Hash, RealmCommit};
use chrono::Duration;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

#[derive(Clone)]
struct CompletionVector {
    handoff: AccountHandoffResponseBody,
    request: RecoveryCompletionGrantRequestBody,
    outcome: IssueRecoveryCompletionGrantResponseBody,
    completed: RecoveryTransactionCompletion,
    commits: [RealmCommit; 2],
    candidate_method: DidUrl,
    candidate_key: PublicKeyMaterial,
    station_method: DidUrl,
    station_key: PublicKeyMaterial,
}

pub fn run_recovery_completion_grant_suite() -> Result<()> {
    let vector = completion_vector()?;
    validate_completion_vector(&vector)?;
    validate_exact_replay(&vector)?;
    validate_mutation_matrix(&vector)
}

fn candidate_signer() -> SigningKey {
    SigningKey::from_bytes(&std::array::from_fn(|index| index as u8 + 1))
}

fn completion_vector() -> Result<CompletionVector> {
    let kat = arkret_schema_conformance::spec_json_artifact(
        "fixtures/security-transaction-resilience-fixture.json",
    )?["single_submit_recovery_kat"]
        .clone();
    let completed: RecoveryTransactionCompletion =
        serde_json::from_value(kat["expected_outcome"].clone())?;
    let commits: [RealmCommit; 2] = serde_json::from_value(kat["native_commits"].clone())?;
    let mut request: RecoveryCompletionGrantRequestBody =
        serde_json::from_value(kat["completion_request"].clone())?;
    let outcome: IssueRecoveryCompletionGrantResponseBody =
        serde_json::from_value(kat["completion_expected_outcome"].clone())?;
    let source = &kat["qualified_inputs"];
    let candidate_method = DidUrl::new(
        source["candidate_method"]
            .as_str()
            .context("formal candidate method")?,
    )
    .map_err(anyhow::Error::msg)?;
    let candidate_key = PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(
            source["candidate_public_key"]
                .as_str()
                .context("formal candidate key")?,
        )?,
    };
    let station = SigningKey::from_bytes(&std::array::from_fn(|index| index as u8 + 33));
    let station_method =
        DidUrl::new("did:web:station.example#service-1").map_err(anyhow::Error::msg)?;
    let station_key = PublicKeyMaterial::Ed25519Raw {
        bytes: station.verifying_key().as_bytes().to_vec(),
    };
    let principal_did = candidate_method
        .as_str()
        .split('#')
        .next()
        .context("candidate principal DID")?;
    let at = request.accepted_device_possession_proof.issued_at;
    let handoff: AccountHandoffResponseBody = serde_json::from_value(json!({
        "request_id":"ak:request:019ba000-0000-7000-8000-000000000011",
        "account_handle":"alice:example.net",
        "account_subject":request.accepted_device_possession_proof.account_subject,
        "account_handoff_grant":"g".repeat(43),
        "expires_at":at + Duration::minutes(5),
        "allowed_operations":ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
        "binding":{"state":"bound","principal_id":request.terminal_receipt.account_id.principal_id,"did":principal_did},
    }))?;
    // R/C/native Commits are exact formal originals. This fresh PoP is really
    // re-signed for this test's independently authenticated handoff token.
    request
        .accepted_device_possession_proof
        .account_handoff_grant_digest = handoff_digest(&handoff)?;
    request.accepted_device_possession_proof.signature =
        Base64UrlString::new(arkret_canonical::base64url_encode(
            candidate_signer()
                .sign(
                    &request
                        .accepted_device_possession_proof
                        .canonical_signing_bytes()?,
                )
                .to_bytes(),
        ))
        .map_err(anyhow::Error::msg)?;
    request.canonical_request_digest = request.expected_canonical_request_digest()?;
    Ok(CompletionVector {
        handoff,
        request,
        outcome,
        completed,
        commits,
        candidate_method,
        candidate_key,
        station_method,
        station_key,
    })
}

fn handoff_digest(handoff: &AccountHandoffResponseBody) -> Result<Hash> {
    Ok(Hash::new(arkret_canonical::sha256_digest(
        handoff.account_handoff_grant.as_bytes(),
    ))?)
}

fn validate_completion_vector(vector: &CompletionVector) -> Result<()> {
    vector.handoff.validate()?;
    ensure!(
        vector.handoff.expires_at > vector.request.accepted_device_possession_proof.issued_at,
        "first completion has an expired handoff"
    );
    let r = &vector.request.terminal_receipt;
    ensure!(
        matches!(&vector.handoff.binding, AccountHandoffBinding::Bound { principal_id, .. } if principal_id == &r.account_id.principal_id),
        "completion requires this full Account's Bound handoff"
    );
    ensure!(
        arkret_canonical::canonical_json_bytes(r)?
            == arkret_canonical::canonical_json_bytes(&vector.completed.recovery_receipt)?,
        "C's native closure changed the complete signed R"
    );
    arkret_signatures::recovery::verify_recovery_receipt(
        r,
        &vector.candidate_method,
        &vector.candidate_key,
    )?;
    arkret_signatures::recovery::verify_recovery_completion(
        &vector.completed,
        &vector.commits,
        &vector.station_method,
        &vector.station_key,
    )?;
    arkret_signatures::recovery::verify_recovery_completion_holder(
        &vector.request,
        &vector.candidate_method,
        &vector.candidate_key,
    )?;
    let holder = vector
        .request
        .initial_session
        .session_public_key
        .thumbprint_sha256()?;
    vector.request.validate_first_issue(
        &vector.completed.completion_attestation,
        &vector.handoff.account_subject,
        &handoff_digest(&vector.handoff)?,
        &holder,
        vector.request.accepted_device_possession_proof.issued_at,
    )?;
    ensure!(
        vector.outcome.transaction_id == r.transaction_id,
        "issuer outcome changed its transaction"
    );
    let grant = &vector.outcome.issued_session;
    grant.validate_binding(
        &r.session_grant_ref.issuer_id,
        &r.account_id,
        &vector.request.initial_session.audience_id,
        &vector.request.initial_session.session_public_key,
        vector.request.accepted_device_possession_proof.issued_at,
    )?;
    ensure!(
        grant.account_id == r.account_id
            && grant.issuer_id == r.session_grant_ref.issuer_id
            && grant.device_id.as_ref() == Some(&r.new_device_id),
        "issuer outcome changed Account/issuer/accepted replacement"
    );
    garth::SessionGrantState::from_initial_registration_outcome(
        &vector.request.initial_session,
        grant.clone(),
        vector.outcome.issued_at,
    )?;
    let operation_values = serde_json::to_string(&ACCOUNT_HANDOFF_ALLOWED_OPERATIONS)?;
    ensure!(
        !operation_values.contains("promote") && !operation_values.contains("exchange_recovery"),
        "handoff exposes a second promotion/exchange path"
    );
    Ok(())
}

fn validate_exact_replay(vector: &CompletionVector) -> Result<()> {
    let issuer = &vector.outcome.issued_session.issuer_id;
    let key = vector.request.operation_identity(issuer)?;
    let request_bytes = arkret_canonical::canonical_json_bytes(&vector.request)?;
    let outcome_bytes = arkret_canonical::canonical_json_bytes(&vector.outcome)?;
    let ledger = std::collections::BTreeMap::from([(
        key.clone(),
        (request_bytes.clone(), outcome_bytes.clone()),
    )]);
    let stored = ledger.get(&key).context("accepted business key absent")?;
    ensure!(
        stored.0 == request_bytes && stored.1 == outcome_bytes,
        "exact replay lost original bytes"
    );
    vector.request.validate_exact_replay(
        &vector.request,
        &vector.request.terminal_receipt.account_id,
        &vector.request.accepted_device_possession_proof.holder_jkt,
    )?;
    let mut changed = vector.request.clone();
    changed.accepted_device_possession_proof.request_id =
        "ak:request:019ba000-0000-7000-8000-000000000099".parse()?;
    changed.canonical_request_digest = changed.expected_canonical_request_digest()?;
    ensure!(
        changed.operation_identity(issuer)? == key,
        "caller request id created another business issuance"
    );
    ensure!(
        changed
            .validate_exact_replay(
                &vector.request,
                &vector.request.terminal_receipt.account_id,
                &vector.request.accepted_device_possession_proof.holder_jkt
            )
            .is_err(),
        "same business key accepted a different whole request"
    );
    let other: arkret_wire::DidCoreId = "ak:did_core:web:other.example".parse()?;
    ensure!(
        vector.request.operation_identity(&other)? != key,
        "issuer scoped business key collapsed"
    );
    ensure!(
        vector
            .request
            .validate_exact_replay(
                &vector.request,
                &vector.request.terminal_receipt.account_id,
                &"A".repeat(43)
            )
            .is_err(),
        "exact body substituted authenticated holder"
    );
    Ok(())
}

fn changed_request(vector: &mut CompletionVector) -> Result<()> {
    vector.request.canonical_request_digest = vector.request.expected_canonical_request_digest()?;
    Ok(())
}

fn validate_mutation_matrix(vector: &CompletionVector) -> Result<()> {
    let mut cases = Vec::new();
    let mut next = vector.clone();
    next.request.terminal_receipt.transaction_id =
        "ak:transaction:019ba000-0000-7000-8000-000000000099".parse()?;
    cases.push(("transaction", next));
    let mut next = vector.clone();
    next.request.terminal_receipt.welcome_count += 1;
    cases.push(("receipt signature", next));
    let mut next = vector.clone();
    next.completed.completion_attestation.completed_at += Duration::seconds(1);
    cases.push(("Station C signature", next));
    let mut next = vector.clone();
    next.completed
        .completion_attestation
        .reanchor_event_ref
        .commit_id = arkret_identifiers::RealmCommitId::from_digest([0x99; 32]);
    cases.push(("reanchor accepting Commit", next));
    let mut next = vector.clone();
    next.completed
        .completion_attestation
        .device_authorization_event_ref
        .stream_position += 1;
    cases.push(("authorization consecutive position", next));
    let mut next = vector.clone();
    next.request.initial_session.device_id =
        "ak:device:019ba000-0000-7000-8000-000000000099".parse()?;
    cases.push(("replacement Device", next));
    let mut next = vector.clone();
    next.request.terminal_receipt.new_model_generation_ref += 1;
    cases.push(("generation", next));
    let mut next = vector.clone();
    next.request.initial_session.session_public_key = CanonicalSessionPublicJwk::new(format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        arkret_canonical::base64url_encode(
            SigningKey::from_bytes(&[0x53; 32])
                .verifying_key()
                .as_bytes()
        )
    ))?;
    cases.push(("new holder JWK", next));
    let mut next = vector.clone();
    next.request.initial_session.audience_id = "ak:did_core:web:other.example".parse()?;
    cases.push(("audience", next));
    let mut next = vector.clone();
    next.request.terminal_receipt.session_grant_ref.issuer_id =
        "ak:did_core:web:other.example".parse()?;
    cases.push(("historical grant issuer", next));
    let mut next = vector.clone();
    next.request
        .accepted_device_possession_proof
        .account_handoff_grant_digest = Hash::new(format!("sha256:{}", "4".repeat(64)))?;
    cases.push(("fresh handoff binding", next));
    let mut next = vector.clone();
    next.request.accepted_device_possession_proof.purpose =
        arkret_wire::AcceptedDeviceIssuePossessionPurpose::SessionGrantIssue;
    cases.push(("completion purpose separation", next));
    let mut next = vector.clone();
    next.handoff.expires_at = next.request.accepted_device_possession_proof.issued_at;
    next.request.accepted_device_possession_proof.expires_at =
        next.request.accepted_device_possession_proof.issued_at;
    cases.push(("PoP validity window", next));
    for (name, mut mutation) in cases {
        changed_request(&mut mutation)?;
        ensure!(
            validate_completion_vector(&mutation).is_err(),
            "completion accepted mutated {name}"
        );
    }
    // Initial session has no client-chosen requested scope; these unknown
    // fields must be rejected by the actual closed parser, not ignored.
    let mut scope = serde_json::to_value(&vector.request)?;
    scope["initial_session"]["requested_scope"] = json!(["ak.self.events.command.submit.v1"]);
    ensure!(
        serde_json::from_value::<RecoveryCompletionGrantRequestBody>(scope).is_err(),
        "initial intent accepted a scope override"
    );
    // Complete EAS carriers are retained; native PCR slots have no generic
    // approval action. Even an empty supplied sidecar must not be stripped.
    let mut carrier = serde_json::to_value(&vector.request)?;
    carrier["terminal_receipt"]["recovery_unit"]["events"][0]["approval_signatures"] = json!([]);
    ensure!(
        serde_json::from_value::<RecoveryCompletionGrantRequestBody>(carrier)
            .map_or(true, |value| value.validate_structural().is_err()),
        "Recovery discarded an unregistered approval carrier"
    );
    let proof = &vector.request.accepted_device_possession_proof;
    ensure!(
        vector
            .request
            .validate_first_issue(
                &vector.completed.completion_attestation,
                &vector.handoff.account_subject,
                &handoff_digest(&vector.handoff)?,
                &proof.holder_jkt,
                proof.expires_at
            )
            .is_err(),
        "expired first-admission PoP was accepted"
    );
    Ok(())
}
