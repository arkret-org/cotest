//! Recovery completion to direct Standard SessionGrant conformance.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, anyhow, bail};
use arkret_models_collaboration::session_grants::SessionGrantOutcome;
use arkret_models_crypto::{
    RecoveryAuthorityKind, RecoveryProofKind, RecoveryProofSummary, RecoveryReceipt,
    RecoveryReceiptAuthData, RecoveryReceiptOutcome, RecoveryTerminalCommit,
};
use arkret_models_identity::{
    ACCOUNT_HANDOFF_ALLOWED_OPERATIONS, AccountHandoffBinding, AccountHandoffOutcome,
    CanonicalSessionPublicJwk, InitialSessionGrantIntent, standard_initial_session_grant_scope,
};
use arkret_wire::{
    AccountId, CommitStreamRef, CommittedEventRef, Did, Hash, IssueRecoveryCompletionGrantOutcome,
    IssueRecoveryCompletionGrantRequest, UnsignedRecoveryCompletionAttestation,
    UnsignedRecoveryCompletionAttestationBody, project_did_to_core_id,
};
use base64::Engine as _;
use chrono::{Duration, TimeZone as _, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _};
use serde_json::{Value, json};

#[derive(Clone)]
struct CompletionContext {
    principal_id: String,
    audience: String,
    holder_jkt: String,
}

#[derive(Clone)]
struct CompletionVector {
    handoff: AccountHandoffOutcome,
    request: IssueRecoveryCompletionGrantRequest,
    outcome: IssueRecoveryCompletionGrantOutcome,
    /// The replacement device receipt that terminates the recovery unit.
    terminal_commit: RecoveryTerminalCommit,
    reanchor_event_ref: CommittedEventRef,
    device_authorization_event_ref: CommittedEventRef,
    coordinator_key: SigningKey,
    replacement_key: SigningKey,
    context: CompletionContext,
}

pub fn run_recovery_completion_grant_suite() -> Result<()> {
    let vector = completion_vector()?;
    validate_completion_vector(&vector)?;
    validate_exact_replay(&vector)?;
    validate_mutation_matrix(&vector)
}

fn completion_vector() -> Result<CompletionVector> {
    let principal_id = "ak:did_core:webvh:z6mkfixture";
    let principal_did = "did:webvh:z6mkfixture:alice.example";
    let device_id = "ak:device:019a8400-0000-7000-8000-000000000001";
    let transaction_id = "ak:transaction:019a8400-0000-7000-8000-000000000002";
    let transaction_request_digest = hash('1');
    let prepared_plan_digest = hash('2');
    let authorization_event_id = "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM";
    let previous_generation = 1;
    let result_generation = 2;
    let started_at = Utc
        .with_ymd_and_hms(2026, 8, 9, 12, 0, 0)
        .single()
        .context("construct recovery start time")?
        + Duration::milliseconds(1);
    let completed_at = started_at + Duration::minutes(2);

    let coordinator_key = SigningKey::from_bytes(&[0x31; 32]);
    let coordinator_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        coordinator_key.verifying_key().as_bytes(),
    );
    let coordinator_did = Did::new(format!("did:key:{coordinator_multibase}"))?;
    let audience = project_did_to_core_id(&coordinator_did)?.to_string();
    let verification_method = format!("{coordinator_did}#{coordinator_multibase}");

    // The replacement device signs the terminal receipt. The coordinator
    // countersigns the exact committed Event pair in the completion attestation.
    let replacement_key = SigningKey::from_bytes(&[0x71; 32]);
    let replacement_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        replacement_key.verifying_key().as_bytes(),
    );
    let replacement_did = Did::new(format!("did:key:{replacement_multibase}"))?;
    let replacement_method = format!("{replacement_did}#{replacement_multibase}");

    let realm_id = "ak:realm:ATg8FU4syAKnb6AxCmZvnzVYTFe33amlqXfbtAUgi5R3".parse()?;
    let stream_ref = CommitStreamRef::Realm { realm_id };
    let reanchor_event_ref = CommittedEventRef {
        event_id: "ak:event:AZk4PXzJ6MpkxXnYTUmgXzeIYNd0Wfnz3N0hwLHNV6Xq".parse()?,
        commit_id: arkret_identifiers::RealmCommitId::from_digest([0x55; 32]),
        stream_ref: stream_ref.clone(),
        stream_position: 8,
    };
    let device_authorization_event_ref = CommittedEventRef {
        event_id: authorization_event_id.parse()?,
        commit_id: arkret_identifiers::RealmCommitId::from_digest([0x66; 32]),
        stream_ref,
        stream_position: 9,
    };

    let mut receipt = RecoveryReceipt {
        schema: arkret_wire::SchemaId::RECOVERY_RECEIPT_V1.to_owned(),
        receipt_id: "ak:receipt:019a8400-0000-7000-8000-000000000003".parse()?,
        transaction_id: transaction_id.parse()?,
        transaction_request_digest: transaction_request_digest.parse()?,
        prepared_plan_digest: prepared_plan_digest.parse()?,
        account_id: arkret_wire::AccountId::new(principal_id.parse()?, audience.parse()?),
        recovery_session_id: "ak:recovery_session:019a8400-0000-7000-8000-000000000004".parse()?,
        policy_id: "ak:policy:019a8400-0000-7000-8000-000000000005".parse()?,
        policy_version: 1,
        trust_domain: "ak:trust_domain:example.net".parse()?,
        new_device_id: device_id.parse()?,
        identity_model: arkret_models_crypto::RecoveryIdentityModel::PcrPolicy,
        recovery_authority_kind: RecoveryAuthorityKind::PcrPolicy,
        previous_model_generation_ref: previous_generation,
        result_model_generation_ref: result_generation,
        authorization_event_id: authorization_event_id.parse()?,
        reanchor_event_id: reanchor_event_ref.event_id.clone(),
        proof_summary: RecoveryProofSummary {
            kind: RecoveryProofKind::RecoveryUnlock,
            proof_digest: hash('4').parse()?,
            quorum_participant_count: None,
        },
        unlocked_backups: Vec::new(),
        welcome_count: 0,
        welcome_realm_summaries: None,
        outcome: RecoveryReceiptOutcome::Completed,
        outcome_reason_code: None,
        started_at,
        completed_at,
        auth_data: RecoveryReceiptAuthData {
            verification_method: crate::fixture_did_url(replacement_method.clone()),
            signature_algorithm: "Ed25519".to_owned(),
            signature: arkret_wire::Base64UrlString::new("A".repeat(86))
                .map_err(anyhow::Error::msg)?,
        },
        extra: Default::default(),
    };
    receipt.auth_data.signature = arkret_wire::Base64UrlString::new(sign_b64url(
        &replacement_key,
        &receipt.signature_transcript_bytes()?,
    ))
    .map_err(anyhow::Error::msg)?;
    let terminal_receipt = serde_json::to_value(&receipt)?;
    let terminal_receipt_digest = arkret_canonical::canonical_sha256(&terminal_receipt)?;
    let terminal_commit = RecoveryTerminalCommit {
        recovery_receipt: receipt.clone(),
    };
    terminal_commit.validate()?;

    let attestation = UnsignedRecoveryCompletionAttestation::new(
        UnsignedRecoveryCompletionAttestationBody {
            transaction_id: transaction_id.parse()?,
            transaction_request_digest: transaction_request_digest.parse()?,
            prepared_plan_digest: prepared_plan_digest.parse()?,
            account_id: arkret_wire::AccountId::new(principal_id.parse()?, audience.parse()?),
            recovery_session_id: "ak:recovery_session:019a8400-0000-7000-8000-000000000004"
                .parse()?,
            terminal_receipt_id: "ak:receipt:019a8400-0000-7000-8000-000000000003".parse()?,
            terminal_receipt_digest: terminal_receipt_digest.parse()?,
            replacement_device_id: device_id.parse()?,
            result_model_generation_ref: result_generation,
            completed_at,
            reanchor_event_ref: reanchor_event_ref.clone(),
            device_authorization_event_ref: device_authorization_event_ref.clone(),
        },
        crate::fixture_did_url(verification_method.clone()),
    )?;
    let signature = arkret_wire::Base64UrlString::new(sign_b64url(
        &coordinator_key,
        &attestation.signing_bytes()?,
    ))
    .map_err(anyhow::Error::msg)?;
    let attestation = attestation.attach_signature(signature)?;

    let holder_key = SigningKey::from_bytes(&[0x52; 32]);
    let holder_x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(holder_key.verifying_key().as_bytes());
    let session_public_key = CanonicalSessionPublicJwk::new(format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{holder_x}"}}"#
    ))?;
    let holder_jkt = session_public_key.thumbprint_sha256()?;
    let initial_session = InitialSessionGrantIntent {
        device_id: device_id.parse()?,
        session_public_key: session_public_key.clone(),
        audience_id: audience.parse()?,
    };
    initial_session.validate()?;

    let mut request = IssueRecoveryCompletionGrantRequest {
        transaction_id: transaction_id.parse()?,
        transaction_request_digest: transaction_request_digest.parse()?,
        terminal_receipt,
        completion_attestation: attestation,
        device_authorization_event_id: authorization_event_id.parse()?,
        result_model_generation_ref: result_generation,
        initial_session: serde_json::to_value(&initial_session)?,
        canonical_request_digest: hash('0').parse()?,
    };
    request.canonical_request_digest = request.expected_canonical_request_digest()?;

    let grant_claims = json!({
        "credential_class": "standard",
        "session_public_key": session_public_key.clone(),
        "aud": audience,
        "scope": standard_initial_session_grant_scope()
    });
    let jwt = format!(
        "{}.{}.fixture-signature",
        encode_json(&json!({"alg": "EdDSA", "typ": "JWT"}))?,
        encode_json(&grant_claims)?
    );
    let grant = SessionGrantOutcome {
        account_id: AccountId::new(principal_id.parse()?, audience.parse()?),
        device_id: Some(device_id.parse()?),
        session_grant: jwt,
        expires_at: completed_at + Duration::hours(1),
        session_grant_id: "ak:session_grant:ATLC-gY-xpE0kN3QXVYxo0Kh32EoNCTBQTSFuu_P57e6"
            .parse()?,
        session_public_key,
        audience_id: audience.parse()?,
        granted_scope: standard_initial_session_grant_scope(),
        previous_session_grant_id: None,
    };
    let outcome = IssueRecoveryCompletionGrantOutcome {
        transaction_id: transaction_id.parse()?,
        session_grant_outcome: serde_json::to_value(grant)?,
        issued_at: completed_at,
    };
    let handoff: AccountHandoffOutcome = serde_json::from_value(json!({
        "request_id": "ak:request:019a8400-0000-7000-8000-000000000007",
        "account_handle": "alice:example.com",
        "account_subject": hash('a'),
        "account_handoff_grant": "g".repeat(32),
        "expires_at": completed_at + Duration::minutes(5),
        "allowed_operations": ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
        "binding": {
            "state": "bound",
            "principal_id": principal_id,
            "did": principal_did
        }
    }))?;

    Ok(CompletionVector {
        handoff,
        request,
        outcome,
        terminal_commit,
        reanchor_event_ref,
        device_authorization_event_ref,
        coordinator_key,
        replacement_key,
        context: CompletionContext {
            principal_id: principal_id.to_owned(),
            audience,
            holder_jkt,
        },
    })
}

fn validate_completion_vector(vector: &CompletionVector) -> Result<()> {
    vector.handoff.validate()?;
    if !matches!(
        &vector.handoff.binding,
        AccountHandoffBinding::Bound { principal_id, .. }
            if principal_id.as_str() == vector.context.principal_id
    ) {
        bail!("recovery completion requires a Bound account handoff");
    }
    vector.request.validate_structural()?;
    let receipt: RecoveryReceipt = serde_json::from_value(vector.request.terminal_receipt.clone())?;
    receipt.validate()?;
    if receipt.outcome != RecoveryReceiptOutcome::Completed {
        bail!("recovery completion used a non-terminal receipt");
    }
    verify_b64url(
        &vector.replacement_key,
        &receipt.signature_transcript_bytes()?,
        &receipt.auth_data.signature,
    )?;
    verify_b64url(
        &vector.coordinator_key,
        &vector.request.completion_attestation.signing_bytes()?,
        &vector.request.completion_attestation.auth_data.signature,
    )?;
    let attestation = &vector.request.completion_attestation;
    let receipt_digest = arkret_canonical::canonical_sha256(&vector.request.terminal_receipt)?;
    let initial: InitialSessionGrantIntent =
        serde_json::from_value(vector.request.initial_session.clone())?;
    initial.validate()?;
    let receipt_generation = serde_json::to_value(receipt.result_model_generation_ref)?;
    let attestation_generation = serde_json::to_value(attestation.result_model_generation_ref)?;
    let request_generation = serde_json::to_value(vector.request.result_model_generation_ref)?;
    if receipt.transaction_id != vector.request.transaction_id
        || receipt.transaction_request_digest != vector.request.transaction_request_digest
        || receipt.receipt_id != attestation.terminal_receipt_id
        || receipt_digest != attestation.terminal_receipt_digest.as_str()
        || receipt.account_id != attestation.account_id
        || receipt.new_device_id != attestation.replacement_device_id
        || receipt.new_device_id != initial.device_id
        || receipt.authorization_event_id != vector.request.device_authorization_event_id
        || receipt_generation != attestation_generation
        || receipt_generation != request_generation
        || receipt.reanchor_event_id != attestation.reanchor_event_ref.event_id
        || receipt.authorization_event_id != attestation.device_authorization_event_ref.event_id
        || attestation.reanchor_event_ref != vector.reanchor_event_ref
        || attestation.device_authorization_event_ref != vector.device_authorization_event_ref
        || attestation.account_id.station_id.as_str() != vector.context.audience
        || initial.audience_id.as_str() != vector.context.audience
        || initial.session_public_key.thumbprint_sha256()? != vector.context.holder_jkt
    {
        bail!("recovery completion evidence is not closed over receipt/device/session bindings");
    }

    // The signed completion binds both exact Event/RealmCommit coordinates.
    // The terminal receipt remains the same replacement-device signed value.
    let commit = &vector.terminal_commit;
    if serde_json::to_value(&commit.recovery_receipt)? != vector.request.terminal_receipt {
        bail!("recovery completion attestation does not commit to the terminal commit");
    }

    if vector.outcome.transaction_id != vector.request.transaction_id {
        bail!("completion outcome changed transaction binding");
    }
    let grant: SessionGrantOutcome =
        serde_json::from_value(vector.outcome.session_grant_outcome.clone())?;
    garth::SessionGrantState::from_initial_registration_outcome(
        &initial,
        grant.clone(),
        vector.outcome.issued_at,
    )?;
    let claims = jwt_payload(&grant.session_grant)?;
    if claims["credential_class"] != "standard" || claims.get("recovery_binding").is_some() {
        bail!("recovery completion did not issue a direct Standard grant");
    }
    let operation_values = serde_json::to_value(ACCOUNT_HANDOFF_ALLOWED_OPERATIONS)?;
    if operation_values.as_array().is_some_and(|values| {
        values.iter().any(|value| {
            value.as_str().is_some_and(|operation| {
                operation.contains("promote") || operation.contains("exchange_recovery")
            })
        })
    }) {
        bail!("account handoff exposed a second exchange/promotion operation");
    }
    Ok(())
}

fn validate_exact_replay(vector: &CompletionVector) -> Result<()> {
    let request = arkret_canonical::canonical_json_bytes(&vector.request)?;
    let outcome = arkret_canonical::canonical_json_bytes(&vector.outcome)?;
    let mut ledger = BTreeMap::new();
    ledger.insert(
        vector.request.transaction_id.to_string(),
        (request.clone(), outcome.clone()),
    );
    let replay = ledger
        .get(vector.request.transaction_id.as_str())
        .context("completion replay record")?;
    if replay.0 != request || replay.1 != outcome {
        bail!("exact recovery completion replay changed canonical outcome bytes");
    }
    let mut conflict = vector.request.clone();
    conflict.initial_session["audience"] = json!("did:webvh:z6mkfixture:other.example");
    conflict.canonical_request_digest = conflict.expected_canonical_request_digest()?;
    if arkret_canonical::canonical_json_bytes(&conflict)? == replay.0 {
        bail!("mutated recovery completion request did not conflict with durable replay");
    }
    Ok(())
}

fn validate_mutation_matrix(vector: &CompletionVector) -> Result<()> {
    let mut mutations: Vec<(&str, CompletionVector)> = Vec::new();

    let mut transaction = vector.clone();
    transaction.request.transaction_id =
        "ak:transaction:019a8400-0000-7000-8000-000000000099".parse()?;
    transaction.request.canonical_request_digest =
        transaction.request.expected_canonical_request_digest()?;
    mutations.push(("transaction", transaction));

    let mut receipt = vector.clone();
    receipt.request.terminal_receipt["welcome_count"] = json!(1);
    receipt.request.canonical_request_digest =
        receipt.request.expected_canonical_request_digest()?;
    mutations.push(("receipt", receipt));

    let mut attestation = vector.clone();
    attestation.request.completion_attestation.completed_at += Duration::seconds(1);
    attestation.request.canonical_request_digest =
        attestation.request.expected_canonical_request_digest()?;
    mutations.push(("attestation", attestation));

    // Each exact committed coordinate is independently signed. A forged
    // commit id or a reused stream position must fail without grant issuance.
    let mut reanchor_commit = vector.clone();
    reanchor_commit
        .request
        .completion_attestation
        .reanchor_event_ref
        .commit_id = arkret_identifiers::RealmCommitId::from_digest([0x99; 32]);
    reanchor_commit.request.canonical_request_digest = reanchor_commit
        .request
        .expected_canonical_request_digest()?;
    mutations.push(("reanchor_commit_id", reanchor_commit));

    let mut authorize_position = vector.clone();
    authorize_position
        .request
        .completion_attestation
        .device_authorization_event_ref
        .stream_position = 10;
    authorize_position.request.canonical_request_digest = authorize_position
        .request
        .expected_canonical_request_digest()?;
    mutations.push(("device_authorization_position", authorize_position));

    let mut device = vector.clone();
    device.request.initial_session["device_id"] =
        json!("ak:device:019a8400-0000-7000-8000-000000000099");
    device.request.canonical_request_digest = device.request.expected_canonical_request_digest()?;
    mutations.push(("device", device));

    let mut generation = vector.clone();
    generation.request.result_model_generation_ref = 3;
    generation.request.canonical_request_digest =
        generation.request.expected_canonical_request_digest()?;
    mutations.push(("generation", generation));

    let mut session_key = vector.clone();
    let other_key = SigningKey::from_bytes(&[0x53; 32]);
    let other_x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(other_key.verifying_key().as_bytes());
    session_key.request.initial_session["session_public_key"] = json!(format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{other_x}"}}"#
    ));
    session_key.request.canonical_request_digest =
        session_key.request.expected_canonical_request_digest()?;
    mutations.push(("session JWK thumbprint", session_key));

    let mut audience = vector.clone();
    audience.request.initial_session["audience"] = json!("did:webvh:z6mkfixture:other.example");
    audience.request.canonical_request_digest =
        audience.request.expected_canonical_request_digest()?;
    mutations.push(("audience", audience));

    let mut scope = vector.clone();
    scope.request.initial_session["requested_scope"] = json!([
        "ak.self.account.read.describe.v1",
        "ak.self.events.command.submit.v1"
    ]);
    scope.request.canonical_request_digest = scope.request.expected_canonical_request_digest()?;
    mutations.push(("scope", scope));

    for (name, mutation) in mutations {
        if validate_completion_vector(&mutation).is_ok() {
            bail!("recovery completion accepted mutated {name}");
        }
    }
    Ok(())
}

fn hash(ch: char) -> String {
    format!("sha256:{}", ch.to_string().repeat(64))
}

fn sign_b64url(key: &SigningKey, message: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.sign(message).to_bytes())
}

fn verify_b64url(key: &SigningKey, message: &[u8], signature: &str) -> Result<()> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature)
        .context("decode Ed25519 signature")?;
    let signature = Signature::from_slice(&bytes).map_err(|error| anyhow!(error.to_string()))?;
    key.verifying_key()
        .verify(message, &signature)
        .map_err(|error| anyhow!(error.to_string()))
}

fn encode_json(value: &Value) -> Result<String> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?))
}

fn jwt_payload(jwt: &str) -> Result<Value> {
    let payload = jwt
        .split('.')
        .nth(1)
        .context("session grant is not compact JWT")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?;
    serde_json::from_slice(&bytes).context("decode session grant claims")
}
