use anyhow::{Result, anyhow, bail};
use arkret_event_draft::Operation;
use arkret_models_collaboration::events_payloads::account::{
    AccountStatusPayload, AccountStatusServiceBinding,
};
use arkret_models_collaboration::events_payloads::private_view_account_data_key;
use arkret_models_collaboration::governance::policy_check::{
    PolicyCheckOutcome, policy_decision_transcript_bytes,
};
use arkret_models_collaboration::objects::queries::View;
use arkret_wire::{Did, ErrorCode, ErrorStatusContext, EventKind, OperationId, RealmId};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{ProjectionEffect, ProjectionState};

pub fn run_downstream_impact_contract_suite() -> Result<()> {
    run_account_status_authority_binding_vector()?;
    run_private_view_account_data_vector()?;
    run_moderation_dismiss_and_concurrent_fold_vector()?;
    run_policy_transcript_tamper_vector()?;
    run_error_status_context_vector()?;
    Ok(())
}

pub fn run_account_status_authority_binding_vector() -> Result<()> {
    let payload: AccountStatusPayload = serde_json::from_value(json!({
        "account_id": "account-cotest-1",
        "principal_id": "did:web:holder.example",
        "status": "deactivated",
        "effective_at": "2026-08-01T00:00:00.000Z"
    }))?;
    let service = Did::new("did:web:coauth.example")?;
    let holder = Did::new("did:web:holder.example")?;
    let third_party = Did::new("did:web:third-party.example")?;

    let binding = |actor, proof_controller, signature_controller, account, principal| {
        AccountStatusServiceBinding {
            actor_id: actor,
            proof_controller,
            signature_kid_controller: signature_controller,
            authoritative_service_id: &service,
            bound_account_id: account,
            bound_principal_id: principal,
            signing_key_valid_at_effective_at: true,
            delegation_covers_account_status: true,
        }
    };
    payload.validate_service_binding(&binding(
        &service,
        &service,
        &service,
        "account-cotest-1",
        &holder,
    ))?;
    assert!(
        payload
            .validate_service_binding(&binding(
                &holder,
                &service,
                &service,
                "account-cotest-1",
                &holder,
            ))
            .is_err()
    );
    assert!(
        payload
            .validate_service_binding(&binding(
                &third_party,
                &third_party,
                &third_party,
                "account-cotest-1",
                &holder,
            ))
            .is_err()
    );
    assert!(
        payload
            .validate_service_binding(&binding(
                &service,
                &service,
                &service,
                "account-cotest-2",
                &holder,
            ))
            .is_err()
    );
    assert!(
        payload
            .validate_service_binding(&binding(
                &service,
                &service,
                &service,
                "account-cotest-1",
                &third_party,
            ))
            .is_err()
    );
    Ok(())
}

pub fn run_private_view_account_data_vector() -> Result<()> {
    let value = json!({
        "schema": "ak.schema.view.v1",
        "id": "ak:view:0196419b-0000-8000-8000-000000000001",
        "realm_id": "ak:realm:0196419b-0000-8000-8000-000000000000",
        "kind": "collection",
        "visibility": "private",
        "state": "active",
        "title": "Quarterly plan",
        "query": {"realm_ids": []},
        "collection": {},
        "created_by": "did:web:holder.example",
        "created_at": "2026-08-01T00:00:00.000Z"
    });
    let view: View = serde_json::from_value(value.clone())?;
    let key = private_view_account_data_key(&view.id);
    view.validate_private_account_data(&key)?;

    for (field, replacement) in [
        ("visibility", json!("shared")),
        ("id", json!("ak:view:0196419b-0000-8000-8000-000000000009")),
        ("state", json!("tombstoned")),
    ] {
        let mut invalid = value.clone();
        invalid[field] = replacement;
        if field == "state" {
            invalid["state_changed_at"] = json!("2026-08-01T00:00:01.000Z");
        }
        let invalid: View = serde_json::from_value(invalid)?;
        if invalid.validate_private_account_data(&key).is_ok() {
            bail!("private View accepted invalid {field} binding");
        }
    }
    Ok(())
}

pub fn run_moderation_dismiss_and_concurrent_fold_vector() -> Result<()> {
    let realm = RealmId::new("ak:realm:01904100-0000-8000-8000-00000000d501")?;
    let hlc = ServerHlc::new("did:web:cotest.soland");
    let mut state = ProjectionState::new();

    let dismiss = operation(
        1,
        &realm,
        json!({
            // A decision's add dot is derived from the Event that carries it,
            // and a decision's `decision_id` is that Event's own id. Building
            // the Operation by hand skips the submit path, so the `event_id`
            // `projection_operation_from_event` injects has to be supplied
            // here or the dot is unresolvable and the decision is rejected.
            "event_id": "ak:event:01904100-0000-8000-8000-00000000d511",
            "decision_id": "ak:event:01904100-0000-8000-8000-00000000d511",
            "issuer": "did:web:moderator.example",
            "target_ref": "ak:event:01904100-0000-8000-8000-00000000d510",
            "decision": "dismiss",
            "request_canonical_digest": format!("sha256:{}", "1".repeat(64))
        }),
    )?;
    assert!(matches!(
        state.apply(&dismiss, &hlc),
        ProjectionEffect::ModerationDecisionProjected { .. }
    ));
    assert_eq!(
        state.effective_moderation_verdict("ak:event:01904100-0000-8000-8000-00000000d510"),
        "none"
    );

    let target = "ak:message:01904100-0000-8000-8000-00000000d520";
    for (index, decision) in [(2, "quarantine"), (3, "hard_deny")] {
        let event = operation(
            index,
            &realm,
            json!({
                "event_id": format!("ak:event:01904100-0000-8000-8000-{index:012x}"),
                "decision_id": format!("ak:event:01904100-0000-8000-8000-{index:012x}"),
                "issuer": format!("did:web:moderator-{index}.example"),
                "target_ref": target,
                "decision": decision,
                "request_canonical_digest": format!("sha256:{index:064x}")
            }),
        )?;
        assert!(matches!(
            state.apply(&event, &hlc),
            ProjectionEffect::ModerationDecisionProjected { .. }
        ));
    }
    assert_eq!(state.effective_moderation_verdict(target), "hard_deny");
    Ok(())
}

fn operation(index: u32, realm: &RealmId, payload: Value) -> Result<Operation> {
    Ok(Operation::create(
        OperationId::new(format!("ak:operation:01904100-0000-7000-8000-{index:012x}"))?,
        realm.clone(),
        EventKind::MODERATION_DECISION,
        payload,
    ))
}

pub fn run_policy_transcript_tamper_vector() -> Result<()> {
    let outcome: PolicyCheckOutcome = serde_json::from_value(json!({
        "request_id": "policy-cotest-1",
        "decision": "hard_deny",
        "bound_to": {
            "realm_id": "ak:realm:01904100-0000-8000-8000-00000000c501",
            "actor_id": "did:web:holder.example",
            "action": "ak.message.create",
            "request_canonical_digest": format!("sha256:{}", "1".repeat(64)),
            "policy_server_id": "did:web:policy.example"
        },
        "reason_code": "policy_denied",
        "freshness_state": "fresh",
        "expires_at": "2026-08-01T00:05:00.000Z",
        "auth_state_digest": format!("sha256:{}", "2".repeat(64)),
        "policy_frontier_digest": format!("sha256:{}", "3".repeat(64)),
        "membership_frontier_digest": format!("sha256:{}", "4".repeat(64)),
        "signature": {"kid": "did:web:policy.example#signing", "sig": "placeholder"},
        "next_retry_at": "2026-08-01T00:00:30.000Z",
        "obligations": [{"type": "audit", "level": "high"}]
    }))?;
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let signature = key.sign(&policy_decision_transcript_bytes(&outcome)?);

    let mut retry_tampered = outcome.clone();
    retry_tampered.next_retry_at = Some(arkret_canonical::parse_timestamp_canonical(
        "2026-08-01T00:00:31.000Z",
    )?);
    assert!(
        key.verifying_key()
            .verify(
                &policy_decision_transcript_bytes(&retry_tampered)?,
                &signature
            )
            .is_err()
    );

    let mut obligations_tampered = outcome;
    obligations_tampered.obligations[0]["level"] = json!("low");
    assert!(
        key.verifying_key()
            .verify(
                &policy_decision_transcript_bytes(&obligations_tampered)?,
                &signature
            )
            .is_err()
    );
    Ok(())
}

pub fn run_error_status_context_vector() -> Result<()> {
    for code in [ErrorCode::AccountLocked, ErrorCode::AccountDeactivated] {
        assert_eq!(
            code.http_status_in(ErrorStatusContext::ProtectedResource),
            401
        );
        assert_eq!(
            code.http_status_in(ErrorStatusContext::SessionIssuanceOrRefresh),
            403
        );
    }
    if ErrorCode::UpstreamUnavailable.http_status() != 503 {
        return Err(anyhow!("upstream_unavailable must map to HTTP 503"));
    }
    Ok(())
}
