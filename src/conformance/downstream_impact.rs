use anyhow::{Result, anyhow, bail};
use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_event_draft::test_support::raw_projected_operation;
use arkret_models_collaboration::events_payloads::private_view_account_data_key;
use arkret_models_collaboration::objects::queries::View;
use arkret_wire::{ErrorCode, ErrorStatusContext, EventKind, OperationId, RealmId};
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{ProjectionEffect, ProjectionState};

pub fn run_downstream_impact_contract_suite() -> Result<()> {
    run_private_view_account_data_vector()?;
    run_moderation_dismiss_and_concurrent_fold_vector()?;
    run_error_status_context_vector()?;
    run_error_code_vocabulary_unregistered_spelling_vector()?;
    run_event_kind_unregistered_spelling_vector()?;
    Ok(())
}

pub fn run_private_view_account_data_vector() -> Result<()> {
    let value = json!({
        "schema": "ak.schema.view.v1",
        "id": "ak:view:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "realm_id": "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
        "kind": "collection",
        "visibility": "private",
        "state": "active",
        "title": "Quarterly plan",
        "query": {"realm_ids": []},
        "collection": {},
        "created_by": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:holder.example")?,
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example")?,
        )),
        "created_at": "2026-08-01T00:00:00.000Z"
    });
    let view: View = serde_json::from_value(value.clone())?;
    let key = private_view_account_data_key(&view.id);
    view.validate_private_account_data(&key)?;

    for (field, replacement) in [
        ("visibility", json!("shared")),
        (
            "id",
            json!("ak:view:AWRG_dEWzM4Zq0kKT_o7Ki7Pbl39AAAer0QSkhWLhblO"),
        ),
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
    let realm = RealmId::new("ak:realm:Aehk8ouR0nK85TCbP4F3AufePk0nSVb_1zu_q_iVuLjB")?;
    let hlc = ServerHlc::new("did:web:cotest.soland");
    let mut state = ProjectionState::new();

    let dismiss = operation(
        1,
        &realm,
        json!({
            "issuer_id": "ak:did_core:web:moderator.example",
            "target_ref": "ak:event:AeT7kJ7nzcZNqlGtEPM_6ii47B_Y8P7N087AORix-7uC",
            "decision": "dismiss",
            "request_canonical_digest": format!("sha256:{}", "1".repeat(64))
        }),
    )?;
    assert!(matches!(
        state.apply(&dismiss, &hlc),
        ProjectionEffect::ModerationDecisionProjected { .. }
    ));
    assert_eq!(
        state.effective_moderation_verdict("ak:event:AeT7kJ7nzcZNqlGtEPM_6ii47B_Y8P7N087AORix-7uC"),
        "none"
    );

    let target = "ak:message:AezGbwu72cSXxrMK4QxMKyWVgI6i_yoX0AnYt4iKz49P";
    for (index, decision) in [(2, "quarantine"), (3, "hard_deny")] {
        let event = operation(
            index,
            &realm,
            json!({
                "issuer_id": format!("ak:did_core:web:moderator-{index}.example"),
                "target_ref": target,
                "decision": decision,
                "request_canonical_digest": format!("sha256:{index:064x}")
            }),
        )?;
        assert!(matches!(
            state.apply(&event, &hlc),
            ProjectionEffect::ModerationDecisionProjected { ref decision_id, .. }
                if decision_id == event.context.event_id.as_str()
        ));
    }
    assert_eq!(state.effective_moderation_verdict(target), "hard_deny");
    Ok(())
}

fn operation(index: u32, realm: &RealmId, payload: Value) -> Result<Operation> {
    Ok(raw_projected_operation(
        OperationId::new(format!("ak:operation:01904100-0000-7000-8000-{index:012x}"))?,
        realm.clone(),
        arkret_wire::event_kind_str::MODERATION_DECISION,
        payload,
    ))
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

fn run_error_code_vocabulary_unregistered_spelling_vector() -> Result<()> {
    const RENAMES: &[(&str, &str)] = &[
        ("bad_json", "json_invalid"),
        ("bad_query", "query_invalid"),
        ("device_not_authorized", "device_unauthorized"),
        ("directory_not_authorized", "directory_unauthorized"),
        (
            "federation_actor_origin_rejected",
            "federation_actor_origin_denied",
        ),
        ("invalid_avatar_blob_ref", "avatar_blob_ref_invalid"),
        ("invalid_genesis_seal", "genesis_seal_invalid"),
        ("invalid_param", "param_invalid"),
        ("invalid_response", "response_invalid"),
        ("invalid_signature", "signature_invalid"),
        ("missing_param", "param_missing"),
        (
            "organization_registration_scope_unsupported",
            "unsupported_organization_registration_scope",
        ),
        ("profile_unsupported", "unsupported_profile"),
        (
            "recovery_policy_device_not_authorized",
            "recovery_policy_device_unauthorized",
        ),
        (
            "service_registration_rejected",
            "service_registration_denied",
        ),
        ("signal_class_not_permitted", "signal_class_denied"),
        ("stale_frontier", "frontier_stale"),
        ("stale_peer", "peer_stale"),
        (
            "stale_peer_state_unavailable",
            "peer_state_stale_unavailable",
        ),
        ("stale_seal_ref", "seal_ref_stale"),
        ("unknown_did", "did_unknown"),
        ("verifier_not_authorized", "verifier_unauthorized"),
    ];

    for &(unregistered, canonical) in RENAMES {
        if ErrorCode::from_wire(unregistered).is_some() {
            bail!("unregistered error code `{unregistered}` is accepted by the SDK parser");
        }
        let parsed = ErrorCode::from_wire(canonical)
            .ok_or_else(|| anyhow!("canonical error code `{canonical}` is not recognised"))?;
        if parsed.as_str() != canonical {
            bail!("canonical error code `{canonical}` did not round-trip exactly");
        }
    }

    Ok(())
}

fn run_event_kind_unregistered_spelling_vector() -> Result<()> {
    const RENAMES: &[(&str, &str)] = &[
        ("ak.contact.tombstoned", "ak.contact.tombstone"),
        ("ak.state.conflict_recovery", "ak.conflict.recovery"),
    ];

    for &(unregistered, canonical) in RENAMES {
        if EventKind::try_new(unregistered)
            .and_then(|kind| kind.descriptor())
            .is_some()
        {
            bail!("unregistered event kind `{unregistered}` resolves to an SDK descriptor");
        }
        let parsed = EventKind::try_new(canonical)
            .ok_or_else(|| anyhow!("canonical event kind `{canonical}` is invalid"))?;
        if parsed.descriptor().is_none() {
            bail!("canonical event kind `{canonical}` has no SDK descriptor");
        }
        if parsed.as_str() != canonical {
            bail!("canonical event kind `{canonical}` did not round-trip exactly");
        }
    }

    Ok(())
}
