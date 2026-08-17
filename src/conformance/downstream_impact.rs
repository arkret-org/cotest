use anyhow::{Result, anyhow, bail};
use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_event_draft::test_support::raw_projected_operation;
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusPrincipalAuthority, UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger;
use arkret_models_collaboration::events_payloads::private_view_account_data_key;
use arkret_models_collaboration::governance::policy_check::{
    PolicyCheckOutcome, policy_decision_transcript_bytes,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_collaboration::objects::queries::View;
use arkret_wire::{
    DidCoreId, DidUrl, ErrorCode, ErrorStatusContext, EventKind, NonEmptyString, OperationId,
    RealmId, ReceiptId, SchemaId,
};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use serde_json::{Value, json};
use soland_domain::hlc::ServerHlc;
use soland_domain::reducer::{ProjectionEffect, ProjectionState};
use soland_storage::{
    AccountStatusReplicaAppend, AccountStatusReplicaConflictKind, SyncStoreRegistry as _,
};

pub fn run_downstream_impact_contract_suite() -> Result<()> {
    run_account_status_authority_binding_vector()?;
    run_private_view_account_data_vector()?;
    run_moderation_dismiss_and_concurrent_fold_vector()?;
    run_policy_transcript_tamper_vector()?;
    run_error_status_context_vector()?;
    run_error_code_vocabulary_unregistered_spelling_vector()?;
    run_event_kind_unregistered_spelling_vector()?;
    Ok(())
}

pub fn run_account_status_authority_binding_vector() -> Result<()> {
    assert_eq!(
        arkret_wire::ReasonCode::ACCOUNT_STATUS_RECORD_STALE,
        "account_status_record_stale"
    );
    assert_eq!(
        arkret_wire::ReasonCode::ACCOUNT_STATUS_RECORD_FORK,
        "account_status_record_fork"
    );
    assert_eq!(
        arkret_wire::ReasonCode::ACCOUNT_STATUS_BINDING_ROLLBACK,
        "account_status_binding_rollback"
    );

    let issuer_key = SigningKey::from_bytes(&[41; 32]);
    let receiver_key = SigningKey::from_bytes(&[43; 32]);
    let accepted_at = "2026-08-01T00:00:01.000Z".parse()?;
    let record = arkret_signatures::account_status::sign_account_status_record(
        UnsignedAccountStatusRecord {
            schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
            account_authority_id: DidCoreId::new("ak:did_core:web:coauth.example")?,
            account_id: NonEmptyString::new("account-cotest-1").map_err(anyhow::Error::msg)?,
            principal_authority: AccountStatusPrincipalAuthority {
                principal_id: DidCoreId::new("ak:did_core:web:holder.example")?,
                principal_server_id: DidCoreId::new("ak:did_core:web:soland.example")?,
            },
            principal_control_realm_id: RealmId::new(
                "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm",
            )?,
            binding_version: 1,
            status_seq: 1,
            previous_account_status_record_id: None,
            status: AccountStatus::Active,
            reason_code: None,
            reason: None,
            issued_at: "2026-08-01T00:00:00.000Z".parse()?,
            effective_at: "2026-08-01T00:00:00.000Z".parse()?,
            expires_at: None,
            verification_method: DidUrl::new("did:web:coauth.example#account-status-key")
                .map_err(anyhow::Error::msg)?,
        },
        &issuer_key,
    )?;
    arkret_signatures::account_status::verify_account_status_record(
        &record,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: issuer_key.verifying_key().to_bytes().to_vec(),
        },
    )?;
    let receipt = arkret_signatures::account_status::sign_account_status_receipt(
        UnsignedAccountStatusReceipt {
            receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000031")?,
            account_status_record_id: record.account_status_record_id.clone(),
            record_digest: record.payload_digest()?,
            account_authority_id: record.account_authority_id.clone(),
            account_id: record.account_id.clone(),
            status_seq: record.status_seq,
            receiver_service_id: record.principal_authority.principal_server_id.clone(),
            accepted_at,
            verification_method: DidUrl::new("did:web:soland.example#notary-key")
                .map_err(anyhow::Error::msg)?,
        },
        &receiver_key,
    )?;
    arkret_signatures::account_status::verify_account_status_receipt(
        &receipt,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: receiver_key.verifying_key().to_bytes().to_vec(),
        },
    )?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let store = soland_storage_memory::SolandMemoryPersistenceStore::new();
        let replicas = store.account_status_replicas();
        assert!(matches!(
            replicas.append(&record, &receipt).await?,
            AccountStatusReplicaAppend::Accepted(_)
        ));

        let duplicate_candidate = arkret_signatures::account_status::sign_account_status_receipt(
            UnsignedAccountStatusReceipt {
                receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000032")?,
                account_status_record_id: record.account_status_record_id.clone(),
                record_digest: record.payload_digest()?,
                account_authority_id: record.account_authority_id.clone(),
                account_id: record.account_id.clone(),
                status_seq: record.status_seq,
                receiver_service_id: record.principal_authority.principal_server_id.clone(),
                accepted_at: "2026-08-01T00:00:02.000Z".parse()?,
                verification_method: DidUrl::new("did:web:soland.example#notary-key")
                    .map_err(anyhow::Error::msg)?,
            },
            &receiver_key,
        )?;
        let AccountStatusReplicaAppend::Duplicate(stored_receipt) =
            replicas.append(&record, &duplicate_candidate).await?
        else {
            bail!("exact account-status replay was not classified as duplicate");
        };
        assert_eq!(stored_receipt, receipt);

        let mut fork_unsigned = record.unsigned();
        fork_unsigned.issued_at = "2026-08-01T00:00:03.000Z".parse()?;
        fork_unsigned.effective_at = fork_unsigned.issued_at;
        let fork = arkret_signatures::account_status::sign_account_status_record(
            fork_unsigned,
            &issuer_key,
        )?;
        let fork_receipt = arkret_signatures::account_status::sign_account_status_receipt(
            UnsignedAccountStatusReceipt {
                receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000033")?,
                account_status_record_id: fork.account_status_record_id.clone(),
                record_digest: fork.payload_digest()?,
                account_authority_id: fork.account_authority_id.clone(),
                account_id: fork.account_id.clone(),
                status_seq: fork.status_seq,
                receiver_service_id: fork.principal_authority.principal_server_id.clone(),
                accepted_at: "2026-08-01T00:00:03.000Z".parse()?,
                verification_method: DidUrl::new("did:web:soland.example#notary-key")
                    .map_err(anyhow::Error::msg)?,
            },
            &receiver_key,
        )?;
        assert!(matches!(
            replicas.append(&fork, &fork_receipt).await?,
            AccountStatusReplicaAppend::Conflict {
                kind: AccountStatusReplicaConflictKind::Fork,
                ..
            }
        ));

        let mut gap_unsigned = record.unsigned();
        gap_unsigned.status_seq = 3;
        gap_unsigned.previous_account_status_record_id =
            Some(record.account_status_record_id.clone());
        gap_unsigned.status = AccountStatus::Suspended;
        gap_unsigned.issued_at = "2026-08-01T00:00:04.000Z".parse()?;
        gap_unsigned.effective_at = gap_unsigned.issued_at;
        let gap = arkret_signatures::account_status::sign_account_status_record(
            gap_unsigned,
            &issuer_key,
        )?;
        let gap_receipt = arkret_signatures::account_status::sign_account_status_receipt(
            UnsignedAccountStatusReceipt {
                receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000034")?,
                account_status_record_id: gap.account_status_record_id.clone(),
                record_digest: gap.payload_digest()?,
                account_authority_id: gap.account_authority_id.clone(),
                account_id: gap.account_id.clone(),
                status_seq: gap.status_seq,
                receiver_service_id: gap.principal_authority.principal_server_id.clone(),
                accepted_at: "2026-08-01T00:00:04.000Z".parse()?,
                verification_method: DidUrl::new("did:web:soland.example#notary-key")
                    .map_err(anyhow::Error::msg)?,
            },
            &receiver_key,
        )?;
        assert!(matches!(
            replicas.append(&gap, &gap_receipt).await?,
            AccountStatusReplicaAppend::DependencyMissing {
                required_status_seq: 2,
                ..
            }
        ));

        let mut successor_unsigned = record.unsigned();
        successor_unsigned.status_seq = 2;
        successor_unsigned.previous_account_status_record_id =
            Some(record.account_status_record_id.clone());
        successor_unsigned.binding_version = 2;
        successor_unsigned.status = AccountStatus::Locked;
        successor_unsigned.principal_control_realm_id =
            RealmId::new("ak:realm:ARmJMvTcKFyiF-V_8oL4mIoHfnlqERCrcgNBONtY4HQD")?;
        successor_unsigned.issued_at = "2026-08-01T00:00:05.000Z".parse()?;
        successor_unsigned.effective_at = successor_unsigned.issued_at;
        let successor = arkret_signatures::account_status::sign_account_status_record(
            successor_unsigned,
            &issuer_key,
        )?;
        let successor_receipt = arkret_signatures::account_status::sign_account_status_receipt(
            UnsignedAccountStatusReceipt {
                receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000035")?,
                account_status_record_id: successor.account_status_record_id.clone(),
                record_digest: successor.payload_digest()?,
                account_authority_id: successor.account_authority_id.clone(),
                account_id: successor.account_id.clone(),
                status_seq: successor.status_seq,
                receiver_service_id: successor.principal_authority.principal_server_id.clone(),
                accepted_at: "2026-08-01T00:00:05.000Z".parse()?,
                verification_method: DidUrl::new("did:web:soland.example#notary-key")
                    .map_err(anyhow::Error::msg)?,
            },
            &receiver_key,
        )?;
        assert!(matches!(
            replicas.append(&successor, &successor_receipt).await?,
            AccountStatusReplicaAppend::Accepted(_)
        ));

        let mut rollback_unsigned = successor.unsigned();
        rollback_unsigned.status_seq = 3;
        rollback_unsigned.previous_account_status_record_id =
            Some(successor.account_status_record_id.clone());
        rollback_unsigned.binding_version = 1;
        rollback_unsigned.status = AccountStatus::Suspended;
        rollback_unsigned.issued_at = "2026-08-01T00:00:06.000Z".parse()?;
        rollback_unsigned.effective_at = rollback_unsigned.issued_at;
        let rollback = arkret_signatures::account_status::sign_account_status_record(
            rollback_unsigned,
            &issuer_key,
        )?;
        let rollback_receipt = arkret_signatures::account_status::sign_account_status_receipt(
            UnsignedAccountStatusReceipt {
                receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000036")?,
                account_status_record_id: rollback.account_status_record_id.clone(),
                record_digest: rollback.payload_digest()?,
                account_authority_id: rollback.account_authority_id.clone(),
                account_id: rollback.account_id.clone(),
                status_seq: rollback.status_seq,
                receiver_service_id: rollback.principal_authority.principal_server_id.clone(),
                accepted_at: "2026-08-01T00:00:06.000Z".parse()?,
                verification_method: DidUrl::new("did:web:soland.example#notary-key")
                    .map_err(anyhow::Error::msg)?,
            },
            &receiver_key,
        )?;
        assert!(matches!(
            replicas.append(&rollback, &rollback_receipt).await?,
            AccountStatusReplicaAppend::Conflict {
                kind: AccountStatusReplicaConflictKind::BindingRollback,
                ..
            }
        ));

        Ok::<(), anyhow::Error>(())
    })?;

    let erasure_trigger = ErasureTrigger::AccountStatusRecord {
        account_status_record_id: record.account_status_record_id.clone(),
    };
    let trigger_json = serde_json::to_value(&erasure_trigger)?;
    assert_eq!(trigger_json["kind"], "account_status_record");
    assert_eq!(
        trigger_json["account_status_record_id"],
        record.account_status_record_id.as_str()
    );
    assert_eq!(
        serde_json::from_value::<ErasureTrigger>(trigger_json)?,
        erasure_trigger
    );
    assert!(
        serde_json::from_value::<ErasureTrigger>(json!({
            "triggering_event_id": "ak:event:AeT7kJ7nzcZNqlGtEPM_6ii47B_Y8P7N087AORix-7uC"
        }))
        .is_err(),
        "the pre-union event-only erasure trigger shape must remain closed"
    );

    let mut tampered = record;
    tampered.binding_version += 1;
    assert!(
        arkret_signatures::account_status::verify_account_status_record(
            &tampered,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: issuer_key.verifying_key().to_bytes().to_vec(),
            },
        )
        .is_err()
    );
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
        "created_by": "ak:did_core:web:holder.example",
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
            // A decision's add dot is derived from the Event that carries it,
            // and a decision's `decision_id` is that Event's own id. Building
            // the Operation by hand skips the submit path, so the `event_id`
            // `projection_operation_from_event` injects has to be supplied
            // here or the dot is unresolvable and the decision is rejected.
            "event_id": "ak:event:ASPgDxjNWk8NeYMYjsMrdQqizmu16D6809n9S9L0eBj0",
            "decision_id": "ak:event:ASPgDxjNWk8NeYMYjsMrdQqizmu16D6809n9S9L0eBj0",
            "issuer": "ak:did_core:web:moderator.example",
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
        let decision_event_id = crate::fixture_event_id(format!("moderation-decision:{index}"));
        let event = operation(
            index,
            &realm,
            json!({
                "event_id": decision_event_id,
                "decision_id": decision_event_id,
                "issuer": format!("ak:did_core:web:moderator-{index}.example"),
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
    Ok(raw_projected_operation(
        OperationId::new(format!("ak:operation:01904100-0000-7000-8000-{index:012x}"))?,
        realm.clone(),
        arkret_wire::event_kind_str::MODERATION_DECISION,
        payload,
    ))
}

pub fn run_policy_transcript_tamper_vector() -> Result<()> {
    let outcome: PolicyCheckOutcome = serde_json::from_value(json!({
        "request_id": "policy-cotest-1",
        "decision": "hard_deny",
        "bound_to": {
            "realm_id": "ak:realm:AeizpTttgA_DDran5rmKMGep4EOHjx10JTeYxZ6aopwg",
            "actor_id": "ak:did_core:web:holder.example",
            "action": "ak.message.create",
            "request_canonical_digest": format!("sha256:{}", "1".repeat(64)),
            "policy_server_id": "ak:did_core:web:policy.example"
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
        ("invalid_avatar_url", "avatar_url_invalid"),
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
