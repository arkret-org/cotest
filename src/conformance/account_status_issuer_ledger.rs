//! `ak.vector.account_status.issuer_ledger.v1` — Account Authority issuer
//! ledger closure (`zh/identity/account-lifecycle.md` §3 / §3.1,
//! `zh/conformance/conformance-vectors.md` "Account status issuer ledger").
//!
//! Account lifecycle is **not** a Principal Control Realm finality domain. An
//! `AccountStatusRecord` is not an Event: it never enters a Realm timeline, an
//! actor frontier, a Seal, a CBA, a Control Proposal or a lattice reducer, and
//! neither a holder device nor a PCR notary can veto an Account Authority deny
//! transition. Everything in this module drives the shared SDK types and the
//! Station replica store, so a divergence here is a real divergence
//! and not a test-local reimplementation.
//!
//! Closure driven here:
//!
//! 1. genesis is `status_seq=1, status=active`, has no predecessor and needs no PCR Seal or
//!    frontier;
//! 2. byte-identical replay returns the first receipt (`duplicate`), not a second write;
//! 3. same-sequence chain conflict is a typed fork, never `duplicate_conflict`;
//! 4. a higher-sequence gap performs zero writes, reports the exact `required_status_seq`, and is
//!    repaired through the bounded `ak.peer.account_status.read.resolve.v1` range;
//! 5. a lower `binding_version` is a typed binding rollback;
//! 6. an offline, revoked or hostile holder cannot veto `locked | suspended | deactivated |
//!    erasure_pending` — the record carries no holder-controlled carrier at all, and a
//!    holder-controlled proof is rejected outright;
//! 7. an Account Authority service-key rotation keeps historical records verifiable and replicable,
//!    while the rotated key must still resolve to the same Account Authority;
//! 8. receipted fanout replicates the exact signed record bytes and accepts only receiver-signed
//!    `AccountStatusReceipt` values;
//! 9. the erasure trigger union is closed and account erasure binds the exact record id.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusReceipt, AccountStatusRecord, AccountStatusResolveOutcome,
    AccountStatusResolveRequestBody, UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::account_status::{
    sign_account_status_receipt, sign_account_status_record as sdk_sign_account_status_record,
    verify_account_status_receipt, verify_account_status_record,
};
use arkret_wire::{
    AccountId, AccountStatusRecordId, DidCoreId, DidUrl, ErrorCode, RealmId, ReasonCode, ReceiptId,
    SchemaId, ServiceOperationId,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use soland_storage::{
    AccountStatusReplicaAppend, AccountStatusReplicaConflictKind, AccountStatusReplicaStore,
    SyncStoreRegistry as _,
};

use super::load_artifact_json;
use super::schema_validation_fixture::SchemaEnv;
use super::security_closure::SecurityClosureFixture;

pub const VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER: &str =
    "ak.vector.account_status.issuer_ledger.v1";

const AUTHORITY_ID: &str = "ak:did_core:web:coauth.example";
const AUTHORITY_METHOD: &str = "did:web:coauth.example#account-status-key";
/// Successor service key after an Account Authority key rotation. Same
/// controller, different key reference.
const AUTHORITY_ROTATED_METHOD: &str = "did:web:coauth.example#account-status-key-2";

fn sign_account_status_record(
    unsigned: UnsignedAccountStatusRecord,
    signing_key: &SigningKey,
) -> arkret_signatures::Result<AccountStatusRecord> {
    sdk_sign_account_status_record(
        unsigned,
        DidUrl::new(AUTHORITY_METHOD).expect("constant Account Authority method"),
        signing_key,
    )
}
const STATION_ID: &str = "ak:did_core:web:soland.example";
const RECEIVER_METHOD: &str = "did:web:soland.example#notary-key";
const PRINCIPAL_CONTROL_REALM: &str = "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm";
const REBOUND_PRINCIPAL_CONTROL_REALM: &str =
    "ak:realm:ARmJMvTcKFyiF-V_8oL4mIoHfnlqERCrcgNBONtY4HQD";

/// Field names that would reintroduce the superseded Event / PCR authority
/// model into a portable record. None of them may appear at any depth.
const FORBIDDEN_RECORD_KEYS: &[&str] = &[
    "seal_basis",
    "pending_seal",
    "authoring_frontiers",
    "account_status_authoring_frontiers",
    "current_status_event_ids",
    "event_id",
    "frontier_digest",
    "seal_ref",
    "device_id",
    "holder_proof",
    "holder_signature",
    "notary_proof",
    "cell_ref",
];

/// Fixture steps this suite deliberately does not drive, asserted here only at
/// the registered-vocabulary level.
///
/// * `record_or_idempotency_mismatch_is_zero_write` is an `Idempotency-Key` scope decision that
///   exists only on the `ak.peer.account_status.command.submit.v1` transport, not on any shared
///   type.
const TRANSPORT_ONLY_STEPS: &[&str] = &["record_or_idempotency_mismatch_is_zero_write"];

/// Machine-readable classification table the receiver decision is compared
/// against. It is the spec's own ordered rule set, so a reordering or a
/// re-typed outcome fails here rather than being absorbed by this suite.
const REPLICA_DECISION_TABLE_REF: &str = "registry/account-status-replica-decision-table.json";

/// What the deterministic model actually produced for one fixture step.
#[derive(Clone, Debug)]
struct StepObservation {
    outcome: &'static str,
    reason_code: Option<String>,
}

impl StepObservation {
    fn accepted() -> Self {
        Self {
            outcome: "accepted",
            reason_code: None,
        }
    }

    fn rejected(reason_code: &str) -> Self {
        Self {
            outcome: "rejected",
            reason_code: Some(reason_code.to_owned()),
        }
    }
}

type Observations = BTreeMap<&'static str, StepObservation>;

pub fn run_account_status_issuer_ledger_vector() -> Result<()> {
    let mut observed: Observations = BTreeMap::new();

    let authority_key = SigningKey::from_bytes(&[41; 32]);
    let rotated_authority_key = SigningKey::from_bytes(&[47; 32]);
    let receiver_key = SigningKey::from_bytes(&[43; 32]);
    let holder_key = SigningKey::from_bytes(&[45; 32]);

    assert_typed_reason_codes_are_registered()?;
    assert_resolve_operation_is_registered()?;
    assert_durable_head_is_the_only_comparison_baseline()?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let receiver = soland_storage_memory::SolandMemoryPersistenceStore::new();
        let replicas = receiver.account_status_replicas();

        assert_genesis_replay_fork_and_binding_rollback(
            replicas,
            &authority_key,
            &receiver_key,
            &mut observed,
        )
        .await?;
        assert_gap_recovery_through_bounded_resolve(
            replicas,
            &authority_key,
            &receiver_key,
            &mut observed,
        )
        .await?;
        assert_offline_and_hostile_holder_cannot_veto_deny(
            replicas,
            &authority_key,
            &receiver_key,
            &holder_key,
        )
        .await?;
        assert_service_key_rotation_keeps_records_verifiable(
            replicas,
            &authority_key,
            &rotated_authority_key,
            &receiver_key,
        )
        .await?;
        assert_below_head_is_stale_against_the_durable_head(
            replicas,
            &authority_key,
            &receiver_key,
            &mut observed,
        )
        .await?;
        Ok::<(), anyhow::Error>(())
    })?;

    assert_receipted_fanout_preserves_the_signed_record(
        &authority_key,
        &receiver_key,
        &mut observed,
    )?;
    assert_erasure_trigger_union_is_closed(&authority_key)?;

    compare_against_fixture(&observed)
}

/// Genesis, exact replay, same-sequence fork and binding rollback on one
/// monotonic replica.
async fn assert_genesis_replay_fork_and_binding_rollback(
    replicas: &dyn AccountStatusReplicaStore,
    authority_key: &SigningKey,
    receiver_key: &SigningKey,
    observed: &mut Observations,
) -> Result<()> {
    let account = "account-issuer-ledger-core";

    // A genesis record is pinned by the shared type: sequence 1 carries no
    // predecessor and no status other than `active`. Neither branch can be
    // signed at all, so no receiver ever has to re-derive the rule.
    let mut invalid_genesis = unsigned(account, 1, None, 1, AccountStatus::Active, 0)?;
    invalid_genesis.status = AccountStatus::Locked;
    if sign_account_status_record(invalid_genesis, authority_key).is_ok() {
        bail!("a non-active account-status genesis record was signable");
    }
    let mut predecessor_genesis = unsigned(account, 1, None, 1, AccountStatus::Active, 0)?;
    predecessor_genesis.previous_account_status_record_id = Some(AccountStatusRecordId::new(
        "ak:account_status_record:AaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqQ",
    )?);
    if sign_account_status_record(predecessor_genesis, authority_key).is_ok() {
        bail!("an account-status genesis record with a predecessor was signable");
    }

    let genesis = sign_account_status_record(
        unsigned(account, 1, None, 1, AccountStatus::Active, 0)?,
        authority_key,
    )?;
    verify_account_status_record(&genesis, &public_key(authority_key))?;
    assert_record_carries_no_event_or_seal_carrier(&genesis)?;

    let genesis_receipt = receipt_for(&genesis, 1, receiver_key)?;
    verify_account_status_receipt(&genesis_receipt, &public_key(receiver_key))?;
    let AccountStatusReplicaAppend::Accepted(accepted_receipt) =
        replicas.append(&genesis, &genesis_receipt).await?
    else {
        bail!("account-status genesis was not accepted by a receiver with no PCR Seal");
    };
    if accepted_receipt != genesis_receipt {
        bail!("account-status genesis acceptance returned a receipt it did not receive");
    }
    observed.insert(
        "genesis_active_is_atomic_without_pcr_frontier",
        StepObservation::accepted(),
    );

    // Exact replay: a retry carries a fresh receipt, and the receiver must
    // answer with the receipt it already made durable rather than writing again.
    let replayed_receipt = receipt_for(&genesis, 2, receiver_key)?;
    let AccountStatusReplicaAppend::Duplicate(stored_receipt) =
        replicas.append(&genesis, &replayed_receipt).await?
    else {
        bail!("exact account-status replay was not classified as duplicate");
    };
    if stored_receipt != genesis_receipt {
        bail!("account-status duplicate returned a receipt other than the first accepted one");
    }

    // Same sequence, different record id: a fork, never an idempotency conflict.
    let mut fork_unsigned = genesis.unsigned();
    fork_unsigned.issued_at = at(3)?;
    fork_unsigned.effective_at = fork_unsigned.issued_at;
    let fork = sign_account_status_record(fork_unsigned, authority_key)?;
    if fork.account_status_record_id == genesis.account_status_record_id {
        bail!("the fork fixture did not produce a second record identity");
    }
    let AccountStatusReplicaAppend::Conflict {
        kind: AccountStatusReplicaConflictKind::Fork,
        ..
    } = replicas
        .append(&fork, &receipt_for(&fork, 3, receiver_key)?)
        .await?
    else {
        bail!("a same-sequence account-status chain conflict was not classified as a fork");
    };
    assert_head_is(replicas, &genesis).await?;
    observed.insert(
        "chain_conflict_is_typed_fork_and_quarantined",
        StepObservation::rejected(ReasonCode::ACCOUNT_STATUS_RECORD_FORK),
    );

    // A valid successor advances the replica exactly once, and a re-bound
    // principal tuple is legitimate only together with a higher binding_version.
    let mut successor_unsigned = unsigned(
        account,
        2,
        Some(genesis.account_status_record_id.clone()),
        2,
        AccountStatus::Locked,
        4,
    )?;
    successor_unsigned.principal_control_realm_id = RealmId::new(REBOUND_PRINCIPAL_CONTROL_REALM)?;
    let successor = sign_account_status_record(successor_unsigned, authority_key)?;
    let AccountStatusReplicaAppend::Accepted(_) = replicas
        .append(&successor, &receipt_for(&successor, 4, receiver_key)?)
        .await?
    else {
        bail!("a valid account-status successor did not advance the monotonic replica");
    };
    assert_head_is(replicas, &successor).await?;
    observed.insert(
        "valid_successor_advances_monotonic_replica",
        StepObservation::accepted(),
    );

    // Lower binding_version under the durable floor: a typed rollback, not a fork.
    let rollback = sign_account_status_record(
        unsigned(
            account,
            3,
            Some(successor.account_status_record_id.clone()),
            1,
            AccountStatus::Suspended,
            5,
        )?,
        authority_key,
    )?;
    let AccountStatusReplicaAppend::Conflict {
        kind: AccountStatusReplicaConflictKind::BindingRollback,
        ..
    } = replicas
        .append(&rollback, &receipt_for(&rollback, 5, receiver_key)?)
        .await?
    else {
        bail!("an account-status binding_version rollback was not typed as a binding rollback");
    };
    assert_head_is(replicas, &successor).await?;
    observed.insert(
        "binding_version_rollback_is_typed_and_zero_write",
        StepObservation::rejected(ReasonCode::ACCOUNT_STATUS_BINDING_ROLLBACK),
    );

    // Signature coverage: the binding_version floor is signed, so a rollback
    // cannot be laundered by editing an accepted record.
    let mut tampered = successor;
    tampered.binding_version += 1;
    if verify_account_status_record(&tampered, &public_key(authority_key)).is_ok() {
        bail!("an account-status record survived binding_version mutation");
    }
    Ok(())
}

/// A higher-sequence submission performs zero writes, names the exact missing
/// sequence, and is repaired by the bounded resolve range rather than by
/// skipping the predecessor.
async fn assert_gap_recovery_through_bounded_resolve(
    replicas: &dyn AccountStatusReplicaStore,
    authority_key: &SigningKey,
    receiver_key: &SigningKey,
    observed: &mut Observations,
) -> Result<()> {
    let account = "account-issuer-ledger-gap";
    let authority_ledger = soland_storage_memory::SolandMemoryPersistenceStore::new();
    // The Account Authority ledger enforces the same single-writer CAS the
    // receiver replays: `status_seq = current + 1` with an exact predecessor.
    let ledger = authority_ledger.account_status_replicas();

    let genesis = sign_account_status_record(
        unsigned(account, 1, None, 1, AccountStatus::Active, 10)?,
        authority_key,
    )?;
    let second = sign_account_status_record(
        unsigned(
            account,
            2,
            Some(genesis.account_status_record_id.clone()),
            1,
            AccountStatus::Suspended,
            11,
        )?,
        authority_key,
    )?;
    let third = sign_account_status_record(
        unsigned(
            account,
            3,
            Some(second.account_status_record_id.clone()),
            1,
            AccountStatus::Deactivated,
            12,
        )?,
        authority_key,
    )?;
    for (index, record) in [&genesis, &second, &third].into_iter().enumerate() {
        let index = 10 + index as u32;
        let AccountStatusReplicaAppend::Accepted(_) = ledger
            .append(record, &receipt_for(record, index, receiver_key)?)
            .await?
        else {
            bail!("the Account Authority ledger rejected its own contiguous successor");
        };
    }

    // The receiver only holds genesis, so the third record is a gap.
    let AccountStatusReplicaAppend::Accepted(_) = replicas
        .append(&genesis, &receipt_for(&genesis, 20, receiver_key)?)
        .await?
    else {
        bail!("the gap-recovery receiver did not accept genesis");
    };
    let AccountStatusReplicaAppend::DependencyMissing {
        required_status_seq,
        current_record,
    } = replicas
        .append(&third, &receipt_for(&third, 21, receiver_key)?)
        .await?
    else {
        bail!("a higher-sequence account-status record was not reported as a dependency gap");
    };
    if required_status_seq != 2 {
        bail!("account-status gap reported required_status_seq {required_status_seq}, expected 2");
    }
    if current_record.map(|record| record.status_seq) != Some(1) {
        bail!("an account-status gap moved the replica head");
    }
    assert_head_is(replicas, &genesis).await?;
    observed.insert(
        "sequence_gap_is_zero_write_and_resolved_contiguously",
        StepObservation {
            outcome: "dependency_missing",
            reason_code: None,
        },
    );

    // Bounded resolve from the exact required sequence. The response is a
    // contiguous range of the original signed records, and the shared outcome
    // type is what proves it.
    let request = AccountStatusResolveRequestBody {
        account_authority_id: DidCoreId::new(AUTHORITY_ID)?,
        account_id: genesis.account_id.clone(),
        from_status_seq: required_status_seq,
        limit: 128,
    };
    request.validate()?;
    let resolved = ledger
        .resolve(
            request.account_authority_id.as_str(),
            &request.account_id,
            request.from_status_seq,
            request.limit,
        )
        .await?;
    let outcome = AccountStatusResolveOutcome {
        account_authority_id: request.account_authority_id.clone(),
        account_id: request.account_id.clone(),
        records: resolved,
        has_more: false,
        next_status_seq: None,
    };
    outcome.validate_for_request(&request)?;
    if outcome.records.len() != 2 {
        bail!(
            "bounded resolve returned {} records, expected the contiguous 2..=3 range",
            outcome.records.len()
        );
    }
    if outcome.records[0] != second || outcome.records[1] != third {
        bail!("bounded resolve did not return the original signed records");
    }

    // Bounds are part of the contract, not a service-local convention.
    for (from_status_seq, limit) in [(0, 128), (2, 0), (2, 129)] {
        let invalid = AccountStatusResolveRequestBody {
            account_authority_id: request.account_authority_id.clone(),
            account_id: request.account_id.clone(),
            from_status_seq,
            limit,
        };
        if invalid.validate().is_ok() {
            bail!(
                "account-status resolve accepted out-of-bounds (from_status_seq={from_status_seq}, \
                 limit={limit})"
            );
        }
    }
    let mut non_contiguous = outcome;
    non_contiguous.records.remove(0);
    if non_contiguous.validate_for_request(&request).is_ok() {
        bail!("account-status resolve accepted a non-contiguous range");
    }

    // Applying the resolved range in order clears the gap; the previously
    // rejected record is now an ordinary successor.
    for (index, record) in [&second, &third].into_iter().enumerate() {
        let index = 22 + index as u32;
        let AccountStatusReplicaAppend::Accepted(_) = replicas
            .append(record, &receipt_for(record, index, receiver_key)?)
            .await?
        else {
            bail!("gap recovery did not advance the replica over the resolved range");
        };
    }
    assert_head_is(replicas, &third).await?;
    Ok(())
}

/// The authority invariant: an offline, revoked or hostile holder cannot block
/// a deny transition, and cannot manufacture a competing record.
async fn assert_offline_and_hostile_holder_cannot_veto_deny(
    replicas: &dyn AccountStatusReplicaStore,
    authority_key: &SigningKey,
    receiver_key: &SigningKey,
    holder_key: &SigningKey,
) -> Result<()> {
    const DENY_STATUSES: &[AccountStatus] = &[
        AccountStatus::Locked,
        AccountStatus::Suspended,
        AccountStatus::Deactivated,
        AccountStatus::ErasurePending,
    ];

    for (index, status) in DENY_STATUSES.iter().copied().enumerate() {
        let account = format!("account-holder-deny-{}", status.as_str());
        let base = 30 + (index as u32) * 4;
        let genesis = sign_account_status_record(
            unsigned(&account, 1, None, 1, AccountStatus::Active, base)?,
            authority_key,
        )?;
        let AccountStatusReplicaAppend::Accepted(_) = replicas
            .append(&genesis, &receipt_for(&genesis, base, receiver_key)?)
            .await?
        else {
            bail!("holder-deny genesis was not accepted");
        };

        if !AccountStatus::Active.can_transition_to(status) {
            bail!(
                "active -> {} must be a legal Account Authority deny transition",
                status.as_str()
            );
        }
        // The deny record is produced with the Account Authority key alone: no
        // holder key, no device key, no PCR notary, no Seal, no frontier read.
        let deny = sign_account_status_record(
            unsigned(
                &account,
                2,
                Some(genesis.account_status_record_id.clone()),
                1,
                status,
                base + 1,
            )?,
            authority_key,
        )?;
        assert_record_carries_no_event_or_seal_carrier(&deny)?;
        let AccountStatusReplicaAppend::Accepted(_) = replicas
            .append(&deny, &receipt_for(&deny, base + 1, receiver_key)?)
            .await?
        else {
            bail!(
                "the receiver refused an Account Authority {} transition while the holder was \
                 offline",
                status.as_str()
            );
        };
        assert_head_is(replicas, &deny).await?;

        // A hostile holder cannot sign a competing record: the proof controller
        // must project to the Account Authority, so a holder-controlled
        // verification method is refused before any signature is even compared.
        let mut forged = deny.unsigned();
        forged.issued_at = at(base + 2)?;
        forged.effective_at = forged.issued_at;
        if sdk_sign_account_status_record(
            forged,
            DidUrl::new("did:web:alice.example#account-status-key").map_err(anyhow::Error::msg)?,
            holder_key,
        )
        .is_ok()
        {
            bail!(
                "a holder-controlled verification method produced a valid {} record",
                status.as_str()
            );
        }

        // A hostile holder cannot undo the deny: only an Account Authority
        // successor can advance this ledger. The replica intentionally cannot
        // inspect the issuer's local appeal or completed-PCR-recovery evidence;
        // it accepts an authority-signed legal successor. `erasure_pending`
        // alone has no outbound edge.
        let reversal = sign_account_status_record(
            unsigned(
                &account,
                3,
                Some(deny.account_status_record_id.clone()),
                1,
                AccountStatus::Active,
                base + 3,
            )?,
            authority_key,
        )?;
        let append = replicas
            .append(&reversal, &receipt_for(&reversal, base + 3, receiver_key)?)
            .await?;
        match status {
            AccountStatus::ErasurePending => {
                let AccountStatusReplicaAppend::Conflict {
                    kind: AccountStatusReplicaConflictKind::ErasurePendingTerminal,
                    ..
                } = append
                else {
                    bail!("erasure_pending accepted a successor despite being terminal");
                };
                assert_head_is(replicas, &deny).await?;
            }
            // `locked` and `suspended` are appealable, while `deactivated` is
            // recoverable only after the issuer's local deployment-policy and
            // completed-PCR-recovery gates. All three appear to the replica as
            // an authority-signed legal successor; authoring conformance checks
            // the distinct local authorization closures.
            _ => {
                let AccountStatusReplicaAppend::Accepted(_) = append else {
                    bail!(
                        "an Account Authority legal successor out of {} was refused",
                        status.as_str()
                    );
                };
            }
        }
    }
    Ok(())
}

/// An Account Authority service-key rotation does not invalidate the ledger:
/// records signed before the rotation stay verifiable under their historical
/// key and stay replicable, while the rotated key still has to resolve to the
/// same Account Authority.
async fn assert_service_key_rotation_keeps_records_verifiable(
    replicas: &dyn AccountStatusReplicaStore,
    authority_key: &SigningKey,
    rotated_authority_key: &SigningKey,
    receiver_key: &SigningKey,
) -> Result<()> {
    let account = "account-issuer-ledger-rotation";
    let before = sign_account_status_record(
        unsigned(account, 1, None, 1, AccountStatus::Active, 50)?,
        authority_key,
    )?;
    let after_unsigned = unsigned(
        account,
        2,
        Some(before.account_status_record_id.clone()),
        1,
        AccountStatus::Suspended,
        51,
    )?;
    let after = sdk_sign_account_status_record(
        after_unsigned,
        DidUrl::new(AUTHORITY_ROTATED_METHOD).map_err(anyhow::Error::msg)?,
        rotated_authority_key,
    )?;

    for (record, key) in [(&before, authority_key), (&after, rotated_authority_key)] {
        verify_account_status_record(record, &public_key(key))?;
    }
    // Rotation is not a wildcard: the historical record does not become
    // verifiable under the new key, nor the reverse.
    if verify_account_status_record(&before, &public_key(rotated_authority_key)).is_ok()
        || verify_account_status_record(&after, &public_key(authority_key)).is_ok()
    {
        bail!("an account-status record verified under the wrong side of a key rotation");
    }

    for (index, record) in [&before, &after].into_iter().enumerate() {
        let index = 50 + index as u32;
        let AccountStatusReplicaAppend::Accepted(_) = replicas
            .append(record, &receipt_for(record, index, receiver_key)?)
            .await?
        else {
            bail!("a service-key rotation broke monotonic replication");
        };
    }
    assert_head_is(replicas, &after).await?;

    // The rotated key still has to be controlled by the same Account
    // Authority; a rotation into a foreign controller is not a rotation.
    let foreign_unsigned = unsigned(
        account,
        3,
        Some(after.account_status_record_id.clone()),
        1,
        AccountStatus::Deactivated,
        52,
    )?;
    if sdk_sign_account_status_record(
        foreign_unsigned,
        DidUrl::new("did:web:evil.example#account-status-key").map_err(anyhow::Error::msg)?,
        rotated_authority_key,
    )
    .is_ok()
    {
        bail!("an account-status record signed by a foreign controller was accepted");
    }
    Ok(())
}

/// Below-head submissions are typed `stale`, and byte-identity with a retained
/// history row does not downgrade that to `duplicate`.
///
/// `account-status-replica-decision-table.json` settles the comparison
/// baseline: the durable replica head is the only one. A receiver that compared
/// against the stored row for the submitted `status_seq` would make the typed
/// outcome depend on how much history it happens to retain — a local retention
/// decision — and would let a bounded outbox mark a destination complete while
/// the successor record is still unreplicated. Both steps run on one replica
/// that *does* still hold the row for the submitted sequence, so the weaker
/// reading is actually reachable and is what fails here.
async fn assert_below_head_is_stale_against_the_durable_head(
    replicas: &dyn AccountStatusReplicaStore,
    authority_key: &SigningKey,
    receiver_key: &SigningKey,
    observed: &mut Observations,
) -> Result<()> {
    let account = "account-issuer-ledger-stale";

    let genesis = sign_account_status_record(
        unsigned(account, 1, None, 1, AccountStatus::Active, 80)?,
        authority_key,
    )?;
    let second = sign_account_status_record(
        unsigned(
            account,
            2,
            Some(genesis.account_status_record_id.clone()),
            1,
            AccountStatus::Locked,
            81,
        )?,
        authority_key,
    )?;
    let third = sign_account_status_record(
        unsigned(
            account,
            3,
            Some(second.account_status_record_id.clone()),
            1,
            AccountStatus::Suspended,
            82,
        )?,
        authority_key,
    )?;
    let second_receipt = receipt_for(&second, 81, receiver_key)?;
    for (index, record, receipt) in [
        (80, &genesis, receipt_for(&genesis, 80, receiver_key)?),
        (81, &second, second_receipt.clone()),
        (82, &third, receipt_for(&third, 82, receiver_key)?),
    ] {
        let AccountStatusReplicaAppend::Accepted(_) = replicas.append(record, &receipt).await?
        else {
            bail!("the stale-baseline replica refused contiguous record {index}");
        };
    }
    assert_head_is(replicas, &third).await?;
    // The receiver still holds the row for the submitted sequence, so a
    // history-row baseline would have something to match against.
    let second_account_key = second.account_id.clone();
    if replicas
        .receipt(second.account_authority_id.as_str(), &second_account_key, 2)
        .await?
        .as_ref()
        != Some(&second_receipt)
    {
        bail!("the stale-baseline replica did not retain the status_seq 2 history row");
    }

    // A below-head submission that is *not* the retained row: typed stale, and
    // never a fork, because the fork rows only cover head and head+1.
    let mut divergent_unsigned = second.unsigned();
    divergent_unsigned.issued_at = at(83)?;
    divergent_unsigned.effective_at = divergent_unsigned.issued_at;
    let divergent = sign_account_status_record(divergent_unsigned, authority_key)?;
    if divergent.account_status_record_id == second.account_status_record_id {
        bail!("the below-head fixture did not produce a second record identity");
    }
    let AccountStatusReplicaAppend::Stale { current_record } = replicas
        .append(&divergent, &receipt_for(&divergent, 83, receiver_key)?)
        .await?
    else {
        bail!("a below-head account-status submission was not classified as stale");
    };
    if current_record.account_status_record_id != third.account_status_record_id {
        bail!("the stale classification did not report the durable head");
    }
    assert_head_is(replicas, &third).await?;
    observed.insert(
        "lower_sequence_is_typed_stale_and_zero_write",
        StepObservation::rejected(ReasonCode::ACCOUNT_STATUS_RECORD_STALE),
    );

    // The same submission, byte-identical to the retained status_seq 2 row.
    // `duplicate` means the durable head already is the submitted record, so
    // this is stale too — the retained row must not downgrade the outcome.
    let replay_receipt = receipt_for(&second, 84, receiver_key)?;
    let replayed = replicas.append(&second, &replay_receipt).await?;
    if let AccountStatusReplicaAppend::Duplicate(_) = replayed {
        bail!(
            "a byte-identical below-head account-status record was answered `duplicate`; the \
             durable head is the only comparison baseline, so a retained history row must not \
             turn a stale submission into a terminal ack"
        );
    }
    let AccountStatusReplicaAppend::Stale { current_record } = replayed else {
        bail!(
            "a byte-identical below-head account-status record was not classified as stale: \
             {replayed:?}"
        );
    };
    if current_record.account_status_record_id != third.account_status_record_id {
        bail!("the byte-identical stale classification did not report the durable head");
    }
    assert_head_is(replicas, &third).await?;
    // Zero write: the retained row keeps its original receipt, and the replay
    // receipt was never made durable.
    let second_account_key = second.account_id.clone();
    let stored = replicas
        .receipt(second.account_authority_id.as_str(), &second_account_key, 2)
        .await?
        .ok_or_else(|| anyhow!("the stale replay dropped the retained status_seq 2 receipt"))?;
    if stored != second_receipt || stored == replay_receipt {
        bail!("a stale account-status submission rewrote the retained receipt");
    }
    observed.insert(
        "byte_identical_lower_sequence_is_stale_not_duplicate",
        StepObservation::rejected(ReasonCode::ACCOUNT_STATUS_RECORD_STALE),
    );
    Ok(())
}

/// The published decision table says what it must: an ordered rule set whose
/// only comparison baseline is the durable replica head, in which `duplicate`
/// is reachable solely when the head already is the submitted record.
fn assert_durable_head_is_the_only_comparison_baseline() -> Result<()> {
    let table = load_artifact_json(REPLICA_DECISION_TABLE_REF)?;
    if table.get("comparison_baseline").and_then(Value::as_str) != Some("durable_replica_head") {
        bail!("the account-status replica decision table no longer names a single baseline");
    }
    let classifications = table
        .get("classifications")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("replica decision table has no classifications[]"))?;

    let row = |name: &str| -> Result<&Value> {
        classifications
            .iter()
            .find(|row| row.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| anyhow!("replica decision table has no `{name}` classification"))
    };
    let stale = row("stale")?;
    if stale.get("outcome").and_then(Value::as_str) != Some("rejected")
        || stale.get("reason_code").and_then(Value::as_str)
            != Some(ReasonCode::ACCOUNT_STATUS_RECORD_STALE)
        || stale.get("replica_writes").and_then(Value::as_str) != Some("none")
        || stale
            .get("retryable_for_exact_record")
            .and_then(Value::as_bool)
            != Some(false)
    {
        bail!("the `stale` classification drifted from a zero-write, non-retryable rejection");
    }
    if stale.get("condition").and_then(Value::as_str)
        != Some("submitted.status_seq < head.status_seq")
    {
        bail!("the `stale` classification is no longer decided purely against the durable head");
    }
    let duplicate = row("duplicate")?;
    if duplicate.get("condition").and_then(Value::as_str)
        != Some(
            "submitted.status_seq == head.status_seq && submitted.account_status_record_id == \
             head.account_status_record_id",
        )
    {
        bail!("`duplicate` is no longer restricted to the durable head being the submitted record");
    }
    // Ordering matters: the binding rollback row is evaluated before every
    // sequence row, so a rolled-back binding can never reach the advance branch.
    let position = |name: &str| {
        classifications
            .iter()
            .position(|row| row.get("name").and_then(Value::as_str) == Some(name))
    };
    let (Some(rollback), Some(advance)) =
        (position("binding_version_rollback"), position("advance"))
    else {
        bail!("replica decision table lost the binding rollback or advance classification");
    };
    if rollback > advance {
        bail!("`binding_version_rollback` is no longer evaluated before the advance branch");
    }
    Ok(())
}

/// Receipted fanout carries the exact signed record bytes and only
/// receiver-signed `AccountStatusReceipt` values.
fn assert_receipted_fanout_preserves_the_signed_record(
    authority_key: &SigningKey,
    receiver_key: &SigningKey,
    observed: &mut Observations,
) -> Result<()> {
    let account = "account-issuer-ledger-fanout";
    let record = sign_account_status_record(
        unsigned(account, 1, None, 1, AccountStatus::Active, 60)?,
        authority_key,
    )?;
    let receipt = receipt_for(&record, 60, receiver_key)?;
    let record_json = serde_json::to_value(&record)?;
    let receipt_json = serde_json::to_value(&receipt)?;

    let env = SchemaEnv::load()?;
    let publication_validator = env.compile(
        "schemas/account-operations.schema.json#/$defs/account_status_publication_request_body",
    )?;

    let initial = json!({"publication": {"record": record_json.clone()}});
    let receipted = json!({
        "publication": {
            "record": record_json.clone(),
            "account_status_receipts": [receipt_json.clone()]
        }
    });
    for (name, body) in [("initial", &initial), ("receipted", &receipted)] {
        if !publication_validator.is_valid(body) {
            let detail = publication_validator
                .iter_errors(body)
                .next()
                .map(|error| format!("{error}"))
                .unwrap_or_else(|| "<no error reported>".to_owned());
            bail!("the {name} account-status publication was rejected by schema: {detail}");
        }
        let parsed: arkret_models_collaboration::account_lifecycle::AccountStatusPublicationRequestBody =
            serde_json::from_value(body.clone())?;
        parsed.validate_shape()?;
        if serde_json::to_value(parsed.publication.record())? != record_json {
            bail!("the {name} account-status publication mutated the signed record bytes");
        }
    }

    // Fanout progress never rewrites the record, and a receipt for another
    // record grants no replication authority.
    let mut mismatched = receipted.clone();
    mismatched["publication"]["account_status_receipts"][0]["status_seq"] = json!(2);
    if serde_json::from_value::<
        arkret_models_collaboration::account_lifecycle::AccountStatusPublicationRequestBody,
    >(mismatched)
    .is_ok_and(|body| body.validate_shape().is_ok())
    {
        bail!("a receipt bound to another record was accepted for fanout");
    }

    // A generic Event ingress receipt is not an AccountStatusReceipt, and an
    // authorization lease is not part of this carrier.
    let mut generic_receipt = receipted.clone();
    generic_receipt["publication"]["account_status_receipts"] = json!([{
        "receipt_id": "ak:receipt:01904100-0000-7000-8000-000000000099",
        "event_id": "ak:event:AeT7kJ7nzcZNqlGtEPM_6ii47B_Y8P7N087AORix-7uC"
    }]);
    let mut leased = receipted.clone();
    leased["publication"]["authorization_lease_id"] =
        json!("ak:authorization_lease:01904100-0000-7000-8000-000000000098");
    for (name, body) in [
        ("generic ingress receipt", &generic_receipt),
        ("authorization lease", &leased),
    ] {
        if publication_validator.is_valid(body) {
            bail!("the account-status fanout carrier accepted a {name}");
        }
        if serde_json::from_value::<
            arkret_models_collaboration::account_lifecycle::AccountStatusPublicationRequestBody,
        >(body.clone())
        .is_ok()
        {
            bail!("the shared fanout type accepted a {name}");
        }
    }
    observed.insert(
        "fanout_requires_dedicated_receipt_without_lease",
        StepObservation::rejected("schema_violation"),
    );
    Ok(())
}

/// Account erasure binds the exact `erasure_pending` record id through the
/// closed `event | account_status_record` trigger union.
fn assert_erasure_trigger_union_is_closed(authority_key: &SigningKey) -> Result<()> {
    let record = sign_account_status_record(
        unsigned(
            "account-issuer-ledger-erasure",
            1,
            None,
            1,
            AccountStatus::Active,
            70,
        )?,
        authority_key,
    )?;
    let trigger = ErasureTrigger::AccountStatusRecord {
        account_status_record_id: record.account_status_record_id.clone(),
    };
    let trigger_json = serde_json::to_value(&trigger)?;
    if trigger_json["kind"] != "account_status_record"
        || trigger_json["account_status_record_id"] != record.account_status_record_id.as_str()
    {
        bail!("the account-status erasure trigger did not bind the exact record id");
    }
    if serde_json::from_value::<ErasureTrigger>(trigger_json)? != trigger {
        bail!("the account-status erasure trigger did not round-trip");
    }
    // The pre-union event-only shape must stay closed; accepting it would let
    // an account erasure be attributed to an Event again.
    if serde_json::from_value::<ErasureTrigger>(json!({
        "triggering_event_id": "ak:event:AeT7kJ7nzcZNqlGtEPM_6ii47B_Y8P7N087AORix-7uC"
    }))
    .is_ok()
    {
        bail!("the pre-union event-only erasure trigger shape was accepted");
    }
    // Both union branches are closed against each other's discriminated field.
    if serde_json::from_value::<ErasureTrigger>(json!({
        "kind": "account_status_record",
        "event_id": "ak:event:AeT7kJ7nzcZNqlGtEPM_6ii47B_Y8P7N087AORix-7uC"
    }))
    .is_ok()
    {
        bail!("the account_status_record erasure trigger branch accepted an event_id");
    }
    Ok(())
}

fn assert_typed_reason_codes_are_registered() -> Result<()> {
    for code in [
        ReasonCode::ACCOUNT_STATUS_RECORD_STALE,
        ReasonCode::ACCOUNT_STATUS_RECORD_FORK,
        ReasonCode::ACCOUNT_STATUS_BINDING_ROLLBACK,
        ReasonCode::ACCOUNT_STATUS_TRANSITION_INVALID,
        ReasonCode::DUPLICATE_CONFLICT,
    ] {
        if matches!(ReasonCode::from_wire(code), ReasonCode::Unknown(_)) {
            bail!("account-status reason code `{code}` is not registered in the SDK vocabulary");
        }
    }
    // The fork classification must never collapse into the idempotency
    // conflict the submit operation reserves for `Idempotency-Key` reuse.
    if ReasonCode::ACCOUNT_STATUS_RECORD_FORK == ReasonCode::DUPLICATE_CONFLICT {
        bail!("the account-status fork reason code reuses duplicate_conflict");
    }
    Ok(())
}

fn assert_resolve_operation_is_registered() -> Result<()> {
    let registry = load_artifact_json("registry/operation-registry.json")?;
    let operations = registry
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation registry missing operations[]"))?;
    for (operation_id, http, request_ref, response_ref) in [
        (
            ServiceOperationId::PEER_ACCOUNT_STATUS_COMMAND_SUBMIT_V1,
            "POST /_arkret/peer/account-status",
            "schemas/account-operations.schema.json#/$defs/account_status_publication_request_body",
            "schemas/account-operations.schema.json#/$defs/account_status_publication_outcome",
        ),
        (
            ServiceOperationId::PEER_ACCOUNT_STATUS_READ_RESOLVE_V1,
            "POST /_arkret/peer/account-status/resolve",
            "schemas/account-operations.schema.json#/$defs/account_status_resolve_request_body",
            "schemas/account-operations.schema.json#/$defs/account_status_resolve_outcome",
        ),
    ] {
        let operation = operations
            .iter()
            .find(|row| row.get("operation_id").and_then(Value::as_str) == Some(operation_id))
            .ok_or_else(|| anyhow!("operation registry missing {operation_id}"))?;
        if operation.get("http").and_then(Value::as_str) != Some(http)
            || operation.get("request_schema_ref").and_then(Value::as_str) != Some(request_ref)
            || operation.get("response_schema_ref").and_then(Value::as_str) != Some(response_ref)
        {
            bail!("account-status operation binding drifted for {operation_id}");
        }
    }
    Ok(())
}

/// Compare the driven observations against the fixture branch, and fail on any
/// step-name drift in either direction.
fn compare_against_fixture(observed: &Observations) -> Result<()> {
    let fixture = SecurityClosureFixture::load()?;
    let vector = fixture.vector(VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER)?;

    let mut fixture_steps = BTreeSet::new();
    for step in &vector.steps {
        if !fixture_steps.insert(step.name.as_str()) {
            bail!(
                "{VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER} repeats step `{}`",
                step.name
            );
        }
        if let Some(reason_code) = step.expected.reason_code.as_deref()
            && matches!(ReasonCode::from_wire(reason_code), ReasonCode::Unknown(_))
            && ErrorCode::from_wire(reason_code).is_none()
        {
            bail!(
                "{VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER} step `{}` names unregistered reason \
                 code `{reason_code}`",
                step.name
            );
        }

        let Some(observation) = observed.get(step.name.as_str()) else {
            if TRANSPORT_ONLY_STEPS.contains(&step.name.as_str()) {
                continue;
            }
            bail!(
                "{VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER} step `{}` has no cotest observation",
                step.name
            );
        };
        if observation.outcome != step.expected.outcome {
            bail!(
                "{VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER} step `{}` observed outcome `{}`, fixture \
                 expects `{}`",
                step.name,
                observation.outcome,
                step.expected.outcome
            );
        }
        if let (Some(actual), Some(expected)) = (
            observation.reason_code.as_deref(),
            step.expected.reason_code.as_deref(),
        ) && actual != expected
        {
            bail!(
                "{VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER} step `{}` observed reason `{actual}`, \
                 fixture expects `{expected}`",
                step.name
            );
        }
    }

    for name in observed.keys() {
        if !fixture_steps.contains(name) {
            bail!(
                "{VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER} has no fixture step `{name}`; the cotest \
                 observation is bound to a step the spec no longer publishes"
            );
        }
    }
    for name in TRANSPORT_ONLY_STEPS {
        if !fixture_steps.contains(name) {
            bail!(
                "{VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER} no longer publishes transport-only step \
                 `{name}`"
            );
        }
    }
    Ok(())
}

fn assert_record_carries_no_event_or_seal_carrier(record: &AccountStatusRecord) -> Result<()> {
    let encoded = serde_json::to_value(record)?;
    let mut keys = BTreeSet::new();
    collect_keys(&encoded, &mut keys);
    for forbidden in FORBIDDEN_RECORD_KEYS {
        if keys.contains(*forbidden) {
            bail!(
                "AccountStatusRecord carries `{forbidden}`; account lifecycle has no Event, Seal, \
                 frontier or holder-device carrier"
            );
        }
    }
    Ok(())
}

fn collect_keys(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                out.insert(key.clone());
                collect_keys(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_keys(item, out);
            }
        }
        _ => {}
    }
}

async fn assert_head_is(
    replicas: &dyn AccountStatusReplicaStore,
    expected: &AccountStatusRecord,
) -> Result<()> {
    let account_key = expected.account_id.clone();
    let head = replicas
        .current(expected.account_authority_id.as_str(), &account_key)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "account-status replica has no head for {}",
                expected.account_id
            )
        })?;
    if head.account_status_record_id != expected.account_status_record_id {
        bail!(
            "account-status replica head is {}, expected {}",
            head.account_status_record_id.as_str(),
            expected.account_status_record_id.as_str()
        );
    }
    Ok(())
}

fn public_key(key: &SigningKey) -> PublicKeyMaterial {
    PublicKeyMaterial::Ed25519Raw {
        bytes: key.verifying_key().to_bytes().to_vec(),
    }
}

fn at(second: u32) -> Result<DateTime<Utc>> {
    Ok(format!(
        "2026-08-01T{:02}:{:02}:{:02}.000Z",
        second / 3600,
        (second / 60) % 60,
        second % 60
    )
    .parse()?)
}

fn unsigned(
    account_id: &str,
    status_seq: u64,
    previous_account_status_record_id: Option<AccountStatusRecordId>,
    binding_version: u64,
    status: AccountStatus,
    second: u32,
) -> Result<UnsignedAccountStatusRecord> {
    let issued_at = at(second)?;
    Ok(UnsignedAccountStatusRecord {
        schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
        account_authority_id: DidCoreId::new(AUTHORITY_ID)?,
        account_id: AccountId::new(
            DidCoreId::new(format!("ak:did_core:web:{account_id}.example"))?,
            DidCoreId::new(STATION_ID)?,
        ),
        principal_control_realm_id: RealmId::new(PRINCIPAL_CONTROL_REALM)?,
        binding_version,
        status_seq,
        previous_account_status_record_id,
        status,
        reason_code: None,
        reason: None,
        issued_at,
        effective_at: issued_at,
        expires_at: None,
    })
}

fn receipt_for(
    record: &AccountStatusRecord,
    index: u32,
    receiver_key: &SigningKey,
) -> Result<AccountStatusReceipt> {
    Ok(sign_account_status_receipt(
        UnsignedAccountStatusReceipt {
            receipt_id: ReceiptId::new(format!("ak:receipt:01904100-0000-7000-8000-{index:012x}"))?,
            account_status_record_id: record.account_status_record_id.clone(),
            record_digest: record.payload_digest()?,
            account_authority_id: record.account_authority_id.clone(),
            account_id: record.account_id.clone(),
            status_seq: record.status_seq,
            receiver_id: record.account_id.station_id.clone(),
            accepted_at: at(1000 + index)?,
            verification_method: DidUrl::new(RECEIVER_METHOD).map_err(anyhow::Error::msg)?,
        },
        receiver_key,
    )?)
}
