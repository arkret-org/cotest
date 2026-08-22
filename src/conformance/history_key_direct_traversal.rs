//! Direct history-governance traversal and history-access ratchet checks.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow, bail};
use arkret_models_collaboration::governance::realm_lifecycle::HistoryAccessPayload;
use arkret_models_collaboration::history_key::{
    AuthorizationIncarnation, HistoryGovernanceTraversalIntent,
    HistoryGovernanceTraversalRetention, PeerHistoryTraversalAccess, SelfHistoryTraversalAccess,
    response_capability_commitment,
};
use arkret_state::direct_traversal::{
    BoundedDirectTraversalJournal, DirectCutDescriptorIndex, DirectCutMaterial, DirectCutRequest,
    SealPredecessorDescriptor, discover_direct_cut, verify_direct_traversal_cut_with_registry,
};
use arkret_state::{BottomMode, CellState, LatticeKind, MemoryCellRegistry, compute_state_root};
use arkret_wire::event_envelope::ScopeRef;
use arkret_wire::{
    CellFamilyId, CellRef, DidCoreId, DidFullId, DidUrl, Event, EventKind, Hash, HistoryAccess,
    Hlc, LatticeOp, LatticeOpType, NotarySig, NotarySignerDescriptor, NotaryValue,
    ProjectedCellWrite, ProjectedOp, Proof, RealmId, Seal, SealBasis, SealId, SealSignature,
    null_subject_cell,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

use super::load_artifact_json;
use crate::transcripts::record_vector_event;

pub fn run_history_key_direct_traversal_suite() -> Result<()> {
    let fixture = load_artifact_json("fixtures/history-key-recovery-fixture.json")?;
    let retention: HistoryGovernanceTraversalRetention = serde_json::from_value(
        fixture
            .pointer("/direct_traversal_kat/member_retention")
            .cloned()
            .context("history-key fixture omits member_retention")?,
    )?;
    retention.validate_digest()?;

    let archive_intent: HistoryGovernanceTraversalIntent = serde_json::from_value(
        fixture
            .pointer("/direct_traversal_kat/organization_recovery_intent")
            .cloned()
            .context("history-key fixture omits organization_recovery_intent")?,
    )?;
    archive_intent.validate()?;

    let self_request: SelfHistoryTraversalAccess = serde_json::from_value(json!({
        "kind": "request_receipt",
        "request_receipt_digest": format!("sha256:{}", "11".repeat(32))
    }))?;
    let self_archive: SelfHistoryTraversalAccess = serde_json::from_value(json!({
        "kind": "archive_replica",
        "archive_replica_digest": format!("sha256:{}", "22".repeat(32))
    }))?;
    let peer_archive: PeerHistoryTraversalAccess = serde_json::from_value(json!({
        "kind": "pending_archive_replica",
        "pending_archive_replica_digest": format!("sha256:{}", "33".repeat(32))
    }))?;
    for access in [
        serde_json::to_value(self_request)?,
        serde_json::to_value(self_archive)?,
        serde_json::to_value(peer_archive)?,
    ] {
        if access.get("kind").and_then(Value::as_str).is_none() {
            bail!("history traversal access lost its closed branch discriminator");
        }
    }

    let negative_cases = fixture
        .pointer("/direct_traversal_kat/negative_cases")
        .and_then(Value::as_array)
        .context("history-key fixture omits direct traversal negative cases")?;
    verify_direct_cut_graph_mutations(
        fixture
            .pointer("/direct_traversal_kat/direct_cut")
            .context("history-key fixture omits direct_cut")?,
        negative_cases,
    )?;
    verify_since_join_lineage(
        fixture
            .pointer("/direct_traversal_kat/since_join_lineage")
            .context("history-key fixture omits since_join_lineage")?,
    )?;
    verify_direct_traversal_replay_kat(
        fixture
            .pointer("/direct_traversal_replay_kat")
            .context("history-key fixture omits direct_traversal_replay_kat")?,
    )?;

    HistoryAccessPayload::initialize(HistoryAccess::AllHistoryForCurrentMembers).validate()?;
    HistoryAccessPayload::tighten().validate()?;
    HistoryAccessPayload {
        from: Some(HistoryAccess::SinceJoin),
        to: HistoryAccess::AllHistoryForCurrentMembers,
        reason: None,
    }
    .validate()
    .expect_err("history access widening must fail closed");

    let capability_kat = fixture
        .pointer("/history_response_capability_kat")
        .context("history-key fixture omits history response capability KAT")?;
    let capability = capability_kat["response_capability_b64u"]
        .as_str()
        .context("history response capability KAT omits capability")?;
    if capability_kat["decoded_length"].as_u64() != Some(32)
        || response_capability_commitment(capability)?.as_ref()
            != capability_kat["expected_response_capability_commitment"]
                .as_str()
                .context("history response capability KAT omits commitment")?
        || capability_kat
            .pointer("/surface/read")
            .and_then(Value::as_str)
            != Some("POST /_arkret/self/history-key-responses/read")
        || capability_kat
            .pointer("/surface/ack")
            .and_then(Value::as_str)
            != Some("POST /_arkret/self/history-key-responses/ack")
        || capability_kat
            .pointer("/surface/request_locator_in_path_query_or_body")
            .and_then(Value::as_bool)
            != Some(false)
    {
        bail!("history response capability KAT drifted");
    }
    let capability_negative_cases = capability_kat["negative_cases"]
        .as_array()
        .context("history response capability KAT omits negative cases")?;
    for required in [
        "unknown_expired_gc_and_unauthorized_same_not_found_shape",
        "stream_a_capability_cannot_read_or_ack_stream_b",
        "stream_a_capability_cannot_consume_stream_b_ack_token",
        "commitment_collision_resampled_before_any_durable_write",
        "exact_create_retry_returns_byte_identical_sealed_capability",
    ] {
        if !capability_negative_cases
            .iter()
            .any(|case| case.as_str() == Some(required))
        {
            bail!("history response capability KAT omits {required}");
        }
    }

    let scale_cases = fixture
        .pointer("/streaming_direct_traversal_scale_kats")
        .and_then(Value::as_array)
        .context("history-key fixture omits streaming scale KATs")?;
    let expected_scale = [
        (
            26_298_u64,
            26_299_u64,
            7_416_182_u64,
            "sha256:c702bba991ec05314014566a763db2c99aeecba920b02fb58cbd0347277aed45",
        ),
        (
            65_536_u64,
            65_537_u64,
            18_481_298_u64,
            "sha256:1d1377c13c8b58b688f887be4d7df282b12aa0597424360d57b74fd06e78da19",
        ),
    ];
    for (epoch_count, seal_count, descriptor_bytes, aggregate_digest) in expected_scale {
        let case = scale_cases
            .iter()
            .find(|case| case["epoch_count"].as_u64() == Some(epoch_count))
            .with_context(|| format!("history scale fixture omits {epoch_count} epochs"))?;
        if case["verified_epoch_count"].as_u64() != Some(epoch_count)
            || case["resolved_control_event_count"].as_u64() != Some(epoch_count)
            || case["resolved_availability_receipt_count"].as_u64() != Some(epoch_count)
            || case["visited_seal_count"].as_u64() != Some(seal_count)
            || case["max_live_descriptor_bytes"].as_u64() != Some(282)
            || case["descriptor_canonical_bytes"].as_u64() != Some(descriptor_bytes)
            || case["descriptor_stream_aggregate_digest"].as_str() != Some(aggregate_digest)
            || case["outbox_write_count"].as_u64() != Some(0)
        {
            bail!("history scale fixture drifted at {epoch_count} epochs");
        }
    }
    let over_limit = fixture
        .pointer("/streaming_direct_traversal_scale_negative_kats/0")
        .context("history-key fixture omits 65,537-epoch prewrite rejection")?;
    if over_limit["epoch_count"].as_u64() != Some(65_537)
        || over_limit["rejected_before_staging"].as_bool() != Some(true)
        || over_limit["journal_rows"].as_u64() != Some(0)
        || over_limit["resolved_objects"].as_u64() != Some(0)
        || over_limit["outbox_writes"].as_u64() != Some(0)
    {
        bail!("history 65,537-epoch prewrite rejection drifted");
    }

    record_vector_event(
        "history_key.direct_traversal",
        &json!({"fixture": "history-key-recovery-fixture.json"}),
        &json!({
            "member_intent_digest_valid": true,
            "organization_recovery_intent_valid": true,
            "closed_access_branches_valid": true,
            "closed_cut_negative_cases_valid": true,
            "since_join_lineage_valid": true,
            "direct_traversal_replay_kat_valid": true,
            "history_access_widening_rejected": true,
            "response_capability_kat_valid": true,
            "streaming_scale_kats_valid": true,
        }),
        &json!({"status": "validated"}),
    );
    Ok(())
}

const REPLAY_KAT_CREATED_AT: &str = "2026-08-22T12:00:00Z";

struct ReplayKatMaterial {
    request: DirectCutRequest,
    historical_descriptor: NotarySignerDescriptor,
    current_descriptor: NotarySignerDescriptor,
    genesis_event: Event,
    successor_event: Event,
    genesis_seal: Seal,
    successor_seal: Seal,
    current_seed: [u8; 32],
}

fn replay_kat_seed(value: &Value, pointer: &str) -> Result<[u8; 32]> {
    let encoded = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .with_context(|| format!("replay KAT omits {pointer}"))?;
    URL_SAFE_NO_PAD
        .decode(encoded)
        .context("replay KAT seed is not canonical base64url")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("replay KAT seed is {} bytes, expected 32", bytes.len()))
}

fn replay_kat_cell(family: &str) -> Result<CellRef> {
    Ok(CellRef::new(null_subject_cell(family))?)
}

fn replay_kat_set(cell: CellRef, value: Value) -> ProjectedCellWrite {
    let mut op = LatticeOp::empty();
    op.op_type = LatticeOpType::Set;
    op.value = Some(value);
    ProjectedCellWrite {
        cell,
        op: ProjectedOp::Direct(op),
    }
}

fn replay_kat_projection(
    event: &Event,
    _suite: arkret_canonical::DigestSuite,
) -> std::result::Result<Vec<ProjectedCellWrite>, String> {
    if event.kind != EventKind::RealmCreate {
        return Ok(Vec::new());
    }
    let notary = event
        .payload
        .get("object")
        .and_then(|object| object.get("notary"))
        .cloned()
        .ok_or_else(|| "replay KAT Genesis omits notary".to_owned())?;
    Ok(vec![
        replay_kat_set(
            replay_kat_cell(CellFamilyId::NOTARY_V1).map_err(|error| error.to_string())?,
            notary,
        ),
        replay_kat_set(
            replay_kat_cell(CellFamilyId::REALM_DIGEST_SUITE_V1)
                .map_err(|error| error.to_string())?,
            json!("sha256"),
        ),
    ])
}

fn attach_replay_kat_proof(event: &mut Event, verification_method: &DidUrl) -> Result<()> {
    let event_digest =
        Hash::new(event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?)?;
    let signer_evidence_digest = Hash::new(format!("sha256:{}", "91".repeat(32)))?;
    event.proofs = vec![Proof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        event_digest,
        signer_resolution_evidence_ref: Some(arkret_wire::SignerEvidenceRef::new(format!(
            "ak:signer_evidence:{}",
            signer_evidence_digest.as_str()
        ))?),
        signer_resolution_evidence_digest: Some(signer_evidence_digest),
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZDI1NTE5In0..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
    }
    .into()];
    Ok(())
}

fn sign_replay_kat_seal(seal: &mut Seal, seed: [u8; 32], method: &DidUrl) -> Result<()> {
    let body = seal.canonical_bytes_for_id()?;
    seal.id = Seal::id_from_canonical_bytes(&body, arkret_canonical::DigestSuite::Sha256)?;
    let protected = arkret_canonical::canonical::canonical_json_bytes(&json!({
        "alg": "Ed25519",
        "kid": method,
    }))?;
    let protected = URL_SAFE_NO_PAD.encode(protected);
    let signing_input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(&body));
    let signature = SigningKey::from_bytes(&seed).sign(signing_input.as_bytes());
    seal.notary_signature = NotarySig::Single(SealSignature {
        verification_method: method.clone(),
        payload_digest: Hash::new(arkret_canonical::digest(
            arkret_canonical::DigestSuite::Sha256,
            &body,
        ))?,
        jws: format!(
            "{protected}..{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
    });
    Ok(())
}

fn replay_kat_seal(
    realm_id: RealmId,
    predecessor_refs: Vec<SealId>,
    delta: Vec<Hash>,
    covered_events: &[(Event, arkret_canonical::DigestSuite)],
    state_root: Hash,
    notary_seq: u64,
    seed: [u8; 32],
    method: &DidUrl,
) -> Result<Seal> {
    let covered = covered_events
        .iter()
        .map(|(event, suite)| Ok(Hash::new(event.event_digest_with_digest_suite(*suite)?)?))
        .collect::<Result<BTreeSet<_>>>()?;
    let control_event_set_root =
        arkret_state::control_event_set_root(&covered, arkret_canonical::DigestSuite::Sha256)?;
    let completeness_root = arkret_state::control_event_completeness_root(
        covered_events,
        &covered,
        arkret_canonical::DigestSuite::Sha256,
    )?;
    let placeholder = Hash::new(format!("sha256:{}", "00".repeat(32)))?;
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))?,
        realm_id,
        predecessor_refs,
        delta,
        control_event_set_root,
        state_root,
        completeness_root,
        notary_seq,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: covered.into_iter().collect(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(SealSignature {
            verification_method: method.clone(),
            payload_digest: placeholder,
            jws: "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYjpyZXBsYXkta2F0LmV4YW1wbGUjbm90YXJ5LWtleS0xIn0..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        }),
        sealed_at: REPLAY_KAT_CREATED_AT.parse()?,
        hlc: Hlc::new("0198d35d9800-0000-a13f9c2e")?,
    };
    sign_replay_kat_seal(&mut seal, seed, method)?;
    Ok(seal)
}

fn build_replay_kat_material(kat: &Value) -> Result<ReplayKatMaterial> {
    let signing = kat
        .get("signing_inputs")
        .context("replay KAT omits signing_inputs")?;
    let historical_descriptor: NotarySignerDescriptor =
        serde_json::from_value(signing["historical_descriptor"].clone())?;
    let current_descriptor: NotarySignerDescriptor =
        serde_json::from_value(signing["current_same_method_descriptor"].clone())?;
    historical_descriptor.validate()?;
    current_descriptor.validate()?;
    if historical_descriptor.verification_method != current_descriptor.verification_method
        || historical_descriptor.frozen_public_key_b64u == current_descriptor.frozen_public_key_b64u
    {
        bail!("replay KAT must use one method id with two different keys");
    }
    let historical_seed = replay_kat_seed(kat, "/signing_inputs/historical_seed_b64u")?;
    let current_seed = replay_kat_seed(kat, "/signing_inputs/current_seed_b64u")?;
    let historical_key = SigningKey::from_bytes(&historical_seed).verifying_key();
    let current_key = SigningKey::from_bytes(&current_seed).verifying_key();
    if URL_SAFE_NO_PAD.encode(historical_key.to_bytes())
        != historical_descriptor.frozen_public_key_b64u
        || URL_SAFE_NO_PAD.encode(current_key.to_bytes())
            != current_descriptor.frozen_public_key_b64u
    {
        bail!("replay KAT seed does not derive its frozen public key");
    }

    let actor_full_id = DidFullId::new(
        signing["actor_full_id"]
            .as_str()
            .context("replay KAT omits actor_full_id")?
            .to_owned(),
    )?;
    let actor_id = DidCoreId::new(
        signing["actor_id"]
            .as_str()
            .context("replay KAT omits actor_id")?
            .to_owned(),
    )?;
    let method = historical_descriptor.verification_method.clone();
    let notary = NotaryValue::single_signer(historical_descriptor.clone());
    let created_at = DateTime::parse_from_rfc3339(REPLAY_KAT_CREATED_AT)?.with_timezone(&Utc);
    let mut genesis_event = arkret_wire::test_support::raw_event_at(
        EventKind::RealmCreate.to_string(),
        ScopeRef::RealmGenesis,
        actor_id.clone(),
        actor_id.clone(),
        0,
        Hlc::new("0198d35d9800-0000-a13f9c2e")?,
        json!({"object": {"digest_algorithm": "sha256", "notary": notary}}),
        created_at,
    )?;
    attach_replay_kat_proof(&mut genesis_event, &method)?;
    let realm_id = genesis_event.realm_id.clone();

    let notary_cell = replay_kat_cell(CellFamilyId::NOTARY_V1)?;
    let digest_suite_cell = replay_kat_cell(CellFamilyId::REALM_DIGEST_SUITE_V1)?;
    let state = BTreeMap::from([
        (
            notary_cell,
            CellState::Value(serde_json::to_value(&notary)?),
        ),
        (digest_suite_cell, CellState::Value(json!("sha256"))),
    ]);
    let state_root = compute_state_root(&state, arkret_canonical::DigestSuite::Sha256)?;
    let genesis_digest = Hash::new(
        genesis_event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
    )?;
    let genesis_seal = replay_kat_seal(
        realm_id.clone(),
        Vec::new(),
        vec![genesis_digest],
        &[(genesis_event.clone(), arkret_canonical::DigestSuite::Sha256)],
        state_root.clone(),
        0,
        historical_seed,
        &method,
    )?;

    let mut successor_event = arkret_wire::test_support::raw_event_at(
        EventKind::PolicySet.to_string(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id.clone(),
        actor_id,
        1,
        Hlc::new("0198d35d9800-0001-a13f9c2e")?,
        json!({"variant": "successor"}),
        created_at,
    )?;
    successor_event.prev_refs = vec![genesis_event.event_id.clone()];
    successor_event.seal_basis = Some(SealBasis {
        leaves: vec![genesis_seal.id.clone()],
    });
    successor_event
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    attach_replay_kat_proof(&mut successor_event, &method)?;
    let successor_digest = Hash::new(
        successor_event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
    )?;
    let successor_seal = replay_kat_seal(
        realm_id.clone(),
        vec![genesis_seal.id.clone()],
        vec![successor_digest],
        &[
            (genesis_event.clone(), arkret_canonical::DigestSuite::Sha256),
            (
                successor_event.clone(),
                arkret_canonical::DigestSuite::Sha256,
            ),
        ],
        state_root,
        1,
        historical_seed,
        &method,
    )?;
    let request = DirectCutRequest {
        realm_id,
        trusted_history_base_basis: SealBasis {
            leaves: vec![genesis_seal.id.clone()],
        },
        trusted_current_basis: SealBasis {
            leaves: vec![genesis_seal.id.clone()],
        },
        target_basis: SealBasis {
            leaves: vec![successor_seal.id.clone()],
        },
    };
    if actor_full_id.as_str()
        != method
            .as_str()
            .split_once('#')
            .map(|pair| pair.0)
            .unwrap_or("")
    {
        bail!("replay KAT method controller drifted from actor_full_id");
    }
    Ok(ReplayKatMaterial {
        request,
        historical_descriptor,
        current_descriptor,
        genesis_event,
        successor_event,
        genesis_seal,
        successor_seal,
        current_seed,
    })
}

fn replay_registry() -> MemoryCellRegistry {
    let mut registry = MemoryCellRegistry::empty();
    registry.register(
        CellFamilyId::NOTARY_V1,
        LatticeKind::CasRegister,
        BottomMode::Reject,
    );
    registry.register(
        CellFamilyId::REALM_DIGEST_SUITE_V1,
        LatticeKind::CasRegister,
        BottomMode::Reject,
    );
    registry
}

fn verify_direct_traversal_replay_kat(kat: &Value) -> Result<()> {
    let material = build_replay_kat_material(kat)?;
    let source = DirectCutMaterial::new(
        [
            material.genesis_seal.clone(),
            material.successor_seal.clone(),
        ],
        [
            material.genesis_event.clone(),
            material.successor_event.clone(),
        ]
        .into_iter()
        .map(|event| {
            Ok((
                Hash::new(
                    event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
                )?,
                event,
            ))
        })
        .collect::<Result<Vec<_>>>()?,
    )?;
    let mut replayed = 0_u64;
    let mut committed_successors = 0_u64;
    let verified = verify_direct_traversal_cut_with_registry(
        &material.request,
        &source,
        &mut BoundedDirectTraversalJournal::default(),
        &[],
        &replay_registry(),
        arkret_signatures::verify_frozen_notary_signature,
        |_event, _suite, _dependencies| Ok(()),
        |_seal, _notary, _context, _dependencies| Ok(()),
        replay_kat_projection,
        &mut |seal, _delta| {
            replayed += 1;
            if !seal.predecessor_refs.is_empty() {
                committed_successors += 1;
            }
            Ok(())
        },
    )?;
    if replayed != 2 || committed_successors != 1 {
        bail!(
            "historical-key positive replay committed {replayed} Seals/{committed_successors} successors"
        );
    }
    let notary_cell = replay_kat_cell(CellFamilyId::NOTARY_V1)?;
    let expected_notary = serde_json::to_value(NotaryValue::single_signer(
        material.historical_descriptor.clone(),
    ))?;
    if verified.effective_state.get(&notary_cell) != Some(&CellState::Value(expected_notary)) {
        bail!("positive replay did not derive the historical notary from Genesis state");
    }

    let ambiguous = kat["cases"]
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["name"] == "ambiguous_delta_resolver_response")
        })
        .context("replay KAT omits ambiguous_delta_resolver_response")?;
    let claimed = Hash::new(
        ambiguous["injection"]["claimed_digest"]
            .as_str()
            .context("ambiguous replay KAT omits claimed_digest")?,
    )?;
    let variant_a = material.successor_event.clone();
    let mut variant_b = variant_a.clone();
    variant_b.payload.insert("variant".to_owned(), json!("b"));
    let ambiguous_replayed = 0_u64;
    let error = DirectCutMaterial::new(
        Vec::<Seal>::new(),
        [(claimed.clone(), variant_a), (claimed, variant_b)],
    )
    .expect_err("ambiguous material must be rejected before replay");
    if !error
        .to_string()
        .contains("ambiguous direct traversal material")
        || ambiguous_replayed != 0
    {
        bail!("ambiguous material did not reject at ingestion with zero replay: {error}");
    }

    let mut substituted_successor = material.successor_seal.clone();
    sign_replay_kat_seal(
        &mut substituted_successor,
        material.current_seed,
        &material.current_descriptor.verification_method,
    )?;
    if substituted_successor.id != material.successor_seal.id {
        bail!("changing only a Seal signature changed the Seal id");
    }
    let substituted_source =
        DirectCutMaterial::new(
            [material.genesis_seal, substituted_successor],
            [material.genesis_event, material.successor_event]
                .into_iter()
                .map(|event| {
                    Ok((
                        Hash::new(event.event_digest_with_digest_suite(
                            arkret_canonical::DigestSuite::Sha256,
                        )?)?,
                        event,
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        )?;
    let mut substituted_replayed = 0_u64;
    let mut substituted_successors = 0_u64;
    let error = verify_direct_traversal_cut_with_registry(
        &material.request,
        &substituted_source,
        &mut BoundedDirectTraversalJournal::default(),
        &[],
        &replay_registry(),
        arkret_signatures::verify_frozen_notary_signature,
        |_event, _suite, _dependencies| Ok(()),
        |_seal, _notary, _context, _dependencies| Ok(()),
        replay_kat_projection,
        &mut |seal, _delta| {
            substituted_replayed += 1;
            if !seal.predecessor_refs.is_empty() {
                substituted_successors += 1;
            }
            Ok(())
        },
    )
    .expect_err("current same-method key must not verify a historical successor Seal");
    if substituted_replayed != 1
        || substituted_successors != 0
        || !error.to_string().contains("signature verification failed")
    {
        bail!(
            "current-key substitution did not fail after predecessor-only replay: replayed={substituted_replayed}, successors={substituted_successors}, error={error}"
        );
    }
    Ok(())
}

/// Fixture-declared reverse-traversal descriptor.
#[derive(Clone, Debug)]
struct DirectCutSeal {
    seal_ref: String,
    predecessor_refs: Vec<String>,
}

impl DirectCutSeal {
    fn into_descriptor(self) -> Result<SealPredecessorDescriptor> {
        Ok(SealPredecessorDescriptor {
            seal_ref: SealId::new(self.seal_ref)?,
            predecessor_refs: self
                .predecessor_refs
                .into_iter()
                .map(|value| Ok(SealId::new(value)?))
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

const UNREACHABLE_SEAL_REF: &str =
    "ak:seal:sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

const TRAVERSAL_REALM_ID: &str = "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN";

fn seal_basis(leaves: &[String]) -> Result<SealBasis> {
    let mut leaves = leaves
        .iter()
        .map(|value| Ok(SealId::new(value.clone())?))
        .collect::<Result<Vec<_>>>()?;
    leaves.sort();
    let basis = SealBasis { leaves };
    basis.validate_protocol_bounds()?;
    Ok(basis)
}

/// Run one cut through the SDK verifier and return its canonical error names.
fn cut_errors(
    base: &[String],
    current: &[String],
    target: &[String],
    seals: &[DirectCutSeal],
) -> Result<BTreeSet<String>> {
    let request = DirectCutRequest {
        realm_id: RealmId::new(TRAVERSAL_REALM_ID)?,
        trusted_history_base_basis: seal_basis(base)?,
        trusted_current_basis: seal_basis(current)?,
        target_basis: seal_basis(target)?,
    };
    let source = DirectCutDescriptorIndex::new(
        seals
            .iter()
            .cloned()
            .map(DirectCutSeal::into_descriptor)
            .collect::<Result<Vec<_>>>()?,
    )?;
    let mut journal = BoundedDirectTraversalJournal::default();
    Ok(discover_direct_cut(&request, &source, &mut journal)?
        .error_names()
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// Drive the SDK direct-traversal verifier against the fixture's canonical cut
/// and its five declared negative mutations. The assertion is equality with each
/// case's complete `actual_errors` set, not mere containment, so a verifier that
/// over- or under-reports fails here.
fn verify_direct_cut_graph_mutations(cut: &Value, negative_cases: &[Value]) -> Result<()> {
    let basis = |name: &str| -> Result<Vec<String>> {
        cut.pointer(&format!("/{name}/leaves"))
            .and_then(Value::as_array)
            .with_context(|| format!("direct cut omits {name}.leaves"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("direct cut {name} leaf is not text"))
            })
            .collect()
    };
    let base = basis("trusted_history_base_basis")?;
    let current = basis("trusted_current_basis")?;
    let target = basis("target_basis")?;
    let seals = cut
        .get("seals")
        .and_then(Value::as_array)
        .context("direct cut omits seals[]")?
        .iter()
        .map(|value| {
            Ok(DirectCutSeal {
                seal_ref: value["seal_ref"]
                    .as_str()
                    .context("direct cut seal_ref is not text")?
                    .to_owned(),
                predecessor_refs: value["predecessor_refs"]
                    .as_array()
                    .context("direct cut predecessor_refs is not an array")?
                    .iter()
                    .map(|predecessor| {
                        predecessor
                            .as_str()
                            .map(str::to_owned)
                            .context("direct cut predecessor ref is not text")
                    })
                    .collect::<Result<Vec<_>>>()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if !cut_errors(&base, &current, &target, &seals)?.is_empty() {
        bail!("canonical direct cut does not satisfy its closed interval");
    }

    let hidden_ref = current
        .first()
        .context("direct cut lacks a first current leaf")?
        .clone();

    // The responder simply omits one interval descriptor while its successor
    // still points at it.
    let mut hidden_predecessor = seals.clone();
    hidden_predecessor.retain(|seal| seal.seal_ref != hidden_ref);

    // The same branch is additionally truncated, so the surviving successor is
    // predecessor-free without being a base leaf.
    let mut branch_stops_before_base = hidden_predecessor.clone();
    for seal in &mut branch_stops_before_base {
        seal.predecessor_refs.retain(|value| *value != hidden_ref);
    }

    let mut extended_base = base.clone();
    extended_base.push(UNREACHABLE_SEAL_REF.to_owned());

    let mut surplus = seals.clone();
    surplus.push(DirectCutSeal {
        seal_ref: UNREACHABLE_SEAL_REF.to_owned(),
        predecessor_refs: Vec::new(),
    });

    let disjoint_current = vec![UNREACHABLE_SEAL_REF.to_owned()];

    let mutations: [(&str, &[String], &[String], &[String], &[DirectCutSeal]); 5] = [
        (
            "hidden_predecessor",
            &base,
            &current,
            &target,
            &hidden_predecessor,
        ),
        (
            "target_does_not_dominate_current",
            &base,
            &disjoint_current,
            &target,
            &seals,
        ),
        (
            "branch_stops_before_base",
            &base,
            &current,
            &target,
            &branch_stops_before_base,
        ),
        (
            "base_leaf_not_consumed",
            &extended_base,
            &current,
            &target,
            &seals,
        ),
        ("surplus_descriptor", &base, &current, &target, &surplus),
    ];
    for (name, base, current, target, seals) in mutations {
        let case = negative_cases
            .iter()
            .find(|case| case["name"].as_str() == Some(name))
            .with_context(|| format!("history traversal fixture omits {name}"))?;
        let expected_error = case["expected_error"]
            .as_str()
            .with_context(|| format!("history traversal case {name} omits expected_error"))?;
        let expected_errors = case["actual_errors"]
            .as_array()
            .with_context(|| format!("history traversal case {name} omits actual_errors"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("history traversal case {name} error is not text"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let observed = cut_errors(base, current, target, seals)?;
        if observed != expected_errors {
            bail!(
                "SDK direct traversal for {name} produced {observed:?}, fixture declares {expected_errors:?}"
            );
        }
        if !observed.contains(expected_error) {
            bail!("SDK direct traversal for {name} did not produce {expected_error}");
        }
    }
    Ok(())
}

/// Check the fixture's `since_join` lineage against the only two admissible
/// `join_epoch` sources: the winning Commit that consumes the exact Add, and a
/// proven Genesis initial leaf. Local clocks and current epoch stay forbidden.
fn verify_since_join_lineage(lineage: &Value) -> Result<()> {
    let incarnation: AuthorizationIncarnation =
        serde_json::from_value(lineage["add_target_authorization_incarnation"].clone())?;
    let AuthorizationIncarnation::Realm {
        realm_membership_incarnation_ref,
    } = &incarnation
    else {
        bail!("since_join lineage fixture is not a Realm incarnation");
    };
    if lineage["membership_incarnation_ref"].as_str()
        != Some(realm_membership_incarnation_ref.as_str())
    {
        bail!("since_join lineage incarnation refs disagree");
    }
    let expected = lineage["expected_join_epoch"]
        .as_u64()
        .context("since_join lineage omits expected_join_epoch")?;
    if lineage["winning_commit_next_epoch"].as_u64() != Some(expected) {
        bail!("since_join lineage expected_join_epoch is not the winning Commit next_epoch");
    }
    let winning_commit_ref = lineage["winning_commit_ref"]
        .as_str()
        .context("since_join lineage omits winning_commit_ref")?;
    let add_proposal_ref = lineage["add_proposal_ref"]
        .as_str()
        .context("since_join lineage omits add_proposal_ref")?;
    if winning_commit_ref == add_proposal_ref
        || !lineage["winning_commit_proposal_refs"]
            .as_array()
            .context("since_join lineage omits winning_commit_proposal_refs")?
            .iter()
            .any(|value| value.as_str() == Some(add_proposal_ref))
    {
        bail!("since_join lineage winning Commit does not consume the exact Add proposal");
    }
    for forbidden in lineage["forbidden_derivations"]
        .as_array()
        .context("since_join lineage omits forbidden_derivations")?
    {
        let forbidden = forbidden
            .as_str()
            .context("since_join forbidden derivation is not text")?;
        if !matches!(
            forbidden,
            "joined_at" | "received_at" | "latest_epoch" | "current_session_device"
        ) {
            bail!("since_join lineage declares an unknown forbidden derivation {forbidden}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_traversal_suite_uses_the_shared_wire_types() {
        run_history_key_direct_traversal_suite().unwrap();
    }
}
