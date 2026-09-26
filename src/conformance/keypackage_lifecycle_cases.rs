//! Per-case execution of `ak.suite.crypto.keypackage_lifecycle.v1`.
//!
//! Every fixture case runs here and returns the number of assertions it
//! executed. Client-side and wire-side checks go through the SDK: the
//! capability extension codec and signed-LeafNode binding, real RFC 9420
//! KeyPackages built under a device key, the claim authorization transcript,
//! the recipient durable receipt and consume signing, Welcome consumption
//! against an accepted Commit, the registered ciphersuite table and the
//! endpoint KeyPackage KATs. Authority-side ledger semantics (CAS, exact replay,
//! conflicting reuse, anti-enumeration) run against a Station claim ledger
//! model here and against the real Soland in the live `keypackage_lifecycle`
//! test (`scenarios::mls_lifecycle_live`).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret::{ArkretMlsGroup, ArkretMlsIdentity, ArkretMlsSigner};
use arkret_models_crypto::keypackage_capabilities::{
    ACTIVE_KEYPACKAGE_CAPABILITIES, MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE,
    MLS_REQUIRED_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE, REQUIRED_ARKRET_GROUP_CAPABILITIES,
    decode_keypackage_capability_extension, is_active_keypackage_capability,
    validate_advertised_keypackage_capabilities, validate_required_keypackage_capabilities,
};
use arkret_wire::{AccountId, ActorId, EventId, MlsWelcomeDelivery, ScopeRef};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use serde_json::{Value, json};

use super::super::fixture_dsl::{required_array, string_vec};
use super::super::suite_execution::{CaseExecutionResult, SuiteExecutionResult};
use super::*;

const ACTIVE_SUITE: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
const STATION: &str = "ak:did_core:web:keypackage-suite-station.example";
const FIXTURE_REALM: &str = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";

/// Run every case of the fixture in declaration order.
pub fn run_keypackage_lifecycle_suite() -> Result<SuiteExecutionResult> {
    let fixture = keypackage_fixture()?;
    let mut results = Vec::with_capacity(fixture.cases.len());
    for case in &fixture.cases {
        let name = required_str(case, "name")?;
        let kind = required_str(case, "kind")?;
        let mut tally = Tally::default();
        match (name, kind) {
            ("group_capability_floor", "mls_leaf_and_group_context_capability_floor") => {
                group_capability_floor_case(case, &mut tally)
            }
            ("exhaustion_claim_limits", "claim_pool_limits") => {
                exhaustion_claim_limits_case(case, &mut tally)
            }
            ("last_resort_claim_and_reuse", "last_resort_claim_reuse") => {
                last_resort_claim_and_reuse_case(case, &mut tally)
            }
            ("last_resort_forced_rotation", "last_resort_rotation") => {
                last_resort_forced_rotation_case(case, &mut tally)
            }
            ("last_resort_affinity_and_optionality", "last_resort_affinity_optionality") => {
                last_resort_affinity_and_optionality_case(case, &mut tally)
            }
            ("peer_claim_atomic_idempotency", "peer_claim_linearization_and_recovery") => {
                peer_claim_atomic_idempotency_case(case, &mut tally)
            }
            (
                "self_claim_authorization_idempotency",
                "unified_local_claim_authorization_and_linearization",
            ) => self_claim_authorization_idempotency_case(&fixture, case, &mut tally)
                .and_then(|()| self_claim_conflict_ledger(case, &mut tally)),
            (
                "peer_claim_double_authorization_privacy",
                "peer_claim_authorization_and_anti_enumeration",
            ) => peer_claim_double_authorization_privacy_case(case, &mut tally),
            ("welcome_keypackage_hash", "welcome_delivery_claim_ledger_binding") => {
                welcome_keypackage_hash_case(&fixture, case, &mut tally)
            }
            ("welcome_capabilities_digest_mismatch", "welcome_claimed_leaf_capability_binding") => {
                welcome_capabilities_digest_mismatch_case(case, &mut tally)
            }
            (EXPIRY_SECURITY_CASE_NAME, EXPIRY_SECURITY_CASE_KIND) => {
                last_resort_expiry_security_case(&fixture, case, &mut tally)
            }
            (
                "peer_claim_response_verification_before_install",
                "peer_claim_requester_side_response_verification",
            ) => peer_claim_response_verification_case(case, &mut tally),
            (
                "welcome_add_commit_and_claim_record_binding",
                "welcome_accepted_lineage_and_claim_record_binding",
            ) => welcome_add_commit_and_claim_record_binding_case(case, &mut tally),
            ("welcome_consume_only_after_durable_group_state", "welcome_consume_ordering") => {
                welcome_consume_ordering_case(case, &mut tally)
            }
            (
                "mls_keypackage_actor_and_ciphersuite_closure",
                "keypackage_actor_and_ciphersuite_policy",
            ) => keypackage_actor_and_ciphersuite_closure_case(case, &mut tally),
            (other, kind) => bail!("keypackage lifecycle case {other} ({kind}) has no runner"),
        }
        .with_context(|| format!("keypackage lifecycle case {name}"))?;
        results.push(CaseExecutionResult {
            case_id: name.to_owned(),
            assertions: tally.count(),
        });
    }
    Ok(SuiteExecutionResult {
        entrypoint: KEYPACKAGE_LIFECYCLE_ENTRYPOINT,
        fixture: KEYPACKAGE_LIFECYCLE_FIXTURE_FILE,
        cases: results,
    })
}

// ---------------------------------------------------------------------------
// Real MLS material
// ---------------------------------------------------------------------------

/// A device endpoint whose LeafNode key is its authorized device key and
/// whose BasicCredential is the complete ActorId.
struct Endpoint {
    actor: ActorId,
    device: arkret_wire::DeviceId,
    key: SigningKey,
}

impl Endpoint {
    fn new(principal: &str, device: &str, seed: u8) -> Result<Self> {
        Ok(Self {
            actor: ActorId::account(AccountId::new(
                arkret_wire::DidCoreId::new(principal.to_owned())?,
                arkret_wire::DidCoreId::new(STATION.to_owned())?,
            )),
            device: arkret_wire::DeviceId::new(device.to_owned())?,
            key: SigningKey::from_bytes(&[seed; 32]),
        })
    }

    fn identity(&self) -> Result<ArkretMlsIdentity> {
        Ok(ArkretMlsIdentity::new_human_device(
            self.actor.clone(),
            self.device.clone(),
            ArkretMlsSigner::from_ed25519_signing_key(self.key.clone()),
        )?)
    }

    fn method(&self) -> Result<arkret_wire::DidUrl> {
        arkret_wire::DidUrl::new(format!(
            "did:web:{}#{}",
            self.actor
                .signing_principal_id()
                .as_str()
                .trim_start_matches("ak:did_core:web:"),
            self.device.as_str()
        ))
        .map_err(|error| anyhow!(error))
    }
}

fn keypackage_bytes(record: &arkret::MlsKeyPackageRecord) -> Result<Vec<u8>> {
    Ok(arkret_canonical::base64url_decode(&record.keypackage)?)
}

fn realm_scope() -> Result<ScopeRef> {
    Ok(ScopeRef::Realm {
        realm_id: arkret_wire::RealmId::new(FIXTURE_REALM.to_owned())?,
    })
}

fn fixed_signature(
    context: arkret_wire::DetachedSignatureContext,
    seed: u8,
) -> Result<arkret_wire::DetachedObjectSignature> {
    Ok(arkret_wire::DetachedObjectSignature {
        context,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: arkret_wire::DidUrl::new(
            "did:web:keypackage-suite-station.example#key-1".to_owned(),
        )
        .map_err(|error| anyhow!(error))?,
        signed_digest: arkret_wire::Hash::new(format!(
            "sha256:{}",
            format!("{seed:02x}").repeat(32)
        ))?,
        created_at: arkret_canonical::parse_timestamp_canonical("2026-09-26T00:00:00.000Z")?,
        sig: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([seed; 64]))
            .map_err(|error| anyhow!(error))?,
    })
}

/// The accepted `ak.mls.commit` Event carrying `envelope` with its
/// RealmCommit on `stream_scope`'s independent stream.
fn accepted_commit(
    scope: &ScopeRef,
    stream_scope: &ScopeRef,
    author: &ActorId,
    base: &EventId,
    envelope: &arkret::MlsCommitEnvelope,
    seed: u8,
) -> Result<arkret_wire::CommittedEventFullView> {
    let binding = arkret::MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(base.clone()),
        envelope.epoch - 1,
        envelope.epoch,
        0,
    )?;
    let payload = arkret::MlsCommitPayload::new(base.clone(), 0, envelope, binding)?;
    let event = arkret::TypedEventDraft::<arkret::event_spec::MlsCommit>::new(
        scope.clone(),
        author.clone(),
        payload,
    )?
    .author_with_digest_suite(
        arkret_canonical::parse_timestamp_canonical("2026-09-26T00:00:00.000Z")?,
        arkret::DigestSuite::Sha256,
    )?
    .into_event();
    let realm_id = scope
        .realm_id_opt()
        .context("the fixture scope names its Realm")?
        .clone();
    let commit = arkret_wire::RealmCommit {
        commit_id: arkret_wire::RealmCommitId::from_digest([seed; 32]),
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::from_scope(stream_scope, Some(realm_id))?,
        stream_position: envelope.epoch,
        previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([seed - 1; 32])),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(base.clone()),
        committed_at: arkret_canonical::parse_timestamp_canonical("2026-09-26T00:00:01.000Z")?,
        signature: fixed_signature(arkret_wire::DetachedSignatureContext::RealmCommit, seed)?,
    };
    Ok(arkret_wire::CommittedEventFullView { commit, event })
}

fn welcome_for(
    draft: &arkret::MlsWelcomeDraft,
    recipient: &Endpoint,
    accepted: &arkret_wire::CommittedEventFullView,
) -> Result<MlsWelcomeDelivery> {
    let delivery = MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new_v7_at(1_790_000_000_000),
        realm_id: accepted.event.realm_id.clone(),
        effective_scope: accepted.event.scope_ref.clone(),
        commit_event_ref: accepted.event.event_id.clone(),
        recipient_actor_id: recipient.actor.clone(),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: recipient.device.clone(),
        },
        keypackage_claim_ref: draft.keypackage_claim_ref.clone(),
        ciphertext_b64: draft.ciphertext_b64.clone(),
        producer_proof: fixed_signature(
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            0x77,
        )?,
    };
    delivery.validate_shape()?;
    Ok(delivery)
}

// ---------------------------------------------------------------------------
// Case 0: capability floor
// ---------------------------------------------------------------------------

fn group_capability_floor_case(case: &Value, tally: &mut Tally) -> Result<()> {
    let registered = string_vec(case, "registered_capabilities")?;
    tally.check(
        registered
            == ACTIVE_KEYPACKAGE_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>(),
        || "registered capability set drifted from the SDK's active set".to_owned(),
    )?;
    for (name, expected) in [
        ("required_capabilities", 0x0003_u16),
        (
            "keypackage_capabilities",
            MLS_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE,
        ),
        (
            "required_keypackage_capabilities",
            MLS_REQUIRED_KEYPACKAGE_CAPABILITIES_EXTENSION_TYPE,
        ),
        (
            "mls_governance_binding",
            arkret_models_crypto::MLS_GOVERNANCE_BINDING_EXTENSION_TYPE,
        ),
    ] {
        let declared = case
            .pointer(&format!("/extension_types/{name}"))
            .and_then(Value::as_str)
            .and_then(|value| u16::from_str_radix(value.trim_start_matches("0x"), 16).ok())
            .with_context(|| format!("extension type {name} is missing"))?;
        tally.check(declared == expected, || {
            format!("extension type {name} is {declared:#06x}, the SDK uses {expected:#06x}")
        })?;
    }
    for row in required_array(case, "extension_encoding_cases")? {
        let name = required_str(row, "name")?;
        let bytes = hex::decode(required_str(row, "extension_data_hex")?)?;
        let valid = decode_keypackage_capability_extension(&bytes).is_ok();
        tally.check(valid == required_bool_field(row, "expect_valid")?, || {
            format!("capability extension case {name} decoded as valid={valid}")
        })?;
    }
    let floor = string_vec(case, "initial_group_floor")?;
    tally.check(
        floor
            == REQUIRED_ARKRET_GROUP_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>(),
        || "initial group floor drifted from the SDK group floor".to_owned(),
    )?;
    // A real KeyPackage signs exactly the supporting leaf's capabilities.
    let endpoint = Endpoint::new(
        "ak:did_core:web:floor.example",
        "ak:device:0196419b-0000-7000-8000-000000000011",
        0x11,
    )?;
    let identity = endpoint.identity()?;
    let group = endpoint.identity()?.create_group(&realm_scope()?)?;
    tally.check(group.required_keypackage_capabilities()? == floor, || {
        "a new group does not carry the fixture floor".to_owned()
    })?;
    let record = identity.key_package_record()?;
    let bytes = keypackage_bytes(&record)?;
    let signed = arkret::keypackage_capabilities_from_key_package_bytes(&bytes)?;
    tally.check(signed == string_vec(case, "supporting_leaf")?, || {
        format!("the signed LeafNode carries {signed:?}")
    })?;
    tally.check(floor.iter().all(|value| signed.contains(value)), || {
        "the supporting leaf does not satisfy the floor".to_owned()
    })?;
    tally.check(
        arkret::validate_keypackage_capability_binding(&bytes, &signed).is_ok(),
        || "the exact signed capability set was not accepted".to_owned(),
    )?;

    for negative in required_array(case, "negative_cases")? {
        let name = required_str(negative, "name")?;
        let expected = required_str(negative, "expected")?;
        match name {
            "add_leaf_missing_floor_value" => {
                let leaf = string_vec(negative, "leaf_capabilities")?;
                let satisfied = floor.iter().all(|value| leaf.contains(value));
                tally.check(!satisfied && expected == "commit_rejected", || {
                    format!("{name}: a leaf missing the floor was admitted")
                })?;
            }
            "outer_record_exceeds_signed_leaf" => {
                let outer = string_vec(negative, "outer_capabilities")?;
                let leaf = string_vec(negative, "leaf_capabilities")?;
                tally.check(outer != leaf && expected == "keypackage_rejected", || {
                    format!("{name}: the fixture outer record equals its leaf")
                })?;
                // The same drift against a real signed LeafNode.
                let drifted = signed
                    .iter()
                    .take(signed.len() - 1)
                    .cloned()
                    .collect::<Vec<_>>();
                tally.check(
                    arkret::validate_keypackage_capability_binding(&bytes, &drifted).is_err(),
                    || format!("{name}: an outer set differing from the signed leaf passed"),
                )?;
            }
            "raise_floor_above_current_member_support" => {
                let new_floor = string_vec(negative, "new_floor")?;
                let supported = string_vec(negative, "current_member_capabilities")?;
                let every_member_supports = new_floor.iter().all(|value| supported.contains(value));
                tally.check(
                    !every_member_supports
                        && expected == "group_context_extensions_proposal_rejected",
                    || format!("{name}: a floor above current member support was accepted"),
                )?;
            }
            "send_profile_not_in_floor" => {
                let selected = required_str(negative, "selected_capability")?;
                tally.check(
                    !floor.iter().any(|value| value == selected)
                        && expected == "application_message_not_sent",
                    || format!("{name}: a profile outside the floor was sendable"),
                )?;
            }
            "unknown_value_cannot_satisfy_claim_or_floor" => {
                let capability = required_str(negative, "capability")?;
                // A well-formed but unregistered value may be advertised, yet it
                // can satisfy neither a claim requirement nor the group floor.
                tally.check(
                    validate_advertised_keypackage_capabilities(&[capability]).is_ok()
                        && !is_active_keypackage_capability(capability)
                        && validate_required_keypackage_capabilities(&[capability], &[capability])
                            .is_err()
                        && expected == "unsupported",
                    || format!("{name}: an unregistered capability satisfied a requirement"),
                )?;
            }
            other => bail!("unexecuted capability-floor negative case {other}"),
        }
    }
    Ok(())
}

fn required_bool_field(value: &Value, field: &str) -> Result<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .with_context(|| format!("missing boolean field {field}"))
}

// ---------------------------------------------------------------------------
// Station claim ledger model (device-lifecycle §9.2.3)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum LedgerAnswer {
    Claimed(Vec<u8>),
    Replayed(Vec<u8>),
    DuplicateConflict,
    ClaimFailed,
}

/// One target authority: a single-use pool and the `(source_id,
/// claim_request_id)` ledger whose CAS, digest and serialized outcome commit
/// together.
#[derive(Default)]
struct ClaimLedger {
    published: Vec<String>,
    claimed: BTreeSet<String>,
    rows: BTreeMap<(String, String), (String, Vec<u8>, String)>,
    cas_count: usize,
    inventory_reads: usize,
}

impl ClaimLedger {
    fn with_pool(refs: &[&str]) -> Self {
        Self {
            published: refs.iter().map(|value| (*value).to_owned()).collect(),
            ..Self::default()
        }
    }

    fn claim(&mut self, source: &str, request_id: &str, digest: &str) -> Result<LedgerAnswer> {
        let key = (source.to_owned(), request_id.to_owned());
        if let Some((stored_digest, outcome, _)) = self.rows.get(&key) {
            return Ok(if stored_digest == digest {
                LedgerAnswer::Replayed(outcome.clone())
            } else {
                LedgerAnswer::DuplicateConflict
            });
        }
        self.inventory_reads += 1;
        let Some(position) = self
            .published
            .iter()
            .position(|reference| !self.claimed.contains(reference))
        else {
            return Ok(LedgerAnswer::ClaimFailed);
        };
        let selected = self.published[position].clone();
        let outcome = arkret_canonical::canonical_json_bytes(&json!({
            "claim_request_id": request_id,
            "keypackage_ref": selected,
        }))?;
        self.claimed.insert(selected.clone());
        self.cas_count += 1;
        self.rows
            .insert(key, (digest.to_owned(), outcome.clone(), selected));
        Ok(LedgerAnswer::Claimed(outcome))
    }

    fn query(&self, source: &str, request_id: &str, digest: &str) -> Option<(&str, &[u8])> {
        self.rows
            .get(&(source.to_owned(), request_id.to_owned()))
            .filter(|(stored, ..)| stored == digest)
            .map(|(_, outcome, selected)| (selected.as_str(), outcome.as_slice()))
    }
}

fn peer_claim_atomic_idempotency_case(case: &Value, tally: &mut Tally) -> Result<()> {
    let source = required_str(case, "source_id")?;
    let request_id = required_str(case, "claim_request_id")?;
    tally.check(required_str(case, "idempotency_key")? == request_id, || {
        "Idempotency-Key is not the claim_request_id".to_owned()
    })?;
    let digest = required_str(case, "request_digest")?;
    let conflicting = required_str(case, "conflicting_request_digest")?;
    let selected_ref = required_str(case, "selected_keypackage_ref")?;
    let spare = "sha256:6666666666666666666666666666666666666666666666666666666666666666";
    let mut ledger = ClaimLedger::with_pool(&[selected_ref, spare]);
    let mut original = None;
    for step in string_vec(case, "sequence")? {
        match step.as_str() {
            "command_commits_but_response_is_lost" => {
                let LedgerAnswer::Claimed(outcome) = ledger.claim(source, request_id, digest)?
                else {
                    bail!("the first claim did not commit");
                };
                original = Some(outcome);
                tally.check(ledger.cas_count == 1, || {
                    "first claim did not CAS once".to_owned()
                })?;
            }
            "query_original_claim_request_id_and_digest" => {
                let (selected, outcome) = ledger
                    .query(source, request_id, digest)
                    .context("the uncertain caller's query found no claim")?;
                tally.check(
                    selected == selected_ref && Some(outcome) == original.as_deref(),
                    || "query did not return the original claim outcome".to_owned(),
                )?;
                tally.check(expected_str(case, "query_state")? == "claimed", || {
                    "query state drifted".to_owned()
                })?;
                tally.check(
                    expected_bool(case, "query_claim_ref_matches_original")?,
                    || "query claim ref expectation drifted".to_owned(),
                )?;
            }
            "duplicate_transport_delivery_of_the_original_command" => {
                let replay = ledger.claim(source, request_id, digest)?;
                tally.check(
                    replay == LedgerAnswer::Replayed(original.clone().unwrap_or_default())
                        && expected_str(case, "replay_response")?
                            == "byte_identical_original_outcome",
                    || "exact replay did not return the stored outcome bytes".to_owned(),
                )?;
                tally.check(ledger.cas_count == 1, || {
                    "exact replay performed a second CAS".to_owned()
                })?;
            }
            "reuse_claim_request_id_with_conflicting_digest" => {
                let answer = ledger.claim(source, request_id, conflicting)?;
                tally.check(
                    answer == LedgerAnswer::DuplicateConflict
                        && expected_str(case, "conflicting_digest_error")? == "duplicate_conflict",
                    || "conflicting reuse was not duplicate_conflict".to_owned(),
                )?;
                tally.check(
                    ledger.claimed.len() == 1 && !expected_bool(case, "second_keypackage_claimed")?,
                    || "conflicting reuse claimed a second KeyPackage".to_owned(),
                )?;
            }
            "new_attempt_uses_new_claim_request_id" => {
                let fresh = "AAAAAAAAAAAAAAAAAAAAAg";
                tally.check(ledger.query(source, fresh, digest).is_none(), || {
                    "a new claim_request_id resolved to the old ledger row".to_owned()
                })?;
                let answer = ledger.claim(source, fresh, conflicting)?;
                tally.check(matches!(answer, LedgerAnswer::Claimed(_)), || {
                    "a genuinely new attempt could not claim".to_owned()
                })?;
            }
            other => bail!("unexecuted peer claim step {other}"),
        }
    }
    tally.check(
        expected_u64(case, "published_to_claimed_cas_count")? == 1,
        || "CAS count expectation drifted".to_owned(),
    )?;
    // The receipt binds the ledger's claim_request_id; the outcome cannot
    // carry a different one.
    let outcome = claim_outcome_value(claim_record_value(ClaimRecordInput {
        claim_id: "ak:keypackage_claim:0199cccc-cccc-7ccc-8ccc-cccccccccccc",
        keypackage_ref: selected_ref,
        principal_id: &core_did("ak:did_core:webvh:z6mkfixture")?,
        device_id: &device("ak:device:0196419b-0000-7000-8000-000000000002")?,
        device_authorize_event_id: "ak:event:ARELvWOpF6BRhrks3DlbQy-9XIE6aAQQumDQp7fA4Ape",
        last_resort: false,
        expires_at: parse_time("2100-01-01T00:00:00.000Z")?,
    }));
    let parsed = parse_claim_outcome(outcome.clone())?;
    tally.check(parsed.validate_shape().is_ok(), || {
        "the canonical claim outcome is not shape-valid".to_owned()
    })?;
    let mut rebound = outcome;
    rebound["claim_receipt"]["claim_request_id"] = json!("AAAAAAAAAAAAAAAAAAAAAw");
    let rebound: KeyPackagesClaimOutcome = serde_json::from_value(rebound)?;
    tally.check(rebound.validate_shape().is_err(), || {
        "a receipt naming another claim_request_id was accepted".to_owned()
    })?;
    Ok(())
}

/// The ledger half of the self claim case: the same identity with another
/// digest is refused before any inventory lookup and claims nothing.
fn self_claim_conflict_ledger(case: &Value, tally: &mut Tally) -> Result<()> {
    let source = case
        .pointer("/object_identity/source_id")
        .and_then(Value::as_str)
        .context("self claim object identity omits source_id")?;
    let request_id = case
        .pointer("/object_identity/claim_request_id")
        .and_then(Value::as_str)
        .context("self claim object identity omits claim_request_id")?;
    let mut ledger = ClaimLedger::with_pool(&[
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    ]);
    for step in string_vec(case, "sequence")? {
        match step.as_str() {
            "claim_cas_and_ledger_commit_but_response_is_lost" => {
                tally.check(
                    matches!(
                        ledger.claim(source, request_id, "sha256:aa")?,
                        LedgerAnswer::Claimed(_)
                    ),
                    || "the self claim did not commit".to_owned(),
                )?;
            }
            "retry_same_source_service_claim_request_id_and_request_digest" => {
                tally.check(
                    matches!(
                        ledger.claim(source, request_id, "sha256:aa")?,
                        LedgerAnswer::Replayed(_)
                    ),
                    || "the self claim retry did not replay".to_owned(),
                )?;
            }
            "reuse_source_service_claim_request_id_with_conflicting_request_digest" => {
                let reads_before = ledger.inventory_reads;
                let answer = ledger.claim(source, request_id, "sha256:bb")?;
                tally.check(answer == LedgerAnswer::DuplicateConflict, || {
                    "conflicting self-claim reuse was not refused".to_owned()
                })?;
                tally.check(
                    ledger.inventory_reads == reads_before
                        && !expected_bool(case, "inventory_lookup_before_conflict")?,
                    || "conflicting reuse read the target inventory".to_owned(),
                )?;
                tally.check(
                    ledger.cas_count == 1 && !expected_bool(case, "second_keypackage_claimed")?,
                    || "conflicting reuse claimed a second KeyPackage".to_owned(),
                )?;
                tally.check(
                    expected_str(case, "conflicting_digest_error")? == "duplicate_conflict",
                    || "conflicting self-claim reuse is not duplicate_conflict".to_owned(),
                )?;
            }
            other => bail!("unexecuted self claim step {other}"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 7: double authorization and anti-enumeration
// ---------------------------------------------------------------------------

fn peer_claim_double_authorization_privacy_case(case: &Value, tally: &mut Tally) -> Result<()> {
    let requester = Endpoint::new(
        "ak:did_core:web:privacy-requester.example",
        "ak:device:0196419b-0000-7000-8000-000000000021",
        0x21,
    )?;
    let source = required_str(case, "source_id")?;
    let destination = required_str(case, "destination_id")?;
    let signed_at = "2026-09-26T00:00:00.000Z";
    let body = |destination_id: &str,
                last_resort_allowed: Option<bool>|
     -> Result<arkret_models_crypto::KeyPackagesClaimRequestBody> {
        let mut value = json!({
            "claim_request_id": "AAAAAAAAAAAAAAAAAAAAAQ",
            "target_account_id": case["target_account_id"],
            "target_device_ids": ["ak:device:0196419b-0000-7000-8000-000000000002"],
            "requester_account_id": case["requester_account_id"],
            "intended_realm_id": case["intended_realm_id"],
            "mls_group_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "claim_purpose": required_str(case, "claim_purpose")?,
            "required_capabilities": ["ak.content.v1"],
            "expires_at": "2026-09-26T00:04:00.000Z",
            "timeout_ms": null,
            "strand_id": case["strand_id"],
            "pair_key": case["pair_key"],
            "service_binding": {"source_id": source, "destination_id": destination_id},
            "requester_authorization": {
                "kind": "device",
                "verification_method": requester.method()?,
                "requester_device_id": requester.device,
                "device_authorize_event_id": "ak:event:ARELvWOpF6BRhrks3DlbQy-9XIE6aAQQumDQp7fA4Ape",
                "signed_at": signed_at,
                "signature": {"kid": requester.method()?, "signature_algorithm": "Ed25519", "sig": "AA"},
            },
        });
        if let Some(allowed) = last_resort_allowed {
            value["last_resort_allowed"] = json!(allowed);
        }
        Ok(serde_json::from_value(value)?)
    };
    let transcript = |request: &arkret_models_crypto::KeyPackagesClaimRequestBody| {
        arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
            &request.unsigned_request(),
            &request.service_binding,
            &request.requester_authorization,
        )
    };
    let honest = body(destination, None)?;
    let signature = requester.key.sign(&transcript(&honest)?);
    tally.check(
        requester
            .key
            .verifying_key()
            .verify(&transcript(&honest)?, &signature)
            .is_ok(),
        || "the participant signature does not verify over its own transcript".to_owned(),
    )?;
    let forwarded = body("ak:did_core:web:another-deployment.example", None)?;
    tally.check(
        requester
            .key
            .verifying_key()
            .verify(&transcript(&forwarded)?, &signature)
            .is_err(),
        || "a participant signature verified for another destination".to_owned(),
    )?;
    tally.check(
        required_str(case, "source_trust_domain")?
            == required_str(case, "destination_trust_domain")?,
        || "the fixture spans two trust domains".to_owned(),
    )?;

    // The destination's gate: each mutation fails exactly one mandatory
    // check, every business failure answers the same opaque claim_failed and
    // leaves the pool untouched; only a broken outer service signature is an
    // authentication failure, independent of the target.
    let mutations = string_vec(case, "negative_mutations")?;
    let failure = claim_failure_outcome_value();
    let forbidden = string_vec(
        case.get("expected")
            .context("privacy case omits expected")?,
        "response_forbidden_fields",
    )?;
    // The honest request passes every destination gate and claims once.
    let honest_inputs = DestinationGate::honest();
    let mut ledger = ClaimLedger::with_pool(&[
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    ]);
    tally.check(
        honest_inputs.evaluate(&mut ledger, source)? == "claimed" && ledger.cas_count == 1,
        || "the honest peer claim did not pass the destination gates".to_owned(),
    )?;
    for mutation in &mutations {
        let mut inputs = DestinationGate::honest();
        match mutation.as_str() {
            "missing_requester_authorization" => {
                let mut value = serde_json::to_value(&honest)?;
                value
                    .as_object_mut()
                    .context("claim request is an object")?
                    .remove("requester_authorization");
                inputs.participant_authorized = serde_json::from_value::<
                    arkret_models_crypto::KeyPackagesClaimRequestBody,
                >(value)
                .is_ok();
            }
            "stale_requester_authorization" => inputs.participant_fresh = false,
            "requester_signature_transport_destination_mismatch" => {
                inputs.destination_bound = requester
                    .key
                    .verifying_key()
                    .verify(&transcript(&forwarded)?, &signature)
                    .is_ok();
            }
            "source_service_not_requester_home_authority" => inputs.source_is_home = false,
            "outer_service_signature_invalid" => inputs.outer_signature_valid = false,
            "contact_not_accepted" => inputs.contact_accepted = false,
            "target_directional_contact_scope_missing" => inputs.contact_scope = false,
            "required_capability_not_in_keypackage" => inputs.capability_satisfied = false,
            "last_resort_allowed_true" => {
                let request = body(destination, Some(true))?;
                inputs.last_resort_requested = request.last_resort_allowed == Some(true)
                    && request.claim_purpose
                        == arkret_models_crypto::PeerKeyPackageClaimPurpose::DirectConversation;
            }
            "truncated_target_device_authorization_chain" => inputs.device_chain_complete = false,
            "target_device_projection_mismatch" => inputs.device_projection_matches = false,
            "target_agent_observation_request_digest_mismatch" => {
                inputs.agent_observation_matches = false
            }
            other => bail!("unexecuted privacy mutation {other}"),
        }
        let mut ledger = ClaimLedger::with_pool(&[
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        ]);
        let answer = inputs.evaluate(&mut ledger, source)?;
        tally.check(
            answer != "claimed" && ledger.cas_count == 0 && ledger.inventory_reads == 0,
            || format!("{mutation}: the refused claim touched the target inventory"),
        )?;
        match answer {
            "claim_failed" => {
                assert_claim_failed(&failure)?;
                tally.check(
                    forbidden.iter().all(|field| {
                        failure.pointer(&format!("/error/{field}")).is_none()
                            && failure.get(field).is_none()
                    }),
                    || format!("{mutation}: the refusal exposes target inventory"),
                )?;
                tally.check(
                    expected_str(case, "authenticated_business_mutations_external_error")?
                        == answer,
                    || "business refusal code drifted".to_owned(),
                )?;
            }
            _ => tally.check(
                mutation == "outer_service_signature_invalid"
                    && expected_str(case, "outer_service_signature_invalid_error")? == answer
                    && expected_bool(case, "outer_auth_error_target_independent")?,
                || format!("{mutation}: outer authentication refusal drifted"),
            )?,
        }
    }
    tally.check(
        expected_bool(case, "keypackage_state_unchanged_on_failure")?
            && !expected_bool(case, "last_resort_record_returned")?,
        || "privacy expectations drifted".to_owned(),
    )?;
    // Claim records carry exactly one branch authorization Event id.
    let mut both = claim_record_value(ClaimRecordInput {
        claim_id: "ak:keypackage_claim:0199cccc-cccc-7ccc-8ccc-cccccccccccc",
        keypackage_ref: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        principal_id: &core_did("ak:did_core:webvh:z6mkfixture")?,
        device_id: &device("ak:device:0196419b-0000-7000-8000-000000000002")?,
        device_authorize_event_id: "ak:event:ARELvWOpF6BRhrks3DlbQy-9XIE6aAQQumDQp7fA4Ape",
        last_resort: false,
        expires_at: parse_time("2100-01-01T00:00:00.000Z")?,
    });
    both["agent_key_authorize_event_id"] =
        json!("ak:event:ARELvWOpF6BRhrks3DlbQy-9XIE6aAQQumDQp7fA4Ape");
    tally.check(
        parse_claim_outcome(claim_outcome_value(both)).is_err(),
        || "a claim record carrying both branch authorizations was accepted".to_owned(),
    )?;
    Ok(())
}

/// The destination's independent admission (device-lifecycle §9.2.1 /
/// §9.2.2). The outer service signature is checked first and is the only
/// target-independent authentication failure; every business gate is
/// evaluated before the ledger is touched and answers the same opaque
/// `claim_failed`.
struct DestinationGate {
    outer_signature_valid: bool,
    participant_authorized: bool,
    participant_fresh: bool,
    destination_bound: bool,
    source_is_home: bool,
    contact_accepted: bool,
    contact_scope: bool,
    capability_satisfied: bool,
    last_resort_requested: bool,
    device_chain_complete: bool,
    device_projection_matches: bool,
    agent_observation_matches: bool,
}

impl DestinationGate {
    fn honest() -> Self {
        Self {
            outer_signature_valid: true,
            participant_authorized: true,
            participant_fresh: true,
            destination_bound: true,
            source_is_home: true,
            contact_accepted: true,
            contact_scope: true,
            capability_satisfied: true,
            last_resort_requested: false,
            device_chain_complete: true,
            device_projection_matches: true,
            agent_observation_matches: true,
        }
    }

    fn evaluate(&self, ledger: &mut ClaimLedger, source: &str) -> Result<&'static str> {
        if !self.outer_signature_valid {
            return Ok("unauthenticated");
        }
        let admitted = self.participant_authorized
            && self.participant_fresh
            && self.destination_bound
            && self.source_is_home
            && self.contact_accepted
            && self.contact_scope
            && self.capability_satisfied
            && !self.last_resort_requested
            && self.device_chain_complete
            && self.device_projection_matches
            && self.agent_observation_matches;
        if !admitted {
            return Ok("claim_failed");
        }
        Ok(
            match ledger.claim(source, "AAAAAAAAAAAAAAAAAAAAAQ", "sha256:aa")? {
                LedgerAnswer::Claimed(_) => "claimed",
                _ => "claim_failed",
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Case 9: claimed leaf capabilities
// ---------------------------------------------------------------------------

fn welcome_capabilities_digest_mismatch_case(case: &Value, tally: &mut Tally) -> Result<()> {
    let required = string_vec(case, "required_capabilities")?;
    let claimed = string_vec(case, "claimed_leaf_capabilities")?;
    let mismatched = string_vec(case, "mismatched_leaf_capabilities")?;
    let satisfies = |leaf: &[String]| required.iter().all(|value| leaf.contains(value));
    tally.check(satisfies(&claimed), || {
        "the claimed leaf does not satisfy the required capabilities".to_owned()
    })?;
    tally.check(
        !satisfies(&mismatched)
            && expected_bool(case, "reject_before_decrypt")?
            && expected_str(case, "reason")? == "welcome_capability_mismatch",
        || "a leaf missing a required capability passed before decryption".to_owned(),
    )?;
    // The recipient recomputes capabilities from the claimed signed LeafNode.
    let endpoint = Endpoint::new(
        "ak:did_core:web:capability-recipient.example",
        "ak:device:0196419b-0000-7000-8000-000000000031",
        0x31,
    )?;
    let bytes = keypackage_bytes(&endpoint.identity()?.key_package_record()?)?;
    let signed = arkret::keypackage_capabilities_from_key_package_bytes(&bytes)?;
    tally.check(satisfies(&signed), || {
        "a real KeyPackage does not satisfy the required capabilities".to_owned()
    })?;
    tally.check(
        arkret::validate_keypackage_capability_binding(&bytes, &mismatched).is_err(),
        || "an outer set other than the signed leaf passed the binding".to_owned(),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 11: requester-side verification before install
// ---------------------------------------------------------------------------

fn peer_claim_response_verification_case(case: &Value, tally: &mut Tally) -> Result<()> {
    let record = case
        .get("keypackage_claim_record")
        .context("case omits keypackage_claim_record")?;
    let request_id = required_str(case, "claim_request_id")?;
    tally.check(
        case.pointer("/claim_receipt/claim_request_id")
            .and_then(Value::as_str)
            == Some(request_id),
        || "the receipt does not name the request's claim_request_id".to_owned(),
    )?;
    let destination = SigningKey::from_bytes(&[0x41; 32]);
    let claim_bytes = arkret_canonical::canonical_json_bytes(record)?;
    let receipt = destination.sign(&claim_bytes);
    // The four checks, each over bytes the requester recomputes itself.
    let verify = |record: &Value, receipt_over: &[u8]| -> Result<bool> {
        let branch_ok = match (
            record
                .get("device_authorize_event_id")
                .filter(|value| !value.is_null()),
            record
                .get("agent_key_authorize_event_id")
                .filter(|value| !value.is_null()),
        ) {
            (Some(device), None) => {
                device.as_str()
                    == case["keypackage_claim_record"]["device_authorize_event_id"].as_str()
            }
            _ => false,
        };
        let recomputed = arkret_canonical::canonical_json_bytes(record)?;
        let receipt_ok = recomputed == receipt_over
            && destination
                .verifying_key()
                .verify(receipt_over, &receipt)
                .is_ok();
        let selectors_ok = record["target_device_id"]
            == case["keypackage_claim_record"]["target_device_id"]
            && record["actor_id"] == case["keypackage_claim_record"]["actor_id"]
            && record["keypackage_digest"] == case["keypackage_claim_record"]["keypackage_digest"];
        let signer_ok = record["signature_verification_method"]
            == case["keypackage_claim_record"]["signature_verification_method"];
        Ok(branch_ok && receipt_ok && selectors_ok && signer_ok)
    };
    tally.check(verify(record, &claim_bytes)?, || {
        "the honest claim record did not pass all four checks".to_owned()
    })?;
    for mutation in string_vec(case, "negative_mutations")? {
        let mut mutated = record.clone();
        let mut receipt_over = claim_bytes.clone();
        match mutation.as_str() {
            "claim_record_omits_the_branch_authorization_event_id" => {
                mutated["device_authorize_event_id"] = Value::Null;
            }
            "claim_record_carries_both_branch_authorization_event_ids" => {
                mutated["agent_key_authorize_event_id"] =
                    mutated["device_authorize_event_id"].clone();
            }
            "claim_record_authorization_event_id_names_another_accepted_event" => {
                mutated["device_authorize_event_id"] =
                    json!("ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD");
            }
            "producer_proof_verifiable_only_by_replaying_the_producer_control_history"
            | "directory_attestation_names_a_superseded_key_or_another_authorize_event" => {
                mutated["signature_verification_method"] =
                    json!("did:webvh:z6mkfixture:alice.example#superseded-key");
            }
            "claim_receipt_signed_over_a_reserialization_of_the_claim_bytes" => {
                receipt_over = serde_json::to_vec_pretty(record)?;
            }
            "claim_receipt_claim_request_id_differs_from_the_request" => {
                tally.check(
                    json!("AAAAAAAAAAAAAAAAAAAAAg") != case["claim_receipt"]["claim_request_id"],
                    || "the mutated receipt id equals the request".to_owned(),
                )?;
                receipt_over = b"another claim_request_id".to_vec();
            }
            "keypackage_signature_valid_but_selector_mismatched" => {
                mutated["target_device_id"] =
                    json!("ak:device:0196419b-0000-7000-8000-000000000099");
            }
            other => bail!("unexecuted response-verification mutation {other}"),
        }
        tally.check(!verify(&mutated, &receipt_over)?, || {
            format!("{mutation}: the requester installed the KeyPackage")
        })?;
    }
    tally.check(
        !expected_bool(case, "install_keypackage_before_all_four_checks_pass")?
            && !expected_bool(case, "author_welcome_before_all_four_checks_pass")?
            && expected_bool(
                case,
                "any_mutation_blocks_both_install_and_welcome_authoring",
            )?
            && !expected_bool(
                case,
                "external_verifier_replays_pcr_genesis_or_realmcommits",
            )?,
        || "response-verification expectations drifted".to_owned(),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 12: accepted winning Add Commit and the claim record
// ---------------------------------------------------------------------------

fn welcome_add_commit_and_claim_record_binding_case(case: &Value, tally: &mut Tally) -> Result<()> {
    let scope = realm_scope()?;
    let creator = Endpoint::new(
        "ak:did_core:web:lineage-creator.example",
        "ak:device:0196419b-0000-7000-8000-000000000051",
        0x51,
    )?;
    let recipient = Endpoint::new(
        "ak:did_core:web:lineage-recipient.example",
        "ak:device:0196419b-0000-7000-8000-000000000052",
        0x52,
    )?;
    let genesis = EventId::from_digest(arkret::DigestSuite::Sha256, [0x53; 32]);
    let genesis_binding = arkret::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let add_binding =
        arkret::MlsGovernanceBindingPayload::new(scope.clone(), Some(genesis.clone()), 0, 1, 0)?;
    // The recipient's KeyPackage private material lives in the identity that
    // generated it; every join attempt restores that exact identity.
    let recipient_identity = recipient.identity()?;
    let mut claimed = recipient_identity.key_package_record()?;
    let recipient_state = recipient_identity.export_private_state()?;
    let recipient_endpoint = recipient_identity.endpoint_identity();
    claimed.state = arkret::MlsKeyPackageState::Claimed;
    claimed.claim_id = Some(required_str(case, "claim_id")?.to_owned());

    let mut winner_group = creator
        .identity()?
        .create_group_with_governance_binding(&scope, &genesis_binding)?;
    let winning_add = winner_group.add_member_with_governance_binding(&claimed, &add_binding)?;
    let winning = accepted_commit(
        &scope,
        &scope,
        &creator.actor,
        &genesis,
        &winning_add.commit,
        0x61,
    )?;
    let delivery = welcome_for(&winning_add.welcome, &recipient, &winning)?;
    tally.check(
        delivery.keypackage_claim_ref.as_str() == required_str(case, "claim_id")?,
        || "the Welcome does not name the exact claim".to_owned(),
    )?;

    // A losing Add Commit of the same epoch from a competing member state.
    let mut loser_group = creator
        .identity()?
        .create_group_with_governance_binding(&scope, &genesis_binding)?;
    let losing_add = loser_group.add_member_with_governance_binding(&claimed, &add_binding)?;
    let losing = accepted_commit(
        &scope,
        &scope,
        &creator.actor,
        &genesis,
        &losing_add.commit,
        0x71,
    )?;
    let circle_scope = ScopeRef::Circle {
        realm_id: arkret_wire::RealmId::new(FIXTURE_REALM.to_owned())?,
        circle_id: arkret_wire::CircleId::from_event_id(&EventId::from_digest(
            arkret::DigestSuite::Sha256,
            [0x54; 32],
        )),
    };
    let other_lineage = accepted_commit(
        &scope,
        &circle_scope,
        &creator.actor,
        &genesis,
        &winning_add.commit,
        0x81,
    )?;

    let join = |delivery: &MlsWelcomeDelivery, accepted: &arkret_wire::CommittedEventFullView| {
        let identity = ArkretMlsIdentity::restore_from_private_state(
            recipient.actor.clone(),
            recipient_endpoint.clone(),
            &recipient_state,
        )?;
        ArkretMlsGroup::join_from_verified_welcome_delivery(identity, delivery, accepted)
            .map_err(anyhow::Error::from)
    };
    tally.check(join(&delivery, &winning).is_ok(), || {
        "the Welcome of the accepted winning Add Commit was refused".to_owned()
    })?;
    // The claim record the recipient resolves the delivery against.
    let claim_record = json!({
        "claim_id": required_str(case, "claim_id")?,
        "recipient_actor_id": recipient.actor,
        "recipient_device_id": recipient.device,
        "keypackage_ref": claimed.keypackage_ref,
        "device_authorization_event_id": case["claim_record"]["device_authorization_event_id"],
        "active_model_generation_ref": case["claim_record"]["active_model_generation_ref"],
    });
    let five_way = |delivery: &MlsWelcomeDelivery, record: &Value, verified: bool| {
        verified
            && delivery.keypackage_claim_ref.as_str()
                == record["claim_id"].as_str().unwrap_or_default()
            && serde_json::to_value(&delivery.recipient_actor_id).ok()
                == Some(record["recipient_actor_id"].clone())
            && matches!(&delivery.recipient_endpoint, arkret_wire::MlsWelcomeRecipientEndpoint::Device { device_id }
                if Some(device_id.as_str()) == record["recipient_device_id"].as_str())
            && record["keypackage_ref"].as_str() == Some(claimed.keypackage_ref.as_str())
            && record["active_model_generation_ref"].as_u64().is_some()
    };
    tally.check(five_way(&delivery, &claim_record, true), || {
        "the honest delivery does not resolve against its claim record".to_owned()
    })?;
    for mutation in string_vec(case, "negative_mutations")? {
        let refused = match mutation.as_str() {
            "welcome_has_no_accepted_winning_add_commit"
            | "welcome_matches_a_losing_add_commit_of_the_same_epoch" => {
                join(&delivery, &losing).is_err()
            }
            "delivery_commit_event_ref_names_a_losing_commit" => {
                let mut mutated = delivery.clone();
                mutated.commit_event_ref = losing.event.event_id.clone();
                join(&mutated, &winning).is_err()
            }
            "add_commit_accepted_on_another_genesis_lineage" => {
                join(&delivery, &other_lineage).is_err()
            }
            "delivery_recipient_endpoint_differs_from_claim" => {
                let mut mutated = delivery.clone();
                mutated.recipient_endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                    device_id: arkret_wire::DeviceId::new(
                        "ak:device:0196419b-0000-7000-8000-000000000099".to_owned(),
                    )?,
                };
                join(&mutated, &winning).is_err() && !five_way(&mutated, &claim_record, true)
            }
            "delivery_claim_ref_names_another_claim" => {
                let mut mutated = delivery.clone();
                mutated.keypackage_claim_ref = arkret_wire::KeypackageClaimId::new(
                    "ak:keypackage_claim:0199dddd-dddd-7ddd-8ddd-dddddddddddd".to_owned(),
                )?;
                !five_way(&mutated, &claim_record, true)
            }
            "binding_device_is_accepted_but_not_the_device_in_the_claim_record" => {
                let mut record = claim_record.clone();
                record["recipient_device_id"] =
                    json!("ak:device:0196419b-0000-7000-8000-000000000098");
                !five_way(&delivery, &record, true)
            }
            "binding_authorization_event_is_superseded_by_a_later_generation" => {
                let mut record = claim_record.clone();
                record["active_model_generation_ref"] = Value::Null;
                !five_way(&delivery, &record, true)
            }
            "bindings_satisfied_only_by_an_unverified_local_cache_entry" => {
                !five_way(&delivery, &claim_record, false)
                    && !expected_bool(case, "unverified_local_cache_accepted_as_proof")?
            }
            other => bail!("unexecuted lineage mutation {other}"),
        };
        tally.check(refused, || {
            format!("{mutation}: the Welcome was accepted before decryption")
        })?;
    }
    tally.check(
        expected_bool(case, "accepted_winning_add_commit_required")?
            && expected_bool(case, "all_five_bindings_resolved_against_one_claim_record")?
            && !expected_bool(case, "station_private_slot_read_required")?
            && expected_str(case, "reason")? == "keypackage_welcome_envelope_mismatch",
        || "lineage expectations drifted".to_owned(),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 13: consume only after the durable group state
// ---------------------------------------------------------------------------

fn welcome_consume_ordering_case(case: &Value, tally: &mut Tally) -> Result<()> {
    tally.check(
        required_str(case, "consume_operation")?
            == arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
        || "consume is not the self operation".to_owned(),
    )?;
    let registry: Value = serde_json::from_str(&std::fs::read_to_string(
        super::super::spec_artifacts_root().join("registry/operation-registry.json"),
    )?)?;
    let operations = registry["operations"]
        .as_array()
        .context("operation registry has no operations[]")?;
    tally.check(
        operations.iter().all(|operation| {
            let id = operation["operation_id"].as_str().unwrap_or_default();
            !(id.starts_with("ak.peer.") && id.contains("consume"))
        }),
        || "the peer surface offers a consume proxy".to_owned(),
    )?;
    let recipient = Endpoint::new(
        "ak:did_core:web:consume-recipient.example",
        "ak:device:0196419b-0000-7000-8000-000000000061",
        0x61,
    )?;
    let identity = recipient.identity()?;
    let welcome_ref = arkret_wire::MlsWelcomeDeliveryId::new_v7_at(1_790_000_000_000);
    let receipt = |identity: &ArkretMlsIdentity,
                   durable: bool|
     -> Result<arkret_models_crypto::RecipientMlsDurableReceipt> {
        if !durable {
            bail!("the durable receipt is signed only after the group state is stored");
        }
        let unsigned = arkret_models_crypto::RecipientMlsDurableReceipt {
            domain: arkret_wire::NonEmptyString::new(
                arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
            )
            .map_err(|error| anyhow!(error))?,
            claim_request_id: arkret_wire::Base64UrlString::new(
                required_str(case, "claim_request_id")?.to_owned(),
            )
            .map_err(|error| anyhow!(error))?,
            key_package_ref: arkret_wire::NonEmptyString::new(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned(),
            )
            .map_err(|error| anyhow!(error))?,
            recipient: arkret_models_crypto::RecipientMlsDurableSigner::Device {
                recipient_account_id: recipient
                    .actor
                    .as_account_id()
                    .context("the recipient is an Account")?
                    .clone(),
                recipient_device_id: recipient.device.clone(),
                device_verification_method: recipient.method()?,
            },
            recipient_id: arkret_wire::DidCoreId::new(STATION.to_owned())?,
            realm_id: arkret_wire::RealmId::new(FIXTURE_REALM.to_owned())?,
            mls_group_id: realm_scope()?.canonical_mls_group_id()?,
            mls_epoch: 1,
            welcome_ref: welcome_ref.clone(),
            welcome_digest: arkret_wire::Hash::new(format!("sha256:{}", "22".repeat(32)))?,
            durable_at: parse_time("2026-09-26T00:00:00.000Z")?,
            signature: arkret_models_crypto::KeyOperationSignature {
                kid: arkret_wire::NonEmptyString::new(recipient.method()?.to_string())
                    .map_err(|error| anyhow!(error))?,
                signature_algorithm: None,
                sig: arkret_wire::Base64UrlString::new("AA".to_owned())
                    .map_err(|error| anyhow!(error))?,
            },
        };
        Ok(identity.sign_recipient_mls_durable_receipt(unsigned)?)
    };
    let claim_id = arkret_wire::KeypackageClaimId::new(required_str(case, "claim_id")?.to_owned())?;
    let mut stored = false;
    let mut consumed = None;
    for step in string_vec(case, "sequence")? {
        match step.as_str() {
            "signed_mls_welcome_delivery_processed" => {
                tally.check(receipt(&identity, stored).is_err(), || {
                    "a receipt was signed before the group state was durable".to_owned()
                })?;
            }
            "group_state_durably_stored" => stored = true,
            "recipient_durable_receipt_generated" => {
                let signed = receipt(&identity, stored)?;
                tally.check(signed.validate_shape().is_ok(), || {
                    "the durable receipt is not shape-valid".to_owned()
                })?;
            }
            "original_claim_consumed_through_own_station" => {
                // An indeterminate consume is retried with the same signed
                // typed request, never a new receipt or claim identity.
                let durable_receipt = receipt(&identity, stored)?;
                let first = identity.signed_key_packages_consume_request(
                    claim_id.clone(),
                    durable_receipt.clone(),
                )?;
                let retry = identity
                    .signed_key_packages_consume_request(claim_id.clone(), durable_receipt)?;
                tally.check(
                    arkret_canonical::canonical_json_bytes(&first)?
                        == arkret_canonical::canonical_json_bytes(&retry)?,
                    || "the consume retry is not the same signed request".to_owned(),
                )?;
                consumed = Some(first);
            }
            other => bail!("unexecuted consume step {other}"),
        }
    }
    let consumed = consumed.context("the sequence never consumed")?;
    tally.check(consumed.claim_id == claim_id, || {
        "consume names another claim".to_owned()
    })?;
    let other = Endpoint::new(
        "ak:did_core:web:consume-other.example",
        "ak:device:0196419b-0000-7000-8000-000000000062",
        0x62,
    )?;
    tally.check(receipt(&other.identity()?, true).is_err(), || {
        "another endpoint signed the recipient's durable receipt".to_owned()
    })?;
    for mutation in string_vec(case, "negative_mutations")? {
        let refused = match mutation.as_str() {
            "consume_issued_before_group_state_is_durable"
            | "recipient_receipt_signed_after_a_failed_durable_store" => {
                receipt(&identity, false).is_err()
            }
            "consume_proxied_through_the_peer_surface" => {
                !expected_bool(case, "peer_surface_offers_a_consume_proxy")?
            }
            "claim_identity_rotated_and_retried_after_an_indeterminate_result"
            | "replacement_keypackage_claimed_in_parallel_after_an_indeterminate_result" => {
                !expected_bool(case, "blind_retry_under_a_new_claim_identity_allowed")?
                    && expected_bool(case, "idempotent_recovery_of_consume_by_signed_request")?
            }
            "claimed_keypackage_returned_to_published" => {
                serde_json::from_value::<MlsKeyPackageState>(json!("claimed"))?
                    != MlsKeyPackageState::Published
            }
            other => bail!("unexecuted consume mutation {other}"),
        };
        tally.check(refused, || {
            format!("{mutation}: the ordering rule did not hold")
        })?;
    }
    tally.check(
        !expected_bool(case, "consume_reachable_before_durable_group_state")?
            && !expected_bool(case, "receipt_signed_on_durable_store_failure")?,
        || "consume ordering expectations drifted".to_owned(),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Case 14: complete ActorId credential and the ciphersuite closure
// ---------------------------------------------------------------------------

fn keypackage_actor_and_ciphersuite_closure_case(case: &Value, tally: &mut Tally) -> Result<()> {
    let root = super::super::spec_artifacts_root();
    let registry: Value = serde_json::from_str(&std::fs::read_to_string(
        root.join(required_str(case, "registry_ref")?),
    )?)?;
    let suites = registry["ciphersuites"]
        .as_array()
        .context("ciphersuite registry has no rows")?;
    let active = suites
        .iter()
        .filter(|row| row["status"] == "active")
        .collect::<Vec<_>>();
    let declared = case
        .get("active_suite")
        .context("case omits active_suite")?;
    tally.check(
        active.len() == 1
            && active[0]["canonical_id"] == declared["canonical_id"]
            && active[0]["rfc9420_id"] == declared["rfc9420_id"]
            && declared["canonical_id"] == ACTIVE_SUITE,
        || "the registry does not have exactly the declared active suite".to_owned(),
    )?;
    tally.check(
        arkret_wire::MLS_CIPHERSUITES
            .iter()
            .filter(|suite| suite.status == "active")
            .map(|suite| suite.canonical_id)
            .collect::<Vec<_>>()
            == vec![ACTIVE_SUITE],
        || "the SDK registry surface drifted from the spec registry".to_owned(),
    )?;
    let is_active_rfc_id = |id: &str| {
        suites
            .iter()
            .any(|row| row["rfc9420_id"] == id && row["status"] == "active")
    };
    for rejection in required_array(case, "rejection_cases")? {
        let name = required_str(rejection, "name")?;
        let refused = match name {
            "publish_rejects_unregistered_suite"
            | "claim_rejects_reserved_suite"
            | "commit_rejects_reserved_suite" => {
                !is_active_rfc_id(required_str(rejection, "presented_suite")?)
            }
            "try_many_is_not_a_fallback" => {
                // The first presented selector decides; a later active one
                // is never tried.
                let presented = string_vec(rejection, "presented_suites")?;
                let first = presented.first().context("no presented suite")?;
                !is_active_rfc_id(first)
                    && presented.iter().skip(1).any(|id| is_active_rfc_id(id))
                    && !required_bool_field(rejection, "accepted_later_suite")?
            }
            "foreign_suite_identifier_is_not_rewritten" => {
                let presented = required_str(rejection, "presented_suite")?;
                let rewrite = required_str(rejection, "proposed_local_rewrite")?;
                !is_active_rfc_id(presented)
                    && is_active_rfc_id(rewrite)
                    && !required_bool_field(rejection, "rewrite_performed")?
            }
            "collapsed_basic_credential_is_rejected" => {
                let collapsed = required_str(rejection, "presented_identity")?;
                arkret_models_crypto::decode_mls_basic_credential_identity(collapsed.as_bytes())
                    .is_err()
                    && required_str(rejection, "expected_identity_source")?
                        == "UTF8(RFC8785_JCS(complete ActorId))"
            }
            other => bail!("unexecuted ciphersuite rejection case {other}"),
        };
        tally.check(
            refused && !required_bool_field(rejection, "state_changed")?,
            || format!("{name}: the rejection did not hold"),
        )?;
    }
    // Endpoint KATs: the BasicCredential is the JCS of the complete ActorId
    // and the KeyPackage declares the active suite.
    for reference in string_vec(case, "endpoint_kat_refs")? {
        let (file, pointer) = reference
            .split_once('#')
            .context("KAT reference has no JSON pointer")?;
        let kat: Value = serde_json::from_str(&std::fs::read_to_string(root.join(file))?)?;
        let row = kat
            .pointer(pointer)
            .context("KAT pointer resolves to nothing")?;
        let bytes = arkret_canonical::base64url_decode(required_str(row, "keypackage")?)?;
        let leaf = arkret::author_leaf_from_key_package_bytes(&bytes, 0)?;
        let arkret::AuthorLeafCredential::Basic { identity } = leaf.credential else {
            bail!("{reference}: the KAT leaf is not a BasicCredential");
        };
        let actor = arkret_models_crypto::decode_mls_basic_credential_identity(&identity)?;
        tally.check(
            std::str::from_utf8(&identity)? == required_str(row, "leaf_credential_jcs")?
                && arkret_canonical::canonical_json_bytes(&actor)? == identity,
            || format!("{reference}: the credential is not the ActorId's JCS"),
        )?;
        tally.check(
            arkret::keypackage_ciphersuite_canonical_id(&bytes)? == ACTIVE_SUITE,
            || format!("{reference}: the KAT KeyPackage does not declare the active suite"),
        )?;
    }
    // A real device KeyPackage carries the complete ActorId the claim and the
    // Welcome name.
    let endpoint = Endpoint::new(
        "ak:did_core:web:closure-owner.example",
        "ak:device:0196419b-0000-7000-8000-000000000071",
        0x71,
    )?;
    let record = endpoint.identity()?.key_package_record()?;
    let leaf = arkret::author_leaf_from_key_package_bytes(&keypackage_bytes(&record)?, 0)?;
    let arkret::AuthorLeafCredential::Basic { identity } = leaf.credential else {
        bail!("the device KeyPackage leaf is not a BasicCredential");
    };
    tally.check(
        arkret_models_crypto::decode_mls_basic_credential_identity(&identity)? == endpoint.actor
            && record.actor_id == endpoint.actor
            && expected_bool(case, "claim_actor_equals_welcome_recipient_actor")?
            && expected_bool(case, "basic_credential_equals_actor_id_jcs_utf8")?
            && !expected_bool(case, "partial_write_on_any_rejection")?,
        || "the device KeyPackage does not carry its complete ActorId".to_owned(),
    )?;
    Ok(())
}
