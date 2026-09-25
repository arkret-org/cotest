//! Executable conformance runner for untrusted Realm join locators.
//!
//! Locator DTOs are exercised through the SDK's closed `RealmJoinCandidate`
//! and `RealmJoinTarget` APIs. Authority cases cross the actual trust
//! boundary: raw bundles are verified by `verify_realm_authority_bundle`, and
//! only its opaque `VerifiedRealmAuthority` output reaches the production
//! convergence evaluator.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret_canonical::canonical;
use arkret_identity::{
    RealmAuthorityChainError, RealmAuthorityConvergenceError, RealmAuthorityFreshness,
    RealmAuthorityKeyMap, VerifiedRealmAuthority, build_authenticated_did_web_service_resolution,
    converge_verified_realm_authorities, verify_realm_authority_bundle,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind, RealmJoinTarget,
};
use arkret_models_identity::DidDocument;
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::detached_object::sign_detached_object;
use arkret_wire::{
    Base64UrlString, CommitStreamHead, CommitStreamRef, DetachedObjectSignature,
    DetachedSignatureAlgorithm, DetachedSignatureContext, Did, DidCoreId, DidUrl, Event, EventId,
    EventKind, Hash, RealmAuthorityBundle, RealmAuthorityCurrentAssertion, RealmAuthorityHandoff,
    RealmAuthorityHandoffId, RealmAuthorityTransition, RealmCommit, RealmCommitAuthorityRef,
    RealmCommitId, RealmId, RealmSnapshotId, ScopeRef, project_did_to_core_id,
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{Value, json};

pub const REALM_JOIN_CANDIDATE_ENTRYPOINT: &str =
    "ak.suite.realm_join_candidate.untrusted_locator.v1";
pub const FIXTURE: &str = "realm-join-candidate-locator-fixture.json";

const STATION_A: &str = "did:web:station-a.example";
const STATION_B: &str = "did:web:station-b.example";
const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAA";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    suite: String,
    fixture_kind: String,
    runner: Runner,
    version: String,
    schema: String,
    vector_id: String,
    accepted_candidate: Value,
    locator_array_contract: LocatorArrayContract,
    accepted_sorted_candidates: Vec<RealmJoinCandidate>,
    trust_contract: TrustContract,
    source_equivalence: Vec<AuthorityLocatorSource>,
    rejected_additional_members: Vec<String>,
    rejected_locator_arrays: Vec<RejectedLocatorArray>,
    freshness_contract: FreshnessContract,
    authority_assertion_cases: Vec<AuthorityAssertionCase>,
    authority_chain_cases: Vec<AuthorityChainCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocatorArrayContract {
    min_items: usize,
    max_items: usize,
    sort_key: String,
    semantic_identity_key: String,
    duplicate_or_conflicting_identity: String,
    directory_field_may_be_omitted: bool,
    explicit_empty_array_is_valid: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustContract {
    candidate_is_authority: bool,
    candidate_is_authorization: bool,
    candidate_is_identity_selector: bool,
    candidate_signature_can_raise_trust: bool,
    client_submits_to_own_station: bool,
    own_station_fetches_nonce_bound_authority_bundle: bool,
    current_governance_station_source: String,
    conflicting_authority_chains: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectedLocatorArray {
    name: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessContract {
    directory: String,
    invite: String,
    join: String,
    locator_specific_ttl_or_skew: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityAssertionCase {
    name: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityChainCase {
    name: String,
    #[serde(default)]
    candidate_count: Option<usize>,
    #[serde(default)]
    verified_chain_count: Option<usize>,
    #[serde(default)]
    chains_are_mutually_exclusive: Option<bool>,
    #[serde(default)]
    candidate_signature_valid: Option<bool>,
    #[serde(default)]
    verified_genesis_and_handoff_chain: Option<bool>,
    expected: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmJoinCandidateExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
}

struct SignedChain {
    bundle: RealmAuthorityBundle,
    keys: RealmAuthorityKeyMap,
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("fixtures").is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn load_fixture() -> Result<FixtureRoot> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

fn validate_fixture_metadata(fixture: &FixtureRoot) -> Result<()> {
    ensure!(
        fixture.suite == "realm_join_candidate_untrusted_locator",
        "fixture suite drifted"
    );
    ensure!(fixture.fixture_kind == "schema_and_semantic");
    ensure!(fixture.runner.kind == "named_suite");
    ensure!(fixture.runner.entrypoint == REALM_JOIN_CANDIDATE_ENTRYPOINT);
    ensure!(!fixture.version.trim().is_empty());
    ensure!(fixture.schema == "arkret.realm-join-candidate-locator-fixture.v1");
    ensure!(fixture.vector_id == "ak.vector.realm_join_candidate.untrusted_locator.v1");

    let contract = &fixture.locator_array_contract;
    ensure!(contract.min_items == 1 && contract.max_items == 8);
    ensure!(contract.sort_key == "service_id_utf8_bytes");
    ensure!(contract.semantic_identity_key == "service_id");
    ensure!(contract.duplicate_or_conflicting_identity == "reject_entire_array");
    ensure!(contract.directory_field_may_be_omitted);
    ensure!(!contract.explicit_empty_array_is_valid);

    let trust = &fixture.trust_contract;
    ensure!(!trust.candidate_is_authority);
    ensure!(!trust.candidate_is_authorization);
    ensure!(!trust.candidate_is_identity_selector);
    ensure!(!trust.candidate_signature_can_raise_trust);
    ensure!(trust.client_submits_to_own_station);
    ensure!(trust.own_station_fetches_nonce_bound_authority_bundle);
    ensure!(
        trust.current_governance_station_source
            == "verified_realm_genesis_and_continuous_handoff_chain"
    );
    ensure!(trust.conflicting_authority_chains == "fail_closed");

    ensure!(fixture.freshness_contract.directory == "enclosing_as_of_and_stale");
    ensure!(fixture.freshness_contract.invite == "enclosing_invite_expires_at");
    ensure!(
        fixture.freshness_contract.join == "enclosing_realm_id_and_nonce_bound_current_assertion"
    );
    ensure!(!fixture.freshness_contract.locator_specific_ttl_or_skew);
    Ok(())
}

fn validate_candidate_controls(fixture: &FixtureRoot) -> Result<()> {
    let accepted: RealmJoinCandidate = serde_json::from_value(fixture.accepted_candidate.clone())?;
    accepted.validate()?;
    ensure!(serde_json::to_value(&accepted)? == fixture.accepted_candidate);

    ensure!(fixture.accepted_sorted_candidates.len() == 2);
    let accepted_target = target(fixture.accepted_sorted_candidates.clone());
    accepted_target.validate()?;
    ensure!(
        fixture.accepted_sorted_candidates[0].endpoint_url.is_none(),
        "the accepted omission control drifted"
    );

    let expected_sources = [
        AuthorityLocatorSource::Invite,
        AuthorityLocatorSource::Directory,
        AuthorityLocatorSource::Cache,
    ];
    ensure!(fixture.source_equivalence == expected_sources);
    for source in &fixture.source_equivalence {
        let mut source_candidate = accepted.clone();
        source_candidate.source = *source;
        source_candidate.validate()?;
    }

    let eight = (0..fixture.locator_array_contract.max_items)
        .map(|index| candidate(&format!("ak:did_core:web:a{index}.example"), "cache", None))
        .collect::<Result<Vec<_>>>()?;
    target(eight.clone()).validate()?;
    let mut nine = eight;
    nine.push(candidate("ak:did_core:web:a8.example", "cache", None)?);
    ensure!(target(nine).validate().is_err());
    Ok(())
}

fn run_additional_member_case(field: &str, fixture: &FixtureRoot) -> Result<CaseExecutionResult> {
    let mut value = fixture.accepted_candidate.clone();
    value
        .as_object_mut()
        .context("accepted_candidate is not an object")?
        .insert(field.to_owned(), json!(true));
    ensure!(
        serde_json::from_value::<RealmJoinCandidate>(value).is_err(),
        "closed RealmJoinCandidate accepted additional member {field}"
    );
    Ok(result(field, 1))
}

fn run_locator_array_case(case: &RejectedLocatorArray) -> Result<CaseExecutionResult> {
    let a = candidate(
        "ak:did_core:web:a.example",
        "invite",
        Some("https://a.example/"),
    )?;
    let b = candidate(
        "ak:did_core:web:b.example",
        "directory",
        Some("https://b.example/"),
    )?;
    let candidates = match case.name.as_str() {
        "exact_duplicate" => {
            ensure!(case.reason == "duplicate_service_id");
            vec![a.clone(), a]
        }
        "same_service_different_source" => {
            ensure!(case.reason == "conflicting_service_id");
            vec![
                a,
                candidate(
                    "ak:did_core:web:a.example",
                    "directory",
                    Some("https://a.example/"),
                )?,
            ]
        }
        "same_service_different_endpoint" => {
            ensure!(case.reason == "conflicting_service_id");
            vec![
                a,
                candidate(
                    "ak:did_core:web:a.example",
                    "invite",
                    Some("https://different.example/"),
                )?,
            ]
        }
        "same_service_missing_endpoint" => {
            ensure!(case.reason == "conflicting_service_id");
            vec![a, candidate("ak:did_core:web:a.example", "invite", None)?]
        }
        "reverse_service_id_order" => {
            ensure!(case.reason == "not_strictly_sorted_by_service_id_utf8_bytes");
            vec![b, a]
        }
        "empty_array" => {
            ensure!(case.reason == "item_count_out_of_bounds");
            Vec::new()
        }
        other => anyhow::bail!("unmapped rejected locator-array case {other}"),
    };
    ensure!(
        target(candidates).validate().is_err(),
        "{} unexpectedly passed RealmJoinTarget::validate",
        case.name
    );
    Ok(result(&case.name, 2))
}

fn run_authority_assertion_case(case: &AuthorityAssertionCase) -> Result<CaseExecutionResult> {
    match case.name.as_str() {
        "directory_stale_false_only" => {
            ensure!(case.expected == "reject_as_authority");
            let candidate: RealmJoinCandidate =
                serde_json::from_value(load_fixture()?.accepted_candidate)?;
            ensure!(candidate.source == AuthorityLocatorSource::Directory);
            candidate.validate()?;
            let error = converge_verified_realm_authorities(&[]).unwrap_err();
            ensure!(error == RealmAuthorityConvergenceError::NoVerifiedAuthority);
            Ok(result(&case.name, 4))
        }
        "invite_unexpired_only" => {
            ensure!(case.expected == "reject_as_authority");
            let mut candidate: RealmJoinCandidate =
                serde_json::from_value(load_fixture()?.accepted_candidate)?;
            candidate.source = AuthorityLocatorSource::Invite;
            candidate.validate()?;
            ensure!(
                converge_verified_realm_authorities(&[]).unwrap_err()
                    == RealmAuthorityConvergenceError::NoVerifiedAuthority
            );
            Ok(result(&case.name, 3))
        }
        "endpoint_reachable_only" => {
            ensure!(case.expected == "reject_as_authority");
            let candidate: RealmJoinCandidate =
                serde_json::from_value(load_fixture()?.accepted_candidate)?;
            candidate.validate()?;
            ensure!(
                candidate
                    .endpoint_url
                    .as_deref()
                    .is_some_and(|url| url.starts_with("https://"))
            );
            ensure!(
                converge_verified_realm_authorities(&[]).unwrap_err()
                    == RealmAuthorityConvergenceError::NoVerifiedAuthority
            );
            Ok(result(&case.name, 4))
        }
        "current_assertion_missing" => {
            ensure!(case.expected == "reject_join");
            let chain = signed_chain()?;
            let mut raw = serde_json::to_value(&chain.bundle)?;
            raw.as_object_mut()
                .context("authority bundle is not an object")?
                .remove("current_assertion");
            ensure!(serde_json::from_value::<RealmAuthorityBundle>(raw).is_err());
            ensure!(
                converge_verified_realm_authorities(&[]).unwrap_err()
                    == RealmAuthorityConvergenceError::NoVerifiedAuthority
            );
            Ok(result(&case.name, 3))
        }
        "current_assertion_expired" => {
            ensure!(case.expected == "reject_join");
            let mut chain = signed_chain()?;
            chain.bundle.current_assertion.expires_at = now() - Duration::seconds(1);
            resign_current_assertion(&mut chain.bundle, &signing_key(0xB2))?;
            let error = verify(&chain).unwrap_err();
            ensure!(matches!(error, RealmAuthorityChainError::NotFresh(_)));
            Ok(result(&case.name, 2))
        }
        "current_assertion_nonce_mismatch" => {
            ensure!(case.expected == "reject_join");
            let mut chain = signed_chain()?;
            chain.bundle.current_assertion.nonce =
                Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB".to_owned())
                    .map_err(anyhow::Error::msg)?;
            resign_current_assertion(&mut chain.bundle, &signing_key(0xB2))?;
            let error = verify(&chain).unwrap_err();
            ensure!(matches!(error, RealmAuthorityChainError::NotFresh(_)));
            Ok(result(&case.name, 2))
        }
        "verified_chain_and_valid_nonce_bound_current_assertion" => {
            ensure!(case.expected == "accept_current_authority");
            let chain = signed_chain()?;
            let verified = verify(&chain)?;
            let authorities = [verified];
            let current = converge_verified_realm_authorities(&authorities)?;
            ensure!(current.current_service_id() == &core_id(STATION_B)?);
            Ok(result(&case.name, 3))
        }
        other => anyhow::bail!("unmapped authority assertion case {other}"),
    }
}

fn run_authority_chain_case(
    case: &AuthorityChainCase,
    fixture: &FixtureRoot,
) -> Result<CaseExecutionResult> {
    match case.name.as_str() {
        "two_locators_converge_on_one_verified_chain" => {
            ensure!(case.candidate_count == Some(2));
            ensure!(case.verified_chain_count == Some(1));
            ensure!(case.expected == "forward_to_verified_current_governance_station");
            target(fixture.accepted_sorted_candidates.clone()).validate()?;
            let chain = signed_chain()?;
            let authorities = [verify(&chain)?, verify(&chain)?];
            let current = converge_verified_realm_authorities(&authorities)?;
            ensure!(current.current_service_id() == &core_id(STATION_B)?);
            Ok(result(&case.name, 5))
        }
        "locators_return_mutually_exclusive_valid_chains" => {
            ensure!(case.candidate_count == Some(2));
            ensure!(case.verified_chain_count == Some(2));
            ensure!(case.chains_are_mutually_exclusive == Some(true));
            ensure!(case.expected == "fail_closed");
            target(fixture.accepted_sorted_candidates.clone()).validate()?;
            let first_chain = signed_chain()?;
            let mut conflicting_chain = signed_chain()?;
            let transition = &mut conflicting_chain.bundle.authority_transitions[0];
            transition.handoff.snapshot_digest = hash('c')?;
            transition.handoff = seal_handoff(
                transition.handoff.clone(),
                &signing_key(0xA1),
                &signing_key(0xB2),
            )?;
            let authorities = [verify(&first_chain)?, verify(&conflicting_chain)?];
            ensure!(
                converge_verified_realm_authorities(&authorities).unwrap_err()
                    == RealmAuthorityConvergenceError::ConflictingVerifiedAuthorities
            );
            Ok(result(&case.name, 6))
        }
        "candidate_self_asserts_current_authority" => {
            ensure!(case.candidate_signature_valid == Some(true));
            ensure!(case.verified_genesis_and_handoff_chain == Some(false));
            ensure!(case.expected == "reject_as_authority");
            let mut raw = fixture.accepted_candidate.clone();
            // The production candidate type has no signature member or proof
            // context. Do not invent one here: closed parsing rejects the
            // member before hypothetical cryptographic validity can affect
            // authority.
            raw.as_object_mut()
                .context("accepted_candidate is not an object")?
                .insert("signature".to_owned(), Value::Null);
            ensure!(serde_json::from_value::<RealmJoinCandidate>(raw).is_err());
            ensure!(
                converge_verified_realm_authorities(&[]).unwrap_err()
                    == RealmAuthorityConvergenceError::NoVerifiedAuthority
            );
            Ok(result(&case.name, 4))
        }
        other => anyhow::bail!("unmapped authority-chain case {other}"),
    }
}

pub fn run_realm_join_candidate_suite() -> Result<RealmJoinCandidateExecution> {
    let fixture = load_fixture()?;
    validate_fixture_metadata(&fixture)?;
    validate_candidate_controls(&fixture)?;

    let mut cases = Vec::new();
    for field in &fixture.rejected_additional_members {
        cases.push(run_additional_member_case(field, &fixture)?);
    }
    for case in &fixture.rejected_locator_arrays {
        cases.push(run_locator_array_case(case)?);
    }
    for case in &fixture.authority_assertion_cases {
        cases.push(run_authority_assertion_case(case)?);
    }
    for case in &fixture.authority_chain_cases {
        cases.push(run_authority_chain_case(case, &fixture)?);
    }

    Ok(RealmJoinCandidateExecution {
        entrypoint: REALM_JOIN_CANDIDATE_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
    })
}

fn result(case_id: &str, assertions: usize) -> CaseExecutionResult {
    CaseExecutionResult {
        case_id: case_id.to_owned(),
        assertions,
    }
}

fn target(authority_locator_hints: Vec<RealmJoinCandidate>) -> RealmJoinTarget {
    RealmJoinTarget {
        realm_id: realm_id(),
        invite_id: None,
        authority_locator_hints,
    }
}

fn candidate(
    service_id: &str,
    source: &str,
    endpoint_url: Option<&str>,
) -> Result<RealmJoinCandidate> {
    let source = serde_json::from_value(Value::String(source.to_owned()))?;
    Ok(RealmJoinCandidate {
        service_kind: RealmJoinCandidateServiceKind::Station,
        service_id: DidCoreId::new(service_id.to_owned())?,
        endpoint_url: endpoint_url.map(str::to_owned),
        source,
    })
}

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_100, 0).unwrap()
}

fn issued_at() -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_050, 0).unwrap()
}

fn expires_at() -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_400, 0).unwrap()
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(key: &SigningKey) -> PublicKeyMaterial {
    PublicKeyMaterial::Ed25519Raw {
        bytes: key.verifying_key().to_bytes().to_vec(),
    }
}

fn multibase(key: &SigningKey) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
}

fn method(did: &str) -> Result<DidUrl> {
    DidUrl::new(format!("{did}#realm-authority")).map_err(anyhow::Error::msg)
}

fn core_id(did: &str) -> Result<DidCoreId> {
    Ok(project_did_to_core_id(&Did::new(did.to_owned())?)?)
}

fn realm_id() -> RealmId {
    RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x10; 32],
    ))
}

fn realm_stream() -> CommitStreamRef {
    CommitStreamRef::Realm {
        realm_id: realm_id(),
    }
}

fn hash(byte: char) -> Result<Hash> {
    Ok(Hash::new(format!(
        "sha256:{}",
        format!("{byte}{byte}").repeat(32)
    ))?)
}

fn placeholder_signature(context: DetachedSignatureContext) -> Result<DetachedObjectSignature> {
    Ok(DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: method(STATION_A)?,
        signed_digest: hash('1')?,
        created_at: issued_at(),
        sig: Base64UrlString::new("A".repeat(86)).map_err(anyhow::Error::msg)?,
    })
}

fn event(kind: EventKind, seconds: i64) -> Result<Event> {
    Ok(arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id(),
        },
        DidCoreId::new("ak:did_core:web:founder.example")?,
        core_id(STATION_A)?,
        json!({}),
        Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap(),
    )?)
}

fn seal_commit(mut commit: RealmCommit, did: &str, key: &SigningKey) -> Result<RealmCommit> {
    let unsigned = canonical::unsigned_value(&commit, &["signature"])?;
    commit.signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        method(did)?,
        issued_at(),
        key,
    )?;
    Ok(commit)
}

#[allow(clippy::too_many_arguments)]
fn commit(
    seed: u8,
    stream_position: u64,
    previous: Option<u8>,
    event_ref: &EventId,
    generation: u64,
    authority_ref: RealmCommitAuthorityRef,
    did: &str,
    key: &SigningKey,
) -> Result<RealmCommit> {
    seal_commit(
        RealmCommit {
            commit_id: RealmCommitId::from_digest([seed; 32]),
            realm_id: realm_id(),
            stream_ref: realm_stream(),
            stream_position,
            previous_commit_ref: previous.map(|byte| RealmCommitId::from_digest([byte; 32])),
            event_ref: event_ref.clone(),
            governance_generation: generation,
            authority_ref,
            committed_at: issued_at(),
            signature: placeholder_signature(DetachedSignatureContext::RealmCommit)?,
        },
        did,
        key,
    )
}

fn seal_handoff(
    mut handoff: RealmAuthorityHandoff,
    old_key: &SigningKey,
    new_key: &SigningKey,
) -> Result<RealmAuthorityHandoff> {
    let unsigned = canonical::unsigned_value(
        &handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )?;
    handoff.old_authority_signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        method(STATION_A)?,
        issued_at(),
        old_key,
    )?;
    handoff.new_authority_acceptance_signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        method(STATION_B)?,
        issued_at(),
        new_key,
    )?;
    Ok(handoff)
}

fn route_document(did: &str, key: &SigningKey) -> Result<DidDocument> {
    Ok(serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#realm-authority"),
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": multibase(key),
        }],
        "authentication": [format!("{did}#realm-authority")],
        "assertionMethod": [format!("{did}#realm-authority")],
        "service": [{
            "id": format!("{did}#station"),
            "type": "ArkretService",
            "serviceEndpoint": "https://station-b.example/",
            "serviceKind": "station",
        }],
    }))?)
}

fn route_record(did: &str, key: &SigningKey) -> Result<Value> {
    let resolution = build_authenticated_did_web_service_resolution(
        core_id(did)?,
        "station".to_owned(),
        route_document(did, key)?,
        now(),
    )?;
    Ok(serde_json::to_value(&resolution)?)
}

fn resign_current_assertion(bundle: &mut RealmAuthorityBundle, key: &SigningKey) -> Result<()> {
    let unsigned = canonical::unsigned_value(&bundle.current_assertion, &["signature"])?;
    bundle.current_assertion.signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        method(STATION_B)?,
        issued_at(),
        key,
    )?;
    Ok(())
}

fn signed_chain() -> Result<SignedChain> {
    let key_a = signing_key(0xA1);
    let key_b = signing_key(0xB2);
    let genesis_event = event(EventKind::RealmCreate, 0)?;
    let genesis_commit = commit(
        0x01,
        0,
        None,
        &genesis_event.event_id,
        0,
        RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis_event.event_id.clone()),
        STATION_A,
        &key_a,
    )?;
    let change_event = event(EventKind::MessageCreate, 1)?;
    let change_commit = commit(
        0x02,
        1,
        Some(0x01),
        &change_event.event_id,
        0,
        RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis_event.event_id.clone()),
        STATION_A,
        &key_a,
    )?;
    let handoff = seal_handoff(
        RealmAuthorityHandoff {
            handoff_id: RealmAuthorityHandoffId::from_digest([0x21; 32]),
            realm_id: realm_id(),
            from_generation: 0,
            to_generation: 1,
            from_service_id: core_id(STATION_A)?,
            to_service_id: core_id(STATION_B)?,
            final_stream_heads_digest: hash('a')?,
            snapshot_ref: RealmSnapshotId::from_digest([0x44; 32]),
            snapshot_digest: hash('b')?,
            change_event_ref: change_event.event_id.clone(),
            change_commit_id: change_commit.commit_id.clone(),
            old_authority_signature: placeholder_signature(
                DetachedSignatureContext::RealmAuthorityHandoffOld,
            )?,
            new_authority_acceptance_signature: placeholder_signature(
                DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            )?,
        },
        &key_a,
        &key_b,
    )?;
    let head = CommitStreamHead {
        stream_ref: realm_stream(),
        stream_position: 1,
        commit_id: change_commit.commit_id.clone(),
    };
    let assertion = RealmAuthorityCurrentAssertion {
        realm_id: realm_id(),
        current_generation: 1,
        current_service_id: core_id(STATION_B)?,
        last_handoff_ref: Some(handoff.handoff_id.clone()),
        realm_stream_head: head.clone(),
        nonce: Base64UrlString::new(NONCE.to_owned()).map_err(anyhow::Error::msg)?,
        expires_at: expires_at(),
        signature: placeholder_signature(DetachedSignatureContext::RealmAuthorityCurrentAssertion)?,
    };
    let mut bundle = RealmAuthorityBundle {
        realm_id: realm_id(),
        genesis_event,
        genesis_commit,
        authority_transitions: vec![RealmAuthorityTransition {
            change_event,
            change_commit,
            handoff,
        }],
        current_generation: 1,
        current_service_id: core_id(STATION_B)?,
        current_route_record: route_record(STATION_B, &key_b)?,
        realm_stream_head: head,
        bundle_issued_at: issued_at(),
        current_assertion: assertion,
    };
    resign_current_assertion(&mut bundle, &key_b)?;
    let keys = RealmAuthorityKeyMap::new()
        .with_key(&method(STATION_A)?, public(&key_a))
        .with_key(&method(STATION_B)?, public(&key_b));
    Ok(SignedChain { bundle, keys })
}

fn freshness() -> RealmAuthorityFreshness {
    RealmAuthorityFreshness::new(
        now(),
        Base64UrlString::new(NONCE.to_owned()).expect("fixed nonce"),
    )
}

fn verify(chain: &SignedChain) -> Result<VerifiedRealmAuthority, RealmAuthorityChainError> {
    verify_realm_authority_bundle(&chain.bundle, &freshness(), &chain.keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_fixture_executes_every_declared_case() -> Result<()> {
        let fixture = load_fixture()?;
        let execution = run_realm_join_candidate_suite()?;
        assert_eq!(execution.entrypoint, REALM_JOIN_CANDIDATE_ENTRYPOINT);
        assert_eq!(execution.cases.len(), 36);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
        let declared = fixture
            .rejected_additional_members
            .into_iter()
            .chain(
                fixture
                    .rejected_locator_arrays
                    .into_iter()
                    .map(|case| case.name),
            )
            .chain(
                fixture
                    .authority_assertion_cases
                    .into_iter()
                    .map(|case| case.name),
            )
            .chain(
                fixture
                    .authority_chain_cases
                    .into_iter()
                    .map(|case| case.name),
            )
            .collect::<Vec<_>>();
        assert_eq!(
            execution
                .cases
                .iter()
                .map(|case| case.case_id.as_str())
                .collect::<Vec<_>>(),
            declared.iter().map(String::as_str).collect::<Vec<_>>()
        );
        Ok(())
    }
}
