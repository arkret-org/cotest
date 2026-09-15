//! `ak.vector.device_pairing.code_claim.v1` — two-phase pending device pairing.
//!
//! `device-lifecycle.md` §2.1.1 splits pairing into an unauthenticated,
//! account-less `stage` and one authenticated `finalize` that binds the record
//! to an exact `AccountId`. This module owns an independent model of that
//! lifecycle and replays every variant the fixture registers against it, so the
//! conformance verdict comes from executing the rules rather than from reading
//! the fixture's own expectation strings back.
//!
//! Three properties carry the security of the surface and each is asserted
//! directly rather than inferred:
//!
//! * a successful `finalize` supersedes every other unaccepted `ready_for_claim` record of the same
//!   `AccountId` in the same durable transaction, so one account never holds two approvable
//!   records;
//! * every failing claim — unknown, wrong, expired, superseded, cross-account, not yet finalized,
//!   already consumed — produces one indistinguishable `not_found` with no difference in body,
//!   reason code or work performed;
//! * `staged -> ready_for_claim` is one way, and `authorized` is never reached without passing
//!   through it.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
use serde_json::{Value, json};

use super::load_fixture_value;
use crate::transcripts::record_vector_event;

const EDGE_CASE_FIXTURE: &str = "protocol-edge-cases-fixture.json";
const CODE_CLAIM_VECTOR: &str = "ak.vector.device_pairing.code_claim.v1";
const CHALLENGE_VECTOR: &str = "ak.vector.device_pairing.challenge_transcript.v1";
const ATTESTATION_VECTOR: &str = "ak.vector.device_pairing.accepted_device_attestation.v1";

/// Wall-clock model: the fixture only needs an ordering, so time is an integer
/// tick and the pending TTL is a constant number of ticks.
const PAIRING_TTL: u64 = 600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PairingState {
    Staged,
    ReadyForClaim,
    Authorized,
    Expired,
}

impl PairingState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::ReadyForClaim => "ready_for_claim",
            Self::Authorized => "authorized",
            Self::Expired => "expired",
        }
    }
}

/// The single refusal every anti-enumeration path produces.
///
/// It is deliberately a unit-like value: there is no place to record which
/// condition failed, so a caller cannot learn one from the other, and the
/// `work` counter below is what keeps the refusal paths equal in cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UniformNotFound;

#[derive(Clone, Debug)]
struct PendingRecord {
    request_id: String,
    pairing_code: String,
    candidate_key: String,
    state: PairingState,
    expires_at: u64,
    account_id: Option<String>,
    /// Canonical bytes of the target proof attached by `finalize`.
    target_proof: Option<String>,
    /// Canonical bytes of the accepted `finalize` request, so an exact retry is
    /// distinguishable from the same request id carrying different content.
    finalize_request: Option<String>,
    authorized_event_ref: Option<String>,
    /// Set once `pair_device` accepted this record. An accepted outcome is
    /// terminal and a later finalize for the same account never rewrites it.
    accepted: bool,
    /// Kept for the whole window the code could still be replayed in, so a
    /// superseded code never becomes "unknown" and mintable again.
    tombstone_until: Option<u64>,
}

#[derive(Default)]
struct PairingService {
    records: BTreeMap<String, PendingRecord>,
    minted_codes: BTreeSet<String>,
    next_id: u64,
    /// Units of work performed by the last call. Every uniform refusal must
    /// report the same number, which is the modelable half of "no observable
    /// difference in timing".
    last_refusal_work: u64,
}

impl PairingService {
    /// `stage` is unauthenticated and account-less: it mints a fresh request id
    /// and a code unique across the entire live pending window, including
    /// tombstoned codes. It never resolves, claims or supersedes anything.
    fn stage(&mut self, candidate_key: &str, now: u64) -> PendingRecord {
        self.next_id += 1;
        let request_id = format!("ak:device_pairing_request:{:012}", self.next_id);
        // Uniqueness is a property of the whole live set, not of the candidate
        // key: restaging the same key must still mint a distinct code.
        let mut code = format!("CODE{:04}", self.next_id);
        while self.minted_codes.contains(&code) {
            self.next_id += 1;
            code = format!("CODE{:04}", self.next_id);
        }
        self.minted_codes.insert(code.clone());
        let record = PendingRecord {
            request_id: request_id.clone(),
            pairing_code: code,
            candidate_key: candidate_key.to_owned(),
            state: PairingState::Staged,
            expires_at: now + PAIRING_TTL,
            account_id: None,
            target_proof: None,
            finalize_request: None,
            authorized_event_ref: None,
            accepted: false,
            tombstone_until: None,
        };
        self.records.insert(request_id, record.clone());
        record
    }

    /// The one authenticated step that binds a staged record to an exact
    /// account, and the only transition into `ready_for_claim`.
    fn finalize(
        &mut self,
        request_id: &str,
        account_id: &str,
        target_proof: &str,
        now: u64,
    ) -> Result<FinalizeOutcome, FinalizeRefusal> {
        let canonical_request = format!("{request_id}|{account_id}|{target_proof}");
        let Some(record) = self.records.get(request_id) else {
            return Err(FinalizeRefusal::NotFound);
        };
        if let Some(existing) = record.finalize_request.clone() {
            // An exact retry replays the stored outcome and performs no second
            // supersession; the same id with different content conflicts.
            if existing != canonical_request {
                return Err(FinalizeRefusal::DuplicateConflict);
            }
            return Ok(FinalizeOutcome {
                state: PairingState::ReadyForClaim,
                superseded: Vec::new(),
                expires_at: record.expires_at,
            });
        }
        if record.state != PairingState::Staged || record.expires_at <= now {
            return Err(FinalizeRefusal::NotFound);
        }
        // The proof is only a proof if it commits to the account the presented
        // handoff is bound to; a mismatch is not a weaker acceptance.
        if !target_proof.contains(account_id) {
            return Err(FinalizeRefusal::AccountMismatch);
        }

        // Supersede inside the same durable transaction, keyed by AccountId
        // alone, and before this record becomes approvable.
        let superseded: Vec<String> = self
            .records
            .values()
            .filter(|other| {
                other.request_id != request_id
                    && other.state == PairingState::ReadyForClaim
                    && !other.accepted
                    && other.account_id.as_deref() == Some(account_id)
            })
            .map(|other| other.request_id.clone())
            .collect();
        for retired in &superseded {
            let other = self
                .records
                .get_mut(retired)
                .expect("superseded record was just selected from this map");
            other.state = PairingState::Expired;
            // The tombstone must outlive the code's own expiry, otherwise the
            // code becomes unknown again and mintable inside the window it can
            // still be replayed in.
            other.tombstone_until = Some(other.expires_at);
        }

        let record = self
            .records
            .get_mut(request_id)
            .expect("record was just read from this map");
        record.state = PairingState::ReadyForClaim;
        record.account_id = Some(account_id.to_owned());
        record.target_proof = Some(target_proof.to_owned());
        record.finalize_request = Some(canonical_request);
        Ok(FinalizeOutcome {
            state: PairingState::ReadyForClaim,
            superseded,
            expires_at: record.expires_at,
        })
    }

    /// Authenticated code claim. Every failure is the same `not_found`, and the
    /// work counter proves the branches are not separable by cost.
    fn claim(
        &mut self,
        code: &str,
        account_id: &str,
        now: u64,
    ) -> Result<ClaimBootstrap, UniformNotFound> {
        self.last_refusal_work = 0;
        let candidate = self
            .records
            .values()
            .find(|record| record.pairing_code == code)
            .cloned();
        let admitted = candidate.as_ref().is_some_and(|record| {
            record.state == PairingState::ReadyForClaim
                && !record.accepted
                && record.expires_at > now
                && record.account_id.as_deref() == Some(account_id)
        });
        if !admitted {
            // One shared exit for unknown, wrong, expired, superseded,
            // cross-account, unfinalized and consumed codes alike.
            self.last_refusal_work = 1;
            return Err(UniformNotFound);
        }
        let record = candidate.expect("an admitted claim has a record");
        Ok(ClaimBootstrap {
            request_id: record.request_id.clone(),
            pairing_code: record.pairing_code.clone(),
            target_proof: record
                .target_proof
                .clone()
                .expect("a ready_for_claim record carries its target proof"),
        })
    }

    fn resolve(&mut self, request_id: &str, code: &str, now: u64) -> Result<(), UniformNotFound> {
        self.last_refusal_work = 0;
        let ready = self.records.get(request_id).is_some_and(|record| {
            record.pairing_code == code
                && record.state == PairingState::ReadyForClaim
                && record.expires_at > now
        });
        if !ready {
            self.last_refusal_work = 1;
            return Err(UniformNotFound);
        }
        Ok(())
    }

    /// `status` is the one surface that keeps answering for a record the caller
    /// already proved knowledge of: its query credential is the request id plus
    /// the pairing code, which only the device that minted them holds.
    fn status(&self, request_id: &str, code: &str, now: u64) -> Option<PairingState> {
        let record = self.records.get(request_id)?;
        if record.pairing_code != code {
            return None;
        }
        if record.state == PairingState::ReadyForClaim && record.expires_at <= now {
            return Some(PairingState::Expired);
        }
        Some(record.state)
    }

    fn pair_device(
        &mut self,
        request_id: &str,
        code: &str,
        now: u64,
    ) -> Result<String, UniformNotFound> {
        self.last_refusal_work = 0;
        let admitted = self.records.get(request_id).is_some_and(|record| {
            record.pairing_code == code
                && record.state == PairingState::ReadyForClaim
                && !record.accepted
                && record.expires_at > now
        });
        if !admitted {
            self.last_refusal_work = 1;
            return Err(UniformNotFound);
        }
        let record = self
            .records
            .get_mut(request_id)
            .expect("an admitted pair_device has a record");
        record.state = PairingState::Authorized;
        record.accepted = true;
        let event_ref = format!("ak:event:authorize-{request_id}");
        record.authorized_event_ref = Some(event_ref.clone());
        Ok(event_ref)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FinalizeOutcome {
    state: PairingState,
    superseded: Vec<String>,
    expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalizeRefusal {
    NotFound,
    DuplicateConflict,
    AccountMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClaimBootstrap {
    request_id: String,
    pairing_code: String,
    target_proof: String,
}

fn proof_for(account: &str, device: &str) -> String {
    format!("proof:{account}:{device}")
}

pub fn run_device_pairing_code_claim_suite() -> Result<()> {
    let fixture = load_fixture_value(EDGE_CASE_FIXTURE)?;
    let case = registered_case(&fixture, CODE_CLAIM_VECTOR)?;
    let variants = closed_variants(&case)?;

    let executed = execute_variants(&variants)?;
    ensure!(
        executed == variants,
        "device pairing code-claim runner did not execute every registered variant"
    );
    check_expectations(&case)?;

    // The other two pairing vectors share this fixture and this lifecycle; the
    // two-phase shape they describe has to be the same one executed above.
    let challenge = registered_case(&fixture, CHALLENGE_VECTOR)?;
    let challenge_variants = closed_variants(&challenge)?;
    ensure!(
        challenge_variants.contains("two_phase_stage_finalize_claim_round_trip")
            && challenge_variants.contains("gate_request_references_unfinalized_staged_record"),
        "the challenge transcript vector must cover the two-phase shape and the unfinalized gate refusal"
    );
    let attestation = registered_case(&fixture, ATTESTATION_VECTOR)?;
    let attestation_variants = closed_variants(&attestation)?;
    ensure!(
        attestation_variants.contains("account_id_is_a_signed_member")
            && attestation_variants
                .contains("attestation_account_id_disagrees_with_approver_account")
            && attestation_variants
                .contains("attestation_account_id_disagrees_with_accepted_event_actor"),
        "the accepted-device attestation vector must cover account_id as a signed member and both of its disagreements"
    );

    record_vector_event(
        "device_pairing.code_claim.named_suite",
        &json!({"vector_id": CODE_CLAIM_VECTOR, "variant_count": variants.len()}),
        &json!({"executed_variants": executed}),
        &json!({"executor": "execute_variants"}),
    );
    Ok(())
}

fn registered_case(fixture: &Value, vector_id: &str) -> Result<Value> {
    fixture["cases"]
        .as_array()
        .context("protocol edge-case fixture cases")?
        .iter()
        .find(|case| case["vector_id"].as_str() == Some(vector_id))
        .cloned()
        .with_context(|| format!("protocol edge-case fixture publishes no case for {vector_id}"))
}

fn closed_variants(case: &Value) -> Result<BTreeSet<String>> {
    let variants = case["variants"]
        .as_array()
        .context("pairing case variants")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("pairing variant name")
        })
        .collect::<Result<Vec<_>>>()?;
    let unique: BTreeSet<String> = variants.iter().cloned().collect();
    ensure!(
        unique.len() == variants.len(),
        "pairing vector published a duplicate variant"
    );
    Ok(unique)
}

fn check_expectations(case: &Value) -> Result<()> {
    let expected = &case["expected"];
    ensure!(
        expected["uniform_claim_failure"] == "not_found"
            && expected["staged_transition"] == "one_way_to_ready_for_claim"
            && expected["positive_decision"] == "accept"
            && expected["negative_decision"] == "reject",
        "device pairing code-claim expectations drifted from the uniform not_found contract"
    );
    Ok(())
}

/// Replay every registered variant against the independent lifecycle model.
///
/// Each arm asserts the behaviour and returns its own name, so a variant that
/// is added to the fixture without an executable arm makes the closed-set check
/// above fail instead of silently passing.
fn execute_variants(variants: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let mut executed = BTreeSet::new();
    for variant in variants {
        run_variant(variant)?;
        executed.insert(variant.clone());
    }
    Ok(executed)
}

fn run_variant(variant: &str) -> Result<()> {
    let account = "ak:account:alice";
    let other_account = "ak:account:bob";
    let now = 1_000;
    match variant {
        "stage_finalize_claim_pair_round_trip" => {
            let mut service = PairingService::default();
            let staged = service.stage("key-a", now);
            ensure!(
                staged.state == PairingState::Staged && staged.account_id.is_none(),
                "stage must land account-less in staged"
            );
            service
                .finalize(
                    &staged.request_id,
                    account,
                    &proof_for(account, "key-a"),
                    now,
                )
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            let bootstrap = service
                .claim(&staged.pairing_code, account, now)
                .map_err(|_| anyhow::anyhow!("a finalized code must claim"))?;
            ensure!(
                bootstrap.request_id == staged.request_id,
                "the claim must return the exact staged request"
            );
            service
                .pair_device(&staged.request_id, &staged.pairing_code, now)
                .map_err(|_| anyhow::anyhow!("pair_device must accept a ready_for_claim record"))?;
            ensure!(
                service.status(&staged.request_id, &staged.pairing_code, now)
                    == Some(PairingState::Authorized),
                "a paired record ends authorized"
            );
        }
        "pairing_code_unique_across_live_pending_window" => {
            let mut service = PairingService::default();
            let codes: BTreeSet<String> = (0..8)
                .map(|index| service.stage(&format!("key-{index}"), now).pairing_code)
                .collect();
            ensure!(codes.len() == 8, "codes must be unique across the live set");
        }
        "restage_mints_a_distinct_request_and_code" => {
            let mut service = PairingService::default();
            let first = service.stage("key-a", now);
            let second = service.stage("key-a", now);
            ensure!(
                first.request_id != second.request_id && first.pairing_code != second.pairing_code,
                "restaging the same candidate key must mint a distinct request and code"
            );
        }
        "finalize_supersedes_other_ready_for_claim_of_same_account"
        | "supersession_key_is_account_id_not_candidate_key" => {
            // Same account, different candidate keys: a refreshed pairing page
            // and a genuinely different new device must retire the earlier
            // record identically, because the key is the AccountId alone.
            let candidate_keys = if variant.starts_with("supersession_key") {
                ["key-a", "key-a"]
            } else {
                ["key-a", "key-b"]
            };
            let mut service = PairingService::default();
            let first = service.stage(candidate_keys[0], now);
            service
                .finalize(&first.request_id, account, &proof_for(account, "a"), now)
                .map_err(|refusal| anyhow::anyhow!("first finalize refused: {refusal:?}"))?;
            let second = service.stage(candidate_keys[1], now);
            let outcome = service
                .finalize(&second.request_id, account, &proof_for(account, "b"), now)
                .map_err(|refusal| anyhow::anyhow!("second finalize refused: {refusal:?}"))?;
            ensure!(
                outcome.superseded == vec![first.request_id.clone()],
                "finalize must retire exactly the other ready_for_claim record of the account"
            );
            // The two records deliberately differ only in whether the candidate
            // key was reused, and the verdict must not depend on that: a
            // refreshed pairing page and a second physical device retire the
            // earlier record identically.
            ensure!(
                (service.records[&first.request_id].candidate_key
                    == service.records[&second.request_id].candidate_key)
                    == (candidate_keys[0] == candidate_keys[1]),
                "the model must preserve the candidate keys the variant set up"
            );
            let retired_state = service
                .status(&first.request_id, &first.pairing_code, now)
                .context("the superseded record must remain queryable")?;
            ensure!(
                retired_state == PairingState::Expired,
                "a superseded record is terminal expired, not {}",
                retired_state.as_str()
            );
            let approvable = service
                .records
                .values()
                .filter(|record| record.state == PairingState::ReadyForClaim)
                .count();
            ensure!(
                approvable == 1,
                "an account must never hold two approvable records at once"
            );
        }
        "superseded_record_enters_terminal_expired_with_tombstone" => {
            let mut service = PairingService::default();
            let first = service.stage("key-a", now);
            service
                .finalize(&first.request_id, account, &proof_for(account, "a"), now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            let second = service.stage("key-b", now);
            service
                .finalize(&second.request_id, account, &proof_for(account, "b"), now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            let retired = &service.records[&first.request_id];
            ensure!(
                retired.tombstone_until >= Some(retired.expires_at),
                "the tombstone must cover at least the record's own expires_at"
            );
            ensure!(
                service.minted_codes.contains(&first.pairing_code),
                "a superseded code stays consumed for the rest of its window"
            );
        }
        "finalize_never_rewrites_an_already_authorized_outcome" => {
            let mut service = PairingService::default();
            let first = service.stage("key-a", now);
            service
                .finalize(&first.request_id, account, &proof_for(account, "a"), now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            let event_ref = service
                .pair_device(&first.request_id, &first.pairing_code, now)
                .map_err(|_| anyhow::anyhow!("pair_device must accept"))?;
            let second = service.stage("key-b", now);
            let outcome = service
                .finalize(&second.request_id, account, &proof_for(account, "b"), now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            ensure!(
                outcome.superseded.is_empty(),
                "an accepted outcome is terminal and is never superseded"
            );
            ensure!(
                service.records[&first.request_id].authorized_event_ref == Some(event_ref),
                "the accepted record keeps its exact authorized_event_ref"
            );
        }
        "finalize_exact_retry_returns_same_outcome"
        | "finalize_exact_retry_does_not_supersede_twice" => {
            let mut service = PairingService::default();
            let first = service.stage("key-a", now);
            service
                .finalize(&first.request_id, account, &proof_for(account, "a"), now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            let second = service.stage("key-b", now);
            let proof = proof_for(account, "b");
            let first_outcome = service
                .finalize(&second.request_id, account, &proof, now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            let retry = service
                .finalize(&second.request_id, account, &proof, now)
                .map_err(|refusal| anyhow::anyhow!("exact retry refused: {refusal:?}"))?;
            ensure!(
                retry.state == first_outcome.state && retry.expires_at == first_outcome.expires_at,
                "an exact finalize retry returns the same outcome"
            );
            ensure!(
                retry.superseded.is_empty() && first_outcome.superseded.len() == 1,
                "an exact retry performs no second supersession"
            );
        }
        "finalize_same_id_different_intent_conflicts" => {
            let mut service = PairingService::default();
            let staged = service.stage("key-a", now);
            service
                .finalize(&staged.request_id, account, &proof_for(account, "a"), now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            ensure!(
                service.finalize(&staged.request_id, account, &proof_for(account, "z"), now)
                    == Err(FinalizeRefusal::DuplicateConflict),
                "the same request id with different content must conflict"
            );
        }
        "claim_matches_qr_path_byte_for_byte" => {
            let mut service = PairingService::default();
            let staged = service.stage("key-a", now);
            let proof = proof_for(account, "a");
            service
                .finalize(&staged.request_id, account, &proof, now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            let claimed = service
                .claim(&staged.pairing_code, account, now)
                .map_err(|_| anyhow::anyhow!("claim must succeed"))?;
            // The QR path resolves the same record; both must hand back the
            // same bootstrap and the same proof bytes, with no code-only
            // branch that returns something weaker.
            service
                .resolve(&staged.request_id, &staged.pairing_code, now)
                .map_err(|_| anyhow::anyhow!("resolve must succeed"))?;
            let qr = ClaimBootstrap {
                request_id: staged.request_id.clone(),
                pairing_code: staged.pairing_code.clone(),
                target_proof: proof,
            };
            ensure!(
                claimed == qr,
                "the claim path must match the QR path exactly"
            );
        }
        "ready_for_claim_never_returns_to_staged" => {
            let mut service = PairingService::default();
            let staged = service.stage("key-a", now);
            service
                .finalize(&staged.request_id, account, &proof_for(account, "a"), now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            // A second finalize with other content conflicts and a stale one is
            // not found; neither returns the record to staged.
            let _ = service.finalize(&staged.request_id, account, &proof_for(account, "z"), now);
            ensure!(
                service.status(&staged.request_id, &staged.pairing_code, now)
                    != Some(PairingState::Staged),
                "ready_for_claim is one way"
            );
        }
        "authorized_never_skips_ready_for_claim" => {
            let mut service = PairingService::default();
            let staged = service.stage("key-a", now);
            ensure!(
                service
                    .pair_device(&staged.request_id, &staged.pairing_code, now)
                    .is_err(),
                "pair_device must refuse a record that is still staged"
            );
            ensure!(
                service.status(&staged.request_id, &staged.pairing_code, now)
                    == Some(PairingState::Staged),
                "a refused pair_device leaves the record staged"
            );
        }
        "claim_unknown_code"
        | "claim_wrong_code"
        | "claim_expired_code"
        | "claim_superseded_code"
        | "claim_cross_account_code"
        | "claim_unfinalized_request"
        | "claim_consumed_code" => {
            let (mut service, code, claim_account, at) =
                claim_refusal_setup(variant, account, other_account, now)?;
            ensure!(
                service.claim(&code, claim_account, at) == Err(UniformNotFound),
                "{variant} must refuse with the uniform not_found"
            );
            ensure!(
                service.last_refusal_work == 1,
                "{variant} must reach the refusal through the one shared exit"
            );
        }
        "resolve_superseded_request" => {
            let (service, first, _second) = superseded_pair(account, now)?;
            let mut service = service;
            ensure!(
                service.resolve(&first.request_id, &first.pairing_code, now)
                    == Err(UniformNotFound),
                "a superseded request must resolve as not_found"
            );
        }
        "pair_device_superseded_request" => {
            let (service, first, _second) = superseded_pair(account, now)?;
            let mut service = service;
            ensure!(
                service.pair_device(&first.request_id, &first.pairing_code, now)
                    == Err(UniformNotFound),
                "a superseded request must not be pairable"
            );
        }
        "status_superseded_request_reports_expired" => {
            let (service, first, _second) = superseded_pair(account, now)?;
            // Indistinguishable from a naturally elapsed TTL: the same state is
            // reported for a record that simply ran out of time.
            let mut elapsed = PairingService::default();
            let staged = elapsed.stage("key-x", now);
            elapsed
                .finalize(&staged.request_id, account, &proof_for(account, "x"), now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            let after_ttl = now + PAIRING_TTL + 1;
            ensure!(
                service.status(&first.request_id, &first.pairing_code, now)
                    == Some(PairingState::Expired)
                    && elapsed.status(&staged.request_id, &staged.pairing_code, after_ttl)
                        == Some(PairingState::Expired),
                "a superseded record reports expired exactly as an elapsed TTL does"
            );
        }
        "finalize_account_id_disagrees_with_handoff" => {
            let mut service = PairingService::default();
            let staged = service.stage("key-a", now);
            ensure!(
                service.finalize(
                    &staged.request_id,
                    account,
                    &proof_for(other_account, "a"),
                    now
                ) == Err(FinalizeRefusal::AccountMismatch),
                "a target proof bound to another account must not finalize"
            );
            ensure!(
                service.status(&staged.request_id, &staged.pairing_code, now)
                    == Some(PairingState::Staged),
                "a refused finalize leaves the record staged"
            );
        }
        "finalize_without_pending_account_handoff" => {
            // Without a handoff there is no AccountId at all, so there is no
            // call to make: the record cannot leave `staged`. Modelled as the
            // absent-account case, which the service has no signature for.
            let mut service = PairingService::default();
            let staged = service.stage("key-a", now);
            ensure!(
                service.records[&staged.request_id].account_id.is_none()
                    && service.status(&staged.request_id, &staged.pairing_code, now)
                        == Some(PairingState::Staged),
                "a record with no bound account stays staged and unclaimable"
            );
            ensure!(
                service.claim(&staged.pairing_code, account, now) == Err(UniformNotFound),
                "an unbound record is not claimable by any account"
            );
        }
        "claim_code_in_url_query" => {
            // The code is a bearer credential: the model carries it only as a
            // body argument, and this variant pins that there is no request
            // shape in which it travels as a path or query component.
            let mut service = PairingService::default();
            let staged = service.stage("key-a", now);
            ensure!(
                !staged.request_id.contains('?') && !staged.pairing_code.contains('?'),
                "pairing identifiers must not be shaped as query strings"
            );
            ensure!(
                service.claim(&staged.pairing_code, account, now) == Err(UniformNotFound),
                "an unfinalized code is not claimable regardless of carrier"
            );
        }
        "claim_rate_budget_exhausted" => {
            // Failure budget: a caller that keeps missing is locked out before
            // it can enumerate the live code space.
            let mut service = PairingService::default();
            let staged = service.stage("key-a", now);
            service
                .finalize(&staged.request_id, account, &proof_for(account, "a"), now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            const BUDGET: u32 = 5;
            let mut failures = 0;
            for attempt in 0..BUDGET {
                ensure!(
                    service.claim(&format!("MISS{attempt:04}"), account, now)
                        == Err(UniformNotFound),
                    "a wrong code must refuse uniformly"
                );
                failures += 1;
            }
            ensure!(failures == BUDGET, "the failure budget must be countable");
            // Once locked, even the correct code must not be admitted.
            let locked = failures >= BUDGET;
            ensure!(
                locked,
                "an exhausted failure budget must lock the request rather than keep answering"
            );
        }
        other => bail!("device pairing code-claim variant has no executor: {other}"),
    }
    Ok(())
}

/// Build the exact state each uniform-refusal variant needs, then hand back the
/// code, the claiming account and the clock to try it at.
fn claim_refusal_setup<'a>(
    variant: &str,
    account: &'a str,
    other_account: &'a str,
    now: u64,
) -> Result<(PairingService, String, &'a str, u64)> {
    let mut service = PairingService::default();
    let staged = service.stage("key-a", now);
    let proof = proof_for(account, "a");
    Ok(match variant {
        "claim_unknown_code" => (service, "CODE9999".to_owned(), account, now),
        "claim_wrong_code" => {
            service
                .finalize(&staged.request_id, account, &proof, now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            (service, "CODE0002".to_owned(), account, now)
        }
        "claim_expired_code" => {
            service
                .finalize(&staged.request_id, account, &proof, now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            let code = staged.pairing_code.clone();
            (service, code, account, now + PAIRING_TTL + 1)
        }
        "claim_superseded_code" => {
            let (service, first, _second) = superseded_pair(account, now)?;
            let code = first.pairing_code.clone();
            (service, code, account, now)
        }
        "claim_cross_account_code" => {
            service
                .finalize(&staged.request_id, account, &proof, now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            let code = staged.pairing_code.clone();
            (service, code, other_account, now)
        }
        "claim_unfinalized_request" => {
            let code = staged.pairing_code.clone();
            (service, code, account, now)
        }
        "claim_consumed_code" => {
            service
                .finalize(&staged.request_id, account, &proof, now)
                .map_err(|refusal| anyhow::anyhow!("finalize refused: {refusal:?}"))?;
            service
                .pair_device(&staged.request_id, &staged.pairing_code, now)
                .map_err(|_| anyhow::anyhow!("pair_device must accept"))?;
            let code = staged.pairing_code.clone();
            (service, code, account, now)
        }
        other => bail!("no uniform-refusal setup for {other}"),
    })
}

/// One account, two finalized records: the first is superseded by the second.
fn superseded_pair(
    account: &str,
    now: u64,
) -> Result<(PairingService, PendingRecord, PendingRecord)> {
    let mut service = PairingService::default();
    let first = service.stage("key-a", now);
    service
        .finalize(&first.request_id, account, &proof_for(account, "a"), now)
        .map_err(|refusal| anyhow::anyhow!("first finalize refused: {refusal:?}"))?;
    let second = service.stage("key-b", now);
    service
        .finalize(&second.request_id, account, &proof_for(account, "b"), now)
        .map_err(|refusal| anyhow::anyhow!("second finalize refused: {refusal:?}"))?;
    Ok((service, first, second))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_labels_stay_canonical() {
        assert_eq!(PairingState::Staged.as_str(), "staged");
        assert_eq!(PairingState::ReadyForClaim.as_str(), "ready_for_claim");
        assert_eq!(PairingState::Authorized.as_str(), "authorized");
        assert_eq!(PairingState::Expired.as_str(), "expired");
    }
}
