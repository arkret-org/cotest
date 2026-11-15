//! Independent single-create durability model over the formal complete R/C.
//! Native authorization and storage are exercised by their separate live suites.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
use ed25519_dalek::Signer as _;
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq)]
struct AtomicState {
    request: Vec<u8>,
    outcome: Value,
    commits: Value,
    generation: Value,
    device: Value,
    session: &'static str,
    content_recovery_fence: Value,
}
#[derive(Clone)]
struct Ledger {
    head: Value,
    generation: Value,
    frozen: Option<Vec<u8>>,
    accepted: BTreeMap<Vec<u8>, AtomicState>,
}
#[derive(Clone, Debug, PartialEq)]
enum Attempt {
    Accepted(Value),
    LostResponse,
    Crashed,
}
impl Ledger {
    fn new(kat: &Value) -> Self {
        Self {
            head: kat["qualified_inputs"]["predecessor_ref"].clone(),
            generation: kat["qualified_inputs"]["current_generation"].clone(),
            frozen: None,
            accepted: BTreeMap::new(),
        }
    }
    fn freeze(&mut self, r: &Value, has_key: bool) -> Result<Vec<u8>> {
        let body = arkret_canonical::canonical_json_bytes(
            &json!({"kind":"recovery","recovery_receipt":r}),
        )?;
        if let Some(original) = &self.frozen {
            ensure!(original == &body, "duplicate_conflict");
            return Ok(body);
        }
        ensure!(has_key, "staged_secret_lost");
        self.frozen = Some(body.clone());
        Ok(body)
    }
    fn submit(
        &mut self,
        r: &Value,
        q: &Value,
        kat: &Value,
        crash_before: bool,
        lost_response: bool,
    ) -> Result<Attempt> {
        ensure!(
            q["current_reader_authorized"] == true && q["account_id"] == r["account_id"],
            "current_reader_unauthorized"
        );
        let body = arkret_canonical::canonical_json_bytes(
            &json!({"kind":"recovery","recovery_receipt":r}),
        )?;
        let key = arkret_canonical::canonical_json_bytes(
            &json!({"account_id":r["account_id"],"transaction_id":r["transaction_id"]}),
        )?;
        if let Some(accepted) = self.accepted.get(&key) {
            ensure!(accepted.request == body, "duplicate_conflict");
            return Ok(Attempt::Accepted(accepted.outcome.clone()));
        }
        ensure!(
            self.frozen.as_ref() == Some(&body),
            "signed R was not durable before network"
        );
        for field in [
            "account_id",
            "recovery_session_id",
            "session_grant_ref",
            "session_grant_cnf_jkt",
            "policy_id",
            "policy_version",
            "trust_domain",
            "new_device_id",
            "proof_summary",
            "previous_model_generation_ref",
        ] {
            ensure!(r[field] == q[field], "source_binding_mismatch");
        }
        ensure!(
            q["policy_active"] == true
                && q["session_verified"] == true
                && q["grant_active"] == true
                && q["session_consumed"] == false
                && q["candidate_already_authorized"] == false,
            "source_not_current"
        );
        ensure!(
            r["previous_model_generation_ref"] == self.generation
                && r["recovery_unit"]["predecessor_ref"] == self.head,
            "generation_or_head_conflict"
        );
        for deadline in [
            &r["expires_at"],
            &q["session_expires_at"],
            &q["grant_expires_at"],
        ] {
            ensure!(
                instant(&q["now"])? < instant(deadline)?,
                "expired_before_first_acceptance"
            );
        }
        ensure!(
            r == &kat["expected_outcome"]["recovery_receipt"],
            "signed receipt changed"
        );
        if crash_before {
            return Ok(Attempt::Crashed);
        }
        let state = AtomicState {
            request: body,
            outcome: kat["expected_outcome"].clone(),
            commits: kat["native_commits"].clone(),
            generation: r["new_model_generation_ref"].clone(),
            device: r["new_device_id"].clone(),
            session: "completed",
            content_recovery_fence: r["recovery_unit"]["events"][0]["event"]["event_id"].clone(),
        };
        // Build the whole next record first. A process can observe either the
        // old state or every Event/Commit/generation/Device/Session/fence/C.
        let mut next = self.clone();
        next.head = state.commits[1]["commit_id"].clone();
        next.generation = state.generation.clone();
        next.accepted.insert(key, state.clone());
        *self = next;
        Ok(if lost_response {
            Attempt::LostResponse
        } else {
            Attempt::Accepted(state.outcome)
        })
    }
}
fn instant(value: &Value) -> Result<chrono::DateTime<chrono::Utc>> {
    Ok(
        chrono::DateTime::parse_from_rfc3339(value.as_str().context("timestamp")?)?
            .with_timezone(&chrono::Utc),
    )
}
fn kat() -> Result<Value> {
    Ok(super::load_fixture_value("security-transaction-resilience-fixture.json")?["single_submit_recovery_kat"].clone())
}

pub fn run_recovery_transaction_fault_matrix() -> Result<()> {
    let kat = kat()?;
    super::run_recovery_completion_grant_suite()?;
    let r = &kat["receipt"];
    let q = &kat["qualified_inputs"];
    let mut executed = 0;
    for position in [
        "before_commit",
        "after_commit_before_local_observe",
        "after_local_observe_before_response",
    ] {
        for fault in [
            "crash",
            "response_lost",
            "coordinator_restart",
            "exact_request_replay",
            "conflicting_request_replay",
            "staged_secret_lost",
            "terminal_replay",
        ] {
            let mut ledger = Ledger::new(&kat);
            if fault == "staged_secret_lost" {
                ensure!(
                    ledger.freeze(r, false).unwrap_err().to_string() == "staged_secret_lost"
                        && ledger.accepted.is_empty()
                        && ledger.frozen.is_none(),
                    "missing authoring key published an unfrozen receipt"
                );
            }
            let frozen = ledger.freeze(r, true)?;
            ensure!(
                ledger.freeze(r, false)? == frozen,
                "loss of authoring key invalidated complete durable R"
            );
            let interrupted = matches!(fault, "crash" | "response_lost" | "coordinator_restart");
            let first = ledger.submit(
                r,
                q,
                &kat,
                position == "before_commit" && interrupted,
                interrupted,
            )?;
            if first == Attempt::Crashed {
                ensure!(
                    ledger.accepted.is_empty()
                        && ledger.head == q["predecessor_ref"]
                        && ledger.generation == q["current_generation"],
                    "pre-commit crash exposed partial effects"
                );
            }
            let mut restarted = ledger.clone();
            let recovered = restarted.submit(r, q, &kat, false, false)?;
            ensure!(
                recovered == Attempt::Accepted(kat["expected_outcome"].clone())
                    && restarted.accepted.len() == 1,
                "response-loss/restart did not converge to one atomic closure"
            );
            let accepted = restarted.accepted.clone();
            let mut consumed = q.clone();
            consumed["session_consumed"] = json!(true);
            consumed["now"] = r["expires_at"].clone();
            ensure!(
                restarted.submit(r, &consumed, &kat, false, false)? == recovered
                    && restarted.accepted == accepted,
                "exact replay re-ran consumed/expired historical qualification"
            );
            let mut changed = r.clone();
            changed["signature_proof"]["signature"] = json!("A".repeat(86));
            ensure!(
                restarted
                    .submit(&changed, q, &kat, false, false)
                    .unwrap_err()
                    .to_string()
                    == "duplicate_conflict"
                    && restarted.accepted == accepted,
                "changed signature bytes rewrote the first outcome"
            );
            let winner = restarted
                .accepted
                .values()
                .next()
                .context("atomic accepted state")?;
            ensure!(
                winner.commits == kat["native_commits"]
                    && winner.generation == r["new_model_generation_ref"]
                    && winner.device == r["new_device_id"]
                    && winner.session == "completed"
                    && winner.content_recovery_fence
                        == r["recovery_unit"]["events"][0]["event"]["event_id"],
                "success lost an authoritative effect"
            );
            // A distinct transaction with the same old basis cannot leave the
            // first Commit, a consumed Session or a partial Device behind.
            let mut contender = r.clone();
            contender["transaction_id"] =
                json!("ak:transaction:019ba000-0000-7000-8000-000000000099");
            let mut unsigned = contender.as_object().context("receipt")?.clone();
            unsigned.remove("signature_proof");
            let mut transcript = b"ak.identity.recovery_receipt.signature.v1\n".to_vec();
            transcript.extend(arkret_canonical::canonical_json_bytes(&unsigned)?);
            contender["signature_proof"]["signature"] = json!(arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&std::array::from_fn(|i| i as u8 + 1))
                    .sign(&transcript)
                    .to_bytes()
            ));
            restarted.frozen = None;
            restarted.freeze(&contender, true)?;
            ensure!(
                restarted
                    .submit(&contender, q, &kat, false, false)
                    .unwrap_err()
                    .to_string()
                    == "generation_or_head_conflict"
                    && restarted.accepted == accepted,
                "CAS loser left recovery residue"
            );
            executed += 1;
        }
    }
    ensure!(
        executed == 21,
        "single-create fault Cartesian matrix incomplete"
    );
    Ok(())
}

#[derive(Default)]
struct IssuerLedger {
    outcomes: BTreeMap<Vec<u8>, (Vec<u8>, Value)>,
    jtis: BTreeSet<String>,
}
impl IssuerLedger {
    fn issue(
        &mut self,
        request: &Value,
        current: &Value,
        jti: &str,
        expected: &Value,
    ) -> Result<Value> {
        let r = &request["terminal_receipt"];
        ensure!(
            current["authenticated_handoff"] == true
                && current["dpop_verified"] == true
                && current["current_device_active"] == true
                && current["account_id"] == r["account_id"]
                && current["issuer_id"] == r["session_grant_ref"]["issuer_id"]
                && current["device_id"] == r["new_device_id"]
                && current["current_generation"] == r["new_model_generation_ref"]
                && current["holder_jkt"]
                    == request["accepted_device_possession_proof"]["holder_jkt"],
            "current_completion_authority_lost"
        );
        // HTTP DPoP remains fresh on exact body retries. The immutable body
        // never licenses reuse of the transport's JTI.
        ensure!(!self.jtis.contains(jti), "proof_replay");
        let business_key = arkret_canonical::canonical_json_bytes(
            &json!({"issuer_id":current["issuer_id"],"operation":"ak.gate.account.command.issue_recovery_completion_grant.v1","account_id":r["account_id"],"transaction_id":r["transaction_id"]}),
        )?;
        let bytes = arkret_canonical::canonical_json_bytes(request)?;
        if let Some((original, outcome)) = self.outcomes.get(&business_key) {
            ensure!(original == &bytes, "duplicate_conflict");
            self.jtis.insert(jti.into());
            return Ok(outcome.clone());
        }
        ensure!(
            instant(&request["accepted_device_possession_proof"]["issued_at"])?
                <= instant(&current["now"])?
                && instant(&current["now"])?
                    < instant(&request["accepted_device_possession_proof"]["expires_at"])?,
            "expired_unaccepted_completion"
        );
        self.jtis.insert(jti.into());
        self.outcomes
            .insert(business_key, (bytes, expected.clone()));
        Ok(expected.clone())
    }
}
pub fn run_recovery_authority_replay_and_candidate_matrix() -> Result<()> {
    let kat = kat()?;
    let request = &kat["completion_request"];
    let current = &kat["completion_qualified_inputs"];
    let expected = &kat["completion_expected_outcome"];
    let mut ledger = IssuerLedger::default();
    let first = ledger.issue(request, current, "http-jti-1", expected)?;
    let mut later = current.clone();
    later["now"] = json!("2099-01-01T00:00:00.000Z");
    ensure!(
        ledger.issue(request, &later, "http-jti-2", expected)? == first
            && ledger.outcomes.len() == 1,
        "accepted proof expiry reissued a grant"
    );
    ensure!(
        ledger
            .issue(request, current, "http-jti-1", expected)
            .unwrap_err()
            .to_string()
            == "proof_replay",
        "exact body excused replayed DPoP"
    );
    let mut changed = request.clone();
    changed["accepted_device_possession_proof"]["request_id"] =
        json!("ak:request:019ba000-0000-7000-8000-000000000099");
    ensure!(
        ledger
            .issue(&changed, current, "http-jti-3", expected)
            .unwrap_err()
            .to_string()
            == "duplicate_conflict"
            && ledger.outcomes.len() == 1,
        "request_id bypassed issuer/full Account/transaction uniqueness"
    );
    let mut revoked = later.clone();
    revoked["current_device_active"] = json!(false);
    ensure!(
        ledger
            .issue(request, &revoked, "http-jti-4", expected)
            .unwrap_err()
            .to_string()
            == "current_completion_authority_lost",
        "historical C replaced current qualification"
    );
    let mut wrong_holder = current.clone();
    wrong_holder["holder_jkt"] = json!("other-holder");
    ensure!(
        ledger
            .issue(request, &wrong_holder, "http-jti-5", expected)
            .is_err(),
        "new holder took another identity's closure"
    );
    let mut empty = IssuerLedger::default();
    ensure!(
        empty
            .issue(request, &later, "http-jti-6", expected)
            .unwrap_err()
            .to_string()
            == "expired_unaccepted_completion"
            && empty.outcomes.is_empty(),
        "expired unaccepted proof occupied the business key"
    );
    let valid = CandidateFence {
        previous_head: "previous",
        candidate_previous_head: "previous",
        frozen_digest: "sha256:candidate",
        observed_digest: "sha256:candidate",
        authority: "authority",
        candidate_authority: "authority",
        generation: "generation-7",
        accepted_generation: "generation-7",
    };
    verify_candidate_fence(&valid)?;
    ensure!(
        verify_candidate_fence(&CandidateFence {
            observed_digest: "sha256:tampered",
            ..valid.clone()
        })
        .unwrap_err()
        .to_string()
            == "candidate_did_entry_tampered",
        "candidate bytes changed"
    );
    ensure!(
        verify_candidate_fence(&CandidateFence {
            accepted_generation: "generation-8",
            ..valid
        })
        .unwrap_err()
        .to_string()
            == "recovery_authority_rotated",
        "authority rotation did not fence the old basis"
    );
    Ok(())
}
#[derive(Clone)]
struct CandidateFence<'a> {
    previous_head: &'a str,
    candidate_previous_head: &'a str,
    frozen_digest: &'a str,
    observed_digest: &'a str,
    authority: &'a str,
    candidate_authority: &'a str,
    generation: &'a str,
    accepted_generation: &'a str,
}
fn verify_candidate_fence(f: &CandidateFence<'_>) -> Result<()> {
    if f.previous_head != f.candidate_previous_head || f.frozen_digest != f.observed_digest {
        bail!("candidate_did_entry_tampered");
    }
    if f.authority != f.candidate_authority || f.generation != f.accepted_generation {
        bail!("recovery_authority_rotated");
    }
    Ok(())
}
/// Owned-process and PostgreSQL cases, separate from the reference fault model.
mod native;
pub use native::run_native_recovery_fault_case;
