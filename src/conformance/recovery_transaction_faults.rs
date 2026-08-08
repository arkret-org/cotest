//! Independent RecoveryTransaction fault and replay model.
//!
//! This harness deliberately owns no Soland, Coauth, Garth, or Inkson state
//! types. It models only the normative durable first-outcome and authority
//! invariants that a joint implementation must expose.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryModel {
    RootAnchored,
}

impl RecoveryModel {
    fn steps(self) -> &'static [&'static str] {
        match self {
            Self::RootAnchored => &[
                "create",
                "publish_did_entry",
                "submit_reanchor_unit",
                "issue_terminal_receipt",
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    CrashBeforeRemote,
    ResponseLostAfterAccepted,
    RestartAfterAccepted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Attempt {
    Accepted(String),
    Crashed,
    ResponseLost,
}

#[derive(Clone, Debug, Default)]
struct DurableLedger {
    outcomes: BTreeMap<String, (Vec<u8>, String)>,
}

impl DurableLedger {
    fn attempt(
        &mut self,
        step: &str,
        operation_id: &str,
        canonical_request: &[u8],
        fault: Fault,
    ) -> Result<Attempt> {
        if let Some((stored_request, outcome)) = self.outcomes.get(operation_id) {
            if stored_request != canonical_request {
                bail!("duplicate_conflict");
            }
            return Ok(Attempt::Accepted(outcome.clone()));
        }
        if fault == Fault::CrashBeforeRemote {
            return Ok(Attempt::Crashed);
        }
        let outcome = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                [step.as_bytes(), &[0], canonical_request].concat()
            ))
        );
        self.outcomes.insert(
            operation_id.to_owned(),
            (canonical_request.to_vec(), outcome.clone()),
        );
        match fault {
            Fault::ResponseLostAfterAccepted => Ok(Attempt::ResponseLost),
            Fault::None | Fault::RestartAfterAccepted => Ok(Attempt::Accepted(outcome)),
            Fault::CrashBeforeRemote => unreachable!("handled before the remote side effect"),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct RecoveryAuthorityLedger {
    accepted_requests: BTreeMap<String, (Vec<u8>, String)>,
    consumed_jtis: BTreeSet<String>,
}

impl RecoveryAuthorityLedger {
    fn authorize(&mut self, identity: &str, canonical_request: &[u8], jti: &str) -> Result<String> {
        if let Some((stored, outcome)) = self.accepted_requests.get(identity) {
            if stored != canonical_request {
                bail!("duplicate_conflict");
            }
            return Ok(outcome.clone());
        }
        if !self.consumed_jtis.insert(jti.to_owned()) {
            bail!("proof_replay");
        }
        let outcome = format!("sha256:{}", hex::encode(Sha256::digest(canonical_request)));
        self.accepted_requests.insert(
            identity.to_owned(),
            (canonical_request.to_vec(), outcome.clone()),
        );
        Ok(outcome)
    }
}

#[derive(Clone, Debug)]
struct CandidateFence<'a> {
    previous_head: &'a str,
    candidate_previous_head: &'a str,
    planned_candidate_digest: &'a str,
    observed_candidate_digest: &'a str,
    pre_fence_authority: &'a str,
    candidate_authority: &'a str,
    authority_generation: &'a str,
    accepted_authority_generation: &'a str,
}

fn verify_candidate_fence(fence: &CandidateFence<'_>) -> Result<()> {
    if fence.previous_head != fence.candidate_previous_head
        || fence.planned_candidate_digest != fence.observed_candidate_digest
    {
        bail!("candidate_did_entry_tampered");
    }
    if fence.pre_fence_authority != fence.candidate_authority
        || fence.authority_generation != fence.accepted_authority_generation
    {
        bail!("recovery_authority_rotated");
    }
    Ok(())
}

fn author_terminal_with_staged_secret(
    ledger: &mut DurableLedger,
    operation_id: &str,
    canonical_request: &[u8],
    staged_secret_available: bool,
) -> Result<Attempt> {
    if !staged_secret_available {
        bail!("staged_secret_lost");
    }
    ledger.attempt(
        "issue_terminal_receipt",
        operation_id,
        canonical_request,
        Fault::None,
    )
}

pub fn run_recovery_transaction_fault_matrix() -> Result<()> {
    for model in [RecoveryModel::RootAnchored] {
        for (index, step) in model.steps().iter().enumerate() {
            let operation_id = format!("{model:?}:{index}");
            let canonical_request = format!("canonical:{model:?}:{step}").into_bytes();

            let mut before = DurableLedger::default();
            assert_eq!(
                before.attempt(
                    step,
                    &operation_id,
                    &canonical_request,
                    Fault::CrashBeforeRemote,
                )?,
                Attempt::Crashed
            );
            assert!(matches!(
                before.attempt(step, &operation_id, &canonical_request, Fault::None)?,
                Attempt::Accepted(_)
            ));
            assert_eq!(before.outcomes.len(), 1);

            let mut response_lost = DurableLedger::default();
            assert_eq!(
                response_lost.attempt(
                    step,
                    &operation_id,
                    &canonical_request,
                    Fault::ResponseLostAfterAccepted,
                )?,
                Attempt::ResponseLost
            );
            assert!(matches!(
                response_lost.attempt(
                    step,
                    &operation_id,
                    &canonical_request,
                    Fault::RestartAfterAccepted,
                )?,
                Attempt::Accepted(_)
            ));
            assert_eq!(response_lost.outcomes.len(), 1);
            assert_eq!(
                response_lost
                    .attempt(
                        step,
                        &operation_id,
                        format!("{step}:changed").as_bytes(),
                        Fault::None,
                    )
                    .expect_err("same operation id with different bytes must fail")
                    .to_string(),
                "duplicate_conflict"
            );
        }
    }

    let mut terminal = DurableLedger::default();
    let terminal_bytes = b"canonical-device-signed-terminal-receipt";
    assert_eq!(
        terminal.attempt(
            "issue_terminal_receipt",
            "terminal-receipt-1",
            terminal_bytes,
            Fault::ResponseLostAfterAccepted,
        )?,
        Attempt::ResponseLost
    );
    assert!(matches!(
        terminal.attempt(
            "issue_terminal_receipt",
            "terminal-receipt-1",
            terminal_bytes,
            Fault::RestartAfterAccepted,
        )?,
        Attempt::Accepted(_)
    ));
    assert_eq!(terminal.outcomes.len(), 1);
    assert_eq!(
        terminal
            .attempt(
                "issue_terminal_receipt",
                "terminal-receipt-1",
                b"different-terminal-receipt",
                Fault::None,
            )
            .expect_err("a second terminal receipt must conflict")
            .to_string(),
        "duplicate_conflict"
    );

    let mut staged_secret_loss = DurableLedger::default();
    assert_eq!(
        author_terminal_with_staged_secret(
            &mut staged_secret_loss,
            "terminal-receipt-2",
            terminal_bytes,
            false,
        )
        .expect_err("missing staged secret must stop before terminal authoring")
        .to_string(),
        "staged_secret_lost"
    );
    assert!(staged_secret_loss.outcomes.is_empty());
    Ok(())
}

pub fn run_recovery_authority_replay_and_candidate_matrix() -> Result<()> {
    let mut authority = RecoveryAuthorityLedger::default();
    let first = authority.authorize("transaction-1:old-grant-1", b"canonical-request", "jti-1")?;
    let exact = authority.authorize("transaction-1:old-grant-1", b"canonical-request", "jti-1")?;
    assert_eq!(
        first, exact,
        "exact lookup must precede JTI freshness checks"
    );
    assert_eq!(
        authority
            .authorize("transaction-2:old-grant-2", b"other-request", "jti-1")
            .expect_err("a JTI cannot authorize a distinct request")
            .to_string(),
        "proof_replay"
    );
    assert_eq!(
        authority
            .authorize("transaction-1:old-grant-1", b"changed-request", "jti-2")
            .expect_err("accepted identity cannot change bytes")
            .to_string(),
        "duplicate_conflict"
    );

    let valid = CandidateFence {
        previous_head: "3-previous",
        candidate_previous_head: "3-previous",
        planned_candidate_digest: "sha256:candidate",
        observed_candidate_digest: "sha256:candidate",
        pre_fence_authority: "did:webvh:authority.example",
        candidate_authority: "did:webvh:authority.example",
        authority_generation: "generation-7",
        accepted_authority_generation: "generation-7",
    };
    verify_candidate_fence(&valid)?;
    assert_eq!(
        verify_candidate_fence(&CandidateFence {
            observed_candidate_digest: "sha256:tampered",
            ..valid.clone()
        })
        .expect_err("candidate bytes cannot change")
        .to_string(),
        "candidate_did_entry_tampered"
    );
    assert_eq!(
        verify_candidate_fence(&CandidateFence {
            accepted_authority_generation: "generation-8",
            ..valid
        })
        .expect_err("authority rotation invalidates the prepared fence")
        .to_string(),
        "recovery_authority_rotated"
    );
    Ok(())
}
