//! `ak.vector.agent.action_approve_expiry.v1` — the single governance clock of
//! an `ak.agent.action_approve` confirmation.
//!
//! `constraint-schema.md` §9.2.6 judges `expires_at` only against the signed
//! `committed_at` of the RealmCommit covering each Event, inclusive and with
//! zero tolerance. Envelope `created_at` and the Station's current time never
//! participate, and an exact retry returns the original Commit without judging
//! the window again.
//!
//! The window comparison is the SDK's `AgentActionApprovePayload::admits_commit_at`;
//! this module adds an independent model of the two admission gates and of the
//! commit ledger, replays every registered variant against it and compares the
//! full rendered outcome with the fixture's `expected` object.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
use arkret_models_collaboration::events_payloads::agent::AgentActionApprovePayload;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::load_fixture_value;
use crate::transcripts::record_vector_event;

const EDGE_CASE_FIXTURE: &str = "protocol-edge-cases-fixture.json";
pub const VECTOR_ID_AGENT_ACTION_APPROVE_EXPIRY: &str = "ak.vector.agent.action_approve_expiry.v1";
const CLOCK: &str = "covering_realm_commit_committed_at";

const REGISTERED_VARIANTS: [&str; 6] = [
    "confirmation_committed_at_equal_to_expiry_accepted",
    "confirmation_committed_one_ms_after_expiry_rejected",
    "confirmation_created_at_is_not_compared",
    "approved_event_committed_at_equal_to_expiry_published",
    "approved_event_published_after_expiry_rejected",
    "confirmation_exact_retry_after_expiry_keeps_original_commit",
];

/// A durable write the model performed; rejected admissions must leave none.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Write {
    Confirmation { committed_at: DateTime<Utc> },
    NonceAllocation,
    ApprovedEvent { committed_at: DateTime<Utc> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    ConfirmationAccepted,
    ConfirmationExpired,
    ApprovedEventPublished,
    ApprovedEventWithoutValidConfirmation,
    OriginalCommit {
        committed_at: DateTime<Utc>,
        additional_writes: usize,
    },
}

/// The governing Station's durable state for one confirmation.
#[derive(Default)]
struct Station {
    writes: Vec<Write>,
    /// Exact confirmation intents already committed, keyed by approval nonce.
    commits: BTreeMap<String, DateTime<Utc>>,
}

impl Station {
    /// Admit a confirmation Event whose covering RealmCommit would carry
    /// `covering_committed_at`. The envelope `created_at` is deliberately an
    /// input so the model can prove it is ignored.
    fn admit_confirmation(
        &mut self,
        approval: &AgentActionApprovePayload,
        covering_committed_at: DateTime<Utc>,
        _envelope_created_at: Option<DateTime<Utc>>,
        _station_clock: DateTime<Utc>,
    ) -> Outcome {
        if let Some(committed_at) = self.commits.get(&approval.approval_nonce) {
            return Outcome::OriginalCommit {
                committed_at: *committed_at,
                additional_writes: 0,
            };
        }
        if !approval.admits_commit_at(covering_committed_at) {
            return Outcome::ConfirmationExpired;
        }
        self.writes.push(Write::Confirmation {
            committed_at: covering_committed_at,
        });
        self.writes.push(Write::NonceAllocation);
        self.commits
            .insert(approval.approval_nonce.clone(), covering_committed_at);
        Outcome::ConfirmationAccepted
    }

    /// Publish the approved Event. A confirmation that no longer covers the
    /// approved Event's commit is treated as absent.
    fn publish_approved_event(
        &mut self,
        approval: &AgentActionApprovePayload,
        covering_committed_at: DateTime<Utc>,
    ) -> Outcome {
        let confirmed = self.commits.contains_key(&approval.approval_nonce);
        if !confirmed || !approval.admits_commit_at(covering_committed_at) {
            return Outcome::ApprovedEventWithoutValidConfirmation;
        }
        self.writes.push(Write::ApprovedEvent {
            committed_at: covering_committed_at,
        });
        Outcome::ApprovedEventPublished
    }
}

pub fn run_agent_action_approve_expiry_vector() -> Result<()> {
    let fixture = load_fixture_value(EDGE_CASE_FIXTURE)?;
    ensure!(
        fixture["covers_vectors"].as_array().is_some_and(|ids| ids
            .iter()
            .any(|id| id == VECTOR_ID_AGENT_ACTION_APPROVE_EXPIRY)),
        "protocol edge-case fixture does not cover {VECTOR_ID_AGENT_ACTION_APPROVE_EXPIRY}"
    );
    let case = registered_case(&fixture)?;
    ensure!(
        case["clock"] == CLOCK && case["tolerance_ms"] == 0,
        "action_approve expiry must be judged on the covering committed_at with zero tolerance"
    );
    let payload_expires_at = timestamp(&case["payload_expires_at"])?;
    let approval = approval_payload(payload_expires_at)?;

    let variants = case["variants"]
        .as_array()
        .context("action_approve expiry variants")?;
    let names = variants
        .iter()
        .map(|variant| variant["name"].as_str().map(str::to_owned))
        .collect::<Option<BTreeSet<_>>>()
        .context("action_approve expiry variant name")?;
    ensure!(
        names.len() == variants.len()
            && names
                == REGISTERED_VARIANTS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
        "action_approve expiry variants drifted from the executed set: {names:?}"
    );

    for variant in variants {
        let name = variant["name"].as_str().unwrap_or_default();
        let actual = execute_variant(&approval, variant)
            .with_context(|| format!("execute action_approve expiry variant {name}"))?;
        ensure!(
            actual == variant["expected"],
            "action_approve expiry variant {name} produced {actual}, fixture expects {}",
            variant["expected"]
        );
        record_vector_event(
            "agent.action_approve_expiry",
            &json!({"vector_id": VECTOR_ID_AGENT_ACTION_APPROVE_EXPIRY, "variant": name}),
            &variant["expected"],
            &actual,
        );
    }
    ensure!(
        case["assertions"]
            .as_array()
            .is_some_and(|assertions| !assertions.is_empty()),
        "action_approve expiry case publishes no assertions"
    );
    Ok(())
}

fn execute_variant(approval: &AgentActionApprovePayload, variant: &Value) -> Result<Value> {
    let subject = variant["subject"].as_str().context("variant subject")?;
    let mut station = Station::default();
    let outcome = match subject {
        "confirmation_event" if variant.get("original_covering_committed_at").is_some() => {
            let original = timestamp(&variant["original_covering_committed_at"])?;
            let retry_clock = timestamp(&variant["station_clock_at_retry"])?;
            ensure!(
                station.admit_confirmation(approval, original, None, original)
                    == Outcome::ConfirmationAccepted,
                "the original confirmation must commit inside the window"
            );
            let writes_before = station.writes.len();
            let retry = station.admit_confirmation(approval, retry_clock, None, retry_clock);
            ensure!(
                station.writes.len() == writes_before,
                "an exact retry wrote durable state"
            );
            ensure!(
                !approval.admits_commit_at(retry_clock),
                "the retry clock must lie past expires_at for the vector to mean anything"
            );
            retry
        }
        "confirmation_event" => {
            let covering = timestamp(&variant["covering_committed_at"])?;
            let created_at = variant
                .get("envelope_created_at")
                .map(timestamp)
                .transpose()?;
            let outcome = station.admit_confirmation(approval, covering, created_at, covering);
            // `created_at` is display only: the same commit without it must
            // decide identically.
            let mut control = Station::default();
            ensure!(
                control.admit_confirmation(approval, covering, None, covering) == outcome,
                "envelope created_at changed the confirmation decision"
            );
            outcome
        }
        "approved_event" => {
            let confirmation = timestamp(&variant["confirmation_committed_at"])?;
            let covering = timestamp(&variant["covering_committed_at"])?;
            ensure!(
                station.admit_confirmation(approval, confirmation, None, confirmation)
                    == Outcome::ConfirmationAccepted,
                "the confirmation must commit inside the window"
            );
            let writes_before = station.writes.len();
            let outcome = station.publish_approved_event(approval, covering);
            if outcome == Outcome::ApprovedEventWithoutValidConfirmation {
                ensure!(
                    station.writes.len() == writes_before,
                    "a rejected approved Event wrote durable state"
                );
            }
            outcome
        }
        other => bail!("unknown action_approve expiry subject {other}"),
    };
    render(&outcome, &station)
}

fn render(outcome: &Outcome, station: &Station) -> Result<Value> {
    let nonce_allocated = station.writes.contains(&Write::NonceAllocation);
    Ok(match outcome {
        Outcome::ConfirmationAccepted => json!({
            "decision": "accept",
            "nonce_allocated": nonce_allocated,
        }),
        Outcome::ConfirmationExpired => json!({
            "decision": "reject",
            "error_code": "failed_precondition",
            "reason_code": null,
            "nonce_allocated": nonce_allocated,
            "durable_writes": station.writes.len(),
        }),
        Outcome::ApprovedEventPublished => json!({"decision": "accept"}),
        Outcome::ApprovedEventWithoutValidConfirmation => {
            let approved_writes = station
                .writes
                .iter()
                .filter(|write| matches!(write, Write::ApprovedEvent { .. }))
                .count();
            json!({
                "decision": "reject",
                "rejected_as": "no_valid_confirmation",
                "error_code": "claim_required",
                "reason_code": "approval_required",
                "durable_writes": approved_writes,
            })
        }
        Outcome::OriginalCommit {
            committed_at,
            additional_writes,
        } => {
            let original = station
                .writes
                .iter()
                .find_map(|write| match write {
                    Write::Confirmation { committed_at } => Some(*committed_at),
                    _ => None,
                })
                .context("exact retry without an original confirmation commit")?;
            json!({
                "decision": "original_commit",
                "committed_at_rewritten": *committed_at != original,
                "additional_writes": additional_writes,
            })
        }
    })
}

/// Build the confirmation through the SDK's closed payload type, so the model
/// can only use members the current schema admits.
fn approval_payload(expires_at: DateTime<Utc>) -> Result<AgentActionApprovePayload> {
    let payload = json!({
        "approval_id": "ak:agent_draft:01999999-0000-7000-8000-00000000c104",
        "agent_id": "ak:did_core:web:agent.example",
        "proposed_action": "ak.message.create",
        "target": {
            "kind": "realm",
            "realm_id": "ak:realm:AbL8oOUkpZusQ-VqkYVKoKNNlWviopqGNtOPvbl98WW4"
        },
        "approved_event_id": "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
        "approval_nonce": "agent-approval-expiry-nonce",
        "expires_at": expires_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    });
    let approval: AgentActionApprovePayload =
        serde_json::from_value(payload.clone()).context("decode typed action_approve payload")?;
    ensure!(
        serde_json::to_value(&approval)? == payload,
        "typed action_approve payload does not round-trip"
    );
    let mut retired = payload;
    retired["approved_at"] = json!("2026-09-24T09:00:00.000Z");
    ensure!(
        serde_json::from_value::<AgentActionApprovePayload>(retired).is_err(),
        "the SDK still admits the removed approved_at member"
    );
    Ok(approval)
}

fn registered_case(fixture: &Value) -> Result<Value> {
    fixture["cases"]
        .as_array()
        .context("protocol edge-case fixture cases")?
        .iter()
        .find(|case| case["vector_id"] == VECTOR_ID_AGENT_ACTION_APPROVE_EXPIRY)
        .cloned()
        .with_context(|| {
            format!("protocol edge-case fixture publishes no case for {VECTOR_ID_AGENT_ACTION_APPROVE_EXPIRY}")
        })
}

fn timestamp(value: &Value) -> Result<DateTime<Utc>> {
    let text = value.as_str().context("timestamp must be a string")?;
    Ok(DateTime::parse_from_rfc3339(text)
        .with_context(|| format!("parse timestamp {text}"))?
        .to_utc())
}
