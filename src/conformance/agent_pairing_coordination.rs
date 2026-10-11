//! Independent oracle for Agent pairing durable coordination.
//!
//! This is deliberately not a mock HTTP success test.  It models the two
//! durable owners fixed by key-management §3.6.1: the request owner retains an
//! exact pending intent until it observes Station durable acceptance, while
//! the Station alone owns `awaiting_accepted_frontier -> active`.  A live
//! response-loss test still needs a Coland Agent-pair post-commit breakpoint;
//! this oracle pins the state transitions that such a test must observe.

use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
struct PairIntent {
    pairing_request_id: String,
    generation: u64,
    authorize_event_id: String,
    authorization_id: String,
    canonical_request: Vec<u8>,
}

impl PairIntent {
    fn fixture(label: &str, generation: u64) -> Self {
        Self {
            pairing_request_id: format!("pairing-request-{label}"),
            generation,
            authorize_event_id: format!("authorize-event-{label}"),
            authorization_id: format!("authorization-{label}"),
            canonical_request: format!("canonical-agent-pair-request-{label}").into_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivationState {
    AwaitingAcceptedFrontier,
    Active,
    Invalidated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PairOutcome {
    pairing_request_id: String,
    authorize_event_id: String,
    authorization_id: String,
    request_digest: String,
    activation_state: ActivationState,
}

#[derive(Clone, Debug)]
struct AcceptedPairing {
    intent: PairIntent,
    outcome: PairOutcome,
}

#[derive(Clone, Debug)]
struct StationPairingLedger {
    current_generation: u64,
    deactivated: bool,
    accepted: BTreeMap<String, AcceptedPairing>,
    current_authorization_id: Option<String>,
}

impl StationPairingLedger {
    fn new() -> Self {
        Self {
            current_generation: 1,
            deactivated: false,
            accepted: BTreeMap::new(),
            current_authorization_id: None,
        }
    }

    fn accept(&mut self, intent: &PairIntent) -> Result<PairOutcome> {
        if let Some(stored) = self.accepted.get(&intent.pairing_request_id) {
            ensure!(stored.intent == *intent, "duplicate_conflict");
            return Ok(stored.outcome.clone());
        }
        ensure!(!self.deactivated, "agent_deactivated");
        ensure!(
            intent.generation == self.current_generation,
            "superseded_by_repairing"
        );
        let request_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(&intent.canonical_request))
        );
        let outcome = PairOutcome {
            pairing_request_id: intent.pairing_request_id.clone(),
            authorize_event_id: intent.authorize_event_id.clone(),
            authorization_id: intent.authorization_id.clone(),
            request_digest,
            activation_state: ActivationState::AwaitingAcceptedFrontier,
        };
        self.accepted.insert(
            intent.pairing_request_id.clone(),
            AcceptedPairing {
                intent: intent.clone(),
                outcome: outcome.clone(),
            },
        );
        Ok(outcome)
    }

    fn reconcile_accepted_frontier(
        &mut self,
        pairing_request_id: &str,
        covered_authorize_event_id: Option<&str>,
    ) -> Result<bool> {
        let accepted = self
            .accepted
            .get(pairing_request_id)
            .ok_or_else(|| anyhow::anyhow!("pairing_request_not_accepted"))?;
        ensure!(!self.deactivated, "agent_deactivated");
        ensure!(
            accepted.intent.generation == self.current_generation
                && accepted.outcome.activation_state != ActivationState::Invalidated,
            "superseded_by_repairing"
        );
        if covered_authorize_event_id != Some(accepted.intent.authorize_event_id.as_str()) {
            return Ok(false);
        }

        let authorization_id = accepted.intent.authorization_id.clone();
        for record in self.accepted.values_mut() {
            if record.outcome.activation_state == ActivationState::Active
                && record.outcome.authorization_id != authorization_id
            {
                record.outcome.activation_state = ActivationState::Invalidated;
            }
        }
        let accepted = self
            .accepted
            .get_mut(pairing_request_id)
            .expect("accepted record remains present");
        accepted.outcome.activation_state = ActivationState::Active;
        self.current_authorization_id = Some(authorization_id);
        Ok(true)
    }

    fn renew_pairing(&mut self) -> u64 {
        self.current_generation += 1;
        for record in self.accepted.values_mut() {
            if record.outcome.activation_state == ActivationState::AwaitingAcceptedFrontier {
                record.outcome.activation_state = ActivationState::Invalidated;
            }
        }
        self.current_generation
    }

    fn cancel_pairing(&mut self) {
        for record in self.accepted.values_mut() {
            if record.intent.generation == self.current_generation
                && record.outcome.activation_state == ActivationState::AwaitingAcceptedFrontier
            {
                record.outcome.activation_state = ActivationState::Invalidated;
            }
        }
        self.current_generation += 1;
    }

    fn deactivate(&mut self) {
        self.deactivated = true;
        self.current_authorization_id = None;
        for record in self.accepted.values_mut() {
            record.outcome.activation_state = ActivationState::Invalidated;
        }
    }

    fn state(&self, pairing_request_id: &str) -> Option<ActivationState> {
        self.accepted
            .get(pairing_request_id)
            .map(|record| record.outcome.activation_state)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeliveryFault {
    None,
    RequestNotDelivered,
    ResponseLostAfterDurableAccept,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DeliveryObservation {
    Accepted(PairOutcome),
    RequestNotDelivered,
    ResponseLost,
}

#[derive(Clone, Debug, Default)]
struct PairingRequestOwner {
    pending: BTreeMap<String, PairIntent>,
    completed: BTreeMap<String, PairOutcome>,
}

#[derive(Clone, Debug, Default)]
struct IssuerProjection {
    active_authorization_id: Option<String>,
}

impl IssuerProjection {
    fn consume_station_current(
        &mut self,
        station: &StationPairingLedger,
        pairing_request_id: &str,
    ) -> Result<()> {
        let record = station
            .accepted
            .get(pairing_request_id)
            .ok_or_else(|| anyhow::anyhow!("station_outcome_missing"))?;
        ensure!(
            record.outcome.activation_state == ActivationState::Active
                && station.current_authorization_id.as_deref()
                    == Some(record.outcome.authorization_id.as_str())
                && !station.deactivated,
            "station_authorization_not_current"
        );
        self.active_authorization_id = Some(record.outcome.authorization_id.clone());
        Ok(())
    }

    fn permits(&self, station: &StationPairingLedger) -> bool {
        !station.deactivated
            && self.active_authorization_id.as_deref()
                == station.current_authorization_id.as_deref()
    }
}

impl PairingRequestOwner {
    fn retain_exact(&mut self, intent: PairIntent) -> Result<()> {
        if let Some(stored) = self.pending.get(&intent.pairing_request_id) {
            ensure!(stored == &intent, "duplicate_conflict");
            return Ok(());
        }
        ensure!(
            !self.completed.contains_key(&intent.pairing_request_id),
            "already_completed"
        );
        self.pending
            .insert(intent.pairing_request_id.clone(), intent);
        Ok(())
    }

    fn deliver(
        &mut self,
        station: &mut StationPairingLedger,
        pairing_request_id: &str,
        fault: DeliveryFault,
    ) -> Result<DeliveryObservation> {
        let intent = self
            .pending
            .get(pairing_request_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("pending_intent_missing"))?;
        if fault == DeliveryFault::RequestNotDelivered {
            return Ok(DeliveryObservation::RequestNotDelivered);
        }
        let outcome = station.accept(&intent)?;
        if fault == DeliveryFault::ResponseLostAfterDurableAccept {
            return Ok(DeliveryObservation::ResponseLost);
        }
        self.pending.remove(pairing_request_id);
        self.completed
            .insert(pairing_request_id.to_owned(), outcome.clone());
        Ok(DeliveryObservation::Accepted(outcome))
    }
}

pub fn run_agent_pairing_durable_coordination_matrix() -> Result<()> {
    // Request never reaches Station: no Station side effect exists, while the
    // exact pending intent survives and a later retry can succeed.
    let first = PairIntent::fixture("not-delivered", 1);
    let mut owner = PairingRequestOwner::default();
    let mut station = StationPairingLedger::new();
    owner.retain_exact(first.clone())?;
    ensure!(
        owner.deliver(
            &mut station,
            &first.pairing_request_id,
            DeliveryFault::RequestNotDelivered,
        )? == DeliveryObservation::RequestNotDelivered
    );
    ensure!(station.accepted.is_empty());
    ensure!(owner.pending.get(&first.pairing_request_id) == Some(&first));
    let delivered = owner.deliver(&mut station, &first.pairing_request_id, DeliveryFault::None)?;
    ensure!(matches!(
        delivered,
        DeliveryObservation::Accepted(PairOutcome {
            activation_state: ActivationState::AwaitingAcceptedFrontier,
            ..
        })
    ));

    // Station commits and the response is lost: after both durable ledgers are
    // reconstructed, the exact retry returns the original outcome and never
    // creates a second acceptance. Changed bytes under that id conflict.
    let lost = PairIntent::fixture("response-lost", 1);
    let mut owner = PairingRequestOwner::default();
    let mut station = StationPairingLedger::new();
    owner.retain_exact(lost.clone())?;
    ensure!(
        owner.deliver(
            &mut station,
            &lost.pairing_request_id,
            DeliveryFault::ResponseLostAfterDurableAccept,
        )? == DeliveryObservation::ResponseLost
    );
    let original = station
        .accepted
        .get(&lost.pairing_request_id)
        .expect("Station durably accepted before response loss")
        .outcome
        .clone();
    let mut restarted_owner = owner.clone();
    let mut restarted_station = station.clone();
    ensure!(
        restarted_owner.deliver(
            &mut restarted_station,
            &lost.pairing_request_id,
            DeliveryFault::None,
        )? == DeliveryObservation::Accepted(original)
    );
    ensure!(restarted_station.accepted.len() == 1);
    let mut changed = lost.clone();
    changed.canonical_request.push(b'!');
    ensure!(
        station
            .accept(&changed)
            .expect_err("changed replay")
            .to_string()
            == "duplicate_conflict"
    );

    // Active is a later Station-owned transition. A durable accept alone is
    // never active, a non-covering Seal is inert, and the background
    // reconciler needs no second delivery or user approval to activate.
    let background = PairIntent::fixture("background", 1);
    let mut owner = PairingRequestOwner::default();
    let mut station = StationPairingLedger::new();
    owner.retain_exact(background.clone())?;
    owner.deliver(
        &mut station,
        &background.pairing_request_id,
        DeliveryFault::None,
    )?;
    ensure!(
        station.state(&background.pairing_request_id)
            == Some(ActivationState::AwaitingAcceptedFrontier)
    );
    ensure!(!station.reconcile_accepted_frontier(&background.pairing_request_id, None)?);
    ensure!(station.current_authorization_id.is_none());
    let mut issuer = IssuerProjection::default();
    ensure!(
        issuer
            .consume_station_current(&station, &background.pairing_request_id)
            .expect_err("durable accept is not active")
            .to_string()
            == "station_authorization_not_current"
    );
    ensure!(station.reconcile_accepted_frontier(
        &background.pairing_request_id,
        Some(&background.authorize_event_id),
    )?);
    ensure!(
        station.state(&background.pairing_request_id) == Some(ActivationState::Active)
            && station.current_authorization_id.as_deref()
                == Some(background.authorization_id.as_str())
    );
    issuer.consume_station_current(&station, &background.pairing_request_id)?;
    ensure!(issuer.permits(&station));

    // A late Seal/outcome from an old handle cannot revive it after renew or
    // cancel, and deactivation invalidates both pending and active authority.
    let old = PairIntent::fixture("old", 1);
    let mut station = StationPairingLedger::new();
    station.accept(&old)?;
    ensure!(station.renew_pairing() == 2);
    ensure!(station.state(&old.pairing_request_id) == Some(ActivationState::Invalidated));
    ensure!(
        IssuerProjection::default()
            .consume_station_current(&station, &old.pairing_request_id)
            .expect_err("issuer cannot promote an invalidated old outcome")
            .to_string()
            == "station_authorization_not_current"
    );
    ensure!(
        station
            .reconcile_accepted_frontier(&old.pairing_request_id, Some(&old.authorize_event_id))
            .expect_err("late old-generation Seal")
            .to_string()
            == "superseded_by_repairing"
    );

    let cancelled = PairIntent::fixture("cancelled", 2);
    station.accept(&cancelled)?;
    station.cancel_pairing();
    ensure!(station.state(&cancelled.pairing_request_id) == Some(ActivationState::Invalidated));
    ensure!(
        station
            .reconcile_accepted_frontier(
                &cancelled.pairing_request_id,
                Some(&cancelled.authorize_event_id),
            )
            .expect_err("late cancelled-generation Seal")
            .to_string()
            == "superseded_by_repairing"
    );

    let active = PairIntent::fixture("active", 3);
    station.accept(&active)?;
    station.reconcile_accepted_frontier(
        &active.pairing_request_id,
        Some(&active.authorize_event_id),
    )?;
    station.deactivate();
    ensure!(station.current_authorization_id.is_none());
    ensure!(station.state(&active.pairing_request_id) == Some(ActivationState::Invalidated));
    let mut stale_issuer = IssuerProjection {
        active_authorization_id: Some(active.authorization_id.clone()),
    };
    ensure!(!stale_issuer.permits(&station));
    ensure!(
        stale_issuer
            .consume_station_current(&station, &active.pairing_request_id)
            .expect_err("AA-local active cannot substitute for Station current state")
            .to_string()
            == "station_authorization_not_current"
    );
    let after_deactivate = PairIntent::fixture("after-deactivate", 3);
    ensure!(
        station
            .accept(&after_deactivate)
            .expect_err("deactivated Agent cannot pair")
            .to_string()
            == "agent_deactivated"
    );

    if station.accepted.values().any(|record| {
        matches!(
            record.outcome.activation_state,
            ActivationState::AwaitingAcceptedFrontier | ActivationState::Active
        )
    }) {
        bail!("old Agent authorization remained usable after deactivation");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn durable_coordination_matrix_is_closed() {
        super::run_agent_pairing_durable_coordination_matrix().unwrap();
    }
}
