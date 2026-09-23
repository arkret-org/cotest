//! Receiver-local presence conformance vectors. The projection consumes only
//! the accepted branch of Garth SignalReceiver; proof and MLS checks are
//! exercised by the Signal recipient suites.

use anyhow::{Result, bail, ensure};
use arkret_models_collaboration::signal_plaintext::{
    SignalPlaintext, SignalSequence, SignalSequenceDecision, SignalSequenceDomain,
    SignalSequenceEndpoint, SignalSequenceHighWater, open_signal_plaintext,
};
use arkret_models_discovery::{PresenceStatus, validate_last_active_at, validate_status_message};
use arkret_wire::{AccountId, ActorId, DeviceId, DidCoreId, RealmId, ScopeRef};
use chrono::{DateTime, Duration, TimeZone, Utc};
use garth::presence::PresenceProjection;
use garth::signal::SignalReceiveOutcome;
use serde_json::{Value, json};

pub const VECTOR_ID_STATE_CLOSED_SET: &str = "ak.vector.presence.state_closed_set.v1";
pub const VECTOR_ID_LAST_ACTIVE_AT_BUCKET: &str = "ak.vector.presence.last_active_at_bucket.v1";
pub const VECTOR_ID_STATUS_MESSAGE_BOUNDS: &str = "ak.vector.presence.status_message_bounds.v1";
pub const VECTOR_ID_MULTI_DEVICE_AGGREGATION: &str =
    "ak.vector.presence.multi_device_aggregation.v1";

pub const ALL_PRESENCE_SIGNAL_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_STATE_CLOSED_SET,
    VECTOR_ID_LAST_ACTIVE_AT_BUCKET,
    VECTOR_ID_STATUS_MESSAGE_BOUNDS,
    VECTOR_ID_MULTI_DEVICE_AGGREGATION,
];

fn actor() -> ActorId {
    ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ))
}

fn sent_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
        .single()
        .unwrap()
}

fn accepted_presence(
    device_suffix: &str,
    fields: Value,
    sequence: u64,
    sent_at: DateTime<Utc>,
) -> Result<SignalReceiveOutcome> {
    let mut body = serde_json::Map::new();
    body.insert("kind".to_owned(), json!("ak.presence"));
    body.insert("actor_id".to_owned(), json!(actor()));
    body.insert("payload_sequence".to_owned(), json!(sequence));
    body.insert("ttl_ms".to_owned(), json!(30_000));
    if let Some(extra) = fields.as_object() {
        body.extend(extra.clone());
    }
    let plaintext = open_signal_plaintext(&arkret_canonical::canonical_json_bytes(
        &Value::Object(body),
    )?)?;
    let realm_id = RealmId::new("ak:realm:AYcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_")?;
    Ok(SignalReceiveOutcome::Accepted {
        domain: Box::new(SignalSequenceDomain {
            sender_actor_id: actor(),
            endpoint: SignalSequenceEndpoint::AccountDevice {
                device_id: DeviceId::new(format!(
                    "ak:device:01904100-0000-7000-8000-{device_suffix}"
                ))?,
            },
            scope_ref: ScopeRef::Realm { realm_id },
        }),
        plaintext,
        effective_expires_at: sent_at + Duration::seconds(30),
    })
}

pub fn run_state_closed_set_vector() -> Result<()> {
    for state in ["online", "idle", "offline", "dnd"] {
        ensure!(PresenceStatus::parse_wire(state).is_some());
        let outcome = accepted_presence("000000000005", json!({"state": state}), 1, sent_at())?;
        ensure!(matches!(
            &outcome,
            SignalReceiveOutcome::Accepted {
                plaintext: SignalPlaintext::Presence(_),
                ..
            }
        ));
        ensure!(PresenceProjection::new().apply_verified(&outcome, sent_at())?);
    }
    for state in ["unavailable", "busy", "away", "Online", ""] {
        ensure!(PresenceStatus::parse_wire(state).is_none());
        ensure!(
            accepted_presence("000000000005", json!({"state": state}), 1, sent_at()).is_err(),
            "invalid presence state {state} entered the closed plaintext union"
        );
    }
    Ok(())
}

pub fn run_last_active_at_bucket_vector() -> Result<()> {
    for value in [
        "2026-06-22T10:34:56.000Z",
        "2026-06-22T10:00:00.000Z/PT1H",
        "2026-06-22T10:34:00.000Z/PT60S",
    ] {
        validate_last_active_at(value)?;
        let outcome = accepted_presence(
            "000000000005",
            json!({"state":"idle","last_active_at":value}),
            1,
            sent_at(),
        )?;
        let mut projection = PresenceProjection::new();
        projection.apply_verified(&outcome, sent_at())?;
        ensure!(projection.last_active_at(&actor(), sent_at()) == Some(value));
    }
    for value in [
        "2026-06-22T10:34:00.000Z/PT1H",
        "2026-06-22T10:00:00.000Z/PT30S",
        "yesterday",
        "2026-06-22T10:00:00.000Z/PT1H/PT1H",
    ] {
        ensure!(validate_last_active_at(value).is_err());
        if let Ok(outcome) = accepted_presence(
            "000000000005",
            json!({"state":"idle","last_active_at":value}),
            1,
            sent_at(),
        ) {
            let mut projection = PresenceProjection::new();
            ensure!(projection.apply_verified(&outcome, sent_at()).is_err());
            ensure!(projection.observation_count(&actor(), sent_at()) == 0);
        }
    }
    Ok(())
}

pub fn run_status_message_bounds_vector() -> Result<()> {
    validate_status_message(&"字".repeat(256))?;
    validate_status_message("In a meeting\tuntil\n15:00")?;
    for value in [
        "字".repeat(257),
        "cafe\u{301}".to_owned(),
        "bell\u{7}".to_owned(),
        "next\u{85}line".to_owned(),
    ] {
        ensure!(validate_status_message(&value).is_err());
        if let Ok(outcome) = accepted_presence(
            "000000000005",
            json!({"state":"dnd","status_message":value}),
            1,
            sent_at(),
        ) {
            let mut projection = PresenceProjection::new();
            ensure!(projection.apply_verified(&outcome, sent_at()).is_err());
            ensure!(projection.observation_count(&actor(), sent_at()) == 0);
        }
    }
    Ok(())
}

pub fn run_multi_device_aggregation_vector() -> Result<()> {
    let mut projection = PresenceProjection::new();
    for (device, state, message, offset) in [
        ("000000000005", "idle", None, 0),
        ("000000000006", "dnd", Some("In a meeting"), 1),
        ("000000000007", "online", None, 0),
    ] {
        let sent = sent_at() + Duration::seconds(offset);
        let mut fields = json!({"state":state});
        if let Some(message) = message {
            fields["status_message"] = json!(message);
        }
        let outcome = accepted_presence(device, fields, 1, sent)?;
        projection.apply_verified(&outcome, sent)?;
    }
    let observed_at = sent_at() + Duration::seconds(2);
    ensure!(projection.aggregated(&actor(), observed_at) == PresenceStatus::Dnd);
    ensure!(projection.status_message(&actor(), observed_at) == Some("In a meeting"));

    // SignalReceiver owns this high-water check; stale outcomes must never
    // reach the projection and cannot rewind one endpoint's state.
    let mut sequence = SignalSequenceHighWater::default();
    ensure!(matches!(
        sequence.observe(SignalSequence::new(1)),
        SignalSequenceDecision::Advanced { .. }
    ));
    ensure!(matches!(
        sequence.observe(SignalSequence::new(1)),
        SignalSequenceDecision::Stale { .. }
    ));
    ensure!(projection.aggregated(&actor(), observed_at) == PresenceStatus::Dnd);
    let expired = sent_at() + Duration::seconds(32);
    ensure!(projection.aggregated(&actor(), expired) == PresenceStatus::Offline);
    ensure!(projection.status_message(&actor(), expired).is_none());
    Ok(())
}

pub fn run_presence_signal_vector_suite() -> Result<()> {
    if ALL_PRESENCE_SIGNAL_VECTOR_IDS.len() != 4 {
        bail!("presence vector registry count drifted");
    }
    run_state_closed_set_vector()?;
    run_last_active_at_bucket_vector()?;
    run_status_message_bounds_vector()?;
    run_multi_device_aggregation_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_receiver_vectors_run_clean() {
        run_presence_signal_vector_suite().unwrap();
    }
}
