//! `ak.vector.sync.device_message_send_admission.v1` — DeviceMessage send
//! admission after decision 0106.
//!
//! `device-lifecycle.md` §7 fixes three rules this module executes:
//!
//! * the exact `device_message_id` plus canonical-intent check runs before the `expires_at` check,
//!   so an exact retry after expiry returns the original enqueue result;
//! * any other target whose `expires_at` is missing, expired, earlier than `sent_at` or beyond the
//!   Station TTL limit fails the whole request with top-level `param_invalid` and enqueues nothing;
//! * `unknown_devices` only means "recipient not deliverable": rows carry `device_message_id` and
//!   `status` and nothing that tells unknown, revoked or fenced recipients apart.
//!
//! Requests and outcomes pass through the SDK's closed DTOs, so a retired
//! member such as the unknown-row `reason_code` cannot be produced or accepted.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
use arkret_models_collaboration::device_messages::{
    DeviceMessageDeliveredRow, DeviceMessageDeliveredStatus, DeviceMessageTarget,
    DeviceMessageUnknownRow, DeviceMessageUnknownStatus, DeviceMessagesSendOutcome,
};
use arkret_wire::{DeviceId, DeviceMessageId, DidCoreId};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value, json};

use super::load_fixture_value;
use crate::transcripts::record_vector_event;

const EDGE_CASE_FIXTURE: &str = "protocol-edge-cases-fixture.json";
pub const VECTOR_ID_DEVICE_MESSAGE_SEND_ADMISSION: &str =
    "ak.vector.sync.device_message_send_admission.v1";
const KIND: &str = "ak.mls.application";

const REGISTERED_VARIANTS: [&str; 3] = [
    "mixed_batch_with_one_invalid_expires_at_rejected_whole",
    "exact_retry_after_expiry_returns_original_result",
    "unknown_and_revoked_recipients_are_indistinguishable",
];
const EXPIRES_AT_DEFECTS: [&str; 4] = ["missing", "expired", "before_sent_at", "over_limit"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recipient {
    Deliverable,
    NeverAuthorized,
    Revoked,
}

/// One target as the sender presents it, before typed decoding.
#[derive(Clone, Debug)]
struct RawTarget {
    principal_id: String,
    device_id: String,
    device_message_id: String,
    expires_at: Option<DateTime<Utc>>,
}

impl RawTarget {
    fn wire(&self) -> Value {
        let mut target = Map::new();
        target.insert("device_message_id".into(), json!(self.device_message_id));
        target.insert("kind".into(), json!(KIND));
        target.insert("content".into(), json!({"ciphertext": "b3BhcXVl"}));
        if let Some(expires_at) = self.expires_at {
            target.insert("expires_at".into(), json!(canonical(expires_at)));
        }
        Value::Object(target)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SendResult {
    ParamInvalid,
    Outcome(Value),
}

struct Station {
    max_ttl: Duration,
    recipients: BTreeMap<(String, String), Recipient>,
    /// Exact idempotency records: device_message_id -> (canonical intent,
    /// original outcome).
    idempotency: BTreeMap<String, (Value, Value)>,
    queue: Vec<String>,
}

impl Station {
    fn new(max_ttl: Duration) -> Self {
        Self {
            max_ttl,
            recipients: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            queue: Vec::new(),
        }
    }

    fn send(&mut self, targets: &[RawTarget], clock: DateTime<Utc>) -> Result<SendResult> {
        // Exact retries are recognised first, before any expiry check.
        let mut exact = Vec::new();
        let mut fresh = Vec::new();
        for target in targets {
            let intent = json!({
                "recipient": [target.principal_id, target.device_id],
                "target": target.wire(),
            });
            match self.idempotency.get(&target.device_message_id) {
                Some((recorded, outcome)) if *recorded == intent => {
                    exact.push(outcome.clone());
                }
                Some(_) => bail!("the vector registers no conflicting retry"),
                None => fresh.push((target, intent)),
            }
        }
        let sent_at = clock;
        let mut admitted = Vec::new();
        for (target, intent) in &fresh {
            let Ok(typed) = serde_json::from_value::<DeviceMessageTarget>(target.wire()) else {
                return Ok(SendResult::ParamInvalid);
            };
            if typed.expires_at <= clock
                || typed.expires_at < sent_at
                || typed.expires_at - sent_at > self.max_ttl
            {
                return Ok(SendResult::ParamInvalid);
            }
            admitted.push((*target, intent.clone(), typed));
        }

        let mut outcome = DeviceMessagesSendOutcome {
            delivered: BTreeMap::new(),
            unknown_devices: BTreeMap::new(),
        };
        for original in exact {
            let original: DeviceMessagesSendOutcome = serde_json::from_value(original)?;
            for (principal, rows) in original.delivered {
                outcome.delivered.entry(principal).or_default().extend(rows);
            }
            for (principal, rows) in original.unknown_devices {
                outcome
                    .unknown_devices
                    .entry(principal)
                    .or_default()
                    .extend(rows);
            }
        }
        for (target, intent, typed) in admitted {
            let principal = DidCoreId::new(target.principal_id.clone())?;
            let device = DeviceId::new(target.device_id.clone())?;
            let mut single = DeviceMessagesSendOutcome {
                delivered: BTreeMap::new(),
                unknown_devices: BTreeMap::new(),
            };
            match self
                .recipients
                .get(&(target.principal_id.clone(), target.device_id.clone()))
                .copied()
                .unwrap_or(Recipient::NeverAuthorized)
            {
                Recipient::Deliverable => {
                    self.queue.push(target.device_message_id.clone());
                    single.delivered.entry(principal).or_default().insert(
                        device,
                        DeviceMessageDeliveredRow {
                            device_message_id: typed.device_message_id,
                            status: DeviceMessageDeliveredStatus::Delivered,
                        },
                    );
                }
                Recipient::NeverAuthorized | Recipient::Revoked => {
                    single.unknown_devices.entry(principal).or_default().insert(
                        device,
                        DeviceMessageUnknownRow {
                            device_message_id: typed.device_message_id,
                            status: DeviceMessageUnknownStatus::Unknown,
                        },
                    );
                }
            }
            self.idempotency.insert(
                target.device_message_id.clone(),
                (intent, serde_json::to_value(&single)?),
            );
            for (principal, rows) in single.delivered {
                outcome.delivered.entry(principal).or_default().extend(rows);
            }
            for (principal, rows) in single.unknown_devices {
                outcome
                    .unknown_devices
                    .entry(principal)
                    .or_default()
                    .extend(rows);
            }
        }
        Ok(SendResult::Outcome(serde_json::to_value(outcome)?))
    }
}

pub fn run_device_message_send_admission_vector() -> Result<()> {
    let fixture = load_fixture_value(EDGE_CASE_FIXTURE)?;
    ensure!(
        fixture["covers_vectors"].as_array().is_some_and(|ids| ids
            .iter()
            .any(|id| id == VECTOR_ID_DEVICE_MESSAGE_SEND_ADMISSION)),
        "protocol edge-case fixture does not cover {VECTOR_ID_DEVICE_MESSAGE_SEND_ADMISSION}"
    );
    let case = fixture["cases"]
        .as_array()
        .context("protocol edge-case fixture cases")?
        .iter()
        .find(|case| case["vector_id"] == VECTOR_ID_DEVICE_MESSAGE_SEND_ADMISSION)
        .cloned()
        .context("protocol edge-case fixture publishes no send-admission case")?;
    let max_ttl = Duration::milliseconds(
        case["station_max_ttl_ms"]
            .as_i64()
            .context("station_max_ttl_ms")?,
    );
    let sent_at = timestamp(&case["request_sent_at"])?;
    let variants = case["variants"]
        .as_array()
        .context("send-admission variants")?;
    let names = variants
        .iter()
        .map(|variant| variant["name"].as_str().map(str::to_owned))
        .collect::<Option<BTreeSet<_>>>()
        .context("send-admission variant name")?;
    ensure!(
        names.len() == variants.len()
            && names
                == REGISTERED_VARIANTS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
        "send-admission variants drifted from the executed set: {names:?}"
    );

    for variant in variants {
        let name = variant["name"].as_str().unwrap_or_default();
        let actual = match name {
            "mixed_batch_with_one_invalid_expires_at_rejected_whole" => {
                mixed_batch(variant, max_ttl, sent_at)?
            }
            "exact_retry_after_expiry_returns_original_result" => {
                exact_retry(variant, max_ttl, sent_at)?
            }
            "unknown_and_revoked_recipients_are_indistinguishable" => {
                unknown_rows(variant, max_ttl, sent_at)?
            }
            other => bail!("send-admission variant {other} has no executor"),
        };
        ensure!(
            actual == variant["expected"],
            "send-admission variant {name} produced {actual}, fixture expects {}",
            variant["expected"]
        );
        record_vector_event(
            "sync.device_message_send_admission",
            &json!({"vector_id": VECTOR_ID_DEVICE_MESSAGE_SEND_ADMISSION, "variant": name}),
            &variant["expected"],
            &actual,
        );
    }

    // The retired unknown-row member is not representable in the SDK DTO.
    let retired = json!({
        "device_message_id": "ak:device_message:01964137-1000-7000-8000-000000000031",
        "status": "unknown",
        "reason_code": "device_result_unavailable"
    });
    ensure!(
        serde_json::from_value::<DeviceMessageUnknownRow>(retired).is_err(),
        "the SDK still admits the removed unknown-row reason_code"
    );
    Ok(())
}

fn mixed_batch(variant: &Value, max_ttl: Duration, sent_at: DateTime<Utc>) -> Result<Value> {
    let targets = variant["targets"]
        .as_array()
        .context("mixed batch targets")?;
    ensure!(
        targets.len() == 2,
        "mixed batch pairs one valid and one defective target"
    );
    let valid = raw_target(&targets[0], Some(timestamp(&targets[0]["expires_at"])?))?;
    let defects = targets[1]["expires_at_variant"]
        .as_array()
        .context("expires_at_variant")?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .context("expires_at_variant name")?;
    ensure!(
        defects == EXPIRES_AT_DEFECTS,
        "expires_at defects drifted: {defects:?}"
    );

    // Positive control: the valid target alone is delivered, so the whole
    // batch rejection below is caused by its defective sibling.
    let mut control = station_with(&[&valid], max_ttl);
    ensure!(
        matches!(
            control.send(std::slice::from_ref(&valid), sent_at)?,
            SendResult::Outcome(_)
        ) && control.queue.len() == 1,
        "the valid target must enqueue on its own"
    );

    let mut enqueued = 0;
    let mut unknown_written = false;
    for defect in &defects {
        let expires_at = match defect.as_str() {
            "missing" => None,
            "expired" => Some(sent_at - Duration::hours(1)),
            "before_sent_at" => Some(sent_at - Duration::milliseconds(1)),
            "over_limit" => Some(sent_at + max_ttl + Duration::milliseconds(1)),
            other => bail!("unknown expires_at defect {other}"),
        };
        let defective = raw_target(&targets[1], expires_at)?;
        let mut station = station_with(&[&valid, &defective], max_ttl);
        let result = station.send(&[valid.clone(), defective], sent_at)?;
        ensure!(
            result == SendResult::ParamInvalid,
            "defect {defect} did not fail the whole request"
        );
        enqueued += station.queue.len();
        unknown_written |= !station.idempotency.is_empty();
    }
    Ok(json!({
        "decision": "reject",
        "error_code": "param_invalid",
        "enqueued": enqueued,
        "unknown_devices_written": unknown_written,
    }))
}

fn exact_retry(variant: &Value, max_ttl: Duration, sent_at: DateTime<Utc>) -> Result<Value> {
    ensure!(
        variant["retry"]
            == json!({
                "same_device_message_id": true,
                "same_canonical_intent": true,
                "station_clock_after_expires_at": true
            }),
        "exact retry preconditions drifted"
    );
    let delivered = variant["original_result"]["delivered"]
        .as_array()
        .context("original delivered rows")?;
    ensure!(
        delivered.len() == 1,
        "the vector retries one delivered target"
    );
    let expires_at = sent_at + Duration::minutes(10);
    let target = raw_target(&delivered[0], Some(expires_at))?;
    let mut station = station_with(&[&target], max_ttl);
    let SendResult::Outcome(original) = station.send(std::slice::from_ref(&target), sent_at)?
    else {
        bail!("the original send must enqueue");
    };
    let typed: DeviceMessagesSendOutcome = serde_json::from_value(original.clone())?;
    ensure!(
        typed.unknown_devices.is_empty()
            && typed
                .delivered
                .get(&DidCoreId::new(target.principal_id.clone())?)
                .and_then(|rows| rows.get(&DeviceId::new(target.device_id.clone()).ok()?))
                .is_some_and(|row| row.device_message_id
                    == DeviceMessageId::new(target.device_message_id.clone()).unwrap()),
        "original send does not match the fixture's delivered row"
    );
    let queued = station.queue.len();

    let retry_clock = expires_at + Duration::minutes(1);
    let retry = station.send(std::slice::from_ref(&target), retry_clock)?;
    // The same target without an idempotency record would fail at this clock,
    // so returning the original result proves the check order.
    let mut fresh = station_with(&[&target], max_ttl);
    let expiry_rejudged = fresh.send(&[target], retry_clock)? == retry;
    ensure!(
        retry == SendResult::Outcome(original),
        "exact retry after expiry did not return the original result"
    );
    Ok(json!({
        "decision": "original_result",
        "additional_enqueued": station.queue.len() - queued,
        "expiry_rejudged": expiry_rejudged,
    }))
}

fn unknown_rows(variant: &Value, max_ttl: Duration, sent_at: DateTime<Utc>) -> Result<Value> {
    let expires_at = sent_at + Duration::minutes(10);
    let mut station = Station::new(max_ttl);
    let mut targets = Vec::new();
    for target in variant["targets"].as_array().context("unknown targets")? {
        let raw = raw_target(target, Some(expires_at))?;
        let recipient = match target["recipient_state"].as_str() {
            Some("never_authorized") => Recipient::NeverAuthorized,
            Some("revoked") => Recipient::Revoked,
            other => bail!("unknown recipient_state {other:?}"),
        };
        station
            .recipients
            .insert((raw.principal_id.clone(), raw.device_id.clone()), recipient);
        targets.push(raw);
    }
    let SendResult::Outcome(outcome) = station.send(&targets, sent_at)? else {
        bail!("undeliverable recipients must not fail the request");
    };
    let typed: DeviceMessagesSendOutcome = serde_json::from_value(outcome.clone())?;
    ensure!(
        typed.delivered.is_empty(),
        "no recipient here is deliverable"
    );

    let mut members = BTreeSet::new();
    let mut stripped = Vec::new();
    for row in outcome["unknown_devices"]
        .as_object()
        .context("unknown_devices")?
        .values()
        .flat_map(|rows| rows.as_object().into_iter().flat_map(|rows| rows.values()))
    {
        let object = row.as_object().context("unknown row")?;
        members.extend(object.keys().cloned());
        let mut without_id = object.clone();
        without_id.remove("device_message_id");
        stripped.push(without_id);
    }
    ensure!(
        stripped.len() == targets.len(),
        "every target yields one unknown row"
    );
    Ok(json!({
        "decision": "accept",
        "unknown_row_members": members,
        "rows_differ_only_by_device_message_id": stripped.windows(2).all(|pair| pair[0] == pair[1]),
        "enqueued": station.queue.len(),
    }))
}

fn station_with(deliverable: &[&RawTarget], max_ttl: Duration) -> Station {
    let mut station = Station::new(max_ttl);
    for target in deliverable {
        station.recipients.insert(
            (target.principal_id.clone(), target.device_id.clone()),
            Recipient::Deliverable,
        );
    }
    station
}

fn raw_target(value: &Value, expires_at: Option<DateTime<Utc>>) -> Result<RawTarget> {
    let text = |key: &str| {
        value[key]
            .as_str()
            .map(str::to_owned)
            .with_context(|| format!("target {key}"))
    };
    Ok(RawTarget {
        principal_id: text("principal_id")?,
        device_id: text("device_id")?,
        device_message_id: text("device_message_id")?,
        expires_at,
    })
}

fn canonical(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn timestamp(value: &Value) -> Result<DateTime<Utc>> {
    let text = value.as_str().context("timestamp must be a string")?;
    Ok(DateTime::parse_from_rfc3339(text)
        .with_context(|| format!("parse timestamp {text}"))?
        .to_utc())
}
