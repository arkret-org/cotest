use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use arkret_wire::ProfileId;
use serde_json::{Value, json};

use super::helpers::{is_empty_json_value, profile_claims};
use super::{load_local_fixture_value, required_str, validate_profile, value_array};
use crate::transcripts::record_vector_event;

const FIXTURE: &str = "station-certification-gate.json";
const FIXTURE_PROFILE: &str = "ak.profile.station_certification_gate.v1";

const REQUIRED_OPERATIONS: &[&str] = &[
    "ak.server.read.describe.v1",
    "ak.self.account.read.describe.v1",
    "ak.self.account.stream.subscribe.v1",
    "ak.self.committed_event.stream.subscribe.v1",
    "ak.self.committed_event.read.scan.v1",
    "ak.self.realm_state_snapshot.read.manifest_head.v1",
    "ak.self.authz.read.check.v1",
];

const REQUIRED_EVENT_KINDS: &[&str] = &[
    "ak.space.create",
    "ak.member.state",
    "ak.strand.create",
    "ak.message.create",
    "ak.capability.grant",
    "ak.capability.revoke",
];

const REQUIRED_SCHEMAS: &[&str] = &[
    "ak.schema.account_subscribe_frame.v1",
    "ak.schema.realm_state_snapshot.v1",
    "ak.schema.capability.v1",
    "ak.schema.grant_constraint.v1",
];

const REQUIRED_MINIMUM_SURFACES: &[&str] = &["admin", "agent", "applet", "media"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StationCertificationStatus {
    Certified,
    NotCertified,
}

pub fn run_station_certification_gate_suite() -> Result<()> {
    let fixture = load_local_fixture_value(FIXTURE)?;
    validate_profile(&fixture, FIXTURE_PROFILE)?;
    let cases = value_array(
        fixture
            .get("cases")
            .ok_or_else(|| anyhow!("{FIXTURE} missing cases[]"))?,
        "Station certification cases",
    )?;

    let mut saw_coland_not_certified = false;
    let mut saw_full_reject = false;
    let mut saw_full_pass = false;
    for case in cases {
        let name = required_str(case, "name")?;
        let expected = required_str(case, "expect")?;
        let describe = case
            .get("describe")
            .ok_or_else(|| anyhow!("{name} missing describe object"))?;
        let result = validate_station_certification(describe);
        match (expected, result) {
            ("certified", Ok(StationCertificationStatus::Certified)) => {
                saw_full_pass = true;
            }
            ("not_certified", Ok(StationCertificationStatus::NotCertified)) => {
                if describe.get("service").and_then(Value::as_str) == Some("coland") {
                    saw_coland_not_certified = true;
                }
            }
            ("reject", Err(_)) => {
                saw_full_reject = true;
            }
            ("reject", Ok(status)) => bail!("{name} expected reject but returned {status:?}"),
            ("certified", Err(error)) | ("not_certified", Err(error)) => {
                bail!("{name} expected {expected} but failed: {error}");
            }
            _ => bail!("{name} uses unknown expect value {expected}"),
        }

        record_vector_event(
            "station_certification.case",
            &json!({
                "name": name,
                "service": describe.get("service").and_then(Value::as_str),
            }),
            &json!({ "expect": expected }),
            &json!({ "status": "ok" }),
        );
    }

    if !saw_coland_not_certified {
        bail!("{FIXTURE} must include a coland not_certified case");
    }
    if !(saw_full_reject && saw_full_pass) {
        bail!("{FIXTURE} must include both rejecting and passing full-profile claims");
    }

    Ok(())
}

pub fn validate_station_certification(describe: &Value) -> Result<StationCertificationStatus> {
    let claims_full = profile_claims(describe).contains(ProfileId::STATION_V1);
    let certification_status = certification_status(describe);
    if !claims_full {
        if certification_status == Some("certified") {
            bail!("station certification cannot be certified without claiming the profile");
        }
        return Ok(StationCertificationStatus::NotCertified);
    }

    if certification_status != Some("certified") {
        bail!("full station claim requires certification.status=certified");
    }
    if contains_non_empty_limitation(describe) {
        bail!("full station claim cannot carry non-empty limitations");
    }

    require_all_operation_bundles(describe, REQUIRED_OPERATIONS)?;
    require_all("supported_event_kinds", describe, REQUIRED_EVENT_KINDS)?;
    require_all("supported_schemas", describe, REQUIRED_SCHEMAS)?;
    require_federation_durability(describe)?;
    require_minimum_surfaces(describe)?;

    Ok(StationCertificationStatus::Certified)
}

fn certification_status(describe: &Value) -> Option<&str> {
    [
        "/certification/station/status",
        "/profile_status/station/status",
        "/limits/profile_status/station/status",
    ]
    .into_iter()
    .find_map(|pointer| describe.pointer(pointer).and_then(Value::as_str))
}

fn require_all(field: &str, describe: &Value, required: &[&str]) -> Result<()> {
    let present = describe
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("station certification missing {field}[]"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    for item in required {
        if !present.contains(item) {
            bail!("station certification missing {field} entry {item}");
        }
    }
    Ok(())
}

fn require_all_operation_bundles(describe: &Value, required: &[&str]) -> Result<()> {
    let present = describe
        .get("supported_operation_bundles")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("station certification missing supported_operation_bundles[]"))?
        .iter()
        .filter_map(Value::as_str)
        .filter_map(arkret_wire::operation_bundle_descriptor)
        .flat_map(|bundle| bundle.members)
        .map(|binding| binding.operation_id.as_str())
        .collect::<BTreeSet<_>>();
    for item in required {
        if !present.contains(item) {
            bail!("station certification bundles do not cover {item}");
        }
    }
    Ok(())
}

fn require_federation_durability(describe: &Value) -> Result<()> {
    for (pointer, label) in [
        (
            "/federation/outbound/http_message_signatures",
            "HTTP Message Signatures",
        ),
        (
            "/federation/outbound/durable_retry_queue",
            "durable retry queue",
        ),
        ("/federation/outbound/retry_worker", "retry worker"),
        (
            "/federation/outbound/dead_letter_audit",
            "dead-letter audit",
        ),
    ] {
        if describe.pointer(pointer).and_then(Value::as_bool) != Some(true) {
            bail!("station certification missing federation {label}");
        }
    }
    Ok(())
}

fn require_minimum_surfaces(describe: &Value) -> Result<()> {
    for surface in REQUIRED_MINIMUM_SURFACES {
        let pointer = format!("/station_minimum/{surface}/status");
        if describe.pointer(&pointer).and_then(Value::as_str) != Some("supported") {
            bail!("station certification missing supported {surface} minimum surface");
        }
    }
    Ok(())
}

fn contains_non_empty_limitation(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, item)| {
            matches!(key.as_str(), "limitation" | "limitations") && !is_empty_json_value(item)
                || contains_non_empty_limitation(item)
        }),
        Value::Array(items) => items.iter().any(contains_non_empty_limitation),
        _ => false,
    }
}
