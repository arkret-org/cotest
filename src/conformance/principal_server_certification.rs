use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use arkret_wire::ProfileId;
use serde_json::{Value, json};

use super::helpers::profile_claims;
use super::{load_local_fixture_value, required_str, validate_profile, value_array};
use crate::transcripts::record_vector_event;

const FIXTURE: &str = "principal-server-certification-gate.json";
const FIXTURE_PROFILE: &str = "ak.profile.principal_server_certification_gate.v1";

const REQUIRED_OPERATIONS: &[&str] = &[
    "ak.server.read.describe",
    "ak.self.account.read.describe",
    "ak.self.account.stream.subscribe",
    "ak.self.events.stream.subscribe",
    "ak.self.events.read.scan",
    "ak.self.snapshot.read.manifest_head",
    "ak.self.authz.read.check",
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
    "ak.schema.snapshot.v1",
    "ak.schema.capability.v1",
    "ak.schema.grant_constraint.v1",
];

const REQUIRED_MINIMUM_SURFACES: &[&str] = &["admin", "agent", "applet", "media"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalCertificationStatus {
    Certified,
    NotCertified,
}

pub fn run_principal_server_certification_gate_suite() -> Result<()> {
    let fixture = load_local_fixture_value(FIXTURE)?;
    validate_profile(&fixture, FIXTURE_PROFILE)?;
    let cases = value_array(
        fixture
            .get("cases")
            .ok_or_else(|| anyhow!("{FIXTURE} missing cases[]"))?,
        "principal server certification cases",
    )?;

    let mut saw_soland_not_certified = false;
    let mut saw_full_reject = false;
    let mut saw_full_pass = false;
    for case in cases {
        let name = required_str(case, "name")?;
        let expected = required_str(case, "expect")?;
        let describe = case
            .get("describe")
            .ok_or_else(|| anyhow!("{name} missing describe object"))?;
        let result = validate_principal_server_certification(describe);
        match (expected, result) {
            ("certified", Ok(PrincipalCertificationStatus::Certified)) => {
                saw_full_pass = true;
            }
            ("not_certified", Ok(PrincipalCertificationStatus::NotCertified)) => {
                if describe.get("service").and_then(Value::as_str) == Some("soland") {
                    saw_soland_not_certified = true;
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
            "principal_server_certification.case",
            &json!({
                "name": name,
                "service": describe.get("service").and_then(Value::as_str),
            }),
            &json!({ "expect": expected }),
            &json!({ "status": "ok" }),
        );
    }

    if !saw_soland_not_certified {
        bail!("{FIXTURE} must include a soland not_certified case");
    }
    if !(saw_full_reject && saw_full_pass) {
        bail!("{FIXTURE} must include both rejecting and passing full-profile claims");
    }

    Ok(())
}

pub fn validate_principal_server_certification(
    describe: &Value,
) -> Result<PrincipalCertificationStatus> {
    let claims_full = profile_claims(describe).contains(ProfileId::PRINCIPAL_SERVER_V1);
    let certification_status = certification_status(describe);
    if !claims_full {
        if certification_status == Some("certified") {
            bail!(
                "principal_server certification cannot be certified without claiming the profile"
            );
        }
        return Ok(PrincipalCertificationStatus::NotCertified);
    }

    if certification_status != Some("certified") {
        bail!("full principal_server claim requires certification.status=certified");
    }
    if contains_non_empty_limitation(describe) {
        bail!("full principal_server claim cannot carry non-empty limitations");
    }

    require_all("supported_operations", describe, REQUIRED_OPERATIONS)?;
    require_all("supported_event_kinds", describe, REQUIRED_EVENT_KINDS)?;
    require_all("supported_schemas", describe, REQUIRED_SCHEMAS)?;
    require_federation_durability(describe)?;
    require_minimum_surfaces(describe)?;

    Ok(PrincipalCertificationStatus::Certified)
}

fn certification_status(describe: &Value) -> Option<&str> {
    [
        "/certification/principal_server/status",
        "/profile_status/principal_server/status",
        "/limits/profile_status/principal_server/status",
    ]
    .into_iter()
    .find_map(|pointer| describe.pointer(pointer).and_then(Value::as_str))
}

fn require_all(field: &str, describe: &Value, required: &[&str]) -> Result<()> {
    let present = describe
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("principal_server certification missing {field}[]"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    for item in required {
        if !present.contains(item) {
            bail!("principal_server certification missing {field} entry {item}");
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
            bail!("principal_server certification missing federation {label}");
        }
    }
    Ok(())
}

fn require_minimum_surfaces(describe: &Value) -> Result<()> {
    for surface in REQUIRED_MINIMUM_SURFACES {
        let pointer = format!("/principal_server_minimum/{surface}/status");
        if describe.pointer(&pointer).and_then(Value::as_str) != Some("supported") {
            bail!("principal_server certification missing supported {surface} minimum surface");
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

fn is_empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.is_empty(),
        Value::Object(object) => object.is_empty(),
        Value::String(text) => text.trim().is_empty(),
        _ => false,
    }
}
