use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use url::Url;

use super::{
    canonical_json, load_local_fixture_value, looks_like_sha256_digest, required_field,
    required_str, sha256_prefixed, validate_profile, value_field_u64,
};
use crate::transcripts::record_vector_event;

const FIXTURE: &str = "security-negative-profile-fixture.json";
const SUITE: &str = "security_negative_profile";

pub fn run_security_negative_profile_suite() -> Result<()> {
    let fixture = load_local_fixture_value(FIXTURE)?;
    if required_str(&fixture, "suite")? != SUITE {
        bail!("{FIXTURE} suite must be {SUITE}");
    }
    validate_profile(&fixture, "cx.profile.privacy_security_vectors.v1")?;

    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{FIXTURE} missing cases[]"))?;
    let mut covered = SecurityCoverage::default();

    for case in cases {
        let name = required_str(case, "name")?;
        let category = required_str(case, "category")?;
        let expected = required_field(case, "expected")?;
        if expected.get("hard_fail").and_then(Value::as_bool) != Some(true) {
            bail!("security negative {name} must declare hard_fail=true");
        }

        let decision = match category {
            "bad_signature" => {
                covered.bad_signature = true;
                validate_bad_signature(case)?
            }
            "bad_canonical_bytes" => {
                covered.bad_canonical_bytes = true;
                validate_bad_canonical_bytes(case)?
            }
            "bad_schema_payload" => {
                covered.bad_schema_payload = true;
                validate_bad_schema_payload(case)?
            }
            "replay" => {
                covered.replay = true;
                validate_replay(case)?
            }
            "downgrade" => {
                covered.downgrade = true;
                validate_downgrade(case)?
            }
            "query_auth_leakage" => {
                covered.query_auth_leakage = true;
                validate_query_auth_leakage(case)?
            }
            other => bail!("unknown security negative category {other} in {name}"),
        };
        assert_decision(name, &decision, expected)?;
        record_vector_event(
            &format!("security_negative.{category}"),
            required_field(case, "input")?,
            expected,
            &json!({
                "decision": decision.decision,
                "error_code": decision.error_code,
            }),
        );
    }

    covered.ensure_complete()?;
    Ok(())
}

fn validate_bad_signature(case: &Value) -> Result<SecurityDecision> {
    let event = required_field(required_field(case, "input")?, "event")?;
    let computed = canonical_event_hash(event)?;
    for proof in event
        .get("proofs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(payload_hash) = proof.get("payload_hash").and_then(Value::as_str) else {
            return Ok(SecurityDecision::reject("invalid_signature"));
        };
        if !looks_like_sha256_digest(payload_hash)
            || payload_hash == zero_sha256()
            || payload_hash != computed
        {
            return Ok(SecurityDecision::reject("invalid_signature"));
        }
    }
    Ok(SecurityDecision::accept())
}

fn validate_bad_canonical_bytes(case: &Value) -> Result<SecurityDecision> {
    let input = required_field(case, "input")?;
    let stored = required_field(input, "stored_event")?;
    let incoming = required_field(input, "incoming_event")?;
    if required_str(stored, "event_id")? != required_str(incoming, "event_id")? {
        return Ok(SecurityDecision::accept());
    }
    let stored_hash = canonical_event_hash(stored)?;
    let incoming_hash = canonical_event_hash(incoming)?;
    if stored_hash != incoming_hash {
        return Ok(SecurityDecision::quarantine("duplicate_conflict"));
    }
    Ok(SecurityDecision::accept())
}

fn validate_bad_schema_payload(case: &Value) -> Result<SecurityDecision> {
    let event = required_field(required_field(case, "input")?, "event")?;
    for field in [
        "event_id",
        "kind",
        "space_id",
        "actor_id",
        "actor_seq",
        "created_at",
        "prev_refs",
        "refs",
        "payload",
        "proofs",
    ] {
        if event.get(field).is_none() {
            return Ok(SecurityDecision::reject("schema_violation"));
        }
    }
    if required_str(event, "kind")? == "cx.message.create" {
        let payload = required_field(event, "payload")?;
        let has_body = ["body", "blocks", "encrypted_payload", "blob_refs"]
            .iter()
            .any(|field| payload.get(*field).is_some());
        if payload.get("flow_id").and_then(Value::as_str).is_none() || !has_body {
            return Ok(SecurityDecision::reject("schema_violation"));
        }
    }
    Ok(SecurityDecision::accept())
}

fn validate_replay(case: &Value) -> Result<SecurityDecision> {
    let input = required_field(case, "input")?;
    let event = required_field(input, "event")?;
    let frontier = required_field(input, "actor_frontier")?;
    if required_str(event, "actor_id")? == required_str(frontier, "actor_id")?
        && value_field_u64(event, "actor_seq")? <= value_field_u64(frontier, "actor_seq")?
    {
        return Ok(SecurityDecision::reject("causal_conflict"));
    }
    Ok(SecurityDecision::accept())
}

fn validate_downgrade(case: &Value) -> Result<SecurityDecision> {
    let input = required_field(case, "input")?;
    let event = required_field(input, "event")?;
    let supported = input
        .get("supported_features")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    for extension in event
        .pointer("/requirements/critical_extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = required_str(extension, "id")?;
        if extension.get("fail_closed").and_then(Value::as_bool) == Some(true)
            && !supported.contains(&id)
        {
            return Ok(SecurityDecision::reject("unsupported_feature"));
        }
    }
    Ok(SecurityDecision::accept())
}

fn validate_query_auth_leakage(case: &Value) -> Result<SecurityDecision> {
    let request = required_field(required_field(case, "input")?, "request")?;
    let url = required_str(request, "url")?;
    let parsed =
        Url::parse(url).or_else(|_| Url::parse(&format!("https://cotest.invalid{url}")))?;
    let leaked = parsed.query_pairs().any(|(key, value)| {
        let key = key.to_ascii_lowercase();
        matches!(
            key.as_str(),
            "access_token"
                | "api_key"
                | "auth"
                | "authorization"
                | "bearer"
                | "signature"
                | "sig"
                | "token"
        ) && !value.is_empty()
    });
    if leaked {
        return Ok(SecurityDecision::reject("query_auth_leakage"));
    }
    Ok(SecurityDecision::accept())
}

fn canonical_event_hash(event: &Value) -> Result<String> {
    let object = event
        .as_object()
        .ok_or_else(|| anyhow!("event must be an object"))?;
    let mut without_proofs = serde_json::Map::new();
    for (key, value) in object {
        if key != "proofs" && key != "unsigned" {
            without_proofs.insert(key.clone(), value.clone());
        }
    }
    Ok(sha256_prefixed(
        canonical_json(&Value::Object(without_proofs))?.as_bytes(),
    ))
}

fn assert_decision(name: &str, actual: &SecurityDecision, expected: &Value) -> Result<()> {
    let expected_decision = required_str(expected, "decision")?;
    if actual.decision != expected_decision {
        bail!(
            "security negative {name} decision drift: expected {expected_decision}, got {}",
            actual.decision
        );
    }
    let expected_error = expected.get("error_code").and_then(Value::as_str);
    if actual.error_code != expected_error {
        bail!(
            "security negative {name} error drift: expected {:?}, got {:?}",
            expected_error,
            actual.error_code
        );
    }
    if actual.decision == "accept" {
        bail!("security negative {name} accepted a hard-fail vector");
    }
    Ok(())
}

fn zero_sha256() -> &'static str {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

#[derive(Debug)]
struct SecurityDecision {
    decision: &'static str,
    error_code: Option<&'static str>,
}

impl SecurityDecision {
    fn accept() -> Self {
        Self {
            decision: "accept",
            error_code: None,
        }
    }

    fn reject(error_code: &'static str) -> Self {
        Self {
            decision: "reject",
            error_code: Some(error_code),
        }
    }

    fn quarantine(error_code: &'static str) -> Self {
        Self {
            decision: "quarantine",
            error_code: Some(error_code),
        }
    }
}

#[derive(Default)]
struct SecurityCoverage {
    bad_signature: bool,
    bad_canonical_bytes: bool,
    bad_schema_payload: bool,
    replay: bool,
    downgrade: bool,
    query_auth_leakage: bool,
}

impl SecurityCoverage {
    fn ensure_complete(&self) -> Result<()> {
        let missing = [
            ("bad_signature", self.bad_signature),
            ("bad_canonical_bytes", self.bad_canonical_bytes),
            ("bad_schema_payload", self.bad_schema_payload),
            ("replay", self.replay),
            ("downgrade", self.downgrade),
            ("query_auth_leakage", self.query_auth_leakage),
        ]
        .into_iter()
        .filter_map(|(name, covered)| (!covered).then_some(name))
        .collect::<Vec<_>>();
        if !missing.is_empty() {
            bail!("security negative fixture missing categories: {missing:?}");
        }
        Ok(())
    }
}
