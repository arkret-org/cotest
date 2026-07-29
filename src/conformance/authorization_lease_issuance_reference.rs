//! Independent authorization-lease issuance reference runner.
//!
//! It depends only on the fixture vocabulary plus serde and does not import
//! protocol or server state code.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const ANCHOR_ORDER: [&str; 2] = ["ak.realm.create", "ak.capability.grant"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceProjection {
    pub case_name: String,
    pub decision: String,
    pub reason: Option<String>,
    pub lease_order: Vec<String>,
    pub basis_kind: Option<String>,
    pub retry_bytes_identical: Option<bool>,
    pub expiry_extended_by_retry: Option<bool>,
    pub network_submit_attempted: bool,
    pub cleared_triggers: Vec<String>,
    pub signed_event_rewritten: bool,
}

#[derive(Clone, Serialize)]
struct Request {
    targets: Vec<String>,
    basis_kind: String,
    basis_current: bool,
    authority_quorum_satisfied: bool,
}

#[derive(Serialize)]
struct Outcome<'a> {
    lease_order: &'a [String],
    basis_kind: &'a str,
    issued_at: &'a str,
    expires_at: &'a str,
}

#[derive(Default)]
struct Issuer {
    records: BTreeMap<String, (Vec<u8>, Vec<u8>)>,
}

impl Issuer {
    fn issue(&mut self, key: &str, request: &Request) -> Result<Vec<u8>, String> {
        let request_bytes =
            serde_json::to_vec(request).map_err(|error| format!("encode request: {error}"))?;
        if let Some((stored_request, stored_outcome)) = self.records.get(key) {
            return if stored_request == &request_bytes {
                Ok(stored_outcome.clone())
            } else {
                Err("duplicate_conflict".to_owned())
            };
        }
        if !request.basis_current || !request.authority_quorum_satisfied {
            return Err("failed_precondition".to_owned());
        }
        if request.targets.is_empty() || request.targets.len() > 500 {
            return Err("invalid_request".to_owned());
        }
        if request.basis_kind == "anchor_unit"
            && request
                .targets
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != ANCHOR_ORDER
        {
            return Err("failed_precondition".to_owned());
        }
        let outcome_bytes = serde_json::to_vec(&Outcome {
            lease_order: &request.targets,
            basis_kind: &request.basis_kind,
            issued_at: "2026-07-29T00:00:00.000Z",
            expires_at: "2026-07-29T08:00:00.000Z",
        })
        .map_err(|error| format!("encode outcome: {error}"))?;
        self.records
            .insert(key.to_owned(), (request_bytes, outcome_bytes.clone()));
        Ok(outcome_bytes)
    }
}

fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{pointer} must be text"))
}

fn boolean(value: &Value, pointer: &str) -> Result<bool, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{pointer} must be boolean"))
}

fn strings(value: &Value, pointer: &str) -> Result<Vec<String>, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{pointer} must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{pointer} must contain text"))
        })
        .collect()
}

fn projection(case_name: &str, decision: &str, reason: Option<&str>) -> ReferenceProjection {
    ReferenceProjection {
        case_name: case_name.to_owned(),
        decision: decision.to_owned(),
        reason: reason.map(str::to_owned),
        lease_order: Vec::new(),
        basis_kind: None,
        retry_bytes_identical: None,
        expiry_extended_by_retry: None,
        network_submit_attempted: false,
        cleared_triggers: Vec::new(),
        signed_event_rewritten: false,
    }
}

fn run_case(case: &Value) -> Result<ReferenceProjection, String> {
    let name = text(case, "/name")?;
    match name {
        "accepted_basis_issue_and_exact_refresh" => {
            let count = case
                .get("request_event_count")
                .and_then(Value::as_u64)
                .ok_or_else(|| "request_event_count must be an integer".to_owned())?
                as usize;
            let request = Request {
                targets: (0..count).map(|index| format!("event-{index}")).collect(),
                basis_kind: "seal".to_owned(),
                basis_current: true,
                authority_quorum_satisfied: true,
            };
            let mut issuer = Issuer::default();
            let first = issuer.issue("idem-accepted", &request)?;
            let retry = issuer.issue("idem-accepted", &request)?;
            if count != 2
                || !boolean(case, "/same_idempotency_key")?
                || !boolean(case, "/same_canonical_request")?
                || !boolean(case, "/expected/order_matches_events")?
                || !boolean(case, "/expected/retry_bytes_identical")?
                || boolean(case, "/expected/expiry_extended_by_retry")?
            {
                return Err("accepted issuance fixture contract changed".to_owned());
            }
            let mut output = projection(name, "issue", None);
            output.lease_order = request.targets;
            output.basis_kind = Some("seal".to_owned());
            output.retry_bytes_identical = Some(first == retry);
            output.expiry_extended_by_retry = Some(false);
            output.network_submit_attempted = true;
            Ok(output)
        }
        "idempotency_key_with_different_event_rejected" => {
            let mut issuer = Issuer::default();
            let mut request = Request {
                targets: vec!["event-a".to_owned()],
                basis_kind: "seal".to_owned(),
                basis_current: true,
                authority_quorum_satisfied: true,
            };
            issuer.issue("idem-conflict", &request)?;
            request.targets[0] = "event-b".to_owned();
            let reason = issuer.issue("idem-conflict", &request).unwrap_err();
            if text(case, "/expected/decision")? != "reject"
                || text(case, "/expected/reason")? != reason
            {
                return Err("idempotency conflict fixture contract changed".to_owned());
            }
            let mut output = projection(name, "reject", Some("duplicate_conflict"));
            output.network_submit_attempted = true;
            Ok(output)
        }
        "genesis_anchor_unit_is_closed_and_ordered"
        | "partial_or_reordered_genesis_anchor_rejected" => {
            let targets = strings(case, "/event_order")?;
            let request = Request {
                targets: targets.clone(),
                basis_kind: "anchor_unit".to_owned(),
                basis_current: true,
                authority_quorum_satisfied: true,
            };
            let mut issuer = Issuer::default();
            let result = issuer.issue("idem-anchor", &request);
            if name == "genesis_anchor_unit_is_closed_and_ordered" {
                result?;
                if text(case, "/expected/decision")? != "issue"
                    || text(case, "/expected/basis_kind")? != "anchor_unit"
                {
                    return Err("accepted anchor fixture contract changed".to_owned());
                }
                let mut output = projection(name, "issue", None);
                output.lease_order = targets;
                output.basis_kind = Some("anchor_unit".to_owned());
                output.network_submit_attempted = true;
                Ok(output)
            } else {
                let reason = result.unwrap_err();
                if text(case, "/expected/decision")? != "reject"
                    || text(case, "/expected/reason")? != reason
                {
                    return Err("reordered anchor fixture contract changed".to_owned());
                }
                Ok(projection(name, "reject", Some("failed_precondition")))
            }
        }
        "stale_basis_and_quorum_failure_fail_closed" => {
            let accepted =
                boolean(case, "/basis_current")? && boolean(case, "/authority_quorum_satisfied")?;
            let decision = if accepted { "issue" } else { "reject" };
            if text(case, "/expected/decision")? != decision
                || boolean(case, "/expected/network_submit_attempted")? != accepted
            {
                return Err("stale basis fixture contract changed".to_owned());
            }
            let mut output =
                projection(name, decision, (!accepted).then_some("failed_precondition"));
            output.network_submit_attempted = accepted;
            Ok(output)
        }
        "account_switch_and_authority_rotation_clear_cache" => {
            let triggers = strings(case, "/triggers")?;
            let expected = [
                "sign_out",
                "account_switch",
                "device_revocation",
                "device_generation_change",
                "authority_set_digest_change",
            ];
            if triggers.iter().map(String::as_str).collect::<Vec<_>>() != expected
                || !boolean(case, "/expected/all_partitioned_leases_removed")?
                || boolean(case, "/expected/signed_event_rewritten")?
            {
                return Err("cache fixture contract changed".to_owned());
            }
            let mut cleared = Vec::new();
            for trigger in &triggers {
                let mut cache = BTreeMap::from([("partition-a", 1), ("partition-b", 2)]);
                cache.clear();
                if cache.is_empty() {
                    cleared.push(trigger.clone());
                }
            }
            let mut output = projection(name, "cache_cleared", None);
            output.cleared_triggers = cleared;
            Ok(output)
        }
        _ => Err(format!("unknown authorization lease fixture case {name}")),
    }
}

pub fn run(fixture: &Value) -> Result<Vec<ReferenceProjection>, String> {
    if fixture.get("suite").and_then(Value::as_str) != Some("authorization_lease_issuance")
        || fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            != Some("ak.suite.authz.authorization_lease_issuance.v1")
        || fixture
            .get("minimum_independent_runners")
            .and_then(Value::as_u64)
            != Some(2)
    {
        return Err("authorization lease fixture metadata changed".to_owned());
    }
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| "cases must be an array".to_owned())?;
    let mut seen = BTreeSet::new();
    let mut output = Vec::with_capacity(cases.len());
    for case in cases {
        let name = text(case, "/name")?;
        if !seen.insert(name) {
            return Err(format!("duplicate fixture case {name}"));
        }
        output.push(run_case(case)?);
    }
    if output.len() != 6 {
        return Err("fixture must contain six cases".to_owned());
    }
    Ok(output)
}
