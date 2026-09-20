//! Static and public-SDK conformance for endpoint-specific Event submit carriers.
//!
//! This suite intentionally does not claim live Station persistence, atomicity,
//! signature verification, or federation delivery. Those semantics remain in
//! the canonical named-suite gap ledger until a real service runner exists.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, ensure};
use arkret_models_collaboration::authority_commit::{
    DirectConversationFoundingDependencyMissingProblem, PeerAuthoritySubmitOutcome,
    PeerAuthoritySubmitRequest, SelfAuthoritySubmitRequest,
};
use arkret_wire::EventCommitSubmission;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{load_artifact_json, spec_artifacts_root};
use crate::conformance::schema_validation_fixture::{schema_invalid, schema_valid};

const LOCAL_FIXTURE: &str = "authority-event-submit-carriers.json";
const CANONICAL_FIXTURE: &str = "peer-event-submit-semantic-union-fixture.json";
const CANONICAL_ENTRYPOINT: &str = "ak.suite.peer.event_submit.semantic_union.v1";

const SELF_REQUEST: &str =
    "schemas/authority-commit-operations.schema.json#/$defs/self_submit_request";
const PEER_REQUEST: &str =
    "schemas/authority-commit-operations.schema.json#/$defs/peer_submit_request";
const PEER_OUTCOME: &str =
    "schemas/authority-commit-operations.schema.json#/$defs/peer_submit_outcome";
const DEPENDENCY_PROBLEM: &str = "schemas/authority-commit-operations.schema.json#/$defs/direct_conversation_founding_dependency_missing_problem";

const EVENT_ID: &str = "ak:event:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRB";
const REALM_ID: &str = "ak:realm:ATh7OWLLpUdTVYsKdp6rkClScUpjYJlF1Y3byjeyHS8J";
const COMMIT_ID: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";
const STRAND_ID: &str = "ak:strand:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityEventSubmitCarrierCoverage {
    pub assertions: usize,
    pub static_cases: Vec<String>,
    pub canonical_named_suite: String,
    pub service_e2e_status: String,
}

pub fn run_authority_event_submit_carrier_conformance()
-> Result<AuthorityEventSubmitCarrierCoverage> {
    let local = load_local_fixture()?;
    ensure!(local["canonical_named_suite"] == CANONICAL_ENTRYPOINT);
    ensure!(local["execution_scope"] == "schema_and_public_sdk_roundtrip");
    ensure!(local["service_e2e_status"] == "unwired");

    let cases = local["required_static_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("required_static_cases must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("required_static_cases contains a non-string"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(cases.len() == 10, "static case ledger must remain closed");

    let canonical = load_artifact_json(&format!("fixtures/{CANONICAL_FIXTURE}"))?;
    assert_canonical_semantic_ledger(&canonical)?;

    let approved = approved_event_submission()?;
    let mut assertions = assert_endpoint_unions_and_approval(&approved)?;
    assertions += assert_replication_carrier(&approved)?;
    assertions += assert_direct_conversation_carriers(&approved)?;
    assertions += assert_membership_compensation_carriers(&approved)?;
    assertions += assert_dependency_problem()?;
    assertions += assert_removed_and_partial_shapes_stay_rejected()?;

    Ok(AuthorityEventSubmitCarrierCoverage {
        assertions,
        static_cases: cases,
        canonical_named_suite: CANONICAL_ENTRYPOINT.to_owned(),
        service_e2e_status: "unwired".to_owned(),
    })
}

fn load_local_fixture() -> Result<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(LOCAL_FIXTURE);
    serde_json::from_slice(&fs::read(&path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn assert_canonical_semantic_ledger(fixture: &Value) -> Result<()> {
    ensure!(fixture.pointer("/runner/kind").and_then(Value::as_str) == Some("named_suite"));
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(CANONICAL_ENTRYPOINT)
    );
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| anyhow!("canonical semantic fixture has no cases"))?;
    let names = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect::<Vec<_>>();
    ensure!(
        names
            == [
                "authority_forward",
                "committed_replication",
                "direct_conversation_founding",
                "founding_authoring_material_non_echo",
                "membership_compensation",
            ],
        "canonical semantic case registry drifted"
    );
    for required_variant in [
        "bounded_source_event_and_commit_stored",
        "one_item_rejected_other_item_stored",
        "self_four_ordered_events_atomic_commit",
        "peer_four_source_commits_atomic_materialization",
        "dependency_missing_closed_details",
        "self_terminal_failure_compensation",
        "peer_source_committed_compensation",
    ] {
        ensure!(contains_string(fixture, required_variant));
    }
    Ok(())
}

fn assert_endpoint_unions_and_approval(approved: &Value) -> Result<usize> {
    schema_valid(SELF_REQUEST, approved)?;
    assert_roundtrip::<EventCommitSubmission>(approved)?;
    assert_roundtrip::<SelfAuthoritySubmitRequest>(approved)?;
    ensure!(
        approved["approval_signatures"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    );

    let mut without_approval = approved.clone();
    without_approval
        .as_object_mut()
        .expect("submission object")
        .remove("approval_signatures");
    ensure!(without_approval["event"] == approved["event"]);
    schema_valid(SELF_REQUEST, &without_approval)?;

    let peer = json!({"branch": "authority_forward", "event_submission": approved});
    schema_valid(PEER_REQUEST, &peer)?;
    assert_roundtrip::<PeerAuthoritySubmitRequest>(&peer)?;

    let mut mixed = peer;
    mixed["mls_submission"] = json!({});
    schema_invalid(PEER_REQUEST, &mixed)?;
    schema_invalid(
        PEER_REQUEST,
        &json!({"branch": "future_branch", "event_submission": approved}),
    )?;
    Ok(10)
}

fn assert_replication_carrier(approved: &Value) -> Result<usize> {
    let item = replication_item(approved.clone());
    let request = replication_request(vec![item.clone()]);
    schema_valid(PEER_REQUEST, &request)?;
    assert_roundtrip::<PeerAuthoritySubmitRequest>(&request)?;

    let hundred = replication_request((0..100).map(|_| item.clone()).collect());
    schema_valid(PEER_REQUEST, &hundred)?;
    let zero = replication_request(Vec::new());
    schema_invalid(PEER_REQUEST, &zero)?;
    let hundred_one = replication_request((0..101).map(|_| item.clone()).collect());
    schema_invalid(PEER_REQUEST, &hundred_one)?;

    let mut missing_commit = request.clone();
    missing_commit["submissions"][0]["committed_event"]
        .as_object_mut()
        .expect("committed event object")
        .remove("source_commit");
    schema_invalid(PEER_REQUEST, &missing_commit)?;

    let mut missing_witness = request;
    missing_witness["submissions"][0]
        .as_object_mut()
        .expect("replication item object")
        .remove("recipient_witnesses");
    schema_invalid(PEER_REQUEST, &missing_witness)?;
    Ok(7)
}

fn assert_direct_conversation_carriers(approved: &Value) -> Result<usize> {
    let events = direct_conversation_events(approved);
    let self_request = json!({
        "unit_kind": "direct_conversation_founding",
        "idempotency_key": "0199fabc-1234-7abc-8abc-1234567890ab",
        "events": events
    });
    schema_valid(SELF_REQUEST, &self_request)?;
    assert_roundtrip::<SelfAuthoritySubmitRequest>(&self_request)?;

    let mut wrong_order = self_request.clone();
    wrong_order["events"].as_array_mut().unwrap().swap(2, 3);
    schema_invalid(SELF_REQUEST, &wrong_order)?;

    let mut echoed_evidence = self_request;
    echoed_evidence["founding_authority_evidence"] = founding_evidence();
    schema_invalid(SELF_REQUEST, &echoed_evidence)?;

    let committed_events = direct_conversation_events(approved)
        .into_iter()
        .enumerate()
        .map(|(index, submission)| {
            json!({
                "event_submission": submission,
                "source_commit": realm_commit(index as u64)
            })
        })
        .collect::<Vec<_>>();
    let peer_request = json!({
        "branch": "registered_atomic_unit",
        "unit": {
            "unit_kind": "direct_conversation_founding",
            "committed_events": committed_events,
            "founding_authority_evidence": founding_evidence()
        }
    });
    schema_valid(PEER_REQUEST, &peer_request)?;
    assert_roundtrip::<PeerAuthoritySubmitRequest>(&peer_request)?;

    let mut missing_evidence = peer_request.clone();
    missing_evidence["unit"]
        .as_object_mut()
        .unwrap()
        .remove("founding_authority_evidence");
    schema_invalid(PEER_REQUEST, &missing_evidence)?;

    let mut legacy_receipt = peer_request;
    legacy_receipt["unit"]["source_acceptance_receipt"] = founding_receipt();
    schema_invalid(PEER_REQUEST, &legacy_receipt)?;
    Ok(8)
}

fn assert_membership_compensation_carriers(approved: &Value) -> Result<usize> {
    let evidence = compensation_evidence();
    let self_request = json!({
        "unit_kind": "membership_compensation",
        "event_submission": approved,
        "membership_compensation_evidence": evidence
    });
    schema_valid(SELF_REQUEST, &self_request)?;
    assert_roundtrip::<SelfAuthoritySubmitRequest>(&self_request)?;

    let peer_request = json!({
        "branch": "registered_atomic_unit",
        "unit": {
            "unit_kind": "membership_compensation",
            "committed_event": {
                "event_submission": approved,
                "source_commit": realm_commit(0)
            },
            "membership_compensation_evidence": compensation_evidence()
        }
    });
    schema_valid(PEER_REQUEST, &peer_request)?;
    assert_roundtrip::<PeerAuthoritySubmitRequest>(&peer_request)?;

    for path in ["terminal_certificate", "single_use_binding"] {
        let mut missing = self_request.clone();
        missing["membership_compensation_evidence"]
            .as_object_mut()
            .unwrap()
            .remove(path);
        schema_invalid(SELF_REQUEST, &missing)?;
    }
    Ok(6)
}

fn assert_dependency_problem() -> Result<usize> {
    let problem = json!({
        "type": "https://arkret.org/problems/dependency_missing",
        "title": "Dependency missing",
        "status": 409,
        "detail": "exact founding dependency is not locally available",
        "details": {"missing_dependencies": [
            {"kind": "committed_event", "event_id": EVENT_ID},
            {"kind": "service_verification_method", "verification_method": "did:web:station.example#authority"}
        ]}
    });
    schema_valid(DEPENDENCY_PROBLEM, &problem)?;
    assert_roundtrip::<DirectConversationFoundingDependencyMissingProblem>(&problem)?;

    let mut wrong_status = problem.clone();
    wrong_status["status"] = json!(400);
    schema_invalid(DEPENDENCY_PROBLEM, &wrong_status)?;
    let mut unknown_kind = problem.clone();
    unknown_kind["details"]["missing_dependencies"][0]["kind"] = json!("opaque");
    schema_invalid(DEPENDENCY_PROBLEM, &unknown_kind)?;
    let mut too_many = problem;
    too_many["details"]["missing_dependencies"] = Value::Array(
        (0..17)
            .map(|_| json!({"kind": "committed_event", "event_id": EVENT_ID}))
            .collect(),
    );
    schema_invalid(DEPENDENCY_PROBLEM, &too_many)?;
    Ok(5)
}

fn assert_removed_and_partial_shapes_stay_rejected() -> Result<usize> {
    let schema_path = spec_artifacts_root()
        .join("schemas")
        .join("authority-commit-operations.schema.json");
    let schema_source = fs::read_to_string(&schema_path)?;
    ensure!(!schema_source.contains("EventFederationSubmission"));

    schema_invalid(
        PEER_REQUEST,
        &json!({"events": [], "source_service_id": "ak:did_core:web:source.example"}),
    )?;
    schema_invalid(
        PEER_OUTCOME,
        &json!({"accepted": [], "duplicate": [], "rejected": []}),
    )?;
    schema_invalid(
        PEER_OUTCOME,
        &json!({"branch": "committed_replication", "accepted": [0]}),
    )?;
    ensure!(!schema_source.contains("\"accepted\""));
    Ok(5)
}

fn approved_event_submission() -> Result<Value> {
    let fixture = load_artifact_json("fixtures/approval-signature-kat-fixture.json")?;
    fixture
        .pointer("/event_id_invariance/submission_with_evidence")
        .cloned()
        .ok_or_else(|| anyhow!("approval fixture lost submission_with_evidence"))
}

fn replication_request(submissions: Vec<Value>) -> Value {
    json!({
        "branch": "committed_replication",
        "processing": "per_item",
        "submissions": submissions
    })
}

fn replication_item(submission: Value) -> Value {
    json!({
        "committed_event": {
            "event_submission": submission,
            "source_commit": realm_commit(0)
        },
        "recipient_witnesses": [{
            "realm_id": REALM_ID,
            "member_id": actor_id(),
            "membership_event_ref": EVENT_ID,
            "recipient_service_id": "ak:did_core:web:recipient.example"
        }]
    })
}

fn direct_conversation_events(approved: &Value) -> Vec<Value> {
    [
        "ak.realm.create",
        "ak.member.state",
        "ak.member.state",
        "ak.strand.create",
    ]
    .into_iter()
    .map(|kind| {
        let mut submission = approved.clone();
        submission["event"]["kind"] = json!(kind);
        submission
            .as_object_mut()
            .unwrap()
            .remove("approval_signatures");
        submission
    })
    .collect()
}

fn realm_commit(position: u64) -> Value {
    json!({
        "commit_id": COMMIT_ID,
        "realm_id": REALM_ID,
        "stream_ref": {"kind": "realm", "realm_id": REALM_ID},
        "stream_position": position,
        "previous_commit_ref": if position == 0 { Value::Null } else { json!(COMMIT_ID) },
        "event_ref": EVENT_ID,
        "governance_generation": 0,
        "authority_ref": EVENT_ID,
        "committed_at": "2026-09-20T00:00:00.000Z",
        "signature": {
            "context": "ak.realm_commit_signature.v1",
            "signature_algorithm": "Ed25519",
            "verification_method": "did:web:station.example#authority",
            "signed_digest": format!("sha256:{}", "4".repeat(64)),
            "created_at": "2026-09-20T00:00:00.000Z",
            "sig": "c2ln"
        }
    })
}

fn founding_receipt() -> Value {
    json!({
        "pair_key": format!("sha256:{}", "1".repeat(64)),
        "founder_id": actor_id(),
        "realm_id": REALM_ID,
        "main_strand_id": STRAND_ID,
        "founding_unit_digest": format!("sha256:{}", "2".repeat(64)),
        "authorization_core": {
            "kind": "controller_agent",
            "agent_provision_ref": EVENT_ID,
            "controller_binding_digest": format!("sha256:{}", "3".repeat(64))
        },
        "issuer_id": "ak:did_core:web:station.example",
        "accepted_at": "2026-09-20T00:00:00.000Z",
        "proof": operation_signature()
    })
}

fn founding_evidence() -> Value {
    json!({
        "kind": "controller_agent",
        "agent_provision_ref": EVENT_ID,
        "controller_binding_digest": format!("sha256:{}", "3".repeat(64))
    })
}

fn compensation_evidence() -> Value {
    let admission = "0199fabc-1234-7abc-8abc-1234567890ab";
    let delegation = format!(
        "ak:membership_compensation_delegation:sha256:{}",
        "5".repeat(64)
    );
    json!({
        "delegation": {
            "delegation_id": delegation,
            "core": {
                "admission_id": admission,
                "join_event_ref": EVENT_ID,
                "join_commit_ref": COMMIT_ID,
                "subject_id": actor_id(),
                "executor_id": actor_id(),
                "executor_service_id": "ak:did_core:web:station.example",
                "verification_method": "did:web:station.example#authority",
                "resource_realm_id": REALM_ID,
                "deadline": "2026-09-20T00:10:00.000Z",
                "action": "ak.member.compensate.leave"
            },
            "proof": operation_signature()
        },
        "terminal_certificate": {
            "admission_id": admission,
            "delegation_id": delegation,
            "status": "join_terminal_failed",
            "certified_at": "2026-09-20T00:00:00.000Z",
            "issuer_id": "ak:did_core:web:station.example",
            "proof": operation_signature()
        },
        "single_use_binding": {
            "admission_id": admission,
            "delegation_id": delegation
        }
    })
}

fn operation_signature() -> Value {
    json!({
        "verification_method": "did:web:station.example#authority",
        "created_at": "2026-09-20T00:00:00.000Z",
        "jws": "eyJhbGciOiJFZDI1NTE5In0..c2ln"
    })
}

fn actor_id() -> Value {
    json!({
        "kind": "account",
        "account_id": {
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:webvh:z6mkfixturestationexample"
        }
    })
}

fn assert_roundtrip<T>(value: &Value) -> Result<()>
where
    T: DeserializeOwned + serde::Serialize,
{
    let parsed: T = serde_json::from_value(value.clone())?;
    ensure!(
        serde_json::to_value(parsed)? == *value,
        "SDK roundtrip drifted"
    );
    Ok(())
}

fn contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value == needle,
        Value::Array(values) => values.iter().any(|value| contains_string(value, needle)),
        Value::Object(values) => values.values().any(|value| contains_string(value, needle)),
        _ => false,
    }
}
