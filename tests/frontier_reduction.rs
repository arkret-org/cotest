use arkret_wire::DidCoreId;
use soland_storage::{frontier_exchange_failure_record, frontier_exchange_success_record};

#[test]
fn federation_frontier_terminal_vectors_match_persisted_state_semantics() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../arkret-spec/spec/v1/artifacts/fixtures/sync-fixture.json"
    ))
    .unwrap();
    let peer = DidCoreId::new("ak:did_core:web:peer.example").unwrap();
    for case in fixture["frontier_reduction_cases"].as_array().unwrap() {
        let mut previous = None;
        for attempt in 0..case["previous_failures"].as_i64().unwrap() {
            previous = Some(frontier_exchange_failure_record(
                previous,
                "realm",
                &peer,
                "network_error",
                attempt,
            ));
        }
        let record = if case["confirmed_evidence"] == true {
            frontier_exchange_failure_record(previous, "realm", &peer, "witness_disagreement", 10)
        } else if case["failure"] == true {
            frontier_exchange_failure_record(previous, "realm", &peer, "schema_violation", 10)
        } else {
            frontier_exchange_success_record(
                previous,
                "realm",
                &peer,
                "different-scope-remote-root",
                10,
            )
        };
        assert_eq!(
            record.status,
            case["expected"]["status"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(
            record.consecutive_failures as i64,
            case["expected"]["failures"].as_i64().unwrap(),
            "{}",
            case["name"]
        );
    }
}
