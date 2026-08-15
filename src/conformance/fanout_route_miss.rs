//! Durable Realm fanout route-miss conformance.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use arkret_models_collaboration::http_bodies::{
    EventDeliveryState, EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody,
    EventDeliveryTargetState, EventDeliveryTargetStatus, EventsSubmitOutcome,
};
use arkret_wire::{DidCoreId, EventId};

use super::load_fixture_value;

const FIXTURE: &str = "fanout-route-miss-fixture.json";
const VECTOR: &str = "ak.vector.fanout.route_miss.v1";
const REQUIRED_CASES: [&str; 8] = [
    "missing_route_accepts_and_freezes_complete_target_set",
    "any_target_or_intent_write_failure_rolls_back_everything",
    "restart_preserves_pending_route_without_attempt_budget_expiry",
    "route_recovery_delivers_idempotently",
    "authority_loss_cancels_before_send_and_rejoin_does_not_revive",
    "one_shared_service_remains_authorized_while_any_frozen_witness_is_current",
    "authorized_status_read_is_complete_and_topology_redacted",
    "offline_target_does_not_block_later_realm_authorship",
];

pub fn run_fanout_route_miss_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    if fixture["suite"] != "fanout_route_miss"
        || fixture["runner"]["kind"] != "named_suite"
        || fixture["runner"]["entrypoint"] != "ak.suite.fanout.route_miss.v1"
        || fixture["covers_vectors"] != serde_json::json!([VECTOR])
    {
        bail!("fanout route-miss fixture identity drifted");
    }
    let cases = fixture["semantic_cases"]
        .as_array()
        .context("fanout route-miss semantic_cases")?;
    let names = cases
        .iter()
        .map(|case| {
            case["name"]
                .as_str()
                .context("fanout route-miss semantic case name")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if names != BTreeSet::from(REQUIRED_CASES) {
        bail!("fanout route-miss fixture is not the closed eight-case set");
    }
    if cases.iter().any(|case| {
        case["invariants"]
            .as_array()
            .is_none_or(|invariants| invariants.is_empty())
    }) {
        bail!("every fanout route-miss semantic case must carry invariants");
    }

    validate_sdk_delivery_contract()
}

fn validate_sdk_delivery_contract() -> Result<()> {
    let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x42; 32]);
    let request = EventDeliveryStatusRequestBody {
        event_id: event_id.clone(),
    };
    let pending = EventDeliveryTargetStatus {
        target_id: "opaque-target-0001".to_owned(),
        status: EventDeliveryTargetState::PendingRoute,
        service_id: None,
    };
    let delivered = EventDeliveryTargetStatus {
        target_id: "opaque-target-0002".to_owned(),
        status: EventDeliveryTargetState::Delivered,
        service_id: Some(DidCoreId::new("ak:did_core:web:visible.example")?),
    };
    let outcome = EventDeliveryStatusOutcome {
        event_id,
        delivery_state: EventDeliveryState::Pending,
        pending_delivery_count: 1,
        targets: vec![pending.clone(), delivered],
    };
    outcome.validate_for_request(&request)?;

    let mut unsorted = outcome.clone();
    unsorted.targets.reverse();
    if unsorted.validate_for_request(&request).is_ok() {
        bail!("delivery status accepted a non-canonical target order");
    }
    let mut duplicate = outcome.clone();
    duplicate.targets = vec![pending.clone(), pending];
    duplicate.pending_delivery_count = 2;
    if duplicate.validate_for_request(&request).is_ok() {
        bail!("delivery status accepted duplicate opaque target ids");
    }

    let submit: EventsSubmitOutcome = serde_json::from_value(serde_json::json!({
        "status": "accepted",
        "accepted": [request.event_id],
        "delivery_state": "pending",
        "pending_delivery_count": 1
    }))?;
    submit.validate_delivery_state()?;
    let encoded = serde_json::to_value(submit)?;
    if encoded.get("targets").is_some() || encoded.get("service_id").is_some() {
        bail!("Event submit summary exposed target topology");
    }

    let complete = EventDeliveryStatusOutcome {
        event_id: request.event_id.clone(),
        delivery_state: EventDeliveryState::Complete,
        pending_delivery_count: 0,
        targets: vec![EventDeliveryTargetStatus {
            target_id: "opaque-target-0003".to_owned(),
            status: EventDeliveryTargetState::CancelledAuthorityLost,
            service_id: None,
        }],
    };
    complete.validate_for_request(&request)?;
    Ok(())
}
