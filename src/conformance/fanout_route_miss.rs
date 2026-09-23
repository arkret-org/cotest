//! Durable Realm fanout route-miss conformance.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use arkret_models_collaboration::event_query::{
    EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody, EventDeliveryTargetId,
    EventDeliveryTargetState, EventDeliveryTargetStatus,
};
use arkret_wire::{DidCoreId, EventId};

use super::load_fixture_value;

const FIXTURE: &str = "fanout-route-miss-fixture.json";
const VECTOR: &str = "ak.vector.fanout.route_miss.v1";
const REQUIRED_CASES: [&str; 11] = [
    "missing_route_accepts_and_freezes_complete_target_set",
    "any_target_or_intent_write_failure_rolls_back_everything",
    "restart_preserves_pending_route_without_attempt_budget_expiry",
    "route_recovery_delivers_idempotently",
    "authority_loss_cancels_before_send_and_rejoin_does_not_revive",
    "one_shared_service_remains_authorized_while_any_frozen_witness_is_current",
    "unchanged_route_projection_cannot_preserve_lost_membership_authority",
    "partial_conditions_from_different_member_witnesses_cannot_be_combined",
    "same_service_endpoint_update_preserves_frozen_authority_and_idempotency",
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
        bail!("fanout route-miss fixture is not the closed eleven-case set");
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
        target_id: EventDeliveryTargetId::new("opaque-target-0001")?,
        status: EventDeliveryTargetState::PendingRoute,
        service_id: None,
    };
    let delivered = EventDeliveryTargetStatus {
        target_id: EventDeliveryTargetId::new("opaque-target-0002")?,
        status: EventDeliveryTargetState::Delivered,
        service_id: Some(DidCoreId::new("ak:did_core:web:visible.example")?),
    };
    let outcome = EventDeliveryStatusOutcome {
        event_id,
        targets: vec![pending.clone(), delivered],
    };
    outcome.validate()?;
    if outcome.event_id != request.event_id || pending_count(&outcome) != 1 {
        bail!("delivery status did not derive its pending aggregate from targets");
    }

    let mut unsorted = outcome.clone();
    unsorted.targets.reverse();
    if unsorted.validate().is_ok() {
        bail!("delivery status accepted a non-canonical target order");
    }
    let mut duplicate = outcome.clone();
    duplicate.targets = vec![pending.clone(), pending];
    if duplicate.validate().is_ok() {
        bail!("delivery status accepted duplicate opaque target ids");
    }

    let complete = EventDeliveryStatusOutcome {
        event_id: request.event_id.clone(),
        targets: vec![EventDeliveryTargetStatus {
            target_id: EventDeliveryTargetId::new("opaque-target-0003")?,
            status: EventDeliveryTargetState::CancelledAuthorityLost,
            service_id: None,
        }],
    };
    complete.validate()?;
    if pending_count(&complete) != 0 {
        bail!("terminal target set derived a pending aggregate");
    }
    Ok(())
}

fn pending_count(outcome: &EventDeliveryStatusOutcome) -> usize {
    outcome
        .targets
        .iter()
        .filter(|target| {
            matches!(
                target.status,
                EventDeliveryTargetState::PendingRoute | EventDeliveryTargetState::PendingDelivery
            )
        })
        .count()
}
