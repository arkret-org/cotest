use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::load_fixture_value;

const FIXTURE: &str = "signal-sequence-high-water-fixture.json";

pub fn run_signal_sequence_high_water_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    if fixture["suite"].as_str() != Some("signal_sequence_high_water")
        || fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            != Some("ak.suite.signal.sequence_high_water.v1")
    {
        bail!("{FIXTURE} suite or runner entrypoint drifted");
    }
    validate_allocator_cases(&fixture["allocator"])?;
    validate_receiver_cases(&fixture["receiver_cases"])?;
    let forbidden = fixture["forbidden_identity_surfaces"]
        .as_array()
        .ok_or_else(|| anyhow!("{FIXTURE} forbidden_identity_surfaces missing"))?;
    for required in [
        "signal_id",
        "ak:signal:",
        "uuidv7_emission_id",
        "durable_envelope_digest_reference",
    ] {
        if !forbidden
            .iter()
            .any(|value| value.as_str() == Some(required))
        {
            bail!("{FIXTURE} does not forbid {required}");
        }
    }
    Ok(())
}

fn validate_allocator_cases(allocator: &Value) -> Result<()> {
    if allocator["domain"]
        != serde_json::json!(["sender_actor_id", "sender_device_id", "canonical_scope_ref"])
    {
        bail!("Signal allocator must bind the complete actor, device, and scope");
    }
    if allocator["value_type"].as_str() != Some("u64")
        || allocator["block_size"].as_u64() != Some(256)
        || allocator["initial_next_unreserved"].as_u64() != Some(1)
    {
        bail!("Signal allocator type/block/initial high-water drifted");
    }
    let cases = allocator["reservation_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("Signal allocator reservation_cases missing"))?;
    for case in cases {
        match case["name"].as_str() {
            Some("restart_after_partial_block_burns_tail") => {
                let blocks = case["reserved_blocks"]
                    .as_array()
                    .ok_or_else(|| anyhow!("restart reservation blocks missing"))?;
                let first_end = blocks[0][1].as_u64().unwrap_or_default();
                let second_start = blocks[1][0].as_u64().unwrap_or_default();
                if second_start != first_end + 1
                    || case["first_after_restart"].as_u64() != Some(second_start)
                    || case["reuse_forbidden"].as_bool() != Some(true)
                {
                    bail!("restart reservation reused or rolled back a sequence");
                }
            }
            Some("failed_submit_burns_sequence") => {
                let emissions = case["emissions"].as_array().unwrap();
                let last = emissions.last().and_then(Value::as_u64).unwrap();
                if case["expected_next"].as_u64() != Some(last + 1)
                    || case["reuse_forbidden"].as_bool() != Some(true)
                {
                    bail!("failed submit did not burn its Signal sequence");
                }
            }
            Some("scopes_have_independent_high_waters") => {
                if case["same_device"].as_bool() != Some(true) || case["scope_a"] != case["scope_b"]
                {
                    bail!("independent Signal scopes do not start from independent high-waters");
                }
            }
            other => bail!("unknown Signal allocator case {other:?}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_sequence_domain_requires_the_complete_actor() {
        let fixture = load_fixture_value(FIXTURE).unwrap();
        validate_allocator_cases(&fixture["allocator"]).unwrap();
        let mut old = fixture["allocator"].clone();
        old["domain"] = serde_json::json!(["sender_device_id", "canonical_scope_ref"]);
        assert!(validate_allocator_cases(&old).is_err());
    }
}

fn validate_receiver_cases(cases: &Value) -> Result<()> {
    for case in cases
        .as_array()
        .ok_or_else(|| anyhow!("Signal receiver_cases missing"))?
    {
        let arrivals = case["arrivals"].as_array().unwrap();
        let expected = case["expected"].as_array().unwrap();
        let digests = case["envelope_digests"].as_array();
        let mut high_water = arkret::SignalSequenceHighWater::default();
        let mut seen_digests = BTreeSet::new();
        for (index, arrival) in arrivals.iter().enumerate() {
            let digest = digests.and_then(|values| values[index].as_str());
            let actual = if digest.is_some_and(|value| !seen_digests.insert(value.to_owned())) {
                "signal_exact_envelope_replay"
            } else {
                match high_water.observe(arkret::SignalSequence::new(arrival.as_u64().unwrap())) {
                    arkret::SignalSequenceDecision::Advanced { .. } => "accepted",
                    arkret::SignalSequenceDecision::Stale { .. } => "signal_payload_sequence_stale",
                }
            };
            if expected[index].as_str() != Some(actual) {
                bail!(
                    "Signal receiver case {} step {index}: expected {}, got {actual}",
                    case["name"].as_str().unwrap_or("<unnamed>"),
                    expected[index].as_str().unwrap_or("<missing>")
                );
            }
        }
        if high_water.current().map(|value| value.get()) != case["final_high_water"].as_u64() {
            bail!(
                "Signal receiver final high-water drifted in {}",
                case["name"]
            );
        }
    }
    Ok(())
}
