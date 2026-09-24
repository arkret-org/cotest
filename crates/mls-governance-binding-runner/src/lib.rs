//! Executable conformance runner for the closed MLS governance binding.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret_canonical::DigestSuite;
use arkret_mls::{
    MlsCurrentSendState, MlsGovernanceBindingPublicState, MlsGovernanceBindingRejection,
    VerifiedMlsGovernanceBinding, verify_current_send_governance_binding,
    verify_governance_binding_against_public_state_and_payload,
    verify_governance_binding_transition, verify_historical_governance_binding,
    verify_mls_genesis_binding_proposal,
};
use arkret_models_collaboration::events_payloads::MlsGenesisBindingProposalCarrier;
use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_wire::{ErrorCode, EventId, ScopeRef, WireError};
use serde_json::Value;

pub const MLS_GOVERNANCE_BINDING_ENTRYPOINT: &str = "ak.suite.mls.governance_binding_closure.v1";
pub const FIXTURE: &str = "mls-governance-binding-closure-fixture.json";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsGovernanceBindingExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
}

#[derive(Default)]
struct EffectSink {
    verified: Vec<VerifiedMlsGovernanceBinding>,
}

impl EffectSink {
    fn accept(
        &mut self,
        result: std::result::Result<VerifiedMlsGovernanceBinding, MlsGovernanceBindingRejection>,
    ) -> Result<()> {
        let before = self.verified.len();
        self.verified.push(result.map_err(|rejection| {
            anyhow::anyhow!(
                "production gate rejected accepted case: {}",
                rejection.code()
            )
        })?);
        ensure!(
            self.verified.len() == before + 1,
            "accepted case wrote no effect"
        );
        Ok(())
    }

    fn reject(
        &mut self,
        result: std::result::Result<VerifiedMlsGovernanceBinding, MlsGovernanceBindingRejection>,
        expected_reason: &str,
    ) -> Result<()> {
        let before = self.verified.len();
        let rejection = match result {
            Ok(effect) => {
                anyhow::bail!("rejected case produced {:?} effect", effect.verified_use())
            }
            Err(rejection) => rejection,
        };
        ensure!(rejection.code() == expected_reason);
        ensure!(
            self.verified.len() == before,
            "rejected case wrote an effect"
        );
        Ok(())
    }

    fn reject_schema<T>(&self, result: std::result::Result<T, WireError>) -> Result<()> {
        let before = self.verified.len();
        let error = match result {
            Ok(_) => anyhow::bail!("schema-invalid case decoded"),
            Err(error) => error,
        };
        ensure!(error.error_code() == Some(ErrorCode::SchemaViolation));
        ensure!(
            self.verified.len() == before,
            "schema rejection wrote an effect"
        );
        Ok(())
    }
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("fixtures").is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn load_fixture() -> Result<Value> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

fn as_binding(value: &Value) -> Result<MlsGovernanceBindingPayload> {
    serde_json::from_value(value.clone()).context("decode typed MLS governance binding")
}

fn reason(sample: &Value) -> Option<&str> {
    sample["expected"]["reason"].as_str()
}

fn case_result(name: &str, assertions: usize) -> CaseExecutionResult {
    CaseExecutionResult {
        case_id: name.to_owned(),
        assertions,
    }
}

/// Negatives that pin the Sidecar-only members to the Sidecar scope.
const SIDECAR_SCOPE_REJECTIONS: [&str; 4] = [
    "sidecar_member_missing",
    "non_sidecar_carries_sidecar_member",
    "authority_stream_head_unsorted",
    "authority_stream_head_duplicate",
];

fn string_list(value: &Value) -> Result<Vec<&str>> {
    value
        .as_array()
        .context("string list missing")?
        .iter()
        .map(|item| item.as_str().context("string list item"))
        .collect()
}

/// Five shared members plus two Sidecar-only members, in RFC 8949 section
/// 4.2.1 order, with each accepted sample carrying exactly its scope's set.
fn check_member_sets(case: &Value) -> Result<usize> {
    let order = string_list(&case["canonical_member_order"])?;
    let sidecar_only = string_list(&case["sidecar_only_members"])?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let all = order.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        order.len() == 7 && all.len() == 7,
        "binding must have seven registered members"
    );
    ensure!(
        sidecar_only == BTreeSet::from(["authority_stream_head", "participant_authority_digest"]),
        "Sidecar-only members drifted"
    );
    let mut deterministic = order.clone();
    deterministic.sort_by(|left, right| {
        left.len()
            .cmp(&right.len())
            .then_with(|| left.as_bytes().cmp(right.as_bytes()))
    });
    ensure!(
        deterministic == order,
        "member order is not RFC 8949 deterministic order"
    );
    let shared = all
        .difference(&sidecar_only)
        .copied()
        .collect::<BTreeSet<_>>();
    let mut sidecar_samples = 0;
    for sample in case["accepted"].as_array().context("accepted[] missing")? {
        let members = sample["binding"]
            .as_object()
            .context("accepted binding object")?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let is_sidecar = sample["binding"]["effective_scope"]["kind"] == "sidecar";
        sidecar_samples += usize::from(is_sidecar);
        ensure!(
            members
                == if is_sidecar {
                    all.clone()
                } else {
                    shared.clone()
                },
            "accepted sample {} carries the wrong member set",
            sample["name"]
        );
    }
    ensure!(
        sidecar_samples == 1,
        "exactly one seven-member Sidecar KAT is registered"
    );
    let rejections = case["rejection_samples"]
        .as_array()
        .context("rejection_samples[] missing")?
        .iter()
        .filter_map(|sample| sample["name"].as_str())
        .collect::<BTreeSet<_>>();
    for name in SIDECAR_SCOPE_REJECTIONS {
        ensure!(
            rejections.contains(name),
            "Sidecar scope negative {name} is missing"
        );
    }
    Ok(5)
}

/// `authority_stream_head` is bounded by the decoder collection limit: the
/// limit itself is accepted and one more ref is a schema violation.
fn check_authority_stream_head_bound(case: &Value) -> Result<usize> {
    let limit = case["resource_limits"]["maximum_collection_items"]
        .as_u64()
        .context("maximum_collection_items missing")?;
    ensure!(limit == 64, "decoder collection limit drifted");
    let sidecar = case["accepted"]
        .as_array()
        .context("accepted[] missing")?
        .iter()
        .find(|sample| sample["binding"]["effective_scope"]["kind"] == "sidecar")
        .context("Sidecar KAT missing")?;
    let with_head = |count: u64| -> Result<MlsGovernanceBindingPayload> {
        let mut refs = (0..count)
            .map(|seed| {
                let seed = u8::try_from(seed)?;
                Ok(EventId::from_digest(DigestSuite::Sha256, [seed; 32]))
            })
            .collect::<Result<Vec<_>>>()?;
        refs.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let mut binding = sidecar["binding"].clone();
        binding["authority_stream_head"] = serde_json::to_value(refs)?;
        as_binding(&binding)
    };
    with_head(limit)?.validate()?;
    let over = with_head(limit + 1)?.validate();
    ensure!(
        matches!(&over, Err(error) if error.error_code() == Some(ErrorCode::SchemaViolation)),
        "a Sidecar head above the collection limit was not a schema violation"
    );
    Ok(2)
}

fn run_wire_encoding(case: &Value) -> Result<CaseExecutionResult> {
    let mut effects = EffectSink::default();
    let mut assertions = check_member_sets(case)? + check_authority_stream_head_bound(case)?;
    for sample in case["accepted"].as_array().context("accepted[] missing")? {
        let encoded = hex::decode(sample["encoded_map_hex"].as_str().context("hex missing")?)?;
        let decoded = MlsGovernanceBindingPayload::from_deterministic_cbor(&encoded)?;
        ensure!(decoded == as_binding(&sample["binding"])?);
        ensure!(decoded.to_deterministic_cbor()? == encoded);
        effects.accept(verify_governance_binding_transition(
            &decoded,
            decoded.key_access_revision(),
        ))?;
        assertions += 4;
    }
    for sample in case["rejection_samples"]
        .as_array()
        .context("rejection_samples[] missing")?
    {
        let encoded = hex::decode(sample["encoded_map_hex"].as_str().context("hex missing")?)?;
        effects.reject_schema(MlsGovernanceBindingPayload::from_deterministic_cbor(
            &encoded,
        ))?;
        ensure!(reason(sample) == Some("schema_violation"));
        assertions += 3;
    }
    Ok(case_result(case["name"].as_str().unwrap(), assertions))
}

fn run_transition(case: &Value) -> Result<CaseExecutionResult> {
    let mut effects = EffectSink::default();
    let mut assertions = 0;
    for sample in case["samples"].as_array().context("samples[] missing")? {
        let binding = as_binding(&sample["binding"])?;
        let current_revision = sample["station_public_state"]["current_key_access_revision"]
            .as_u64()
            .unwrap_or_else(|| binding.key_access_revision());
        let result = verify_governance_binding_transition(&binding, current_revision);
        match reason(sample) {
            Some(expected) => effects.reject(result, expected)?,
            None => effects.accept(result)?,
        }
        assertions += 2;
    }
    Ok(case_result(case["name"].as_str().unwrap(), assertions))
}

fn run_public_state_and_payload(case: &Value) -> Result<CaseExecutionResult> {
    let mut effects = EffectSink::default();
    let event_payload_binding = as_binding(&case["event_payload_binding"])?;
    let scope: ScopeRef =
        serde_json::from_value(case["station_public_state"]["effective_scope"].clone())?;
    let base: EventId =
        serde_json::from_value(case["station_public_state"]["base_group_state_ref"].clone())?;
    let public_state = MlsGovernanceBindingPublicState::new(
        scope,
        Some(base),
        event_payload_binding.previous_epoch(),
        case["station_public_state"]["current_key_access_revision"]
            .as_u64()
            .context("current revision missing")?,
    );
    let mut assertions = 0;
    for sample in case["samples"].as_array().context("samples[] missing")? {
        let binding = as_binding(&sample["binding"])?;
        let result = verify_governance_binding_against_public_state_and_payload(
            &binding,
            &public_state,
            &event_payload_binding,
        );
        match reason(sample) {
            Some(expected) => effects.reject(result, expected)?,
            None => effects.accept(result)?,
        }
        assertions += 2;
    }
    Ok(case_result(case["name"].as_str().unwrap(), assertions))
}

fn run_historical_replay(case: &Value) -> Result<CaseExecutionResult> {
    let mut effects = EffectSink::default();
    let historical = as_binding(&case["historical_accepted_binding"])?;
    effects.accept(verify_historical_governance_binding(
        &historical,
        &historical,
    ))?;
    let current = MlsCurrentSendState::new(
        historical.effective_scope().clone(),
        historical.next_epoch(),
        case["current_public_state"]["current_key_access_revision"]
            .as_u64()
            .context("current revision missing")?,
    );
    effects.reject(
        verify_current_send_governance_binding(&historical, &current),
        case["expected"]["current_send_reason"]
            .as_str()
            .context("current send reason missing")?,
    )?;
    ensure!(case["expected"]["historical_replay_decision"] == "accept");
    ensure!(case["expected"]["current_send_decision"] == "reject");
    Ok(case_result(case["name"].as_str().unwrap(), 6))
}

fn run_proposal(case: &Value) -> Result<CaseExecutionResult> {
    let mut effects = EffectSink::default();
    let accepted = serde_json::to_vec(&case["accepted_carrier"])?;
    let carrier = MlsGenesisBindingProposalCarrier::from_json_slice(&accepted)?;
    effects.accept(verify_mls_genesis_binding_proposal(&carrier))?;
    let mut assertions = 2;
    for sample in case["rejection_samples"]
        .as_array()
        .context("rejection_samples[] missing")?
    {
        let encoded = serde_json::to_vec(&sample["carrier"])?;
        match reason(sample) {
            Some("schema_violation") => {
                effects
                    .reject_schema(MlsGenesisBindingProposalCarrier::from_json_slice(&encoded))?;
            }
            Some(expected) => {
                let carrier = MlsGenesisBindingProposalCarrier::from_json_slice(&encoded)?;
                effects.reject(verify_mls_genesis_binding_proposal(&carrier), expected)?;
            }
            None => anyhow::bail!("proposal rejection has no reason"),
        }
        ensure!(sample["expected"]["proof_emitted"] == false);
        ensure!(sample["expected"]["cache_entry_written"] == false);
        assertions += 4;
    }
    Ok(case_result(case["name"].as_str().unwrap(), assertions))
}

pub fn run_mls_governance_binding_suite() -> Result<MlsGovernanceBindingExecution> {
    let fixture = load_fixture()?;
    ensure!(fixture["suite"] == "mls_governance_binding_closure");
    ensure!(fixture["runner"]["kind"] == "named_suite");
    ensure!(fixture["runner"]["entrypoint"] == MLS_GOVERNANCE_BINDING_ENTRYPOINT);
    let cases = fixture["cases"].as_array().context("cases[] missing")?;
    ensure!(cases.len() == 5, "canonical top-case count drifted");

    let executed = cases
        .iter()
        .map(|case| match case["name"].as_str().unwrap_or_default() {
            "governance_binding_wire_encoding_is_closed" => run_wire_encoding(case),
            "governance_binding_epoch_transition_is_fixed" => run_transition(case),
            "binding_matches_public_state_and_payload" => run_public_state_and_payload(case),
            "historical_replay_does_not_grant_current_send_authority" => {
                run_historical_replay(case)
            }
            "pre_genesis_proposal_uses_the_same_binding_schema" => run_proposal(case),
            other => anyhow::bail!("unmapped MLS governance-binding top case {other}"),
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(MlsGovernanceBindingExecution {
        entrypoint: MLS_GOVERNANCE_BINDING_ENTRYPOINT,
        fixture: FIXTURE,
        cases: executed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_all_five_top_cases_through_production_gates() {
        let execution = run_mls_governance_binding_suite().unwrap();
        assert_eq!(execution.cases.len(), 5);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
    }
}
