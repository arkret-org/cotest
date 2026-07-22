use anyhow::{Result, anyhow, bail};
use arkret_core::models::MlsWelcomePayloadClaimRef;
use serde::Deserialize;
use serde_json::json;

const FIXTURE: &str = "agent-mls-keypackage-authorization-fixture.json";
const VECTOR_ID: &str = "ak.vector.agent.mls_keypackage_authorization.v1";
const ENTRYPOINT: &str = "ak.suite.agent.mls_keypackage_authorization.v1";

#[derive(Deserialize)]
struct Fixture {
    profile: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    expected: String,
    agent_id: String,
    claim_principal_id: String,
    current_agent_key_authorize_event_id: String,
    #[serde(default)]
    claim_agent_key_authorize_event_id: Option<String>,
    #[serde(default)]
    device_authorize_event_id: Option<String>,
    #[serde(default)]
    ssk_generation: Option<u64>,
    current_verification_method: String,
    leaf_signature_key: String,
    leaf_signature_valid: bool,
    authorization_status: String,
}

fn claim_is_authorized(case: &Case) -> bool {
    let claim_ref = json!({
        "claim_id": "agent-claim-1",
        "keypackage_ref": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "keypackage_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "capabilities_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "agent_key_authorize_event_id": case.claim_agent_key_authorize_event_id,
        "device_authorize_event_id": case.device_authorize_event_id,
        "ssk_generation": case.ssk_generation,
    });
    let binding_is_exclusive =
        serde_json::from_value::<MlsWelcomePayloadClaimRef>(claim_ref).is_ok();

    binding_is_exclusive
        && case.agent_id == case.claim_principal_id
        && case.claim_agent_key_authorize_event_id.as_deref()
            == Some(case.current_agent_key_authorize_event_id.as_str())
        && case.leaf_signature_key == case.current_verification_method
        && case.leaf_signature_valid
        && case.authorization_status == "active"
}

pub fn run_agent_mls_keypackage_authorization_vector() -> Result<()> {
    let fixture: Fixture = serde_json::from_value(super::load_fixture_value(FIXTURE)?)?;
    if fixture.profile != "ak.profile.agent_runtime.v1"
        || fixture.runner.kind != "named_suite"
        || fixture.runner.entrypoint != ENTRYPOINT
        || fixture.covers_vectors != [VECTOR_ID]
    {
        bail!("{FIXTURE} metadata drifted from the registered vector");
    }
    if fixture.cases.len() < 9 {
        bail!("{FIXTURE} must cover the positive case and every fail-closed branch");
    }

    let mut accepted = 0;
    for case in &fixture.cases {
        let actual = if claim_is_authorized(case) {
            "accepted"
        } else {
            "rejected"
        };
        if actual != case.expected {
            return Err(anyhow!(
                "agent MLS KeyPackage case {} produced {actual}, expected {}",
                case.name,
                case.expected
            ));
        }
        accepted += usize::from(actual == "accepted");
    }
    if accepted != 1 {
        bail!("{FIXTURE} must contain exactly one accepted current-authorization case");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn agent_mls_keypackage_authorization_vector_runs_clean() {
        super::run_agent_mls_keypackage_authorization_vector().unwrap();
    }
}
