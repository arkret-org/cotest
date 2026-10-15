//! Reviewed Agent cases execute the normal Station HTTP and durable stores.

use anyhow::{Result, anyhow};

use super::SuiteExecutionResult;

mod schema;
pub(super) use schema::REVIEWED_SCHEMA_CASES;

pub(super) const REVIEWED_PRODUCTION_CASES: [&str; 15] = [
    "agent_provision",
    "agent_pcr_genesis_forward_declaration",
    "agent_pcr_genesis_without_declaration_rejected",
    "two_provisions_declaring_one_realm_id_rejected",
    "agent_pcr_genesis_same_batch_rejected",
    "agent_pairing_expiry",
    "agent_session_grant_replay",
    "agent_repairing_supersede",
    "agent_requested_scope_privacy",
    "agent_pcr_separation",
    "agent_runtime_key_binding",
    "agent_controller_lifecycle",
    "agent_longevity_no_expiry",
    "agent_act_on_behalf",
    "agent_human_approval_required",
];

pub(super) const REVIEWED_CASE_GROUPS: &[&[&str]] = &[
    &REVIEWED_SCHEMA_CASES,
    &REVIEWED_PRODUCTION_CASES,
    &crate::scenarios::agent_runtime_live::REVIEWED_CONTENT_CASES,
    &crate::scenarios::agent_runtime_live::REVIEWED_GRANT_CONTENT_CASES,
];

pub fn reviewed_agent_production_case_ids() -> Vec<&'static str> {
    REVIEWED_CASE_GROUPS
        .iter()
        .flat_map(|cases| cases.iter().copied())
        .collect()
}

pub fn run_agent_vectors_production_suite() -> Result<SuiteExecutionResult> {
    std::thread::Builder::new()
        .name("agent-vectors-production".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let schema_cases = schema::run_schema_cases()?;
            let mut execution = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(32 * 1024 * 1024)
                .enable_all()
                .build()?
                .block_on(async {
                    let mut execution =
                        crate::scenarios::agent_runtime_live::run_agent_provision_production()
                            .await?;
                    let genesis = crate::scenarios::agent_runtime_live::run_agent_genesis_production_cases().await?;
                    execution.cases.extend(genesis.cases);
                    let pairing =
                        crate::scenarios::agent_runtime_live::run_agent_pairing_expiry_production()
                            .await?;
                    execution.cases.extend(pairing.cases);
                    let session = crate::scenarios::agent_runtime_live::run_agent_session_grant_replay_production().await?;
                    execution.cases.extend(session.cases);
                    let repairing = crate::scenarios::agent_runtime_live::run_agent_repairing_production().await?;
                    execution.cases.extend(repairing.cases);
                    let privacy = crate::scenarios::agent_runtime_live::run_agent_requested_scope_privacy_production().await?;
                    execution.cases.extend(privacy.cases);
                    let pcr = crate::scenarios::agent_runtime_live::run_agent_pcr_profile_admission().await?;
                    execution.cases.extend(pcr.cases);
                    let binding = crate::scenarios::agent_runtime_live::run_agent_runtime_binding_admission().await?;
                    execution.cases.extend(binding.cases);
                    let lifecycle = crate::scenarios::agent_runtime_live::run_agent_controller_lifecycle_production().await?;
                    execution.cases.extend(lifecycle.cases);
                    let longevity = crate::scenarios::agent_runtime_live::run_agent_longevity_production().await?;
                    execution.cases.extend(longevity.cases);
                    let attribution = crate::scenarios::agent_runtime_live::run_agent_act_on_behalf_production().await?;
                    execution.cases.extend(attribution.cases);
                    let approval = crate::scenarios::agent_runtime_live::run_agent_human_approval_production().await?;
                    execution.cases.extend(approval.cases);
                    let content = crate::scenarios::agent_runtime_live::run_agent_session_content_production().await?;
                    execution.cases.extend(content.cases);
                    let grants = crate::scenarios::agent_runtime_live::run_agent_content_grant_production().await?;
                    execution.cases.extend(grants.cases);
                    Ok::<SuiteExecutionResult, anyhow::Error>(execution)
                })?;
            execution.cases.splice(0..0, schema_cases);
            Ok(execution)
        })?
        .join()
        .map_err(|_| anyhow!("Agent production runner panicked"))?
}
