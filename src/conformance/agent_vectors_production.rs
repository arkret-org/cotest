//! Reviewed Agent cases execute the normal Station HTTP and durable stores.

use anyhow::{Result, anyhow};

use super::SuiteExecutionResult;

pub fn run_agent_vectors_production_suite() -> Result<SuiteExecutionResult> {
    std::thread::Builder::new()
        .name("agent-vectors-production".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(32 * 1024 * 1024)
                .enable_all()
                .build()?
                .block_on(
                    crate::scenarios::agent_runtime_live::run_agent_genesis_production_cases(),
                )
        })?
        .join()
        .map_err(|_| anyhow!("Agent production runner panicked"))?
}
