//! Protocol reference decisions and native SDK cryptographic component checks.
//! Live management review and managed Device delivery remain separate acceptance.
use anyhow::Result;
pub use cotest_managed_governance_runner::MANAGED_GOVERNANCE_ENTRYPOINT;

pub fn run_managed_governance_suite() -> Result<()> {
    cotest_managed_governance_runner::run_managed_governance_suite()
}
