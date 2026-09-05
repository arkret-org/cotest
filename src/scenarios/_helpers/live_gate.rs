//! Fail-closed gating for lanes that declare the live service stack present.
//!
//! Several `#[ignore]` scenarios historically soft-skipped — they printed a
//! `skip:` line and returned `Ok(())` when Docker, a sibling binary or a
//! database URL was missing. That convention is correct for an operator who
//! opts in ad hoc with `--ignored`: the run reports what it could not do
//! instead of failing on an unrelated machine.
//!
//! It is exactly wrong for a CI profile whose entire purpose is to prove the
//! real services come up. There the run must fail when a prerequisite is
//! missing, because a green report with every live leg skipped is a false
//! green, not a pass.
//!
//! `COTEST_REQUIRE_LIVE_SERVICES=1` is the operator's declaration that every
//! prerequisite is present. The `services-live` CI profile sets it; ad hoc
//! `--ignored` runs leave it unset and keep the soft-skip behaviour. This
//! mirrors `COTEST_REQUIRE_JOINT_STACK` on the Playwright side.

use anyhow::{Result, bail};

/// Env var an operator (or CI profile) sets to declare the live stack present.
pub const REQUIRE_LIVE_SERVICES_ENV: &str = "COTEST_REQUIRE_LIVE_SERVICES";

/// Whether the current run declared that every live prerequisite is available.
pub fn live_services_required() -> bool {
    std::env::var(REQUIRE_LIVE_SERVICES_ENV)
        .as_deref()
        .map(declares_opt_in)
        .unwrap_or(false)
}

/// Only an exact `1` opts in. A runner that exports an empty string — which
/// PowerShell produces for `$env:X = ""`, unlike `Remove-Item Env:X` — must
/// not be read as a declaration that the live stack is present.
fn declares_opt_in(value: &str) -> bool {
    value.trim() == "1"
}

/// Call at the point a scenario would otherwise soft-skip.
///
/// Returns `Err` when the run declared the live stack present, so the missing
/// prerequisite surfaces as a failure instead of a skipped-but-green test.
/// Otherwise prints the conventional `skip:` line and returns `Ok(())` so the
/// caller can return early.
pub fn skip_or_fail(scenario: &str, detail: &str) -> Result<()> {
    decide(scenario, detail, live_services_required())
}

/// Pure decision behind [`skip_or_fail`], split out so the fail-closed and
/// soft-skip branches are testable without mutating the process environment.
fn decide(scenario: &str, detail: &str, live_services_required: bool) -> Result<()> {
    if live_services_required {
        bail!(
            "{scenario}: {REQUIRE_LIVE_SERVICES_ENV}=1 declares the live service stack present, \
             but a prerequisite is missing: {detail}. Refusing to report a skipped live leg as a \
             pass — provide the prerequisite or unset {REQUIRE_LIVE_SERVICES_ENV}."
        );
    }
    eprintln!("skip: {scenario}: {detail}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declared_live_lane_fails_and_names_the_missing_prerequisite() {
        let error = format!(
            "{}",
            decide("ct-x", "docker is unavailable", true).unwrap_err()
        );
        assert!(error.contains("ct-x"), "{error}");
        assert!(error.contains("docker is unavailable"), "{error}");
        assert!(error.contains(REQUIRE_LIVE_SERVICES_ENV), "{error}");
    }

    #[test]
    fn an_undeclared_lane_soft_skips() {
        assert!(decide("ct-x", "docker is unavailable", false).is_ok());
    }

    #[test]
    fn only_an_exact_1_declares_the_stack_present() {
        assert!(declares_opt_in("1"));
        assert!(declares_opt_in(" 1 "));
        for value in ["", "  ", "0", "false", "true", "yes", "11"] {
            assert!(!declares_opt_in(value), "{value:?} must not opt in");
        }
    }
}
