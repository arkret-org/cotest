use anyhow::Result;

#[test]
fn push_rule_core_consistency_vectors_match_all_implementations() -> Result<()> {
    cotest::conformance::run_push_rule_core_fixture_suite()
}
