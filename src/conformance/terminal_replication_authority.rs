//! The canonical terminal suite executes real PostgreSQL-backed TLS Stations.
//! No modeled admission, parser-only fixture or optional live skip is evidence.

use anyhow::{Result, ensure};

use super::{CaseExecutionResult, SuiteExecutionResult, load_fixture_value};
use crate::scenarios::{fanout_route_miss_live, signal_live};

pub const TERMINAL_REPLICATION_AUTHORITY_ENTRYPOINT: &str =
    "ak.suite.federation.terminal_replication_authority.v1";
const FIXTURE: &str = "terminal-replication-authority-fixture.json";

// Construct each large native journey outside the aggregate poll frame.
// This preserves the default Windows test/worker stack without a stack override.
#[inline(never)]
fn heap_live<F: std::future::Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}
pub const TERMINAL_CASES: [&str; 8] = [
    "joined_holder_terminal",
    "last_member_leave_then_terminal",
    "another_joined_member_remains",
    "authority_lost_before_send",
    "missing_predecessor",
    "departure_with_gap",
    "restart_and_stale_delivery",
    "hard_erasure",
];

pub async fn run_terminal_replication_authority_case(name: &str) -> Result<CaseExecutionResult> {
    ensure!(
        crate::scenarios::_helpers::live_gate::live_services_required(),
        "terminal suite requires COTEST_REQUIRE_LIVE_SERVICES=1; optional live skips cannot establish case execution"
    );
    // These are the same assertion-bearing production journeys used by their
    // dedicated regression targets. Every awaited journey must succeed before
    // the single conjunctive assertion in the canonical case is recorded.
    match name {
        "joined_holder_terminal" => {
            heap_live(|| fanout_route_miss_live::terminal_consumers_live::run()).await?;
            heap_live(|| {
                fanout_route_miss_live::terminal_restart_live::pending_terminal_survives_restart(
                    true,
                )
            })
            .await?;
            heap_live(|| {
                fanout_route_miss_live::terminal_restart_live::pending_terminal_survives_restart(
                    false,
                )
            })
            .await?;
            heap_live(|| signal_live::run_terminal()).await?;
        }
        "last_member_leave_then_terminal" => {
            heap_live(|| {
                fanout_route_miss_live::terminal_restart_live::departure_survives_restart(false)
            })
            .await?;
            heap_live(|| {
                fanout_route_miss_live::terminal_restart_live::departure_survives_restart(true)
            })
            .await?;
            heap_live(|| signal_live::run()).await?;
            heap_live(|| signal_live::run_ban()).await?;
        }
        "another_joined_member_remains" => {
            heap_live(|| {
                fanout_route_miss_live::frozen_authority_live::remaining_witness_and_rejoin()
            })
            .await?;
            heap_live(|| signal_live::run_remaining_member_leave()).await?;
            heap_live(|| signal_live::run_remaining_member_ban()).await?;
        }
        "authority_lost_before_send" => {
            heap_live(|| fanout_route_miss_live::frozen_authority_live::terminal_disclosure(true))
                .await?;
            heap_live(|| {
                fanout_route_miss_live::frozen_authority_live::scope_and_policy_withdrawal()
            })
            .await?;
        }
        "missing_predecessor" => {
            heap_live(|| fanout_route_miss_live::terminal_gap_live::recover(None)).await?;
        }
        "departure_with_gap" => {
            heap_live(|| fanout_route_miss_live::terminal_gap_live::recover(Some(false))).await?;
            heap_live(|| fanout_route_miss_live::terminal_gap_live::recover(Some(true))).await?;
        }
        "restart_and_stale_delivery" => {
            heap_live(|| {
                fanout_route_miss_live::terminal_restart_live::departure_survives_restart(false)
            })
            .await?;
            heap_live(|| {
                fanout_route_miss_live::terminal_restart_live::departure_survives_restart(true)
            })
            .await?;
        }
        "hard_erasure" => {
            heap_live(|| fanout_route_miss_live::erasure_receipt_live::run(false)).await?;
            heap_live(|| fanout_route_miss_live::erasure_receipt_live::run(true)).await?;
        }
        _ => anyhow::bail!("unknown terminal fixture case {name}"),
    }
    println!("[terminal-suite] case={name} production_assertion=passed");
    Ok(CaseExecutionResult {
        case_id: name.into(),
        assertions: 1,
    })
}

pub fn run_terminal_replication_authority_suite() -> Result<SuiteExecutionResult> {
    let fixture = load_fixture_value(FIXTURE)?;
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(serde_json::Value::as_str)
            == Some(TERMINAL_REPLICATION_AUTHORITY_ENTRYPOINT)
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let cases = runtime.block_on(async {
        let mut results = Vec::new();
        for name in TERMINAL_CASES {
            results.push(heap_live(|| run_terminal_replication_authority_case(name)).await?);
        }
        Ok::<_, anyhow::Error>(results)
    })?;
    let result = SuiteExecutionResult {
        entrypoint: TERMINAL_REPLICATION_AUTHORITY_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
    };
    result.assert_complete_against(&fixture)?;
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/terminal-authority-closure");
    std::fs::create_dir_all(&directory)?;
    std::fs::write(
        directory.join("terminal-suite-execution.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"entrypoint":result.entrypoint,"fixture":result.fixture,
            "cases":result.cases.iter().map(|case| serde_json::json!({"case_id":case.case_id,
                "assertions":case.assertions})).collect::<Vec<_>>()}),
        )?,
    )?;
    Ok(result)
}
