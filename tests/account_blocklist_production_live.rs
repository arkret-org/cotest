//! Production-only blocklist evidence; missing client cases stay uncertified.

use anyhow::Result;

#[test]
fn blocklist_whole_value_cas_runs_through_http_and_postgres() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(verify_blocklist_whole_value_cas())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("blocklist CAS worker panicked"))?
}

async fn verify_blocklist_whole_value_cas() -> Result<()> {
    let result = cotest::conformance::run_account_blocklist_production_cases().await?;
    assert_eq!(result.cases.len(), 5);
    assert_eq!(
        result
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>(),
        [
            "whole_value_cas_rejects_a_stale_expected_revision",
            "whole_value_cas_rejects_a_stale_concurrent_write",
            "unregistered_blocklist_event_kind_is_not_an_authoring_surface",
            "target_closure_rejects_realm_and_organization_targets",
            "an_unsynced_device_treats_freshness_as_unknown",
        ]
    );
    assert!(result.cases.iter().all(|case| case.assertions > 0));
    Ok(())
}

#[test]
fn blocklist_full_suite_runs_all_production_case_executors() -> Result<()> {
    let result = cotest::conformance::run_account_blocklist_projection_suite()?;
    assert_eq!(result.cases.len(), 8);
    assert!(result.cases.iter().all(|case| case.assertions > 0));
    Ok(())
}

#[test]
fn blocklist_real_call_invite_uses_accepted_ordinary_call_and_sealed_delivery() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(cotest::scenarios::mls_lifecycle_live::run_blocklist_call_invite_live())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("CallInvite live worker panicked"))?
}

#[test]
fn blocklist_case4_shared_realm_automatic_receipt_production_slice() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(
                    cotest::scenarios::mls_lifecycle_live::run_blocklist_automatic_receipt_live(),
                )
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("automatic receipt live worker panicked"))?
}

#[test]
fn blocklist_case4_combined_shared_history_and_receipt_slice() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(cotest::conformance::run_account_blocklist_case4_combined_slice())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("case 4 production worker panicked"))?
}

#[test]
fn blocklist_case4_federated_ingress_keeps_private_value_at_holder() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(
                    cotest::conformance::run_account_blocklist_case4_federated_boundary_slice(),
                )
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("case 4 federation boundary worker panicked"))?
}

#[test]
fn blocklist_case4_full_fixture_runs_production_executor() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(async {
                    let result =
                        cotest::conformance::run_account_blocklist_case4_production().await?;
                    assert_eq!(
                        result.case_id,
                        "shared_history_is_received_then_filtered_by_the_holder"
                    );
                    assert_eq!(result.assertions, 6);
                    Ok(())
                })
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("case 4 full fixture worker panicked"))?
}

#[test]
fn blocklist_case5_full_fixture_runs_production_executor() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(async {
                    let result =
                        cotest::conformance::run_account_blocklist_case5_production().await?;
                    assert_eq!(
                        result.case_id,
                        "unblock_rebuilds_the_projection_from_retained_material"
                    );
                    assert_eq!(result.assertions, 4);
                    Ok(())
                })
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("case 5 full fixture worker panicked"))?
}

#[test]
fn blocklist_case6_contact_call_and_federation_combined_slice() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(cotest::conformance::run_account_blocklist_case6_combined_slice())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("case 6 combined slice worker panicked"))?
}

#[test]
fn blocklist_case6_full_fixture_runs_production_executor() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(async {
                    let result =
                        cotest::conformance::run_account_blocklist_case6_production().await?;
                    assert_eq!(
                        result.case_id,
                        "holder_side_request_filtering_stays_indistinguishable"
                    );
                    assert_eq!(result.assertions, 4);
                    Ok(())
                })
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("case 6 full fixture worker panicked"))?
}

#[test]
fn blocklist_case6_cross_station_contact_first_dm_private_boundary_slice() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(
                    cotest::conformance::contact_first_dm_cross_station_private_boundary_live(),
                )
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("case 6 Contact peer relay worker panicked"))?
}

#[test]
fn blocklist_dm_binding_signed_snapshot_is_participant_only() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(
                    cotest::scenarios::direct_conversation_founding_live::blocklist_dm_binding_snapshot_live(),
                )
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("DM binding Snapshot live worker panicked"))?
}

#[test]
fn blocklist_dm_retained_message_automatic_receipt_production_slice() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(
                    cotest::scenarios::direct_conversation_founding_live::blocklist_dm_retained_receipt_live(),
                )
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("DM retained receipt live worker panicked"))?
}

#[test]
fn blocklist_case5_dm_history_restores_but_contact_terminal_does_not_backfill() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(
                    cotest::scenarios::direct_conversation_founding_live::blocklist_case5_dm_history_and_contact_terminal_live(),
                )
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("DM case5 live worker panicked"))?
}

#[test]
fn blocklist_contact_first_dm_pending_request_is_delivered_then_filtered_locally() -> Result<()> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(
                    cotest::scenarios::direct_conversation_founding_live::blocklist_contact_first_dm_pending_request_live(),
                )
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("Contact first-DM blocklist live worker panicked"))?
}
