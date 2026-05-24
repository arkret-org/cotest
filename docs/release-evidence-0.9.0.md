# cotest Local Release Evidence: 0.9.0

Date: 2026-05-25

Status: local `release-gate` evidence recorded. No GitHub release, tag, remote
CI publication, or registry publication was created.

## Command

```powershell
pwsh -NoProfile -File scripts\run-cotest.ps1 -Profile release-gate -Runtime process -SkipJointSmokeGate
```

## Result

- Status: success
- Runtime: process
- SUT: `manifest:D:\Works\contrix-dev\soland\Cargo.toml`
- Passed: 28
- Failed: 0
- Ignored: 0
- Duration: 99.36 seconds
- Summary: `artifacts/runs/20260525-055932/summary.md`
- Release gate: `artifacts/runs/20260525-055932/release-gate.md`
- Coverage gate: `artifacts/runs/20260525-055932/coverage-gate.md`
- Secret scan: `artifacts/runs/20260525-055932/secret-scan.md`

## Gate Notes

- `mock-parity-allowlist.json` remains empty.
- `coverage-gate.md` passed with no coverage regressions.
- `secret-scan.md` passed.
- `joint_smoke_gate` was intentionally skipped in this protocol-only local
  run via `-SkipJointSmokeGate`; joint UI coverage remains tracked separately.

## Passed Release-Gate Tests

- `artifact_registry_suite_matches_reference_semantics`
- `event_envelope_fixture_suite_matches_reference_semantics`
- `capability_fixture_suite_matches_reference_semantics`
- `state_resolution_fixture_suite_matches_reference_semantics`
- `move_anchor_lattice_fixture_suite_matches_reference_semantics`
- `lattice_round_trip_suite_matches_reference_semantics`
- `anchor_view_compaction_fixture_suite_matches_reference_semantics`
- `anchorer_cell_fixture_suite_matches_reference_semantics`
- `conflict_repair_fixture_suite_matches_reference_semantics`
- `mls_move_covered_frontier_fixture_suite_matches_reference_semantics`
- `discovery_profile_fixture_suite_matches_reference_semantics`
- `sync_fixture_suite_matches_reference_semantics`
- `privacy_security_fixture_suite_matches_reference_semantics`
- `push_rule_core_consistency_vectors_match_all_implementations`
- `yougen_client_profile_manifest_suite_matches_reference_semantics`
- `coauth_account_lifecycle_fixture_suite_matches_reference_semantics`
- `live_describe_profile_gate_suite_matches_reference_semantics`
- `consent_fixture_suite_matches_reference_semantics`
- `composite_state_subject_fixture_suite_matches_reference_semantics`
- `mimi_components_fixture_suite_matches_reference_semantics`
- `events_keys_device_blob_push_and_moderation_surfaces_work`
- `push_and_moderation_edges_are_enforced`
- `account_auth_and_session_edges_are_enforced`
- `federation_replay_snapshot_and_redaction_contracts_work`
- `teabay_directory_service_profile_is_discoverable`
- `starid_optional_resolver_profile_is_discoverable`
- `session_grant_exchange_uses_configured_coauth_introspection`
- `yougen_mock_contract_matches_live_soland_baseline`
