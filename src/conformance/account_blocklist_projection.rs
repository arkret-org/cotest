//! Production evidence for the holder-private blocklist CAS rail.
//!
//! The whole fixture is deliberately refused until every client and service
//! decision point has a production executor. No harness replica or constant
//! sender observation can certify those missing cases.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow, bail, ensure};
use arkret_models_collaboration::events_payloads::account_data::{
    AccountDataBody, AccountDataSetPayload,
};
use arkret_models_collaboration::objects::productivity::AccountBlocklistValue;
use arkret_models_identity::account::{AccountDataReplaceRequestBody, AccountDataRow};
use arkret_wire::{AccountId, ActorId, DidCoreId};
use reqwest::StatusCode;
use serde_json::{Value, json};

use super::{
    fixture_runner_entrypoint, load_artifact_json, load_fixture_value, required_field,
    required_str, value_array,
};
use crate::harness::{ArkretServer, TestActorClient, actor_core_id, expect_api_error, expect_json};
use crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres_for;
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub const VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION: &str =
    "ak.vector.account.blocklist_projection.v1";
pub const ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT: &str =
    "ak.suite.account.blocklist_projection.v1";
const FIXTURE: &str = "account-blocklist-projection-fixture.json";
const SUITE: &str = "account_blocklist_projection";
const BLOCKLIST_KEY: &str = "ak.account.blocklist";
const PATH: &str = "/_arkret/self/account_data/ak.account.blocklist";
const SECRET: [u8; 32] = [7; 32];
const MISSING_CASES: [&str; 5] = [
    "unregistered_blocklist_event_kind_is_not_an_authoring_surface",
    "shared_history_is_received_then_filtered_by_the_holder",
    "unblock_rebuilds_the_projection_from_retained_material",
    "holder_side_request_filtering_stays_indistinguishable",
    "an_unsynced_device_treats_freshness_as_unknown",
];

pub fn run_account_blocklist_projection_vector() -> Result<()> {
    run_account_blocklist_projection_suite().map(|_| ())
}

pub fn run_account_blocklist_projection_suite() -> Result<super::SuiteExecutionResult> {
    validated_fixture()?;
    bail!(
        "blocklist suite lacks production executors for: {}; the dedicated live CAS slice does not certify the full fixture",
        MISSING_CASES.join(", ")
    )
}

fn validated_fixture() -> Result<Value> {
    let fixture = load_fixture_value(FIXTURE)?;
    verify_fixture_identity(&fixture)?;
    verify_registry_contract()?;
    verify_security_evidence_mapping(&fixture)?;
    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    ensure!(
        cases.len() == 8,
        "blocklist fixture must carry exactly 8 cases"
    );
    let names = cases
        .iter()
        .map(|case| required_str(case, "name"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(names.len() == 8, "duplicate blocklist fixture case");
    let implemented = [
        "whole_value_cas_rejects_a_stale_expected_revision",
        "whole_value_cas_rejects_a_stale_concurrent_write",
        "target_closure_rejects_realm_and_organization_targets",
    ];
    ensure!(
        names == implemented.into_iter().chain(MISSING_CASES).collect(),
        "blocklist fixture cases drifted"
    );
    Ok(fixture)
}

/// Execute the explicitly bounded production slice. This result is never
/// returned by the complete named-suite runner while other cases are missing.
pub async fn run_account_blocklist_production_cases() -> Result<super::SuiteExecutionResult> {
    let fixture = validated_fixture()?;
    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    assert_case(&cases[0], "reject", Some("cas_conflict"))?;
    assert_case(&cases[1], "reject", Some("cas_conflict"))?;
    target_closure(&cases[3])?;
    let database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?
        .context("blocklist live evidence requires an isolated PostgreSQL database")?;
    let server = ArkretServer::spawn_with_database_url(
        "blocklist-cas-production",
        &database.connect_url,
        &[],
    )
    .await?;
    let did = actor_did_for_service_did(server.service_did(), "blocklist-holder")?;
    let holder = server
        .standard_client(&did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let secondary = server
        .standard_client(&did, "ak:device:01904100-0000-7000-8000-0000000000a2")
        .await?;
    let owner = ActorId::account(AccountId::new(
        DidCoreId::new(actor_core_id(&holder.actor)?)?,
        server.service_id().clone(),
    ));

    // Reach revision 7 exclusively through signed, accepted HTTP writes.
    for expected in 0..7 {
        let request = write_request(&holder, &owner, expected, "alice:example.test").await?;
        let row: AccountDataRow = serde_json::from_value(
            expect_json(
                holder.put(PATH).json(&request),
                if expected == 0 {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
            )
            .await?,
        )?;
        ensure!(row.revision == expected + 1);
    }
    let before = persisted_snapshot(&database.connect_url).await?;
    let stale = write_request(&holder, &owner, 6, "bob:example.test").await?;
    expect_api_error(
        holder.put(PATH).json(&stale),
        StatusCode::CONFLICT,
        "cas_conflict",
    )
    .await?;
    ensure!(
        persisted_snapshot(&database.connect_url).await? == before,
        "stale CAS changed the value or retry ledger"
    );
    let row = read_row(&holder).await?;
    ensure!(row.revision == 7 && plaintext(&owner, &row)? == blocklist("alice:example.test")?);

    ensure!(
        read_row(&secondary).await? == row,
        "both devices must start from revision 7"
    );

    // Independent active devices submit different whole values against 7.
    let left = write_request(&holder, &owner, 7, "bob:example.test").await?;
    let right = write_request(&secondary, &owner, 7, "carol:example.test").await?;
    let (left_response, right_response) = tokio::try_join!(
        holder
            .put(PATH)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(arkret_canonical::canonical_json_bytes(&left)?)
            .send(),
        secondary
            .put(PATH)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(arkret_canonical::canonical_json_bytes(&right)?)
            .send()
    )?;
    let left_status = left_response.status();
    let right_status = right_response.status();
    let left_body: Value = left_response.json().await?;
    let right_body: Value = right_response.json().await?;
    let (winner, loser, losing_client, losing_request, winning_client, winning_request, handle) =
        match (left_status, right_status) {
            (StatusCode::OK, StatusCode::CONFLICT) => (
                left_body,
                right_body,
                &secondary,
                &right,
                &holder,
                &left,
                "bob:example.test",
            ),
            (StatusCode::CONFLICT, StatusCode::OK) => (
                right_body,
                left_body,
                &holder,
                &left,
                &secondary,
                &right,
                "carol:example.test",
            ),
            other => bail!(
                "concurrent blocklist CAS must accept exactly one write: {other:?}; left={left_body}, right={right_body}"
            ),
        };
    ensure!(
        loser["type"] == "https://arkret.org/problems/cas_conflict",
        "losing write reason drifted: {loser}"
    );
    let winner: AccountDataRow = serde_json::from_value(winner)?;
    ensure!(
        winner.revision == 8 && plaintext(&owner, &winner)? == blocklist(handle)?,
        "CAS merged or rewrote the winning whole value"
    );
    ensure!(
        read_row(&holder).await? == winner && read_row(&secondary).await? == winner,
        "holder devices disagree on the accepted value"
    );
    let accepted = persisted_snapshot(&database.connect_url).await?;
    ensure!(
        accepted.2 == before.2 + 1,
        "CAS must add exactly one accepted private Event"
    );
    expect_api_error(
        losing_client.put(PATH).json(losing_request),
        StatusCode::CONFLICT,
        "cas_conflict",
    )
    .await?;
    ensure!(
        persisted_snapshot(&database.connect_url).await? == accepted,
        "losing retry changed durable state"
    );
    let exact: AccountDataRow = serde_json::from_value(
        expect_json(
            winning_client.put(PATH).json(winning_request),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        exact == winner && persisted_snapshot(&database.connect_url).await? == accepted,
        "exact retry changed the whole value or ledger"
    );

    // The loser must catch up and author a new Event at the winning revision;
    // resending its unchanged signed body never becomes an accepted write.
    let reread = read_row(losing_client).await?;
    ensure!(reread == winner, "losing device failed to read revision 8");
    let losing_handle = if handle == "bob:example.test" {
        "carol:example.test"
    } else {
        "bob:example.test"
    };
    let reauthored = write_request(losing_client, &owner, reread.revision, losing_handle).await?;
    ensure!(
        reauthored.set_event.event_id != losing_request.set_event.event_id,
        "CAS recovery reused the rejected Event"
    );
    let recovered: AccountDataRow = serde_json::from_value(
        expect_json(losing_client.put(PATH).json(&reauthored), StatusCode::OK).await?,
    )?;
    ensure!(
        recovered.revision == 9 && plaintext(&owner, &recovered)? == blocklist(losing_handle)?,
        "re-authored whole-value write did not replace revision 8"
    );

    ensure!(
        read_row(&holder).await? == recovered
            && read_row(&secondary).await? == recovered
            && persisted_snapshot(&database.connect_url).await?.2 == accepted.2 + 1,
        "the re-authored replacement did not persist once for both devices"
    );

    Ok(super::SuiteExecutionResult {
        entrypoint: ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT,
        fixture: FIXTURE,
        cases: [(0, 3), (1, 12), (3, 3)]
            .into_iter()
            .map(|(index, assertions)| super::CaseExecutionResult {
                case_id: required_str(&cases[index], "name").unwrap().to_owned(),
                assertions,
            })
            .collect(),
    })
}

fn blocklist(handle: &str) -> Result<Value> {
    let value = json!({"entries": [{"target": {"kind": "handle", "value": handle}, "mode": "block", "applies_to": ["messages"], "created_at": "2026-09-20T00:00:00.000Z"}]});
    let typed: AccountBlocklistValue = serde_json::from_value(value)?;
    typed.validate()?;
    Ok(serde_json::to_value(typed)?)
}

async fn write_request(
    holder: &TestActorClient,
    owner: &ActorId,
    expected: u64,
    handle: &str,
) -> Result<AccountDataReplaceRequestBody> {
    let body = arkret_crypto::account_data_crypto::seal_account_data_value(
        &SECRET,
        owner,
        BLOCKLIST_KEY,
        &blocklist(handle)?,
    )?;
    let payload = AccountDataSetPayload {
        key: arkret_wire::NonEmptyString::new(BLOCKLIST_KEY).map_err(anyhow::Error::msg)?,
        expected_server_revision: expected,
        body: AccountDataBody::Value(serde_json::to_value(body)?),
        encrypted_payload: None,
        tombstone: false,
        updated_at: None,
        source_pending_event_id: None,
    };
    payload.validate()?;
    let pcr = holder
        .principal
        .as_ref()
        .context("holder has no provisioned PCR")?
        .pcr_realm_id
        .to_string();
    let set_event = holder
        .author_event(&pcr, "ak.account_data.set", serde_json::to_value(payload)?)
        .await?;
    Ok(AccountDataReplaceRequestBody { set_event })
}

async fn read_row(holder: &TestActorClient) -> Result<AccountDataRow> {
    Ok(serde_json::from_value(
        expect_json(holder.get(PATH), StatusCode::OK).await?,
    )?)
}

fn plaintext(owner: &ActorId, row: &AccountDataRow) -> Result<Value> {
    Ok(arkret_crypto::account_data_crypto::open_account_data_value(
        &SECRET,
        owner,
        BLOCKLIST_KEY,
        &serde_json::from_value(row.content.clone())?,
    )?)
}

// Read the production database using a new connection on every check. No
// fixture inserts or mutations can substitute for the HTTP transaction.
async fn persisted_snapshot(url: &str) -> Result<(String, String, i64)> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<(String, String, i64)> {
        let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
        let values = connection
            .query_one(
                "SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY actor_id, account_data_key),
                '[]'::jsonb)::text FROM account_datas a WHERE account_data_key = $1",
                &[&BLOCKLIST_KEY],
            )?
            .get(0);
        let ledger = connection
            .query_one(
                "SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY event_id), '[]'::jsonb)::text
                FROM actor_private_events e WHERE kind = 'ak.account_data.set'
                AND envelope->'payload'->>'key' = $1",
                &[&BLOCKLIST_KEY],
            )?
            .get(0);
        let events = connection
            .query_one(
                "SELECT count(*) FROM actor_private_events WHERE kind = 'ak.account_data.set'
                AND envelope->'payload'->>'key' = $1",
                &[&BLOCKLIST_KEY],
            )?
            .get(0);
        Ok((values, ledger, events))
    })
    .await?
}

fn assert_case(case: &Value, decision: &str, reason: Option<&str>) -> Result<()> {
    ensure!(
        required_str(case, "decision")? == decision,
        "{}: decision drifted",
        required_str(case, "name")?
    );
    match reason {
        Some(expected) => ensure!(
            required_str(case, "reason")? == expected,
            "{}: reason drifted",
            required_str(case, "name")?
        ),
        None => ensure!(
            case.get("reason").is_none(),
            "{}: successful case unexpectedly declares a failure reason",
            required_str(case, "name")?
        ),
    }
    ensure!(
        !value_array(required_field(case, "assertions")?, "case.assertions")?.is_empty(),
        "{}: case has no observable assertions",
        required_str(case, "name")?
    );
    Ok(())
}

fn target_closure(case: &Value) -> Result<()> {
    assert_case(case, "reject", Some("schema_violation"))?;
    let valid = json!({
        "entries": [{
            "target": {"kind": "handle", "value": "alice:example.test"},
            "mode": "block",
            "applies_to": ["messages"],
            "created_at": "2026-09-20T00:00:00.000Z"
        }]
    });
    let valid: AccountBlocklistValue = serde_json::from_value(valid)?;
    valid.validate()?;

    for forbidden in [
        json!({"kind": "realm", "value": "ak:realm:forbidden"}),
        json!({"kind": "organization", "value": "ak:org:forbidden"}),
    ] {
        let value = json!({
            "entries": [{
                "target": forbidden,
                "mode": "block",
                "applies_to": ["messages"],
                "created_at": "2026-09-20T00:00:00.000Z"
            }]
        });
        ensure!(
            serde_json::from_value::<AccountBlocklistValue>(value).is_err(),
            "the SDK accepted an unregistered Realm/Organization target"
        );
    }
    Ok(())
}

fn verify_fixture_identity(fixture: &Value) -> Result<()> {
    ensure!(
        required_str(fixture, "suite")? == SUITE,
        "fixture suite drifted"
    );
    ensure!(
        fixture_runner_entrypoint(fixture)? == ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT,
        "fixture entrypoint drifted"
    );
    let covers = value_array(required_field(fixture, "covers_vectors")?, "covers_vectors")?;
    ensure!(
        covers
            .iter()
            .any(|value| value.as_str() == Some(VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION)),
        "fixture no longer covers {VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION}"
    );
    Ok(())
}

fn verify_registry_contract() -> Result<()> {
    let registry = load_artifact_json("registry/account-data-key-registry.json")?;
    let rows = value_array(
        required_field(&registry, "account_data_key_patterns")?,
        "account_data_key_patterns",
    )?;
    let row = rows
        .iter()
        .find(|row| row.get("key_pattern").and_then(Value::as_str) == Some(BLOCKLIST_KEY))
        .ok_or_else(|| anyhow!("account-data registry lost {BLOCKLIST_KEY}"))?;
    ensure!(required_str(row, "storage")? == "encrypted_account_data");
    ensure!(required_str(row, "scope")? == "principal_private_policy");
    let writers = value_array(
        required_field(row, "write_event_kinds")?,
        "write_event_kinds",
    )?;
    let writers = writers
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        writers == BTreeSet::from(["ak.account_data.set"]),
        "blocklist authoring surfaces drifted: {writers:?}"
    );
    Ok(())
}

fn verify_security_evidence_mapping(fixture: &Value) -> Result<()> {
    let evidence_rows = value_array(
        required_field(fixture, "security_evidence")?,
        "security_evidence",
    )?;
    ensure!(
        evidence_rows.len() == 1,
        "blocklist fixture must have one evidence row"
    );
    let evidence = &evidence_rows[0];
    ensure!(required_str(evidence, "vector_id")? == VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION);
    ensure!(required_str(evidence, "clause_id")? == "AK-NC-072");
    let expected: BTreeMap<&str, &[&str]> = BTreeMap::from([
        ("whole_value_cas", &["/cases/0", "/cases/1", "/cases/2"][..]),
        ("target_closure", &["/cases/3"][..]),
        ("receive_before_filter", &["/cases/4", "/cases/6"][..]),
        ("unblock_projection_rebuild", &["/cases/5"][..]),
        ("non_enumerable_outcome", &["/cases/6", "/cases/7"][..]),
    ]);
    let mut observed = BTreeSet::new();
    for point in value_array(
        required_field(evidence, "decision_points")?,
        "decision_points",
    )? {
        let id = required_str(&point, "id")?;
        ensure!(observed.insert(id), "duplicate decision point {id}");
        let expected_pointers = expected
            .get(id)
            .ok_or_else(|| anyhow!("unexecuted blocklist decision point {id}"))?;
        let pointers = value_array(required_field(point, "evidence")?, "evidence")?;
        let actual = pointers
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>();
        ensure!(
            actual
                .iter()
                .copied()
                .eq(expected_pointers.iter().map(|value| Some(*value))),
            "{id}: evidence pointers drifted: {actual:?}"
        );
        for pointer in expected_pointers.iter().copied() {
            ensure!(
                fixture.pointer(pointer).is_some(),
                "unresolved evidence pointer {pointer}"
            );
        }
    }
    ensure!(
        observed.len() == expected.len(),
        "not every decision point executed"
    );
    Ok(())
}
