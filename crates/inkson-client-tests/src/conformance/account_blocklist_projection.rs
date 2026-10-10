//! Production evidence for the holder-private blocklist CAS rail.
//!
//! Every fixture case runs through production client and service decisions.
//! No harness replica or constant sender observation certifies a case.

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
pub fn run_account_blocklist_projection_vector() -> Result<()> {
    run_account_blocklist_projection_suite().map(|_| ())
}

pub fn run_account_blocklist_projection_suite() -> Result<super::SuiteExecutionResult> {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| -> Result<super::SuiteExecutionResult> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()?
                .block_on(run_account_blocklist_projection_suite_live())
        })?
        .join()
        .map_err(|_| anyhow!("blocklist full suite worker panicked"))?
}

async fn run_account_blocklist_projection_suite_live() -> Result<super::SuiteExecutionResult> {
    let fixture = validated_fixture()?;
    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    let base = run_account_blocklist_production_cases()
        .await
        .context("blocklist full suite CAS, target, freshness and shared history")?;
    ensure!(
        base.cases.len() == 5,
        "blocklist base did not execute five cases"
    );

    assert_case(&cases[4], "accept", None)?;
    run_account_blocklist_case4_receipt_leg()
        .await
        .context("blocklist full suite encrypted Message and receipt")?;
    run_account_blocklist_case4_federated_boundary_slice()
        .await
        .context("blocklist full suite federation boundary")?;

    assert_case(&cases[5], "accept", None)?;
    run_account_blocklist_case5_dm_leg()
        .await
        .context("blocklist full suite retained DM and Contact terminal")?;

    let case6 = run_account_blocklist_case6_production()
        .await
        .context("blocklist full suite holder-side request filtering")?;
    let mut executed = base
        .cases
        .into_iter()
        .chain([
            fixture_case_result(&cases[4])?,
            fixture_case_result(&cases[5])?,
            case6,
        ])
        .map(|result| (result.case_id.clone(), result))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        executed.len() == 8,
        "blocklist full suite returned duplicate cases"
    );
    let ordered = cases
        .iter()
        .map(|case| {
            let name = required_str(case, "name")?;
            executed
                .remove(name)
                .with_context(|| format!("blocklist full suite did not execute {name}"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        executed.is_empty(),
        "blocklist full suite returned unknown cases"
    );
    let result = super::SuiteExecutionResult {
        entrypoint: ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT,
        fixture: FIXTURE,
        cases: ordered,
    };
    result.assert_complete_against(&fixture)?;
    Ok(result)
}

fn fixture_case_result(case: &Value) -> Result<super::CaseExecutionResult> {
    Ok(super::CaseExecutionResult {
        case_id: required_str(case, "name")?.to_owned(),
        assertions: value_array(required_field(case, "assertions")?, "case.assertions")?.len(),
    })
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
        "unregistered_blocklist_event_kind_is_not_an_authoring_surface",
        "shared_history_is_received_then_filtered_by_the_holder",
        "unblock_rebuilds_the_projection_from_retained_material",
        "holder_side_request_filtering_stays_indistinguishable",
        "an_unsynced_device_treats_freshness_as_unknown",
    ];
    ensure!(
        names == implemented.into_iter().collect(),
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
    assert_case(&cases[2], "reject", Some("schema_violation"))?;
    target_closure(&cases[3])?;
    let database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?
        .context("blocklist live evidence requires an isolated PostgreSQL database")?;
    let server = ArkretServer::spawn_with_database_url(
        "blocklist-cas-production",
        &database.connect_url,
        &[],
    )
    .await?;
    server.assert_tls_trust_boundaries().await?;
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
        reauthored.set_event.event.event_id != losing_request.set_event.event.event_id,
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

    // The retired kind has no authoring lane on either registered ingress.
    // The negative request is still a fully content-bound, signed SDK Event.
    let pcr = holder
        .principal
        .as_ref()
        .context("holder PCR")?
        .pcr_realm_id
        .to_string();
    let retired = holder
        .author_event(&pcr, BLOCKLIST_KEY, blocklist("retired:example.test")?)
        .await?;
    let before = all_event_ledger_snapshot(&database.connect_url).await?;
    expect_api_error(
        holder
            .post("/_arkret/self/events")
            .json(&arkret_wire::EventAdmissionSubmission::new(retired.clone())),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;
    ensure!(
        all_event_ledger_snapshot(&database.connect_url).await? == before,
        "retired shared ingress wrote an Event"
    );
    expect_api_error(
        holder.post("/_arkret/self/actor-private-events").json(
            &arkret_wire::ActorPrivateEventSubmitRequestBody::new(retired),
        ),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;
    ensure!(
        all_event_ledger_snapshot(&database.connect_url).await? == before,
        "retired private ingress wrote an Event"
    );
    ensure!(
        read_row(&holder).await? == recovered,
        "retired kind changed the account-data revision"
    );

    // The same principal core at another Station starts a separate key lane.
    let other_database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?
        .context("other Station requires isolated PostgreSQL")?;
    let other_server = ArkretServer::spawn_with_database_url(
        "blocklist-other-station",
        &other_database.connect_url,
        &[],
    )
    .await?;
    let other_holder = other_server
        .standard_client(&did, "ak:device:01904100-0000-7000-8000-0000000000a3")
        .await?;
    let other_owner = ActorId::account(AccountId::new(
        DidCoreId::new(actor_core_id(&other_holder.actor)?)?,
        other_server.service_id().clone(),
    ));
    ensure!(
        owner.signing_principal_id() == other_owner.signing_principal_id() && owner != other_owner,
        "fixture must use one principal at two exact Station accounts"
    );
    let independent =
        write_request(&other_holder, &other_owner, 0, "independent:example.test").await?;
    let independent: AccountDataRow = serde_json::from_value(
        expect_json(
            other_holder.put(PATH).json(&independent),
            StatusCode::CREATED,
        )
        .await?,
    )?;
    ensure!(
        independent.revision == 1
            && plaintext(&other_owner, &independent)? == blocklist("independent:example.test")?,
        "other Station reused the first account's counter or rules"
    );
    ensure!(
        read_row(&holder).await? == recovered,
        "other Station mutated the first account"
    );

    let _session = native_account_session(&holder).await?;
    private_account_catchup(&holder, &owner).await?;
    retained_shared_history(&server, &holder, &owner).await?;

    Ok(super::SuiteExecutionResult {
        entrypoint: ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT,
        fixture: FIXTURE,
        cases: [(0, 3), (1, 12), (2, 8), (3, 3), (7, 3)]
            .into_iter()
            .map(|(index, assertions)| super::CaseExecutionResult {
                case_id: required_str(&cases[index], "name").unwrap().to_owned(),
                assertions,
            })
            .collect(),
    })
}

/// Execute case 4 against the same production paths used by the bounded CAS
/// runner. The shared Realm leg proves that the accepted Message is retained
/// before the holder filters it and compares two fresh submissions by the
/// same sender under the same Realm authority. The MLS leg observes the
/// automatic receipt difference through the real Native and Signal paths.
/// The full suite also runs this leg after its base five cases, without
/// repeating the same CAS fixture.
pub async fn run_account_blocklist_case4_combined_slice() -> Result<()> {
    let fixture = validated_fixture()?;
    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    assert_case(&cases[4], "accept", None)?;

    // This runner includes retained_shared_history, whose paired sender
    // submissions use one Realm, sender, operation and authority. It also
    // checks the exact verified Commit and durable Native retention.
    let base = run_account_blocklist_production_cases().await?;
    ensure!(
        base.cases.len() == 5,
        "bounded production prerequisite did not execute all existing cases"
    );
    run_account_blocklist_case4_receipt_leg()
        .await
        .context("case 4 encrypted Message and automatic receipt production leg")?;

    Ok(())
}

async fn run_account_blocklist_case4_receipt_leg() -> Result<()> {
    crate::scenarios::mls_lifecycle_live::run_blocklist_automatic_receipt_live().await
}

/// Cross the real peer ingress and federation relay with the holder's private
/// value present only at its own Station. The remote sender repeats the same
/// ordinary operation with unchanged Realm authority after the holder removes
/// the entry; neither Station receives the holder's plaintext target.
pub async fn run_account_blocklist_case4_federated_boundary_slice() -> Result<()> {
    use crate::harness::TestServerGroup;
    use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
    use crate::scenarios::cross_station_mls_welcome::join_through_invite;
    use crate::scenarios::human_device_producer_live::{
        create_realm_with_join_rule, database, grant_message_create, station_env,
        wait_for_committed,
    };
    use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
    use crate::scenarios::mls_lifecycle_live::Member;

    const GROUP: &str = "blocklist-federated-boundary";
    let holder_database = database(GROUP)?.context("holder Station needs isolated PostgreSQL")?;
    let sender_database = database(GROUP)?.context("sender Station needs isolated PostgreSQL")?;
    ensure!(holder_database.connect_url != sender_database.connect_url);
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&holder_database.connect_url, &coauth),
            station_env(&sender_database.connect_url, &coauth),
        ],
    )
    .await?
    .context("case 4 federation boundary requires two real Soland processes")?;
    let holder_station = group.server(0);
    let sender_station = group.server(1);
    let holder = Member::provision(
        holder_station,
        &coauth,
        "blocklist-federated-holder",
        "ak:device:01904100-0000-7000-8000-000000002471",
    )
    .await?;
    let sender = Member::provision(
        sender_station,
        &coauth,
        "blocklist-federated-sender",
        "ak:device:01904100-0000-7000-8000-000000002472",
    )
    .await?;
    let realm = create_realm_with_join_rule(
        &holder.client,
        "Blocklist federated submission boundary",
        "invite",
        &[holder_station, sender_station],
    )
    .await?;
    let strand = holder.client.default_strand_id(&realm)?;
    join_through_invite(
        &holder,
        holder_station,
        &sender,
        &realm,
        "ak:request:019b0000-0000-7000-8000-000000002473",
        'd',
    )
    .await?;
    grant_message_create(&holder.client, holder_station, &realm, &sender.account).await?;

    block_direct_peer(&holder, &sender).await?;
    let (holder_value, holder_ledger, holder_writes) =
        persisted_snapshot(&holder_database.connect_url).await?;
    let (remote_value, remote_ledger, remote_writes) =
        persisted_snapshot(&sender_database.connect_url).await?;
    ensure!(
        holder_writes == 1
            && !holder_value.contains(&sender.actor.to_string())
            && !holder_ledger.contains(&sender.actor.to_string())
            && remote_value == "[]"
            && remote_ledger == "[]"
            && remote_writes == 0,
        "private blocklist target escaped the holder's encrypted Account Data lane"
    );

    let blocked = observed_shared_message(
        &sender.client,
        &realm,
        &strand,
        "federated Message while privately blocked",
    )
    .await?;
    let arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. } = &blocked.outcome else {
        bail!("remote blocked submission did not commit");
    };
    let holder_view = wait_for_committed(&holder.client, &commit.event_ref).await?;
    let sender_view = wait_for_committed(&sender.client, &commit.event_ref).await?;
    ensure!(
        holder_view == sender_view && holder_view.commit() == commit,
        "federation relay changed or withheld the blocked sender's accepted Commit"
    );

    unblock_direct_peer(&holder).await?;
    ensure!(
        persisted_snapshot(&sender_database.connect_url).await?.2 == 0,
        "private unblock revision appeared in the sender Station"
    );
    let unblocked = observed_shared_message(
        &sender.client,
        &realm,
        &strand,
        "federated Message after private unblock",
    )
    .await?;
    let arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. } = &unblocked.outcome else {
        bail!("remote unblocked submission did not commit");
    };
    let holder_view = wait_for_committed(&holder.client, &commit.event_ref).await?;
    let sender_view = wait_for_committed(&sender.client, &commit.event_ref).await?;
    ensure!(
        holder_view == sender_view && holder_view.commit() == commit,
        "federation relay changed or withheld the unblocked sender's accepted Commit"
    );
    compare_shared_sender_observations(&blocked, &unblocked)?;
    Ok(())
}

/// Complete the fixture's shared-history case with production evidence from
/// the holder, sender, Signal and federation paths.
pub async fn run_account_blocklist_case4_production() -> Result<super::CaseExecutionResult> {
    let fixture = validated_fixture()?;
    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    let case = &cases[4];
    assert_case(case, "accept", None)?;
    run_account_blocklist_case4_combined_slice()
        .await
        .context("case 4 holder retention and automatic receipt")?;
    run_account_blocklist_case4_federated_boundary_slice()
        .await
        .context("case 4 encrypted private value and peer ingress boundary")?;
    fixture_case_result(case)
}

/// Exercise the fixture's retained-history restoration in both shared Realm
/// and direct-conversation scopes. The shared leg proves an unchanged raw
/// history is merely reprojected after the next accepted private revision;
/// the DM leg proves the exact ciphertext reappears while a separate Contact
/// tombstone keeps a subsequently refused Message absent after unblock.
pub async fn run_account_blocklist_case5_production() -> Result<super::CaseExecutionResult> {
    let fixture = validated_fixture()?;
    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    let case = &cases[5];
    assert_case(case, "accept", None)?;
    let base = run_account_blocklist_production_cases()
        .await
        .context("case 5 shared Realm retained-history projection")?;
    ensure!(
        base.cases.len() == 5,
        "case 5 shared history prerequisite did not execute its production checks"
    );
    run_account_blocklist_case5_dm_leg()
        .await
        .context("case 5 retained DM history and Contact terminal")?;
    fixture_case_result(case)
}

async fn run_account_blocklist_case5_dm_leg() -> Result<()> {
    crate::scenarios::direct_conversation_founding_live::blocklist_case5_dm_history_and_contact_terminal_live().await
}

/// Exercise the registered holder-side Contact/first-DM and CallInvite
/// surfaces together with the exact two-Station Contact peer carrier.
/// The Contact `direct_message` carrier is also the registered first-DM
/// invitation; it is not a second invented Event kind.
pub async fn run_account_blocklist_case6_combined_slice() -> Result<()> {
    let fixture = validated_fixture()?;
    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    assert_case(&cases[6], "accept", None)?;
    contact_and_first_dm_pending_request_live()
        .await
        .context("case 6 Contact direct_message request and holder filter")?;
    contact_first_dm_cross_station_private_boundary_live()
        .await
        .context("case 6 Contact direct_message peer relay and private data boundary")?;
    crate::scenarios::mls_lifecycle_live::run_blocklist_call_invite_live()
        .await
        .context("case 6 sealed CallInvite and Native dispatch")?;
    Ok(())
}

pub async fn run_account_blocklist_case6_production() -> Result<super::CaseExecutionResult> {
    let fixture = validated_fixture()?;
    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    let case = &cases[6];
    assert_case(case, "accept", None)?;
    run_account_blocklist_case6_combined_slice()
        .await
        .context("case 6 Contact, first-DM, CallInvite and peer response production legs")?;
    fixture_case_result(case)
}

async fn native_account_session(
    client: &TestActorClient,
) -> Result<inkson::conformance::NativeAccountSession> {
    use arkret_models_collaboration::session_grants::{
        SessionGrantValidationByJwt, SessionGrantValidationInput, SessionGrantValidationOutcome,
    };
    use base64::Engine as _;
    let crate::harness::ClientSession::Canonical { grant, signing_key } = client.session() else {
        bail!("native Account evidence requires an issuer-backed DPoP grant");
    };
    let description = client.sdk().describe().await?;
    let authority = description
        .auth_metadata
        .account_authority
        .context("fixture Account Authority")?;
    let request = SessionGrantValidationInput::ByJwt(SessionGrantValidationByJwt {
        grant_jwt: grant.clone(),
        audience_id: Some(description.service_id.clone()),
        proof: None,
    });
    // This is the deployment-private harness issuer, never a client-facing
    // authentication route or a grant reconstructed from unverified JWT claims.
    let result: SessionGrantValidationOutcome = reqwest::Client::new()
        .post(format!(
            "{}/_coauth/internal/session-grants/introspect",
            authority.origin.as_str().trim_end_matches('/')
        ))
        .bearer_auth(crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET)
        .json(&request)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    result.validate()?;
    ensure!(
        result.active && !result.proof_required && !result.one_time_use_consumed,
        "fixture issuer did not confirm an active grant"
    );
    let metadata = result.grant.context("active fixture grant metadata")?;
    let device = arkret_wire::DeviceId::new(client.device_id.clone())?;
    ensure!(
        metadata.account_id.principal_id.as_str() == actor_core_id(&client.actor)?
            && metadata.account_id.station_id == description.service_id
            && metadata.device_id.as_ref() == Some(&device),
        "issuer grant differs from the actual native endpoint"
    );
    let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_key.to_bytes());
    let jwk =
        arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&signing_key.verifying_key());
    ensure!(
        metadata.cnf_jkt == arkret_signatures::dpop::dpop_jwk_thumbprint(&jwk)?,
        "issuer grant is bound to another DPoP holder"
    );
    let outcome = arkret_models_collaboration::session_grants::SessionGrantOutcome {
        session_grant: grant.clone(),
        session_grant_id: metadata.id,
        session_public_key: metadata.session_public_key,
        audience_id: metadata.audience_id,
        granted_scope: metadata.scopes,
        account_id: metadata.account_id,
        device_id: Some(device),
        expires_at: metadata.expires_at,
        previous_session_grant_id: None,
    };
    let principal = client
        .principal
        .as_ref()
        .context("native fixture lacks its accepted Device identity")?;
    inkson::conformance::restore_native_account_session(
        &outcome,
        client.sdk().base_url().as_str(),
        &seed,
        &principal.did,
        &principal.device_signing_key.to_bytes(),
    )
    .await
}

/// Exercise the ordinary Inkson Account projector and Garth subscription,
/// including the durable cursor on a real undecryptable accepted Delta.
async fn private_account_catchup(holder: &TestActorClient, owner: &ActorId) -> Result<()> {
    use base64::Engine as _;
    let authority = owner
        .as_account_id()
        .context("holder exact Account")?
        .clone();
    let secure = inkson::secure_key_store::default_secure_key_store("inkson");
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SECRET);
    inkson::mls::runtime::store_account_mls_secret(secure.as_ref(), &authority, &secret)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("account-blocklist-catchup.json");
    let host = inkson::sync_engine::NativeAccountHost::new(
        holder.sdk(),
        authority.clone(),
        arkret_wire::DeviceId::new(holder.device_id.clone())?,
        inkson::LocalStateStore::with_path(&path),
    )
    .await?;
    ensure!(!host.state_store().blocklist_freshness_known());
    host.catch_up().await?;
    let snapshot = host.state_store();
    ensure!(
        snapshot.blocklist_freshness_known() && snapshot.client_blocklist_revision() == 9,
        "actual account projector did not catch up accepted revision 9"
    );
    ensure!(
        serde_json::to_value(snapshot.client_blocklist())?
            == plaintext(owner, &read_row(holder).await?)?["entries"],
        "actual Account Data hydration differs from the accepted encrypted whole value"
    );
    let checkpoint = snapshot
        .sync_cursor()
        .context("durable account checkpoint")?;
    drop(host);
    ensure!(
        !snapshot.blocklist_freshness_known(),
        "dropped account attempt retained Signal authority"
    );
    let request = write_request(holder, owner, 9, "fresh-catchup:example.test").await?;
    expect_json(holder.put(PATH).json(&request), StatusCode::OK).await?;
    inkson::mls::runtime::store_account_mls_secret(
        secure.as_ref(),
        &authority,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([8u8; 32]),
    )?;
    let failed = inkson::sync_engine::NativeAccountHost::new(
        holder.sdk(),
        authority.clone(),
        arkret_wire::DeviceId::new(holder.device_id.clone())?,
        inkson::LocalStateStore::with_path(&path),
    )
    .await?;
    ensure!(
        failed.catch_up().await.is_err(),
        "undecryptable accepted Delta crossed the actual Account projector"
    );
    ensure!(
        !failed.state_store().blocklist_freshness_known()
            && failed.state_store().client_blocklist_revision() == 9
            && failed.state_store().sync_cursor().as_deref() == Some(checkpoint.as_str()),
        "bad Delta advanced the production checkpoint or released freshness"
    );
    drop(failed);
    inkson::mls::runtime::store_account_mls_secret(secure.as_ref(), &authority, &secret)?;
    let repaired = inkson::sync_engine::NativeAccountHost::new(
        holder.sdk(),
        authority.clone(),
        arkret_wire::DeviceId::new(holder.device_id.clone())?,
        inkson::LocalStateStore::with_path(&path),
    )
    .await?;
    repaired.catch_up().await?;
    ensure!(
        repaired.state_store().blocklist_freshness_known()
            && repaired.state_store().client_blocklist_revision() == 10,
        "repair did not replay the failed Delta through the real account driver"
    );
    Ok(())
}

use cotest::conformance::shared_submission::{
    compare_shared_sender_observations, json_shape, observed_authored_shared_message,
    observed_shared_message,
};

/// This executor inspects the real Garth verification and Inkson retention /
/// timeline path. It is a bounded layer of cases 4/5, not their full oracle.
async fn retained_shared_history(
    server: &ArkretServer,
    holder: &TestActorClient,
    owner: &ActorId,
) -> Result<()> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let peer_did = actor_did_for_service_did(server.service_did(), "blocklist-shared-peer")?;
    let peer = server
        .standard_client(&peer_did, "ak:device:01904100-0000-7000-8000-0000000000b1")
        .await?;
    crate::scenarios::identity_test_support::create_human_actor_profile(holder, "Blocklist holder")
        .await?;
    crate::scenarios::identity_test_support::create_human_actor_profile(&peer, "Blocklist peer")
        .await?;
    let realm = holder
        .create_realm("Blocklist retained shared history")
        .await?;
    let strand = holder.default_strand_id(&realm)?;
    holder.add_member(&realm, &peer).await?;
    holder
        .grant_realm_actions_to(&realm, &peer.actor, &["ak.message.create"])
        .await?;
    let body = "retained body survives holder block and unblock";
    let http = holder.sdk();
    let authority = garth::AuthorityClient::new(http.clone());
    let realm_id = arkret_wire::RealmId::new(realm.clone())?;
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let nonce = arkret_wire::Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(
            format!(
                "{}:{}",
                realm_id,
                chrono::Utc::now()
                    .timestamp_nanos_opt()
                    .context("nonce clock")?
            )
            .as_bytes(),
        )),
    )
    .map_err(anyhow::Error::msg)?;
    let request = arkret_wire::AuthorityBundleRequest {
        realm_id: realm_id.clone(),
        nonce: nonce.clone(),
    };
    let mut replica = garth::RealmReplica::new(realm_id.clone());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("retained-blocklist-history.json");
    let peer_actor = ActorId::account(AccountId::new(
        DidCoreId::new(actor_core_id(&peer.actor)?)?,
        server.service_id().clone(),
    ));
    let entry = inkson::account_data::new_blocklist_entry(
        inkson::account_data::BlocklistUiTargetKind::Actor,
        &peer_actor.to_string(),
        None,
        Vec::new(),
        None,
        chrono::Utc::now(),
    )
    .map_err(anyhow::Error::msg)?;
    let prior = read_row(holder).await?;
    let blocking_revision = prior
        .revision
        .checked_add(1)
        .context("blocking revision overflow")?;
    let write =
        write_value_request(holder, owner, prior.revision, json!({"entries":[entry]})).await?;
    expect_json(holder.put(PATH).json(&write), StatusCode::OK).await?;
    let account = owner
        .as_account_id()
        .context("exact holder Account")?
        .clone();
    let host = inkson::sync_engine::NativeAccountHost::new(
        holder.sdk(),
        account.clone(),
        arkret_wire::DeviceId::new(holder.device_id.clone())?,
        inkson::LocalStateStore::with_path(&path),
    )
    .await?;
    host.catch_up().await?;
    let mut store = host.state_store();
    ensure!(
        store.blocklist_freshness_known() && store.client_blocklist_revision() == blocking_revision,
        "production account catch-up did not apply the accepted actor block value"
    );
    let blocked_sender = observed_shared_message(&peer, &realm, &strand, body).await?;
    // Resolve the head after the peer's accepted Message, so the verifier's
    // authenticated target cut includes the exact material being inspected.
    let bundle = authority.resolve_authority(&request).await?;
    let freshness = arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), nonce);
    let keys = garth::fetch_historical_station_key_directory(&http, &bundle, None, None).await?;
    replica.install_verified_authority(&request, bundle.clone(), &freshness, &keys)?;
    let mut after = None;
    loop {
        let scan = arkret_wire::StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(after),
            limit: 64,
        };
        let page = authority.scan(&scan).await?;
        let truncated = page.truncated;
        let page_keys =
            garth::fetch_historical_station_key_directory(&http, &bundle, Some(&page), None)
                .await?;
        let verified = replica.apply_verified_scan(&scan, page, &freshness, &page_keys)?;
        host.state_store_handle()
            .write(|store| store.ingest_verified_message_history(&verified))
            .map_err(anyhow::Error::msg)?;
        store = host.state_store();
        after = Some(
            replica
                .verified_head(&stream)
                .context("verified shared head")?
                .stream_position,
        );
        if !truncated {
            break;
        }
    }
    ensure!(
        replica.verified_head(&stream) == Some(&bundle.realm_stream_head),
        "blocking must not stop shared Commit advancement"
    );
    let blocked = inkson::conformance::retained_blocklist_message_projection(&store);
    let retained = blocked
        .iter()
        .find(|(_, text, _)| text == body)
        .context("accepted canonical message was not retained by the production reducer")?;
    ensure!(
        retained.2,
        "production timeline failed to hide the exact blocked actor"
    );
    let retained_id = retained.0.clone();
    ensure!(
        inkson::conformance::retained_blocklist_receipt_candidate(&store, &realm, &strand)
            .is_none(),
        "blocked retained message became an automatic receipt candidate"
    );
    let raw_before = store.load().raw_operations;
    drop(host);
    let reopened = inkson::LocalStateStore::with_path(&path);
    ensure!(
        inkson::conformance::retained_blocklist_message_projection(&reopened)
            .iter()
            .any(|(id, text, hidden)| id == &retained_id && text == body && *hidden),
        "retention or private filter did not survive durable reload"
    );
    ensure!(
        !reopened.blocklist_freshness_known()
            && reopened.client_blocklist_revision() == blocking_revision,
        "reload must keep the held revision while refusing freshness"
    );
    let write =
        write_value_request(holder, owner, blocking_revision, json!({"entries":[]})).await?;
    expect_json(holder.put(PATH).json(&write), StatusCode::OK).await?;
    let host = inkson::sync_engine::NativeAccountHost::new(
        holder.sdk(),
        account,
        arkret_wire::DeviceId::new(holder.device_id.clone())?,
        reopened,
    )
    .await?;
    observe_unknown_privacy_signals(
        holder,
        &host,
        owner.as_account_id().context("holder Account")?,
        &realm,
        &strand,
        &retained_id,
    )
    .await?;
    host.catch_up().await?;
    let reopened = host.state_store();
    ensure!(
        reopened.blocklist_freshness_known()
            && reopened.client_blocklist_revision() == blocking_revision + 1,
        "unblock did not arrive through the accepted private Account stream"
    );
    ensure!(
        inkson::conformance::retained_blocklist_message_projection(&reopened)
            .iter()
            .any(|(id, text, hidden)| id == &retained_id && text == body && !hidden),
        "unblock failed to rebuild from canonical retained history"
    );
    ensure!(
        inkson::conformance::retained_blocklist_receipt_candidate(&reopened, &realm, &strand)
            .as_deref()
            == Some(retained_id.as_str()),
        "unblock did not restore the actual automatic receipt selector"
    );
    ensure!(
        reopened.load().raw_operations == raw_before,
        "private unblock rewrote shared history"
    );
    let unblocked_sender = observed_shared_message(&peer, &realm, &strand, body).await?;
    compare_shared_sender_observations(&blocked_sender, &unblocked_sender)?;
    Ok(())
}

/// Observe the actual sender before its first authority lookup. The listener
/// refuses every request; it supplies no authority, MLS or Signal success.
async fn observe_unknown_privacy_signals(
    holder: &TestActorClient,
    host: &inkson::sync_engine::NativeAccountHost,
    account: &AccountId,
    realm: &str,
    strand: &str,
    event: &str,
) -> Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    ensure!(!host.state_store().blocklist_freshness_known());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/", listener.local_addr()?);
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let receiver = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let mut buffer = [0u8; 8192];
            if socket.read(&mut buffer).await.unwrap_or(0) > 0 {
                observed.fetch_add(1, Ordering::SeqCst);
                let _ = socket.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            }
        }
    });
    // This listener is an intentionally refusing loopback transport probe.
    // It carries no session authority and cannot admit a Signal.
    let observer = arkret_http_client::Client::builder(endpoint.parse()?)
        .allow_insecure_localhost()
        .build()?;
    let submitter = inkson::event_submit::EventSubmitter::new(observer.clone());
    let material = inkson::signal::SignalKeyMaterial {
        group_state_ref: event.to_owned(),
        epoch: 0,
        aead_profile: arkret::MLS_CIPHERSUITES
            .iter()
            .find(|suite| suite.status == "active")
            .context("active MLS suite")?
            .canonical_id
            .to_owned(),
    };
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: arkret_wire::RealmId::new(realm)?,
    };
    let payloads = [
        inkson::signal::SignalPayload::Presence {
            state: "online".to_owned(),
            status_message: None,
            last_active_at: None,
        },
        inkson::signal::SignalPayload::ReadReceipt {
            strand_id: arkret_wire::StrandId::new(strand)?,
            event_id: arkret_wire::EventId::new(event)?,
        },
    ];
    for payload in payloads {
        let error = submitter
            .send_scope_signal(
                scope.clone(),
                account,
                &arkret_wire::DeviceId::new(holder.device_id.clone())?,
                &material,
                &payload,
                &host.state_store_handle(),
            )
            .await
            .unwrap_err();
        ensure!(
            error.to_string().contains("blocklist freshness is unknown"),
            "unknown freshness reached a later sender gate: {error}"
        );
        ensure!(
            requests.load(Ordering::SeqCst) == 0,
            "unknown freshness emitted an HTTP request"
        );
    }
    // A real SDK request proves that this listener observes outbound traffic.
    ensure!(observer.describe().await.is_err());
    ensure!(
        requests.load(Ordering::SeqCst) > 0,
        "network observer saw no positive control"
    );
    receiver.abort();
    Ok(())
}

fn blocklist(handle: &str) -> Result<Value> {
    let value = json!({"entries": [{"target": {"kind": "handle", "value": handle}, "mode": "block", "applies_to": ["messages"], "created_at": "2026-09-20T00:00:00.000Z"}]});
    let typed: AccountBlocklistValue = serde_json::from_value(value)?;
    typed.validate()?;
    Ok(serde_json::to_value(typed)?)
}

pub(crate) async fn block_direct_peer(
    holder: &crate::scenarios::mls_lifecycle_live::Member,
    peer: &crate::scenarios::mls_lifecycle_live::Member,
) -> Result<()> {
    use base64::Engine as _;
    inkson::mls::runtime::store_account_mls_secret(
        inkson::secure_key_store::default_secure_key_store("inkson").as_ref(),
        &holder.account,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SECRET),
    )?;
    let entry = inkson::account_data::new_blocklist_entry(
        inkson::account_data::BlocklistUiTargetKind::Actor,
        &peer.actor.to_string(),
        None,
        Vec::new(),
        None,
        chrono::Utc::now(),
    )
    .map_err(anyhow::Error::msg)?;
    let response = holder.client.get(PATH).send().await?;
    let revision = match response.status() {
        StatusCode::OK => response.json::<AccountDataRow>().await?.revision,
        StatusCode::NOT_FOUND => 0,
        status => bail!("actual blocklist read failed before DM fixture: {status}"),
    };
    let request = write_value_request(
        &holder.client,
        &holder.actor,
        revision,
        json!({"entries":[entry]}),
    )
    .await?;
    expect_json(
        holder.client.put(PATH).json(&request),
        if revision == 0 {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
    )
    .await?;
    Ok(())
}

pub(crate) async fn unblock_direct_peer(
    holder: &crate::scenarios::mls_lifecycle_live::Member,
) -> Result<()> {
    let row = read_row(&holder.client).await?;
    let request = write_value_request(
        &holder.client,
        &holder.actor,
        row.revision,
        json!({"entries": []}),
    )
    .await?;
    expect_json(holder.client.put(PATH).json(&request), StatusCode::OK).await?;
    ensure!(
        plaintext(&holder.actor, &read_row(&holder.client).await?)? == json!({"entries": []}),
        "the holder's accepted unblock revision did not remove the private entry"
    );
    Ok(())
}

/// A Contact request with `direct_message` scope is the registered first-DM
/// invitation. The holder receives its accepted row before private filtering.
pub async fn contact_and_first_dm_pending_request_live() -> Result<()> {
    use arkret::contact_operations::{
        ContactAcceptedOutcome, ContactCommitPhase, ContactCommitRequestBody,
        ContactOperationOutcome, ContactOperationRequestBody, ContactPreparedOutcome, ContactScope,
        ContactState,
    };

    use crate::harness::TestServerGroup;
    use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
    use crate::scenarios::_helpers::live_gate::skip_or_fail;
    use crate::scenarios::human_device_producer_live::{database, station_env};
    use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
    use crate::scenarios::mls_lifecycle_live::Member;

    const GROUP: &str = "blocklist-contact-first-dm-live";
    let Some(database) = database(GROUP)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let node_envs = [station_env(&database.connect_url, &coauth)];
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(GROUP, &node_envs).await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let station = group.server(0);
    let alice = Member::provision(
        station,
        &coauth,
        "blocklist-contact-holder",
        "ak:device:01904100-0000-7000-8000-000000002461",
    )
    .await?;
    let bob = Member::provision(
        station,
        &coauth,
        "blocklist-contact-sender",
        "ak:device:01904100-0000-7000-8000-000000002462",
    )
    .await?;
    block_direct_peer(&alice, &bob).await?;
    let directory = tempfile::tempdir()?;
    let holder_host = inkson::sync_engine::NativeAccountHost::new(
        alice.client.sdk(),
        alice.account.clone(),
        alice.device.clone(),
        inkson::LocalStateStore::with_path(directory.path().join("contact-holder.json")),
    )
    .await?;
    holder_host.catch_up().await?;
    catch_up_blocklist_revision(&holder_host, read_row(&alice.client).await?.revision).await?;
    ensure!(
        inkson::account_data::hides_contact_request(
            &holder_host.state_store().client_blocklist(),
            &bob.actor,
        ),
        "accepted private block did not filter Bob's Contact surface"
    );

    let prepare = bob.client.contact_request_prepare(&alice.client.actor)?;
    let ContactOperationRequestBody::Prepare(prepared_input) = &prepare else {
        bail!("first DM Contact fixture lacks a prepare request");
    };
    ensure!(
        prepared_input.granted_to_peer_scopes == vec![ContactScope::DirectMessage],
        "first DM request did not use the registered Contact direct_message scope"
    );
    let mut observations = Vec::new();
    let mut prepared = None;
    for blocked in [true, false] {
        let started = std::time::Instant::now();
        let response = bob
            .client
            .post("/_arkret/self/contacts/request")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(arkret_canonical::canonical_json_bytes(&prepare)?)
            .send()
            .await?;
        let status = response.status();
        let protocol = format!("{:?}", response.version());
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        ensure!(
            !response.headers().iter().any(|(_, value)| value
                .to_str()
                .is_ok_and(|value| value.contains("blocked_by_user"))),
            "holder-private block leaked through a Contact prepare response header"
        );
        let bytes = response.bytes().await?;
        let elapsed = started.elapsed();
        ensure!(
            status == StatusCode::OK,
            "Contact prepare changed sender-visible status at blocked={blocked}: {status} {}",
            String::from_utf8_lossy(&bytes)
        );
        let value: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            !value.to_string().contains("blocked_by_user"),
            "holder-private block leaked through Contact prepare response"
        );
        let outcome: ContactOperationOutcome = serde_json::from_value(value.clone())?;
        ensure!(
            matches!(
                &outcome,
                ContactOperationOutcome::Prepared {
                    outcome: ContactPreparedOutcome::Request { .. }
                }
            ),
            "Contact prepare did not return its registered request branch: {outcome:?}"
        );
        observations.push((status, protocol, content_type, json_shape(&value), elapsed));
        prepared = Some(outcome);
        if blocked {
            unblock_direct_peer(&alice).await?;
            catch_up_blocklist_revision(&holder_host, read_row(&alice.client).await?.revision)
                .await?;
        }
    }
    ensure!(
        observations[0].0 == observations[1].0
            && observations[0].1 == observations[1].1
            && observations[0].2 == observations[1].2
            && observations[0].3 == observations[1].3,
        "holder-private block changed the exact Contact prepare replay response envelope"
    );
    block_direct_peer(&alice, &bob).await?;
    catch_up_blocklist_revision(&holder_host, read_row(&alice.client).await?.revision).await?;
    let ContactOperationOutcome::Prepared {
        outcome:
            ContactPreparedOutcome::Request {
                reservation_handle,
                event_draft,
                ..
            },
    } = prepared.context("Contact prepare yielded no result")?
    else {
        bail!("Contact prepare replay omitted its request draft");
    };
    let commit = ContactOperationRequestBody::Commit(ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id: prepared_input.operation_id.clone(),
        idempotency_key: prepared_input.idempotency_key.clone(),
        reservation_handle,
        signed_event: bob.client.sign_prepared_contact_event(
            &event_draft,
            arkret_wire::event_kind_str::CONTACT_REQUESTED,
        )?,
    });
    let commit_request_bytes = arkret_canonical::canonical_json_bytes(&commit)?;
    let started = std::time::Instant::now();
    let response = bob
        .client
        .post("/_arkret/self/contacts/request")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(commit_request_bytes.clone())
        .send()
        .await?;
    let commit_status = response.status();
    ensure!(
        !response.headers().iter().any(|(_, value)| value
            .to_str()
            .is_ok_and(|value| value.contains("blocked_by_user"))),
        "holder-private block leaked through a Contact commit response header"
    );
    let commit_bytes = response.bytes().await?;
    let commit_elapsed = started.elapsed();
    ensure!(
        commit_status == StatusCode::OK,
        "blocked Contact commit was not accepted: {commit_status} {}",
        String::from_utf8_lossy(&commit_bytes)
    );
    let committed: ContactOperationOutcome = serde_json::from_slice(&commit_bytes)?;
    let ContactOperationOutcome::Accepted {
        outcome:
            ContactAcceptedOutcome::Request {
                request_acceptance_receipt,
                ..
            },
    } = committed
    else {
        bail!("blocked Contact commit changed its closed outcome: {committed:?}");
    };
    let row = alice
        .client
        .sdk()
        .contacts_list()
        .await?
        .contacts
        .into_iter()
        .find(|row| row.peer.contact_actor_id() == bob.actor)
        .context("Contact service did not deliver Bob's accepted request to Alice")?;
    ensure!(
        row.state == ContactState::PendingIncoming
            && row.request_event_ref.as_ref()
                == Some(&request_acceptance_receipt.core.request_event_ref)
            && row
                .granted_by_peer_scopes
                .contains(&ContactScope::DirectMessage),
        "holder did not retain exact first-DM-scoped Contact request"
    );
    let sender_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let sender_row = bob
            .client
            .sdk()
            .contacts_list()
            .await?
            .contacts
            .into_iter()
            .find(|candidate| candidate.peer.contact_actor_id() == alice.actor);
        if sender_row.as_ref().is_some_and(|candidate| {
            candidate.state == ContactState::PendingOutgoing
                && candidate.request_event_ref == row.request_event_ref
        }) {
            break;
        }
        ensure!(
            std::time::Instant::now() < sender_deadline,
            "sender's queried Contact projection did not retain its accepted pending request: {sender_row:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    ensure!(
        inkson::account_data::hides_contact_request(
            &holder_host.state_store().client_blocklist(),
            &bob.actor
        ),
        "holder default Contact inbox did not filter the accepted pending request"
    );
    let mut committed_replays = Vec::new();
    for blocked in [true, false] {
        if !blocked {
            unblock_direct_peer(&alice).await?;
            catch_up_blocklist_revision(&holder_host, read_row(&alice.client).await?.revision)
                .await?;
        }
        let started = std::time::Instant::now();
        let response = bob
            .client
            .post("/_arkret/self/contacts/request")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(commit_request_bytes.clone())
            .send()
            .await?;
        let status = response.status();
        let protocol = format!("{:?}", response.version());
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        ensure!(
            !response.headers().iter().any(|(_, value)| value
                .to_str()
                .is_ok_and(|value| value.contains("blocked_by_user"))),
            "holder-private block leaked through Contact Commit replay headers"
        );
        let bytes = response.bytes().await?;
        let elapsed = started.elapsed();
        ensure!(
            status == StatusCode::OK
                && bytes.as_ref() == commit_bytes.as_ref()
                && !String::from_utf8_lossy(&bytes).contains("blocked_by_user"),
            "Contact exact Commit replay changed its accepted outcome at blocked={blocked}: {status} {}",
            String::from_utf8_lossy(&bytes)
        );
        committed_replays.push((status, protocol, content_type, elapsed));
    }
    ensure!(
        committed_replays[0].0 == committed_replays[1].0
            && committed_replays[0].1 == committed_replays[1].1
            && committed_replays[0].2 == committed_replays[1].2,
        "holder-private block changed the exact Contact Commit replay transport envelope"
    );
    ensure!(
        !inkson::account_data::hides_contact_request(
            &holder_host.state_store().client_blocklist(),
            &bob.actor
        ),
        "unblock did not restore the accepted pending Contact request"
    );
    let reopened = alice.client.sdk().contacts_list().await?.contacts;
    ensure!(
        reopened
            .iter()
            .any(|candidate| candidate.peer.contact_actor_id() == bob.actor
                && candidate.state == ContactState::PendingIncoming
                && candidate.request_event_ref == row.request_event_ref),
        "private unblock changed or deleted the accepted first-DM Contact row"
    );
    eprintln!(
        "blocklist Contact first-DM exact replays: prepare_protocol={}, prepare_status={}, prepare_shape={}, blocked_prepare_ns={}, unblocked_prepare_ns={}; first_commit_status={}, first_commit_ns={}; blocked_commit_replay_ns={}, unblocked_commit_replay_ns={}; timing is diagnostic only",
        observations[0].1,
        observations[0].0,
        observations[0].3,
        observations[0].4.as_nanos(),
        observations[1].4.as_nanos(),
        commit_status,
        commit_elapsed.as_nanos(),
        committed_replays[0].3.as_nanos(),
        committed_replays[1].3.as_nanos(),
    );
    Ok(())
}

/// Keep the Contact/first-DM request on its registered peer carrier while
/// only the holder's encrypted Account Data revision changes. Both Stations
/// must retain the same request Event; the sender Station has no blocklist
/// row or target material to inspect.
pub async fn contact_first_dm_cross_station_private_boundary_live() -> Result<()> {
    use arkret::contact_operations::{
        ContactAcceptedOutcome, ContactCommitPhase, ContactCommitRequestBody,
        ContactOperationOutcome, ContactOperationRequestBody, ContactPeer, ContactPreparePhase,
        ContactPrepareRequestBody, ContactPreparedOutcome, ContactScope, ContactState,
    };
    use arkret_models_collaboration::governance::invite_addressing::{
        InviteLocatorIssueRequestBody, InviteLocatorResolveRequestBody, PrincipalLocator,
    };
    use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;

    use crate::harness::{TestServerGroup, next_typed_id};
    use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
    use crate::scenarios::human_device_producer_live::{database, station_env};
    use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
    use crate::scenarios::mls_lifecycle_live::Member;

    const GROUP: &str = "blocklist-first-dm-contact-federation";
    let holder_database = database(GROUP)?.context("holder needs isolated PostgreSQL")?;
    let sender_database = database(GROUP)?.context("sender needs isolated PostgreSQL")?;
    ensure!(holder_database.connect_url != sender_database.connect_url);
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let station = |url: &str| {
        let mut env = station_env(url, &coauth);
        env.push(("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()));
        env
    };
    let group = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station(&holder_database.connect_url),
            station(&sender_database.connect_url),
        ],
    )
    .await?
    .context("first-DM Contact federation needs two real Soland processes")?;
    let holder = Member::provision(
        group.server(0),
        &coauth,
        "blocklist-first-dm-federated-holder",
        "ak:device:01904100-0000-7000-8000-000000002481",
    )
    .await?;
    let sender = Member::provision(
        group.server(1),
        &coauth,
        "blocklist-first-dm-federated-sender",
        "ak:device:01904100-0000-7000-8000-000000002482",
    )
    .await?;
    block_direct_peer(&holder, &sender).await?;
    let directory = tempfile::tempdir()?;
    let holder_host = inkson::sync_engine::NativeAccountHost::new(
        holder.client.sdk(),
        holder.account.clone(),
        holder.device.clone(),
        inkson::LocalStateStore::with_path(directory.path().join("holder.json")),
    )
    .await?;
    holder_host.catch_up().await?;
    catch_up_blocklist_revision(&holder_host, read_row(&holder.client).await?.revision).await?;
    ensure!(
        inkson::account_data::hides_contact_request(
            &holder_host.state_store().client_blocklist(),
            &sender.actor
        ),
        "cross-Station holder did not install its private Contact filter"
    );
    let (holder_value, holder_ledger, holder_writes) =
        persisted_snapshot(&holder_database.connect_url).await?;
    let (sender_value, sender_ledger, sender_writes) =
        persisted_snapshot(&sender_database.connect_url).await?;
    ensure!(
        holder_writes == 1
            && !holder_value.contains(&sender.actor.to_string())
            && !holder_ledger.contains(&sender.actor.to_string())
            && sender_value == "[]"
            && sender_ledger == "[]"
            && sender_writes == 0,
        "holder-private target escaped to the Contact sender Station"
    );

    let locator_issued = expect_json(
        holder
            .client
            .post("/_arkret/self/invite-locators")
            .json(&InviteLocatorIssueRequestBody {
                ttl_seconds: Some(900),
                ..Default::default()
            }),
        StatusCode::OK,
    )
    .await?;
    let locator_token = locator_issued["locator_token"]
        .as_str()
        .context("holder locator issue omitted token")?;
    let locator: PrincipalLocator = serde_json::from_value(
        expect_json(
            holder
                .client
                .post("/_arkret/open/invite-locators/resolve")
                .json(&InviteLocatorResolveRequestBody::new(locator_token)),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(locator.account_id == holder.account);
    let operation_id =
        arkret::ProtocolOperationId::new(next_typed_id("operation")).map_err(anyhow::Error::msg)?;
    let idempotency_key =
        arkret::IdempotencyKey::new(next_typed_id("idempotency")).map_err(anyhow::Error::msg)?;
    let prepare = ContactOperationRequestBody::Prepare(ContactPrepareRequestBody {
        phase: ContactPreparePhase::Prepare,
        operation_id: operation_id.clone(),
        idempotency_key: idempotency_key.clone(),
        peer: ContactPeer::Human {
            account_id: holder.account.clone(),
        },
        granted_to_peer_scopes: vec![ContactScope::DirectMessage],
        introduction_evidence: ContactIntroductionEvidence::LocatorRef {
            principal_locator: locator,
        },
        continuity_evidence: None,
        message: None,
    });
    let prepared = expect_json(
        sender
            .client
            .post("/_arkret/self/contacts/request")
            .json(&prepare),
        StatusCode::OK,
    )
    .await?;
    ensure!(!prepared.to_string().contains("blocked_by_user"));
    let ContactOperationOutcome::Prepared {
        outcome:
            ContactPreparedOutcome::Request {
                reservation_handle,
                event_draft,
                ..
            },
    } = serde_json::from_value(prepared)?
    else {
        bail!("cross-Station first-DM Contact request did not prepare");
    };
    let commit = ContactOperationRequestBody::Commit(ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id,
        idempotency_key,
        reservation_handle,
        signed_event: sender.client.sign_prepared_contact_event(
            &event_draft,
            arkret_wire::event_kind_str::CONTACT_REQUESTED,
        )?,
    });
    let commit_bytes = arkret_canonical::canonical_json_bytes(&commit)?;
    let initial_started = std::time::Instant::now();
    let response = sender
        .client
        .post("/_arkret/self/contacts/request")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(commit_bytes.clone())
        .send()
        .await?;
    let initial_status = response.status();
    ensure!(
        !response.headers().iter().any(|(_, value)| value
            .to_str()
            .is_ok_and(|value| value.contains("blocked_by_user"))),
        "Contact peer submission disclosed a private block in response headers"
    );
    let initial_body = response.bytes().await?;
    let initial_elapsed = initial_started.elapsed();
    ensure!(
        initial_status == StatusCode::OK,
        "blocked first-DM peer submission failed: {initial_status} {}",
        String::from_utf8_lossy(&initial_body)
    );
    let accepted: Value = serde_json::from_slice(&initial_body)?;
    ensure!(!accepted.to_string().contains("blocked_by_user"));
    let ContactOperationOutcome::Accepted {
        outcome:
            ContactAcceptedOutcome::Request {
                request_acceptance_receipt,
                ..
            },
    } = serde_json::from_value(accepted)?
    else {
        bail!("cross-Station first-DM Contact request did not commit");
    };
    let event_ref = request_acceptance_receipt.core.request_event_ref;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let incoming = holder
            .client
            .sdk()
            .contacts_list()
            .await?
            .contacts
            .into_iter()
            .find(|row| row.peer.contact_actor_id() == sender.actor);
        let outgoing = sender
            .client
            .sdk()
            .contacts_list()
            .await?
            .contacts
            .into_iter()
            .find(|row| row.peer.contact_actor_id() == holder.actor);
        if incoming.as_ref().is_some_and(|row| {
            row.state == ContactState::PendingIncoming
                && row.request_event_ref.as_ref() == Some(&event_ref)
                && row
                    .granted_by_peer_scopes
                    .contains(&ContactScope::DirectMessage)
        }) && outgoing.as_ref().is_some_and(|row| {
            row.state == ContactState::PendingOutgoing
                && row.request_event_ref.as_ref() == Some(&event_ref)
        }) {
            break;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "Contact peer relay did not converge on exact first-DM Event: holder={incoming:?}, sender={outgoing:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    ensure!(
        inkson::account_data::hides_contact_request(
            &holder_host.state_store().client_blocklist(),
            &sender.actor
        ),
        "holder default Contact view lost private block after accepted peer relay"
    );
    let mut replays = Vec::new();
    for blocked in [true, false] {
        if !blocked {
            unblock_direct_peer(&holder).await?;
            catch_up_blocklist_revision(&holder_host, read_row(&holder.client).await?.revision)
                .await?;
        }
        let started = std::time::Instant::now();
        let response = sender
            .client
            .post("/_arkret/self/contacts/request")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(commit_bytes.clone())
            .send()
            .await?;
        let status = response.status();
        let protocol = format!("{:?}", response.version());
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        ensure!(
            !response.headers().iter().any(|(_, value)| value
                .to_str()
                .is_ok_and(|value| value.contains("blocked_by_user"))),
            "Contact peer replay disclosed a private block in response headers"
        );
        let body = response.bytes().await?;
        let elapsed = started.elapsed();
        ensure!(
            status == StatusCode::OK && !String::from_utf8_lossy(&body).contains("blocked_by_user"),
            "Contact peer replay changed sender-visible result at blocked={blocked}: {status} {}",
            String::from_utf8_lossy(&body)
        );
        let outcome: ContactOperationOutcome = serde_json::from_slice(&body)?;
        ensure!(
            matches!(
                outcome,
                ContactOperationOutcome::Accepted {
                    outcome: ContactAcceptedOutcome::Request { .. }
                }
            ),
            "Contact peer exact Commit replay changed its accepted branch"
        );
        replays.push((
            status,
            protocol,
            content_type,
            json_shape(&serde_json::from_slice::<Value>(&body)?),
            elapsed,
            body.to_vec(),
        ));
    }
    ensure!(
        replays[0].0 == replays[1].0
            && replays[0].1 == replays[1].1
            && replays[0].2 == replays[1].2
            && replays[0].3 == replays[1].3
            && replays[0].5 == replays[1].5,
        "holder-private block changed the Contact peer replay response envelope"
    );
    ensure!(
        !inkson::account_data::hides_contact_request(
            &holder_host.state_store().client_blocklist(),
            &sender.actor
        ),
        "cross-Station unblock did not restore the retained first-DM request"
    );
    ensure!(
        holder
            .client
            .sdk()
            .contacts_list()
            .await?
            .contacts
            .iter()
            .any(|row| row.peer.contact_actor_id() == sender.actor
                && row.state == ContactState::PendingIncoming
                && row.request_event_ref.as_ref() == Some(&event_ref)),
        "private unblock changed the peer-relayed Contact Event"
    );
    ensure!(
        persisted_snapshot(&sender_database.connect_url).await?.2 == 0,
        "private unblock revision appeared in the Contact sender Station"
    );
    eprintln!(
        "blocklist first-DM Contact peer relay: exact_event={}, initial_status={}, initial_ns={}, replay_status={}, replay_protocol={}, response_shape={}, blocked_replay_ns={}, unblocked_replay_ns={}; durations are regression observations",
        event_ref,
        initial_status,
        initial_elapsed.as_nanos(),
        replays[0].0,
        replays[0].1,
        replays[0].3,
        replays[0].4.as_nanos(),
        replays[1].4.as_nanos()
    );
    Ok(())
}

/// Observe a retained, accepted DM Message through the real Native receipt rail.
/// The holder's private block revision is installed before `message_id` commits.
#[expect(
    clippy::too_many_arguments,
    reason = "Receipt observation binds both MLS endpoints and the accepted message context"
)]
pub(crate) async fn observe_dm_retained_receipt(
    sender: &crate::scenarios::mls_lifecycle_live::Member,
    holder: &crate::scenarios::mls_lifecycle_live::Member,
    realm: &arkret_wire::RealmId,
    strand: &str,
    accepted_group: &arkret_wire::EventId,
    sender_group: &arkret::ArkretMlsGroup,
    holder_group: &arkret::ArkretMlsGroup,
    message_id: &arkret_wire::EventId,
    latest_cursor: &arkret_wire::EventId,
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let sender_host = native_signal_endpoint(
        sender,
        realm,
        accepted_group,
        sender_group,
        &directory.path().join("dm-receipt-sender.json"),
    )
    .await
    .context("DM sender Native endpoint")?;
    let holder_host = native_signal_endpoint(
        holder,
        realm,
        accepted_group,
        holder_group,
        &directory.path().join("dm-receipt-holder.json"),
    )
    .await
    .context("DM holder Native endpoint")?;
    catch_up_blocklist_revision(&holder_host, read_row(&holder.client).await?.revision).await?;
    ensure!(
        inkson::account_data::blocks_call_invite(
            &holder_host.state_store().client_blocklist(),
            &sender.actor,
        ),
        "DM holder Native projection omitted the accepted private block"
    );
    ensure!(
        inkson::conformance::retained_blocklist_message_projection(&holder_host.state_store())
            .iter()
            .any(|(id, _, hidden)| id.as_str() == message_id.as_str() && *hidden),
        "blocked DM ciphertext was not retained and hidden"
    );
    let blocked_candidate = inkson::conformance::retained_blocklist_receipt_candidate(
        &holder_host.state_store(),
        realm.as_str(),
        strand,
    );
    ensure!(
        blocked_candidate.as_deref() == Some(latest_cursor.as_str())
            && blocked_candidate.as_deref() != Some(message_id.as_str()),
        "blocked DM ciphertext displaced the acknowledged prior visible cursor: candidate={blocked_candidate:?}, prior={latest_cursor}, blocked={message_id}"
    );
    ensure!(
        inkson::conformance::send_native_automatic_read_receipt(
            &holder_host,
            holder.client.sdk(),
            realm.as_str(),
            strand,
            latest_cursor.as_str(),
        )
        .await?
        .is_none(),
        "blocked DM ciphertext emitted an automatic receipt"
    );

    let row = read_row(&holder.client).await?;
    let request = write_value_request(
        &holder.client,
        &holder.actor,
        row.revision,
        json!({"entries": []}),
    )
    .await?;
    expect_json(holder.client.put(PATH).json(&request), StatusCode::OK).await?;
    holder_host
        .catch_up_selected_realm_until_complete(realm)
        .await
        .context("DM selected Realm catch-up after private unblock")?;
    catch_up_blocklist_revision(&holder_host, read_row(&holder.client).await?.revision).await?;
    ensure!(
        holder_host.state_store().client_blocklist().is_empty(),
        "DM holder did not consume its private unblock delta"
    );
    ensure!(
        inkson::conformance::retained_blocklist_receipt_candidate(
            &holder_host.state_store(),
            realm.as_str(),
            strand,
        )
        .as_deref()
            == Some(message_id.as_str()),
        "unblocked retained DM Message was not the exact receipt candidate"
    );
    ensure!(
        inkson::conformance::retained_blocklist_message_projection(&holder_host.state_store())
            .iter()
            .any(|(id, _, hidden)| id.as_str() == message_id.as_str() && !*hidden),
        "unblock did not restore the exact retained DM Message to the holder view"
    );
    holder_host
        .state_store_handle()
        .write(|store| store.set_read_receipt_default_send(true));
    let mut stream = sender.client.sdk().signal_subscribe_frames().await?;
    let _signer = ActiveEndpointSigner::install(holder)?;
    let outcome = inkson::conformance::send_native_automatic_read_receipt(
        &holder_host,
        holder.client.sdk(),
        realm.as_str(),
        strand,
        latest_cursor.as_str(),
    )
    .await
    .context("unblocked DM automatic ReadReceipt submission")?
    .context("visible retained DM Message did not emit a receipt")?;
    ensure!(outcome.accepted && outcome.realm_id == *realm);
    let received = next_admitted_signal(
        &mut stream,
        &sender_host,
        sender,
        &mut garth::signal::SignalReceiver::new(),
    )
    .await?;
    let garth::signal::SignalReceiveOutcome::Accepted { plaintext, .. } = received else {
        bail!("DM receipt failed sender MLS admission: {received:?}");
    };
    let arkret::SignalPlaintext::ReadReceipt(read) = plaintext else {
        bail!("non receipt Signal reached DM receipt subscriber");
    };
    ensure!(
        read.event_id == *message_id && read.actor_id == holder.actor,
        "DM automatic receipt did not bind the exact retained Message and holder"
    );
    Ok(())
}

async fn ingest_retained_realm(
    holder: &TestActorClient,
    host: &inkson::sync_engine::NativeAccountHost,
    realm: &arkret_wire::RealmId,
) -> Result<()> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let http = holder.sdk();
    let authority = garth::AuthorityClient::new(http.clone());
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut required_position = None;
    loop {
        // A stream can advance after the signed bundle was issued. Garth
        // correctly refuses that scan; obtain a fresh nonce-bound authority
        // instead of weakening its exact-head check or installing any pages
        // from the failed attempt.
        let nonce = arkret_wire::Base64UrlString::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(
                format!(
                    "{realm}:{}",
                    chrono::Utc::now()
                        .timestamp_nanos_opt()
                        .context("nonce clock")?
                )
                .as_bytes(),
            )),
        )
        .map_err(anyhow::Error::msg)?;
        let request = arkret_wire::AuthorityBundleRequest {
            realm_id: realm.clone(),
            nonce: nonce.clone(),
        };
        let bundle = authority.resolve_authority(&request).await?;
        if required_position
            .is_some_and(|position| bundle.realm_stream_head.stream_position < position)
        {
            ensure!(
                std::time::Instant::now() < deadline,
                "verified authority did not reach the scanned Realm Commit position {required_position:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }
        let freshness = arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), nonce);
        let keys =
            garth::fetch_historical_station_key_directory(&http, &bundle, None, None).await?;
        let mut replica = garth::RealmReplica::new(realm.clone());
        replica.install_verified_authority(&request, bundle.clone(), &freshness, &keys)?;
        let mut verified_pages = Vec::new();
        let mut after = None;
        let mut newer_cut_required = false;
        loop {
            let scan = arkret_wire::StreamScanRequest {
                realm_id: realm.clone(),
                stream_ref: stream.clone(),
                direction: arkret_wire::StreamScanDirection::After(after),
                limit: 64,
            };
            let page = authority.scan(&scan).await?;
            let truncated = page.truncated;
            let observed_position = page
                .committed_events
                .last()
                .map(|view| view.commit().stream_position);
            let keys =
                garth::fetch_historical_station_key_directory(&http, &bundle, Some(&page), None)
                    .await?;
            match replica.apply_verified_scan(&scan, page, &freshness, &keys) {
                Ok(verified) => verified_pages.push(verified),
                Err(garth::Error::AuthorityCutBehind) => {
                    required_position =
                        observed_position.into_iter().chain(required_position).max();
                    newer_cut_required = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
            after = Some(
                replica
                    .verified_head(&stream)
                    .context("verified DM head")?
                    .stream_position,
            );
            if !truncated {
                break;
            }
        }
        if newer_cut_required {
            ensure!(
                std::time::Instant::now() < deadline,
                "verified authority did not advance before the bounded catch-up deadline"
            );
            continue;
        }
        ensure!(
            replica.verified_head(&stream) == Some(&bundle.realm_stream_head),
            "private block stopped the real DM Commit cursor"
        );
        for verified in &verified_pages {
            host.state_store_handle()
                .write(|store| store.ingest_verified_message_history(verified))
                .map_err(anyhow::Error::msg)?;
        }
        return Ok(());
    }
}

async fn write_request(
    holder: &TestActorClient,
    owner: &ActorId,
    expected: u64,
    handle: &str,
) -> Result<AccountDataReplaceRequestBody> {
    write_value_request(holder, owner, expected, blocklist(handle)?).await
}

async fn write_value_request(
    holder: &TestActorClient,
    owner: &ActorId,
    expected: u64,
    value: Value,
) -> Result<AccountDataReplaceRequestBody> {
    let typed: AccountBlocklistValue = serde_json::from_value(value)?;
    typed.validate()?;
    let body = arkret_crypto::account_data_crypto::seal_account_data_value(
        &SECRET,
        owner,
        BLOCKLIST_KEY,
        &serde_json::to_value(typed)?,
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
    Ok(AccountDataReplaceRequestBody {
        set_event: arkret_wire::EventAdmissionSubmission::new(set_event),
    })
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

async fn all_event_ledger_snapshot(url: &str) -> Result<(String, String)> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<(String, String)> {
        let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
        let shared = connection.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id), '[]'::jsonb)::text FROM canonical_events e", &[])?.get(0);
        let private = connection.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY event_id), '[]'::jsonb)::text FROM actor_private_events e", &[])?.get(0);
        Ok((shared, private))
    }).await?
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
        let id = required_str(point, "id")?;
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

// An actual endpoint's live provider is transferred through the production
// encrypted restart checkpoint, never replaced by a fabricated MLS model.
async fn native_signal_endpoint(
    member: &crate::scenarios::mls_lifecycle_live::Member,
    realm: &arkret_wire::RealmId,
    accepted_group: &arkret_wire::EventId,
    group: &arkret::ArkretMlsGroup,
    path: &std::path::Path,
) -> Result<inkson::sync_engine::NativeAccountHost> {
    use base64::Engine as _;
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SECRET);
    inkson::mls::runtime::store_account_mls_secret(
        inkson::secure_key_store::default_secure_key_store("inkson").as_ref(),
        &member.account,
        &secret,
    )?;
    let host = inkson::sync_engine::NativeAccountHost::new_for_realm(
        member.client.sdk(),
        member.account.clone(),
        member.device.clone(),
        inkson::LocalStateStore::with_path(path),
        realm.clone(),
    )
    .await?;
    let record = group.export_state_record()?;
    let accepted = member
        .client
        .sdk()
        .committed_event_get(accepted_group)
        .await?;
    ensure!(accepted.commit().event_ref == *accepted_group);
    let mut checkpoint = inkson::mls::persistence::encrypt_state(
        realm.as_str(),
        record.group_id.as_str(),
        record.epoch,
        &serde_json::to_vec(&record)?,
        &secret,
        &[44; 16],
    );
    checkpoint.group_state_event_id = Some(accepted_group.clone());
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    host.state_store_handle()
        .write(|store| store.save_mls_checkpoint_for_scope(&scope, checkpoint))
        .map_err(anyhow::Error::msg)?;
    host.catch_up_selected_realm_until_complete(realm)
        .await
        .context("Native selected Realm catch-up after accepted MLS checkpoint")?;
    ingest_retained_realm(&member.client, &host, realm).await?;
    let installed_ref = host
        .state_store()
        .mls_group_state_ref_for_scope(&scope, record.group_id.as_str(), record.epoch)
        .map_err(anyhow::Error::msg)
        .context("Native checkpoint lost its accepted MLS group-state reference after ingest")?;
    ensure!(
        installed_ref == *accepted_group,
        "Native checkpoint installed another accepted MLS group-state Event"
    );
    Ok(host)
}

async fn catch_up_blocklist_revision(
    host: &inkson::sync_engine::NativeAccountHost,
    expected_revision: u64,
) -> Result<()> {
    for _ in 0..8 {
        if host.state_store().client_blocklist_revision() >= expected_revision {
            return Ok(());
        }
        tokio::time::timeout(std::time::Duration::from_secs(20), host.catch_up())
            .await
            .context("private blocklist catch-up timed out")??;
    }
    bail!(
        "private blocklist revision stayed at {} below server revision {expected_revision}",
        host.state_store().client_blocklist_revision()
    )
}

struct ActiveEndpointSigner {
    previous: Option<std::sync::Arc<inkson::event_signer::InksonEventSigner>>,
    mode: inkson::operation::ProofMode,
}
impl ActiveEndpointSigner {
    fn install(member: &crate::scenarios::mls_lifecycle_live::Member) -> Result<Self> {
        let principal = member
            .client
            .principal
            .as_ref()
            .context("actual signing principal")?;
        let signer = inkson::event_signer::build_ed25519_device_signer(
            member.key.to_bytes(),
            principal.did.as_str(),
            member.device.as_str(),
        );
        let mode = inkson::operation::current_proof_mode();
        let previous =
            inkson::event_signer::replace_active_signer(Some(std::sync::Arc::new(signer)));
        inkson::operation::set_proof_mode(inkson::operation::ProofMode::RealEd25519);
        Ok(Self { previous, mode })
    }
}
impl Drop for ActiveEndpointSigner {
    fn drop(&mut self) {
        inkson::event_signer::replace_active_signer(self.previous.take());
        inkson::operation::set_proof_mode(self.mode);
    }
}

async fn next_admitted_signal(
    stream: &mut arkret_http_client::SignalSubscribeFrameStream,
    host: &inkson::sync_engine::NativeAccountHost,
    member: &crate::scenarios::mls_lifecycle_live::Member,
    receiver: &mut garth::signal::SignalReceiver,
) -> Result<garth::signal::SignalReceiveOutcome> {
    let decryptor = inkson::signal_receive_engine::MlsSignalDecryptor::new(
        host.state_store_handle(),
        member.account.clone(),
        member.device.clone(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match stream
                .next_frame()
                .await?
                .context("live Signal rail ended")?
            {
                arkret_wire::SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } => {
                    return Ok(receiver
                        .receive(
                            &envelope,
                            &delivery_authority,
                            &decryptor,
                            chrono::Utc::now(),
                        )
                        .await?);
                }
                arkret_wire::SignalStreamFrame::Heartbeat => {}
                terminal => bail!("Signal rail terminated before actual delivery: {terminal:?}"),
            }
        }
    })
    .await
    .context("actual Signal delivery observation timed out; no latency claim")?
}

/// Actual ordinary Realm MLS is necessary: the DM participant profile has no
/// CallCreate action and may not gain one for a test.
async fn authored_encrypted_blocklist_message(
    sender: &crate::scenarios::mls_lifecycle_live::Member,
    realm: &arkret_wire::RealmId,
    strand: &str,
    accepted_group: &arkret_wire::EventId,
    sender_group: &mut arkret::ArkretMlsGroup,
) -> Result<arkret_wire::Event> {
    let body = arkret_canonical::canonical_json_bytes(&arkret::ContentBlock::text(
        "retained MLS message",
    ))?;
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        arkret_wire::EventKind::MessageCreate.as_str(),
        sender_group.epoch(),
        accepted_group.clone(),
        sender_group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let sealed = arkret::MessageCrypto::encrypt(
        sender_group,
        crate::scenarios::mls_lifecycle_live::fresh_uuid_v7(),
        header,
        &body,
    )?;
    let payload: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
        serde_json::from_value(json!({
            "strand_id": strand,
            "track_name": "discussion",
            "encrypted_content": sealed.payload.to_envelope()?,
        }))?;
    sender
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::MessageCreate.as_str(),
            serde_json::to_value(payload)?,
        )
        .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Call observation binds both MLS endpoints and the accepted call context"
)]
pub(crate) async fn observe_ordinary_call_invite(
    sender: &crate::scenarios::mls_lifecycle_live::Member,
    holder: &crate::scenarios::mls_lifecycle_live::Member,
    station: &ArkretServer,
    realm: &arkret_wire::RealmId,
    accepted_group: &arkret_wire::EventId,
    sender_group: &mut arkret::ArkretMlsGroup,
    holder_group: &arkret::ArkretMlsGroup,
    observe_receipt: bool,
) -> Result<()> {
    use arkret_models_collaboration::events_payloads::call::{
        CallCreatePayload, CallLifecycleState,
    };

    use crate::scenarios::human_device_producer_live::{
        grant_realm_actions, submit_and_expect_commit,
    };
    let actions = if observe_receipt {
        vec!["ak.message.create"]
    } else {
        vec!["ak.call.join", "ak.call.signal.send"]
    };
    let grant = grant_realm_actions(
        &sender.client,
        station,
        realm.as_str(),
        &sender.account,
        &actions,
    )
    .await?;
    let (call_id, call_commit) = if observe_receipt {
        (None, None)
    } else {
        let payload = CallCreatePayload {
            initial_state: CallLifecycleState::Ringing,
        };
        payload.validate().map_err(anyhow::Error::msg)?;
        let create = sender
            .client
            .author_event(
                realm.as_str(),
                arkret_wire::EventKind::CallCreate.as_str(),
                serde_json::to_value(payload)?,
            )
            .await?;
        let commit = submit_and_expect_commit(
            &sender.client,
            &sender.account,
            sender.device.as_str(),
            &create,
        )
        .await?;
        ensure!(
            commit.event_ref == create.event_id && grant.stream_position < commit.stream_position,
            "Call create was not accepted after its actual grant"
        );
        (
            Some(arkret_wire::CallId::from_event_id(&create.event_id)),
            Some(commit),
        )
    };
    block_direct_peer(holder, sender).await?;
    let receipt_message = if observe_receipt {
        let strand = sender.client.default_strand_id(realm.as_str())?;
        let message = authored_encrypted_blocklist_message(
            sender,
            realm,
            &strand,
            accepted_group,
            sender_group,
        )
        .await?;
        let blocked_sender =
            observed_authored_shared_message(&sender.client, message.clone()).await?;
        Some((strand, message.event_id, blocked_sender))
    } else {
        None
    };
    let directory = tempfile::tempdir()?;
    let sender_host = native_signal_endpoint(
        sender,
        realm,
        accepted_group,
        sender_group,
        &directory.path().join("call-sender.json"),
    )
    .await
    .context("sender Native Signal endpoint initialization")?;
    let holder_host = native_signal_endpoint(
        holder,
        realm,
        accepted_group,
        holder_group,
        &directory.path().join("call-recipient.json"),
    )
    .await
    .context("holder Native Signal endpoint initialization")?;
    let blocked_revision = read_row(&holder.client).await?.revision;
    catch_up_blocklist_revision(&holder_host, blocked_revision).await?;
    ensure!(
        inkson::account_data::blocks_call_invite(
            &holder_host.state_store().client_blocklist(),
            &sender.actor,
        ),
        "accepted private block revision did not block the exact Call sender"
    );
    if let Some((strand, message_id, _)) = &receipt_message {
        ensure!(
            inkson::conformance::retained_blocklist_message_projection(&holder_host.state_store())
                .iter()
                .any(|(id, _, hidden)| id.as_str() == message_id.as_str() && *hidden),
            "the blocked encrypted Message was not retained before receipt suppression"
        );
        ensure!(
            inkson::conformance::retained_blocklist_receipt_candidate(
                &holder_host.state_store(),
                realm.as_str(),
                strand,
            )
            .is_none(),
            "blocked encrypted Message became an automatic receipt candidate"
        );
        ensure!(
            inkson::conformance::send_native_automatic_read_receipt(
                &holder_host,
                holder.client.sdk(),
                realm.as_str(),
                strand,
                "",
            )
            .await?
            .is_none(),
            "blocked encrypted Message emitted an automatic read receipt"
        );
    }
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let mut receiver = garth::signal::SignalReceiver::new();
    let mut observed = Vec::new();
    for (seq, blocked) in [(1, true), (2, false)] {
        if !blocked {
            let row = read_row(&holder.client).await?;
            let request = write_value_request(
                &holder.client,
                &holder.actor,
                row.revision,
                json!({"entries":[]}),
            )
            .await?;
            expect_json(holder.client.put(PATH).json(&request), StatusCode::OK).await?;
            holder_host
                .catch_up_selected_realm_until_complete(realm)
                .await
                .context("selected Realm catch-up after private unblock")?;
            catch_up_blocklist_revision(&holder_host, read_row(&holder.client).await?.revision)
                .await?;
            ensure!(
                holder_host.state_store().client_blocklist().is_empty(),
                "actual unblock delta was not consumed"
            );
            if let Some((strand, message_id, blocked_sender)) = &receipt_message {
                ensure!(
                    inkson::conformance::retained_blocklist_receipt_candidate(
                        &holder_host.state_store(),
                        realm.as_str(),
                        strand,
                    )
                    .as_deref()
                        == Some(message_id.as_str()),
                    "unblock did not restore the retained encrypted Message receipt candidate"
                );
                holder_host
                    .state_store_handle()
                    .write(|store| store.set_read_receipt_default_send(true));
                let current_store = holder_host.state_store();
                let restored = inkson::signal::restore_signal_mls_session(
                    &current_store,
                    inkson::secure_key_store::default_secure_key_store("inkson").as_ref(),
                    &scope,
                    &holder.account,
                    &holder.device,
                    holder_group.epoch(),
                )
                .context("restore holder MLS session before automatic receipt")?;
                let restored_ref = current_store
                    .mls_group_state_ref_for_scope(
                        &scope,
                        &restored.group.group_id(),
                        restored.group.epoch(),
                    )
                    .map_err(anyhow::Error::msg)
                    .with_context(|| {
                        format!(
                            "restored holder MLS group lacks exact accepted Event reference: restored_group={}, restored_epoch={}, checkpoint_group={}, checkpoint_epoch={}",
                            restored.group.group_id(),
                            restored.group.epoch(),
                            restored.snapshot.group_id,
                            restored.snapshot.epoch,
                        )
                    })?;
                ensure!(
                    restored_ref == *accepted_group,
                    "restored holder MLS group refers to another accepted Event"
                );
                let mut receipt_stream = sender.client.sdk().signal_subscribe_frames().await?;
                let _receipt_signer = ActiveEndpointSigner::install(holder)?;
                let receipt = inkson::conformance::send_native_automatic_read_receipt(
                    &holder_host,
                    holder.client.sdk(),
                    realm.as_str(),
                    strand,
                    "",
                )
                .await
                .context("unblocked Native automatic ReadReceipt submission")?
                .context("visible retained Message did not emit an automatic receipt")?;
                ensure!(receipt.accepted && receipt.realm_id == *realm);
                let mut receipt_receiver = garth::signal::SignalReceiver::new();
                let received = next_admitted_signal(
                    &mut receipt_stream,
                    &sender_host,
                    sender,
                    &mut receipt_receiver,
                )
                .await?;
                let garth::signal::SignalReceiveOutcome::Accepted { plaintext, .. } = received
                else {
                    bail!("automatic receipt was not admitted by the real sender: {received:?}");
                };
                let arkret::SignalPlaintext::ReadReceipt(read) = plaintext else {
                    bail!("another Signal profile reached the automatic receipt subscriber");
                };
                ensure!(
                    read.event_id == *message_id && read.actor_id == holder.actor,
                    "automatic receipt did not bind the visible retained Message and exact holder"
                );
                let unblocked_message = authored_encrypted_blocklist_message(
                    sender,
                    realm,
                    strand,
                    accepted_group,
                    sender_group,
                )
                .await?;
                let unblocked_sender =
                    observed_authored_shared_message(&sender.client, unblocked_message).await?;
                compare_shared_sender_observations(blocked_sender, &unblocked_sender)?;
                eprintln!(
                    "blocklist paired encrypted Message submissions and automatic receipt: blocked=None, unblocked=accepted, sender MLS receiver admitted exact event {}",
                    message_id,
                );
            }
        }
        if observe_receipt {
            if blocked {
                continue;
            }
            return Ok(());
        }
        let call_id = call_id
            .clone()
            .context("CallInvite fixture lacks accepted CallCreate")?;
        let payload = inkson::signal::SignalPayload::CallSignal {
            call_id: call_id.clone(),
            seq,
            signal: arkret::CallSignalData::Invite(arkret::CallInviteSignalData {
                lifetime_ms: 30_000,
                offer: arkret::SessionDescription {
                    sdp_type: arkret::SessionDescriptionType::Offer,
                    sdp: "v=0".to_owned(),
                },
                media: arkret::CallMediaSelection {
                    audio: true,
                    video: false,
                    screen: None,
                },
            }),
        };
        let mut stream = holder.client.sdk().signal_subscribe_frames().await?;
        let _signer = ActiveEndpointSigner::install(sender)?;
        let material = inkson::signal::key_material_for_scope(
            &sender_host.state_store(),
            realm.as_str(),
            None,
        )
        .context("sender Native key material after accepted MLS checkpoint")?;
        let (outcome, transport) = sender_host
            .send_scope_signal_with_transport_observation(scope.clone(), &material, &payload)
            .await
            .context("CallInvite send after holder blocklist projection")?;
        ensure!(
            outcome.accepted && outcome.realm_id == *realm,
            "real CallInvite was not accepted: {outcome:?}"
        );
        let received =
            next_admitted_signal(&mut stream, &holder_host, holder, &mut receiver).await?;
        let garth::signal::SignalReceiveOutcome::Accepted {
            domain, plaintext, ..
        } = &received
        else {
            bail!("real CallInvite failed producer/MLS admission: {received:?}");
        };
        ensure!(
            domain.sender_actor_id == sender.actor && domain.scope_ref == scope,
            "actual Call sender or scope changed"
        );
        let arkret::SignalPlaintext::CallSignal(call) = plaintext else {
            bail!("another sealed profile reached the Call consumer");
        };
        ensure!(
            call.call_id == call_id && call.seq == seq,
            "Call plaintext did not name the accepted create-derived identity"
        );
        let dispatch =
            inkson::conformance::observe_native_call_projection(&holder_host, received).await?;
        ensure!(
            dispatch == usize::from(!blocked),
            "private block/unblock did not govern the actual accepted Call product: blocked={blocked}, dispatch={dispatch}, entries={}, matches_sender={}",
            holder_host.state_store().client_blocklist().len(),
            inkson::account_data::blocks_call_invite(
                &holder_host.state_store().client_blocklist(),
                &sender.actor,
            )
        );
        observed.push((outcome, transport));
    }
    ensure!(
        observed[0].0.accepted == observed[1].0.accepted
            && observed[0].0.realm_id == observed[1].0.realm_id
            && observed[0].0.dispatched_recipient_count == observed[1].0.dispatched_recipient_count
            && observed[0].1.status == 200
            && observed[0].1.status == observed[1].1.status
            && observed[0].1.http_version == observed[1].1.http_version
            && observed[0].1.content_type == observed[1].1.content_type
            && json_shape(&serde_json::to_value(&observed[0].0)?)
                == json_shape(&serde_json::to_value(&observed[1].0)?),
        "private block leaked through typed public response eligibility"
    );
    eprintln!(
        "blocklist CallInvite paired Signal HTTP transport: scope={}, sender={}, protocol={}, status={}, content_type={}, blocked_start_to_full_response_ns={}, unblocked_start_to_full_response_ns={}, public_response_shape={}, accepted={}, recipient_count={:?}; durations are regression observations without a pass threshold",
        realm,
        sender.actor,
        observed[0].1.http_version,
        observed[0].1.status,
        observed[0].1.content_type,
        observed[0].1.start_to_full_response.as_nanos(),
        observed[1].1.start_to_full_response.as_nanos(),
        json_shape(&serde_json::to_value(&observed[0].0)?),
        observed[0].0.accepted,
        observed[0].0.dispatched_recipient_count,
    );
    // A held historical joined cut cannot authorize a sender that has left
    // before the next source ingress. Bind the fresh encrypted attempt to the
    // actual earlier CallCreate Commit and keep the verified Native cut held.
    // The server must re-observe current membership despite that valid old basis.
    let leave=holder.client.author_event(
        realm.as_str(),arkret_wire::EventKind::MemberState.as_str(),
        crate::scenarios::human_device_producer_live::membership_payload(
            realm.as_str(),holder.account.clone(),
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave,
            "Signal current membership refusal",
        )?,
    ).await?;
    submit_and_expect_commit(
        &holder.client,
        &holder.account,
        holder.device.as_str(),
        &leave,
    )
    .await?;
    let call_id = call_id.context("held-cut fixture lacks accepted CallCreate")?;
    let commit = call_commit.context("held-cut fixture lacks accepted CallCreate Commit")?;
    let material =
        inkson::signal::key_material_for_scope(&holder_host.state_store(), realm.as_str(), None)?;
    let payload = inkson::signal::SignalPayload::CallSignal {
        call_id,
        seq: 3,
        signal: arkret::CallSignalData::Invite(arkret::CallInviteSignalData {
            lifetime_ms: 30_000,
            offer: arkret::SessionDescription {
                sdp_type: arkret::SessionDescriptionType::Offer,
                sdp: "v=0".to_owned(),
            },
            media: arkret::CallMediaSelection {
                audio: true,
                video: false,
                screen: None,
            },
        }),
    };
    let _signer = ActiveEndpointSigner::install(holder)?;
    let header = inkson::signal::SignalHeader::new(
        scope,
        holder.actor.clone(),
        holder.device.clone(),
        commit.commit_id.clone(),
        None,
        payload.signal_class(),
        chrono::Utc::now(),
    );
    let denied = inkson::event_submit::EventSubmitter::new(holder.client.sdk())
        .send_signal(
            &holder.account,
            header,
            &material,
            &payload,
            &holder_host.state_store_handle(),
        )
        .await
        .unwrap_err();
    ensure!(
        denied.to_string().contains("signal_class_denied"),
        "held joined cut was not refused by the registered current membership gate: {denied:#}"
    );
    eprintln!(
        "blocklist actual accepted ordinary CallCreate + sealed CallInvite: real producer/MLS/sequence receiver, private product 0->1, unchanged public response shape; Contact and first-DM production observations run in their separately named live case"
    );
    Ok(())
}
