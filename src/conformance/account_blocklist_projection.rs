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
const MISSING_CASES: [&str; 2] = [
    "shared_history_is_received_then_filtered_by_the_holder",
    "holder_side_request_filtering_stays_indistinguishable",
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
        "unregistered_blocklist_event_kind_is_not_an_authoring_surface",
        "unblock_rebuilds_the_projection_from_retained_material",
        "an_unsynced_device_treats_freshness_as_unknown",
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

    private_account_catchup(&holder, &owner).await?;
    retained_shared_history(&server, &holder, &owner).await?;
    crate::scenarios::direct_conversation_founding_live::blocklist_retained_direct_conversation()
        .await?;

    Ok(super::SuiteExecutionResult {
        entrypoint: ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT,
        fixture: FIXTURE,
        cases: [(0, 3), (1, 12), (2, 8), (3, 3), (5, 4), (7, 3)]
            .into_iter()
            .map(|(index, assertions)| super::CaseExecutionResult {
                case_id: required_str(&cases[index], "name").unwrap().to_owned(),
                assertions,
            })
            .collect(),
    })
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

/// A real sender observation; elapsed transport time is regression evidence,
/// not an invented timing bucket or a proof of statistical indistinguishability.
struct SharedSubmissionObservation {
    status: StatusCode,
    content_type: String,
    outcome: arkret_wire::AuthoritySubmitOutcome,
    elapsed: std::time::Duration,
}

async fn observed_shared_message(
    peer: &TestActorClient,
    realm: &str,
    strand: &str,
    text: &str,
) -> Result<SharedSubmissionObservation> {
    use arkret_models_collaboration::authority_commit::{
        SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
    };
    let event = peer
        .author_event(
            realm,
            "ak.message.create",
            crate::harness::message_create_text_payload(strand, text)?,
        )
        .await?;
    let request = SelfAuthoritySubmitRequest::Event(crate::publication::initial_submission(
        event.clone(),
        "",
    )?);
    let started = std::time::Instant::now();
    let response = peer
        .post("/_arkret/self/events")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(&request)?)
        .send()
        .await?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .context("accepted sender response lacks Content-Type")?
        .to_str()?
        .to_owned();
    ensure!(
        !response.headers().iter().any(|(_, value)| value
            .to_str()
            .is_ok_and(|value| value.contains("blocked_by_user"))),
        "private block leaked through a response header"
    );
    let bytes = response.bytes().await?;
    let elapsed = started.elapsed();
    ensure!(
        status == StatusCode::OK,
        "shared Message submission failed: {}",
        String::from_utf8_lossy(&bytes)
    );
    ensure!(
        !String::from_utf8_lossy(&bytes).contains("blocked_by_user"),
        "private block leaked through the sender result"
    );
    let outcome: SelfAuthoritySubmitOutcome = serde_json::from_slice(&bytes)?;
    outcome.validate_for_request(&request)?;
    let SelfAuthoritySubmitOutcome::Ordinary(outcome) = outcome else {
        bail!("shared Message returned an unrelated authoring branch");
    };
    let arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: accepted_status,
        commit,
    } = &outcome
    else {
        bail!("shared Message was rejected: {outcome:?}");
    };
    ensure!(
        *accepted_status == arkret_wire::AuthorityCommitStatus::Committed,
        "fresh shared Message did not commit"
    );
    arkret_wire::CommittedEventFullView {
        event,
        commit: commit.clone(),
    }
    .validate_shape()?;
    Ok(SharedSubmissionObservation {
        status,
        content_type,
        outcome,
        elapsed,
    })
}

fn compare_shared_sender_observations(
    blocked: &SharedSubmissionObservation,
    unblocked: &SharedSubmissionObservation,
) -> Result<()> {
    ensure!(
        blocked.status == unblocked.status && blocked.content_type == unblocked.content_type,
        "private block changed the sender's response shape"
    );
    let arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: blocked_status,
        commit: blocked_commit,
    } = &blocked.outcome
    else {
        bail!("blocked peer was not accepted");
    };
    let arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: unblocked_status,
        commit: unblocked_commit,
    } = &unblocked.outcome
    else {
        bail!("unblocked peer was not accepted");
    };
    ensure!(
        blocked_status == unblocked_status
            && blocked_commit.realm_id == unblocked_commit.realm_id
            && blocked_commit.stream_ref == unblocked_commit.stream_ref
            && blocked_commit.governance_generation == unblocked_commit.governance_generation,
        "private block changed the sender's accepted authority result"
    );
    ensure!(
        blocked_commit.event_ref != unblocked_commit.event_ref
            && blocked_commit.commit_id != unblocked_commit.commit_id,
        "distinct observations reused a fabricated acceptance"
    );
    eprintln!(
        "blocklist shared sender observations: both HTTP {} / committed / no reason; blocked transport {:?}, unblocked transport {:?}; full privacy oracle remains unwired",
        blocked.status, blocked.elapsed, unblocked.elapsed
    );
    Ok(())
}

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
    let strand = holder.create_default_strand(&realm).await?;
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
    let observer = holder.sdk().with_base_url(endpoint.parse()?)?;
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

/// Observe the actual Native automatic-receipt path with real accepted MLS
/// material. The receiver supplies no authority or Signal success: an
/// unblocked control must reach HTTP, a filtered message must not reach it.
async fn observe_retained_automatic_receipt(
    holder: &TestActorClient,
    host: &inkson::sync_engine::NativeAccountHost,
    realm: &str,
    strand: &str,
    expect_transport: bool,
) -> Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let store = host.state_store();
    ensure!(
        store.blocklist_freshness_known(),
        "receipt observation requires actual private catch-up"
    );
    inkson::signal::key_material_for_scope(&store, realm, None)
        .context("receipt observation requires the receiving endpoint's accepted MLS state")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/", listener.local_addr()?);
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let receiver = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let mut bytes = [0u8; 8192];
            if socket.read(&mut bytes).await.unwrap_or(0) > 0 {
                observed.fetch_add(1, Ordering::SeqCst);
                let _ = socket.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            }
        }
    });
    let http = holder.sdk().with_base_url(endpoint.parse()?)?;
    let result = inkson::conformance::send_native_automatic_read_receipt(
        host,
        http.clone(),
        realm,
        strand,
        "",
    )
    .await;
    let count = requests.load(Ordering::SeqCst);
    if expect_transport {
        ensure!(
            result.is_err() && count > 0,
            "eligible unblocked automatic receipt did not reach the actual transport: {result:?}, requests={count}"
        );
    } else {
        ensure!(
            matches!(result, Ok(None)) && count == 0,
            "filtered automatic receipt reached the actual transport: {result:?}, requests={count}"
        );
        ensure!(
            http.describe().await.is_err() && requests.load(Ordering::SeqCst) > 0,
            "receipt network observer lacks an actual positive control"
        );
    }
    receiver.abort();
    eprintln!(
        "blocklist Native MLS automatic receipt: expected transport={expect_transport}, observed requests={count}; observer refuses authority, no Signal delivery claimed"
    );
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

pub(crate) async fn retained_direct_history(
    holder: &crate::scenarios::mls_lifecycle_live::Member,
    peer: &crate::scenarios::mls_lifecycle_live::Member,
    realm: &arkret_wire::RealmId,
    strand: &arkret_wire::StrandId,
    accepted_group: &arkret_wire::EventId,
    message: &arkret_wire::EventId,
    group: &arkret::ArkretMlsGroup,
    peer_group: &arkret::ArkretMlsGroup,
) -> Result<()> {
    use base64::Engine as _;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("retained-direct-history.json");
    let host = inkson::sync_engine::NativeAccountHost::new_for_realm(
        holder.client.sdk(),
        holder.account.clone(),
        holder.device.clone(),
        inkson::LocalStateStore::with_path(&path),
        realm.clone(),
    )
    .await?;
    host.catch_up_selected_realm_until_complete(realm).await?;
    let mut store = host.state_store();
    ensure!(store.blocklist_freshness_known());
    let blocking_revision = store.client_blocklist_revision();
    // Transfer this receiving endpoint's real live MLS provider through the
    // same encrypted checkpoint format used by native restart restoration.
    let record = group.export_state_record()?;
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SECRET);
    let mut checkpoint = inkson::mls::persistence::encrypt_state(
        realm.as_str(),
        record.group_id.as_str(),
        record.epoch,
        &serde_json::to_vec(&record)?,
        &secret,
        &[43; 16],
    );
    let accepted = holder
        .client
        .sdk()
        .committed_event_get(accepted_group)
        .await?;
    ensure!(
        accepted.commit().event_ref == *accepted_group,
        "MLS checkpoint lacks its accepted covering Commit"
    );
    checkpoint.group_state_event_id = Some(accepted_group.clone());
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    host.state_store_handle()
        .write(|store| store.save_mls_checkpoint_for_scope(&scope, checkpoint))
        .map_err(anyhow::Error::msg)?;
    ingest_retained_realm(&holder.client, &host, realm).await?;
    store = host.state_store();
    let actor = holder.actor.to_string();
    let projection = inkson::conformance::retained_blocklist_message_projection_for_account(
        &store,
        &holder.account,
        &actor,
        &holder.device,
    );
    ensure!(
        projection
            .iter()
            .any(|(id, body, hidden)| id == message.as_str() && body == "hello, Alice" && *hidden),
        "actual Native encrypted DM retention/decryption/filter failed"
    );
    observe_retained_automatic_receipt(
        &holder.client,
        &host,
        realm.as_str(),
        strand.as_str(),
        false,
    )
    .await?;
    let peer_host = native_signal_endpoint(
        peer,
        realm,
        accepted_group,
        peer_group,
        &directory.path().join("direct-peer.json"),
    )
    .await?;
    let raw = store.load().raw_operations;
    let write = write_value_request(
        &holder.client,
        &holder.actor,
        blocking_revision,
        json!({"entries":[]}),
    )
    .await?;
    expect_json(holder.client.put(PATH).json(&write), StatusCode::OK).await?;
    host.catch_up_selected_realm_until_complete(realm).await?;
    let store = host.state_store();
    ensure!(
        store.blocklist_freshness_known()
            && store.client_blocklist_revision() == blocking_revision + 1
    );
    let projection = inkson::conformance::retained_blocklist_message_projection_for_account(
        &store,
        &holder.account,
        &actor,
        &holder.device,
    );
    ensure!(
        projection
            .iter()
            .any(|(id, body, hidden)| id == message.as_str() && body == "hello, Alice" && !hidden),
        "unblock did not restore real encrypted DM retained material"
    );
    ensure!(
        store.load().raw_operations == raw,
        "DM unblock changed shared retained history"
    );
    observe_retained_automatic_receipt(
        &holder.client,
        &host,
        realm.as_str(),
        strand.as_str(),
        true,
    )
    .await?;
    observe_sealed_read_receipt(holder, &host, peer, &peer_host, realm, strand, message).await?;
    eprintln!(
        "blocklist unauthorized relay: Contact and first DM founding accepted with an already-held private block; legal CallInvite requires an accepted CallCreate writer; authorized service branch remains missing"
    );
    ensure!(
        peer.client
            .sdk()
            .committed_event_get(message)
            .await?
            .commit()
            .event_ref
            == *message,
        "private block changed the sender's accepted Message"
    );
    ensure!(strand.as_str() != "", "DM fixture lacks its actual Strand");
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
    let freshness = arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), nonce);
    let keys = garth::fetch_historical_station_key_directory(&http, &bundle, None, None).await?;
    let mut replica = garth::RealmReplica::new(realm.clone());
    replica.install_verified_authority(&request, bundle.clone(), &freshness, &keys)?;
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let mut after = None;
    loop {
        let scan = arkret_wire::StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(after),
            limit: 64,
        };
        let page = authority.scan(&scan).await?;
        let truncated = page.truncated;
        let keys = garth::fetch_historical_station_key_directory(&http, &bundle, Some(&page), None)
            .await?;
        let verified = replica.apply_verified_scan(&scan, page, &freshness, &keys)?;
        host.state_store_handle()
            .write(|store| store.ingest_verified_message_history(&verified))
            .map_err(anyhow::Error::msg)?;
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
    ensure!(
        replica.verified_head(&stream) == Some(&bundle.realm_stream_head),
        "private block stopped the real DM Commit cursor"
    );
    Ok(())
}

pub(crate) async fn tombstone_direct_peer(
    holder: &crate::scenarios::mls_lifecycle_live::Member,
    peer: &crate::scenarios::mls_lifecycle_live::Member,
) -> Result<()> {
    use arkret::contact_operations::{
        ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome,
        ContactPreparedOutcome,
    };
    let row = holder
        .client
        .sdk()
        .contacts_list()
        .await?
        .contacts
        .into_iter()
        .find(|row| row.peer.contact_actor_id() == peer.actor)
        .context("actual accepted DM Contact")?;
    let next = row
        .next_prepare_input
        .context("accepted Contact next prepare input")?;
    let operation_id = arkret::ProtocolOperationId::new(crate::harness::next_typed_id("operation"))
        .map_err(anyhow::Error::msg)?;
    let idempotency_key = arkret::IdempotencyKey::new(crate::harness::next_typed_id("idempotency"))
        .map_err(anyhow::Error::msg)?;
    let path = "/_arkret/self/contacts/tombstone";
    let prepared: ContactOperationOutcome = serde_json::from_value(
        expect_json(
            holder.client.post(path).json(&json!({
                "phase":"prepare", "operation_id":operation_id, "idempotency_key":idempotency_key,
                "peer":row.peer, "contact_round_id":next.contact_round_id, "version":next.version,
                "predecessor_event_ref":next.predecessor_event_ref, "block_peer":true,
            })),
            StatusCode::OK,
        )
        .await?,
    )?;
    let ContactOperationOutcome::Prepared {
        outcome:
            ContactPreparedOutcome::Tombstone {
                reservation_handle,
                event_draft,
                ..
            },
    } = prepared
    else {
        bail!("actual Contact tombstone did not prepare")
    };
    let commit = ContactCommitRequestBody {
        phase: ContactCommitPhase::Commit,
        operation_id,
        idempotency_key,
        reservation_handle,
        signed_event: holder.client.sign_prepared_contact_event(
            &event_draft,
            arkret_wire::event_kind_str::CONTACT_TOMBSTONE,
        )?,
    };
    let result: ContactOperationOutcome = serde_json::from_value(
        expect_json(holder.client.post(path).json(&commit), StatusCode::OK).await?,
    )?;
    ensure!(
        matches!(result, ContactOperationOutcome::Accepted { .. }),
        "Contact tombstone failed actual acceptance"
    );
    Ok(())
}

pub(crate) async fn unblock_after_tombstone(
    holder: &crate::scenarios::mls_lifecycle_live::Member,
    realm: &arkret_wire::RealmId,
    refused: &arkret_wire::EventId,
) -> Result<()> {
    let row = holder.client.sdk().account_data_get(BLOCKLIST_KEY).await?;
    let write = write_value_request(
        &holder.client,
        &holder.actor,
        row.revision,
        json!({"entries":[]}),
    )
    .await?;
    expect_json(holder.client.put(PATH).json(&write), StatusCode::OK).await?;
    let directory = tempfile::tempdir()?;
    let host = inkson::sync_engine::NativeAccountHost::new(
        holder.client.sdk(),
        holder.account.clone(),
        holder.device.clone(),
        inkson::LocalStateStore::with_path(directory.path().join("tombstone-unblock.json")),
    )
    .await?;
    host.catch_up().await?;
    let mut store = host.state_store();
    ensure!(
        store.blocklist_freshness_known() && store.client_blocklist_revision() == row.revision + 1
    );
    ingest_retained_realm(&holder.client, &host, realm).await?;
    store = host.state_store();
    ensure!(
        !serde_json::to_string(&store.load().raw_operations)?.contains(refused.as_str()),
        "private unblock back-filled a Contact-refused DM Message"
    );
    ensure!(
        holder
            .client
            .sdk()
            .committed_event_get(refused)
            .await
            .is_err(),
        "private unblock materialized a refused DM Message"
    );
    Ok(())
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
    host.catch_up_selected_realm_until_complete(realm).await?;
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
    ingest_retained_realm(&member.client, &host, realm).await?;
    Ok(host)
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

async fn observe_sealed_read_receipt(
    holder: &crate::scenarios::mls_lifecycle_live::Member,
    host: &inkson::sync_engine::NativeAccountHost,
    peer: &crate::scenarios::mls_lifecycle_live::Member,
    peer_host: &inkson::sync_engine::NativeAccountHost,
    realm: &arkret_wire::RealmId,
    strand: &arkret_wire::StrandId,
    message: &arkret_wire::EventId,
) -> Result<()> {
    let mut stream = peer.client.sdk().signal_subscribe_frames().await?;
    let _signer = ActiveEndpointSigner::install(holder)?;
    let outcome = host
        .send_automatic_read_receipt(realm.as_str(), strand.as_str(), "")
        .await?
        .context("unblocked actual automatic receipt was not sent")?;
    ensure!(
        outcome.accepted && outcome.realm_id == *realm,
        "actual Station did not accept the sealed receipt: {outcome:?}"
    );
    let mut receiver = garth::signal::SignalReceiver::new();
    let received = next_admitted_signal(&mut stream, peer_host, peer, &mut receiver).await?;
    let garth::signal::SignalReceiveOutcome::Accepted {
        domain, plaintext, ..
    } = received
    else {
        bail!("actual sealed receipt not admitted: {received:?}");
    };
    let arkret::SignalPlaintext::ReadReceipt(receipt) = plaintext else {
        bail!("actual receiver admitted a different Signal profile: {plaintext:?}");
    };
    ensure!(
        domain.sender_actor_id == holder.actor
            && receipt.actor_id == holder.actor
            && receipt.event_id == *message
            && receipt.read_scope.object_ref.as_deref() == Some(strand.as_str())
            && domain.scope_ref
                == (arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone()
                }),
        "actual sealed receipt changed authenticated sender, scope or retained event"
    );
    eprintln!(
        "blocklist actual formal Signal receipt: accepted at Station, streamed to peer, real MLS AEAD/proof/sequence admission; no timing oracle claim"
    );
    Ok(())
}

/// Actual ordinary Realm MLS is necessary: the DM participant profile has no
/// CallCreate action and may not gain one for a test.
pub(crate) async fn observe_ordinary_call_invite(
    sender: &crate::scenarios::mls_lifecycle_live::Member,
    holder: &crate::scenarios::mls_lifecycle_live::Member,
    station: &ArkretServer,
    realm: &arkret_wire::RealmId,
    accepted_group: &arkret_wire::EventId,
    sender_group: &arkret::ArkretMlsGroup,
    holder_group: &arkret::ArkretMlsGroup,
) -> Result<()> {
    use arkret_models_collaboration::events_payloads::call::{
        CallCreatePayload, CallLifecycleState,
    };

    use crate::scenarios::human_device_producer_live::{
        grant_realm_actions, submit_and_expect_commit,
    };
    let grant = grant_realm_actions(
        &sender.client,
        station,
        realm.as_str(),
        &sender.account,
        &["ak.call.join", "ak.call.signal.send"],
    )
    .await?;
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
    let call_id = arkret_wire::CallId::from_event_id(&create.event_id);
    block_direct_peer(holder, sender).await?;
    let directory = tempfile::tempdir()?;
    let sender_host = native_signal_endpoint(
        sender,
        realm,
        accepted_group,
        sender_group,
        &directory.path().join("call-sender.json"),
    )
    .await?;
    let holder_host = native_signal_endpoint(
        holder,
        realm,
        accepted_group,
        holder_group,
        &directory.path().join("call-recipient.json"),
    )
    .await?;
    let scope = arkret_wire::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let material =
        inkson::signal::key_material_for_scope(&sender_host.state_store(), realm.as_str(), None)?;
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
                .await?;
            ensure!(
                holder_host.state_store().client_blocklist().is_empty(),
                "actual unblock delta was not consumed"
            );
        }
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
        let outcome = sender_host
            .send_scope_signal(scope.clone(), &material, &payload)
            .await?;
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
            "private block/unblock did not govern the actual accepted Call product"
        );
        observed.push(outcome);
    }
    ensure!(
        observed[0].accepted == observed[1].accepted
            && observed[0].realm_id == observed[1].realm_id
            && observed[0].dispatched_recipient_count == observed[1].dispatched_recipient_count,
        "private block leaked through typed public response eligibility"
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
        "blocklist actual accepted ordinary CallCreate + sealed CallInvite: real producer/MLS/sequence receiver, private product 0->1, unchanged public accepted/recipient count; whole case6 remains missing authorized holder-private carrier"
    );
    Ok(())
}
