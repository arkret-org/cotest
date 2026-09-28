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
const MISSING_CASES: [&str; 3] = [
    "shared_history_is_received_then_filtered_by_the_holder",
    "unblock_rebuilds_the_projection_from_retained_material",
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
pub(crate) struct SharedSubmissionObservation {
    sender_actor: ActorId,
    event_kind: arkret_wire::EventKind,
    scope_ref: arkret_wire::ScopeRef,
    authorization_ref: Option<arkret_wire::AuthorizationRef>,
    status: StatusCode,
    content_type: String,
    transport_protocol: String,
    response_shape: Value,
    pub(crate) outcome: arkret_wire::AuthoritySubmitOutcome,
    elapsed: std::time::Duration,
    attempts: Vec<(StatusCode, Option<String>)>,
}

fn json_shape(value: &Value) -> Value {
    match value {
        Value::Null => json!("null"),
        Value::Bool(_) => json!("boolean"),
        Value::Number(_) => json!("number"),
        Value::String(_) => json!("string"),
        Value::Array(values) => Value::Array(values.iter().map(json_shape).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), json_shape(value)))
                .collect(),
        ),
    }
}

async fn observed_shared_message(
    peer: &TestActorClient,
    realm: &str,
    strand: &str,
    text: &str,
) -> Result<SharedSubmissionObservation> {
    let event = peer
        .author_event(
            realm,
            "ak.message.create",
            crate::harness::message_create_text_payload(strand, text)?,
        )
        .await?;
    observed_authored_shared_message(peer, event).await
}

pub(crate) async fn observed_authored_shared_message(
    peer: &TestActorClient,
    event: arkret_wire::Event,
) -> Result<SharedSubmissionObservation> {
    use arkret_models_collaboration::authority_commit::{
        SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
    };
    let request = SelfAuthoritySubmitRequest::Event(crate::publication::initial_submission(
        event.clone(),
        "",
    )?);
    let request_bytes = arkret_canonical::canonical_json_bytes(&request)?;
    let started = std::time::Instant::now();
    let mut attempts = Vec::new();
    let (status, transport_protocol, content_type, bytes) = loop {
        let response = peer
            .post("/_arkret/self/events")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request_bytes.clone())
            .send()
            .await?;
        let status = response.status();
        let transport_protocol = format!("{:?}", response.version());
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .context("sender response lacks Content-Type")?
            .to_str()?
            .to_owned();
        ensure!(
            !response.headers().iter().any(|(_, value)| value
                .to_str()
                .is_ok_and(|value| value.contains("blocked_by_user"))),
            "private block leaked through a response header"
        );
        let bytes = response.bytes().await?;
        let problem_type = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| value.get("type")?.as_str().map(ToOwned::to_owned));
        attempts.push((status, problem_type.clone()));
        if status == StatusCode::SERVICE_UNAVAILABLE
            && problem_type.as_deref()
                == Some("https://arkret.org/problems/temporarily_unavailable")
            && attempts.len() < 3
        {
            tokio::time::sleep(std::time::Duration::from_millis(
                100 * attempts.len() as u64,
            ))
            .await;
            continue;
        }
        break (status, transport_protocol, content_type, bytes);
    };
    let elapsed = started.elapsed();
    eprintln!(
        "blocklist exact signed Message request attempts: event={}, attempts={attempts:?}, total_start_to_full_response_ns={}",
        event.event_id,
        elapsed.as_nanos(),
    );
    ensure!(
        status == StatusCode::OK,
        "shared Message submission failed after {attempts:?}: {}",
        String::from_utf8_lossy(&bytes)
    );
    ensure!(
        !String::from_utf8_lossy(&bytes).contains("blocked_by_user"),
        "private block leaked through the sender result"
    );
    let response_shape = json_shape(&serde_json::from_slice::<Value>(&bytes)?);
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
    let sender_actor = event.actor_id.clone();
    let event_kind = event.kind.clone();
    let scope_ref = event.scope_ref.clone();
    let authorization_ref = event.authorization_ref.clone();
    arkret_wire::CommittedEventFullView {
        event,
        commit: commit.clone(),
    }
    .validate_shape()?;
    Ok(SharedSubmissionObservation {
        sender_actor,
        event_kind,
        scope_ref,
        authorization_ref,
        status,
        content_type,
        transport_protocol,
        response_shape,
        outcome,
        elapsed,
        attempts,
    })
}

pub(crate) fn compare_shared_sender_observations(
    blocked: &SharedSubmissionObservation,
    unblocked: &SharedSubmissionObservation,
) -> Result<()> {
    ensure!(
        blocked.attempts.len() == 1 && unblocked.attempts.len() == 1,
        "paired one-shot transport differs because a registered retry occurred: blocked={:?}, unblocked={:?}; retries are recorded as availability evidence, not response-independence proof",
        blocked.attempts,
        unblocked.attempts,
    );
    ensure!(
        blocked.sender_actor == unblocked.sender_actor
            && blocked.event_kind == unblocked.event_kind
            && blocked.scope_ref == unblocked.scope_ref
            && blocked.authorization_ref == unblocked.authorization_ref
            && blocked.status == unblocked.status
            && blocked.content_type == unblocked.content_type
            && blocked.transport_protocol == unblocked.transport_protocol
            && blocked.response_shape == unblocked.response_shape,
        "paired submissions changed sender, scope, authority, operation, protocol or response shape"
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
        "blocklist shared sender paired transport: actor={}, operation={}, realm={}, protocol={}, status={}, content_type={}, response_shape={}, outcome=committed/no_problem_reason, blocked_start_to_full_response_ns={}, unblocked_start_to_full_response_ns={}; durations are regression observations without a pass threshold",
        blocked.sender_actor,
        blocked.event_kind.as_str(),
        blocked_commit.realm_id,
        blocked.transport_protocol,
        blocked.status,
        blocked.content_type,
        blocked.response_shape,
        blocked.elapsed.as_nanos(),
        unblocked.elapsed.as_nanos()
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

/// Observe a retained, accepted DM Message through the real Native receipt rail.
/// The holder's private block revision is installed before `message_id` commits.
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
                &strand,
            )
            .is_none(),
            "blocked encrypted Message became an automatic receipt candidate"
        );
        ensure!(
            inkson::conformance::send_native_automatic_read_receipt(
                &holder_host,
                holder.client.sdk(),
                realm.as_str(),
                &strand,
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
                        &strand,
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
                    &strand,
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
        let started = std::time::Instant::now();
        let outcome = sender_host
            .send_scope_signal(scope.clone(), &material, &payload)
            .await
            .context("CallInvite send after holder blocklist projection")?;
        let elapsed = started.elapsed();
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
        observed.push((outcome, elapsed));
    }
    ensure!(
        observed[0].0.accepted == observed[1].0.accepted
            && observed[0].0.realm_id == observed[1].0.realm_id
            && observed[0].0.dispatched_recipient_count == observed[1].0.dispatched_recipient_count
            && json_shape(&serde_json::to_value(&observed[0].0)?)
                == json_shape(&serde_json::to_value(&observed[1].0)?),
        "private block leaked through typed public response eligibility"
    );
    eprintln!(
        "blocklist CallInvite paired client submission: scope={}, sender={}, blocked_invocation_to_response_ns={}, unblocked_invocation_to_response_ns={}, public_response_shape={}, accepted={}, recipient_count={:?}; durations include local encryption and are not isolated transport timing",
        realm,
        sender.actor,
        observed[0].1.as_nanos(),
        observed[1].1.as_nanos(),
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
        "blocklist actual accepted ordinary CallCreate + sealed CallInvite: real producer/MLS/sequence receiver, private product 0->1, unchanged public response shape; full case 6 still requires Contact and first DM production paths"
    );
    Ok(())
}
