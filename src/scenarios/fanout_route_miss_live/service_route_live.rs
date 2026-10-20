//! Real outbox -> current native method -> carrier -> Describe -> durable floor.
use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::{
    AuthenticatedServiceResolution, ResolutionCommitment, ResolutionMethodHistoryEvidence,
};

use super::frozen_authority_live::{hold_schedule, release, settled};
use super::terminal_restart_live::{
    ensure_same_intent, fanout, frozen_duplicate_request, replay_frozen_duplicate,
};
use super::*;
use crate::harness::{ServiceRouteControl, ServiceRouteRelay};

const NATIVE: &str = "/webvh/service/did.jsonl";
const DOCUMENT: &str = "/webvh/service/did.json";
const DESCRIBE: &str = "/_arkret/describe";

fn resolution_path(server: &ArkretServer) -> String {
    arkret_models_identity::canonical_service_resolution_path(server.service_id())
}

async fn resolution(server: &ArkretServer) -> Result<AuthenticatedServiceResolution> {
    Ok(server
        .http()
        .get(server.url(&resolution_path(server)))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}
async fn describe(server: &ArkretServer) -> Result<ServiceDescribe> {
    Ok(server
        .http()
        .get(server.url("/_arkret/describe?service_kind=station"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}
fn entries(resolution: &AuthenticatedServiceResolution) -> Result<Vec<Value>> {
    let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
        &resolution.method_history_evidence
    else {
        bail!("live fixture must use WebVH")
    };
    Ok(log_entries.clone())
}
fn canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(arkret_canonical::canonical_json_bytes(value)?)
}
fn native(entries: &[Value]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend(canonical(entry)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn method_replies(entries: &[Value]) -> Result<Vec<(String, u16, Vec<u8>)>> {
    Ok(vec![
        (NATIVE.into(), 200, native(entries)?),
        (
            DOCUMENT.into(),
            200,
            canonical(&entries.last().context("native document head")?["state"])?,
        ),
    ])
}

async fn route_rows(database: &str, core: &arkret_wire::DidCoreId) -> Result<Value> {
    let database = database.to_owned();
    let core = core.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let mut result = serde_json::Map::new();
        for table in ["service_method_states", "service_route_cache", "service_resolution_histories", "service_resolution_fork_quarantine"] {
            let rows = db.query(&format!("SELECT to_jsonb(r) FROM {table} r WHERE service_id=$1 AND service_kind='station' ORDER BY to_jsonb(r)::text"), &[&core])?;
            result.insert(table.into(), Value::Array(rows.iter().map(|row| row.get(0)).collect()));
        }
        Ok(Value::Object(result))
    }).await?
}

async fn stored_counts(database: &str, event: &EventId) -> Result<(i64, i64)> {
    let database = database.to_owned();
    let event = event.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok((
            db.query_one(
                "SELECT count(*) FROM canonical_events WHERE envelope->>'event_id'=$1",
                &[&event],
            )?
            .get(0),
            db.query_one(
                "SELECT count(*) FROM realm_commits WHERE commit_json->>'event_ref'=$1",
                &[&event],
            )?
            .get(0),
        ))
    })
    .await?
}

async fn queued(fixture: &CurrentOriginFixture, text: &str) -> Result<(Event, RealmCommit, Value)> {
    let (event, commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &fixture.alice.default_strand_id(&fixture.realm)?,
        text,
    )
    .await?;
    let rows = fanout(&fixture._governance_database.connect_url, &commit).await?;
    ensure!(
        rows.len() == 1 && matches!(rows[0]["state"].as_str(), Some("pending" | "pending_route")),
        "one original pending intent is required: {rows:?}"
    );
    ensure!(stored_counts(&fixture._member_database.connect_url, &event.event_id).await? == (0, 0));
    Ok((event, commit, rows[0].clone()))
}

async fn delivered(
    fixture: &CurrentOriginFixture,
    event: &Event,
    commit: &RealmCommit,
    before: &Value,
) -> Result<()> {
    ensure_same_commit(
        commit,
        &wait_held(&fixture.bob, &event.event_id, ROUTE_MISS_WINDOW).await?,
    )?;
    let row = settled(
        &fixture._governance_database.connect_url,
        commit,
        "delivered",
    )
    .await?;
    ensure_same_intent(before, &row)?;
    ensure!(stored_counts(&fixture._member_database.connect_url, &event.event_id).await? == (1, 1));
    Ok(())
}

async fn establish_old_route(
    fixture: &CurrentOriginFixture,
    expected: &AuthenticatedServiceResolution,
) -> Result<()> {
    // A stable core alone contains no method-host locator. Establish the
    // predecessor through a real delivery before retiring its service API.
    let (event, commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &fixture.alice.default_strand_id(&fixture.realm)?,
        "accepted predecessor route before endpoint retirement",
    )
    .await?;
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    settled(
        &fixture._governance_database.connect_url,
        &commit,
        "delivered",
    )
    .await?;
    let rows = route_rows(
        &fixture._governance_database.connect_url,
        fixture.group.server(1).service_id(),
    )
    .await?;
    ensure!(
        rows["service_method_states"]
            .as_array()
            .context("predecessor method floor")?
            .len()
            == 1
    );
    ensure!(
        rows["service_method_states"][0]["method_state"]["method_history_head"]
            == expected.projection()?.method_history_head
    );
    Ok(())
}

async fn moved_fixture(
    name: &str,
) -> Result<
    Option<(
        CurrentOriginFixture,
        ServiceRouteRelay,
        ServiceRouteRelay,
        AuthenticatedServiceResolution,
        ServiceDescribe,
        crate::harness::ServiceRouteSigner,
    )>,
> {
    let Some(mut fixture) = current_origin_fixture(name).await? else {
        return Ok(None);
    };
    let old_relay = fixture
        .group
        .server_mut(1)
        .install_service_route_relay()
        .await?;
    let old = resolution(fixture.group.server(1)).await?;
    let old_describe = describe(fixture.group.server(1)).await?;
    establish_old_route(&fixture, &old).await?;
    let signer = fixture
        .group
        .server(1)
        .service_route_signer(&fixture._member_database.connect_url, &old)
        .await?;
    let new_relay = fixture
        .group
        .server_mut(1)
        .move_service_endpoint(&old_relay.control())
        .await?;
    fixture.bob = fixture.group.server(1).rebind_actor_client(&fixture.bob)?;
    let new = resolution(fixture.group.server(1)).await?;
    ensure!(
        new.service_id == old.service_id
            && new.normalized_did_document.id == old.normalized_did_document.id
    );
    ensure!(
        new.projection()?.base_url != old.projection()?.base_url
            && new.projection()?.method_history_head != old.projection()?.method_history_head
    );
    ensure!(
        entries(&new)?.starts_with(&entries(&old)?),
        "endpoint successor lost its native predecessor"
    );
    Ok(Some((
        fixture,
        old_relay,
        new_relay,
        old,
        old_describe,
        signer,
    )))
}

pub async fn endpoint_successor() -> Result<()> {
    const NAME: &str = "service-method-endpoint-successor";
    let Some(mut fixture) = current_origin_fixture(NAME).await? else {
        return Ok(());
    };
    let old_relay = fixture
        .group
        .server_mut(1)
        .install_service_route_relay()
        .await?;
    let old_url = fixture.group.server(1).base_url();
    let old_resolution = resolution(fixture.group.server(1)).await?;
    let old_describe = describe(fixture.group.server(1)).await?;
    establish_old_route(&fixture, &old_resolution).await?;
    let source = fixture._governance_database.connect_url.clone();
    hold_schedule(&source, true).await?;
    let (event, commit, intent) = queued(
        &fixture,
        "same core endpoint successor retains this exact intent",
    )
    .await?;
    fixture.group.server_mut(0).stop_external_process().await?;
    let before = route_rows(&source, fixture.group.server(1).service_id()).await?;
    ensure!(
        before["service_method_states"]
            .as_array()
            .context("accepted native floor")?
            .len()
            == 1
    );
    let new_relay = fixture
        .group
        .server_mut(1)
        .move_service_endpoint(&old_relay.control())
        .await?;
    fixture.bob = fixture.group.server(1).rebind_actor_client(&fixture.bob)?;
    let next = resolution(fixture.group.server(1)).await?;
    let next_describe = describe(fixture.group.server(1)).await?;
    ensure!(
        next.service_id == old_resolution.service_id
            && next.normalized_did_document.id == old_resolution.normalized_did_document.id
    );
    ensure!(entries(&next)?.starts_with(&entries(&old_resolution)?));
    ensure!(
        next_describe.trust_domain == old_describe.trust_domain
            && next_describe.service_resolution != old_describe.service_resolution
    );
    ensure!(
        fixture
            .group
            .server(1)
            .http()
            .get(old_url.join(DESCRIBE)?)
            .send()
            .await?
            .status()
            == StatusCode::SERVICE_UNAVAILABLE
    );
    ensure!(
        fixture
            .group
            .server(1)
            .http()
            .get(old_url.join(&resolution_path(fixture.group.server(1)))?)
            .send()
            .await?
            .status()
            == StatusCode::SERVICE_UNAVAILABLE
    );
    let native_before = old_relay.control().requests(NATIVE);
    let resolution_before = new_relay
        .control()
        .requests(&resolution_path(fixture.group.server(1)));
    let describe_before = new_relay.control().requests(DESCRIBE);
    release(&source, &intent).await?;
    fixture.group.server_mut(0).start_external_process().await?;
    delivered(&fixture, &event, &commit, &intent).await?;
    let after = route_rows(&source, fixture.group.server(1).service_id()).await?;
    ensure!(
        after["service_method_states"][0]["method_state"]["method_history_head"]
            == next.projection()?.method_history_head
    );
    ensure!(
        after["service_route_cache"][0]["entry"]["projection"]["base_url"]
            == fixture.group.server(1).base_url().as_str()
    );
    ensure!(after["service_resolution_fork_quarantine"] == json!([]));
    ensure!(
        old_relay.control().requests(NATIVE) > native_before
            && new_relay
                .control()
                .requests(&resolution_path(fixture.group.server(1)))
                > resolution_before
            && new_relay.control().requests(DESCRIBE) > describe_before
    );
    // Preserve an exact transport transcript, not just an equivalent Event.
    let body = intent["payload_json"]
        .as_str()
        .context("original canonical replication body")?
        .as_bytes();
    let replay =
        frozen_duplicate_request(fixture.group.server(1), fixture.group.server(0), body).await?;
    fixture
        .group
        .server_mut(0)
        .restart_external_process()
        .await?;
    fixture
        .group
        .server_mut(1)
        .restart_external_process()
        .await?;
    replay_frozen_duplicate(fixture.group.server(1), &replay).await?;
    ensure!(stored_counts(&fixture._member_database.connect_url, &event.event_id).await? == (1, 1));
    let final_intent = fanout(&source, &commit).await?;
    ensure!(final_intent.len() == 1);
    ensure_same_intent(&intent, &final_intent[0])?;
    eprintln!(
        "service route case=endpoint_successor actual_process_restarts=4 original_intent=preserved duplicate=stable"
    );
    Ok(())
}

struct Fault {
    name: &'static str,
    old: Vec<(String, u16, Vec<u8>)>,
    new: Vec<(String, u16, Vec<u8>)>,
    observed_path: String,
    observe_old: bool,
}
impl Fault {
    fn install(&self, old: &ServiceRouteControl, new: &ServiceRouteControl) {
        old.clear();
        new.clear();
        for (path, status, bytes) in &self.old {
            old.reply(path, *status, bytes.clone());
        }
        for (path, status, bytes) in &self.new {
            new.reply(path, *status, bytes.clone());
        }
    }
}

pub async fn method_faults() -> Result<()> {
    const NAME: &str = "service-method-http-faults";
    let Some((mut fixture, old_relay, new_relay, old_resolution, old_describe, old_signer)) =
        moved_fixture(NAME).await?
    else {
        return Ok(());
    };
    let old = old_relay.control();
    let new = new_relay.control();
    let source = fixture._governance_database.connect_url.clone();
    // Establish the legitimate successor through the actual original dispatcher.
    hold_schedule(&source, true).await?;
    let (event, commit, intent) =
        queued(&fixture, "positive current endpoint before HTTP faults").await?;
    fixture
        .group
        .server_mut(0)
        .restart_external_process()
        .await?;
    release(&source, &intent).await?;
    delivered(&fixture, &event, &commit, &intent).await?;
    let current = resolution(fixture.group.server(1)).await?;
    let current_describe = describe(fixture.group.server(1)).await?;
    let path = resolution_path(fixture.group.server(1));
    let foreign = resolution(fixture.group.server(0)).await?;
    let signer = fixture
        .group
        .server(1)
        .service_route_signer(&fixture._member_database.connect_url, &current)
        .await?;
    let mut role_state =
        entries(&current)?.last().context("current native entry")?["state"].clone();
    let role_services = role_state["service"]
        .as_array_mut()
        .context("role entries")?;
    let role_entry = role_services
        .iter_mut()
        .find(|entry| entry["type"] == "ArkretService" && entry["serviceKind"] == "station")
        .context("Station role")?;
    role_entry["serviceKind"] = json!("push_gateway");
    let wrong_role = signer.successor(role_state).await?;
    let mut egress_state = entries(&current)?.last().unwrap()["state"].clone();
    for service in egress_state["service"]
        .as_array_mut()
        .context("egress service entries")?
    {
        if service["type"] == "ArkretService" && service["serviceKind"] == "station" {
            service["serviceEndpoint"] = json!("https://169.254.169.254/");
        }
    }
    let malicious = signer.successor(egress_state).await?;
    let mut renamed_state = entries(&current)?.last().unwrap()["state"].clone();
    let original_did = current.normalized_did_document.id.as_str();
    let scid = original_did
        .strip_prefix("did:webvh:")
        .context("WebVH fixture DID")?
        .split(':')
        .next()
        .context("fixture SCID")?;
    renamed_state["id"] = json!(format!("did:webvh:{scid}:unapproved.invalid:webvh:service"));
    let renamed = signer.successor(renamed_state).await?;
    let mut wrong_describe = current_describe.clone();
    wrong_describe.service_resolution.method_history_head =
        old_describe.service_resolution.method_history_head.clone();
    let faults = vec![
        Fault {
            name: "method_unavailable",
            old: vec![(NATIVE.into(), 503, b"method unavailable".to_vec())],
            new: vec![],
            observed_path: NATIVE.into(),
            observe_old: true,
        },
        Fault {
            name: "wrong_core_carrier",
            old: vec![],
            new: vec![(path.clone(), 200, canonical(&foreign)?)],
            observed_path: path.clone(),
            observe_old: false,
        },
        Fault {
            name: "wrong_role_native_successor",
            old: method_replies(&wrong_role)?,
            new: vec![],
            observed_path: NATIVE.into(),
            observe_old: true,
        },
        Fault {
            name: "describe_mismatch",
            old: vec![],
            new: vec![(DESCRIBE.into(), 200, canonical(&wrong_describe)?)],
            observed_path: DESCRIBE.into(),
            observe_old: false,
        },
        Fault {
            name: "native_rollback",
            old: method_replies(&entries(&old_resolution)?)?
                .into_iter()
                .chain(vec![
                    (path.clone(), 200, canonical(&old_resolution)?),
                    (DESCRIBE.into(), 200, canonical(&old_describe)?),
                ])
                .collect(),
            new: vec![],
            observed_path: path.clone(),
            observe_old: true,
        },
        Fault {
            name: "invalid_same_scid_rename",
            old: method_replies(&renamed)?,
            new: vec![],
            observed_path: NATIVE.into(),
            observe_old: true,
        },
        Fault {
            name: "different_scid_native_history",
            old: method_replies(&entries(&foreign)?)?,
            new: vec![],
            observed_path: NATIVE.into(),
            observe_old: true,
        },
        Fault {
            name: "signed_endpoint_egress_denial",
            old: method_replies(&malicious)?,
            new: vec![],
            observed_path: NATIVE.into(),
            observe_old: true,
        },
    ];
    for fault in faults {
        let (event, commit, intent) = queued(&fixture, fault.name).await?;
        fixture.group.server_mut(0).stop_external_process().await?;
        fault.install(&old, &new);
        let control = if fault.observe_old { &old } else { &new };
        let observed = control.requests(&fault.observed_path);
        let before = route_rows(&source, fixture.group.server(1).service_id()).await?;
        release(&source, &intent).await?;
        fixture.group.server_mut(0).start_external_process().await?;
        let refused = settled(&source, &commit, "pending_route").await?;
        ensure!(
            refused["last_error_code"] == "service_route_unavailable"
                && refused["last_http_status"].is_null(),
            "{} did not fail before delivery: {refused}",
            fault.name
        );
        ensure!(
            control.requests(&fault.observed_path) > observed,
            "{} never reached its real HTTP fault: {refused}",
            fault.name
        );
        ensure_same_intent(&intent, &refused)?;
        ensure!(
            refused["semantic_attempts"] == intent["semantic_attempts"]
                && refused["semantic_attempts"] == json!(0),
            "{} consumed a semantic attempt before delivery",
            fault.name
        );
        ensure!(
            stored_counts(&fixture._member_database.connect_url, &event.event_id).await? == (0, 0),
            "{} installed business data",
            fault.name
        );
        ensure!(
            route_rows(&source, fixture.group.server(1).service_id()).await? == before,
            "{} changed accepted floor/cache/history or extended its TTL",
            fault.name
        );
        let actual_error = refused["last_response_excerpt"]
            .as_str()
            .context("actual route refusal")?;
        let expected_stage = match fault.name {
            "wrong_role_native_successor" => Some("current DID service endpoint is ambiguous"),
            "describe_mismatch" => Some("ServiceDescribe"),
            "native_rollback" => Some("rollback"),
            "different_scid_native_history" => Some("changed its stable identity"),
            _ => None,
        };
        if let Some(stage) = expected_stage {
            ensure!(
                actual_error.contains(stage),
                "{} did not reach the expected verifier: {actual_error}",
                fault.name
            );
        }
        if fault.name == "signed_endpoint_egress_denial" {
            let error = refused["last_response_excerpt"]
                .as_str()
                .context("actual egress refusal")?;
            ensure!(
                error.contains("denied")
                    && (error.contains("link-local") || error.contains("metadata")),
                "signed malicious URL did not reach actual egress guard: {error}"
            );
        }
        old.clear();
        new.clear();
        release(&source, &refused).await?;
        delivered(&fixture, &event, &commit, &intent).await?;
        eprintln!(
            "service route case={} native_http=observed floor_ttl=unchanged pending_intent=preserved restored_delivery=accepted",
            fault.name
        );
    }
    // A valid sibling signed by the real precommitted fixture key must reach
    // the durable anti-fork gate; malformed signatures cannot prove this case.
    let fork_entries = old_signer
        .successor(entries(&current)?.last().unwrap()["state"].clone())
        .await?;
    let fork = old_signer.resolution(fork_entries.clone())?;
    ensure!(
        fork.projection()?.version_id.split('-').next()
            == current.projection()?.version_id.split('-').next()
    );
    ensure!(fork.projection()?.method_history_head != current.projection()?.method_history_head);
    let mut fork_describe = current_describe.clone();
    let p = fork.projection()?;
    fork_describe.service_resolution = ResolutionCommitment {
        did: p.did,
        method_history_head: p.method_history_head,
        version_id: p.version_id,
    };
    fork_describe.validate_route_projection(&fork.projection()?)?;
    let (event, commit, intent) = queued(
        &fixture,
        "valid native fork remains quarantined across restart",
    )
    .await?;
    fixture.group.server_mut(0).stop_external_process().await?;
    let before = route_rows(&source, fixture.group.server(1).service_id()).await?;
    old.reply(NATIVE, 200, native(&fork_entries)?);
    old.reply(
        DOCUMENT,
        200,
        canonical(&fork_entries.last().unwrap()["state"])?,
    );
    new.reply(&path, 200, canonical(&fork)?);
    new.reply(DESCRIBE, 200, canonical(&fork_describe)?);
    release(&source, &intent).await?;
    fixture.group.server_mut(0).start_external_process().await?;
    let refused = settled(&source, &commit, "pending_route").await?;
    ensure_same_intent(&intent, &refused)?;
    ensure!(
        refused["last_error_code"] == "service_route_unavailable"
            && refused["last_http_status"].is_null()
            && refused["semantic_attempts"] == json!(0)
    );
    let after = route_rows(&source, fixture.group.server(1).service_id()).await?;
    for table in [
        "service_method_states",
        "service_route_cache",
        "service_resolution_histories",
    ] {
        ensure!(after[table] == before[table], "fork replaced {table}");
    }
    ensure!(
        after["service_resolution_fork_quarantine"]
            .as_array()
            .context("actual durable quarantine")?
            .len()
            == 1
    );
    let evidence: AuthenticatedServiceResolution =
        serde_json::from_value(after["service_resolution_fork_quarantine"][0]["evidence"].clone())?;
    ensure!(
        after["service_resolution_fork_quarantine"][0]["accepted_digest"]
            == current.projection()?.method_history_head
    );
    ensure!(
        after["service_resolution_fork_quarantine"][0]["conflicting_digest"]
            == fork.projection()?.method_history_head
    );
    ensure!(
        evidence == fork,
        "quarantine lost the actual verified sibling"
    );
    ensure!(stored_counts(&fixture._member_database.connect_url, &event.event_id).await? == (0, 0));
    old.clear();
    new.clear();
    fixture
        .group
        .server_mut(0)
        .restart_external_process()
        .await?;
    release(&source, &refused).await?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let final_refusal = loop {
        let rows = fanout(&source, &commit).await?;
        ensure!(rows.len() == 1);
        if rows[0]["state"] == "pending_route"
            && rows[0]["attempts"].as_i64().context("retry attempts")?
                > refused["attempts"].as_i64().context("original attempts")?
        {
            break rows[0].clone();
        }
        ensure!(
            Instant::now() < deadline,
            "quarantine was not exercised after the real restart"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    ensure_same_intent(&intent, &final_refusal)?;
    ensure!(
        final_refusal["last_response_excerpt"]
            .as_str()
            .context("quarantine refusal")?
            .contains("quarantined")
    );
    ensure!(stored_counts(&fixture._member_database.connect_url, &event.event_id).await? == (0, 0));
    ensure!(route_rows(&source, fixture.group.server(1).service_id()).await? == after);
    eprintln!(
        "service route case=valid_native_fork signature=verified quarantine=durable restart=refused original_intent=preserved"
    );
    Ok(())
}
