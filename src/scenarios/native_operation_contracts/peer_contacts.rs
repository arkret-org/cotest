//! Actual native Contact round and its authenticated peer CurrentRefresh.
use arkret_models_collaboration::contact_operations::*;
use arkret_models_collaboration::governance::peer_contact::{
    ContactIntroductionEvidence, PeerContactAddress,
};

use super::*;
use crate::harness::ArkretServer;
use crate::scenarios::mls_lifecycle_live::Member;

const OP: &str = "ak.peer.contacts.command.submit.v1";

pub(super) async fn run() -> Result<()> {
    let (result, observations) = observe(crate::harness::heap_future(|| async {
        let mut source = crate::harness::heap_future(|| {
            crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
                "native-contact-source",
            )
        })
        .await?;
        let mut target = crate::harness::heap_future(|| {
            crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
                "native-contact-target",
            )
        })
        .await?;
        ensure!(
            source.station.service_id() != target.station.service_id(),
            "native Contact requires two independent Station authorities"
        );
        source
            .station
            .restart_with_federation_mesh(&[target.station.url("")])
            .await?;
        target
            .station
            .restart_with_federation_mesh(&[source.station.url("")])
            .await?;
        let alice =
            super::mls_interop::member(source.controller.clone(), source.station.service_id())?;
        let bob =
            super::mls_interop::member(target.controller.clone(), target.station.service_id())?;
        let mut artifact = crate::harness::heap_future(|| {
            exercise(&source.station, &target.station, &alice, &bob)
        })
        .await?;
        artifact["processes"] = json!([
            source.coauth.server.native_process_identity()?,
            source.station.native_process_identity()?,
            target.coauth.server.native_process_identity()?,
            target.station.native_process_identity()?
        ]);
        Ok::<_, anyhow::Error>(artifact)
    }))
    .await;
    retain_attempt("peer-contacts", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &[OP])?;
    verify(&observations, &artifact)?;
    artifact["case"] = json!("peer_contacts");

    artifact["scope"] = json!([OP]);
    artifact["observations"] = json!(observations);
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("peer-contacts.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    println!("native operation contract passed: {OP}");
    Ok(())
}

async fn control_original(
    station: &ArkretServer,
    alice: &Member,
    request: &PeerContactSubmitRequestBody,
) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("owned Contact control database")?
        .to_owned();
    let actor = json!(alice.actor);
    let PeerContactSubmitRequestBody::CurrentRefresh {
        idempotency_key, ..
    } = request
    else {
        anyhow::bail!("not actual Contact current recovery")
    };
    let key = idempotency_key.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let row = db.query_one("SELECT to_jsonb(i) FROM idempotency_keys i WHERE authenticated_actor=$1 AND operation_id=$2 AND idempotency_key=$3", &[&actor, &OP, &key])?;
        Ok(row.get(0))
    }).await?
}

async fn original(station: &ArkretServer, alice: &Member, bob: &Member) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("owned native Contact database")?
        .to_owned();
    let a = alice.actor.to_string();
    let b = bob.actor.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let rows = db.query("SELECT to_jsonb(c) FROM contacts c WHERE (requester_id=$1 AND target_id=$2) OR (requester_id=$2 AND target_id=$1)", &[&a, &b])?;
        let [row] = rows.as_slice() else { anyhow::bail!("actual Contact pair has no unique durable original") };
        Ok(row.get(0))
    }).await?
}

async fn send(
    receiver: &ArkretServer,
    source: &ArkretServer,
    body: &PeerContactSubmitRequestBody,
) -> Result<Value> {
    let raw = arkret_canonical::canonical_json_bytes(body)?;
    let request = receiver.signed_peer_post_request_with_idempotency_key(
        source,
        "/_arkret/peer/contacts",
        &raw,
        receiver.service_id(),
        None,
    )?;
    let frozen = request
        .try_clone()
        .context("actual buffered peer Contact request")?;
    let response = receiver.http().execute(request).await?;
    let status = response.status();
    let raw = response.bytes().await?;
    cotest_test_support::operation_observation::record_response(
        Some(&frozen),
        status.as_u16(),
        &raw,
    )?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "native peer Contact: {status} {}",
        String::from_utf8_lossy(&raw)
    );
    Ok(serde_json::from_slice(&raw)?)
}

pub(super) async fn exercise(
    source: &ArkretServer,
    target: &ArkretServer,
    alice: &Member,
    bob: &Member,
) -> Result<Value> {
    let locator = crate::scenarios::contact_federation_live::issued_locator(&bob.client).await?;
    ensure!(
        locator.account_id == bob.account,
        "actual native locator changed its holder"
    );
    let receipt = alice
        .client
        .request_contact_with_peer(
            ContactPeer::Human {
                account_id: bob.account.clone(),
            },
            ContactIntroductionEvidence::LocatorRef {
                principal_locator: locator.clone(),
            },
        )
        .await?;
    let incoming = crate::scenarios::contact_federation_live::wait_contact(
        &bob.client,
        &alice.actor,
        ContactState::PendingIncoming,
    )
    .await?;
    ensure!(
        incoming.request_event_ref.as_ref() == Some(&receipt.core.request_event_ref),
        "target Contact lacks its actual native request"
    );
    bob.client.accept_contact(&alice.client).await?;
    let accepted_alice = crate::scenarios::contact_federation_live::wait_contact(
        &alice.client,
        &bob.actor,
        ContactState::Accepted,
    )
    .await?;
    let accepted_bob = crate::scenarios::contact_federation_live::wait_contact(
        &bob.client,
        &alice.actor,
        ContactState::Accepted,
    )
    .await?;
    let before = original(target, alice, bob).await?;
    let current: ContactPrivateState = serde_json::from_value(before["current_state"].clone())?;
    let direction = current
        .direction_actor(&bob.actor)
        .context("actual native holder direction absent")?;
    ensure!(
        !direction.scope_instances.is_empty() && !direction.scope_grants.is_empty(),
        "native Contact CurrentRefresh requires actual nonempty granted scope originals"
    );
    let mut refs = direction
        .scope_instances
        .iter()
        .map(|instance| instance.grant_event_ref.clone())
        .collect::<Vec<_>>();
    refs.sort();
    refs.dedup();
    let request = PeerContactSubmitRequestBody::CurrentRefresh {
        idempotency_key: arkret_wire::IdempotencyKey::new(arkret_identifiers::new_prefixed_uuid7(
            "ak:idempotency:",
        ))
        .map_err(anyhow::Error::msg)?,
        requester: ContactPeer::Human {
            account_id: alice.account.clone(),
        },
        trust_domain_id: target.trust_domain().clone(),
        initial_contact_round_id: Some(
            current
                .initial_identity
                .as_ref()
                .context("actual accepted first Contact identity absent")?
                .round
                .contact_round_id
                .clone(),
        ),
        known_version: direction.head_operation.version(),
        grant_event_refs: refs,
        contact_address: PeerContactAddress::for_recipient(
            ContactPeer::Human {
                account_id: bob.account.clone(),
            },
            arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: target.url(
                    &arkret_models_identity::canonical_service_resolution_path(target.service_id()),
                ),
            },
        ),
    };
    let response = send(target, source, &request).await?;
    let after = original(target, alice, bob).await?;
    let control = control_original(target, alice, &request).await?;
    ensure!(
        control["response_body"] == response
            && control["request_hash"] == arkret_canonical::canonical_sha256(&request)?,
        "native Contact control has no exact durable result"
    );
    let replay = send(target, source, &request).await?;
    ensure!(
        response == replay,
        "peer Contact exact replay changed its frozen native original"
    );
    let after_replay = original(target, alice, bob).await?;
    let control_replay = control_original(target, alice, &request).await?;
    ensure!(
        after == after_replay && control == control_replay,
        "native Contact retry changed its stored source or frozen control original"
    );
    let source_original = original(source, alice, bob).await?;
    let actual: ContactPrivateState = serde_json::from_value(after["current_state"].clone())?;
    ensure!(
        actual.initial_identity == current.initial_identity
            && actual.round_events == current.round_events
            && actual
                .direction_actor(&bob.actor)
                .context("native holder direction disappeared")?
                .head_operation
                == direction.head_operation,
        "native CurrentRefresh changed its accepted round or holder operation"
    );
    Ok(
        json!({"locator":locator,"request_receipt":receipt,"incoming":incoming,"accepted_source":accepted_alice,"accepted_target":accepted_bob,"before":before,"after":after,"after_replay":after_replay,"control":control,"control_replay":control_replay,"source_original":source_original,"request":request,"response":response,"replay":replay,"source_actor":alice.actor,"target_actor":bob.actor}),
    )
}

struct NativeContactHistory(Vec<arkret_models_identity::IdentityLogListResponseBody>);
impl arkret_identity::AuthorityDidHistoryResolver for NativeContactHistory {
    fn resolve_complete_history(
        &self,
        did: &arkret_wire::Did,
    ) -> std::result::Result<
        arkret_models_identity::IdentityLogListResponseBody,
        arkret_identity::AuthorityHistoryUnavailable,
    > {
        self.0
            .iter()
            .find(|history| &history.did == did)
            .cloned()
            .ok_or_else(|| arkret_identity::AuthorityHistoryUnavailable {
                message: "DID is outside independently admitted native Station histories".into(),
            })
    }
}

pub(super) fn verify(observations: &NativeOperationObservations, artifact: &Value) -> Result<()> {
    let request: PeerContactSubmitRequestBody =
        serde_json::from_value(artifact["request"].clone())?;
    let response: PeerContactSubmitResponseBody =
        serde_json::from_value(artifact["response"].clone())?;
    let histories = observations.accepted_identity_material.iter().map(|material|serde_json::from_value(material["account_authority_history"].clone())).collect::<std::result::Result<Vec<arkret_models_identity::IdentityLogListResponseBody>,_>>()?;
    for history in &histories {
        let service = arkret_identifiers::project_did_to_core_id(&history.did)?;
        let _ = native_station_resolution(observations, &service, chrono::Utc::now())?;
    }
    arkret::contact_authorization::verify_contact_current_refresh_response(
        &request,
        &response,
        arkret_canonical::DigestSuite::Sha256,
        chrono::Utc::now(),
        &NativeContactHistory(histories),
    )?;
    let PeerContactSubmitResponseBody::Control(
        PeerContactControlSubmitResponseBody::CurrentRefresh { material, .. },
    ) = &response
    else {
        anyhow::bail!("native Contact response has no full actual authority material")
    };
    ensure!(
        !material.current_proof.scope_instances.is_empty(),
        "native Contact response omitted its nonempty granted scope"
    );
    let exchanges = observations
        .exchanges
        .iter()
        .filter(|row| row.operation_id.as_str() == OP)
        .collect::<Vec<_>>();
    ensure!(
        exchanges.len() >= 2,
        "native Contact current recovery and exact replay exchanges absent"
    );
    for exchange in exchanges {
        verify_native_station_http_request(observations, exchange, &[])?;
        ensure!(
            exchange.explicit_request_headers["source-service-id"]
                != exchange.explicit_request_headers["destination-service-id"],
            "native peer Contact reused one Station"
        );
        ensure!(
            exchange.request_body == artifact["request"]
                && exchange.response_body == artifact["response"],
            "peer Contact proof differs from actual observed bytes"
        );
    }
    Ok(())
}
