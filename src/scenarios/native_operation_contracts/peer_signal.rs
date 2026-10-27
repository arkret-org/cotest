//! A real peer batch must reach an admitted MLS recipient without writing history.
use arkret::ArkretMlsGroup;
use arkret_models_collaboration::SignalStreamFrame;
use arkret_wire::{RealmId, ScopeRef, SignalClass, SignalRelayRequestBody};

use super::*;
use crate::harness::ArkretServer;
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

async fn history(database: &str, realm: &RealmId) -> Result<Value> {
    let database = database.to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let row = db.query_one("SELECT (SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY pk),'[]'::jsonb) FROM canonical_events e WHERE realm_id=$1),(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY commit_id),'[]'::jsonb) FROM realm_commits c WHERE realm_id=$1)", &[&realm])?;
        Ok(json!({"events":row.get::<_,Value>(0),"commits":row.get::<_,Value>(1)}))
    }).await?
}

pub(super) async fn exercise(
    station: &ArkretServer,
    alice: &Member,
    bob: &Member,
    realm: &RealmId,
    state: &arkret_wire::EventId,
    sender: &mut ArkretMlsGroup,
    recipient: &mut ArkretMlsGroup,
) -> Result<Value> {
    let snapshot =
        crate::scenarios::strand_watch_live::signed_snapshot(&alice.client, realm).await?;
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let head = snapshot.visible_stream_heads.iter().find(|head| matches!(&head.stream_ref, arkret_wire::CommitStreamRef::Realm { realm_id } if realm_id == realm)).context("actual Signal Realm head")?;
    let strand = alice.client.default_strand_id(realm.as_str())?;
    let mut stream = bob.client.sdk().signal_subscribe_frames().await?;
    ensure!(
        matches!(
            stream.next_frame().await?,
            Some(SignalStreamFrame::Heartbeat)
        ),
        "recipient rail was not live before peer submission"
    );
    let envelope = crate::scenarios::signal_live::scoped_envelope_with_payload(
        alice,
        sender,
        realm,
        &strand,
        state,
        &head.commit_id,
        SignalClass::Session,
        1,
        scope,
        None,
        None,
    )?;
    let request = SignalRelayRequestBody {
        realm_id: realm.clone(),
        signals: vec![envelope.clone()],
    };
    request.validate()?;
    let database = station
        .owned_database_url()
        .context("owned Signal database")?;
    let before = history(database, realm).await?;
    let bytes = arkret_canonical::canonical_json_bytes(&request)?;
    let outgoing = station.signed_peer_post_request_with_idempotency_key(
        station,
        "/_arkret/peer/signal",
        &bytes,
        station.service_id(),
        None,
    )?;
    let original = outgoing
        .try_clone()
        .context("native buffered Signal request")?;
    let response = station.http().execute(outgoing).await?;
    let status = response.status();
    let raw = response.bytes().await?;
    cotest_test_support::operation_observation::record_response(
        Some(&original),
        status.as_u16(),
        &raw,
    )?;
    ensure!(
        status == reqwest::StatusCode::NO_CONTENT && raw.is_empty(),
        "peer Signal response must be HTTP 204 with zero entity bytes: {status}"
    );
    let (received, authority) = tokio::time::timeout(std::time::Duration::from_secs(25), async {
        loop {
            match stream
                .next_frame()
                .await?
                .context("actual recipient rail closed")?
            {
                SignalStreamFrame::Heartbeat => {}
                SignalStreamFrame::Signal {
                    envelope: received,
                    delivery_authority,
                } if received.proof.envelope_digest == envelope.proof.envelope_digest => {
                    break Ok::<_, anyhow::Error>((received, delivery_authority));
                }
                other => anyhow::bail!("unexpected native Signal frame: {other:?}"),
            }
        }
    })
    .await
    .context("native peer Signal did not reach its actual recipient")??;
    ensure!(
        received == envelope
            && authority.recipient_account_id == bob.account
            && authority.key.actor == alice.actor
            && authority.key.authorization_ref == alice.authorize_event_id,
        "native relay changed its original encrypted frame or accepted endpoints"
    );
    let expected = alice.key.verifying_key().to_bytes();
    ensure!(
        arkret_canonical::base64url_decode(authority.key.public_key_base64url.as_str())?
            == expected,
        "recipient was given a substituted producer key"
    );
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: expected.to_vec(),
    };
    let plaintext = recipient.open_signal_envelope(
        &received,
        arkret::mls::SignalSenderAuthority::AccountDevice {
            public_key: &key,
            device_authorize_event_id: &alice.authorize_event_id,
        },
        state.as_str(),
        &head.commit_id,
        &mut arkret::AeadNonceReplayTracker::default(),
    )?;
    let opened = arkret_models_collaboration::signal_plaintext::open_signal_plaintext(&plaintext)?;
    ensure!(
        opened.signal_class() == SignalClass::Session && opened.payload_sequence() == 1,
        "native recipient did not authenticate and decrypt the actual sender's payload"
    );
    let after = history(database, realm).await?;
    ensure!(
        before == after,
        "peer Signal wrote canonical Event or Commit history"
    );
    let authorize = mls::accepted_full_view(&alice.client, &alice.authorize_event_id).await?;
    Ok(
        json!({"request":request,"status":status.as_u16(),"response_base64url":arkret_canonical::base64url_encode(&raw),"received":received,"delivery_authority":authority,"plaintext_base64url":arkret_canonical::base64url_encode(&plaintext),"before":before,"after":after,"sender_authorize":authorize,"snapshot":snapshot}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    let authorize: arkret_wire::CommittedEventFullView =
        serde_json::from_value(evidence["sender_authorize"].clone())?;
    verify_native_station_commits(observations, &[authorize])?;
    for exchange in &observations.exchanges {
        if exchange.operation_id.as_str() == "ak.peer.signal.command.relay.v1" {
            let input = verify_native_station_http_request(observations, exchange, &[])?;
            ensure!(
                input.expires - input.created <= 5
                    && !exchange
                        .explicit_request_headers
                        .contains_key("idempotency-key")
                    && exchange.response_status == 204,
                "peer Signal lost its short-lived single-attempt transport contract"
            );
        }
    }
    Ok(())
}
