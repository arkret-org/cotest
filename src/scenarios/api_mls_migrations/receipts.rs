//! Opaque receipt transport and typed accepted policy. Client UI is a separate consumer.

use anyhow::{Context, Result, ensure};
use arkret::mls::SignalSenderAuthority;
use arkret::{
    ArkretMlsGroup, EventId, RealmCommitId, RealmId, ScopeRef, SignalClass, SignalEnvelope,
    SignalStreamFrame,
};
use arkret_models_collaboration::signal_plaintext::{ReadReceipt, SignalPlaintext};
use chrono::{Duration, Utc};
use serde_json::json;

use super::{MlsApiContext, scan};
use crate::scenarios::mls_lifecycle_live::Member;

#[allow(clippy::too_many_arguments)]
fn envelope(
    sender: &Member,
    group: &mut ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    state: &EventId,
    head: &RealmCommitId,
    scope: &ScopeRef,
    parent: Option<&RealmCommitId>,
    event: &EventId,
    sequence: u64,
) -> Result<SignalEnvelope> {
    let receipt = ReadReceipt::new(
        sequence,
        sender.actor.clone(),
        event.clone(),
        arkret::ReadReceiptScope::strand(strand.to_owned(), Some("discussion")),
    )?;
    crate::scenarios::signal_live::scoped_envelope_with_payload(
        sender,
        group,
        realm,
        strand,
        state,
        head,
        SignalClass::Session,
        sequence,
        scope.clone(),
        parent,
        Some(arkret_canonical::canonical_json_bytes(&receipt)?),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn deliver(
    sender: &Member,
    receiver: &Member,
    sender_group: &mut ArkretMlsGroup,
    receiver_group: &ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    state: &EventId,
    scope: &ScopeRef,
    parent: Option<&RealmCommitId>,
    target: &EventId,
    sequence: u64,
) -> Result<()> {
    let head = scan(&sender.client, scope)
        .await?
        .committed_events
        .last()
        .context("receipt scope has no accepted head")?
        .commit()
        .commit_id
        .clone();
    let before = crate::scenarios::private_read_marker_api::list(&receiver.client, realm).await?;
    let mut stream = receiver.client.sdk().signal_subscribe_frames().await?;
    ensure!(
        matches!(
            stream.next_frame().await?,
            Some(SignalStreamFrame::Heartbeat)
        ),
        "receipt subscription omitted its initial heartbeat"
    );
    let signal = envelope(
        sender,
        sender_group,
        realm,
        strand,
        state,
        &head,
        scope,
        parent,
        target,
        sequence,
    )?;
    let outcome = sender.client.sdk().signal_send(&signal).await?;
    ensure!(
        outcome.accepted && outcome.envelope_digest == signal.envelope_digest()?,
        "receipt ingress did not bind the exact encrypted envelope"
    );
    let (received, authority) = tokio::time::timeout(std::time::Duration::from_secs(25), async {
        loop {
            match stream
                .next_frame()
                .await?
                .context("receipt stream closed before delivery")?
            {
                SignalStreamFrame::Heartbeat => {}
                SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } if envelope.proof.envelope_digest == signal.proof.envelope_digest => {
                    break Ok::<_, anyhow::Error>((envelope, delivery_authority));
                }
                _ => anyhow::bail!("unexpected receipt control or unrelated Signal"),
            }
        }
    })
    .await
    .context("receipt recipient delivery bound")??;
    ensure!(
        received == signal
            && authority.recipient_account_id == receiver.account
            && authority.key.actor == sender.actor
            && authority.key.authorization_ref == sender.authorize_event_id,
        "receipt relay changed its exact bytes or original accepted Device authority"
    );
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(authority.key.public_key_b64u.as_str())?,
    };
    let mut replay = arkret::AeadNonceReplayTracker::default();
    let bytes = receiver_group.open_signal_envelope(
        &received,
        SignalSenderAuthority::AccountDevice {
            public_key: &public,
            device_authorize_event_id: &authority.key.authorization_ref,
        },
        state.as_str(),
        &head,
        &mut replay,
    )?;
    let SignalPlaintext::ReadReceipt(receipt) =
        arkret_models_collaboration::signal_plaintext::open_signal_plaintext(&bytes)?
    else {
        anyhow::bail!("receipt plaintext dispatched to another registered product")
    };
    ensure!(
        receipt.actor_id == sender.actor
            && receipt.event_id == *target
            && receipt.payload_sequence == sequence
            && receipt.read_scope
                == arkret::ReadReceiptScope::strand(strand.to_owned(), Some("discussion")),
        "decrypted receipt changed its exact target or private discussion scope"
    );
    let wire = serde_json::to_value(&received)?;
    ensure!(
        wire.get("event_id").is_none()
            && wire.get("kind").is_none()
            && wire.get("read_scope").is_none(),
        "opaque envelope disclosed receipt plaintext routing"
    );
    let after = crate::scenarios::private_read_marker_api::list(&receiver.client, realm).await?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&before)?
            == arkret_canonical::canonical_json_bytes(&after)?,
        "ephemeral receipt created a durable marker"
    );
    Ok(())
}

async fn refused(
    client: &crate::harness::TestActorClient,
    signal: &SignalEnvelope,
    status: reqwest::StatusCode,
    code: &str,
) -> Result<()> {
    crate::harness::expect_api_error(
        client.post("/_arkret/self/signal").json(signal),
        status,
        code,
    )
    .await?;
    Ok(())
}

pub(super) async fn run(ctx: &mut MlsApiContext<'_>) -> Result<()> {
    let message = crate::scenarios::message_mls_cross_station_live::submit_and_open(
        ctx.source,
        ctx.holder,
        ctx.source_group,
        ctx.holder_group,
        ctx.realm,
        ctx.strand,
        ctx.state,
        "receipt encrypted target",
    )
    .await?;
    let scope = ScopeRef::Realm {
        realm_id: ctx.realm.clone(),
    };
    deliver(
        ctx.source,
        ctx.holder,
        ctx.source_group,
        ctx.holder_group,
        ctx.realm,
        ctx.strand,
        ctx.state,
        &scope,
        None,
        &message.event_ref,
        1,
    )
    .await?;
    let head = crate::scenarios::websocket_live::realm_head(&ctx.source.client, ctx.realm.as_str())
        .await?;
    let mut too_long = envelope(
        ctx.source,
        ctx.source_group,
        ctx.realm,
        ctx.strand,
        ctx.state,
        &head.commit_id,
        &scope,
        None,
        &message.event_ref,
        2,
    )?;
    too_long.expires_at = too_long.sent_at + Duration::milliseconds(30_001);
    crate::harness::attach_signal_proof(&mut too_long, &ctx.source.key);
    refused(
        &ctx.source.client,
        &too_long,
        reqwest::StatusCode::BAD_REQUEST,
        "signal_ttl_out_of_range",
    )
    .await?;
    let mut expired = envelope(
        ctx.source,
        ctx.source_group,
        ctx.realm,
        ctx.strand,
        ctx.state,
        &head.commit_id,
        &scope,
        None,
        &message.event_ref,
        3,
    )?;
    expired.sent_at =
        arkret_canonical::normalize_timestamp_canonical(Utc::now() - Duration::seconds(10));
    expired.expires_at = expired.sent_at + Duration::seconds(5);
    crate::harness::attach_signal_proof(&mut expired, &ctx.source.key);
    refused(
        &ctx.source.client,
        &expired,
        reqwest::StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;
    let mismatched = envelope(
        ctx.holder,
        ctx.holder_group,
        ctx.realm,
        ctx.strand,
        ctx.state,
        &head.commit_id,
        &scope,
        None,
        &message.event_ref,
        4,
    )?;
    refused(
        &ctx.source.client,
        &mismatched,
        reqwest::StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    let outsider = Member::provision(
        ctx.station,
        ctx.issuer,
        "receipt-outsider",
        &arkret_identifiers::new_prefixed_uuid7("ak:device:"),
    )
    .await?;
    // This negative preserves an opaque member ciphertext while the outsider
    // signs its own complete header; admission must fail before any recipient
    // tries AEAD opening. It is not a claim that the outsider holds the group.
    let mut unjoined = envelope(
        ctx.source,
        ctx.source_group,
        ctx.realm,
        ctx.strand,
        ctx.state,
        &head.commit_id,
        &scope,
        None,
        &message.event_ref,
        5,
    )?;
    unjoined.sender_actor_id = outsider.actor.clone();
    unjoined.sender_device_id = Some(outsider.device.clone());
    unjoined.proof.verification_method = outsider.method.clone();
    crate::harness::attach_signal_proof(&mut unjoined, &outsider.key);
    refused(
        &outsider.client,
        &unjoined,
        reqwest::StatusCode::FORBIDDEN,
        "signal_class_denied",
    )
    .await?;

    // Policy storage is a live Station contract. The receiver-side policy
    // vectors remain explicitly a protocol KAT, not a claim about a UI.
    for (index, (disclosure, visibility)) in [
        ("disabled", "members"),
        ("optional", "private"),
        ("optional", "members"),
    ]
    .into_iter()
    .enumerate()
    {
        let payload: arkret_models_collaboration::events_payloads::ReadReceiptPolicyPayload =
            serde_json::from_value(json!({"disclosure":disclosure,"visibility":visibility}))?;
        let event = ctx
            .source
            .client
            .author_event(
                ctx.realm.as_str(),
                "ak.scope.read_receipt_policy",
                serde_json::to_value(&payload)?,
            )
            .await?;
        let commit = crate::scenarios::human_device_producer_live::submit_and_expect_commit(
            &ctx.source.client,
            &ctx.source.account,
            ctx.source.device.as_str(),
            &event,
        )
        .await?;
        let snapshot = ctx
            .holder
            .client
            .sdk()
            .realm_state_snapshot_head(ctx.realm)
            .await?;
        use sha2::Digest as _;
        let request = arkret_wire::AuthorityBundleRequest {
            realm_id: ctx.realm.clone(),
            nonce: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                sha2::Sha256::digest(arkret_identifiers::new_prefixed_uuid7("ak:request:")),
            ))
            .map_err(anyhow::Error::msg)?,
        };
        let http = ctx.holder.client.sdk();
        let bundle = http.realm_authority_bundle(&request).await?;
        let service_id: arkret_identifiers::DidCoreId = ctx.source.client.service_id().parse()?;
        let resolution = http.open_service_resolution(&service_id).await?;
        ensure!(
            cotest_test_support::wire::verify_realm_state_snapshot(json!({
                "snapshot":snapshot,"expected_snapshot_id":snapshot.snapshot_id,
                "authority_request":request,"authority_bundle":bundle,
                "trusted_service_id":service_id,"service_resolution":resolution
            }))? == json!({"verified":true}),
            "receipt policy snapshot failed the shared cryptographic history/authority verifier"
        );
        let snapshot = serde_json::to_value(snapshot)?;
        let rows = snapshot["current_state_entries"]
            .as_array()
            .context("snapshot current rows")?
            .iter()
            .filter(|r| r["selector"]["kind"] == "scope_read_receipt_policy")
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1
                && rows[0]["value"] == serde_json::to_value(payload)?
                && rows[0]["source_stream_ref"] == serde_json::to_value(&commit.stream_ref)?
                && rows[0]["revision"]
                    == json!({"commit_id":commit.commit_id,"stream_position":commit.stream_position}),
            "receipt policy snapshot lost its exact accepted current revision"
        );
        // An encrypted relay cannot select a plaintext target or reader.
        deliver(
            ctx.source,
            ctx.holder,
            ctx.source_group,
            ctx.holder_group,
            ctx.realm,
            ctx.strand,
            ctx.state,
            &scope,
            None,
            &message.event_ref,
            6 + index as u64,
        )
        .await?;
    }
    crate::conformance::run_read_receipt_policy_fixture_suite()?;
    println!(
        "read_receipts: real encrypted delivery, exact accepted Device authority, no durable marker, TTL/expiry/actor/membership refusals, accepted policy current rows, separate receiver-policy KAT verified"
    );
    Ok(())
}
