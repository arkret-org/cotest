//! Actual Inkson local message authoring, durable unknown outcome and cold replay.
use anyhow::{Context as _, Result, bail, ensure};
use arkret::{ArkretMlsGroup, EventKind, ScopeRef};
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
use cotest::scenarios::mls_lifecycle_live::{Member, MlsClientObserver};

use super::account_blocklist_projection::{native_account_session, native_call_endpoint};

pub async fn run_native_message_unknown_cold_recovery() -> Result<()> {
    let observer = MessageObserver;
    Box::pin(
        cotest::scenarios::mls_lifecycle_live::run_with_blocklist_observer(Some(&observer), false),
    )
    .await
}

struct MessageObserver;

async fn message_footprint(
    station: &cotest::harness::ArkretServer,
    realm: &arkret::RealmId,
) -> Result<(i64, i64)> {
    let database = station
        .configured_database_url()
        .context("message conformance requires the actual isolated PostgreSQL")?
        .to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let row = db.query_one(
            "SELECT (SELECT count(*) FROM canonical_events WHERE realm_id=$1 AND envelope->>'kind'='ak.message.create'), \
             (SELECT count(*) FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE e.realm_id=$1 AND e.envelope->>'kind'='ak.message.create')",
            &[&realm],
        )?;
        Ok((row.get(0), row.get(1)))
    }).await?
}

#[async_trait::async_trait(?Send)]
impl MlsClientObserver for MessageObserver {
    async fn observe_ordinary_call_invite(
        &self,
        sender: &Member,
        holder: &Member,
        station: &cotest::harness::ArkretServer,
        realm: &arkret::RealmId,
        accepted_group: &arkret::EventId,
        sender_group: &mut ArkretMlsGroup,
        holder_group: &ArkretMlsGroup,
        _observe_receipt: bool,
    ) -> Result<()> {
        ensure!(
            !_observe_receipt,
            "message evidence requires the ordinary MLS lifecycle"
        );
        eprintln!("[native-message-production] phase=independent_accepted_mls_executor");
        // Keep the real lifecycle leases alive while the product send and cold
        // recovery run without the provisioning future's aggregate poll frames.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()?;
                    runtime.block_on(tokio::task::LocalSet::new().run_until(
                        cotest::harness::heap_future(|| {
                            run_message_case(
                                sender,
                                holder,
                                station,
                                realm,
                                accepted_group,
                                sender_group,
                                holder_group,
                            )
                        }),
                    ))
                })
                .join()
                .map_err(|_| anyhow::anyhow!("native message worker panicked"))?
        })
    }
}

async fn run_message_case(
    sender: &Member,
    holder: &Member,
    station: &cotest::harness::ArkretServer,
    realm: &arkret::RealmId,
    accepted_group: &arkret::EventId,
    sender_group: &mut ArkretMlsGroup,
    holder_group: &ArkretMlsGroup,
) -> Result<()> {
    let session = native_account_session(&sender.client).await?;
    let directory = tempfile::tempdir()?;
    let host = Box::pin(native_call_endpoint(
        sender,
        realm,
        accepted_group,
        sender_group,
        &directory.path().join("message.json"),
    ))
    .await?;
    host.refresh_authoring_authority().await?;
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let strand = arkret::StrandId::new(sender.client.default_strand_id(realm.as_str())?)?;
    let before = inkson::conformance::native_private_mls_record(&host, &scope)?;
    let footprint = message_footprint(station, realm).await?;
    let body =
        "Production Inkson author once, lose accepted response, recover original after cold reopen";
    let lost =
        inkson::conformance::MessageResponseLoss::arm(sender.account.clone(), scope.clone())?;
    let (original, original_commit) = {
        let send =
            inkson::conformance::send_native_ordinary_mls_message(&host, realm, &strand, body);
        tokio::pin!(send);
        tokio::time::timeout(std::time::Duration::from_secs(90), async {
                tokio::select! {
                    outcome = &mut send => bail!("message finished before the real accepted-response crash point: {outcome:?}"),
                    request = lost.accepted() => request,
                }
            }).await.context("real Inkson message did not reach authenticated SUT admission")??
        // Dropping `send` here models process loss before consuming the
        // genuine accepted reply. Queue and private state are already durable.
    };
    drop(lost);
    let SelfAuthoritySubmitRequest::Event(submission) = &original else {
        bail!("ordinary author produced a non Event request");
    };
    ensure!(submission.event.kind == EventKind::MessageCreate);
    ensure!(submission.event.actor_id == sender.actor && submission.event.scope_ref == scope);
    let event_id = submission.event.event_id.clone();
    let exact_bytes = arkret_canonical::canonical_json_bytes(&original)?;
    let after = inkson::conformance::native_private_mls_record(&host, &scope)?;
    ensure!(
        before.serialized_state != after.serialized_state,
        "real sender ratchet never advanced"
    );
    let unknown = inkson::conformance::native_ordinary_outbound_snapshot(&host).await?;
    let item = unknown
        .items
        .iter()
        .find(|item| item.event_id() == &event_id)
        .context("accepted response loss did not preserve a durable queue item")?;
    ensure!(
        item.status != garth::SendQueueStatus::Committed && item.attempts == 1,
        "client consumed the lost authority response"
    );
    ensure!(arkret_canonical::canonical_json_bytes(item.request())? == exact_bytes);
    let disk = host.state_store().conformance_reopen();
    drop(host);
    drop(session);

    // Rebuild the authenticated runtime and state from their actual durable
    // origins. Never invoke the send/author/encrypt entry again.
    let restored_session = native_account_session(&sender.client).await?;
    let cold = inkson::sync_engine::NativeAccountHost::new_for_realm(
        restored_session.client(),
        sender.account.clone(),
        sender.device.clone(),
        disk,
        realm.clone(),
    )
    .await?;
    ensure!(
        inkson::conformance::native_private_mls_record(&cold, &scope)?.serialized_state
            == after.serialized_state,
        "account durable flush did not preserve the sender ratchet before private-cache hydration"
    );
    cold.state_store_handle()
        .write(inkson::conformance::hydrate_native_private_cache)?;
    ensure!(
        inkson::conformance::native_private_mls_record(&cold, &scope)?.serialized_state
            == after.serialized_state,
        "cold state lost the once-consumed sender ratchet"
    );
    let reopened = inkson::conformance::native_ordinary_outbound_snapshot(&cold).await?;
    ensure!(
        arkret_canonical::canonical_json_bytes(
            reopened
                .items
                .iter()
                .find(|item| item.event_id() == &event_id)
                .context("cold queue lost original")?
                .request()
        )? == exact_bytes
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(90),
        inkson::conformance::drain_native_ordinary_messages(&cold),
    )
    .await
    .context("original durable drain did not complete")??;
    let settled = inkson::conformance::native_ordinary_outbound_snapshot(&cold).await?;
    let final_item = settled
        .items
        .iter()
        .find(|item| item.event_id() == &event_id)
        .context("drain discarded original queue identity")?;
    ensure!(
        final_item.status == garth::SendQueueStatus::Committed,
        "cold drain did not restore acceptance: {:?}",
        final_item.status
    );
    ensure!(
        final_item.commit() == Some(&original_commit),
        "cold queue recovered a different acceptance Commit"
    );
    ensure!(arkret_canonical::canonical_json_bytes(final_item.request())? == exact_bytes);
    let final_state = inkson::conformance::native_private_mls_record(&cold, &scope)?;
    ensure!(
        final_state.serialized_state == after.serialized_state,
        "cold replay consumed another MLS sender generation"
    );
    ensure!(
        message_footprint(station, realm).await? == (footprint.0 + 1, footprint.1 + 1),
        "unknown recovery authored or committed a second Message"
    );
    let accepted = holder.client.sdk().committed_event_get(&event_id).await?;
    ensure!(
        accepted.commit() == &original_commit,
        "recipient received a different acceptance Commit"
    );
    ensure!(
        accepted.reducer_input() == Some(&submission.event),
        "recipient received a substituted Event"
    );
    let payload: arkret::MessageCreatePayload =
        serde_json::from_value(serde_json::to_value(&submission.event.payload)?)?;
    let envelope = payload
        .encrypted_content
        .context("ordinary Message lost ciphertext")?;
    let header = envelope.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope,
        EventKind::MessageCreate.as_str(),
        String::from_utf8(arkret::mls_basic_credential_identity(&sender.actor)?)?,
        None,
    )?;
    let encrypted = arkret::encrypted_envelope_to_payload_with_verified_header(&envelope, header)?;
    let mut receiver =
        ArkretMlsGroup::restore_from_state_record(&holder_group.export_state_record()?)?;
    let plain = receiver.decrypt_payload(&encrypted)?;
    ensure!(
        plain == arkret_canonical::canonical_json_bytes(&arkret::ContentBlock::text(body))?,
        "real recipient could not open original ciphertext"
    );
    // The surrounding actual lifecycle continues from exactly this sender
    // state, not the stale pre-test provider.
    *sender_group = ArkretMlsGroup::restore_from_state_record(&final_state)?;
    eprintln!(
        "[native-message-production] product_author_queue_submit=1 actual_admission=1 unknown_response=1 cold_reopen=1 exact_signed_bytes=1 sender_generation_once=1 event_commit_once=1 recipient_decrypt=1"
    );
    Ok(())
}
