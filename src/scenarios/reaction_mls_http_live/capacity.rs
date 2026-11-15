//! Storage-formed legal shape followed by actual whole-Snapshot HTTP reads.
//! Seed Events traverse the production UoW, not a claimed per-Event HTTP lane.

use std::sync::Arc;

use coland_services::authority_commit::AuthorityCommitApplication;
use coland_services::persistence::PersistenceHandle;
use coland_storage::{EventBatchCommitRequest, EventCommitRequest, EventCommitUnitOfWork};
use coland_storage_postgres::{Db, PgEventCommitUnitOfWork, PgPersistenceStore, PoolTuning};

use super::*;

const BATCH: usize = 64;
const HOUR_MS: i64 = 3_600_000;
// Each item is one NFC scalar and an established Unicode emoji. No profile
// short tag or artificial key padding supplies this capacity domain.
const EMOJIS: [&str; 10] = ["👍", "👎", "😂", "🎉", "🔥", "👀", "🚀", "✅", "😀", "😎"];

pub(super) async fn footprint(station: &ArkretServer, realm: &RealmId) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("owned PostgreSQL absent")?
        .to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || ->Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let mut result=serde_json::Map::new();
        for table in ["canonical_events","realm_commits","projection_events","message_reactions_current_states","current_state_heads","realm_authorities","event_approval_private_audit"] {
            let sql=format!("SELECT jsonb_build_object('count',count(*),'rows_sha256',encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text,'UTF8')),'hex')) FROM {table} t WHERE realm_id=$1");
            result.insert(table.into(),db.query_one(&sql,&[&realm])?.get(0));
        }
        for table in ["federation_outbox","event_federation_outbox","capability_quota_consumptions","capability_quota_counters","capability_quota_buckets","content_key_domains","content_original_roots"] {
            let sql=format!("SELECT jsonb_build_object('count',count(*),'rows_sha256',encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text,'UTF8')),'hex')) FROM {table} t");
            result.insert(table.into(),db.query_one(&sql,&[])?.get(0));
        }
        Ok(Value::Object(result))
    }).await?
}

pub(super) async fn reject_domain_mutations(
    station: &ArkretServer,
    member: &Member,
    realm: &RealmId,
    candidates: &[(&str, Event, reqwest::StatusCode, arkret_wire::ErrorCode)],
) -> Result<()> {
    for (label, candidate, expected_status, expected_code) in candidates {
        let before = footprint(station, realm).await?;
        let submission = crate::publication::initial_submission(candidate.clone(), "")?;
        let response = member
            .client
            .post("/_arkret/self/events")
            .json(&submission)
            .send()
            .await?;
        let status = response.status();
        let problem: arkret_wire::Problem = response.json().await?;
        ensure!(
            status == *expected_status && problem.error_code() == Some(*expected_code),
            "{label} did not return its exact registered refusal: {status} {problem:?}"
        );
        ensure!(
            footprint(station, realm).await? == before,
            "{label} changed durable business effects"
        );
    }
    Ok(())
}

fn batch(events: Vec<EventCommitRequest>) -> EventBatchCommitRequest {
    EventBatchCommitRequest {
        audit_unit: None,
        events,
        realm_organization_proof: None,
        event_approvals: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    }
}

fn source(request: &EventCommitRequest) -> arkret_wire::CommittedEventRef {
    let transaction = &request.authority_commit;
    arkret_wire::CommittedEventRef {
        event_id: transaction.event.event_id.clone(),
        commit_id: transaction.commit.commit_id.clone(),
        stream_ref: transaction.commit.stream_ref.clone(),
        stream_position: transaction.commit.stream_position,
    }
}

fn request(transaction: coland_storage::AuthorityCommitTransaction) -> Result<EventCommitRequest> {
    let event = &transaction.event;
    let fact = transaction
        .producer_signer_fact
        .as_ref()
        .and_then(|fact| fact.as_account_device())
        .context("native accepted Account Device source absent")?;
    let selector = coland_storage::DeviceRevocationGateSelector {
        principal_id: fact
            .actor
            .as_account_id()
            .context("native Account actor")?
            .principal_id
            .clone(),
        station_id: fact
            .actor
            .as_account_id()
            .context("native Account actor")?
            .station_id
            .clone(),
        device_id: event
            .account_device_producer()?
            .context("native producer")?
            .device_id
            .to_string(),
        authorization_ref: fact.key.authorization_ref.clone(),
    };
    let suite = event.realm_id.digest_suite_code().digest_suite();
    let canonical_bytes = arkret_canonical::canonical_json_bytes(&event.digest_payload()?)?;
    let record = coland_storage::CanonicalEventRecord {
        event_id: event.event_id.to_string(),
        actor_id: event.actor_id.to_string(),
        realm_id: Some(event.realm_id.to_string()),
        kind: event.kind.as_str().into(),
        schema_id: arkret_wire::SchemaId::EVENT_V1.into(),
        digest_suite: suite,
        canonical_digest: event.event_digest_with_digest_suite(suite)?,
        canonical_bytes,
        envelope: serde_json::to_value(event)?,
        received_at: transaction.commit.committed_at,
    };
    let projection = coland_storage::ProjectionEventRecord {
        event_id: event.event_id.to_string(),
        realm_id: event.realm_id.to_string(),
        event_kind: event.kind.as_str().into(),
        operation_kind: "create".into(),
        operation_id: None,
        sender: Some(event.actor_id.to_string()),
        payload: json!(event.payload),
        created_at: event.created_at,
        received_at: transaction.commit.committed_at,
    };
    Ok(EventCommitRequest {
        verified_media_participant: None,
        self_producer_guard: Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
            selector,
        )),
        applet_producer_guard: None,
        widget_token_gate: None,
        agent_grant_scope_evidence: None,
        forwarded_producer_evidence: None,
        owner_transfer_successor: None,
        forwarded_agent_producer: None,
        agent_deployment_ceiling:
            arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
        event: record,
        parent_membership_admission: None,
        contact_projection: None,
        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: vec![projection],
        idempotency: None,
        outbox: Vec::new(),
        realm_fanout_source: Some(arkret_wire::EventAdmissionSubmission::new(event.clone())),
        authority_commit: transaction,
    })
}

struct Seed<'a> {
    station: &'a ArkretServer,
    member: &'a Member,
    realm: &'a RealmId,
    target: &'a EventId,
    application: AuthorityCommitApplication,
    method: arkret_wire::DidUrl,
    group: ArkretMlsGroup,
    reference: EventId,
    template: arkret_models_crypto::EventContentMaterial,
    root: arkret_models_crypto::ContentRootSecret,
    not_before: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    first_window: u64,
    window_count: usize,
    max_keys: usize,
    tags: std::collections::BTreeMap<String, usize>,
}

impl Seed<'_> {
    fn coordinates(&self, index: usize) -> Result<(DateTime<Utc>, &'static str)> {
        let offset = index / EMOJIS.len();
        ensure!(
            offset < self.window_count,
            "real accepted Device hour domains exhausted"
        );
        let window = self
            .first_window
            .checked_add(u64::try_from(offset)?)
            .context("hour overflow")?;
        let millis = i64::try_from(window)?
            .checked_mul(HOUR_MS)
            .and_then(|v| v.checked_add(1))
            .context("timestamp overflow")?;
        let at = DateTime::from_timestamp_millis(millis).context("hour timestamp unavailable")?;
        ensure!(
            at >= self.not_before && at < Utc::now() && self.expires_at.is_none_or(|end| at < end),
            "Reaction display time left its actual Device window"
        );
        Ok((at, EMOJIS[index % EMOJIS.len()]))
    }

    fn key(&self, index: usize) -> Result<String> {
        let (at, emoji) = self.coordinates(index)?;
        tag(&self.group, self.group.scope(), self.target, at, emoji)
    }

    async fn prepare(
        &mut self,
        first: usize,
        count: usize,
        kind: EventKind,
    ) -> Result<Vec<EventCommitRequest>> {
        let mut events = Vec::with_capacity(count);
        for index in first..first + count {
            let (at, emoji) = self.coordinates(index)?;
            let key = self.key(index)?;
            if let Some(previous) = self.tags.insert(key.clone(), index) {
                ensure!(previous == index, "distinct valid routing domains collided");
            }
            let mut event=self.member.client.author_event(self.realm.as_str(),kind.as_str(),
                json!({"target_ref":arkret_wire::MessageId::from_event_id(self.target),"key":key})).await?;
            event.created_at = at;
            sign_now(self.member, &mut event)?;
            // The actual backup PUT qualified only this immutable root and
            // protection set. Each new intent still needs its own salt,
            // outer Event projection and real SDK key commitment.
            let mut context = self.template.content_context.clone();
            context.content_key_salt = arkret::crypto::content_history::fresh_content_key_salt()?;
            let content_key =
                arkret::crypto::content_history::derive_content_key(&self.root, &context)?;
            let commitment =
                arkret::crypto::content_history::content_key_commitment(&context, &content_key)?;
            let material = arkret_models_crypto::EventContentMaterial {
                content_context: context,
                outer_event: arkret_models_crypto::EventContentMaterial::outer_event_for(&event)?,
                protection: self.template.protection.clone(),
                key_commitment: commitment,
            };
            let header = arkret::EventContentPreEncryptionHeader::reconstruct(
                "1.0",
                CONTENT_TYPE,
                arkret::EncryptedPayloadScheme::EpochContentAead,
                self.group.scope().clone(),
                kind.as_str(),
                self.group.epoch(),
                self.reference.clone(),
                self.group.local_content_sender_domain()?,
                arkret::EventContentRoutingContext::Reaction {
                    target_ref: self.target.clone(),
                    routing_window: window(at)?,
                    routing_tag: key,
                },
                material,
            )?;
            let plaintext = arkret_canonical::canonical_json_bytes(&json!({"key":emoji}))?;
            let encrypted = self.group.encrypt_payload(header, &plaintext)?;
            event.payload.insert(
                "encrypted_payload".into(),
                serde_json::to_value(encrypted.to_envelope()?)?,
            );
            sign_now(self.member, &mut event)?;
            events.push(event);
        }
        let method = self.method.clone();
        let signing = self.station.federation_signing_key()?;
        let facts = vec![None; events.len()];
        let transactions = heap_future(|| {
            self.application.prepare_registered_event_transactions(
                &events,
                self.station.service_id(),
                method,
                &signing,
                Utc::now(),
                &facts,
            )
        })
        .await?;
        transactions.into_iter().map(request).collect()
    }
}

pub(super) async fn run() -> Result<()> {
    let (station, member, realm, target) = fixture("reaction-whole-http-capacity-native").await?;
    ensure!(
        EMOJIS
            .iter()
            .all(|emoji| emoji.chars().count() == 1 && arkret_canonical::to_nfc(emoji) == *emoji)
    );
    let authorization =
        lifecycle::accepted_full_view(&member.client, &member.authorize_event_id).await?;
    let authorization: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(json!(authorization.event.payload))?;
    let now = Utc::now();
    let expiry = authorization.expires_at.flatten();
    ensure!(
        authorization.device_id == member.device
            && authorization.not_before <= now
            && expiry.is_none_or(|end| now < end),
        "actual Device is not eligible for this capacity supply"
    );
    let lower = authorization.not_before.timestamp_millis();
    let first_hour = lower.div_euclid(HOUR_MS) + i64::from(lower.rem_euclid(HOUR_MS) != 0);
    let last_hour = now.timestamp_millis().div_euclid(HOUR_MS) - 1;
    ensure!(
        last_hour >= first_hour,
        "no complete past Device-authorized Reaction hour"
    );
    let window_count = usize::try_from(last_hour - first_hour + 1)?;
    let first_window = u64::try_from(first_hour)?;
    let domain_count = window_count
        .checked_mul(EMOJIS.len())
        .context("domain count overflow")?;
    let first_at = DateTime::from_timestamp_millis(
        first_hour
            .checked_mul(HOUR_MS)
            .and_then(|v| v.checked_add(1))
            .context("first hour overflow")?,
    )
    .context("first hour timestamp")?;
    let (mut group, genesis) = heap_future(|| genesis(&member, &realm)).await?;
    let current = current_group(&snapshot(&member, &realm).await?, group.scope())?;
    ensure!(
        current.epoch == group.epoch()
            && current.current_mls_commit_event_ref == genesis.event.event_id
            && current.covered_key_access_revision >= current.current_key_access_revision
    );
    // This first actual HTTP admission qualifies the oldest usable display
    // window and root custody before the expensive native fill begins.
    let first_domain = Domain {
        reference: &genesis.event.event_id,
        target: &target,
        at: first_at,
    };
    let first =
        heap_future(|| seal(&member, &mut group, &first_domain, EventKind::ReactionAdd)).await?;
    let first = submit(&member, &first).await?;
    let envelope: EncryptedEnvelope =
        serde_json::from_value(first.event.payload["encrypted_payload"].clone())?;
    let template =
        crate::harness::content::original_material(&member.client, &group, &first.event, &envelope)
            .await?;
    let root = group.export_content_root(&template.content_context.root_context)?;
    let initial = snapshot(&member, &realm).await?;
    let initial_set = reactions(&initial, &target)?;
    ensure!(
        initial_set.entries().len() == 1,
        "capacity fixture did not start from one actual accepted entry"
    );
    let entry = &initial_set.entries()[0];
    ensure!(
        entry.actor_id == member.actor
            && json!(entry.key) == first.event.payload["key"]
            && entry.key.len() == 43
            && entry.key.is_ascii()
            && entry.source.event_id == first.event.event_id
            && entry.source.commit_id == first.commit.commit_id
            && entry.source.stream_ref == first.commit.stream_ref
            && entry.source.stream_position == first.commit.stream_position
    );
    let entry_bytes = arkret_canonical::canonical_json_bytes(entry)?.len();
    // All subsequent entries have this same Actor/stream and fixed-width
    // 43-byte tags and suite tokens. Their positive source positions only
    // grow in digit width. Thus b+one comma is a lower bound, not a fake row.
    let max_keys = coland_storage::MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES / (entry_bytes + 1) + 2;
    ensure!(
        domain_count >= max_keys,
        "actual Device offers {domain_count} valid domains, fewer than the rigorous capacity upper bound {max_keys}"
    );
    println!(
        "reaction capacity supply: windows={window_count}, emojis={}, legal_domains={domain_count}, actual_actor_jcs_bytes={}, actual_first_entry_bytes={entry_bytes}, sufficient_entry_bound={max_keys}",
        EMOJIS.len(),
        arkret_canonical::canonical_json_bytes(&member.actor)?.len()
    );
    let db = Db::connect(station.owned_database_url(), PoolTuning::default()).await?;
    let pool = db.pool.context("native PostgreSQL pool absent")?;
    let application = AuthorityCommitApplication::new(
        PersistenceHandle::new(Arc::new(PgPersistenceStore::new(pool.clone()))),
        0,
    );
    let uow = PgEventCommitUnitOfWork::new(pool);
    let mut seed = Seed {
        station: &station,
        member: &member,
        realm: &realm,
        target: &target,
        application,
        method: first.commit.signature.verification_method.clone(),
        group,
        reference: genesis.event.event_id,
        template,
        root,
        not_before: authorization.not_before,
        expires_at: expiry,
        first_window,
        window_count,
        max_keys,
        tags: std::collections::BTreeMap::new(),
    };
    let first_key = seed.key(0)?;
    ensure!(
        json!(first_key) == first.event.payload["key"],
        "domain index0 differs from the real HTTP sample"
    );
    seed.tags.insert(first_key, 0);
    let mut active = 1usize;
    let mut accepted_sources = vec![entry.source.clone()];
    let mut last = None;
    loop {
        ensure!(
            active < seed.max_keys,
            "native capacity was not enforced within the rigorous legal-domain bound"
        );
        let count = BATCH.min(seed.max_keys - active);
        let prepared = heap_future(|| seed.prepare(active, count, EventKind::ReactionAdd)).await?;
        let candidate = prepared.last().context("empty native batch")?.clone();
        let candidate_sources = prepared.iter().map(source).collect::<Vec<_>>();
        let before = footprint(&station, &realm).await?;
        match uow.commit_event_batch(batch(prepared)).await {
            Ok(_) => {
                active += count;
                accepted_sources.extend(candidate_sources);
                last = Some(candidate);
            }
            Err(error) => {
                ensure!(
                    error.conflict_code()
                        == Some(coland_storage::ConflictCode::SnapshotCapacityExceeded),
                    "unexpected native fill refusal: {error}"
                );
                ensure!(
                    footprint(&station, &realm).await? == before,
                    "capacity rejection changed the native transaction"
                );
                break;
            }
        }
    }
    let mut refused = false;
    for _ in 0..BATCH {
        let prepared = heap_future(|| seed.prepare(active, 1, EventKind::ReactionAdd))
            .await?
            .remove(0);
        let before = footprint(&station, &realm).await?;
        match uow.commit_event(prepared.clone()).await {
            Ok(_) => {
                active += 1;
                accepted_sources.push(source(&prepared));
                last = Some(prepared);
            }
            Err(error) => {
                ensure!(
                    error.conflict_code()
                        == Some(coland_storage::ConflictCode::SnapshotCapacityExceeded),
                    "unexpected final native fill refusal: {error}"
                );
                ensure!(
                    footprint(&station, &realm).await? == before,
                    "last refused Event left effects"
                );
                refused = true;
                break;
            }
        }
    }
    ensure!(
        refused && active > 2,
        "real last allowed shape was not reached"
    );
    let last = last.context("no accepted active entries")?;
    let before = footprint(&station, &realm).await?;
    ensure!(
        !uow.commit_event(last).await?.event_inserted,
        "exact native replay inserted another Event"
    );
    ensure!(
        footprint(&station, &realm).await? == before,
        "exact native replay changed original/current"
    );
    // Reclaim enough room for real issuance timestamp-width variation through
    // actual removes, not by deleting current rows or padding a synthetic body.
    for index in 0..2 {
        let remove = heap_future(|| seed.prepare(index, 1, EventKind::ReactionRemove))
            .await?
            .remove(0);
        uow.commit_event(remove).await?;
    }
    let snapshot = snapshot(&member, &realm).await?;
    let set = reactions(&snapshot, &target)?;
    ensure!(
        set.entries().len() == active - 2,
        "whole HTTP Snapshot clipped active Reaction entries"
    );
    let by_key = set
        .entries()
        .iter()
        .map(|entry| (entry.key.as_str(), entry))
        .collect::<std::collections::BTreeMap<_, _>>();
    ensure!(accepted_sources.len() == active);
    for (index, source) in accepted_sources.iter().enumerate().skip(2) {
        let expected_key = seed.key(index)?;
        let entry = by_key
            .get(expected_key.as_str())
            .context("HTTP omitted an actual accepted active key")?;
        ensure!(
            entry.actor_id == member.actor && &entry.source == source,
            "HTTP changed an accepted active key's actual Event/Commit/source coordinate"
        );
    }
    let bytes = arkret_canonical::canonical_json_bytes(&snapshot)?;
    ensure!(
        bytes.len() <= coland_storage::MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES,
        "HTTP returned an oversized complete signed body"
    );
    ensure!(
        bytes.len() >= coland_storage::MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES - 16 * 1024,
        "a small/filtered shape cannot prove the near-capacity whole HTTP boundary"
    );
    let source = member
        .client
        .sdk()
        .own_station_result_client()?
        .context("native own-Station source absent")?;
    let exact = source
        .snapshot_by_ref(&realm, &snapshot.snapshot_id)
        .await?;
    ensure!(
        arkret_canonical::canonical_json_bytes(exact.value()?)? == bytes,
        "by-ref HTTP changed the exact issued whole object"
    );
    source.check_session()?;
    println!(
        "reaction HTTP composition passed: {active} storage-admitted keys, {} whole signed bytes, native over-budget rollback and {} HTTP-visible active keys; seed Events were not per-Event HTTP submissions",
        bytes.len(),
        active - 2
    );
    Ok(())
}
