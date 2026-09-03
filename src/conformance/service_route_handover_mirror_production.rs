//! Production-path closure for the service-route handover/mirror fixture.
//!
//! The schema runner deliberately remains implementation-neutral. This suite
//! complements it by driving Soland's real route store and resolver types, so
//! persistence ordering and cache/quarantine behavior cannot drift behind a
//! locally reimplemented fixture FSM.

use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow, bail, ensure};
use arkret_models_identity::{
    ServiceResolutionPublishAck, ServiceResolutionPublishAckCore, ServiceResolutionPublishRequest,
    ServiceResolutionRecord, ServiceResolutionRecordCore, ServiceRouteHandoverNotice,
    ServiceRouteHandoverNoticeCore, ServiceRouteHandoverState,
    canonical_service_current_record_path,
};
use arkret_wire::{
    Base64UrlString, Did, DidCoreId, DidUrl, Hash, ProtocolSignature, RealmId, RequestId,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use soland_services::service_route::{
    RouteSource, ServiceRouteFetcher, ServiceRouteResolver, VerifiedRouteCandidate,
    VerifiedServiceDescribeMetadata,
};
use soland_services::{ServiceError, ServiceResult};
use soland_storage::{
    ServiceResolutionForkEvidence, ServiceResolutionMirrorCommit, ServiceResolutionMirrorEntry,
    ServiceRouteStore,
};
use soland_storage_postgres::PgServiceRouteStore;
use soland_storage_postgres::test_database::TestDatabase;

use crate::transcripts::record_vector_event;

const SERVICE_KIND: &str = "station";

fn digest(value: &impl serde::Serialize) -> Result<Hash> {
    Ok(Hash::new(arkret_canonical::canonical_sha256(value)?)?)
}

fn service_id(did: &Did) -> Result<DidCoreId> {
    Ok(arkret_wire::project_did_to_core_id(did)?)
}

fn signature(did: &Did, created_at: DateTime<Utc>) -> Result<ProtocolSignature> {
    Ok(ProtocolSignature {
        verification_method: DidUrl::new(format!("{did}#assertion-1"))
            .map_err(|error| anyhow!(error))?,
        created_at,
        jws: Base64UrlString::new("AA".to_owned()).map_err(|error| anyhow!(error))?,
    })
}

fn record(
    full: &str,
    sequence: u64,
    previous_record_digest: Option<Hash>,
    base_url: &str,
) -> Result<ServiceResolutionRecord> {
    let did = Did::new(full)?;
    let service_id = service_id(&did)?;
    let issued_at = Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap();
    Ok(ServiceResolutionRecord {
        record: ServiceResolutionRecordCore {
            service_id: service_id.clone(),
            service_kind: SERVICE_KIND.to_owned(),
            did: did.clone(),
            method_history_head: format!("did-history-{sequence}-{base_url}"),
            version_id: format!("version-{sequence}"),
            resolution_event_ref: format!("did-webvh-entry-sha256:{sequence:064x}"),
            record_sequence: sequence,
            previous_record_digest,
            current_record_url: format!(
                "{}{}",
                base_url.trim_end_matches('/'),
                canonical_service_current_record_path(&service_id)
            ),
            base_url: base_url.to_owned(),
            describe_digest: Hash::new(format!("sha256:{}", "d".repeat(64)))?,
            issued_at,
            refresh_after: issued_at + Duration::minutes(30),
            expires_at: issued_at + Duration::hours(2),
        },
        proof: signature(&did, issued_at)?,
    })
}

fn scheduled_notice(
    floor_record: &ServiceResolutionRecord,
    floor_digest: Hash,
) -> Result<ServiceRouteHandoverNotice> {
    let issued_at = Utc.with_ymd_and_hms(2026, 8, 10, 0, 5, 0).unwrap();
    let candidate_base_url = "https://new-route.example/";
    Ok(ServiceRouteHandoverNotice {
        notice: ServiceRouteHandoverNoticeCore {
            service_id: floor_record.record.service_id.clone(),
            service_kind: floor_record.record.service_kind.clone(),
            handover_id: "ak:service_route_handover:019f0000-0000-7000-8000-000000000001"
                .to_owned(),
            notice_revision: 0,
            state: ServiceRouteHandoverState::Scheduled,
            from_record_sequence: floor_record.record.record_sequence,
            from_record_digest: floor_digest,
            candidate_base_url: Some(candidate_base_url.to_owned()),
            candidate_record_url: Some(format!(
                "{}{}",
                candidate_base_url.trim_end_matches('/'),
                canonical_service_current_record_path(&floor_record.record.service_id)
            )),
            issued_at,
            not_before: Some(issued_at + Duration::minutes(5)),
            cutover_at: Some(issued_at + Duration::minutes(10)),
            grace_until: Some(issued_at + Duration::minutes(20)),
            previous_notice_digest: None,
            expires_at: issued_at + Duration::minutes(30),
        },
        proof: signature(&floor_record.record.did, issued_at)?,
    })
}

fn mirror_entry(
    source_id: &DidCoreId,
    receiver_id: &DidCoreId,
    realm_id: &RealmId,
    request_id: &str,
    record: Option<ServiceResolutionRecord>,
    notice: Option<ServiceRouteHandoverNotice>,
    accepted_at: DateTime<Utc>,
) -> Result<ServiceResolutionMirrorEntry> {
    let artifact_digest = match (&record, &notice) {
        (Some(record), None) => digest(record)?,
        (None, Some(notice)) => digest(notice)?,
        _ => bail!("mirror helper requires exactly one artifact"),
    };
    let request = ServiceResolutionPublishRequest {
        request_id: RequestId::new(request_id)?,
        realm_id: realm_id.clone(),
        artifact_digest: artifact_digest.clone(),
        service_resolution_record: record,
        service_route_handover_notice: notice,
    };
    let artifact_key = request.validate()?;
    let request_digest = request.canonical_digest()?;
    let receiver_did = Did::new("did:web:mirror.example")?;
    let ack = ServiceResolutionPublishAck {
        ack: ServiceResolutionPublishAckCore {
            request_id: request.request_id.clone(),
            source_id: source_id.clone(),
            receiver_id: receiver_id.clone(),
            realm_id: realm_id.clone(),
            request_digest: request_digest.clone(),
            artifact_key: artifact_key.clone(),
            artifact_digest: artifact_digest.clone(),
            accepted_at,
        },
        proof: signature(&receiver_did, accepted_at)?,
    };
    Ok(ServiceResolutionMirrorEntry {
        source_id: source_id.clone(),
        realm_id: realm_id.clone(),
        request_id: request.request_id.clone(),
        request_digest,
        artifact_key,
        artifact_digest,
        request,
        ack,
        accepted_at,
    })
}

#[derive(Default)]
struct ProductionFetcher {
    current: Option<ServiceResolutionRecord>,
    notice: Option<ServiceResolutionRecord>,
    calls: Mutex<Vec<RouteSource>>,
}

impl ProductionFetcher {
    fn description(record: &ServiceResolutionRecord) -> VerifiedServiceDescribeMetadata {
        VerifiedServiceDescribeMetadata {
            service_id: record.record.service_id.clone(),
            service_kind: record.record.service_kind.clone(),
            service_resolution: arkret_models_identity::ResolutionCommitment {
                did: record.record.did.clone(),
                method_history_head: record.record.method_history_head.clone(),
                version_id: record.record.version_id.clone(),
            },
            http_json_base_url: record.record.base_url.clone(),
            route_binding_digest: record.record.describe_digest.clone(),
            trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:route.example")
                .expect("fixed trust domain"),
            protocol_version: "1".to_owned(),
        }
    }

    fn take_candidate(
        &self,
        source: RouteSource,
        record: &Option<ServiceResolutionRecord>,
    ) -> Option<VerifiedRouteCandidate> {
        self.calls
            .lock()
            .expect("fetch call log poisoned")
            .push(source);
        record.clone().map(|record| VerifiedRouteCandidate {
            source,
            description: Self::description(&record),
            record,
        })
    }

    fn calls(&self) -> Vec<RouteSource> {
        self.calls.lock().expect("fetch call log poisoned").clone()
    }
}

#[async_trait]
impl ServiceRouteFetcher for ProductionFetcher {
    async fn fetch_current(
        &self,
        _: &DidCoreId,
        _: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok(self.take_candidate(RouteSource::CurrentRecord, &self.current))
    }

    async fn fetch_notice_candidate(
        &self,
        _: &DidCoreId,
        _: &str,
    ) -> ServiceResult<Option<VerifiedRouteCandidate>> {
        Ok(self.take_candidate(RouteSource::ScheduledNotice, &self.notice))
    }
}

async fn exercise_atomic_mirror_store() -> Result<()> {
    let database = TestDatabase::lease().await;
    let store = PgServiceRouteStore {
        pool: database.pool(),
    };
    let source_did = Did::new("did:web:source.example")?;
    let receiver_did = Did::new("did:web:mirror.example")?;
    let source = service_id(&source_did)?;
    let receiver = service_id(&receiver_did)?;
    let realm = RealmId::new("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1")?;
    let accepted_at = Utc.with_ymd_and_hms(2026, 8, 10, 0, 6, 0).unwrap();
    let first = record(
        "did:webvh:z6mkstable:old.example",
        0,
        None,
        "https://old-route.example/",
    )?;
    let first_entry = mirror_entry(
        &source,
        &receiver,
        &realm,
        "ak:request:019f0000-0000-7000-8000-000000000001",
        Some(first.clone()),
        None,
        accepted_at,
    )?;
    let stored_ack = match store.commit_mirror(first_entry.clone()).await? {
        ServiceResolutionMirrorCommit::Stored(ack) => ack,
        outcome => bail!("first mirror commit was not stored: {outcome:?}"),
    };
    ensure!(stored_ack == first_entry.ack, "stored ACK bytes drifted");
    let floor = store
        .last_seen_floor(&first.record.service_id, SERVICE_KIND)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Stored returned without an atomic durable floor"))?;
    ensure!(
        floor.record_sequence == 0 && floor.record_digest == first_entry.artifact_digest,
        "Stored returned with a mismatched durable floor"
    );
    ensure!(
        matches!(
            store.commit_mirror(first_entry.clone()).await?,
            ServiceResolutionMirrorCommit::Replay(ref ack) if ack == &stored_ack
        ),
        "exact transport replay did not return the original ACK"
    );

    let conflicting = record(
        "did:webvh:z6mkstable:other.example",
        0,
        None,
        "https://conflict.example/",
    )?;
    let transport_conflict = mirror_entry(
        &source,
        &receiver,
        &realm,
        "ak:request:019f0000-0000-7000-8000-000000000001",
        Some(conflicting.clone()),
        None,
        accepted_at,
    )?;
    ensure!(
        matches!(
            store.commit_mirror(transport_conflict).await?,
            ServiceResolutionMirrorCommit::TransportConflict
        ),
        "same transport key accepted a different request digest"
    );
    let artifact_conflict = mirror_entry(
        &source,
        &receiver,
        &realm,
        "ak:request:019f0000-0000-7000-8000-000000000002",
        Some(conflicting),
        None,
        accepted_at,
    )?;
    ensure!(
        matches!(
            store.commit_mirror(artifact_conflict).await?,
            ServiceResolutionMirrorCommit::ArtifactConflict { .. }
        ),
        "same artifact key accepted a different artifact digest"
    );

    let notice = scheduled_notice(&first, first_entry.artifact_digest.clone())?;
    let notice_entry = mirror_entry(
        &source,
        &receiver,
        &realm,
        "ak:request:019f0000-0000-7000-8000-000000000003",
        None,
        Some(notice.clone()),
        accepted_at + Duration::seconds(1),
    )?;
    let notice_ack = match store.commit_mirror(notice_entry.clone()).await? {
        ServiceResolutionMirrorCommit::Stored(ack) => ack,
        outcome => bail!("scheduled notice commit was not stored: {outcome:?}"),
    };
    let notice_state = store
        .notice_state(
            &first.record.service_id,
            SERVICE_KIND,
            &notice.notice.handover_id,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("Stored notice ACK has no durable notice state"))?;
    ensure!(
        notice_state.notice_digest == notice_entry.artifact_digest
            && notice_state.from_record_digest == first_entry.artifact_digest,
        "notice state, record basis, and ACK were not committed atomically"
    );
    ensure!(
        matches!(
            store.commit_mirror(notice_entry).await?,
            ServiceResolutionMirrorCommit::Replay(ref ack) if ack == &notice_ack
        ),
        "notice exact replay did not return its original ACK"
    );

    let successor = record(
        "did:webvh:z6mkstable:new.example",
        1,
        Some(first_entry.artifact_digest.clone()),
        "https://new-route.example/",
    )?;
    let successor_entry = mirror_entry(
        &source,
        &receiver,
        &realm,
        "ak:request:019f0000-0000-7000-8000-000000000004",
        Some(successor.clone()),
        None,
        accepted_at + Duration::seconds(2),
    )?;
    ensure!(
        matches!(
            store.commit_mirror(successor_entry).await?,
            ServiceResolutionMirrorCommit::Stored(_)
        ),
        "exact successor record was not stored"
    );
    let resolved = store
        .successor_records(
            &source,
            &realm,
            &first.record.service_id,
            SERVICE_KIND,
            0,
            32,
        )
        .await?;
    ensure!(
        resolved == vec![successor]
            && store
                .latest_notice(&source, &realm, &first.record.service_id, SERVICE_KIND)
                .await?
                == Some(notice),
        "production resolve store did not return the committed successor/notice"
    );
    Ok(())
}

async fn resolve_with(
    store: Arc<PgServiceRouteStore>,
    expected: &DidCoreId,
    record: ServiceResolutionRecord,
    now: DateTime<Utc>,
) -> (
    ServiceResult<arkret_models_identity::ServiceRouteCacheEntry>,
    Arc<ProductionFetcher>,
) {
    let fetcher = Arc::new(ProductionFetcher {
        current: Some(record),
        ..ProductionFetcher::default()
    });
    let outcome = ServiceRouteResolver::new(store, fetcher.clone())
        .resolve(expected, SERVICE_KIND, now, true)
        .await;
    (outcome, fetcher)
}

async fn exercise_resolver_safety() -> Result<()> {
    let now = Utc.with_ymd_and_hms(2026, 8, 10, 0, 10, 0).unwrap();
    let first = record(
        "did:webvh:z6mkstable:old.example",
        0,
        None,
        "https://old-route.example/",
    )?;
    let expected = first.record.service_id.clone();
    let first_digest = digest(&first)?;
    let successor = record(
        "did:webvh:z6mkstable:new.example",
        1,
        Some(first_digest),
        "https://new-route.example/",
    )?;

    let restart_database = TestDatabase::lease().await;
    let restart_store = Arc::new(PgServiceRouteStore {
        pool: restart_database.pool(),
    });
    resolve_with(restart_store.clone(), &expected, first.clone(), now)
        .await
        .0?;
    let successor_entry = resolve_with(
        restart_store.clone(),
        &expected,
        successor.clone(),
        now + Duration::seconds(1),
    )
    .await
    .0?;
    ensure!(
        successor_entry.record_sequence == 1 && service_id(&successor_entry.did)? == expected,
        "same-core handover changed the service identity"
    );
    restart_store
        .evict_route_cache(&expected, SERVICE_KIND)
        .await?;
    let (restart_outcome, _) = resolve_with(
        restart_store.clone(),
        &expected,
        first.clone(),
        now + Duration::seconds(2),
    )
    .await;
    ensure!(
        matches!(restart_outcome, Err(ServiceError::Conflict(_)))
            && restart_store
                .last_seen_floor(&expected, SERVICE_KIND)
                .await?
                .is_some_and(|floor| floor.record_sequence == 1),
        "resolver restart/cache eviction lost the durable anti-rollback floor"
    );

    let replacement = record(
        "did:webvh:z6mkreplacement:new.example",
        0,
        None,
        "https://replacement.example/",
    )?;
    let replacement_id = replacement.record.service_id.clone();
    ensure!(
        replacement_id != expected,
        "replacement fixture did not change core id"
    );
    let (wrong_service_identity, _) = resolve_with(
        restart_store.clone(),
        &expected,
        replacement.clone(),
        now + Duration::seconds(3),
    )
    .await;
    ensure!(
        matches!(wrong_service_identity, Err(ServiceError::NotFound(_)))
            && restart_store
                .last_seen_floor(&replacement_id, SERVICE_KIND)
                .await?
                .is_none(),
        "new core route was accepted as the existing service identity"
    );
    let new_service_route = resolve_with(
        restart_store,
        &replacement_id,
        replacement,
        now + Duration::seconds(4),
    )
    .await
    .0?;
    ensure!(
        new_service_route.service_id == replacement_id,
        "new core route was not resolved under its own distinct service identity"
    );

    let quarantine_database = TestDatabase::lease().await;
    let quarantine_store = Arc::new(PgServiceRouteStore {
        pool: quarantine_database.pool(),
    });
    let cached = resolve_with(quarantine_store.clone(), &expected, first.clone(), now)
        .await
        .0?;
    quarantine_store
        .quarantine_fork(ServiceResolutionForkEvidence {
            service_id: expected.clone(),
            service_kind: SERVICE_KIND.to_owned(),
            artifact_family: "service_resolution_record".to_owned(),
            artifact_key: "0".to_owned(),
            accepted_digest: cached.record_digest.clone(),
            conflicting_digest: Hash::new(format!("sha256:{}", "f".repeat(64)))?,
            evidence: serde_json::json!({"source": "cotest-production"}),
            quarantined_at: now + Duration::seconds(1),
        })
        .await?;
    let cached_fetcher = Arc::new(ProductionFetcher::default());
    let quarantined = ServiceRouteResolver::new(quarantine_store, cached_fetcher.clone())
        .resolve(&expected, SERVICE_KIND, now + Duration::seconds(2), false)
        .await;
    ensure!(
        matches!(quarantined, Err(ServiceError::Conflict(_))) && cached_fetcher.calls().is_empty(),
        "resolver consulted cache/fetcher before durable quarantine"
    );

    let fork_database = TestDatabase::lease().await;
    let fork_store = Arc::new(PgServiceRouteStore {
        pool: fork_database.pool(),
    });
    resolve_with(fork_store.clone(), &expected, first.clone(), now)
        .await
        .0?;
    let fork = record(
        "did:webvh:z6mkstable:fork.example",
        0,
        None,
        "https://fork.example/",
    )?;
    let (fork_outcome, _) = resolve_with(
        fork_store.clone(),
        &expected,
        fork,
        now + Duration::seconds(1),
    )
    .await;
    ensure!(
        matches!(fork_outcome, Err(ServiceError::Conflict(_)))
            && fork_store.is_quarantined(&expected, SERVICE_KIND).await?
            && fork_store
                .route_cache(&expected, SERVICE_KIND)
                .await?
                .is_none(),
        "same-sequence fork did not quarantine and fail closed before cache"
    );
    let post_fork_fetcher = Arc::new(ProductionFetcher {
        current: Some(first),
        ..ProductionFetcher::default()
    });
    let post_fork = ServiceRouteResolver::new(fork_store, post_fork_fetcher.clone())
        .resolve(&expected, SERVICE_KIND, now + Duration::seconds(2), false)
        .await;
    ensure!(
        matches!(post_fork, Err(ServiceError::Conflict(_))) && post_fork_fetcher.calls().is_empty(),
        "fork quarantine allowed a later cache/fetch fallback"
    );
    Ok(())
}

/// Execute the fixture's safety claims through Soland production store and
/// resolver types rather than through the reference mini-FSM alone.
pub async fn run_service_route_handover_mirror_production_suite() -> Result<()> {
    exercise_atomic_mirror_store().await?;
    exercise_resolver_safety().await?;
    record_vector_event(
        "service_route_handover_mirror.production",
        &serde_json::json!({"store": "PgServiceRouteStore", "resolver": "ServiceRouteResolver"}),
        &serde_json::json!({
            "dual_idempotency": true,
            "atomic_floor_notice_ack": true,
            "quarantine_before_cache": true,
            "fork_fail_closed": true,
            "restart_floor": true,
            "same_core_handover": true,
            "new_core_identity_isolation": true
        }),
        &serde_json::json!({"status": "validated"}),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn soland_production_route_paths_close_fixture_semantics() {
        super::run_service_route_handover_mirror_production_suite()
            .await
            .expect("Soland production route paths must satisfy fixture semantics");
    }
}
