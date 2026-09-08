//! Route consumers share the production evaluator and method verification.
use anyhow::{Result, ensure};
use chrono::{Duration, Utc};
use garth::service_route_material::test_fixture::current_web_route_fixture;
use garth::{
    MemoryServiceRouteStateStore, PrefetchedRouteSource, ServiceRouteEvaluator,
    authenticate_fetched_resolution, describe_route_binding,
};
pub fn run_service_did_routes_suite() -> Result<()> {
    let fixture = current_web_route_fixture("routes.example", "station", 31);
    let now = Utc::now();
    let mut evaluator = ServiceRouteEvaluator::new(
        MemoryServiceRouteStateStore::default(),
        Duration::minutes(1),
    )?;
    for at in [now, now + Duration::hours(1), now + Duration::days(3)] {
        let candidate = authenticate_fetched_resolution(
            fixture.resolution.clone(),
            arkret_identity::ResolvedDid::proofless(fixture.document.clone()),
            at,
        )?;
        let mut source = PrefetchedRouteSource::new(Some(candidate));
        source.insert_describe(describe_route_binding(
            &fixture.resolution,
            &fixture.describe,
            at,
        )?);
        let route = evaluator.resolve(&fixture.service_id, "station", at, &mut source)?;
        ensure!(route.route().base_url == "https://routes.example/");
        evaluator = ServiceRouteEvaluator::new(evaluator.store().clone(), Duration::minutes(1))?;
    }
    ensure!(
        arkret_identity::verify_authenticated_service_resolution_history(
            &fixture.resolution,
            &fixture.service_id,
            now
        )
        .is_err(),
        "did:web cannot manufacture historical signer evidence"
    );
    let mut stale_document = fixture.document.clone();
    stale_document
        .raw_properties
        .insert("service".into(), serde_json::json!([]));
    ensure!(
        authenticate_fetched_resolution(
            fixture.resolution.clone(),
            arkret_identity::ResolvedDid::proofless(stale_document),
            now
        )
        .is_err(),
        "carrier must match independent current state"
    );
    let wrong = current_web_route_fixture("other.example", "station", 32);
    ensure!(
        arkret_identity::verify_current_service_resolution(
            &wrong.resolution,
            &fixture.service_id,
            "station",
            &arkret_identity::ResolvedDid::proofless(wrong.document.clone()),
            now
        )
        .is_err()
    );
    ensure!(
        arkret_identity::verify_current_service_resolution(
            &fixture.resolution,
            &fixture.service_id,
            "media_service",
            &arkret_identity::ResolvedDid::proofless(fixture.document.clone()),
            now
        )
        .is_err()
    );
    Ok(())
}
