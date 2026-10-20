//! Actual reporter authority, transaction rollback and durable provider retries.
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_models_collaboration::mimi_operations::MimiReportAbuseRequestBody;
use arkret_wire::{AccountId, ActorId, DidCoreId};

use super::*;
use crate::scenarios::human_device_producer_live::membership_payload;

const PATH: &str = "/_arkret/open/mimi/report-abuse";
const SECOND_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002882";

fn sign(member: &Member, request: &mut MimiReportAbuseRequestBody) -> Result<Value> {
    request.reporter_authority.proof.payload_digest = request.payload_digest()?;
    request.reporter_authority.proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &request.reporter_authority_binding_bytes()?,
        &member.key,
    )
    .map_err(anyhow::Error::msg)?;
    request.validate()?;
    Ok(serde_json::to_value(request)?)
}

fn distinct(member: &Member, original: &MimiReportAbuseRequestBody, label: &str) -> Result<Value> {
    let mut request = original.clone();
    request.report_claim.description = Some(label.to_owned());
    sign(member, &mut request)
}

async fn snapshot(url: &str, realm: &str) -> Result<Value> {
    let url = url.to_owned();
    let realm = realm.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
        Ok(db.query_one("SELECT jsonb_build_object('events',(SELECT count(*) FROM canonical_events WHERE realm_id=$1),'commits',(SELECT count(*) FROM realm_commits WHERE realm_id=$1),'outbox',(SELECT count(*) FROM federation_outbox),'event_outbox',(SELECT count(*) FROM event_federation_outbox),'reports',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY report_event_id),'[]'::jsonb) FROM moderation_report_current_results r WHERE realm_id=$1),'idempotency',(SELECT COALESCE(jsonb_agg(to_jsonb(k) ORDER BY actor_key,idempotency_key),'[]'::jsonb) FROM idempotency_keys k WHERE operation_id='ak.open.mimi.command.report_abuse.v1'))",&[&realm])?.get(0))
    }).await?
}

async fn verify_reports(
    server: &ArkretServer,
    database: &str,
    realm: &str,
    effects: &Value,
) -> Result<()> {
    let database = database.to_owned();
    let realm = realm.to_owned();
    let rows = tokio::task::spawn_blocking(move || -> Result<Vec<(Value, Value, Value)>> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db.query("SELECT e.envelope,c.commit_json,to_jsonb(r) FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk JOIN moderation_report_current_results r ON r.current_commit_id=c.commit_id AND r.report_event_id=(c.commit_json->>'event_ref') WHERE e.realm_id=$1 AND e.kind=$2 ORDER BY c.stream_position", &[&realm,&EventKind::SelfModerationReport.as_str()])?.into_iter().map(|r|(r.get(0),r.get(1),r.get(2))).collect())
    }).await??;
    ensure!(
        !rows.is_empty()
            && rows.len()
                == effects["reports"]
                    .as_array()
                    .context("report currents")?
                    .len(),
        "reports and their native originals are not one-to-one"
    );
    let actor = ActorId::service(DidCoreId::new(server.service_id().to_string())?);
    let method = format!("{}#notary-key", server.service_did());
    let commit_method = format!("{}#federation-fanout-key", server.service_did());
    let key = server.federation_signing_key()?;
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            key.verifying_key().as_bytes(),
        ),
    };
    for (event, commit, current) in &rows {
        let event: arkret_wire::Event = serde_json::from_value(event.clone())?;
        let commit: arkret_wire::RealmCommit = serde_json::from_value(commit.clone())?;
        ensure!(
            event.actor_id == actor
                && event.kind == EventKind::SelfModerationReport
                && commit.event_ref == event.event_id
                && commit.realm_id == event.realm_id,
            "report was not service-authored with its covering Commit"
        );
        let suite =
            arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())?;
        event.verify_event_id_matches_content_with_digest_suite(suite)?;
        let proof = event
            .producer_proof
            .as_ref()
            .context("report producer proof")?;
        ensure!(
            proof.verification_method.as_str() == method,
            "report used a different producer key"
        );
        let bytes = arkret_signatures::EventProofBuilder::new().envelope_bytes(&event)?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &bytes,
            &event.actor_id,
            &material,
            suite,
        )?;
        commit.verify_commit_id_matches_content()?;
        ensure!(
            commit.signature.verification_method.as_str() == commit_method,
            "covering Commit used another key"
        );
        arkret_signatures::detached_object::verify_detached_object_signature(
            &commit.signature,
            &arkret_canonical::canonical::unsigned_value(&commit, &["signature"])?,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &material,
        )?;
        ensure!(
            current["current_commit_id"] == serde_json::to_value(&commit.commit_id)?
                && current["current_stream_position"] == json!(commit.stream_position),
            "report current points to another Commit"
        );
        let report_id =
            serde_json::to_value(arkret_wire::ReportId::from_event_id(&event.event_id))?;
        let records = effects["idempotency"]
            .as_array()
            .context("report ledger")?
            .iter()
            .filter(|k| k["response_body"]["report_id"] == report_id)
            .collect::<Vec<_>>();
        ensure!(
            records.len() == 1
                && records[0]["authenticated_actor"] == serde_json::to_value(&actor)?
                && records[0]["response_status"] == 200,
            "report receipt ledger is not bound to its actual Event and authenticated service"
        );
    }
    println!(
        "[mimi-report] signed_native_reports: events={} commits={} currents={} receipt_ledgers={} independent_crypto=1",
        rows.len(),
        rows.len(),
        rows.len(),
        rows.len()
    );
    Ok(())
}

async fn fault(url: &str, enabled: bool) -> Result<i64> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<i64> {
        let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
        if enabled {
            db.batch_execute("CREATE SEQUENCE cotest_mimi_report_fault_hits; CREATE FUNCTION cotest_mimi_report_abort() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operation_id='ak.open.mimi.command.report_abuse.v1' THEN PERFORM nextval('cotest_mimi_report_fault_hits'); RAISE EXCEPTION 'cotest_mimi_report_late_abort'; END IF; RETURN NEW; END $$; CREATE TRIGGER cotest_mimi_report_abort BEFORE INSERT ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION cotest_mimi_report_abort();")?;
            Ok(0)
        } else {
            let hits:i64=db.query_one("SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM cotest_mimi_report_fault_hits",&[])?.get(0);
            db.batch_execute("DROP TRIGGER cotest_mimi_report_abort ON idempotency_keys; DROP FUNCTION cotest_mimi_report_abort(); DROP SEQUENCE cotest_mimi_report_fault_hits;")?;
            Ok(hits)
        }
    }).await?
}

async fn rejected(
    server: &ArkretServer,
    database: &str,
    realm: &str,
    room: &str,
    provider: &str,
    label: &str,
    body: &Value,
) -> Result<()> {
    let typed = serde_json::from_value::<MimiReportAbuseRequestBody>(body.clone())?;
    if label == "target_swap_under_original_proof" {
        ensure!(
            typed.validate().is_err(),
            "target swap must break the original proof binding"
        );
    } else {
        typed.validate()?;
    }
    let before = snapshot(database, realm).await?;
    let (status, problem) = signed_post(server, PATH, room, provider, body).await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            && problem["type"] == "https://arkret.org/problems/capability_denied"
            && problem["detail"] == "MIMI reporter authority admission is unavailable",
        "{label}: wrong reporter refusal {status}: {problem}"
    );
    ensure!(
        snapshot(database, realm).await? == before,
        "{label}: rejected report changed committed effects"
    );
    println!("[mimi-report] {label}: valid_provider_signature=1 refused=1 zero_effects=1");
    Ok(())
}

pub(super) struct ReplayProbe {
    body: Value,
    receipt: Value,
    effects: Value,
}

impl ReplayProbe {
    pub(super) async fn after_restart(
        &self,
        server: &ArkretServer,
        database: &str,
        realm: &str,
        room: &str,
        provider: &str,
    ) -> Result<()> {
        ensure!(
            snapshot(database, realm).await? == self.effects,
            "cold restart changed durable report effects"
        );
        let (status, receipt) = signed_post(server, PATH, room, provider, &self.body).await?;
        ensure!(
            status.is_success() && receipt == self.receipt,
            "cold report retry changed original result: {status}: {receipt}"
        );
        ensure!(
            snapshot(database, realm).await? == self.effects,
            "cold retry appended effects"
        );
        verify_reports(server, database, realm, &self.effects).await?;
        println!(
            "[mimi-report] real_process_restart: exact_body=1 original_receipt=1 zero_extra_effects=1"
        );
        Ok(())
    }
}

pub(super) async fn exercise(
    server: &ArkretServer,
    coauth: &MockCoauthIntrospectionServer,
    member: &Member,
    database: &str,
    realm: &str,
    room: &str,
    provider: &str,
    original: &Value,
) -> Result<ReplayProbe> {
    let original: MimiReportAbuseRequestBody = serde_json::from_value(original.clone())?;
    for label in [
        "same_principal_other_station",
        "other_principal",
        "membership_commit_swap",
        "membership_position_swap",
        "room_commit_swap",
        "room_event_swap",
        "expired_proof",
        "wrong_audience",
        "unknown_device_key",
        "wrong_holder_signature",
        "target_swap_under_original_proof",
    ] {
        let mut candidate = original.clone();
        candidate.report_claim.description = Some(format!("refusal:{label}"));
        match label {
            "same_principal_other_station" => {
                candidate.reporter_authority.actor_id = ActorId::account(AccountId::new(
                    member.account.principal_id.clone(),
                    DidCoreId::new("ak:did_core:web:other-station.example")?,
                ))
            }
            "other_principal" => {
                candidate.reporter_authority.actor_id = ActorId::account(AccountId::new(
                    DidCoreId::new("ak:did_core:web:other-principal.example")?,
                    member.account.station_id.clone(),
                ))
            }
            "membership_commit_swap" => {
                candidate.reporter_authority.membership_ref.commit_id = candidate
                    .reporter_authority
                    .room_binding_ref
                    .commit_id
                    .clone()
            }
            "membership_position_swap" => {
                candidate.reporter_authority.membership_ref.stream_position += 1
            }
            "room_commit_swap" => {
                candidate.reporter_authority.room_binding_ref.commit_id = candidate
                    .reporter_authority
                    .membership_ref
                    .commit_id
                    .clone()
            }
            "room_event_swap" => {
                candidate.reporter_authority.room_binding_ref.event_id =
                    candidate.reporter_authority.membership_ref.event_id.clone()
            }
            "expired_proof" => {
                candidate.reporter_authority.expires_at =
                    candidate.reporter_authority.proof.created_at
                        + chrono::Duration::milliseconds(1);
                ensure!(
                    candidate.reporter_authority.expires_at < chrono::Utc::now(),
                    "expiry counterexample must already be expired"
                );
            }
            "wrong_audience" => {
                candidate.reporter_authority.proof.audience =
                    arkret_wire::Audience::Single("ak:did_core:web:other-facade.example".into())
            }
            "unknown_device_key" => {
                candidate.reporter_authority.proof.verification_method =
                    arkret_wire::DidUrl::new(format!(
                        "{}#unknown-device",
                        member
                            .method
                            .as_str()
                            .split('#')
                            .next()
                            .context("member DID")?
                    ))
                    .map_err(anyhow::Error::msg)?
            }
            _ => {}
        }
        let mut body = sign(member, &mut candidate)?;
        if label == "wrong_holder_signature" {
            let wrong = ed25519_dalek::SigningKey::from_bytes(&[222; 32]);
            body["reporter_authority"]["proof"]["jws"] = json!(
                arkret_signatures::jws::sign_jws_ed25519(
                    &candidate.reporter_authority_binding_bytes()?,
                    &wrong
                )
                .map_err(anyhow::Error::msg)?
            );
        }
        if label == "target_swap_under_original_proof" {
            body["report_claim"]["target_ref"] =
                serde_json::to_value(&candidate.reporter_authority.membership_ref.event_id)?;
        }
        rejected(server, database, realm, room, provider, label, &body).await?;
    }
    // The transport tamper is separate from the valid-transport authority cases.
    let before = snapshot(database, realm).await?;
    let (status, problem) = super::signed_post_inner(
        server,
        PATH,
        Some(room),
        provider,
        &serde_json::to_value(&original)?,
        Some("mimi://other-provider.example"),
    )
    .await?;
    ensure!(
        status == StatusCode::UNAUTHORIZED
            && problem["type"]
                .as_str()
                .is_some_and(|t| t.ends_with("http_signature_invalid")),
        "provider transport substitution was accepted: {status}: {problem}"
    );
    ensure!(
        snapshot(database, realm).await? == before,
        "provider tamper changed report effects"
    );
    println!("[mimi-report] provider_header_substitution: http_signature_invalid=1 zero_effects=1");

    // Fail at the final response-ledger INSERT, after the native unit prepared
    // its Event, covering Commit and report current in the same transaction.
    let request = distinct(member, &original, "late-transaction-failure")?;
    let before = snapshot(database, realm).await?;
    fault(database, true).await?;
    let failed = signed_post(server, PATH, room, provider, &request).await;
    let fault_hits = fault(database, false).await?;
    ensure!(
        fault_hits == 1,
        "the failed request did not reach the late SQL fault exactly once: {fault_hits}"
    );
    let (status, problem) = failed?;
    ensure!(
        status.is_server_error(),
        "late SQL fault did not fail: {status}: {problem}"
    );
    ensure!(
        snapshot(database, realm).await? == before,
        "late SQL failure left partial effects"
    );
    let (status, receipt) = signed_post(server, PATH, room, provider, &request).await?;
    ensure!(
        status.is_success(),
        "original failed request did not recover: {status}: {receipt}"
    );
    println!("[mimi-report] late_sql_failure: zero_partial_effects=1 original_body_recovered=1");

    // Two authenticated requests race over one canonical body and must commit
    // one native report, with one response and one durable idempotency row.
    let concurrent = distinct(member, &original, "concurrent-exact-provider-retries")?;
    let before = snapshot(database, realm).await?;
    let (a, b) = tokio::try_join!(
        signed_post(server, PATH, room, provider, &concurrent),
        signed_post(server, PATH, room, provider, &concurrent)
    )?;
    ensure!(
        a.0.is_success() && b.0.is_success() && a.1 == b.1,
        "concurrent retries diverged: {a:?} / {b:?}"
    );
    let after = snapshot(database, realm).await?;
    ensure!(
        after["events"].as_i64() == before["events"].as_i64().map(|v| v + 1)
            && after["commits"].as_i64() == before["commits"].as_i64().map(|v| v + 1),
        "concurrent report appended multiple Events/Commits"
    );
    ensure!(
        after["reports"].as_array().context("reports")?.len()
            == before["reports"].as_array().context("reports")?.len() + 1
            && after["idempotency"].as_array().context("keys")?.len()
                == before["idempotency"].as_array().context("keys")?.len() + 1,
        "concurrent report current/ledger were not singular"
    );
    println!(
        "[mimi-report] concurrent_retries: one_event=1 one_commit=1 one_current=1 one_ledger=1 same_receipt=1"
    );

    // Establish a real second reporter, then withdraw its participation before
    // submitting a new frozen request. The successful receipt is no authority.
    let reporter =
        Member::provision(server, coauth, "mimi-withdrawn-reporter", SECOND_DEVICE).await?;
    let join = reporter
        .client
        .author_event(
            realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                realm,
                reporter.account.clone(),
                MembershipPayloadState::Join,
                "reporter joins",
            )?,
        )
        .await?;
    let commit =
        submit_and_expect_commit(&reporter.client, &reporter.account, SECOND_DEVICE, &join).await?;
    let mut request = original.clone();
    request.reporter_authority.actor_id = reporter.actor.clone();
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    request.reporter_authority.proof.created_at = now;
    request.reporter_authority.expires_at = now + chrono::Duration::seconds(240);
    request.reporter_authority.proof.verification_method = reporter.method.clone();
    request.reporter_authority.membership_ref = arkret_wire::CommittedEventRef {
        event_id: commit.event_ref.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    request.report_claim.description = Some("joined reporter positive control".into());
    let body = sign(&reporter, &mut request)?;
    let (status, receipt) = signed_post(server, PATH, room, provider, &body).await?;
    ensure!(
        status.is_success(),
        "joined reporter positive control failed: {status}: {receipt}"
    );
    request.report_claim.description =
        Some("new request frozen before participation withdrawal".into());
    let withdrawn = sign(&reporter, &mut request)?;
    let leave = reporter
        .client
        .author_event(
            realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                realm,
                reporter.account.clone(),
                MembershipPayloadState::Leave,
                "reporter withdraws",
            )?,
        )
        .await?;
    submit_and_expect_commit(&reporter.client, &reporter.account, SECOND_DEVICE, &leave).await?;
    rejected(
        server,
        database,
        realm,
        room,
        provider,
        "withdrawn_membership_new_request",
        &withdrawn,
    )
    .await?;

    let effects = snapshot(database, realm).await?;
    verify_reports(server, database, realm, &effects).await?;
    println!(
        "[mimi-report] recovery_probe body_digest={} receipt={} effects={}",
        arkret_canonical::sha256_digest(&arkret_canonical::canonical_json_bytes(&concurrent)?),
        a.1,
        effects
    );
    Ok(ReplayProbe {
        body: concurrent,
        receipt: a.1,
        effects,
    })
}
