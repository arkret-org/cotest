//! Timestamp cases use signed, otherwise valid Genesis submissions on real
//! Station HTTP/PG paths. The fixture's partial Events supply only clock deltas.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use anyhow::{Context, Result, ensure};
use arkret_wire::{Event, ScopeRef};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::mls_lifecycle_live::{Member, MlsGenesisObserver};
use crate::conformance::CaseExecutionResult;

struct Probe {
    cases: Vec<Value>,
    results: Mutex<BTreeMap<String, CaseExecutionResult>>,
    winners: Mutex<Vec<Event>>,
    rejected: Mutex<Vec<arkret_wire::EventId>>,
}

fn scope_kind(scope: &ScopeRef) -> Result<&'static str> {
    Ok(match scope {
        ScopeRef::Realm { .. } => "realm",
        ScopeRef::Circle { .. } => "circle",
        ScopeRef::Sidecar { .. } => "sidecar",
        _ => anyhow::bail!("timestamp fixture names an unsupported MLS scope"),
    })
}

fn time(value: &Value) -> Result<DateTime<Utc>> {
    let text = value
        .as_str()
        .context("fixture timestamp is not a string")?;
    arkret_canonical::validate_timestamp_canonical(text)?;
    Ok(DateTime::parse_from_rfc3339(text)?.with_timezone(&Utc))
}

async fn signed(member: &Member, mut event: Event) -> Result<Event> {
    let floor = event.created_at + chrono::Duration::milliseconds(2);
    let delay = (floor - Utc::now()).num_milliseconds();
    if delay >= 0 {
        tokio::time::sleep(std::time::Duration::from_millis(delay as u64 + 1)).await;
    }
    let proof_time = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    ensure!(
        proof_time > event.created_at,
        "proof clock is not independent"
    );
    event.producer_proof = None;
    let principal = member
        .client
        .principal
        .as_ref()
        .context("fixture identity")?;
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        member.key.to_bytes(),
        principal.did.clone(),
        member.method.clone(),
    );
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )?;
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(proof_time),
    )?;
    let event = authored.into_event();
    arkret_signatures::proof::verify_ed25519_detached_jws_proof(
        event
            .producer_proof
            .as_ref()
            .context("signed Genesis has no proof")?,
        &arkret_canonical::canonical_json_bytes(&event.digest_payload()?)?,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: member.key.verifying_key().to_bytes().to_vec(),
        },
    )?;
    Ok(event)
}

async fn durable_cut(database_url: &str) -> Result<Value> {
    let database_url = database_url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let mut result = serde_json::Map::new();
        for table in ["canonical_events", "realm_commits", "mls_group_current_results",
            "mls_consumed_proposal_provenance", "mls_welcome_provenance",
            "mls_welcome_deliveries", "mls_add_authority_attestations",
            "mls_add_authority_attestation_outbox", "mls_replica_genesis_provenance", "blobs",
            "projection_events", "event_federation_outbox", "federation_outbox", "federation_outbox_dead_letter"] {
            let query = format!("SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM {table} r");
            let rows: Value = db.query_one(&query, &[])?.get(0);
            result.insert(table.into(), rows);
        }
        Ok(Value::Object(result))
    }).await?
}

impl Probe {
    fn for_scope(&self, scope: &ScopeRef) -> Result<Vec<&Value>> {
        let kind = scope_kind(scope)?;
        let cases = self
            .cases
            .iter()
            .filter(|case| {
                case["event"]["payload"]["governance_binding"]["effective_scope"]["kind"] == kind
            })
            .collect::<Vec<_>>();
        ensure!(!cases.is_empty(), "fixture omits {kind} timestamp cases");
        Ok(cases)
    }

    fn record(&self, case: &Value, assertions: usize) -> Result<()> {
        let name = case["name"]
            .as_str()
            .context("timestamp case has no name")?;
        ensure!(
            self.results
                .lock()
                .unwrap()
                .insert(
                    name.into(),
                    CaseExecutionResult {
                        case_id: name.into(),
                        assertions,
                    }
                )
                .is_none(),
            "timestamp case ran twice: {name}"
        );
        Ok(())
    }

    async fn winner(&self, member: &Member, event: &Event) -> Result<()> {
        let original = member
            .client
            .sdk()
            .committed_event_get(&event.event_id)
            .await?;
        ensure!(
            original.commit().committed_at > event.created_at,
            "commit clock is not independent of the frozen creation timestamp"
        );
        let original = original
            .reducer_input()
            .context("winner original is undisclosed")?;
        ensure!(
            arkret_canonical::canonical_json_bytes(original)?
                == arkret_canonical::canonical_json_bytes(event)?,
            "accepted winner bytes changed"
        );
        let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
            serde_json::from_value(serde_json::to_value(&original.payload)?)?;
        ensure!(
            original.created_at == payload.created_at,
            "mismatched winner was accepted"
        );
        let snapshot = member
            .client
            .sdk()
            .realm_state_snapshot_head(&event.realm_id)
            .await?;
        let current = snapshot
            .current_state_entries
            .iter()
            .find_map(|row| match row {
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref },
                    value,
                    ..
                } if scope_ref == &event.scope_ref => Some(value),
                _ => None,
            })
            .context("accepted winner has no current MLS group")?;
        let current: arkret_wire::MlsGroupCurrent = serde_json::from_value(current.clone())?;
        ensure!(
            current.genesis_event_ref == event.event_id
                && current.effective_scope == event.scope_ref,
            "current selects another Genesis winner"
        );
        let rejected = self.rejected.lock().unwrap().clone();
        for reference in rejected {
            ensure!(
                reference != current.genesis_event_ref,
                "mismatch became winner"
            );
            let error = member
                .client
                .sdk()
                .committed_event_get(&reference)
                .await
                .expect_err("timestamp mismatch has an accepted original");
            ensure!(
                error.error_code() == Some(arkret_wire::ErrorCode::NotFound),
                "absence was not an authenticated not_found: {error}"
            );
        }
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl MlsGenesisObserver for Probe {
    async fn before(&self, member: &Member, event: &mut Event, database_url: &str) -> Result<()> {
        let payload = serde_json::to_value(&event.payload)?;
        let base = time(&payload["created_at"])?;
        event.created_at = base;
        *event = signed(member, event.clone()).await?;
        for case in self.for_scope(&event.scope_ref)? {
            let declared = &case["event"];
            ensure!(
                declared["kind"] == "ak.mls.genesis",
                "unexpected timestamp Event kind"
            );
            let outer = time(&declared["created_at"])?;
            let inner = time(&declared["payload"]["created_at"])?;
            let passes = case["expected"]["timestamp_gate_passes"]
                .as_bool()
                .context("missing timestamp verdict")?;
            ensure!(
                passes == (outer == inner),
                "fixture timestamp predicate disagrees"
            );
            if passes {
                continue;
            }
            ensure!(
                case["expected"]["mismatch_accepted_effects"] == json!([]),
                "mismatch fixture permits effects"
            );
            let anchor = outer.min(inner);
            let mut rejected = event.clone();
            rejected.created_at = base + (outer - anchor);
            let mut changed = payload.clone();
            changed["created_at"] = json!(arkret_canonical::format_timestamp_canonical(
                base + (inner - anchor)
            ));
            rejected.payload = serde_json::from_value(changed)?;
            let rejected = signed(member, rejected).await?;
            let before = durable_cut(database_url).await?;
            let (status, problem) = super::mls_lifecycle_live::post_json(
                &member.client,
                &crate::publication::initial_submission(rejected.clone(), "")?,
            )
            .await?;
            ensure!(
                !status.is_success()
                    && problem["type"]
                        == format!(
                            "https://arkret.org/problems/{}",
                            case["expected"]["mismatch_error_code"]
                                .as_str()
                                .context("missing mismatch code")?
                        ),
                "{}: expected timestamp refusal, got {status} {problem}",
                case["name"]
            );
            ensure!(
                problem["reason_code"] == case["expected"]["mismatch_reason_code"],
                "timestamp refusal reason differs"
            );
            ensure!(
                durable_cut(database_url).await? == before,
                "timestamp refusal changed durable accepted effects"
            );
            ensure!(
                case["expected"]["timestamp_eligible_as_accepted_winner"] == false,
                "mismatch fixture permits a winner"
            );
            self.rejected.lock().unwrap().push(rejected.event_id);
            self.record(case, 6)?;
        }
        Ok(())
    }

    async fn after(&self, member: &Member, event: &Event, _database_url: &str) -> Result<()> {
        self.winner(member, event).await?;
        self.winners.lock().unwrap().push(event.clone());
        Ok(())
    }

    async fn after_restart(&self, member: &Member) -> Result<()> {
        let winners = self.winners.lock().unwrap().clone();
        for event in winners
            .into_iter()
            .filter(|event| event.actor_id == member.actor)
        {
            self.winner(member, &event).await?;
            for case in self.for_scope(&event.scope_ref)? {
                if case["expected"]["timestamp_gate_passes"] == true {
                    ensure!(
                        case["expected"]["timestamp_eligible_as_accepted_winner"] == true,
                        "equal timestamp fixture refuses winner"
                    );
                    self.record(case, 6)?;
                }
            }
        }
        Ok(())
    }
}

/// Run live cases on a worker with enough stack for the existing MLS lifecycle.
pub fn run_live(cases: Vec<Value>) -> Result<Vec<CaseExecutionResult>> {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || -> Result<Vec<CaseExecutionResult>> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(32 * 1024 * 1024)
                .enable_all()
                .build()?;
            runtime.block_on(run(&cases))
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("timestamp evidence worker panicked"))?
}

async fn run(cases: &[Value]) -> Result<Vec<CaseExecutionResult>> {
    let expected = cases
        .iter()
        .map(|case| {
            case["name"]
                .as_str()
                .context("unnamed timestamp case")
                .map(str::to_owned)
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        !expected.is_empty() && expected.len() == cases.len(),
        "empty or duplicated timestamp cases"
    );
    let probe = Probe {
        cases: cases.to_vec(),
        results: Default::default(),
        winners: Default::default(),
        rejected: Default::default(),
    };
    super::mls_lifecycle_live::run_with_genesis_observer(&probe).await?;
    super::sidecar_authority_live::run_with_genesis_observer(Some(&probe)).await?;
    let results = probe.results.into_inner().unwrap();
    ensure!(
        results.keys().cloned().collect::<BTreeSet<_>>() == expected,
        "timestamp case execution is incomplete"
    );
    Ok(results.into_values().collect())
}
