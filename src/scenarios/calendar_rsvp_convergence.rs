//! Live Calendar RSVP convergence against a real server.
//!
//! The unit and fixture suites pin the rules in isolation; this exercises them
//! end to end, because the convergence properties only mean something once a
//! real reducer has admitted the Events:
//!
//! * an RSVP carries the registry-derived cell effect, so it reaches its CBA cell instead of being
//!   accepted as a side-band record;
//! * two responses that do not observe each other stay exposed as two heads — the server may not
//!   pick a winner by HLC, arrival order or event id;
//! * a response that names both heads in `causal_refs` dominates them, so the responder converges
//!   back to one answer;
//!
//! Cell-subject isolation between responders is not repeated here: the
//! accountable actor is part of the composite subject, which the reducer unit
//! tests already pin. What only a live server can show is the concurrency and
//! domination behaviour below.

use std::time::Duration;

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ArkretServer, TestActorClient, eventually, expect_json};

const ALICE_DID: &str = "did:web:cotest-rsvp-alice.example";
const CALENDAR_STRAND_ID: &str = "ak:strand:01904100-0000-7000-8000-00000000ca01";

fn calendar_subtree() -> Value {
    json!({
        "start": "2026-06-22T09:00:00",
        "end": "2026-06-22T10:00:00",
        "timezone": "America/Los_Angeles",
        "tzdb_version": "2025a",
        "all_day": false,
        "status": "confirmed",
        "recurrence": {"frequency": "weekly", "count": 10}
    })
}

fn rsvp_payload(status: &str, basis: &[String]) -> Value {
    json!({
        "event_ref": CALENDAR_STRAND_ID,
        "occurrence": null,
        "entry": {
            "schedule_basis_refs": basis,
            "response": {"status": status}
        }
    })
}

/// Reads the schedule revision frontier and the live RSVP heads.
async fn read_strand(client: &TestActorClient) -> Result<Value> {
    expect_json(
        client.get(&format!("/_soland/self/strands/{CALENDAR_STRAND_ID}")),
        StatusCode::OK,
    )
    .await
}

fn heads_for(strand: &Value, actor: &str) -> Vec<Value> {
    strand["rsvps"]
        .as_array()
        .map(|cells| {
            cells
                .iter()
                .filter(|cell| cell["actor_id"].as_str() == Some(actor))
                .flat_map(|cell| {
                    cell["heads"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn head_statuses(heads: &[Value]) -> Vec<String> {
    let mut statuses: Vec<String> = heads
        .iter()
        .filter_map(|head| head["entry"]["response"]["status"].as_str())
        .map(ToOwned::to_owned)
        .collect();
    statuses.sort();
    statuses
}

fn submitted_digest(response: &Value) -> Result<String> {
    response["cotest_event_digest"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("submit response carries no event digest"))
}

pub async fn calendar_rsvp_converges_across_concurrent_responses() -> Result<()> {
    let server = ArkretServer::spawn("calendar-rsvp-convergence").await?;
    let alice = server
        .register_client(
            ALICE_DID,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000c1",
        )
        .await?;
    let created = alice
        .create_realm_with(json!({
            "title": "RSVP convergence",
            "summary": "RSVP convergence",
            "public": false,
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("realm create response has no realm_id"))?
        .to_owned();
    // A DataEvent that writes a cell names a covering grant; the founding grant
    // is the one the Realm bootstrap issued to its creator.
    let grant_refs = vec![
        created["founding_grant_id"]
            .as_str()
            .ok_or_else(|| anyhow!("realm bootstrap exposed no founding grant"))?
            .to_owned(),
    ];

    // The product coordinator, not an operator endpoint, must publish the
    // non-empty bootstrap Seal before a client authors its first DataEvent.
    eventually(
        "Realm bootstrap Seal",
        Duration::from_secs(30),
        Duration::from_millis(100),
        || async {
            let frontier = expect_json(
                alice
                    .get("/_arkret/self/events/frontier")
                    .query(&[("realm_id", realm_id.as_str())]),
                StatusCode::OK,
            )
            .await?;
            let root = frontier["frontier"]["control_event_set_root"]
                .as_str()
                .ok_or_else(|| anyhow!("Realm frontier has no control_event_set_root"))?;
            if root == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
                return Err(anyhow!("Realm bootstrap Seal is still empty"));
            }
            Ok(())
        },
    )
    .await?;

    // Activation is one canonical pair: the schema ref plus the calendar
    // namespace. A lone ref or a lone subtree is calendar_activation_mismatch.
    alice
        .submit_event(
            &realm_id,
            "ak.strand.create",
            json!({
                "object": {
                    "id": CALENDAR_STRAND_ID,
                    "schema": "ak.schema.strand.v1",
                    "realm_id": realm_id,
                    "schema_refs": ["ak.schema.calendar_event.v1"],
                    "metadata": {
                        "title": "Weekly sync",
                        "fields": {"calendar": calendar_subtree()}
                    },
                    "tracks": {"synthesis": {"enabled": true, "is_primary": true}},
                    "created_by": ALICE_DID,
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
        )
        .await?;

    let strand = read_strand(&alice).await?;
    let frontier: Vec<String> = strand["schedule_revision_heads"]
        .as_array()
        .ok_or_else(|| anyhow!("calendar strand exposes no schedule revision frontier"))?
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    if frontier.is_empty() {
        return Err(anyhow!(
            "calendar create must publish a schedule revision head; without it a client cannot \
             author an RSVP at all"
        ));
    }

    // First answer, observing only the schedule.
    let first = alice
        .submit_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            rsvp_payload("accepted", &frontier),
            frontier.clone(),
            grant_refs.clone(),
        )
        .await?;
    let first_digest = submitted_digest(&first)?;

    let strand = read_strand(&alice).await?;
    let heads = heads_for(&strand, ALICE_DID);
    if heads.len() != 1 {
        return Err(anyhow!("first RSVP must produce exactly one head"));
    }
    // effect_projection = set(payload.entry): the head carries the whole entry,
    // so the basis and the response converge together.
    if heads[0]["entry"]["schedule_basis_refs"][0].as_str() != Some(frontier[0].as_str()) {
        return Err(anyhow!("head must carry the signed schedule basis"));
    }

    // Second answer that does NOT observe the first: concurrent by
    // construction, so both heads stay exposed.
    alice
        .submit_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            rsvp_payload("declined", &frontier),
            frontier.clone(),
            grant_refs.clone(),
        )
        .await?;
    let strand = read_strand(&alice).await?;
    let heads = heads_for(&strand, ALICE_DID);
    if heads.len() != 2 {
        return Err(anyhow!(
            "concurrent responses must expose two heads, got {}; the server may not choose \
             between them by HLC, arrival order or event id",
            heads.len()
        ));
    }
    if head_statuses(&heads) != vec!["accepted".to_owned(), "declined".to_owned()] {
        return Err(anyhow!("both concurrent answers must remain visible"));
    }
    let second_digest = heads
        .iter()
        .filter_map(|head| head["source_event_digest"].as_str())
        .find(|digest| *digest != first_digest)
        .ok_or_else(|| anyhow!("second head carries no distinct digest"))?
        .to_owned();

    // Causal successor: naming both heads dominates them, so Alice converges
    // back to a single answer without anyone picking a winner for her.
    let mut resolving_basis = frontier.clone();
    resolving_basis.push(first_digest.clone());
    resolving_basis.push(second_digest.clone());
    resolving_basis.sort();
    resolving_basis.dedup();
    alice
        .submit_event_with_causal_refs(
            &realm_id,
            "ak.rsvp.set",
            // The entry basis stays the schedule frontier; the extra causal
            // edges are what dominate the earlier RSVP heads.
            rsvp_payload("tentative", &frontier),
            resolving_basis,
            grant_refs.clone(),
        )
        .await?;

    let strand = read_strand(&alice).await?;
    let heads = heads_for(&strand, ALICE_DID);
    if heads.len() != 1 {
        return Err(anyhow!(
            "a response observing both heads must dominate them, got {} heads",
            heads.len()
        ));
    }
    if head_statuses(&heads) != vec!["tentative".to_owned()] {
        return Err(anyhow!("the surviving head must be the causal successor"));
    }

    Ok(())
}

/// An RSVP whose effect was stripped must not be accepted.
///
/// This is the concrete defect the closure review found in the client: the
/// Event validated against the payload schema, so it looked fine, but it never
/// reached `ak.component.calendar.rsvp.v1` and the response silently did not
/// converge.
pub async fn calendar_rsvp_without_cell_effect_is_rejected() -> Result<()> {
    let server = ArkretServer::spawn("calendar-rsvp-effectless").await?;
    let alice = server
        .register_client(
            ALICE_DID,
            "@cotest-rsvp-alice",
            "ak:device:01904100-0000-7000-8000-0000000000c3",
        )
        .await?;
    let realm_id = alice.create_realm("RSVP effect contract").await?;
    alice
        .submit_event(
            &realm_id,
            "ak.strand.create",
            json!({
                "object": {
                    "id": CALENDAR_STRAND_ID,
                    "schema": "ak.schema.strand.v1",
                    "realm_id": realm_id,
                    "schema_refs": ["ak.schema.calendar_event.v1"],
                    "metadata": {
                        "title": "Weekly sync",
                        "fields": {"calendar": calendar_subtree()}
                    },
                    "tracks": {"synthesis": {"enabled": true, "is_primary": true}},
                    "created_by": ALICE_DID,
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
        )
        .await?;

    let strand = read_strand(&alice).await?;
    let frontier: Vec<String> = strand["schedule_revision_heads"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();

    let mut event = alice
        .author_event(
            &realm_id,
            "ak.rsvp.set",
            rsvp_payload("accepted", &frontier),
        )
        .await?;
    event["effects"] = json!([]);
    let response = alice
        .post("/_arkret/self/events")
        .json(&event)
        .send()
        .await?;
    if response.status() == StatusCode::OK {
        return Err(anyhow!(
            "an effect-less RSVP must not be accepted: it never reaches its CBA cell"
        ));
    }
    Ok(())
}
