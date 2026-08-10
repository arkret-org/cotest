//! Receiver-side presence conformance vectors
//! (`discovery/profiles-presence.md` §3).
//!
//! Presence is Signal state, never a durable Event and never a sync-frame
//! bucket (§3.1). The Sync Service may not decrypt, aggregate or project
//! presence content (§3.3), so **every** check these vectors make is a
//! receiver check running on decrypted plaintext — there is no server-side
//! schema gate left to assert against.
//!
//! Registered vector ids:
//! - `ak.vector.presence.state_closed_set.v1`
//! - `ak.vector.presence.last_active_at_bucket.v1`
//! - `ak.vector.presence.status_message_bounds.v1`
//! - `ak.vector.presence.multi_device_aggregation.v1`

use anyhow::{Result, bail};
use arkret_models_discovery::{PresenceStatus, validate_last_active_at, validate_status_message};
use arkret_wire::{DeviceId, DidCoreId, RealmId, ScopeRef, SealId, SignalClass};
use chrono::{DateTime, Duration, TimeZone, Utc};
use garth::signal::{PresenceProjection, SIGNAL_PLAINTEXT_KIND_PRESENCE, SignalPlaintext};
use serde_json::{Value, json};

pub const VECTOR_ID_STATE_CLOSED_SET: &str = "ak.vector.presence.state_closed_set.v1";
pub const VECTOR_ID_LAST_ACTIVE_AT_BUCKET: &str = "ak.vector.presence.last_active_at_bucket.v1";
pub const VECTOR_ID_STATUS_MESSAGE_BOUNDS: &str = "ak.vector.presence.status_message_bounds.v1";
pub const VECTOR_ID_MULTI_DEVICE_AGGREGATION: &str =
    "ak.vector.presence.multi_device_aggregation.v1";

pub const ALL_PRESENCE_SIGNAL_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_STATE_CLOSED_SET,
    VECTOR_ID_LAST_ACTIVE_AT_BUCKET,
    VECTOR_ID_STATUS_MESSAGE_BOUNDS,
    VECTOR_ID_MULTI_DEVICE_AGGREGATION,
];

// ─── VECT-PS-1 — state is a v1 closed set ──────────────────────────────────

/// §3.2: `state` is exactly `online` / `idle` / `offline` / `dnd`. A receiver
/// meeting anything else MUST drop the update or fail closed with
/// `schema_violation`, and MUST NOT guess a nearby state — the Matrix-legacy
/// `unavailable` and `busy` are not v1 wire values.
pub fn run_state_closed_set_vector() -> Result<()> {
    for accepted in ["online", "idle", "offline", "dnd"] {
        if PresenceStatus::parse_wire(accepted).is_none() {
            bail!("{VECTOR_ID_STATE_CLOSED_SET} rejected the v1 state `{accepted}`");
        }
        let mut projection = PresenceProjection::new();
        projection.apply(&presence_plaintext(json!({"state": accepted}), 1)?)?;
    }
    for retired in ["unavailable", "busy", "away", "Online", ""] {
        if PresenceStatus::parse_wire(retired).is_some() {
            bail!("{VECTOR_ID_STATE_CLOSED_SET} accepted the non-v1 state `{retired}`");
        }
        // The drop may land at either of two gates, and both count: since the
        // 2026-08-01 closure the plaintext is validated against
        // `ak.schema.signal_presence.v1` on the way in (`signal.md` §1.1), so a
        // non-v1 `state` is usually rejected before a projection ever sees it.
        // What §3.2 forbids is the third outcome — being mapped onto a nearby
        // state — so the assertion is that nothing is retained either way.
        let Ok(plaintext) = presence_plaintext(json!({"state": retired}), 1) else {
            continue;
        };
        let mut projection = PresenceProjection::new();
        if projection.apply(&plaintext).is_ok() {
            bail!(
                "{VECTOR_ID_STATE_CLOSED_SET} projected the non-v1 state `{retired}` instead of dropping it"
            );
        }
        // Dropping must be total: no observation may survive.
        if !projection.observations(&actor()?, sent_at()).is_empty() {
            bail!("{VECTOR_ID_STATE_CLOSED_SET} retained an observation for a dropped state");
        }
    }
    Ok(())
}

// ─── VECT-PS-2 — last_active_at bucket admission ───────────────────────────

/// §3.3: `last_active_at` is either an RFC 3339 UTC timestamp or an ISO 8601
/// interval bucket whose start is aligned to the Unix-epoch UTC grid and whose
/// duration is at least PT60S. The receiver independently validates the bucket
/// boundary and duration and fails closed on a malformed value.
pub fn run_last_active_at_bucket_vector() -> Result<()> {
    for accepted in [
        "2026-06-22T10:34:56.000Z",
        "2026-06-22T10:00:00.000Z/PT1H",
        "2026-06-22T10:34:00.000Z/PT60S",
    ] {
        validate_last_active_at(accepted).map_err(|error| {
            anyhow::anyhow!("{VECTOR_ID_LAST_ACTIVE_AT_BUCKET} rejected `{accepted}`: {error}")
        })?;
    }
    for rejected in [
        // Start not aligned to the bucket duration on the epoch grid.
        "2026-06-22T10:34:00.000Z/PT1H",
        // Duration below the PT60S protocol floor.
        "2026-06-22T10:00:00.000Z/PT30S",
        // Not a timestamp at all.
        "yesterday",
        // Two separators: not a single interval.
        "2026-06-22T10:00:00.000Z/PT1H/PT1H",
    ] {
        if validate_last_active_at(rejected).is_ok() {
            bail!("{VECTOR_ID_LAST_ACTIVE_AT_BUCKET} accepted the malformed value `{rejected}`");
        }
        let mut projection = PresenceProjection::new();
        if projection
            .apply(&presence_plaintext(
                json!({"state": "idle", "last_active_at": rejected}),
                1,
            )?)
            .is_ok()
        {
            bail!(
                "{VECTOR_ID_LAST_ACTIVE_AT_BUCKET} projected a presence signal carrying `{rejected}`"
            );
        }
    }
    Ok(())
}

// ─── VECT-PS-3 — status_message bounds ─────────────────────────────────────

/// §3.3: `status_message` is at most 256 Unicode code points, NFC-normalised,
/// and carries no C0/C1 control other than U+0009 / U+000A.
pub fn run_status_message_bounds_vector() -> Result<()> {
    let at_limit = "字".repeat(256);
    validate_status_message(&at_limit).map_err(|error| {
        anyhow::anyhow!(
            "{VECTOR_ID_STATUS_MESSAGE_BOUNDS} rejected a 256-code-point value: {error}"
        )
    })?;
    validate_status_message("In a meeting\tuntil\n15:00").map_err(|error| {
        anyhow::anyhow!("{VECTOR_ID_STATUS_MESSAGE_BOUNDS} rejected permitted whitespace: {error}")
    })?;

    let over_limit = "字".repeat(257);
    for rejected in [
        over_limit.as_str(),
        // U+0301 combining acute after `e`: not NFC.
        "cafe\u{301}",
        // C0 control other than tab / newline.
        "bell\u{7}",
        // C1 control.
        "next\u{85}line",
    ] {
        if validate_status_message(rejected).is_ok() {
            bail!("{VECTOR_ID_STATUS_MESSAGE_BOUNDS} accepted a malformed status_message");
        }
        // As in VECT-PS-1, the drop may land at the plaintext gate or at the
        // projection. Both are conformant; retaining the value is not.
        let Ok(plaintext) =
            presence_plaintext(json!({"state": "dnd", "status_message": rejected}), 1)
        else {
            continue;
        };
        let mut projection = PresenceProjection::new();
        if projection.apply(&plaintext).is_ok() {
            bail!(
                "{VECTOR_ID_STATUS_MESSAGE_BOUNDS} projected a presence signal with a malformed status_message"
            );
        }
    }
    Ok(())
}

// ─── VECT-PS-4 — deterministic multi-device aggregation ────────────────────

/// §3.3: the receiver aggregates an actor's devices itself. Only signals whose
/// outer *and* plaintext TTL are unexpired and whose sequence has not regressed
/// count; `state` folds under `dnd > online > idle`, falling back to `offline`
/// when nothing valid remains; `status_message` takes the latest `sent_at`.
pub fn run_multi_device_aggregation_vector() -> Result<()> {
    let mut projection = PresenceProjection::new();
    projection.apply(&device_presence(
        "000000000005",
        json!({"state": "idle"}),
        1,
        sent_at(),
    )?)?;
    projection.apply(&device_presence(
        "000000000006",
        json!({"state": "dnd", "status_message": "In a meeting"}),
        1,
        sent_at() + Duration::seconds(1),
    )?)?;
    projection.apply(&device_presence(
        "000000000007",
        json!({"state": "online"}),
        1,
        sent_at(),
    )?)?;

    if projection.aggregated(&actor()?, sent_at()) != PresenceStatus::Dnd {
        bail!(
            "{VECTOR_ID_MULTI_DEVICE_AGGREGATION} did not apply the dnd > online > idle priority"
        );
    }
    if projection.status_message(&actor()?, sent_at()) != Some("In a meeting") {
        bail!(
            "{VECTOR_ID_MULTI_DEVICE_AGGREGATION} did not take the latest sent_at status message"
        );
    }

    // A regressed sequence on a device is dropped and must not roll that
    // device's state back.
    if projection
        .apply(&device_presence(
            "000000000006",
            json!({"state": "offline"}),
            1,
            sent_at() + Duration::seconds(2),
        )?)
        .is_ok()
    {
        bail!("{VECTOR_ID_MULTI_DEVICE_AGGREGATION} accepted a non-advancing payload_sequence");
    }
    if projection.aggregated(&actor()?, sent_at()) != PresenceStatus::Dnd {
        bail!("{VECTOR_ID_MULTI_DEVICE_AGGREGATION} let a dropped signal change the aggregate");
    }

    // Past the plaintext TTL nothing valid remains, which is `offline` — not a
    // sticky last-known state.
    let after_ttl = sent_at() + Duration::seconds(31);
    if projection.aggregated(&actor()?, after_ttl) != PresenceStatus::Offline {
        bail!("{VECTOR_ID_MULTI_DEVICE_AGGREGATION} kept an expired signal in the aggregate");
    }
    if projection.status_message(&actor()?, after_ttl).is_some() {
        bail!("{VECTOR_ID_MULTI_DEVICE_AGGREGATION} kept an expired status message");
    }
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────────

fn actor() -> Result<DidCoreId> {
    Ok(DidCoreId::new("did:webvh:z6mkfixture:alice.example")?)
}

fn realm() -> Result<RealmId> {
    Ok(RealmId::new(
        "ak:realm:AYcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_",
    )?)
}

fn sent_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
        .single()
        .expect("static fixture instant is unambiguous")
}

fn presence_plaintext(fields: Value, payload_sequence: u64) -> Result<SignalPlaintext> {
    device_presence("000000000005", fields, payload_sequence, sent_at())
}

/// A decrypted presence plaintext exactly as `profiles-presence.md` §3.3
/// defines it: `kind`, `actor_id`, `state`, `payload_sequence` and `ttl_ms` at
/// minimum, with `status_message` / `last_active_at` optional. The outer
/// `signal_class` is `session`, whose 30-second ceiling bounds `expires_at`.
fn device_presence(
    device_suffix: &str,
    fields: Value,
    payload_sequence: u64,
    sent_at: DateTime<Utc>,
) -> Result<SignalPlaintext> {
    const TTL_MS: u64 = 30_000;
    let mut body = serde_json::Map::new();
    body.insert("kind".to_owned(), json!(SIGNAL_PLAINTEXT_KIND_PRESENCE));
    body.insert("actor_id".to_owned(), json!(actor()?.as_str()));
    body.insert("payload_sequence".to_owned(), json!(payload_sequence));
    body.insert("ttl_ms".to_owned(), json!(TTL_MS));
    if let Some(extra) = fields.as_object() {
        for (key, value) in extra {
            body.insert(key.clone(), value.clone());
        }
    }
    debug_assert_eq!(SignalClass::Session.max_ttl(), Duration::seconds(30));
    // The typed profile is what a receiver actually dispatches to
    // (`sync/signal.md` §1.1), so the fixture carries it rather than a bare
    // JSON body. A `state` outside the closed v1 set fails here — which is the
    // §3.2 drop these vectors assert — so it is surfaced as the payload the
    // vector then feeds to the projection.
    let payload = garth::open_signal_plaintext(&arkret_canonical::canonical_json_bytes(
        &Value::Object(body.clone()),
    )?)
    .map_err(|error| anyhow::anyhow!("presence fixture is not a registered plaintext: {error}"))?;
    Ok(SignalPlaintext {
        kind: SIGNAL_PLAINTEXT_KIND_PRESENCE.to_owned(),
        actor_id: actor()?,
        payload_sequence,
        ttl_ms: Some(TTL_MS),
        payload,
        sent_at,
        expires_at: sent_at + Duration::milliseconds(TTL_MS as i64),
        scope_ref: ScopeRef::Realm { realm_id: realm()? },
        seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))?,
        sender_device_id: DeviceId::new(format!(
            "ak:device:01904100-0000-7000-8000-{device_suffix}"
        ))?,
    })
}

/// Suite entry point — runs all presence receiver vectors back to back.
pub fn run_presence_signal_vector_suite() -> Result<()> {
    if ALL_PRESENCE_SIGNAL_VECTOR_IDS.len() != 4 {
        bail!(
            "expected 4 presence signal vector ids, got {}",
            ALL_PRESENCE_SIGNAL_VECTOR_IDS.len()
        );
    }
    run_state_closed_set_vector()?;
    run_last_active_at_bucket_vector()?;
    run_status_message_bounds_vector()?;
    run_multi_device_aggregation_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_receiver_vectors_run_clean() {
        run_presence_signal_vector_suite().unwrap();
    }
}
