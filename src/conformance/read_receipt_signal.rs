//! Joint coverage for the 2026-08-01 Signal plaintext closure
//! (`sync/signal.md` §1.1, `discovery/read-receipts.md` §2.1).
//!
//! Two things the per-repo unit tests structurally cannot show, because each
//! one only ever sees one side of the wire:
//!
//! - **E1** — a read receipt A seals is the same object B opens. The old durable shape could not do
//!   this at all: it carried `receipt_kind` / `schema` / `realm_id` / `created_at`, none of which
//!   the closed profile declares, so a sender's own bytes failed the receiver's
//!   `deny_unknown_fields` parse. This suite seals through the SDK entry and opens through garth's
//!   receiver dispatch, which is the real pair.
//! - **E2** — a genesis Realm bundle carrying `join_policy` is a legal policy_bundle revision.
//!   Before the ruling `join_policy` was not a declared component, so the closed def rejected the
//!   very write `join-policy.md` §3 mandates.
//!
//! Neither needs a live soland: the sealing entry, the receiver dispatch and
//! the bundle payload type are the shared SDK surfaces both sides compile
//! against, so a drift between them is a drift here.

use anyhow::{Result, bail};
use arkret_models_collaboration::events_payloads::RealmPolicyBundlePayload;
use arkret_models_collaboration::signal_plaintext::{
    ReadReceipt, SignalPlaintext, SignalPlaintextKind, open_signal_plaintext, seal_signal_plaintext,
};
use arkret_wire::{DidCoreId, EventId, ReadReceiptScope, StrandId};
use serde_json::{Value, json};

pub const VECTOR_ID_READ_RECEIPT_ROUND_TRIP: &str = "ak.vector.receipt.read.signal_round_trip.v1";
pub const VECTOR_ID_GENESIS_JOIN_POLICY_BUNDLE: &str = "ak.vector.realm.genesis_join_policy.v1";

pub const ALL_READ_RECEIPT_SIGNAL_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_READ_RECEIPT_ROUND_TRIP,
    VECTOR_ID_GENESIS_JOIN_POLICY_BUNDLE,
];

fn actor() -> Result<DidCoreId> {
    Ok(DidCoreId::new("ak:did_core:web:alice.example")?)
}

fn event_id() -> Result<EventId> {
    Ok(EventId::new(
        "ak:event:ATJ_DJ_0dc3yFbBW3UWM7qysprZ6zJPZzhxGzqahfHEA",
    )?)
}

fn strand_id() -> Result<StrandId> {
    Ok(StrandId::new(
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
    )?)
}

/// E1 — A seals a read receipt, B opens it as the same closed profile, and a
/// plaintext missing `payload_sequence` is dropped as `schema_violation`.
pub fn run_read_receipt_round_trip_vector() -> Result<()> {
    let sealed = ReadReceipt::new(
        7,
        actor()?,
        event_id()?,
        ReadReceiptScope::strand(strand_id()?.as_str().to_owned(), Some("discussion")),
    )?;
    let bytes = seal_signal_plaintext(&sealed)?;

    // The receive side dispatches on `kind` and picks exactly one closed type.
    let opened = open_signal_plaintext(&bytes)?;
    if opened.kind() != SignalPlaintextKind::ReadReceipt {
        bail!(
            "{VECTOR_ID_READ_RECEIPT_ROUND_TRIP}: dispatched to {:?}, expected ak.receipt.read",
            opened.kind()
        );
    }
    let SignalPlaintext::ReadReceipt(reopened) = &opened else {
        bail!("{VECTOR_ID_READ_RECEIPT_ROUND_TRIP}: kind and variant disagree");
    };
    if reopened != &sealed {
        bail!("{VECTOR_ID_READ_RECEIPT_ROUND_TRIP}: the receipt B opened is not the one A sealed");
    }
    if opened.payload_sequence() != 7 {
        bail!(
            "{VECTOR_ID_READ_RECEIPT_ROUND_TRIP}: payload_sequence did not survive the round trip"
        );
    }

    // §2.1 — the plaintext restates nothing the signed envelope already
    // carries, and keeps none of the retired durable-object fields.
    let body: Value = serde_json::from_slice(&bytes)?;
    for forbidden in [
        "realm_id",
        "sender_device_id",
        "sent_at",
        "created_at",
        "receipt_kind",
        "schema",
        "ttl_ms",
    ] {
        if body.get(forbidden).is_some() {
            bail!(
                "{VECTOR_ID_READ_RECEIPT_ROUND_TRIP}: read receipt plaintext carries `{forbidden}`"
            );
        }
    }

    // §1.1 — `payload_sequence` is the third component of the receiver dedupe
    // triple. Without it the triple degrades to (device, scope), so a plaintext
    // that omits it MUST be dropped, not defaulted to zero.
    let mut missing = body.clone();
    missing
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("read receipt plaintext is an object"))?
        .remove("payload_sequence");
    let rejected = open_signal_plaintext(&arkret_canonical::canonical_json_bytes(&missing)?);
    match rejected {
        Ok(_) => bail!(
            "{VECTOR_ID_READ_RECEIPT_ROUND_TRIP}: a receipt without payload_sequence was admitted"
        ),
        Err(error) => {
            let error = error.to_string();
            if !error.contains("schema_violation") {
                bail!(
                    "{VECTOR_ID_READ_RECEIPT_ROUND_TRIP}: expected schema_violation, got `{error}`"
                );
            }
        }
    }

    // An unregistered `kind` is dropped rather than parsed by field name, even
    // though every other field of this body is a valid read receipt.
    let mut unregistered = body;
    unregistered
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("read receipt plaintext is an object"))?
        .insert("kind".to_owned(), json!("ak.receipt.delivered"));
    if open_signal_plaintext(&arkret_canonical::canonical_json_bytes(&unregistered)?).is_ok() {
        bail!("{VECTOR_ID_READ_RECEIPT_ROUND_TRIP}: an unregistered payload kind was admitted");
    }
    Ok(())
}

/// E2 — a genesis Realm bundle may carry `join_policy`, and the value survives
/// a full serialize / parse round trip through the closed def.
pub fn run_genesis_join_policy_bundle_vector() -> Result<()> {
    let join_policy = json!({
        "combinator": "all",
        "gates": [{
            "gate_id": "open",
            "kind": "principal_admission",
            "auto_resolve": true,
            "allowed_principal_dids": ["did:web:alice.example"]
        }]
    });
    let mut bundle = RealmPolicyBundlePayload::new(1);
    bundle.content_scheme = Some("mls_exporter_aead_v1".to_owned());
    bundle.join_policy = Some(serde_json::from_value(join_policy)?);
    bundle.aad_visibility = Some(
        arkret_models_collaboration::events_payloads::RealmAadVisibilityPolicy {
            event_id: arkret_models_crypto::EncryptedEnvelopeAadVisibility::RoutingDigest,
        },
    );

    let wire = bundle.to_value()?;
    if wire.get("join_policy").is_none() {
        bail!(
            "{VECTOR_ID_GENESIS_JOIN_POLICY_BUNDLE}: join_policy did not serialize; the bundle is \
             the only carrier for a component with no facet Event kind"
        );
    }
    let reparsed: RealmPolicyBundlePayload = serde_json::from_value(wire)?;
    if reparsed != bundle {
        bail!("{VECTOR_ID_GENESIS_JOIN_POLICY_BUNDLE}: the bundle did not survive a round trip");
    }

    // The `cas_register` hazard: a follow-up revision authored from the
    // accepted value keeps every component. Authoring one from scratch clears
    // them — including the aad_visibility ceiling, which then presents
    // downstream as "dedupe suddenly broke" rather than as a policy edit.
    let next = bundle.restate(2);
    if next.join_policy.is_none() || next.aad_visibility != bundle.aad_visibility {
        bail!(
            "{VECTOR_ID_GENESIS_JOIN_POLICY_BUNDLE}: restating a revision must carry every \
             component forward"
        );
    }
    if RealmPolicyBundlePayload::new(2).aad_visibility.is_some() {
        bail!(
            "{VECTOR_ID_GENESIS_JOIN_POLICY_BUNDLE}: a bare revision must start with no components \
             so the clearing hazard stays visible at the call site"
        );
    }
    Ok(())
}

/// Suite entry point.
pub fn run_read_receipt_signal_vector_suite() -> Result<()> {
    run_read_receipt_round_trip_vector()?;
    run_genesis_join_policy_bundle_vector()?;
    Ok(())
}
