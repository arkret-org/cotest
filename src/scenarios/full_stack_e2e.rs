//! Cross-service contract smoke test after the Station identity cutover.
//!
//! The identity leg is delegated to `handle_to_join_e2e`: it proves that a
//! directory result and the resulting membership preserve the complete
//! `(principal_id, station_id)` pair. This module then retains the independent
//! message/push privacy checks from the former broad full-stack scenario.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::events_payloads::{
    CONTENT_KIND_TEXT, ContentBlock, MessageCreatePayload,
};
use arkret_push_policy::blind_payload_sanitizer::{
    sanitize_blind_payload, sanitize_blind_payload_strict,
};
use arkret_wire::StrandId;
use serde_json::{Value, json};

const STRAND_ID: &str = "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";
const PUSH_TARGET_ID: &str = "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8";

pub async fn full_stack_e2e_run() -> Result<()> {
    super::handle_to_join_e2e::handle_to_join_e2e_run()
        .await
        .context("exact-account handle-to-membership leg")?;

    let message = MessageCreatePayload::with_content(
        StrandId::new(STRAND_ID)?,
        "discussion",
        ContentBlock::text("hello from exact Station account"),
    )
    .to_value()?;
    // A text block carries its body in `body` under an `ak.content.text` kind.
    // The former assertion read `content.text`, a field the model has never
    // serialized, so it compared `null` against the string and could only ever
    // fail. It went unnoticed because the entrypoint was `#[ignore]`d for a
    // live leg this scenario does not have.
    ensure!(
        message["content"]["kind"] == CONTENT_KIND_TEXT,
        "message content must be an ak.content.text block, got {}",
        message["content"]["kind"]
    );
    ensure!(
        message["content"]["body"] == "hello from exact Station account",
        "message content body must round-trip verbatim, got {}",
        message["content"]["body"]
    );
    ensure!(
        message["track_name"] == "discussion",
        "message must keep its track name, got {}",
        message["track_name"]
    );

    // The strict blind wakeup requires the pairwise target and coarse wakeup kind.
    let blind = json!({
        "push_target_id": PUSH_TARGET_ID,
        "wakeup_kind": "message"
    });
    sanitize_blind_payload(&blind).context("blind wakeup payload")?;
    sanitize_blind_payload_strict(&blind).context("strict blind wakeup payload")?;

    for forbidden in ["realm_id", "space_id", "strand_id", "event_id", "actor_id"] {
        let mut leaked = blind.clone();
        leaked[forbidden] = Value::String("stable-protocol-identifier".to_owned());
        ensure!(
            sanitize_blind_payload(&leaked).is_err(),
            "blind push must reject {forbidden}"
        );
    }
    Ok(())
}
