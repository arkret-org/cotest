//! S5 — a Message author edits and then retracts a plaintext Message through
//! the single Event/RealmCommit carrier (`zh/models/strand-and-message.md`
//! §9.5, `zh/sync/current-results.md` `message_revision` / `object_redaction`).
//!
//! The scenario proves, against a live Soland:
//!
//! 1. Bob joins Alice's Realm by accepting her directed Invite;
//! 2. Alice's `ak.message.revise` of her Message is accepted with a RealmCommit on the Realm
//!    stream, and an exact replay is the stored `duplicate` outcome naming the same Commit;
//! 3. the same edit from Bob, a joined member holding no edit action, and from an account outside
//!    the Realm is `capability_denied` and appends no RealmCommit;
//! 4. Bob's own scan discloses the create and the revise in full, so the latest version he reads is
//!    the revise body;
//! 5. `ak.message.redact` is accepted, after which Bob's scan keeps the create and revise Commit
//!    slots as withheld branches while the redaction itself stays disclosed;
//! 6. a revise of the retracted Message is refused and appends no RealmCommit.

use anyhow::{Context, Result, anyhow, ensure};
use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, InvitePreviousState,
};
use arkret_wire::{AccountId, DidCoreId, InviteId};
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{
    CanonicalJsonBody, TestActorClient, actor_core_id, expect_json, invite_create_payload,
    message_redact_payload, message_revise_text_payload, submitted_event_id,
};
use crate::scenarios::invite_create_and_dispatch::InviteStation;

/// The committed Realm stream as `(event_ref, disclosed?)` per Commit, plus
/// the disclosed Event of every fully disclosed row.
async fn committed_stream(
    client: &TestActorClient,
    realm_id: &str,
) -> Result<Vec<(String, Option<Value>)>> {
    let scanned = client.realm_seal_frontier(realm_id).await?;
    scanned["committed_events"]
        .as_array()
        .ok_or_else(|| anyhow!("committed stream scan missing events: {scanned}"))?
        .iter()
        .map(|item| {
            let event_ref = item["commit"]["event_ref"]
                .as_str()
                .ok_or_else(|| anyhow!("committed row has no event_ref: {item}"))?
                .to_owned();
            let disclosed = match item.get("event") {
                Some(event) => Some(event.clone()),
                None => {
                    ensure!(
                        item["event_disclosure"]["status"] == "withheld",
                        "a row without its Event must be the withheld branch: {item}"
                    );
                    None
                }
            };
            Ok((event_ref, disclosed))
        })
        .collect()
}

async fn submit(actor: &TestActorClient, event: arkret_wire::Event) -> Result<(StatusCode, Value)> {
    let response = actor
        .post("/_arkret/self/events")
        .canonical_json(&crate::publication::initial_submission(event, "")?)?
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

/// The registered problem code of a refusal: the final segment of its
/// problem `type` URI.
fn problem_code(body: &Value) -> &str {
    body["type"]
        .as_str()
        .and_then(|kind| kind.rsplit('/').next())
        .unwrap_or("<no problem type>")
}

fn row<'a>(stream: &'a [(String, Option<Value>)], event_id: &str) -> Result<&'a Option<Value>> {
    stream
        .iter()
        .find(|(event_ref, _)| event_ref == event_id)
        .map(|(_, disclosed)| disclosed)
        .ok_or_else(|| anyhow!("the committed stream has no Commit for {event_id}"))
}

pub async fn message_edit_and_retract_run() -> Result<()> {
    let station = InviteStation::spawn("message-edit-and-retract").await?;
    let author = station
        .grant_bearing_client(
            "alice-message-edit-retract",
            "ak:device:01904100-0000-7000-8000-0000000000c5",
        )
        .await
        .context("bootstrap the author client")?;
    let member = station
        .grant_bearing_client(
            "bob-message-edit-retract",
            "ak:device:01904100-0000-7000-8000-0000000000e5",
        )
        .await
        .context("bootstrap the member client")?;
    let outsider = station
        .grant_bearing_client(
            "mallory-message-edit-retract",
            "ak:device:01904100-0000-7000-8000-0000000000d5",
        )
        .await
        .context("bootstrap the outsider client")?;
    let realm_id = author
        .create_realm("Message Edit And Retract")
        .await
        .context("create the Realm")?;
    let strand_id = author.default_strand_id(&realm_id)?;

    // (1) Bob joins by accepting Alice's directed Invite.
    let invited = author
        .submit_event(
            &realm_id,
            "ak.invite.create",
            invite_create_payload(
                &member.actor,
                member.service_id(),
                format!("sha256:{}", "e".repeat(64)),
                Utc::now() + ChronoDuration::days(7),
            )?,
        )
        .await
        .context("invite Bob")?;
    let member_account = AccountId::new(
        DidCoreId::new(actor_core_id(&member.actor)?)?,
        DidCoreId::new(member.service_id().to_owned())?,
    );
    member
        .submit_event(
            &realm_id,
            "ak.invite.accept",
            serde_json::to_value(InviteAcceptPayload::directed(
                InviteId::from_event_id(&submitted_event_id(&invited)?),
                member_account,
                InvitePreviousState::Pending,
            ))?,
        )
        .await
        .context("Bob accepts and joins")?;

    let sent = author
        .send_message(&realm_id, &strand_id, "first draft")
        .await
        .context("send the Message")?;
    let message_event_id = submitted_event_id(&sent)?;

    // (2) the author's edit is committed on the Realm stream.
    let revise = author
        .author_event(
            &realm_id,
            "ak.message.revise",
            message_revise_text_payload(message_event_id.as_str(), "final text")?,
        )
        .await?;
    let (status, revised) = submit(&author, revise.clone()).await?;
    ensure!(
        status == StatusCode::OK && revised["status"] == "committed",
        "the author's revise must be committed: {status} {revised}"
    );
    let (status, replayed) = submit(&author, revise.clone()).await?;
    ensure!(
        status == StatusCode::OK
            && replayed["status"] == "duplicate"
            && replayed["commit"] == revised["commit"],
        "an exact revise replay must return the stored Commit: {status} {replayed}"
    );

    // (3) neither a member without an edit action nor an outsider may edit it.
    let before = committed_stream(&author, &realm_id).await?;
    for (label, editor) in [("member", &member), ("outsider", &outsider)] {
        let foreign = editor
            .author_event(
                &realm_id,
                "ak.message.revise",
                message_revise_text_payload(message_event_id.as_str(), "not yours")?,
            )
            .await?;
        let (status, refused) = submit(editor, foreign).await?;
        ensure!(
            status == StatusCode::FORBIDDEN && problem_code(&refused) == "capability_denied",
            "a {label} revise must be capability_denied: {status} {refused}"
        );
        ensure!(
            committed_stream(&author, &realm_id).await? == before,
            "a refused {label} revise must append no RealmCommit"
        );
    }

    // (4) Bob reads the revise body as the latest version.
    let member_view = committed_stream(&member, &realm_id).await?;
    let revise_row = row(&member_view, revise.event_id.as_str())?
        .as_ref()
        .context("the revise must be disclosed to Bob before retraction")?;
    ensure!(
        revise_row["payload"]["content"]["body"] == "final text",
        "the disclosed latest version must be the revise body: {revise_row}"
    );
    ensure!(
        row(&member_view, message_event_id.as_str())?.is_some(),
        "the original create must be disclosed to Bob before retraction"
    );

    // (5) retraction withholds every version from Bob and keeps its own Commit.
    let redacted = expect_json(
        author.post("/_arkret/self/events").canonical_json(
            &crate::publication::initial_submission(
                author
                    .author_event(
                        &realm_id,
                        "ak.message.redact",
                        message_redact_payload(message_event_id.as_str(), Some("retracted"))?,
                    )
                    .await?,
                "",
            )?,
        )?,
        StatusCode::OK,
    )
    .await
    .context("retract the Message")?;
    let redact_event_id = submitted_event_id(&redacted)?;
    let after = committed_stream(&member, &realm_id).await?;
    ensure!(
        after.len() == member_view.len() + 1,
        "the retraction appends exactly one Commit"
    );
    ensure!(
        row(&after, message_event_id.as_str())?.is_none()
            && row(&after, revise.event_id.as_str())?.is_none(),
        "the retracted create and revise must keep only withheld Commit slots"
    );
    ensure!(
        row(&after, redact_event_id.as_str())?.is_some(),
        "the redaction itself stays disclosed"
    );

    // (6) a retracted Message cannot be edited again.
    let too_late = author
        .author_event(
            &realm_id,
            "ak.message.revise",
            message_revise_text_payload(message_event_id.as_str(), "too late")?,
        )
        .await?;
    let (status, refused) = submit(&author, too_late).await?;
    ensure!(
        !status.is_success() && problem_code(&refused) == "failed_precondition",
        "a revise of a retracted Message must be failed_precondition: {status} {refused}"
    );
    ensure!(
        committed_stream(&member, &realm_id).await? == after,
        "a refused revise must append no RealmCommit"
    );
    Ok(())
}
