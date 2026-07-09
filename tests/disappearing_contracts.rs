use cokret_core::models::{
    ContentBlock, DisappearingMessageExpiry, DisappearingMessageExpiryTrigger,
    MessageCreatePayload, StrandId,
};
use serde_json::{Value, json};

#[derive(Debug, PartialEq, Eq)]
enum SendDecision {
    SubmitDisappearing,
    SubmitPermanent,
    RejectUnsupported,
}

#[derive(Debug, PartialEq, Eq)]
enum ProjectionShape {
    Message,
    ExpiryStub,
}

#[derive(Debug)]
struct ProjectionOutcome {
    shape: ProjectionShape,
    body_present: bool,
    key_material_present: bool,
    stub: Value,
}

fn strand_id() -> StrandId {
    StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap()
}

fn expiry(trigger: DisappearingMessageExpiryTrigger) -> DisappearingMessageExpiry {
    DisappearingMessageExpiry::new(60_000, trigger)
        .unwrap()
        .with_grace_ms(5_000)
}

fn payload_for(trigger: DisappearingMessageExpiryTrigger) -> Value {
    MessageCreatePayload::with_content(
        strand_id(),
        "discussion",
        ContentBlock::text("temporary body").to_value().unwrap(),
    )
    .with_message_id("ak:message:01904100-0000-7000-8000-000000000003")
    .with_expiry(expiry(trigger))
    .to_value()
    .unwrap()
}

fn send_decision(supports_disappearing: bool, payload: &Value) -> SendDecision {
    if payload.get("expiry").is_none() {
        return SendDecision::SubmitPermanent;
    }
    if supports_disappearing {
        SendDecision::SubmitDisappearing
    } else {
        SendDecision::RejectUnsupported
    }
}

fn project_on_send(
    expiry: &DisappearingMessageExpiry,
    anchor_ms: u64,
    now_ms: u64,
) -> ProjectionOutcome {
    assert_eq!(expiry.trigger, DisappearingMessageExpiryTrigger::OnSend);
    let expires_at_ms = anchor_ms + expiry.ttl_ms + expiry.grace_ms.unwrap_or(0);
    if now_ms < expires_at_ms {
        return ProjectionOutcome {
            shape: ProjectionShape::Message,
            body_present: true,
            key_material_present: true,
            stub: json!({}),
        };
    }

    ProjectionOutcome {
        shape: ProjectionShape::ExpiryStub,
        body_present: false,
        key_material_present: false,
        stub: json!({
            "message_id": "ak:message:01904100-0000-7000-8000-000000000003",
            "strand_id": strand_id().as_str(),
            "track_name": "discussion",
            "expiry_stub": true,
            "expiry_reason": "disappearing_expired",
            "expired_at_ms": expires_at_ms,
            "audit_ref": "ak:event:01904100-0000-7000-8000-000000000004"
        }),
    }
}

fn late_recovery_decision(outcome: &ProjectionOutcome) -> (&'static str, Option<&'static str>) {
    if outcome.shape == ProjectionShape::ExpiryStub {
        ("reject", Some("late_recovery_rejected_expired"))
    } else {
        ("allow", None)
    }
}

#[test]
fn disappearing_message_payloads_keep_expiry_for_all_triggers() {
    for (trigger, expected_wire) in [
        (DisappearingMessageExpiryTrigger::OnSend, "on_send"),
        (
            DisappearingMessageExpiryTrigger::OnFirstRead,
            "on_first_read",
        ),
        (DisappearingMessageExpiryTrigger::OnLastRead, "on_last_read"),
    ] {
        let payload = payload_for(trigger);
        assert_eq!(payload["expiry"]["ttl_ms"], 60_000);
        assert_eq!(payload["expiry"]["trigger"], expected_wire);
        assert_eq!(payload["expiry"]["grace_ms"], 5_000);
        assert!(payload.get("expiry").is_some());
        cokret_core::schema::event_payload_validator_catalog()
            .unwrap()
            .validate_payload("ck.message.create", &payload)
            .unwrap();

        assert_eq!(
            send_decision(false, &payload),
            SendDecision::RejectUnsupported,
            "unsupported implementations must not downgrade expiry payloads to permanent messages"
        );
        assert_eq!(
            send_decision(true, &payload),
            SendDecision::SubmitDisappearing
        );
    }

    let permanent = MessageCreatePayload::with_content(
        strand_id(),
        "discussion",
        ContentBlock::text("ordinary body").to_value().unwrap(),
    )
    .to_value()
    .unwrap();
    assert_eq!(
        send_decision(false, &permanent),
        SendDecision::SubmitPermanent
    );
}

#[test]
fn on_send_grace_projection_stubs_and_shreds_temporary_material() {
    let expiry = expiry(DisappearingMessageExpiryTrigger::OnSend);
    let anchor_ms = 1_000;

    let before_grace_end = project_on_send(&expiry, anchor_ms, 65_999);
    assert_eq!(before_grace_end.shape, ProjectionShape::Message);
    assert!(before_grace_end.body_present);
    assert!(before_grace_end.key_material_present);

    let expired = project_on_send(&expiry, anchor_ms, 66_000);
    assert_eq!(expired.shape, ProjectionShape::ExpiryStub);
    assert!(!expired.body_present);
    assert!(!expired.key_material_present);
    assert_eq!(expired.stub["expiry_stub"], true);
    assert_eq!(expired.stub["expiry_reason"], "disappearing_expired");
    for forbidden in [
        "content",
        "encrypted_content",
        "attachment_preview",
        "push_snippet",
        "search_tokens",
        "redacted",
        "redaction_ref",
    ] {
        assert!(
            expired.stub.get(forbidden).is_none(),
            "expiry stub leaked forbidden field {forbidden}"
        );
    }

    assert_eq!(
        late_recovery_decision(&expired),
        ("reject", Some("late_recovery_rejected_expired"))
    );
}
