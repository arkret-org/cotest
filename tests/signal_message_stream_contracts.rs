use arkret::{
    DeviceId, Did, Event, EventId, Hlc, MessageCreatePayload, MessageId, MessageStreamDelta,
    MessageStreamFormat, MessageStreamFrame, MessageStreamId, MessageStreamKeyframe,
    MessageStreamProducer, RealmId, ScopeRef, SealId, StrandId,
};
use chrono::{DateTime, Utc};
use garth::{
    MessageStreamApplyOutcome, MessageStreamProjection, SIGNAL_PLAINTEXT_KIND_MESSAGE_STREAM,
    SignalPlaintext,
};
use serde_json::{Value, json};

fn actor() -> Did {
    Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
}

fn device() -> DeviceId {
    DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
}

fn realm() -> RealmId {
    RealmId::new("ak:realm:01904100-0000-7000-8000-000000000004").unwrap()
}

fn strand() -> StrandId {
    StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap()
}

fn event_id() -> EventId {
    EventId::new("ak:event:01904100-0000-7000-8000-000000000003").unwrap()
}

fn stream_id() -> MessageStreamId {
    MessageStreamId::new("ak:message_stream:01904100-0000-7000-8000-000000000005").unwrap()
}

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-07-28T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
        + chrono::Duration::seconds(seconds)
}

fn plaintext(frame: MessageStreamFrame) -> SignalPlaintext {
    let payload_sequence = frame.payload_sequence();
    let Value::Object(body) = serde_json::to_value(frame).unwrap() else {
        unreachable!()
    };
    SignalPlaintext {
        kind: SIGNAL_PLAINTEXT_KIND_MESSAGE_STREAM.to_owned(),
        actor_id: actor(),
        payload_sequence,
        ttl_ms: None,
        body: body.into_iter().collect(),
        sent_at: at(0),
        expires_at: at(30),
        scope_ref: ScopeRef::Realm { realm_id: realm() },
        seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
        sender_device_id: device(),
    }
}

fn authorize_frame(_: &SignalPlaintext, _: &MessageStreamFrame) -> bool {
    true
}

#[test]
fn producer_and_consumer_self_heal_then_bind_direct_final() {
    let event_id = event_id();
    let message_id = MessageId::from_event_id(&event_id);
    let (mut producer, initial) = MessageStreamProducer::start(
        1,
        event_id.clone(),
        strand(),
        0,
        stream_id(),
        MessageStreamFormat::Markdown,
        0,
    )
    .unwrap();
    let mut projection = MessageStreamProjection::new();
    assert_eq!(
        projection
            .apply(&plaintext(initial), &authorize_frame, at(0))
            .unwrap(),
        MessageStreamApplyOutcome::Activated
    );

    // A missing delta is ignored; a later self-contained keyframe repairs the
    // preview without a reorder buffer or clearing authenticated text.
    let gap = MessageStreamFrame::Delta(
        MessageStreamDelta::new(
            2,
            strand(),
            message_id.clone(),
            0,
            stream_id(),
            2,
            1,
            "lost",
        )
        .unwrap(),
    );
    assert!(matches!(
        projection
            .apply(&plaintext(gap), &authorize_frame, at(1))
            .unwrap(),
        MessageStreamApplyOutcome::Ignored(_)
    ));
    let recovery = MessageStreamFrame::Keyframe(
        MessageStreamKeyframe::new(
            3,
            strand(),
            message_id.clone(),
            0,
            stream_id(),
            3,
            MessageStreamFormat::Markdown,
            "complete preview",
            false,
        )
        .unwrap(),
    );
    assert_eq!(
        projection
            .apply(&plaintext(recovery), &authorize_frame, at(2))
            .unwrap(),
        MessageStreamApplyOutcome::Updated
    );

    let payload = MessageCreatePayload::with_content(
        strand(),
        "discussion",
        arkret::ContentBlock::text("complete final"),
    );
    let final_event = Event::new_with_id_at(
        event_id,
        "ak.message.create",
        ScopeRef::Realm { realm_id: realm() },
        actor(),
        1,
        Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
        payload.to_value().unwrap(),
        at(3),
    )
    .unwrap();
    let removed = projection
        .bind_verified_final(&final_event, &device())
        .unwrap()
        .expect("matching direct final removes preview");
    assert_eq!(removed.message_id, message_id);
    producer.finish();
    assert!(producer.is_finished());
}

#[test]
fn fixture_and_closed_message_create_identity_contract_are_present() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../arkret-spec/spec/v1/artifacts/fixtures/signal-message-stream-fixture.json"
    ))
    .unwrap();
    assert_eq!(fixture["profile"], "ak.profile.signal_message_stream.v1");
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 5);

    let illegal = json!({
        "strand_id": strand().as_str(),
        "track_name": "discussion",
        "message_id": MessageId::from_event_id(&event_id()).as_str(),
        "content": {"kind": "ak.content.text", "body": "must fail"}
    });
    assert!(serde_json::from_value::<MessageCreatePayload>(illegal).is_err());
}
