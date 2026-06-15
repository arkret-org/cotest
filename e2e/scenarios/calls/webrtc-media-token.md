# WebRTC Media Token Exchange (CKP-0010)

Verifies the `ck.realm.media_service` -> media token exchange path against a
live soland instance.

## Setup

1. Register Alice; create a public realm she owns.
2. Project a `ck.realm.media_service` epoch with a single LiveKit focus
   (`ck:focus:livekit-lhr`, `issuer_kid = did:web:media.example#media-token`,
   `e2ee_key_source = mls-exporter`).
3. Create an ephemeral WebRTC session (`POST /_soland/self/webrtc/sessions`).

## Steps & Expectations

- `POST /_cokret/self/rtc/token` for the committed `session_focus` returns a
  `CallMediaTokenExchangeOutcome`:
  - `backend_type = livekit`, `connect_url` echoes the focus config.
  - `participant_binding.scheme = ck.media.participant_binding.v1` with the full
    bound tuple (issuer_kid / realm_id / call_id / focus_id / actor_id /
    device_id / participant_identity / expires_at / sig).
  - `service_signature` is issuer-kid-prefixed.
  - `backend_token` decodes to a LiveKit JWT: `iss`, `sub` =
    `participant_identity`, `video.room` is opaque (`ck_call_*`, never the raw
    call id), `canPublish`, `canPublishSources` = [microphone, camera]
    (no `screen_share` without `capability_refs`), `canSubscribe = true`.
- An off-focus `focus_id` fails closed with `focus_mismatch`.
- A realm member who is not a call participant gets
  `participant_identity_unrecognised`.

Spec: crypto-media/media-service-binding.md §5/§8.1, bindings/livekit.md §2/§5,
conformance/conformance-vectors.md §12.10/§12.16-§12.19.
