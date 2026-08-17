# WebRTC Media Token Exchange (AKP-0010)

Verifies the `ak.realm.media_service` -> media token exchange path against a
live soland instance.

## Setup

1. Register Alice; create a public realm she owns.
2. Project a `ak.realm.media_service` epoch with a single LiveKit focus
   (`ak:focus:livekit-lhr`, `issuer_kid = did:web:media.example#media-token`,
   `e2ee_key_source = mls-exporter`).
3. Commit the first durable `ak.call.state` for the call, including the
   selected `session_focus`, and exchange signaling through
   `POST /_arkret/self/signal` with encrypted `ak.call.signal` plaintext; no
   soland-private WebRTC session surface is used.

## Steps & Expectations

- `POST /_arkret/self/rtc/token` for the committed `session_focus` returns a
  `CallMediaTokenExchangeOutcome`:
  - `backend_kind = livekit`, `connect_url` echoes the focus config.
  - `participant_binding.scheme = ak.media.participant_binding.v1` with the full
    bound tuple (issuer_kid / realm_id / call_id / focus_id / actor_id /
    device_id / participant_identity / expires_at / sig).
  - `service_signature` is issuer-kid-prefixed.
  - `backend_token` decodes to a LiveKit JWT: `iss`, `sub` =
    `participant_identity`, `video.room` is the opaque backend room id derived
    from `(realm_id, call_id, focus_id)` (`ak_call_<sha256-prefix>`, never raw
    protocol ids), `canPublish`, `canPublishSources` = [microphone, camera]
    (no `screen_share` without `capability_refs`), `canSubscribe = true`.
- An off-focus `focus_id` fails closed with `focus_mismatch`.
- A realm member who is not a call participant gets
  `participant_identity_unrecognised`.

Spec: crypto-media/media-service-binding.md §5/§8.1, bindings/livekit.md §2/§5,
conformance/conformance-vectors.md §12.10/§12.16-§12.19.
