# WebRTC Recording Gating + Moderation

Verifies recording-policy gating and moderator kick/ban provenance against a
live coland instance.

## Recording gating

- `recording_policy=allow`: `POST .../recording/start` succeeds, returns a
  `recording_blob_ref` of the form `ak:blob:sha256:*` and a `recording_state`.
- `recording_policy=none`: the same call fails with HTTP 412 and wire code
  `recording_policy_violation`.

## Moderation (kick / ban / end-for-all)

- A moderator sends a first-class `ak.call.signal{signal_kind=moderation}` frame.
  A `kick` carries `data.action=kick` with `target_actor_id` + `target_device_id`;
  coland projects it into `ak.component.call.moderation.v1` and the frame is
  readable by the kicked participant in the signal log.
- A `ban` carries `data.action=ban` with `target_actor_id` only (no
  `target_device_id`), encoding the actor-wide ban scope; a banned actor's
  subsequent `/rtc/token` exchange is refused with `call_participant_removed`.
- An `end_for_all` carries `data.action=end_for_all` and drives the derived
  `call_state` to the terminal `ended`.

Moderation now rides the first-class `moderation` signal type server-side; the
`call_moderation_unauthorised` and `call_participant_removed` reducer gates are
pinned by the Rust `call_state.moderator_kick_ban` conformance vector.

Spec: crypto-media/webrtc-signaling.md §3/§3a/§13, crypto-media/call-state.md
§5.2, conformance/conformance-vectors.md §12.16/§12.18.
