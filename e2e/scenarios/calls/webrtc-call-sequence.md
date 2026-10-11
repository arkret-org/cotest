# WebRTC 1:1 + Multi-Party Signaling Sequence

Verifies the `ak.call.signal` ordering contract against a live coland instance.

## 1:1 sequence

1. Alice + Bob in a shared realm; Alice creates a session pre-registering Bob.
2. Append `invite` (Alice) -> `answer` (Bob) -> `candidate` (Alice) ->
   `hangup` (Alice).

Expected:

- The server assigns a strictly monotonic dense `seq` (1, 2, 3, 4).
- Call Morph: `invite` -> connecting, `answer` -> active, `candidate` leaves
  the lifecycle untouched (ephemeral status), `hangup` -> ended.
- Read-back attributes each frame to the correct sender DID.

## Multi-party focus_join

1. Alice + Bob + Carol in a shared realm; Alice creates an SFU-bound session.
2. Each participant appends `focus_join` for the same `focus_id`.

Expected:

- `focus_join` frames are logged in seq order (alice, bob, carol).
- Each frame carries the shared `focus_id`.

Spec: crypto-media/webrtc-signaling.md §5-§6, crypto-media/call-state.md §4.2,
crypto-media/media-service-binding.md §5.
