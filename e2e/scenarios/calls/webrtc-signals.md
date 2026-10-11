# WebRTC Signal Catalog

Verifies the `ak.call.signal` v2 signal catalog against a live coland instance.
Each signal type is appended to a fresh call session and read back with a
monotonic `seq`, sender DID, and `device_proof`.

Covered signal types: offer, answer, ice, hangup, reject, mute_state,
media_state, speaking, focus_join, focus_leave, error, device_change,
renegotiate.
