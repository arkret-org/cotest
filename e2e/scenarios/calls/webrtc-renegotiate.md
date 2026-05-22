# WebRTC Renegotiation

Verifies the live ICE config endpoint and the device-switch renegotiation path.
The scenario requests signed ICE config for a call, emits `device_change`, then
emits `renegotiate` and checks that the tail cursor returns the renegotiation
signal with a valid `device_proof`.
