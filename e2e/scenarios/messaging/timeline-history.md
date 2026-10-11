# Real WASM Timeline History

Owner: 1725, AV-UI-BOUND.

This scenario tests presentation of accepted ordinary Realm messages, not
independent services-live identity acceptance or the Sidecar history matrix.
The browser uses a real Coauth DPoP session fixture; plaintext history is
authored through the existing signed Event helper and accepted by Coland.
It does not inject client projections, message rows, or authority state.

## Acceptance

- Freeze the served WASM, browser viewport/device and 256 accepted messages.
- Alternate body lengths; cold document navigation installs real history.
- Traverse the actual virtual feed and reach every accepted message.
- Mounted rows, including transient DOM peaks, never exceed 120.
- Locate the oldest message, exercise real wheel input, and return to latest.
- Enter and discard an unsent draft without changing accepted history.
- Record cold visible latency, main-thread long tasks and input-to-frame latency.
  Each measured composer input must paint within 1000 ms; long tasks are
  retained as evidence rather than silently discarded.
- Capture the latest-message screenshot and performance JSON as test artifacts.

This does not close mixed ordinary/Sidecar history, late image arrival,
generation preview growth, cancellation of active generation, or semantic
fold/decrypt invalidation. Those remain separate requirements of owner 1725.
