# Complement-Inspired Contrix Test Map

Complement treats a homeserver as a black box: deploy real instances, create
high-level test clients, and validate protocol behavior by domain. `cotest`
applies the same pattern to Contrix.

## Concept Mapping

- Complement deployment helpers map to `ContrixServer` and `TestServerGroup`.
- Complement client helpers map to `TestActorClient`, shared HTTP assertions,
  and selected `contrix-rust-sdk` helpers.
- Complement's domain-oriented test packages map to `src/scenarios/*.rs`.
- Complement federation coverage maps to `federation_readiness`,
  `federation_contract`, and `federation_collaboration`.
- Complement's out-of-repo discipline maps to keeping reusable logic in `src/`
  and leaving `tests/` as wrappers only.

## Coverage Translation

- Service and framework surface:
  health, server description, supported operations, unknown routes, bad JSON,
  wrong methods, and standard error envelopes.
- Account and social graph:
  register, login, logout, session checks, duplicate handling, and contact
  edge cases.
- Collaboration and policy:
  space lifecycle, membership, permissions, sync projection, and private
  plaintext policy enforcement.
- Repo and sync:
  commit submission, idempotency, CAS conflicts, read paths, repo sync,
  directory/index parameter handling, and expanded commit reads.
- Identity, authz, and realtime:
  identity resolution/log/receipts, grant and policy document lifecycle,
  presence/typing, push rules, and WebRTC signaling.
- Delivery and media:
  keys, to-device delivery, blob upload/download, range requests, and payload
  preservation.
- Federation:
  readiness checks, public contract validation, and end-to-end cross-server
  collaboration behavior.
- Extension gaps:
  executable coverage for missing applet/agent route surfaces so gaps remain
  visible without leaving ignored placeholder tests behind.
