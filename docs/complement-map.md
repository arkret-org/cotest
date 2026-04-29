# Complement-Inspired Contrix Test Map

Complement is broad because it treats a server as a black box and tests each
protocol surface in several dimensions: success path, invalid input, auth,
authorization, idempotency, state visibility, sync projection, media/device
delivery, and federation inbound/outbound behavior.

`cotest` maps that style to Contrix as follows:

- Account/Auth: register, login, logout, duplicate handling, invalid IDs, token
  rejection, auth material in query strings.
- Space/Collaboration: create, invite/member changes, owner-only actions,
  private visibility, deleted-space behavior, non-member send denial.
- Sync/Directory/Index: visibility, search limits, missing parameters, thread
  and notification projections, subscribe/backfill/snapshot behavior.
- Repo: commit submit, CAS mismatch, duplicate submit, missing commits,
  operation validation, expanded commit reads.
- Crypto/Delivery/Media: device key upload/query/claim, to-device idempotency,
  opaque payload preservation, blob hash/range/HEAD behavior, push routing.
- Federation: transaction/push/pull/space-members/verify-actor positive and
  invalid-input behavior, remote operation projection into sync/index.
- Torture/Framework: unknown endpoints, wrong methods, invalid JSON, bad query
  parameters, standard error envelopes.

