# cotest Test Strategy

`cotest` is a black-box server conformance suite. A test group starts the server
processes it needs, creates one or more test clients, and exercises public HTTP
APIs only.

## Harness Model

- Single-server group: start one `serverx`; create local clients such as Alice,
  Bob, and Carol.
- Multi-server group: start two or more `serverx` instances; create local
  clients on different servers; verify federation behavior through HTTP
  federation endpoints.
- Each integration test file is named by protocol/business domain, not by
  milestone number.
- `M0`, `M1`, etc. are planning folders only. They must not leak into Rust file
  names, modules, structs, or test function names.

## Feature Groups

### Service and API Contract

- Health and service description.
- Supported operations and advertised protocol version.
- Unknown endpoints, wrong methods, invalid JSON, malformed identifiers.
- Standard Contrix error envelope.

Servers: one. Clients: none or one authenticated client when auth is required.

### Account and Session

- Register user.
- Login account.
- `account/me`.
- Logout account.
- Duplicate account/handle rejection.
- Invalid DID, invalid handle, invalid device ID.
- Missing token, invalid token, and token in query string rejection.

Servers: one. Clients: Alice/Bob/invalid anonymous client.

### Social Graph / Contacts

- Add friend/contact request.
- Accept/reject contact request.
- List contacts.
- Duplicate contact request.
- Self-target and unknown target rejection.
- Contact visibility impact on user directory.

Servers: one for local graph; two for future remote contact/federated discovery.
Clients: Alice and Bob.

### Space Lifecycle and Membership

- Create space.
- Join space or add member, depending on server API surface.
- Delete space.
- Add member.
- Remove member.
- Owner-only mutation checks.
- Private/public visibility.
- Sending events denied for non-members.
- Deleted spaces disappear from sync/directory/index and reject new writes.

Servers: one for local; two for federated invite/join/member propagation.
Clients: owner, member, outsider.

### Applets

- Add applet to a space.
- Delete applet.
- Query applet metadata.
- Applet portal/transaction behavior.
- Permission checks for applet installation/removal.

Current `serverx` state: schema and SDK names exist, but HTTP routes are not
registered. These tests should be added as pending/ignored or implemented after
the server exposes applet endpoints.

Servers: one initially; two when applet state must federate.
Clients: space owner, member, outsider.

### AI Agents

- Add AI agent to a space.
- Delete AI agent.
- Agent event emission.
- Agent permission boundaries.
- Agent memory/state visibility.

Current `serverx` state: no concrete HTTP route has been identified. This needs
server API design before positive tests.

Servers: one initially; two when agent state must federate.
Clients: owner/admin, member, agent principal.

### Events and Entity State

- Send event/message.
- Change entity state.
- Relation/entity create/update/delete operations.
- Reaction/read-marker operations.
- Event ordering and projection.
- Event missing backfill: create a gap, then verify backfill recovers missing
  operations/events.
- Duplicate transaction or idempotency behavior.

Servers: one for local repo/projection; two for missing event backfill over
federation.
Clients: author, reader, outsider.

### Sync, Directory, and Index

- Initial sync.
- Incremental sync.
- Subscribe stream.
- Backfill.
- Snapshot head.
- Search spaces.
- Resolve space.
- Search users/actors/organizations.
- Query/index thread/entity/inbox/notifications.
- Visibility and pagination/cursor errors.

Servers: one and two. Clients: member, outsider, anonymous.

### Repo

- Submit commit.
- Read commit.
- List commits.
- Get operations.
- Repo sync.
- CAS conflict.
- Idempotent duplicate submit.
- Missing commit and unknown operation behavior.
- Invalid operation family rejection.

Servers: one for local; two for federation operation propagation.
Clients: repo author and anonymous protocol client as permitted by API.

### Keys, To-Device, Blob, Push, Moderation

- Upload/query/claim keys.
- One-time key consumption.
- To-device delivery and queue drain.
- Opaque encrypted payload preservation.
- Blob upload/download/HEAD/range/hash mismatch.
- Push register/unregister/notify rejection.
- Moderation report permission checks.

Servers: one for local; two when key/device/blob behavior must federate.
Clients: sender, receiver, outsider.

### Federation

- Remote service metadata and DID verification.
- Transaction receive.
- Push operations.
- Pull operations with cursor.
- Space members.
- Verify actor.
- Cross-server invite/join/member projection.
- Cross-server message/event propagation.
- Missing event backfill over federation.
- Invalid JSON/missing parameter/invalid ID rejection.

Servers: two or more. Clients: local user on each server.

