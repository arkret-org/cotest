# Events Submit Batch Realm Bootstrap

## Intent

Prove `ck.self.events.command.submit` batch mode is a real protocol response path and that `ck.realm.create` materializes the creator's initial Realm membership before subsequent owner writes.

## Strand

1. Register Alice and issue a dev session.
2. Submit a batch body `{ events: [ck.realm.create], idempotency_key }` to `POST /_arkret/self/events`.
3. Assert the response is JSON, accepted, and contains no rejected events.
4. Submit a `ck.message.create` event as Alice into the new Realm.
5. Query the Realm timeline and confirm the message is visible.

## Acceptance

- Batch `ck.self.events.command.submit` never returns an empty 2xx response.
- Realm bootstrap writes the owner membership index before the owner sends the next event.
- The scenario is tagged `@fully-implemented` so `joint-smoke` covers it.
