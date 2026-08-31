# Event Actor authoring regression

Evidence class: fixture-only. No live product or server acceptance claim.

Source: `tests/harness/event-actor.spec.ts`.

Spec basis: `event-envelope.schema.json` and `common-ids.schema.json#/$defs/actor_id`.
The SDK derives and signs Events with complete account Actors. The same principal
at two Stations must produce distinct signed bytes. Proof refresh preserves this
identity and rederives the Event ID after actor chain changes. A fake frontier
transport checks exact structured selection and accepts an equal JSON Actor
returned as a different object instance. Retired scalar Actors are rejected.
