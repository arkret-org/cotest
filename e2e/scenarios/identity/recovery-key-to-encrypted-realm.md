# Recovery Key to plaintext and encrypted Realms

Canonical Arkret Joint Product E2E smoke journey for a new ordinary human account.

## Evidence contract

- `suite_kind`: `joint-e2e`
- `realism_level`: `live-product`
- Real services: Inkson, Coauth, Soland, PostgreSQL-backed persistence
- Mocks: none for Arkret product boundaries; the runner may provide an explicitly named email-delivery mock, and this scenario reads the delivered verification code from that mock inbox while submitting it through the Coauth UI
- Identity establishment: Coauth registration UI, OAuth authorization/consent UI, Inkson identity onboarding UI
- Protocol object producer: Inkson and its production Arkret SDK/MLS implementation
- Allowed test bypasses: none
- Forbidden bypasses: session injection, `prepareMlsDevice: false`, `cotest-wire` KeyPackage generation, raw HTTP setup fixtures, recovery override

## Acceptance

All four cases create a fresh account in the browser, confirm the generated 24-word Recovery Key, and observes Inkson's real RFC 9420 KeyPackage upload. Each account then exercises both ordinary Realm branches:

- `encryption_profile=mls_rfc9420`: create, write, verify that Event ingress contains `encrypted_content` but not the message plaintext, reload the same browser profile, decrypt/read the message again, close the entire browser process, reopen the original durable profile, retain the same AccountId and DeviceId, decrypt the original message and send another ciphertext message;
- `encryption_profile=none`: create, write, verify that Event ingress contains the message plaintext and no `encrypted_content`, reload the same browser profile, and read the message again.

It fails on any undeclared recovery gate, unexpected Arkret 5xx, request failure, MLS runtime failure, or retry exhaustion. The normative pending `revision_unavailable` response during the first unsealed recovery-policy publication remains required and is reconciled by the onboarding flow before either Realm is created.

The three response-loss cases interrupt accepted Realm create, default discussion create, or default selection. Each forwards the original product request to the real Station and verifies success, drops its response, and closes the browser process before any Genesis request. The resumed profile uses its original stored identity and keys; it must complete Genesis automatically and all observed retries must retain the exact original signed interrupted request bytes, with one original discussion and one original selection before Genesis. This network fault supplies no protocol object or authority evidence. Normal and interrupted cases both continue through actual encrypted writes, full process restart, original-message decryption and plaintext Realm writes. No session, signer, KeyPackage, private MLS state or recovery override is injected.

A transient `realm_state_snapshot_unavailable` 503 is allowed only on the head read for one of this journey's exact Realm IDs. Every observed unavailable cut must be followed by a successful signed snapshot read for that same Realm. A missing or unrelated Realm, another error code or an unresolved unavailable result still fails. The product must also complete the original Genesis and all real encrypted reads and writes; this condition supplies no absence or authority proof.
