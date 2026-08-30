# Recovery Key to plaintext and encrypted Realms

Canonical Arkret Joint Product E2E smoke journey for a new ordinary human account.

## Evidence contract

- `suite_kind`: `joint-e2e`
- `realism_level`: `live-product`
- Real services: Inkson, Coauth, Soland, PostgreSQL-backed persistence
- Mocks: none for Arkret product boundaries; the runner may provide an explicitly named email-delivery mock, but this scenario registers without email
- Identity establishment: Coauth registration UI, OAuth authorization/consent UI, Inkson identity onboarding UI
- Protocol object producer: Inkson and its production Arkret SDK/MLS implementation
- Allowed test bypasses: none
- Forbidden bypasses: session injection, `prepareMlsDevice: false`, `cotest-wire` KeyPackage generation, raw HTTP setup fixtures, recovery override

## Acceptance

The scenario creates a fresh account in the browser, confirms the generated 24-word Recovery Key, and observes Inkson's real RFC 9420 KeyPackage upload. The same account then exercises both ordinary Realm branches:

- `encryption_profile=mls_rfc9420`: create, write, verify that Event ingress contains `encrypted_content` but not the message plaintext, reload the same browser profile, and decrypt/read the message again;
- `encryption_profile=none`: create, write, verify that Event ingress contains the message plaintext and no `encrypted_content`, reload the same browser profile, and read the message again.

It fails on any undeclared recovery gate, unexpected Arkret 5xx, request failure, MLS runtime failure, or retry exhaustion. The normative pending `frontier_unavailable` response during the first unsealed recovery-policy publication remains required and is reconciled by the onboarding flow before either Realm is created.
