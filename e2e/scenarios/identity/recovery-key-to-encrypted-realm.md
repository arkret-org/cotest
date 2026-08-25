# Recovery Key to encrypted Realm

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

The scenario creates a fresh account in the browser, confirms the generated 24-word Recovery Key, observes Inkson's real RFC 9420 KeyPackage upload, creates an `mls_rfc9420` Realm, writes encrypted timeline content, reloads the same browser profile, and reads the content again. It fails on any recovery gate, unexpected Arkret 5xx, `frontier_unavailable`, request failure, MLS runtime failure, or retry exhaustion.
