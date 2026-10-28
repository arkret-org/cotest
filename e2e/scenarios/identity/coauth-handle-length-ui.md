# Coauth username persistence boundaries

Source: `e2e/tests/identity/coauth-handle-length-ui.spec.ts`.

The normative bounds come from `arkret-spec/spec/v1/zh/identity/identity-handles.md`
and `string-profiles.schema.json`: a prepared Human localpart contains 1–128
Unicode code points. JavaScript UTF-16 units and UTF-8 bytes are not code points.

The scenario requires a real Coauth service with password registration, required
email verification, and a configured verification-delivery path. It uses the
existing verification-code helper; it does not replace registration responses,
inject sessions, or disable TLS verification.

For 64, 65 and 128 ASCII characters and 128 valid non-BMP CJK characters (512
UTF-8 bytes), enter the complete username, an independent short unique email,
and the normal test password in the Coauth registration page. Complete email
verification and display-name setup, require finish success, and read the exact
username through the product's authenticated viewer. Reload the account page.
Open a separate browser context, establish that it has no current account, then
sign in with the original complete username and password. Require the same
persisted account and exact username.

For 129 characters, require a normal validation response and readable guidance,
with the original field value retained and no internal persistence error.

This verifies Coauth account registration and password authentication. It does
not claim OAuth authorization, principal founding, recovery-key custody, MLS,
or authenticated Coland business operations. Static inventory entries are not
runtime pass results. The production storage regression separately verifies a
382-code-point / 766-byte canonical handle preference and its verified claim.
