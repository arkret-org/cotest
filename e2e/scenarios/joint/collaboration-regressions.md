# Collaboration findings regression coverage

| Finding | Existing coverage | Added boundary |
| --- | --- | --- |
| Garth #2, Inkson #25 | Native share-link acceptance and encrypted-member tests use separate setup paths | `joint/realm-invite-link-sync.spec.ts`: real share UI, three member pages, plaintext and MLS, accepted sends, peer delivery and post-reload leave |
| Inkson #27 | `identity/account-profile-ui.spec.ts` uploads, deletes, then reloads | Reload while the avatar still exists, require a decoded image and no Blob transport error |
| Inkson #28 | Contact fixtures establish the relation through API helpers | `discovery/contact-request-ui.spec.ts`: cold page, real locator, UI prepare/sign/commit and recipient acceptance |
| Inkson #26 | No supported-address instruction assertion | Separate Contact instructions test; it does not gate the signing regression |
| Coauth #4 | Registration continuation always fills email | `identity/registration-contact-validation.spec.ts`: missing email and phone gives actionable text, never an internal code |
| Coland #11 | `tests/websocket_live.rs` owns direct TLS | `sync/websocket-deployment.spec.ts`: same-origin challenge through the configured public HTTPS deployment, including Caddy when that deployment uses it |

Tests use fresh canonical accounts and normal UI operations, not the previous exploration's fixed profiles. A direct-TLS deployment alone cannot establish proxy coverage; run the WSS deployment case with the real Caddy public URL as well. Use the ordinary joint-stack prerequisites and existing build identity gate. A failure or unavailable prerequisite is not a passing product scenario.
