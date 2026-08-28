# WebRTC Media Token Exchange (AKP-0010)

Verifies the `ak.realm.media_service` foci -> media token exchange path against
a live soland instance.

## Setup

1. Register Alice; create a public realm she owns.
2. Project a `ak.realm.media_service` epoch naming this deployment's
   `service_id` with two foci (closed `media_service_focus` shape:
   `focus_id` / `focus_kind` / `token_endpoint` / `connect_url` only):
   - `livekit-lhr` (`focus_kind = livekit`)
   - `arkret-native-reference` (`focus_kind = arkret_native`)
   Issuance configuration (`issuer_kid`, TTL, e2ee key source) is deployment
   configuration of the issuing service, never Realm cell state: the joint
   runner leaves `SOLAND_MEDIA_ISSUER_KID` unset, so `issuer_kid` /
   `participant_binding.issuer_kid` anchors on `<service DID>#media-1`, and each
   focus `token_endpoint` origin must equal the deployment's public base URL
   (`POST /_arkret/self/rtc/token`) or issuance fails closed
   (media-service-binding.md §2.1/§3).
3. No `ak.call.state` commit and no `/_arkret/self/signal` signaling session
   are required: token exchange authorization is Realm membership + the
   `ak.call.join` capability + the durable ban set
   (media-service-binding.md §6 / call-state.md §4.1). The Realm owner holds
   all capabilities, so no explicit grant is needed for her.

## Steps & Expectations

- `POST /_arkret/self/rtc/token` for a configured `focus_id` returns a
  `CallMediaTokenExchangeOutcome`:
  - `backend_kind = livekit`, `connect_url` echoes the focus config.
  - `participant_identity` is a fresh `ak:rtc_participant:<uuidv7>` handle.
  - `participant_binding.scheme = ak.media.participant_binding.v1` with the full
    bound tuple (issuer_kid / realm_id / call_id / focus_id / actor_id /
    device_id / participant_identity / issued_at / expires_at / sig).
  - `participant_binding.sig` is the single Realm-anchored media service
    assertion; the closed outcome has no redundant `service_signature`.
  - `backend_token` decodes to a LiveKit JWT: `iss` = the runner-configured
    `SOLAND_LIVEKIT_API_KEY` (`did:web:media.example#media-token`, a backend
    credential distinct from the Realm-anchored issuer kid), `sub` =
    `participant_identity`, `video.room` is the opaque backend room id derived
    from `(realm_id, call_id, focus_id)` (`ak_call_<sha256-prefix>`, never raw
    protocol ids), `canPublish`, `canPublishSources` = [microphone, camera]
    (no `screen_share` without `capability_refs`), `canSubscribe = true`, and
    `exp - iat` within the 600s TTL ceiling.
- The `arkret_native` focus returns a closed signed token object
  (`kid` / `sig` / `payload`); the payload carries `call_id` / `focus_id` /
  `participant_identity` / `media` / `issued_at` / `expires_at` and never
  `actor_id` / `device_id` / `realm_id`.
- An unknown `focus_id` fails closed with 409 `focus_mismatch`.
- A Realm member lacking `ak.call.join` is refused with 403
  `capability_denied`; granting the capability admits them.

Spec: crypto-media/media-service-binding.md §5/§8.1, bindings/livekit.md §2/§5,
conformance/conformance-vectors.md §12.10/§12.16-§12.19.
