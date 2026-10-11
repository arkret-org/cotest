# Same-server Direct Conversation recovery

Live joint regression using two isolated Coauth accounts, the real Inkson client,
and Coland. Contact request/accept uses the signed protocol helper; conversation
creation, MLS preparation, message sends, reloads, and history rendering use Inkson.
Three independent tests cover ordinary initialization, interrupted acknowledgement,
and a founder sending while the peer device is offline.
All three require bidirectional plaintext delivery, readable history after reload, another
post-reload message, and both participants' encrypted presence to become online.

1. Establish an accepted direct-message Contact and open the same conversation on both clients.
2. Abort the real KeyPackage consume request to interrupt preparation after Welcome delivery.
   In the offline case, abort claim instead, keeping the founder at epoch 0 and
   checking the since_join boundary (§6; history-visibility §3).
3. Assert that the non-founder cannot send without its keys. Require the founder's
   provisional exporter message to be accepted before the peer's durable receipt;
   the offline case disables the peer's network during this send (§7.2).
4. Remove the transport fault and reload both clients; require the same Realm/Strand and enabled composers.
5. After the peer joins, disconnect its device again, send another message, then
   require plaintext delivery on reconnect. Exchange messages in both directions.
6. Reload both clients, verify every authorized message (including post-Add provisional messages),
   then send and receive another message.
   Epoch 0 pre-join content must remain readable by the founder and absent from
   the future peer's plaintext timeline; the test asserts the transmitted epoch.
7. Check each peer's encrypted presence independently with soft assertions; failures
   still fail the test, but do not prevent the message assertions from executing.
8. Reject invalid source proofs, missing receipt-retained Seals, and cryptographically
   rejected response records. Interrupted/offline cases additionally require a
   fetched secret chunk's exact record digest in a successful `installed` ack;
   a manifest acknowledgement or visible optimistic message alone does not pass.

No response is mocked as successful, no binding is inserted into storage, and no
ordinary Realm capability grant is injected to authorize the Direct Conversation.
The fixture's ordinary Realm only prepares the test accounts; all message assertions
target the separate `/direct/` route.

Run through the supported entry with a required scenario and forbidden skips:

```powershell
pwsh -NoProfile -File scripts/run-joint-e2e.ps1 -RunProfile joint-smoke -ServerCount 1 -StartCoauth -StartMocks -PlaywrightProject joint-inkson -Grep 'same-server Direct Conversation' -RequireScenario joint/direct-conversation-live -ForbidSkippedTests
```

This covers interrupted acknowledgement and reload recovery. Expired Welcome/claim
recovery is a separate case; this test does not simulate elapsed claim expiry.
