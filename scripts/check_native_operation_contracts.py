"""Check native obligations; declarations, refusals and mock runs earn no coverage."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
from datetime import datetime
from pathlib import Path
import re
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO.parent
CONTRACTS = REPO / "tests/fixtures/native-operation-contracts.json"


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_digest(value) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def declarations(document=None):
    document = read(CONTRACTS) if document is None else document
    rows = document["operations"]
    require(set(document) == {"cases", "operations"}, "native inventory has redundant or unknown root fields")
    identifiers = [row["operation_id"] for row in rows]
    require(len(set(identifiers)) == len(rows), "duplicate native obligation")
    import sys
    sys.path.insert(0, str(ROOT / "inkson/tools"))
    from check_mock_operation_review import verify_contract_bindings
    review = read(ROOT / "inkson/tests/contract/mock-operation-review.json")
    try:
        verify_contract_bindings(review)
    except AssertionError as error:
        raise ValueError(str(error)) from error
    required = {row["operation_id"] for row in review["operations"]
                if row["verification_need"] in {"native_authority", "native_evidence_fixture"}}
    require(set(identifiers) == required, "native obligation inventory omits a current authority requirement")
    artifacts = ROOT / "arkret-spec/spec/v1/artifacts/registry"
    registry = {row["operation_id"]: row for row in
                read(artifacts / "contract-registry.json")["operation_registry"]["operations"]}
    errors = {row["operation_id"]: row for row in
              read(artifacts / "operations-error-mapping.json")["operations"]}
    cases = document["cases"]
    for identifier, case in cases.items():
        require(re.fullmatch(r"[a-z][a-z0-9_]*", identifier), "invalid native case name")
        require(re.fullmatch(r"[a-z][a-z0-9_]*", case["target"]), "invalid native test target")
        test = (REPO / "tests" / (case["target"] + ".rs")).read_text(encoding="utf-8")
        require("#[ignore" not in test and f"async fn {case['test']}(" in test,
                f"native case has no mandatory named test: {identifier}")
        require(f"native_operation_contracts::{identifier}().await" in test,
                f"native case does not call its domain proof: {identifier}")
        require(Path(case["artifact"]).name == case["artifact"], "native artifact escapes evidence directory")
    for row in rows:
        identifier = row["operation_id"]
        require(identifier in registry and identifier in errors, f"unregistered operation: {identifier}")
        require(set(row) == {"operation_id", "native_case"}, f"native inventory repeats canonical contract fields: {identifier}")
        require(row["native_case"] is None or row["native_case"] in cases,
                f"native obligation has no implemented case: {identifier}")
    # Runtime validation derives bindings from the one canonical registry.
    enriched = []
    for row in rows:
        operation = registry[row["operation_id"]]
        method, path = operation["http"].split(" ", 1)
        enriched.append({**row, "method": method, "path": path,
                         "request_schema_ref": operation.get("request_schema_ref"),
                         "response_schema_ref": operation.get("response_schema_ref"),
                         "success_shape_kind": operation["success_shape_kind"]})
    return {**document, "operations": enriched}


def decoded_json(value):
    require(isinstance(value, str) and "=" not in value, "invalid native base64url original")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(base64.urlsafe_b64encode(raw).decode().rstrip("=") == value,
            "noncanonical native base64url original")
    return json.loads(raw)


def verify_executed_artifact(result, path):
    require(result.get("evidence_sha256", {}).get(path.name) == hashlib.sha256(path.read_bytes()).hexdigest(),
            f"native evidence differs from the executed artifact: {path.name}")


def account_identity_creation(evidence):
    originals = evidence["authority_originals"]
    observations = evidence["observations"]
    by_id = {row["operation_id"]: row for row in observations["exchanges"]}
    handoff = by_id["ak.gate.account.exchange.create_handoff.v1"]
    challenge = by_id["ak.gate.account.command.issue_identity_binding_challenge.v1"]
    register = by_id["ak.gate.account.command.register.v1"]
    onboarding = by_id["ak.gate.account.read.onboarding.v1"]["response_body"]
    require(onboarding == evidence["onboarding"] and
            onboarding["handoff_request_id"] == handoff["request_body"]["request_id"] and
            onboarding["account_subject"] == handoff["response_body"]["account_subject"] and
            onboarding["binding"] == {"state": "bound", "principal_id": register["request_body"]["principal_id"],
                                       "did": register["request_body"]["did"]},
            "onboarding projection is not the exact accepted account binding")
    require(decoded_json(originals["handoff_original_bytes_base64url"]) ==
            originals["handoff_original"] == handoff["response_body"], "handoff original changed")
    lease = originals["identity_creation_lease"]
    require(lease["state"] == "completed" and bool(lease["registry_receipt"]) and
            bool(lease["pcr_genesis_outcome"]) and lease["register_outcome"] == register["response_body"],
            "native identity creation lacks the full accepted saga")
    require(any(row["challenge_id"] == challenge["response_body"]["challenge_id"] and
                row["consumed_at"] for row in originals["identity_binding_challenges"]),
            "native challenge was not consumed by the registration")
    proofs = observations["accepted_identity_material"]
    require(any(proof["register_response"] == register["response_body"] and
                proof["register_request"] == register["request_body"] and
                proof["native_history_base64url"] and proof["station_resolution"]
                for proof in proofs), "HTTP success has no independently verified identity original")
    sessions = originals["issued_session_originals"]
    require(len(sessions) == 1 and sessions[0]["grant_jwt"] ==
            register["response_body"]["issued_session"]["session_grant"], "issuer session original changed")
    require(bool(evidence["station_readback"]), "Station audit readback absent")
    require({row["operation_id"] for row in evidence["exact_replays"]} ==
            {handoff["operation_id"], register["operation_id"]}, "exact terminal replays absent")
    for replay in evidence["exact_replays"]:
        require(200 <= replay["status"] < 300 and
                decoded_json(replay["decoded_response_bytes_base64url"]) == by_id[replay["operation_id"]]["response_body"],
                "native replay did not return the accepted original")


def account_device_sessions(evidence):
    account_logout(evidence["logout"], evidence)
    originals = evidence["authority_originals"]
    require(originals["total_grants"] == 3 and originals["issued"]["grant"]["lifecycle_state"] == "superseded" and
            originals["refreshed"]["grant"]["lifecycle_state"] == "active", "native grant lineage or replay count changed")
    for phase, operation in (("issued", "ak.gate.account.command.issue_session_grant.v1"),
                             ("refreshed", "ak.gate.account.command.refresh_session_grant.v1")):
        original = originals[phase]
        responses = [row for row in evidence["observations"]["exchanges"] if row["operation_id"] == operation]
        require(len(responses) == 2 and len({row["request_json_base64url"] for row in responses}) == 1,
                "native session operation did not replay the frozen request")
        body = decoded_json(original["canonical_outcome_base64url"])
        require(body == original["canonical_outcome"] and all(row["response_body"] == body for row in responses) and
                original["operation"]["state"] == "committed" and original["grant"]["grant_jwt"] == body["session_grant"],
                "native response lost its immutable issuer original")
        verified = evidence[phase + "_verification"]
        require(verified["signing_key_id"] == original["grant"]["signing_key_id"] == original["operation"]["signing_key_id"],
                "verified JWT did not use the issuer ledger's exact signing key")
        token = body["session_grant"].split(".")
        require(len(token) == 3 and decoded_json(token[1]) == verified["claims"], "verified JWT claims changed")
        claims = verified["claims"]
        preimage = {key: value for key, value in claims.items() if key not in {"kind", "jti"}}
        preimage["schema"] = "ak.session_grant.issuance.v1"
        require(decoded_json(original["issuance_preimage_base64url"]) == original["issuance_preimage"] == preimage,
                "session grant was not derived from the stored issuance preimage")
        require(claims["account_id"] == evidence["station_readback"]["account_id"] and
                claims["device_binding"]["authorization_event_id"] == evidence["station_readback"]["founding_device_authorize_event"]["event_id"] and
                verified["station_viewer"]["principal_id"] == claims["account_id"]["principal_id"] and bool(verified["issuer_jwks"]),
                "native session has no exact accepted Device and Station consumer closure")
    require(originals["refreshed"]["canonical_outcome"]["previous_session_grant_id"] ==
            originals["issued"]["canonical_outcome"]["session_grant_id"], "refresh changed its exact predecessor")
    require(bool(evidence["observations"]["accepted_identity_material"]), "native Device prerequisite absent")


def account_device_pairing(evidence):
    originals = evidence["authority_originals"]
    before = evidence["before_claim"]
    require(before["record"]["state"] == "ready_for_claim" and before["record"]["code_consumed_at"] is None and
            originals["record"]["state"] == "authorized" and originals["record"]["admission_state"] == "completed",
            "pairing lacked a genuine claimable target and subsequent PCR admission")
    for phase in ("stage", "finalize", "authorization_submission", "commit", "admission"):
        require(decoded_json(originals[phase]["bytes_base64url"]) == originals[phase]["value"], "pairing original changed")
    response = originals["finalize"]["value"]
    rows = [row for row in evidence["observations"]["exchanges"]
            if row["operation_id"] == "ak.gate.account.command.finalize_device_pairing.v1"]
    require(len(rows) == 2 and len({row["request_json_base64url"] for row in rows}) == 1 and
            all(row["response_body"] == response for row in rows), "pairing finalize did not replay its exact original")
    claims = [row for row in evidence["observations"]["exchanges"]
              if row["operation_id"] == "ak.gate.account.read.claim_device_pairing_code.v1"]
    require(len(claims) == 1 and claims[0]["response_body"] == evidence["claimed"] and
            evidence["claimed"]["target_proof"] == originals["record"]["target_proof"], "code claim changed its actual target proof")
    require(originals["authorization_submission"]["value"] == evidence["approval_request"]["authorize_event"] and
            originals["authorization_submission"]["value"]["event"] == evidence["station_readback"]["event"] and
            originals["commit"]["value"] == evidence["station_readback"]["commit"] and
            originals["record"]["authorized_event_ref"] == originals["admission"]["value"]["authorized_event_ref"],
            "pairing authority and Station disagree on the accepted original")
    require(bool(evidence["observations"]["accepted_identity_material"]), "pairing controller has no admitted PCR prerequisite")


def account_policy_recovery(evidence):
    originals = evidence["authority_originals"]
    exchanges = evidence["observations"]["exchanges"]
    by_id = {row["operation_id"]: row for row in exchanges}
    create = by_id["ak.self.security_transaction.command.create.v1"]
    continued = by_id["ak.self.security_transaction.command.continue.v1"]
    transaction = evidence["transaction"]
    require(decoded_json(originals["transaction_request_bytes"]) == originals["transaction_request"] == create["request_body"],
            "recovery transaction lost its exact creation request")
    require(originals["transaction"]["prepared_plan"] == transaction["prepared_plan"] == create["response_body"]["prepared_plan"] and
            originals["transaction"]["terminal_outcome"] == transaction["terminal_outcome"] == continued["response_body"]["terminal_outcome"],
            "native recovery transaction differs from its durable plan or terminal outcome")
    request = evidence["completion_request"]
    completion = request["completion_attestation"]
    require(decoded_json(originals["issuance_request_bytes"]) == originals["issuance_request"] == request and
            decoded_json(originals["issuance_outcome_bytes"]) == originals["issuance_outcome"] == evidence["issued"],
            "recovery issuance request or response differs from the issuer original")
    sessions = originals["sessions"]
    require(len(sessions) == 1 and sessions[0]["state"] == "completed" and sessions[0]["proof_payload"] is not None,
            "recovery lacks a durably accepted proof and completed session")
    require(bool(originals["steps"]) and originals["grant"]["grant_jwt"] == evidence["issued"]["issued_session"]["session_grant"],
            "recovery lacks accepted transaction steps or the issued credential original")
    require(decoded_json(originals["issuance_preimage_bytes"]) == originals["issuance_preimage"],
            "recovery issuance preimage was replaced")
    for member, ref_member in (("reanchor", "reanchor_event_ref"), ("authorize", "device_authorization_event_ref")):
        view, reference = evidence[member], completion[ref_member]
        require(view["event"]["event_id"] == reference["event_id"] and
                view["commit"]["commit_id"] == reference["commit_id"] and
                view["commit"]["realm_id"] == evidence["policy"]["commit"]["realm_id"],
                "recovery completion does not close over the accepted PCR originals")
    require(bool(evidence["observations"]["accepted_identity_material"]), "recovery has no admitted identity prerequisite")


def matches_registered_path(template, path):
    parts = re.split(r"(\{[a-zA-Z_][a-zA-Z0-9_]*\})", template)
    pattern = "".join(r"[^/]+" if part.startswith("{") and part.endswith("}") else re.escape(part) for part in parts)
    return re.fullmatch(pattern, path) is not None


def account_private_storage(evidence):
    actor_private(evidence["private_route"])
    envelope = evidence["envelope"]
    require(evidence["before"]["backup"]["payload"] == envelope == evidence["unlocked"] and
            envelope["encryption"]["recipient_method"] == "passphrase_kdf" and
            bool(envelope["encryption"]["kdf"]) and bool(envelope["ciphertext"]),
            "backup contract lacks the accepted actual encrypted original")
    require(evidence["before"]["delete_backup"]["payload"] == evidence["deletion_envelope"] and
            evidence["deletion_envelope"]["backup_id"] != envelope["backup_id"] and
            evidence["accepted_pointer"]["event"]["payload"]["active_series_id"] == envelope["series_id"],
            "unlock lacks an accepted active pointer or deletion targets the active envelope")
    require(bool(evidence["before"]["unlock_authorities"]) and bool(evidence["before"]["unlock_entries"]),
            "unlock lacks native challenge and consumption originals")
    require(evidence["recovery_session"]["state"] == "verified" and
            evidence["delete_request"]["proof"]["kind"] == "recovery_unlock" and
            evidence["delete_request"]["proof"]["recovery_session_id"] == evidence["recovery_session"]["recovery_session_id"],
            "delete lacks a real separately verified recovery factor")
    rollback = evidence["rollback_probe"]
    require(rollback["status"] == 500 and rollback["before"] == rollback["after"] and
            rollback["before"]["backups"] == [evidence["deletion_envelope"]] and
            rollback["before"]["challenge"]["consumed_at"] is None and rollback["before"]["receipts"] == [],
            "failed receipt persistence did not atomically roll back the real delete")
    require(evidence["sdk_delete_replay_verified"] is True, "SDK did not consume the actual empty native delete replay")
    receipts = evidence["accepted_delete"]["receipts"]
    require(len(receipts) == 1 and receipts[0]["response_body"] is None and receipts[0]["response_status"] == evidence["deleted"] == evidence["delete_replay"] == 200 and
            evidence["accepted_delete"]["backups"] == [] and
            evidence["accepted_delete"]["challenge"]["consumed_at"] is not None,
            "accepted delete has no atomic terminal original and exact replay")
    trusted=evidence["trusted_request"]["proof"]
    services=[entry for method in evidence["recovery_policy"]["event"]["payload"]["value"]["methods"]
              if method["kind"]=="trusted_recovery_service" for entry in method["services"]]
    require(trusted["kind"]=="trusted_recovery_service" and trusted["recovery_session_id"]==evidence["recovery_session"]["recovery_session_id"] and
            sum(entry["service_id"]==trusted["service_id"] and entry["authorization_verification_method"]==trusted["proof"]["verification_method"] for entry in services)==1 and
            evidence["recovery_session"]["proof_summary"]["kind"]=="recovery_unlock",
            "trusted delete lacks an explicit accepted delegation and independent recovery factor")
    trusted_receipts=evidence["trusted_original"]["receipts"]
    require(len(trusted_receipts)==1 and trusted_receipts[0]["response_body"] is None and trusted_receipts[0]["response_status"]==evidence["trusted_deleted"]==200 and
            evidence["trusted_original"]["backups"]==[], "trusted delete lacks its durable accepted original")
    require(evidence["after"]["backup_count"] == 0 and evidence["deleted"] == 200 and
            evidence["after"]["delete_challenge"]["challenge"] == evidence["delete_challenge"] and
            evidence["after"]["delete_challenge"]["consumed_at"] is not None,
            "backup deletion lacks its accepted challenge or durable effect")
    revocations = evidence["after"]["cursor_revocations"]
    # This is an issuing-service ledger audit, never a client request dependency.
    cursor = decoded_json(evidence["cursor"].removeprefix("ak:cursor:"))
    require(len(revocations) == 1 and revocations[0]["scope"] == "this_cursor" and
            revocations[0]["cursor_digest"] == hashlib.sha256(cursor["h"].encode()).hexdigest(),
            "cursor revocation is not bound to the actual issued token")
    required = set(evidence["scope"])
    exchanges = [row for row in evidence["observations"]["exchanges"] if row["operation_id"] in required]
    by_id = {row["operation_id"]: row for row in exchanges}
    deletions=[row for row in exchanges if row["operation_id"]=="ak.self.keys.backups.resource.delete.v1"]
    require(any(row["request_body"]==evidence["delete_request"] and row["response_body"] is None and row["response_status"]==evidence["deleted"] for row in deletions) and
            any(row["request_body"]==evidence["trusted_request"] and row["response_body"] is None and row["response_status"]==evidence["trusted_deleted"] for row in deletions),
            "delete authority branch evidence differs from its actual requests")
    require(by_id["ak.self.keys.backups.command.unlock.v1"]["response_body"] == envelope and
            by_id["ak.self.account.command.revoke_cursor.v1"]["request_body"] == evidence["revoke_request"] and
            by_id["ak.self.account.command.revoke_cursor.v1"]["response_body"] == evidence["revoked"],
            "private storage evidence changed the actual requests or responses")
    require(bool(evidence["observations"]["accepted_identity_material"]), "private storage has no admitted identity prerequisite")


def mls_interop(evidence):
    binding = evidence["mimi_control"]["binding_commit"]
    expected = {"selector": {"kind": "mimi_room_binding", "mimi_room_uri": binding["event"]["payload"]["mimi_room_uri"]},
                "source_stream_ref": binding["commit"]["stream_ref"],
                "revision": {"commit_id": binding["commit"]["commit_id"], "stream_position": binding["commit"]["stream_position"]},
                "value": binding["event"]["payload"]}
    require(expected in evidence["peer_reads"]["bootstrap"]["snapshot"]["current_state_entries"],
            "bootstrap omitted or changed the actual accepted MIMI binding Current")
    mimi_message(evidence["mimi_message"])
    mimi_notify(evidence["mimi_notify"], evidence["mimi_message"], binding, evidence["observations"])
    watch_audit(evidence["watch_audit"])
    media_token(evidence["media_token"])
    peer_invite(evidence["peer_invite"])
    originals = evidence["authority_originals"]
    require(originals["claim"]["state"] == "consumed" and originals["claim"]["outcome"] == evidence["claim"] and
            originals["claim"]["consume_receipt"] is not None and originals["revoked_package"]["claimed_by_mls_group_id"] == "revoked" and
            originals["revoked_package"]["claim_expires_at_unix_ms"] is None,
            "MLS lifecycle lacks its exact consumed claim original or revoke effect")
    binding = originals["welcome_binding"]
    welcome = evidence["welcome"]
    require(binding["welcome_id"] == welcome["welcome_id"] and
            binding["commit_event_ref"] == evidence["committed"]["event"]["event_id"] == welcome["commit_event_ref"] and
            evidence["committed"]["event"] == evidence["submission"]["commit_event"] and
            evidence["submission"]["welcomes"] == [welcome], "claim Welcome is not the actual admitted Add original")
    require(evidence["query"] == evidence["claim"] and evidence["restored_epoch"] == 1 and
            re.fullmatch(r"sha256:[a-f0-9]{64}", evidence["durable_snapshot_digest"]) is not None,
            "MLS recipient lacks its original claim or restored durable group")
    require(len(evidence["observations"]["accepted_identity_material"]) == 2,
            "MLS lifecycle requires two genuinely admitted and issued member identities")
    by_id = {row["operation_id"]: row for row in evidence["observations"]["exchanges"]}
    for operation, member in (("ak.self.keys.keypackages.command.claim.v1", "claim_request"),
                              ("ak.self.keys.keypackages.command.consume.v1", "consume_request"),
                              ("ak.self.keys.keypackages.command.revoke.v1", "revoke_request")):
        require(by_id[operation]["request_body"] == evidence[member], "MLS operation changed its actual valid request")

    peer_membership_reads(evidence["peer_reads"], evidence["realm_genesis"], evidence["observations"])
    peer_signal(evidence["signal"], evidence["observations"])
    mimi_control(evidence["mimi_control"])
    mimi_claim(evidence["mimi_control"]["claim_material"])
    require(evidence["mimi_control"]["claim_material"]["room"]==evidence["mimi_control"]["binding_commit"]["event"]["payload"]["mimi_room_uri"],"MIMI claim substituted its accepted room")


def native_snapshot_receive_cut(evidence):
    response = evidence["bootstrap"]
    assertion = response["authority_bundle"]["current_assertion"]
    instant = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00"))
    received = instant(evidence["bootstrap_received_at"])
    require(instant(assertion["signature"]["created_at"]) <= received < instant(assertion["expires_at"]) and
            instant(response["snapshot"]["created_at"]) <= received,
            "native snapshot freshness does not use its actual receive cut")


def native_genesis_realm(original):
    event, commit = original["event"], original["commit"]
    realm = "ak:realm:" + event["event_id"].removeprefix("ak:event:")
    require(event["event_id"].startswith("ak:event:") and event["scope_ref"] == {"kind": "realm_genesis"} and
            commit["realm_id"] == realm, "native genesis does not derive its exact accepted Realm")
    return realm


def peer_membership_reads(evidence, genesis, observations):
    native_snapshot_receive_cut(evidence)
    request=evidence["bootstrap_request"]
    response=evidence["bootstrap"]
    bundle=response["authority_bundle"]
    snapshot=response["snapshot"]
    require(response["request_id"]==request["request_id"] and request["realm_id"]==native_genesis_realm(genesis) and
            request["membership_commit_id"]==evidence["membership"]["commit"]["commit_id"] and
            bundle["genesis_event"]==genesis["event"] and bundle["genesis_commit"]==genesis["commit"] and
            int(bundle["current_generation"])==0 and bundle["authority_transitions"]==[] and
            bool(snapshot["current_state_entries"]) and bool(snapshot["visible_stream_heads"]) and
            snapshot["realm_id"]==request["realm_id"], "peer bootstrap lacks its actual genesis, member and complete authority snapshot")
    nonce=base64.urlsafe_b64encode(hashlib.sha256(request["request_id"].encode()).digest()).decode().rstrip("=")
    require(bundle["current_assertion"]["nonce"]==nonce, "peer bootstrap replaced its request-bound authority nonce")
    preview=evidence["preview"]
    require(preview["request_id"]==evidence["preview_request"]["request_id"] and preview["preview"]["realm_id"]==request["realm_id"] and
            evidence["preview_policy"]["event"]["kind"]=="ak.realm.preview_policy" and
            "realm_member" in evidence["preview_policy"]["event"]["payload"]["value"]["audiences"], "peer preview lacks its actual accepted disclosure policy")
    keys=evidence["keys"]
    selected=evidence["keys_request"]
    require(keys["request_id"]==selected["request_id"] and len(keys["device_keys"])==1 and len(keys["device_generations"])==1,
            "peer keys lookup did not disclose the actual selected accepted device")
    entry=keys["device_keys"][0]
    device=evidence["member_device_id"]
    require(entry["account_id"]==evidence["member_account_id"] and set(entry["device_keys"])=={device}, "peer device selectors drifted")
    core=entry["device_keys"][device]["device_projection_attestation"]["attestation"]
    require(core["account_id"]==entry["account_id"] and core["device_id"]==device and
            core["device_signing_key_did"]=="did:key:"+evidence["expected_device_key"] and
            core["device_authorize_event_id"]==evidence["member_authorize_event_id"] and
            core["device_status"]=="active" and int(core["authorized_generation_ref"])==int(keys["device_generations"][0]["generation_state"]["current_device_generation_ref"]),
            "peer device attestation substituted the original accepted key or generation")
    by_id={row["operation_id"]:row for row in observations["exchanges"]}
    for operation, request_member, response_member in [
        ("ak.peer.realm_join.read.bootstrap.v1","bootstrap_request","bootstrap"),
        ("ak.peer.realm_join.read.preview.v1","preview_request","preview"),
        ("ak.peer.keys.read.lookup.v1","keys_request","keys")]:
        require(by_id[operation]["request_body"]==evidence[request_member] and by_id[operation]["response_body"]==evidence[response_member],
                "peer read proof differs from actual native HTTP bytes")


def peer_signal(evidence, observations):
    require(evidence["status"]==204 and evidence["response_base64url"]=="" and evidence["before"]==evidence["after"],
            "peer Signal did not preserve empty 204 and zero canonical history effects")
    request=evidence["request"]
    require(len(request["signals"])==1 and evidence["received"]==request["signals"][0] and bool(evidence["plaintext_base64url"]),
            "peer Signal has no actual recipient frame and authenticated plaintext")
    sender=evidence["sender_authorize"]["event"]
    authority=evidence["delivery_authority"]
    require(sender["kind"]=="ak.device.authorize" and sender["event_id"]==authority["key"]["authorization_ref"] and
            sender["actor_id"]==request["signals"][0]["sender_actor_id"]==authority["key"]["actor"],
            "peer Signal lost its actual accepted producer authorization")
    matches=[row for row in observations["exchanges"] if row["operation_id"]=="ak.peer.signal.command.relay.v1"]
    require(len(matches)==1 and matches[0]["request_body"]==request and matches[0]["response_status"]==204 and
            matches[0]["decoded_response_bytes_base64url"]=="" and matches[0]["response_body"] is None and
            "idempotency-key" not in matches[0]["explicit_request_headers"],
            "peer Signal proof is not the actual empty single-attempt HTTP exchange")


def account_consent(evidence):
    peer = evidence["peer"]["actor_id"]
    pending = evidence["pending"]
    require(pending == evidence["pending_replay"] and len(pending["quarantine"]) == 1,
            "Consent constant response lacks a stable admitted quarantine original")
    entries = pending["quarantine"][0]["payload"]["quarantine_entries"]
    require(sum(row["source_peer_actor_id"] == peer and row["surface_kind"] == "consent_request" and
                row["consent_scope"] == evidence["request"]["consent_scope"] for row in entries) == 1,
            "Consent quarantine did not admit the actual requester and scope")
    cuts = [row["response"]["current"] for row in evidence["currents"]]
    require(cuts[0]["state"] == "never_written" and cuts[1]["state"] == cuts[2]["state"] == "present" and
            cuts[1]["current_state"]["value"]["permissions"] == evidence["grant"]["payload"]["permissions"] and
            bool(cuts[1]["current_state"]["value"]["permissions"]) and
            cuts[2]["current_state"]["value"]["permissions"] == [],
            "Consent current does not preserve the accepted grant and empty revocation")
    require(len(evidence["after"]["current"]) == 1 and len(evidence["after"]["versions"]) == 2 and
            evidence["grant_commit"]["event"] == evidence["grant"] and
            evidence["revoke_commit"]["event"] == evidence["revoke"] and
            len(evidence["observations"]["accepted_identity_material"]) == 2,
            "Consent lacks both independently admitted identities and immutable accepted versions")
    exchanges = evidence["observations"]["exchanges"]
    for cut in evidence["currents"]:
        require(any(row["operation_id"] == "ak.self.consent.read.current.v1" and
                    row["request_body"] == cut["request"] and row["response_body"] == cut["response"]
                    for row in exchanges), "Consent current changed its actual request or signed response")
    for event, view in ((evidence["grant"], evidence["granted"]), (evidence["revoke"], evidence["revoked"])):
        require(any(row["operation_id"] == "ak.self.consent.command.replace.v1" and
                    row["request_body"]["consent_event"]["event"] == event and row["response_body"] == view
                    for row in exchanges), "Consent replacement lacks its exact submitted and accepted original")


def identity_reservations(evidence):
    request=evidence["abandon_request"]
    before=evidence["before"]
    after=evidence["after_abandonment"]
    identifier=request["request_id"].removeprefix("ak:request:")
    terminal=[r for r in after["identity_abandonments"] if r["request_id"]==identifier]
    require(len(terminal)==1 and terminal[0]["outcome"]==evidence["abandoned"]==evidence["abandon_replay"] and
            terminal[0]["request_digest"]=="sha256:"+canonical_digest(request),"abandonment lacks its exact durable terminal original")
    lease=request["identity_creation_lease_id"]
    frozen=[r for r in before["identity_creation_leases"] if r["lease_id"]==lease]
    require(len(frozen)==1 and not any(r["lease_id"]==lease for r in after["identity_creation_leases"]) and
            evidence["pcr_count_before"]==evidence["pcr_count_after"]==0,
            "abandonment did not release its genuine never-accepted reservation")
    tombstones=[r for r in after["identity_orphan_anchor_tombstones"] if r["principal_id"]==request["principal_id"] and r["did_version_id"]==request["did_version_id"]]
    require(len(tombstones)==1 and tombstones[0]["abandonment_request_id"]==identifier,"abandonment has no exact orphan-anchor tombstone")
    initial=[r for r in before["identity_binding_challenges"] if r["lease_id"]==lease]
    require(bool(initial),"reservation has no actual issuer-frozen challenge")
    instant=lambda value:datetime.fromisoformat(value.replace("Z","+00:00"))
    first=min(instant(r["issued_at"]) for r in initial)
    owner=terminal[0]["local_account_id"]
    fresh=evidence["fresh_authentication"]
    grants=[r for r in fresh["account_handoff_grants"] if r["local_account_id"]==owner and r["cnf_jkt"]==terminal[0]["holder_jkt"] and instant(r["issued_at"])>first]
    require(any(any(a["user_session_id"]==g["browser_session_id"] and first<instant(a["created_at"])<=instant(g["issued_at"]) for a in fresh["user_session_authentications"]) and
                any(s["id"]==g["browser_session_id"] and s["user_id"]==owner for s in fresh["user_sessions"]) for g in grants),
            "abandonment used token renewal instead of actual fresh issuer authentication")
    native=evidence["native_request"]
    require(evidence["history"]["did"]==native["did"] and evidence["history"]["entries"]==[native["operation"]] and
            evidence["published"]["accepted_at"]==evidence["root_replay"]["accepted_at"] and
            evidence["published"]["operation_ref"]==evidence["root_replay"]["operation_ref"],
            "native method publication lacks its exact accepted history and retry")
    bind=evidence["binding_request"];challenge=evidence["binding"]
    records=[r for r in evidence["published_originals"]["did_binding_challenges"] if r["request_id"]==bind["request_id"].removeprefix("ak:request:")]
    require(len(records)==1 and evidence["binding_replay"]==challenge and records[0]["request_digest"]=="sha256:"+canonical_digest(bind) and
            records[0]["did"]==native["did"]==challenge["did"] and
            records[0]["did_version_id"]==native["operation"]["versionId"]==challenge["did_version_id"] and
            records[0]["log_head_digest"]=="sha256:"+canonical_digest(native["operation"]) and
            records[0]["control_key_digest"]==challenge["control_key_digest"] and
            records[0]["dpop_jkt"]==challenge["dpop_jkt"],"published DID challenge lacks the actual native method and holder pins")


def service_registrations(evidence):
    original=evidence["before"]["registration"]["outcome"]
    read_original={**original,"created":False}
    require(read_original==evidence["get"]==evidence["ensured"]==evidence["replay"]==evidence["after_get"] and original==evidence["after"]["registration"]["outcome"],
            "service registration did not replay the actual native bootstrap outcome")
    request=evidence["ensure_request"]
    require(request["inception_operation"]==evidence["before"]["inception_operation"]==evidence["after"]["inception_operation"] and
            request["previous_receipt"]==original["registration_receipt"] and
            request["did"]==original["did_document"]["id"] and
            evidence["before"]["entry_count"]==evidence["after"]["entry_count"]>=1,
            "service ensure lacks the original accepted inception or created another method entry")
    receipt=original["registration_receipt"]
    require(receipt["registration_key"]==evidence["key"] and
            receipt["version_id"]==request["inception_operation"]["versionId"] and
            receipt["log_head_digest"]=="sha256:"+canonical_digest(request["inception_operation"]),
            "service registration receipt changed its actual registration key or method original")


def organization_registrations(evidence):
    organization=evidence["organization_id"]
    request=evidence["ensure_request"]
    first=evidence["issued"]["registration_receipt"]
    refreshed=evidence["refreshed"]["registration_receipt"]
    revoked=evidence["revoked"]["registration_receipt"]
    require(evidence["issued"]["created"] is True and evidence["ensure_replay"]==evidence["first_get"]=={**evidence["issued"],"created":False},
            "organization ensure/read lacks the original receipt and exact retry")
    require(evidence["refresh_replay"]==evidence["refreshed"] and evidence["revoke_replay"]==evidence["final_get"]==evidence["revoked"] and
            evidence["refreshed"]["created"] is False and evidence["revoked"]["created"] is False,
            "organization refresh/revoke changed the accepted original")
    require(first["status"]==refreshed["status"]=="active" and revoked["status"]=="revoked" and
            first["registration_generation"]==refreshed["registration_generation"]==revoked["registration_generation"]==1 and
            first["local_admin_subject_id"]==refreshed["local_admin_subject_id"]==revoked["local_admin_subject_id"]==evidence["administrator"],
            "organization lifecycle changed the actual beneficiary or generation")
    before=evidence["external_before"];after=evidence["external_after"]
    require(len(before)==1 and len(after)==2 and before[0]==after[0] and evidence["public_history"]["entries"]==after and evidence["registry_native_history"]==[],
            "local registry hosted, rewrote or fabricated external native history")
    require(first["version_id"]==before[0]["versionId"] and refreshed["version_id"]==revoked["version_id"]==after[1]["versionId"] and
            first["log_head_digest"]=="sha256:"+canonical_digest(before[0]) and
            refreshed["log_head_digest"]==revoked["log_head_digest"]=="sha256:"+canonical_digest(after[1]),
            "organization receipt is not pinned to the actual accepted native head")
    require(evidence["accepted_inception"]["status"] in {"accepted","duplicate"} and evidence["accepted_inception"]["sequence"]==1 and
            evidence["accepted_rotation"]["status"] in {"accepted","duplicate"} and evidence["accepted_rotation"]["sequence"]==2,
            "external organization operations were not natively accepted")
    exchanges=evidence["observations"]["exchanges"]
    for name,challenge_name,snapshot_name,outcome in (("ensure_request","challenge","after_ensure",first),
                                                    ("refresh_request","refresh_challenge","after_refresh",refreshed)):
        request=evidence[name];challenge=evidence[challenge_name];snapshot=evidence[snapshot_name]
        require(request["organization_id"]==challenge["organization_id"]==outcome["organization_id"]==organization and
                request["organization_did"]==challenge["organization_did"]==outcome["organization_did"] and
                request["challenge_id"]==challenge["challenge_id"] and
                challenge["local_admin_subject_id"]==evidence["administrator"] and
                challenge["requested_scopes"]==evidence["challenge_request"]["requested_scopes"]==outcome["delegated_scopes"],
                "organization challenge did not bind the exact beneficiary/scopes")
        require(any(row["request_body"]==request for row in exchanges),"organization artifact differs from the actual request")
        rows=[row for row in snapshot["organization_registration_challenges"] if row["challenge_id"]==challenge["challenge_id"]]
        require(len(rows)==1 and rows[0]["record"]["challenge"]==challenge and rows[0]["consumed_at"] and
                rows[0]["consumed_request_digest"]=="sha256:"+canonical_digest(request) and
                rows[0]["consumed_outcome_id"]==outcome["registration_receipt_id"],
                "organization challenge lacks its exact atomic consumption ledger")
    snapshot=evidence["after_revoke"]
    outcomes=snapshot["organization_registration_outcomes"]
    require(len(outcomes)==3 and {row["outcome_id"] for row in outcomes}=={r["registration_receipt_id"] for r in (first,refreshed,revoked)},
            "organization lifecycle lacks its three immutable native outcomes")
    for receipt in (first,refreshed,revoked):
        require(any(row["outcome"]["registration_receipt"]==receipt for row in outcomes),"organization receipt differs from its native original")
    states=snapshot["organization_registration_states"]
    require(len(states)==1 and states[0]["current_generation"]==1 and states[0]["current_outcome_id"]==revoked["registration_receipt_id"] and
            states[0]["state"]["generations"]["1"]["status"]=="revoked" and
            states[0]["state"]["generations"]["1"]["terminal_reason"]=="organization_registration_withdrawn",
            "organization revoke lacks its durable terminal current pointer")


def mimi_control(evidence):
    request=evidence["binding_request"]
    event=request["room_binding_event"]["event"]
    binding=evidence["binding_commit"]
    require(binding["event"]==event and evidence["bound"]["room_state_ref"]==event["event_id"] and
            binding["commit"]["event_ref"]==event["event_id"],"MIMI binding did not retain the exact caller Event and covering commit")
    require(evidence["receipt"]["accepted"] is True and "room_state_ref" not in evidence["receipt"] and
            evidence["before_receipt"]==evidence["after_receipt"],"receipt-only update claimed an Event or changed durable native state")
    identifiers=evidence["identifiers"]
    require(identifiers["has_more"] is False and identifiers.get("proofs",[])==[] and
            len(identifiers["matches"])==len(evidence["identifier_request"]["identifiers"]),"MIMI no-discovery response omitted commitments or disclosed proof")
    for requested,matched in zip(evidence["identifier_request"]["identifiers"],identifiers["matches"]):
        require(requested["identifier_commitment"]==matched["identifier_commitment"] and matched["matched"] is False and
                "subject_id" not in matched and "mimi_uri" not in matched,"MIMI manufactured a discovery match or identity handoff")
    request=evidence["consent_request"]
    consent=evidence["correlation"]["consent_id"]
    rows=evidence["after_request"]["mimi_consent_correlations"]
    require(len(rows)==1 and rows[0]["consent_id"]==consent and
            json.loads(rows[0]["requester_actor_id"])==request["requester_actor_id"] and
            json.loads(rows[0]["holder_account_id"])==request["holder_account_id"] and
            rows[0]["purpose"]==request["purpose"] and rows[0]["strand_id"]==request["strand_id"] and
            rows[0]["source_class"]=="service" and rows[0]["source_id"]==evidence["directory"]["service_id"],
            "MIMI consent correlation lacks its exact native requester/holder/source original")
    request=evidence["consent_update"]
    event=request["consent_event"]["event"]
    accepted=evidence["consent_accepted"]
    require(accepted==evidence["consent_replay"] and accepted["consent_id"]==consent==request["consent_id"] and
            accepted["event_ref"]==event["event_id"] and evidence["consent_commit"]["event"]==event and
            event["payload"]["peer"]=={"kind":"actor","actor_id":evidence["consent_request"]["requester_actor_id"]} and
            event["actor_id"]["account_id"]==evidence["consent_request"]["holder_account_id"],
            "MIMI consent did not admit the exact holder-signed, beneficiary-bound replacement")
    attempts=evidence["after_update"]["mimi_consent_decision_attempts"]
    require(len(attempts)==1 and attempts[0]["consent_id"]==consent and attempts[0]["event_id"]==event["event_id"] and
            attempts[0]["submission"]==request["consent_event"],"MIMI lacks its durable exact decision/Event attempt")
    report=evidence["report_commit"]
    require(evidence["reported"]==evidence["report_replay"] and report["event"]["actor_id"]=={"kind":"service","service_id":evidence["directory"]["service_id"]} and
            report["commit"]["event_ref"]==report["event"]["event_id"] and report["event"]["kind"]=="ak.self.moderation.report" and
            len([row for row in evidence["after_report"]["committed"] if row["event"]["kind"]=="ak.self.moderation.report"])==1,
            "MIMI report lacks its real unique Service-authored accepted native result")


def blob_presign(evidence):
    content=evidence["content_base64url"]
    require(content==evidence["fetched_base64url"]==evidence["repeated_base64url"],"native bearer URL did not return the original stored bytes twice")
    blob=evidence["originals"]["blob"]
    upload=evidence["upload"]
    payload=evidence["envelope"]["payload"]
    require(blob["id"]==upload["blob_ref"]==payload["blob_ref"]==evidence["request"]["blob_ref"] and
            blob["realm_id"]==payload["realm_id"]==evidence["realm_id"]==evidence["request"]["realm_id"] and
            blob["payload"]["encryption"] is None and blob["size_bytes"]==upload["size_bytes"]==evidence["head_length"],
            "native presign lacks its exact classified blob and scope original")
    require(payload["access_scope"]=={"method":["GET","HEAD"]} and payload["purpose"]==evidence["request"]["purpose"]=="download" and
            payload["expires_at"]==evidence["issued"]["expires_at"] and evidence["denied_status"]==404,
            "native presign widened access or survived accepted policy tightening")
    require(evidence["allowed"]["event"]["payload"]["value"]["direct_download_allowed"] is True and
            evidence["tightened"]["event"]["payload"]["value"]["direct_download_allowed"] is False and
            int(evidence["allowed"]["commit"]["stream_position"])<int(evidence["tightened"]["commit"]["stream_position"]),
            "presign policy changes lack their actual accepted native commits")


def native_issuer_pin(captured):
    resolution = captured["resolution"]
    originals = captured["originals"]
    pins = originals["enrollments"]
    require(len(pins) == 1, "native issuer pin must be an actual unique enrollment")
    pin = pins[0]
    document = resolution["normalized_did_document"]
    history = resolution["method_history_evidence"]
    boundary = history["boundary"]
    endpoints = [entry["endpoint"] for entry in document["services"]
                 if entry["protocol_names"] == ["ArkretService"] and
                 {"name": "serviceKind", "value": "station"} in entry["extensions"]]
    require(pin["name"] == originals["configured_name"] and
            pin["canonical_endpoint"] == originals["configured_endpoint"] and
            endpoints == [pin["canonical_endpoint"]] and
            pin["service_id"] == resolution["service_id"] and
            pin["service_kind"] == resolution["service_kind"] == "station" and
            pin["did"] == document["did"] and
            pin["method_history_head"] == boundary["to_method_history_head"] and
            pin["version_id"] == boundary["to_version_id"] and
            pin["source"] == "automatic_verified" and
            history["evidence_kind"] == "webvh_log" and bool(history["log_entries"]),
            "native issuer original pin does not bind the complete actual Station proof")
    instant = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(instant(pin["enrolled_at"]) <= instant(pin["last_verified_at"]),
            "native issuer pin predates its original enrollment")
    audits = originals["audits"]
    require(any(row["action"] == "enrolled" and row["enrollment_name"] == pin["name"] and
                row["service_id"] == pin["service_id"] for row in audits) and
            all(row["action"] not in {"replaced", "revoked"} for row in audits),
            "native issuer lacks its original enrollment audit or accepted a revoked/replaced pin")
    return pin


def native_issuer_continuity(evidence):
    pins = {phase: native_issuer_pin(evidence[phase]) for phase in ("before", "after", "restarted")}
    before, after, restarted = (pins[phase] for phase in ("before", "after", "restarted"))
    require(before["service_id"] == after["service_id"] == restarted["service_id"] and
            before["name"] == after["name"] == restarted["name"] and
            before["enrolled_at"] == after["enrolled_at"] == restarted["enrolled_at"] and
            before["canonical_endpoint"] != after["canonical_endpoint"] == restarted["canonical_endpoint"] and
            before["method_history_head"] != after["method_history_head"] == restarted["method_history_head"] and
            before["version_id"] != after["version_id"] == restarted["version_id"] and
            evidence["preflight"]["status"] == "preflight" and evidence["applied"]["status"] == "migrated",
            "native issuer continuity changed its original identity or did not advance/retain its floor")
    old_history = evidence["before"]["resolution"]["method_history_evidence"]["log_entries"]
    new_history = evidence["after"]["resolution"]["method_history_evidence"]["log_entries"]
    require(len(new_history) > len(old_history) and new_history[:len(old_history)] == old_history and
            new_history == evidence["restarted"]["resolution"]["method_history_evidence"]["log_entries"],
            "native issuer continuity omitted original method entries or changed them on restart")
    audits = evidence["after"]["originals"]["audits"]
    require(any(row["action"] == "endpoint_relocated" and row["service_id"] == after["service_id"] for row in audits) and
            audits == evidence["restarted"]["originals"]["audits"],
            "native issuer relocation lacks its original audit or repeated it on restart")


def native_issuer_bindings(observations, origins):
    bindings = observations.get("issuer_bindings", [])
    admitted = {material["station_resolution"]["service_id"]: material["station_resolution"]
                for material in observations["accepted_identity_material"]}
    require(bool(admitted) and len(bindings) == len(admitted),
            "native authority lacks original AA bindings for every admitted Station")
    pins = [native_issuer_pin(binding) for binding in bindings]
    require({pin["service_id"] for pin in pins} == set(admitted),
            "native AA bindings are duplicated or name different Stations")
    for binding, pin in zip(bindings, pins):
        resolution = admitted[pin["service_id"]]
        require(pin["canonical_endpoint"].rstrip("/") in origins and
                resolution["method_history_evidence"]["boundary"]["to_method_history_head"] == pin["method_history_head"] and
                resolution["method_history_evidence"]["boundary"]["to_version_id"] == pin["version_id"] and
                resolution["method_history_evidence"]["log_entries"] == binding["resolution"]["method_history_evidence"]["log_entries"],
                "native AA binding lacks its actual owning process and admitted complete method history")


def mimi_notify(evidence, message, binding, observations=None):
    before = evidence.get("consumer_count_before")
    after = evidence.get("consumer_count_after")
    require(evidence.get("accepted", {}).get("accepted") is True and
            evidence.get("consumer_checkpoint", {}).get("kind") == "checkpoint" and
            isinstance(before, (int, float)) and not isinstance(before, bool) and math.isfinite(before) and before >= 0 and
            isinstance(after, (int, float)) and not isinstance(after, bool) and math.isfinite(after) and after >= before + 1,
            "MIMI notification ACK has no actual authorized consumer")
    originals = evidence.get("canonical_before")
    require(isinstance(originals, list) and bool(originals) and originals == evidence.get("canonical_after"),
            "MIMI notification omitted or changed its canonical originals")
    initial = evidence["consumer_checkpoint"]
    refreshed = evidence.get("refresh_checkpoint", {})
    require(refreshed.get("kind") == "checkpoint" and isinstance(initial.get("cursor"), str) and
            refreshed.get("cursor") == initial["cursor"] and "payload" not in refreshed,
            "MIMI notification has no refresh on the exact authorized subscriber connection")
    request = evidence["request"]
    service = message["directory"]["service_id"]
    require(evidence["binding"] == binding and evidence["realm_id"] == binding["event"]["realm_id"] and
            request["origin_provider_id"] == evidence["recipient_account"]["station_id"] == service and
            request["routing"]["mimi_room_uri"] == binding["event"]["payload"]["mimi_room_uri"] and
            request["routing"]["target_provider_ids"] == [service] and
            request["notification"]["fanout_ref"] == message["committed"]["event"]["event_id"] and
            any(row["event"] == message["committed"]["event"] and row["commit"] == message["committed"]["commit"] for row in originals),
            "MIMI notification lacks its exact actual source, room, recipient and mapped message")
    exchanges = [row for row in (observations or {}).get("exchanges", [])
                 if row["operation_id"] == "ak.open.mimi.command.notify.v1" and row["response_status"] == 200]
    require(len(exchanges) == 1, "MIMI notification has no unique actual signed inbound exchange")
    exchange = exchanges[0]
    headers = exchange["explicit_request_headers"]
    require(exchange["request_body"] == request and exchange["response_body"] == evidence["accepted"] and
            headers.get("source-service-id") == headers.get("destination-service-id") == service and
            headers.get("provider-id") == message["directory"]["mimi"]["provider_id"] and
            headers.get("mimi-room-uri") == request["routing"]["mimi_room_uri"] and
            bool(headers.get("signature")) and bool(headers.get("signature-input")),
            "MIMI notification substituted the signed request, actual source or accepted response")


def account_erasure_status(evidence):
    bindings = evidence["issuer_bindings"]
    participants = {evidence["receipt_evidence"]["source_id"], evidence["receipt_evidence"]["receiver_id"]}
    require(len(bindings) == len(participants) == 2 and
            {native_issuer_pin(binding)["service_id"] for binding in bindings} == participants,
            "native erasure lacks its exact two actual issuer bindings")
    native_issuer_continuity(evidence["issuer_continuity"])
    require(native_issuer_pin(evidence["issuer_continuity"]["after"])["service_id"] == evidence["receipt_evidence"]["source_id"],
            "native issuer continuity belongs to another executor")
    require(evidence["erasure_request_max_auth_age"] == 300, "native erasure has no actual configured high-risk freshness policy")
    accepted=evidence["accepted"]
    intent=evidence["originals"]["intent"]
    require(accepted==evidence["replay"]==json.loads(base64.b64decode(evidence["originals"]["canonical_outcome_base64"])) and
            accepted["request_id"]==evidence["request"]["request_id"]==intent["request_id"] and
            intent["request_digest"]=="sha256:"+canonical_digest(evidence["request"]) and intent["record_issued_at"] and
            "withdrawal_window_ends_at" not in accepted,"erasure response did not retain its actual atomic intent and original acceptance")
    instant=lambda value:datetime.fromisoformat(value.replace("Z","+00:00"))
    recorded=instant(accepted["recorded_at"])
    require(any(0 <= (recorded-instant(row["created_at"])).total_seconds() <= 60 for row in evidence["originals"]["authentications"]),
            "erasure request lacks its actual newly authenticated issuer session")
    records=[row["record"] for row in evidence["originals"]["records"]]
    require(bool(records) and records[-1]["status"]=="erasure_pending" and
            intent["account_status_record_id"]==records[-1]["account_status_record_id"],"erasure acceptance lacks its actual signed pending record")
    for index,record in enumerate(records):
        require(record["account_id"]==evidence["resolve_request"]["account_id"] and record["principal_control_realm_id"]==evidence["original_pcr"] and
                int(record["status_sequence"])==index+1 and record.get("previous_account_status_record_id")==
                (None if index==0 else records[index-1]["account_status_record_id"]),"issuer chain changed its original Account/PCR or predecessor")
    require(evidence["resolved"]["records"]==records and evidence["resolved"]["has_more"] is False and
            "next_status_sequence" not in evidence["resolved"] and len(evidence["replica"])==len(evidence["publications"])==len(records),"resolve returned a partial or invented issuer chain")
    jobs=evidence["originals"]["jobs"]
    for publication,record,replica in zip(evidence["publications"],records,evidence["replica"]):
        require(publication["body"]["publication"]["record"]==record==replica["record"] and publication["accepted"]==publication["replay"] and
                publication["accepted"]["status"] in {"accepted","duplicate"} and publication["accepted"]["receipt"]==replica["receipt"],
                "native publication lacks the exact actual record, receiver receipt or safe replay")
        require(any(job["payload"]["body"]==publication["body"] and job["payload"]["idempotency_key"]==publication["key"] and
                    job["payload"]["body_digest"]=="sha256:"+canonical_digest(publication["body"]) for job in jobs),
                "native publication was reconstructed rather than retained from the actual durable job")
    native_erasure_receipts(evidence["receipt_evidence"],records[-1],evidence["observations"])


def native_erasure_receipts(evidence, terminal, observations):
    package=evidence["package"]
    receipt=package["receipt"]
    before=evidence["seed"]["before"]
    after=evidence["completion"]["after"]
    account=terminal["account_id"]
    require(terminal["status"]=="erasure_pending" and evidence["source_id"]!=evidence["receiver_id"] and
            receipt["issuer_id"]==evidence["source_id"] and receipt["outcome"]=="completed" and
            receipt["trigger"]=={"kind":"account_status_record","account_status_record_id":terminal["account_status_record_id"]} and
            receipt["subject"]=={"kind":"principal","subject_ref":account["principal_id"]} and
            receipt["scope"]=={"storage_boundary":"account_private_store","target_refs":[account["principal_id"]],"service_scope":"account_status.erasure_execution"},
            "receipt did not originate from the exact native terminal Account execution")
    require(set(receipt["erased_classes"])=={"account_private_state","push_routes","device_secrets","projection_rows"} and
            len(receipt["erased_classes"])==4 and bool(receipt["proofs"]) and "legal_hold_ref" not in receipt and
            "retained_stub" not in receipt and receipt["retained_stub_digest"]=="sha256:"+canonical_digest(package["retained_stub"]),
            "native completed receipt has incomplete classes/proof/stub binding")
    for field in ("data","backups","private_events","routes"):
        require(bool(before[field]),f"native erasure has no real pre-existing {field}")
    require(any(row["payload"]==evidence["seed"]["backup"] for row in before["backups"]),
            "erasure did not start with the actual accepted encrypted backup")
    for field in ("data","backups","private_events","routes","data_changes","global_versions"):
        require(after[field]==[],f"Completed retained private {field}")
    require(after["canonical_pcr"]==before["canonical_pcr"] and bool(after["canonical_pcr"]),
            "erasure rewrote or omitted its accepted canonical PCR")
    require(len(after["completions"])==1 and after["completions"][0]["package"]==package==evidence["completion"]["package"] and
            after["completions"][0]["account_id"]==account and
            after["completions"][0]["triggering_status_record_id"]==terminal["account_status_record_id"],
            "receipt has no exact atomic native completion original")
    acknowledgement=evidence["accepted"]
    receipt_bytes=json.dumps(receipt,ensure_ascii=False,sort_keys=True,separators=(",", ":")).encode()
    digest="sha256:"+hashlib.sha256(b"ak.erasure-receipt.v1\n"+receipt_bytes).hexdigest()
    require(acknowledgement==evidence["replay"]==evidence["duplicate"] and evidence["fetched"]==package and
            acknowledgement["status"]=="accepted" and acknowledgement["receipt_id"]==receipt["receipt_id"] and
            acknowledgement["receipt_digest"]==digest and acknowledgement["issuer_id"]==evidence["source_id"] and
            acknowledgement["receiver_id"]==evidence["receiver_id"],"receipt transport changed its native frozen acknowledgement or package")
    originals=evidence["receiver_originals"]
    replies=[row for row in originals if row["operation_id"]=="ak.peer.erasure_receipt.command.submit.v1"]
    lookups=[row for row in originals if row["idempotency_key"]=="erasure-receipt:lookup:"+receipt["receipt_id"]]
    require(len(replies)==2 and all(row["response_body"]==acknowledgement for row in replies) and
            len(lookups)==1 and lookups[0]["response_body"]["package"]==package and
            lookups[0]["response_body"]["acceptance"]==acknowledgement,
            "native receiver lacks its exact atomic response and lookup custody")
    exchanges=[row for row in observations["exchanges"] if row["operation_id"].startswith("ak.peer.erasure_receipt.")]
    require(len(exchanges)>=4 and all(row["response_status"]==200 and
            row["explicit_request_headers"]["source-service-id"]==evidence["source_id"] and
            row["explicit_request_headers"]["destination-service-id"]==evidence["receiver_id"] for row in exchanges),
            "receipt operations have no actual qualified cross-Station transports")

def mimi_claim(evidence):
    request=evidence["request"]
    accepted=evidence["accepted"]
    require(accepted==evidence["replay"] and
            accepted["state"]=="claimed" and accepted["claim_request_id"]==request["claim_request_id"],
            "MIMI did not preserve its actual local accepted original")
    outcome=accepted["claim_outcome"]
    ledger=evidence["originals"]["ledger"]
    material=evidence["material"]
    package=evidence["originals"]["package"]
    require(ledger["outcome"]==outcome and ledger["state"]=="claimed" and ledger["key_package_use"]=="single_use" and
            ledger["request_digest"]=="sha256:"+canonical_digest(request) and len(outcome["claims"])==1,
            "MIMI lacks its exact real single-use claim CAS and digest")
    claim=outcome["claims"][0]
    require(claim["keypackage_ref"]==material["keypackage_ref"]==package["keypackage_ref"]==request["target_keypackage_ref"] and
            claim["keypackage"]==material["keypackage"] and "mimi.content.v1" in claim["capabilities"] and
            package["claimed_by_mls_group_id"]==request["mls_group_id"],
            "MIMI returned substituted bytes, capabilities, endpoint or group binding")




def account_logout(evidence, session):
    require(evidence["accepted"] == {"revoked": True} and evidence["replay"] == {"revoked": False},
            "logout did not complete its actual native invocation and terminal retry")
    require(evidence["principal_authority_before"] == evidence["principal_authority_after"] and
            bool(evidence["principal_authority_before"]["devices"]),
            "logout changed accepted principal authority or has no actual Device")
    rows = evidence["issuer_originals"]
    require(len(rows) == 2 and rows[1]["grant"]["lifecycle_state"] == "revoked" and
            bool(rows[1]["grant"]["revoked_at"]) and all(row["browser_session"]["finished_at"] for row in rows),
            "logout acknowledgement preceded real issuer and browser-session termination")
    for phase, row in zip(("issued", "refreshed"), rows):
        require(decoded_json(row["canonical_outcome_base64url"]) == row["canonical_outcome"] ==
                session["authority_originals"][phase]["canonical_outcome"],
                "logout rewrote an immutable issued original")
    claims = session["refreshed_verification"]["claims"]
    journal = evidence["journal"]
    require(journal["account_id"] == claims["account_id"] and
            journal["device_id"] == claims["device_binding"]["device_id"] and
            journal["auth_side_confirmed"] is True and bool(journal["completed_at"]),
            "logout lacks the exact native holder journal's durable completion")


def actor_private(evidence):
    event = evidence["request"]["event"]
    original = evidence["original"]
    require(evidence["response"] == evidence["replay"] == original["event_original"]["outcome"] and
            original == evidence["after"] and original["event_original"]["envelope"] == event,
            "actor-private response has no unchanged actual accepted original")
    require(event["kind"] == "ak.device.push_route" and event["payload"]["revoked"] is True and
            original["route"]["route_value"] == event["payload"] and original["route"]["revoked"] is True and
            original["route"]["accepted_event_id"] == event["event_id"] == evidence["response"]["accepted_event_id"] and
            original["route"]["revision"] == evidence["response"]["revision"] == 1 and
            original["shared_events"] == original["realm_commits"] == 0,
            "private tombstone has no real CAS or leaked into shared history")
    require(evidence["device_authorization"]["event"]["actor_id"] == event["actor_id"],
            "private write used another accepted Account's Device")


def mimi_message(evidence):
    request = evidence["request"]
    event = evidence["committed"]["event"]
    container = decoded_json(request["ciphertext"]["payload"])
    receipt = evidence["mapping_receipt"]
    require(bool(evidence["plaintext_base64url"]) and event["payload"]["encrypted_content"] == container["encrypted_content"] and
            "content" not in event["payload"] and event["actor_id"] != request["sender_actor_id"],
            "MIMI did not retain an actual decryptable encrypted envelope and facade authorship")
    provenance = event["payload"]["mimi_provenance"]
    require(provenance["attributed_sender_actor_id"] == request["sender_actor_id"] and
            provenance["attributed_sender_device_id"] == request["device_id"] and
            provenance["room_binding_ref"] == evidence["binding"]["event"]["event_id"] and
            provenance["source_envelope_digest"] == "sha256:" + canonical_digest(request) and
            receipt["arkret_event_id"] == event["event_id"] == evidence["response"]["event_ref"] and
            receipt["original_envelope_digest"] == provenance["source_envelope_digest"] and bool(receipt["proof"]),
            "MIMI mapping has no exact native receipt, accepted binding or sender attribution")


def watch_audit(evidence):
    accepted = evidence["accepted"]
    current = evidence["current"]
    require(accepted == evidence["replay"] and accepted["audit_commit"] == evidence["audit_commit"]["commit"] and
            evidence["audit_commit"]["event"] == evidence["audit_request"]["audit_submission"]["event"] and
            accepted["current"]["current_state"]["revision"]["commit_id"] == evidence["watch"]["commit"]["commit_id"] and
            accepted["current"]["current_state"]["value"]["level"] == "all",
            "audited read did not freeze a real nonempty accepted Watch")
    require(current["audit_commit"] == evidence["next_commit"]["commit"] and
            current["current"]["current_state"]["value"] is None and
            current["current"]["current_state"]["revision"]["commit_id"] == evidence["clear"]["commit"]["commit_id"],
            "fresh audit confused an admitted cleared value with absence")


def media_token(evidence):
    request = evidence["request"]
    response = evidence["response"]
    token = response["backend_token"]
    require(response["backend_kind"] == "arkret_native" and bool(token["signature"]) and
            token["payload"]["participant_id"] == response["participant_id"] and
            token["payload"]["call_id"] == request["call_id"] == response["call_id"] and
            token["payload"]["focus_id"] == request["focus_id"] == response["focus_id"] and
            token["payload"]["expires_at"] == response["expires_at"] == response["participant_binding"]["expires_at"],
            "media acknowledgement lacks its actual signed native ticket and participant binding")
    require(evidence["nonce_original"]["subject_actor_id"] == request["actor_id"] == response["actor_id"] and
            evidence["nonce_original"]["subject_device_id"] == request["device_id"] == response["device_id"] and
            evidence["nonce_original"]["nonce"] == request["join_context"]["nonce"] and
            evidence["focus"]["event"]["payload"]["call_id"] == request["call_id"],
            "media ticket lacks actual current Call authority or native consumption of holder intent")


def peer_invite(evidence):
    request = evidence["request"]
    event = evidence["source"]["event"]
    entries = evidence["quarantine_original"]["content"]["quarantine_entries"]
    require(all(evidence[key]["status"] == "deferred" and
                "disclosed_outcome" not in evidence[key] for key in ("accepted", "replay")) and
            evidence["quarantine_original"] == evidence["quarantine_after"] and
            request["invite_event"] == event and request["invite_commit"] == evidence["source"]["commit"] and
            any(row["invite_event_id"] == event["event_id"] and row["source_peer_actor_id"] == event["actor_id"] and
                row["account_id"] == request["invite_address"]["account_id"] for row in entries),
            "opaque peer acknowledgement has no actual admitted invitation and holder quarantine effect")
    require(evidence["before_originals"]["quota"] == [] and
            len(evidence["originals"]["quota"]) == 1 and
            evidence["originals"] == evidence["after_originals"],
            "peer Invite replay changed its accepted private original or charged quota twice")
    cell = evidence["quarantine_original"]
    require(any(row["account_data_key"] == "ak.account.holder_quarantine" and
                row["payload"] == cell["content"] and row["revision"] == cell["revision"]
                for row in evidence["originals"]["cells"]),
            "holder quarantine response differs from its actual stored revision")
    attempts = evidence["attempts"]
    require(len(attempts) == 2 and [row["response"] for row in attempts] ==
            [evidence["accepted"], evidence["replay"]], "Invite attempt windows do not bind both actual replies")
    instant = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00"))
    for attempt in attempts:
        start, end = instant(attempt["started_at"]), instant(attempt["completed_at"])
        received = attempt["response"].get("received_at")
        require(start <= end and (received is None or start <= instant(received) <= end),
                "opaque Invite reply exposed a stored admission timestamp instead of its receive attempt")


def peer_events(evidence, observations):
    request = evidence["request"]
    response = evidence["response"]
    accepted = evidence["accepted"]
    original = evidence["origin_original"]
    require(evidence["origin_service_id"] != evidence["target_service_id"] and
            request["branch"] == response["branch"] == "authority_forward" and
            request["event_submission"] == original["original_submission_json"] and
            evidence["device_evidence_original"] in original["device_evidence_originals"] and
            evidence["device_evidence_original"]["evidence_json"] == request["producer_device_evidence"] and
            request["event_submission"]["event"] == accepted["event"] and
            original["accepted_commit_json"] == response["response_body"]["commit"] == accepted["commit"] and
            response["response_body"]["status"] in {"committed", "duplicate"} and response == evidence["replay"],
            "peer Events did not recover an actual frozen native-origin forward and accepted Commit")
    require(evidence["before"] == evidence["after"] and
            evidence["before"]["event"]["state"] == "committed" and
            evidence["before"]["event"]["envelope"] == accepted["event"] and
            evidence["before"]["commit"]["commit_json"] == accepted["commit"] and
            all(original[key] == evidence["origin_after"][key] for key in
                ("original_submission_json", "device_evidence_originals", "accepted_commit_json")),
            "peer Events has no unique durable original or changed canonical history on exact replay")
    core = request["producer_device_evidence"]["device_projection_attestation"]["attestation"]
    unsigned = {key: value for key, value in request.items() if key != "producer_device_evidence"}
    require(core["account_id"]["station_id"] == evidence["origin_service_id"] and
            accepted["event"]["actor_id"] == {"kind": "account", "account_id": core["account_id"]} and
            core["event_authorization"]["event_id"] == accepted["event"]["event_id"] and
            core["event_authorization"]["destination_service_id"] == evidence["target_service_id"] and
            core["event_authorization"]["forward_body_digest"] == "sha256:" + canonical_digest(unsigned) and
            bool(accepted["commit"]["producer_signer_fact_digest"]),
            "peer Events lacks the native-origin Device source bound to its exact body/destination and Commit")
    instant = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(all(instant(core["attested_at"]) <= instant(evidence[field]) < instant(core["expires_at"])
                for field in ("received_at", "replay_received_at")), "peer Events used expired origin evidence")
    exchanges = [row for row in observations["exchanges"] if row["operation_id"] == "ak.peer.events.command.submit.v1"]
    require(len(exchanges) >= 2 and all(row["request_body"] == request and row["response_body"] == response and
                row["explicit_request_headers"]["source-service-id"] == evidence["origin_service_id"] and
                row["explicit_request_headers"]["destination-service-id"] == evidence["target_service_id"] for row in exchanges),
            "peer Events lacks actual two-authority recovery and replay HTTP originals")


def peer_watch(evidence, observations):
    watch_audit(evidence)
    request = evidence["peer_request"]
    event = evidence["audit_commit"]["event"]
    original = evidence["before"]
    source, target = evidence["source_service_id"], evidence["governor_service_id"]
    require(source != target and request["audit_submission"] == evidence["audit_request"]["audit_submission"] and
            original == evidence["after"] and original["logical_request"] == evidence["audit_request"] and
            original["row"]["canonical_request"] == "\\x" + json.dumps(evidence["audit_request"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode().hex() and
            original["event"] == event and original["commit"] == evidence["audit_commit"]["commit"] and
            original["row"]["outcome"] == evidence["accepted"] == evidence["response"] and
            original["row"]["audit_event_id"] == event["event_id"] and
            json.loads(original["row"]["auditor_actor_id"]) == event["actor_id"] and
            bool(original["row"]["private_audit_digest"]),
            "peer Watch audit has no exact durable private observation or native accepted audit original")
    selected = evidence["device_evidence_original"]
    require(selected in evidence["device_evidence_originals"] and selected["evidence_json"] == request["producer_device_evidence"],
            "peer Watch audit substituted its native source Device archive")
    core = request["producer_device_evidence"]["device_projection_attestation"]["attestation"]
    unsigned = {key: value for key, value in request.items() if key != "producer_device_evidence"}
    require(core["account_id"]["station_id"] == source and
            event["actor_id"] == {"kind": "account", "account_id": core["account_id"]} and
            core["event_authorization"]["event_id"] == event["event_id"] and
            core["event_authorization"]["destination_service_id"] == target and
            core["event_authorization"]["forward_body_digest"] == "sha256:" + canonical_digest(unsigned) and
            bool(evidence["audit_commit"]["commit"]["producer_signer_fact_digest"]),
            "peer Watch audit source does not bind its exact body, destination and accepted Commit")
    instant = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(all(instant(core["attested_at"]) <= instant(evidence[field]) < instant(core["expires_at"])
                for field in ("received_at", "replay_received_at")), "peer Watch audit used expired native source evidence")
    exchanges = [row for row in observations["exchanges"]
                 if row["operation_id"] == "ak.peer.strand.watch.command.audit_read.v1"]
    require(len(exchanges) >= 2 and all(row["request_body"] == request and row["response_body"] == evidence["accepted"] and
                row["explicit_request_headers"]["source-service-id"] == source and
                row["explicit_request_headers"]["destination-service-id"] == target for row in exchanges),
            "peer Watch audit lacks actual two-authority recovery and exact replay HTTP originals")
    require(any(row["operation_id"] == "ak.self.strand.watch.command.audit_read.v1" and row["response_status"] == 200 and
                row["request_body"] == evidence["audit_request"] and row["response_body"] == evidence["accepted"]
                for row in observations["exchanges"]), "peer Watch audit lacks an actually completed native source request")


def peer_contacts(evidence):
    request, response = evidence["request"], evidence["response"]
    require(request["kind"] == "current_refresh" and response.get("operation_kind") == "current_refresh" and
            response["status"] == "accepted" and response == evidence["replay"],
            "peer Contact acknowledgement is not nonempty accepted current recovery")
    material = response["material"]
    proof = material["current_proof"]
    before = evidence["before"]["current_state"]
    after = evidence["after"]["current_state"]
    direction = [row for row in before["directions"] if row["head_operation"] == material["head_operation"]]
    require(len(direction) == 1 and bool(direction[0]["scope_instances"]) and bool(direction[0]["scope_grants"]) and
            proof["scope_instances"] == direction[0]["scope_instances"] and
            material["scope_grants"] == direction[0]["scope_grants"] and
            material["initial_identity"] == before["initial_identity"] == after["initial_identity"] ==
                evidence["source_original"]["current_state"]["initial_identity"] and
            material["round_events"] == before["round_events"] == after["round_events"] and
            evidence["after"] == evidence["after_replay"],
            "peer Contact lacks actual accepted directional scope/round originals or changed them on replay")
    require(evidence["accepted_source"]["state"] == evidence["accepted_target"]["state"] == "accepted" and
            evidence["source_actor"] != evidence["target_actor"] and
            evidence["source_actor"]["account_id"]["station_id"] != evidence["target_actor"]["account_id"]["station_id"] and
            request["requester"]["account_id"] == evidence["source_actor"]["account_id"] and
            request["contact_address"]["recipient"] == proof["holder"] and
            proof["peer"] == request["requester"] and proof["version"] >= request["known_version"] and
            bool(request["grant_event_refs"]) and bool(material["historical_intervals"]),
            "peer Contact used a loopback, absent acceptance, wrong direction or empty authority intervals")
    control = evidence["control"]
    require(control == evidence["control_replay"] and control["operation_id"] == "ak.peer.contacts.command.submit.v1" and
            control["authenticated_actor"] == evidence["source_actor"] and
            control["idempotency_key"] == request["idempotency_key"] and
            control["request_hash"] == response["control_receipt"]["request_digest"] == "sha256:" + canonical_digest(request) and
            control["response_status"] == 200 and control["response_body"] == response,
            "peer Contact control has no exact immutable native transaction result")
    exchanges = [row for row in evidence["observations"]["exchanges"]
                 if row["operation_id"] == "ak.peer.contacts.command.submit.v1"]
    require(len(exchanges) >= 2 and len(evidence["observations"]["accepted_identity_material"]) == 2 and
            all(row["request_body"] == request and row["response_body"] == response and
                row["explicit_request_headers"]["source-service-id"] != row["explicit_request_headers"]["destination-service-id"]
                for row in exchanges), "peer Contact is not the actual two-authority recovery and replay")


def mls_attest_add(evidence, parent):
    request = evidence.get("request", {})
    producer = evidence.get("producer_original", {})
    installed = evidence.get("governance_original", {})
    require(bool(request) and bool(producer) and bool(installed) and
            isinstance(producer.get("acknowledged_at"), str) and
            producer.get("request_json") == installed.get("request_json") == request and
            installed == evidence.get("governance_after") and
            producer.get("attestation_digest") == installed.get("attestation_digest") == "sha256:" + canonical_digest(request),
            "MLS Add has no actual acknowledged recipient producer and unchanged original governance installation")
    attestation = request["attestation"]
    commit = evidence["committed"]
    welcome = evidence["welcome"]
    source = parent["source_description"]["service_id"]
    recipient = parent["destination_description"]["service_id"]
    require(source != recipient and attestation["attestor_station_id"] == recipient and
            request["claim_outcome"] == parent["issued"] and
            attestation["claim_receipt"] == parent["issued"]["claim_receipt"] and
            attestation["claim_id"] == parent["issued"]["claims"][0]["claim_id"] and
            attestation["actor_id"] == parent["issued"]["claims"][0]["actor_id"] and
            attestation["realm_id"] == native_genesis_realm(parent["genesis"]) == commit["event"]["realm_id"] and
            attestation["genesis_event_ref"] == evidence["genesis"]["event"]["event_id"] and
            attestation["commit_event_ref"] == commit["event"]["event_id"] == welcome["commit_event_ref"] and
            attestation["commit_stream_position"] == commit["commit"]["stream_position"] and
            attestation["welcome_id"] == welcome["welcome_id"] and
            evidence["recipient_welcome"] == [welcome] and
            attestation["epoch"] == "1" and type(evidence["restored_epoch"]) is int and evidence["restored_epoch"] == 1 and
            re.fullmatch(r"sha256:[a-f0-9]{64}", evidence.get("durable_state_digest", "")) is not None,
            "MLS Add substituted its real claim, recipient, accepted Commit/Welcome or durable private state")
    require(evidence["submission"]["commit_event"] == commit["event"] and
            evidence["submission"]["welcomes"] == [welcome] and
            evidence["replay"] == {"status": "duplicate", "attestation_digest": producer["attestation_digest"]},
            "MLS Add replay changed its actual accepted unit or original attestation digest")
    exchanges = [row for row in parent["observations"]["exchanges"]
                 if row["operation_id"] == "ak.peer.mls.command.attest_add.v1" and row["response_status"] == 200]
    require(len(exchanges) == 1 and exchanges[0]["request_body"] == request and
            exchanges[0]["response_body"] == evidence["replay"] and
            exchanges[0]["explicit_request_headers"].get("source-service-id") == recipient and
            exchanges[0]["explicit_request_headers"].get("destination-service-id") == source,
            "MLS Add lacks its exact real recipient-to-governor signed peer exchange")


def peer_keypackage_claims(evidence):
    request = evidence["request"]
    binding = request["service_binding"]
    require(binding["source_id"] != binding["destination_id"] and
            binding["source_id"] == evidence["source_description"]["service_id"] and
            binding["destination_id"] == evidence["destination_description"]["service_id"],
            "peer claim substituted a loopback or unadmitted Station identity")
    require(evidence["recovered"] == evidence["queried"] and evidence["recovered"]["state"] == "claimed" and
            evidence["recovered"]["claim_outcome"] == evidence["issued"] == evidence["originals"]["ledger"]["outcome"] and
            evidence["originals"]["ledger"]["state"] == "claimed" and
            evidence["originals"]["ledger"]["request_digest"] == evidence["query"]["request_digest"] == "sha256:"+canonical_digest(request),
            "cross-Station recovery lacks the destination's actual immutable claim CAS")
    source = evidence.get("source_original", {})
    require(source.get("state") == "claimed" and source.get("outcome") == evidence["issued"] and
            source.get("request_digest") == evidence["query"]["request_digest"] and
            any(row["operation_id"] == "ak.self.keys.keypackages.command.claim.v1" and
                row["response_status"] == 200 and row["response_body"] == evidence["issued"]
                for row in evidence["observations"]["exchanges"]),
            "queued relay or direct peer replay cannot replace the source's completed native claim")
    require(len(evidence["issued"]["claims"]) == 1 and
            evidence["issued"]["claims"][0]["keypackage"] == evidence["material"]["keypackage"] and
            evidence["issued"]["claims"][0]["keypackage_ref"] == evidence["material"]["keypackage_ref"] == evidence["originals"]["package"]["keypackage_ref"] and
            evidence["membership"]["event"]["kind"] == "ak.member.state" and
            len(evidence["observations"]["accepted_identity_material"]) == 2,
            "peer claim lacks real admitted participants, target bytes or independent authority closures")
    peer_events(evidence["peer_event"], evidence["observations"])
    peer_watch(evidence["peer_watch"], evidence["observations"])
    mls_attest_add(evidence["mls_add"], evidence)


PROOFS = {"peer_contacts": peer_contacts, "peer_keypackage_claims": peer_keypackage_claims,"account_identity_creation": account_identity_creation, "account_device_sessions": account_device_sessions,
          "account_device_pairing": account_device_pairing, "account_policy_recovery": account_policy_recovery,
          "account_private_storage": account_private_storage, "mls_interop": mls_interop,
          "account_consent": account_consent,"identity_reservations":identity_reservations,
          "service_registrations":service_registrations,"organization_registrations":organization_registrations,"blob_presign":blob_presign}


def deployment_boundary_guard(source_fence):
    # A deployment guard is never evidence of issuer authority or operation effects.
    from check_service_isolation import source_errors
    failures = source_errors(ROOT, source_fence)
    require(not failures, "; ".join(failures))


def evidence_coverage(document, directory: Path, execution: Path):
    result = read(execution)
    require(result["exit_code"] == 0 and result["sources_unchanged"] is True,
            "native execution failed or its sources changed")
    log = (execution.parent / result["log"]).read_text(encoding="utf-8")
    source_fence = read(execution.parent / result["source_fence"])
    required_sources = {
        "coland/Cargo.toml",
        "coland/crates/server/Cargo.toml",
        "coauth/Cargo.toml",
        "coauth/crates/backend/Cargo.toml",
        "arkret-rust-sdk/crates/deployment-contracts/Cargo.toml",
        "arkret-rust-sdk/crates/deployment-contracts/src/account_projection.rs",
        "arkret-rust-sdk/crates/deployment-contracts/src/agent_session_authority.rs",
        "coland/crates/http/src/routing/identity/account_authority_client.rs",
        "coland/crates/http/src/routing/identity/auth_grant_dpop.rs",
        "coland/crates/http/src/state/authority_forward.rs",
        "coland/crates/http/src/state/account_authority_device_pairing.rs",
        "coland/crates/server/src/main.rs",
        "coauth/crates/backend/src/handlers/arkret/session_grant/introspection.rs",
        "coauth/crates/backend/src/handlers/arkret/controller_gate.rs",
        "coauth/crates/backend/src/handlers/arkret/session_grant/session_logout.rs",
        "coauth/crates/backend/src/handlers/arkret/device_pairing.rs",
        "coauth/crates/backend/src/services/station_trust.rs",
        "coauth/crates/storage-postgres/src/station_trust.rs",
        "cotest/src/scenarios/agent_runtime_live/coauth_session_evidence.rs",
        "cotest/src/scenarios/_helpers/native_issuer_binding.rs",
        "cotest/src/harness/public_base.rs",
        "cotest/crates/test-support/src/operation_observation.rs",
        "cotest/tests/native_operation_contracts.rs",
        "cotest/tests/fixtures/native-operation-contracts.json",
        "cotest/src/scenarios/native_operation_contracts.rs",
        "cotest/crates/test-support/src/provisioning/gate.rs",
        "coauth/crates/backend/src/handlers/arkret/account_register.rs",
        "coland/crates/services/src/authority_commit.rs",
        "arkret-spec/spec/v1/artifacts/registry/contract-registry.json",
    }
    require(required_sources <= source_fence.keys(), "native source provenance is incomplete")
    require("--no-run" not in result["command"] and "--list" not in result["command"],
            "compiling or listing tests is not native execution")
    for relative, expected in source_fence.items():
        path = ROOT / relative if not relative.startswith("savfox/") else ROOT.parent / "savfox-ai" / relative
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                f"native execution belongs to different sources: {relative}")
    require("test result: ok." in log and "0 failed; 0 ignored;" in log,
            "native test did not actually execute without skips")
    products = result.get("native_products", [])
    require(len(products) >= 2, "native executable build provenance absent")
    product_identities = set()
    for product in products:
        producer = read(execution.parent / product["producer_result"])
        require(producer["exit_code"] == 0 and producer["sources_unchanged"] is True and
                producer["sha256"] == product["sha256"] and producer["executable"] == product["executable"],
                "native executable differs from its successful build")
        inputs = read(execution.parent / producer["source_fence"])
        # Cotest is not a production dependency of either native executable.
        require(all(source_fence.get(path) == digest for path, digest in inputs.items()
                    if not path.startswith("cotest/")), "native executable belongs to old production sources")
        product_identities.add((product["executable"], product["sha256"]))
    rows = {row["operation_id"]: row for row in document["operations"]}
    covered = set()
    for identifier, case in document["cases"].items():
        path = directory / case["artifact"]
        if not path.exists():
            continue
        require(f"test {case['test']} ..." in log, f"native case was not run: {identifier}")
        verify_executed_artifact(result, path)
        require(case["target"] in result["command"] or "--workspace" in result["command"],
                "native test target was not selected by the execution")
        proof = read(path)
        scope = {op for op, row in rows.items() if row["native_case"] == identifier}
        require(proof["case"] == identifier and set(proof["scope"]) == scope and bool(scope),
                "native evidence has the wrong operation scope")
        processes = proof["processes"]
        require(len(processes) >= 2, "native issuer and authority processes absent")
        origins = {row["origin"].rstrip("/") for row in processes}
        for process in processes:
            executable = Path(process["executable"])
            require(process["pid"] > 0 and executable.is_file() and
                    process["sha256"].removeprefix("sha256:") == hashlib.sha256(executable.read_bytes()).hexdigest(),
                    "native process executable changed")
            require((process["executable"], process["sha256"].removeprefix("sha256:")) in product_identities,
                    "native process did not use the frozen product build")
        seen = set()
        for exchange in proof["observations"]["exchanges"]:
            operation = exchange["operation_id"]
            if operation not in scope:
                continue
            binding = rows[operation]
            url = urlsplit(exchange["url"])
            require(f"{url.scheme}://{url.netloc}" in origins and matches_registered_path(binding["path"], url.path) and
                    exchange["method"] == binding["method"], "request did not reach the owning native process")
            require(exchange["explicit_request_headers"]["arkret-operation"] == operation and
                    200 <= exchange["response_status"] < 300, "refused or wrong operation is not coverage")
            if binding["request_schema_ref"] is None:
                require(exchange["request_json_base64url"] == "" and exchange["request_body"] is None,
                        "bodyless operation carried invented request JSON")
            else:
                require(decoded_json(exchange["request_json_base64url"]) == exchange["request_body"],
                        "native request original changed")
            if binding["success_shape_kind"] == "empty_response":
                require(binding["response_schema_ref"] is None and exchange["response_body"] is None and
                        exchange["decoded_response_bytes_base64url"] == "", "registered empty response carried invented JSON")
            else:
                require(decoded_json(exchange["decoded_response_bytes_base64url"]) == exchange["response_body"],
                        "native response original changed")
                require(isinstance(exchange["response_body"], dict) and bool(exchange["response_body"]),
                        "empty typed response is not a native authority proof")
            require(f"native operation contract passed: {operation}" in log, "domain proof did not complete")
            seen.add(operation)
        require(seen == scope and identifier in PROOFS, "native operation domain proof absent")
        native_issuer_bindings(proof["observations"], origins)
        try:
            PROOFS[identifier](proof)
        except (KeyError, IndexError, TypeError, ValueError) as error:
            raise ValueError(f"native domain proof invalid for {identifier}: {type(error).__name__}: {error}") from error
        covered.update(scope)
    deployment_boundary_guard(source_fence)
    from check_service_isolation import live_graph_errors
    isolation_failures, _ = live_graph_errors(ROOT)
    require(not isolation_failures, "; ".join(isolation_failures))
    return covered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--execution", type=Path)
    parser.add_argument("--declarations-only", action="store_true",
                        help="Check bindings only; deliberately certifies no native coverage.")
    args = parser.parse_args()
    document = declarations()
    require(bool(args.evidence_dir) == bool(args.execution), "evidence and native execution must be supplied together")
    require(args.declarations_only or args.evidence_dir, "native evidence is required for acceptance")
    require(not args.declarations_only or not args.evidence_dir, "declarations cannot certify native evidence")
    covered = evidence_coverage(document, args.evidence_dir, args.execution) if args.evidence_dir else set()
    missing = sorted(row["operation_id"] for row in document["operations"] if row["operation_id"] not in covered)
    print(json.dumps({"scope": len(document["operations"]), "native_covered": len(covered), "remaining": len(missing),
                      "uncovered_operations": missing}, indent=2))
    require(args.declarations_only or not missing, "native operation authority contracts are incomplete")


if __name__ == "__main__":
    main()
