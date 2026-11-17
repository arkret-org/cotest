"""Structural companion to the actual native Circle crypto/HTTP scenario.

This function cannot certify execution independently of the original process,
source, exact-test and raw exchange gates in check_native_operation_contracts.
"""
import re
from urllib.parse import urlsplit


def check(evidence, *, require, decode, digest, error_registry):
    scope = {"kind": "circle", "realm_id": evidence["realm_id"],
             "circle_id": evidence["circle_id"]}
    require(evidence["scope_ref"] == scope and
            evidence["circle_id"] == "ak:circle:" + evidence["circle_creation"]["event"]["event_id"].removeprefix("ak:event:"),
            "Circle rotation lacks its accepted Circle identity and exact scope")
    require(evidence["circle_read"]["circle_id"] == evidence["circle_id"] and
            evidence["circle_read"]["realm_id"] == evidence["realm_id"] and
            evidence["circle_read"]["mls_group_id"] == evidence["group_id"],
            "Circle member readback substituted another MLS group")
    require(len(evidence["observations"]["accepted_identity_material"]) == 2,
            "Circle rotation needs two actually admitted Account/Device identities")
    operation = "ak.self.circle.command.rotate_scope.v1"
    exchanges = [row for row in evidence["observations"]["exchanges"] if row["operation_id"] == operation]
    require(len(evidence["processes"]) == 2 and len(exchanges) == 4,
            "Circle domain lacks its four actual successful operation exchanges")
    origin = urlsplit(evidence["processes"][1]["origin"])
    path = "/_arkret/self/circles/" + evidence["circle_id"] + "/scope-rotate"
    for exchange, label in zip(exchanges, ("add", "update", "add", "update")):
        actual = urlsplit(exchange["url"])
        require(actual.scheme == origin.scheme and actual.netloc == origin.netloc and
                actual.path == path and not actual.query and not actual.fragment and
                exchange["method"] == "POST" and exchange["response_status"] == 200 and
                exchange["explicit_request_headers"]["arkret-operation"] == operation and
                exchange["request_json_base64url"] == evidence[label + "_request_base64url"] and
                decode(exchange["request_json_base64url"]) == exchange["request_body"] == evidence[label + "_request"] and
                exchange["decoded_response_bytes_base64url"] == evidence[label + "_response_base64url"] and
                decode(exchange["decoded_response_bytes_base64url"]) == exchange["response_body"] == evidence[label + "_outcome"],
                "Circle actual exchange substituted path, complete request, original result or replay")
    genesis = evidence["circle_genesis"]
    require(genesis["event"]["kind"] == "ak.mls.genesis" and
            genesis["event"]["scope_ref"] == scope and
            genesis["commit"]["event_ref"] == genesis["event"]["event_id"],
            "Circle rotation has no independent accepted MLS Genesis")
    require(evidence["parent_genesis"]["event"]["scope_ref"] ==
            {"kind": "realm", "realm_id": evidence["realm_id"]} and
            evidence["parent_current"]["current_mls_commit_event_ref"] ==
            evidence["parent_genesis"]["event"]["event_id"],
            "Circle fixture substituted its independent parent group")
    states = [evidence[name] for name in ("before", "after_add", "after_update")]
    require([int(state["epoch"]) for state in states] == [0, 1, 2] and
            all(state["effective_scope"] == scope and
                state["genesis_event_ref"] == genesis["event"]["event_id"] for state in states) and
            states[0]["current_mls_commit_event_ref"] == genesis["event"]["event_id"] and
            evidence["final_current"] == states[2],
            "Circle source current did not preserve its own exact epoch transitions")
    welcome = evidence["welcome"]
    require(evidence["queue"] == [welcome] and
            welcome["effective_scope"] == scope and
            evidence["add_request"]["welcomes"] == [welcome] and
            evidence["update_request"]["welcomes"] == [],
            "Circle fixture lacks the original Add Welcome and empty-Welcome rotation")
    require(evidence["recipient_commit"] == evidence["add_committed"] and
            evidence["recipient_update"] == evidence["update_committed"],
            "recipient used a different accepted Circle original")
    originals = evidence["originals"]
    for index, label in enumerate(("add", "update")):
        request = evidence[label + "_request"]
        outcome = evidence[label + "_outcome"]
        original = evidence[label + "_committed"]
        event = request["commit_event"]
        require("recovery_source" not in request and
                event == original["event"] and event["kind"] == "ak.mls.commit" and
                event["scope_ref"] == scope and event["realm_id"] == evidence["realm_id"] and
                original["commit"]["event_ref"] == event["event_id"] and
                original["commit"]["stream_ref"] == scope,
                "Circle operation changed its complete client carrier or accepted original")
        require(decode(evidence[label + "_request_base64url"]) == request and
                decode(evidence[label + "_response_base64url"]) == outcome and
                outcome["status"] == "committed" and outcome["commit"] == original["commit"],
                "Circle first outcome is not the actual committed original")
        payload = event["payload"]
        require(payload["base_group_state_ref"] == states[index]["current_mls_commit_event_ref"] and
                int(payload["previous_epoch"]) == index and int(payload["next_epoch"]) == index + 1 and
                states[index + 1]["current_mls_commit_event_ref"] == event["event_id"] and
                states[index + 1]["public_tree_ref"] == payload["ratchet_tree_ref"],
                "Circle Commit did not adopt the accepted base and exact public tree")
        replay = evidence[label + "_retry"]
        require(replay["status"] == 200 and
                replay["body_base64url"] == evidence[label + "_response_base64url"] and
                bool(replay["before"]) and replay["before"] == replay["after"],
                "Circle exact replay changed its original outcome or wrote again")
        source = [row for row in originals["canonical_events"]
                  if row["envelope"]["event_id"] == event["event_id"]]
        ledger = [row for row in originals["idempotency_keys"]
                  if row["idempotency_key"] == request["idempotency_key"] and
                  row["operation_id"] == "ak.self.events.command.submit.v1"]
        require(len(source) == len(ledger) == 1 and source[0]["state"] == "committed" and
                ledger[0]["source_event_pk"] == source[0]["pk"] and
                ledger[0]["request_hash"].removeprefix("sha256:") == digest(request) and
                ledger[0]["response_status"] == 200 and ledger[0]["response_body"] == outcome,
                "Circle retry lacks one exact source-bound original key/hash/result")
    claim_request = evidence["claim_request"]
    claim = evidence["claim"]
    require(claim_request["effective_scope"] == scope and
            claim_request["mls_group_id"] == evidence["group_id"] and
            len(claim["claims"]) == 1 and
            claim["claims"][0]["claim_id"] == welcome["keypackage_claim_ref"] and
            claim["claims"][0]["actor_id"] == welcome["recipient_actor_id"] and
            welcome["commit_event_ref"] == evidence["add_committed"]["event"]["event_id"],
            "Circle Welcome substituted a claim, recipient or group")
    deliveries = [row for row in originals["mls_welcome_deliveries"] if row["welcome_id"] == welcome["welcome_id"]]
    bindings = [row for row in originals["keypackage_claim_welcome_bindings"] if row["welcome_id"] == welcome["welcome_id"]]
    require(len(deliveries) == len(bindings) == 1 and
            deliveries[0]["delivery_json"] == welcome and
            bindings[0]["claim_id"] == welcome["keypackage_claim_ref"] and
            bindings[0]["commit_event_ref"] == welcome["commit_event_ref"],
            "Circle source has no unique actual Welcome/claim binding")
    claim_rows = [row for row in originals["peer_keypackage_claims"]
                  if row["source_id"] == bindings[0]["source_id"] and
                  row["claim_request_id"] == bindings[0]["claim_request_id"]]
    require(len(claim_rows) == 1 and claim_rows[0]["outcome"] == claim,
            "Circle source lacks the original actually issued claim")
    problem_codes = {row["code"]: row for row in error_registry["codes"]}
    for label, code in (("changed_body", "duplicate_conflict"),
                        ("changed_key", "duplicate_conflict"),
                        ("wrong_path", "schema_violation")):
        refused = evidence[label]
        registered = problem_codes[code]
        require(refused["status"] == refused["body"]["status"] == registered["http_status"] and
                refused["body"]["type"] == registered["type_uri"] and
                decode(refused["body_base64url"]) == refused["body"] and
                bool(refused["before"]) and refused["before"] == refused["after"],
                "Circle negative did not preserve its registered refusal and zero-effect cut")
    changed = dict(evidence["add_request"])
    changed["welcomes"] = []
    require(evidence["changed_body"]["request"] == changed,
            "changed-body negative did not alter only the complete Welcome inventory")
    changed = dict(evidence["changed_key"]["request"])
    require(changed["idempotency_key"] != evidence["add_request"]["idempotency_key"],
            "changed-key negative reused the original key")
    changed["idempotency_key"] = evidence["add_request"]["idempotency_key"]
    require(changed == evidence["add_request"] and evidence["wrong_path"]["request"] == evidence["add_request"],
            "Circle negative substituted Event or signature material")
    encrypted = evidence["encrypted"]
    header = encrypted["pre_encryption_header"]
    material = header["material"]
    require(encrypted["scheme"] == header["scheme"] and
            encrypted["group_id"] == header["mls_group_id"] and
            encrypted["epoch"] == header["epoch"] and
            encrypted["content_type"] == header["content_type"] and
            header["effective_scope"] == scope and header["event_kind"] == "ak.message.create" and
            header["routing_context"] == {"kind": "none"},
            "Circle internal decrypt payload differs from its authenticated header")
    envelope = {
        "version": header["envelope_version"],
        "content_type": header["content_type"],
        "encryption_scheme": header["scheme"],
        "encryption_context": {
            "epoch": header["epoch"],
            "group_state_ref": header["group_state_ref"],
            "content_key_salt": material["content_context"]["content_key_salt"],
            "root_ref": material["content_context"]["root_ref"],
            "key_commitment": material["key_commitment"],
            "protection": material["protection"],
        },
        "ciphertext": encrypted["ciphertext"],
    }
    require(evidence["message_committed"]["event"]["scope_ref"] == scope and
            evidence["message_committed"]["event"]["payload"]["encrypted_content"] == envelope and
            encrypted["group_id"] == evidence["group_id"] and int(encrypted["epoch"]) == 2 and
            encrypted["pre_encryption_header"]["group_state_ref"] == evidence["update_committed"]["event"]["event_id"] and
            bool(encrypted["ciphertext"]) and evidence["opened_base64url"] == evidence["expected_plaintext_base64url"] and
            bool(evidence["opened_base64url"]),
            "Circle consumer did not read and decrypt the original new-epoch ciphertext")
    for first, last in (("old_state_before_digest", "old_state_after_digest"),
                        ("old_checkpoint_digest", "old_checkpoint_after_digest")):
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", evidence[first]) is not None and
                evidence[first] == evidence[last],
                "failed old-epoch Circle decryption changed private state or durable checkpoint")
