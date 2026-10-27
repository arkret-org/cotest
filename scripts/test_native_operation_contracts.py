"""Regression gates for scope drift and false native coverage credit."""
from contextlib import redirect_stdout
import copy
import base64
import io
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_native_operation_contracts as gate
import audit_native_operation_schemas as schema_audit


class NativeOperationContractGates(unittest.TestCase):
    def test_mls_add_ack_cannot_replace_recipient_producer_or_governance_original(self):
        for evidence in ({"replay": {"status": "duplicate"}},
                         {"request": {"component": True}, "producer_original": {"request_json": {"component": True}},
                          "governance_original": {"request_json": {"component": True}}}):
            with self.subTest(evidence=evidence), self.assertRaisesRegex(ValueError, "acknowledged recipient producer"):
                gate.mls_attest_add(evidence, {})

    def test_mimi_notification_requires_the_exact_recorded_exchange(self):
        # Structural component only. No execution, issuer or signature credit.
        binding = {"event": {"realm_id": "component-realm", "payload": {"mimi_room_uri": "component-room"}}}
        message = {"directory": {"service_id": "component-service", "mimi": {"provider_id": "component-provider"}},
                   "committed": {"event": {"event_id": "component-event"}, "commit": {"component_commit": True}}}
        request = {"origin_provider_id": "component-service", "routing": {"mimi_room_uri": "component-room", "target_provider_ids": ["component-service"]},
                   "notification": {"fanout_ref": "component-event"}}
        checkpoint = {"kind": "checkpoint", "cursor": "component-cut"}
        evidence = {"request": request, "accepted": {"accepted": True}, "consumer_checkpoint": checkpoint,
                    "refresh_checkpoint": checkpoint, "consumer_count_before": 0, "consumer_count_after": 1,
                    "canonical_before": [message["committed"]], "canonical_after": [message["committed"]],
                    "binding": binding, "realm_id": "component-realm", "recipient_account": {"station_id": "component-service"}}
        exchange = {"operation_id": "ak.open.mimi.command.notify.v1", "response_status": 200,
                    "request_body": request, "response_body": evidence["accepted"],
                    "explicit_request_headers": {"source-service-id": "component-service", "destination-service-id": "component-service",
                     "provider-id": "component-provider", "mimi-room-uri": "component-room", "signature": "component-only", "signature-input": "component-only"}}
        gate.mimi_notify(evidence, message, binding, {"exchanges": [exchange]})
        for member, replacement in (("response_status", 403), ("request_body", {}), ("response_body", {"accepted": False})):
            changed = copy.deepcopy(exchange)
            changed[member] = replacement
            with self.subTest(member=member), self.assertRaises(ValueError):
                gate.mimi_notify(evidence, message, binding, {"exchanges": [changed]})
        with self.assertRaisesRegex(ValueError, "unique actual signed"):
            gate.mimi_notify(evidence, message, binding, {"exchanges": [exchange, exchange]})

    def test_mimi_notification_ack_and_sender_count_are_not_consumer_coverage(self):
        evidence = {"accepted": {"accepted": True}, "consumer_checkpoint": {"kind": "checkpoint"},
                    "consumer_count_before": 0, "consumer_count_after": 0,
                    "canonical_before": [], "canonical_after": []}
        with self.assertRaisesRegex(ValueError, "authorized consumer"):
            gate.mimi_notify(evidence, {}, {})
        for count in (float("inf"), float("nan"), True):
            changed = copy.deepcopy(evidence)
            changed["consumer_count_after"] = count
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "authorized consumer"):
                gate.mimi_notify(changed, {}, {})
        evidence["consumer_count_after"] = 1
        with self.assertRaisesRegex(ValueError, "canonical originals"):
            gate.mimi_notify(evidence, {}, {})

    def test_unrelated_consumer_metrics_cannot_replace_the_same_subscription_refresh(self):
        evidence = {"accepted": {"accepted": True}, "consumer_checkpoint": {"kind": "checkpoint", "cursor": "actual-cut"},
                    "consumer_count_before": 0, "consumer_count_after": 1,
                    "canonical_before": [{"component_only": True}], "canonical_after": [{"component_only": True}]}
        for refreshed in ({}, {"kind": "checkpoint", "cursor": "other-cut"},
                          {"kind": "checkpoint", "cursor": "actual-cut", "payload": {"fake_event": True}}):
            changed = copy.deepcopy(evidence)
            changed["refresh_checkpoint"] = refreshed
            with self.subTest(refreshed=refreshed), self.assertRaisesRegex(ValueError, "exact authorized subscriber"):
                gate.mimi_notify(changed, {}, {})
        evidence["canonical_before"] = [{"component_only": True}]
        evidence["canonical_after"] = [{"fake_event": True}]
        with self.assertRaisesRegex(ValueError, "canonical originals"):
            gate.mimi_notify(evidence, {}, {})

    def test_issuer_original_pin_drift_and_revocation_are_rejected(self):
        # Structural component only: synthetic storage rows grant no native credit.
        resolution = gate.read(gate.ROOT / "coauth/crates/backend/src/services/station_trust/fixtures/native_station_resolutions.json")[0]
        document = resolution["normalized_did_document"]
        boundary = resolution["method_history_evidence"]["boundary"]
        pin = {"name": "component-owner", "canonical_endpoint": document["services"][0]["endpoint"],
               "service_id": resolution["service_id"], "service_kind": "station", "did": document["did"],
               "method_history_head": boundary["to_method_history_head"], "version_id": boundary["to_version_id"],
               "source": "automatic_verified", "enrolled_at": "2026-10-26T00:00:00Z",
               "last_verified_at": "2026-10-26T00:00:01Z"}
        audit = {"action": "enrolled", "enrollment_name": pin["name"], "service_id": pin["service_id"]}
        captured = {"resolution": resolution, "originals": {"configured_name": pin["name"],
                    "configured_endpoint": pin["canonical_endpoint"], "enrollments": [pin], "audits": [audit]}}
        gate.native_issuer_pin(captured)
        observed = {"accepted_identity_material": [{"station_resolution": resolution}], "issuer_bindings": [captured]}
        origins = {pin["canonical_endpoint"].rstrip("/")}
        gate.native_issuer_bindings(observed, origins)
        for bindings in ([], [captured, captured]):
            changed = copy.deepcopy(observed)
            changed["issuer_bindings"] = bindings
            with self.subTest(bindings=len(bindings)), self.assertRaisesRegex(ValueError, "every admitted Station"):
                gate.native_issuer_bindings(changed, origins)
        with self.assertRaisesRegex(ValueError, "actual owning process"):
            gate.native_issuer_bindings(observed, {"https://wrong-process.example"})
        changed = copy.deepcopy(observed)
        changed["accepted_identity_material"][0]["station_resolution"] = copy.deepcopy(resolution)
        changed["accepted_identity_material"][0]["station_resolution"]["method_history_evidence"]["log_entries"] = []
        with self.assertRaisesRegex(ValueError, "complete method history"):
            gate.native_issuer_bindings(changed, origins)
        for field in ("name", "canonical_endpoint", "service_id", "service_kind", "did", "method_history_head", "version_id", "source"):
            changed = copy.deepcopy(captured)
            changed["originals"]["enrollments"][0][field] = "wrong-component-value"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "original pin"):
                gate.native_issuer_pin(changed)
        for audits in ([], [dict(audit, action="revoked")], [audit, dict(audit, action="replaced")]):
            changed = copy.deepcopy(captured)
            changed["originals"]["audits"] = audits
            with self.subTest(audits=audits), self.assertRaisesRegex(ValueError, "enrollment audit"):
                gate.native_issuer_pin(changed)
        for enrollments in ([], [pin, pin]):
            changed = copy.deepcopy(captured)
            changed["originals"]["enrollments"] = enrollments
            with self.subTest(count=len(enrollments)), self.assertRaisesRegex(ValueError, "unique enrollment"):
                gate.native_issuer_pin(changed)

    def test_original_erasure_run_without_issuer_pin_cannot_be_reused(self):
        # An old successful acknowledgement cannot satisfy new original-pin gates.
        with self.assertRaises(KeyError):
            gate.account_erasure_status({"accepted": True, "replay": True})





    def test_authenticated_private_transport_is_allowed_without_native_credit(self):
        manifest = "coland/crates/server/Cargo.toml"
        adapter = "coland/crates/http/src/config.rs"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, content in {
                manifest: '[package]\nname="coland"\n[dependencies]\nreqwest="0.12"\n',
                adapter: 'const INTERNAL_GRANT_PATH: &str = "/_coauth/internal/session-grants/introspect";',
            }.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            with patch.object(gate, "ROOT", root):
                gate.deployment_boundary_guard({manifest: "component-only", adapter: "component-only"})
                with self.assertRaisesRegex(ValueError, "manifest provenance absent"):
                    gate.deployment_boundary_guard({})

    def test_embedded_backend_dependency_is_rejected_under_any_dependency_name(self):
        manifest = "coland/crates/server/Cargo.toml"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / manifest
            target.parent.mkdir(parents=True)
            for dependency in ('coauth-backend={path="../coauth"}',
                               'issuer={package="coauth-backend",path="../coauth"}'):
                target.write_text('[package]\nname="coland"\n[dependencies]\n'+dependency+'\n', encoding="utf-8")
                with patch.object(gate, "ROOT", root), self.assertRaisesRegex(ValueError, "must not load"):
                    gate.deployment_boundary_guard({manifest: "component-only"})

    def test_receipt_without_real_preexisting_private_state_is_not_native_coverage(self):
        # Structural negative only: these unsigned markers are not an accepted
        # record, package, service, or native fixture and earn no coverage.
        account={"principal_id":"component-principal","station_id":"component-source"}
        terminal={"status":"erasure_pending","account_id":account,"account_status_record_id":"component-trigger"}
        stub={"component_only":True}
        receipt={"issuer_id":"component-source","outcome":"completed",
                 "trigger":{"kind":"account_status_record","account_status_record_id":"component-trigger"},
                 "subject":{"kind":"principal","subject_ref":account["principal_id"]},
                 "scope":{"storage_boundary":"account_private_store","target_refs":[account["principal_id"]],"service_scope":"account_status.erasure_execution"},
                 "erased_classes":["account_private_state","push_routes","device_secrets","projection_rows"],
                 "proofs":["unsigned-component-marker"],"retained_stub_digest":"sha256:"+gate.canonical_digest(stub)}
        evidence={"source_id":"component-source","receiver_id":"component-receiver",
                  "package":{"receipt":receipt,"retained_stub":stub},
                  "seed":{"before":{"data":[],"backups":[],"private_events":[],"routes":[]}},
                  "completion":{"after":{}}}
        with self.assertRaisesRegex(ValueError,"no real pre-existing data"):
            gate.native_erasure_receipts(evidence,terminal,{"exchanges":[]})

    def test_invite_presentation_requires_consumed_custody_not_activated_material(self):
        row = {"request_id": "component-only", "state": "consumed", "token_selector": None,
               "deliver_after": None, "encrypted_record": "encrypted-component-audit"}
        # Structural checks only; this object is not native custody evidence.
        gate.native_invite_consumed_custody([row], "component-only")
        for member, value in (("state", "activated"), ("token_selector", "still-live"),
                              ("deliver_after", "queued"), ("request_id", "another"),
                              ("encrypted_record", "")):
            changed = dict(row, **{member: value})
            with self.subTest(member=member), self.assertRaisesRegex(ValueError, "consume its exact native custody"):
                gate.native_invite_consumed_custody([changed], "component-only")

    def test_genesis_realm_comes_from_its_content_address_and_exact_commit(self):
        original = {"event": {"event_id": "ak:event:structural-component", "scope_ref": {"kind": "realm_genesis"}},
                    "commit": {"realm_id": "ak:realm:structural-component"}}
        # Structural regression only; this is not an admitted Event fixture.
        self.assertEqual(gate.native_genesis_realm(original), original["commit"]["realm_id"])
        original["commit"]["realm_id"] = "ak:realm:another"
        with self.assertRaisesRegex(ValueError, "exact accepted Realm"):
            gate.native_genesis_realm(original)

    def test_snapshot_receive_cut_cannot_be_an_earlier_remote_signature_or_expired_time(self):
        evidence = {"bootstrap": {"authority_bundle": {"current_assertion": {
            "signature": {"created_at": "2026-10-26T00:00:00Z"}, "expires_at": "2026-10-26T00:05:00Z"}},
            "snapshot": {"created_at": "2026-10-26T00:00:01Z"}},
            "bootstrap_received_at": "2026-10-26T00:00:02Z"}
        # This checks the local clock boundary only, never native authority.
        gate.native_snapshot_receive_cut(evidence)
        for received in ("2026-10-26T00:00:00Z", "2026-10-26T00:05:00Z"):
            changed = copy.deepcopy(evidence)
            changed["bootstrap_received_at"] = received
            with self.subTest(received=received), self.assertRaisesRegex(ValueError, "receive cut"):
                gate.native_snapshot_receive_cut(changed)

    def test_schema_audit_collects_drift_without_granting_native_credit(self):
        root = {"controller_actor_id": {"kind": "service", "service_id": "ak:did_core:web:controller.example"},
                "controller_epoch": 0, "authority_generation": 0,
                "authority_event_ref": "ak:event:ARwa3HDa5tnXi6LS3su6qRZWOynOrcxh4u7Cai_7EdLm"}
        document = {"operations": [{"operation_id": "component-only",
                    "request_schema_ref": "schemas/current-state.schema.json#/$defs/realm_authority_root_value",
                    "response_schema_ref": None}]}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "attempt-component.json"
            def capture(value, response=""):
                path.write_text(json.dumps({"observations": {"exchanges": [{
                    "operation_id": "component-only", "request_body": value,
                    "request_json_base64url": base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("="),
                    "response_body": None, "decoded_response_bytes_base64url": response}]}}), encoding="utf-8")
            capture(root)
            report = schema_audit.audit(document, directory)
            self.assertFalse(report["native_coverage"])
            self.assertFalse(report["schema_valid"])
            self.assertEqual(report["findings"][0]["path"], ["authority_generation"])
            valid = copy.deepcopy(root)
            valid["authority_generation"] = "0"
            capture(valid)
            report = schema_audit.audit(document, directory)
            self.assertTrue(report["schema_valid"])
            self.assertFalse(report["native_coverage"])
            capture(valid, base64.urlsafe_b64encode(b"null").decode().rstrip("="))
            report = schema_audit.audit(document, directory)
            self.assertEqual(report["findings"][0]["keyword"], "registered_empty_body")

    def test_altered_or_unbound_native_original_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "native.json"
            path.write_text('{"accepted":true}', encoding="utf-8")
            result = {"evidence_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()}}
            gate.verify_executed_artifact(result, path)
            path.write_text('{"accepted":false}', encoding="utf-8")
            for record in (result, {}):
                with self.assertRaisesRegex(ValueError, "executed artifact"):
                    gate.verify_executed_artifact(record, path)

    def test_registered_resource_paths_match_one_segment_only(self):
        template = "/_arkret/self/security-transactions/{transaction_id}"
        self.assertTrue(gate.matches_registered_path(template, "/_arkret/self/security-transactions/ak:transaction:123"))
        for path in ("/_arkret/self/security-transactions/", "/_arkret/self/security-transactions/a/continue", "/_arkret/self/securityXtransactions/a"):
            self.assertFalse(gate.matches_registered_path(template, path))

    def test_registered_obligations_are_not_native_coverage(self):
        gate.declarations()
        with patch.object(sys, "argv", ["gate"]), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "evidence is required"):
                gate.main()

    def test_duplicate_obligation_cannot_hide_an_uncovered_operation(self):
        document = copy.deepcopy(gate.read(gate.CONTRACTS))
        document["operations"][1] = copy.deepcopy(document["operations"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            gate.declarations(document)

    def test_changed_operation_binding_and_unimplemented_case_are_rejected(self):
        for member, replacement in (("path", "/_arkret/wrong"),
                                    ("spec_operation_sha256", "0" * 64),
                                    ("error_mapping_sha256", "0" * 64),
                                    ("success_shape_kind", "empty_response"),
                                    ("native_case", "unimplemented_case")):
            document = copy.deepcopy(gate.read(gate.CONTRACTS))
            document["operations"][0][member] = replacement
            with self.subTest(member=member), self.assertRaises(ValueError):
                gate.declarations(document)

    def test_request_rejection_and_success_without_source_provenance_earn_no_credit(self):
        document = gate.declarations()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "run.log").write_text("test result: ok. 1 passed; 0 failed; 0 ignored;", encoding="utf-8")
            (directory / "sources.json").write_text("{}", encoding="utf-8")
            for exit_code, message in ((101, "execution failed"), (0, "provenance is incomplete")):
                (directory / "result.json").write_text(json.dumps({
                    "exit_code": exit_code, "sources_unchanged": True,
                    "log": "run.log", "source_fence": "sources.json", "command": ["cargo", "test"],
                }), encoding="utf-8")
                with self.subTest(exit_code=exit_code), self.assertRaisesRegex(ValueError, message):
                    gate.evidence_coverage(document, directory, directory / "result.json")

    def test_peer_signal_acknowledgement_alone_is_not_delivery(self):
        for status, body in [(200, ""), (200, "e30"), (204, "")]:
            evidence={"status":status,"response_base64url":body,"before":{},"after":{},"request":{"signals":[]},"received":{},"plaintext_base64url":""}
            with self.subTest(status=status,body=body), self.assertRaises(ValueError):
                gate.peer_signal(evidence,{"exchanges":[]})

    def test_empty_or_unaccepted_material_has_no_domain_proof(self):
        with self.assertRaises((KeyError, ValueError)):
            gate.account_identity_creation({"authority_originals": {}, "observations": {"exchanges": []}})

    def test_new_native_acknowledgements_cannot_replace_domain_effects(self):
        for proof in (gate.actor_private, gate.mimi_message, gate.watch_audit,
                      gate.media_token, gate.peer_invite, gate.peer_keypackage_claims, gate.peer_contacts):
            with self.subTest(proof=proof.__name__), self.assertRaises((KeyError, ValueError)):
                proof({"accepted": True})
        with self.assertRaises((KeyError, ValueError)):
            gate.account_logout({"accepted": {"revoked": True}, "replay": {"revoked": False}}, {})
        with self.assertRaises((KeyError, ValueError)):
            gate.peer_events({"accepted": True}, {"exchanges": []})
        with self.assertRaises((KeyError, ValueError)):
            gate.peer_watch({"accepted": True}, {"exchanges": []})

    def test_cross_station_claim_cannot_use_one_logical_authority(self):
        evidence = {"request": {"service_binding": {"source_id": "same", "destination_id": "same"}}}
        with self.assertRaisesRegex(ValueError, "loopback"):
            gate.peer_keypackage_claims(evidence)

    def test_direct_peer_claim_without_completed_source_relay_is_not_coverage(self):
        request = {"service_binding": {"source_id": "source", "destination_id": "target"}}
        digest = "sha256:" + gate.canonical_digest(request)
        issued = {"claims": []}
        original = {"state": "claimed", "claim_outcome": issued}
        evidence = {"request": request, "source_description": {"service_id": "source"},
                    "destination_description": {"service_id": "target"}, "issued": issued,
                    "recovered": original, "queried": original, "query": {"request_digest": digest},
                    "originals": {"ledger": {"state": "claimed", "outcome": issued, "request_digest": digest}},
                    "observations": {"exchanges": []}}
        for source in ({}, {"state": "claimed", "outcome": issued, "request_digest": digest}):
            evidence["source_original"] = source
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "completed native claim"):
                gate.peer_keypackage_claims(evidence)

    def test_invite_attempt_times_do_not_replace_immutable_quarantine_and_quota(self):
        event = {"event_id": "invite", "actor_id": {"actor": "sender"}}
        account = {"account": "holder"}
        cell = {"revision": 1, "content": {"quarantine_entries": [{"invite_event_id": "invite",
                 "source_peer_actor_id": event["actor_id"], "account_id": account}]}}
        originals = {"quota": [{"source_digest": "source", "first_admitted_at": "2026-10-26T00:00:00.000Z"}],
                     "cells": [{"account_data_key": "ak.account.holder_quarantine", "payload": cell["content"], "revision": 1}]}
        replies = [{"status": "deferred", "received_at": f"2026-10-26T00:00:0{index}.000Z"} for index in (1, 2)]
        evidence = {"request": {"invite_event": event, "invite_commit": {}, "invite_address": {"account_id": account}},
                    "source": {"event": event, "commit": {}}, "quarantine_original": cell, "quarantine_after": cell,
                    "accepted": replies[0], "replay": replies[1], "before_originals": {"quota": []},
                    "originals": originals, "after_originals": copy.deepcopy(originals),
                    "attempts": [{"started_at": reply["received_at"], "completed_at": reply["received_at"], "response": reply}
                                 for reply in replies]}
        # Component contract only; this grants no executed native authority credit.
        gate.peer_invite(evidence)
        changed = copy.deepcopy(evidence)
        changed["after_originals"]["quota"].append({"source_digest": "second-charge"})
        with self.assertRaisesRegex(ValueError, "charged quota twice"):
            gate.peer_invite(changed)
        changed = copy.deepcopy(evidence)
        changed["replay"]["disclosed_outcome"] = "blocked"
        with self.assertRaisesRegex(ValueError, "opaque peer acknowledgement"):
            gate.peer_invite(changed)
        changed = copy.deepcopy(evidence)
        changed["attempts"][1]["started_at"] = "2026-10-26T00:00:03.000Z"
        with self.assertRaisesRegex(ValueError, "stored admission timestamp"):
            gate.peer_invite(changed)


if __name__ == "__main__":
    unittest.main()
