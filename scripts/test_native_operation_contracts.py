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
    @classmethod
    def setUpClass(cls):
        # Compute the actual recursive closure once. Individual gate mutations
        # do not need to rehash every unchanged schema in the workspace.
        gate.declarations()
        import check_operation_closure_locks as closure
        reference = gate.read(closure.OPERATION_LOCK)["closures"]
        guard = patch.object(closure, "operation_closures", return_value=reference)
        guard.start()
        cls.addClassCleanup(guard.stop)


    def test_call_invitation_deferred_cannot_replace_the_actual_recipient_admission(self):
        # Component test for the structural domain oracle only. Actual producer,
        # native Station history, MLS decrypt and verdict signatures are checked
        # by the Rust native case; this dictionary earns no native credit.
        sender = {"kind": "account", "account_id": {"principal_id": "sender", "station_id": "A"}}
        holder = {"principal_id": "holder", "station_id": "H"}
        envelope = {"component": "same actual encrypted envelope"}
        invitation = {"call_id": "call", "media": {"audio": True, "video": False, "screen": False},
                      "expires_at": "2026-11-15T00:00:30.000Z", "proof": {"verification_method": "method"}}
        request = {"invitation": invitation, "envelope": envelope}
        outstanding = {**request, "subject_actor_id": {"kind": "account", "account_id": holder},
                       "subject_device_id": "device", "admission_phase": "product_delivery",
                       "audience_actor_id": {"kind": "service", "service_id": "H"},
                       "nonce": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg"}
        decision = {"request_digest": "sha256:" + gate.canonical_digest(outstanding), "admitted": True,
                    "authority_generation": "0", "evaluated_at": "2026-11-15T00:00:00.000Z",
                    "expires_at": "2026-11-15T00:00:30.000Z"}
        plaintext = {"kind": "ak.call.signal", "signal_kind": "invite", "call_id": "call",
                     "data": {"media": {"audio": True, "video": False}}}
        encoded = base64.urlsafe_b64encode(json.dumps(plaintext).encode()).decode().rstrip("=")
        delivery = {"envelope": envelope, "plaintext_base64url": encoded, "received_at": "2026-11-15T00:00:01.000Z",
                    "delivery_authority": {"recipient_account_id": holder,
                    "key": {"actor": sender, "verification_method": "method"},
                    "call_invitation": {"invitation": invitation, "request": outstanding, "decision": decision}}}
        gate.call_invitation_delivery(delivery, request, sender, holder, "device", True)
        missing = copy.deepcopy(delivery)
        missing["delivery_authority"].pop("call_invitation")
        with self.assertRaisesRegex(ValueError, "Deferred has no exact actual recipient"):
            gate.call_invitation_delivery(missing, request, sender, holder, "device", True)
        with self.assertRaisesRegex(ValueError, "revoked invitation retained"):
            gate.call_invitation_delivery(delivery, request, sender, holder, "device", False)
        gate.call_invitation_delivery(missing, request, sender, holder, "device", False)
        changed = copy.deepcopy(delivery)
        changed["delivery_authority"]["call_invitation"]["request"]["nonce"] = "eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXk"
        with self.assertRaisesRegex(ValueError, "Deferred has no exact actual recipient"):
            gate.call_invitation_delivery(changed, request, sender, holder, "device", True)
        changed = copy.deepcopy(delivery)
        changed["delivery_authority"]["recipient_account_id"]["station_id"] = "other"
        with self.assertRaisesRegex(ValueError, "full recipient"):
            gate.call_invitation_delivery(changed, request, sender, holder, "device", True)
        for received in ("2026-11-14T23:59:59.000Z", "2026-11-15T00:00:30.000Z"):
            with self.subTest(received=received), self.assertRaisesRegex(ValueError, "fresh outstanding"):
                gate.call_invitation_verdict(outstanding, decision, received, True)
        changed = copy.deepcopy(decision)
        changed["authority_generation"] = "1"
        with self.assertRaisesRegex(ValueError, "fresh outstanding"):
            gate.call_invitation_verdict(outstanding, changed, delivery["received_at"], True)

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
        # Structural component only. These intentionally unsigned placeholders
        # test pin consistency, not SDK verification or native execution.
        resolution = {
            "service_id": "component-station", "service_kind": "station",
            "normalized_did_document": {
                "did": "did:webvh:component", "services": [{
                    "endpoint": "https://component-station.example",
                    "protocol_names": ["ArkretService"],
                    "extensions": [{"name": "service_kind", "value": "station"}],
                }],
            },
            "method_history_evidence": {
                "evidence_kind": "webvh_log",
                "boundary": {"to_method_history_head": "component-head", "to_version_id": "component-version"},
                "log_entries": [{"unsigned_component_placeholder": True}],
            },
        }
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
        from check_service_isolation import source_errors
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = {}
            for name, content in {
                "coland/crates/server/Cargo.toml": '[package]\nname="coland"\n[dependencies]\nreqwest="0.12"\n',
                "coauth/crates/backend/Cargo.toml": '[package]\nname="coauth-backend"\n[dependencies]\nreqwest="0.12"\n',
                "coland/crates/http/src/config.rs": 'const PATH: &str = "/_coauth/internal/session-grants/introspect";',
            }.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                sources[name] = "component-only"
            self.assertEqual(source_errors(root, sources), [])
            with patch.object(gate, "ROOT", root):
                gate.deployment_boundary_guard(sources)
                with self.assertRaisesRegex(ValueError, "manifest provenance absent"):
                    gate.deployment_boundary_guard({})

    def test_foreign_implementation_dependency_is_rejected_in_both_directions(self):
        from check_service_isolation import source_errors
        for owner, other in (("coland", "coauth"), ("coauth", "coland")):
            for section in ("dependencies", "build-dependencies", "target.'cfg(windows)'.dependencies"):
                for dependency in (f'{other}-backend={{path="../../../{other}/crates/backend"}}',
                                   f'authority={{package="{other}-storage",version="0.3"}}',
                                   f'innocent={{path="../../../{other}/crates/backend"}}'):
                    with self.subTest(owner=owner, section=section, dependency=dependency), tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        sources = {}
                        for relative in ("coland/crates/server/Cargo.toml", "coauth/crates/backend/Cargo.toml"):
                            path = root / relative
                            path.parent.mkdir(parents=True, exist_ok=True)
                            is_owner = relative.startswith(owner + "/")
                            path.write_text('[package]\nname="fixture"\n' + (f'[{section}]\n{dependency}\n' if is_owner else ''), encoding="utf-8")
                            sources[relative] = "component-only"
                        self.assertTrue(any("must not load" in error for error in source_errors(root, sources)))

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

    def test_missing_obligation_is_detected_without_a_copied_scope_counter(self):
        document = copy.deepcopy(gate.read(gate.CONTRACTS))
        document["operations"].pop()
        with self.assertRaisesRegex(ValueError, "omits a current authority requirement"):
            gate.declarations(document)

    def test_changed_recursive_contract_requires_review(self):
        gate.declarations()
        import check_operation_closure_locks as closure
        import check_mock_operation_review as review
        rows = copy.deepcopy(gate.read(closure.OPERATION_LOCK)["closures"])
        identifier = review.read(review.REVIEW)["operations"][0]["operation_id"]
        next(row for row in rows if row["operation_id"] == identifier)["sha256"] = "sha256:" + "0" * 64
        with patch.object(closure, "operation_closures", return_value=rows):
            with self.assertRaisesRegex(ValueError, "reviewed operation contract changed"):
                gate.declarations()

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



class AppletInstallationProofGates(unittest.TestCase):
    """Component-only mutation tests. No process/crypto/native credit exists here."""
    @staticmethod
    def component():
        actor = {"kind":"account","account_id":{"principal_id":"component-human","station_id":"component-station"}}
        scope = {"kind":"realm","realm_id":"component-realm"}
        def original(kind, label, position, payload):
            return {"event":{"kind":kind,"realm_id":"component-realm","scope_ref":scope,"actor_id":actor,
                             "event_id":"component-event-"+label,"payload":payload},
                    "commit":{"commit_id":"component-commit-"+label,"event_ref":"component-event-"+label,
                              "stream_ref":scope,"stream_position":position}}
        reg = original("ak.applet.registration","registration",0,{})
        grant = original("ak.capability.grant","grant",1,{})
        revoke = original("ak.capability.revoke","revoke",2,{"grant_id":"component-grant","expected_commit_id":grant["commit"]["commit_id"]})
        package = {"applet_id":"component-applet","service_id":"component-service","registration_epoch":"component-epoch","package_digest":"component-package","requested_scopes":["ak.call.record"],
                   "webhook_signature_policy":{"key_ref":"component-service#key"}}
        grant["event"]["payload"]={"grant":{"issuer_id":actor,"subject":{"kind":"service","service_id":"component-service"},
            "actions":["ak.call.record"],"resources":[scope],"constraints":[{"constraint_kind":"authority_control","constraint_subkind":"applet_authority",
            "applet_id":"component-applet","executed_by":{"kind":"service","service_id":"component-service"},"registration_epoch":"component-epoch"}]}}
        basis = {"effective_scope":scope,"install_actor_id":actor,"target_station_id":"component-station",
                 "applet_id":"component-applet","service_id":"component-service","package_digest":"component-package",
                 "registration_event":reg["event"],"capability_grant_events":[grant["event"]]}
        request = {"applet_package":package,"authoring_request_basis":basis,"plan_digest":"component-plan"}
        install = {"install_id":"component-install","applet_id":"component-applet","service_id":"component-service",
                   "registration_event_ref":reg["event"]["event_id"],"registration_epoch":"component-epoch",
                   "capability_grant_refs":["component-grant"],"rejections":[]}
        def snap(status, committed):
            grant_status = "active" if status=="installed" else "revoked"
            return {"installations":[{"record":{"install_id":"component-install","status":status,"effective_scope":scope,"owner_actor_id":actor,
                        "target_station_id":"component-station","install_body_digest":"sha256:"+gate.canonical_digest(request)}}],
                    "sources":[{"install_id":"component-install","grant_id":"component-grant","registration_event_ref":reg["event"]["event_id"],
                                "realm_id":"component-realm","applet_id":"component-applet","service_id":"component-service"}],
                    "grants":[{"grant_id":"component-grant","status":grant_status,"current_commit_id":(grant if status=="installed" else revoke)["commit"]["commit_id"]}],
                    "committed":committed,"events":[x["event"] for x in committed],
                    "quota_counters":[],"quota_buckets":[],"quota_consumptions":[]}
        before = {"installations":[],"sources":[],"grants":[],"committed":[],"events":[],"quota_counters":[],"quota_buckets":[],"quota_consumptions":[]}
        installed = snap("installed",[reg,grant]); revoked = snap("revoked",[reg,grant,revoke])
        registration_ref = {"event_id":reg["event"]["event_id"],"commit_id":reg["commit"]["commit_id"],"stream_ref":scope,"stream_position":0}
        def material(active):
            return {"applet_id":"component-applet","service_id":"component-service","effective_scope":scope,"registration":reg,"grant_events":[grant],
                    "current_binding":({"status":"active","registration_ref":registration_ref,"registration_epoch":"component-epoch","service_id":"component-service"} if active else {"status":"inactive"})}
        plan = {"capability_revocations":[{"grant_id":"component-grant","expected_commit_id":grant["commit"]["commit_id"]}],"membership_removals":[],"widget_token_refs":[]}
        revoke_request = {"revoke_plan_digest":"sha256:"+gate.canonical_digest(plan),"capability_revoke_events":[{"event":revoke["event"]}],"membership_state_events":[]}
        outcome = {"status":"complete","revoke_plan_digest":revoke_request["revoke_plan_digest"],"revoked_refs":[{"event_id":revoke["event"]["event_id"],"commit_id":revoke["commit"]["commit_id"],"stream_ref":scope,"stream_position":2}]}
        evidence = {"realm_id":"component-realm","station_id":"component-station","actor_id":actor,"package":package,
                    "service_resolution":{"service_id":"component-service","service_kind":"applet_service","method_history_evidence":{"component_only":True}},
                    "install_request":request,"installed":install,"install_replay":install,"old_install_replay":install,"install_key":"component-install-key",
                    "registration":reg,"grant":grant,"revoke":revoke,
                    "snapshots":{"before":before,"after_preview":before,"installed":installed,"install_replay":installed,"revoke_preview":installed,"revoked":revoked,"after_replays":revoked},
                    "material_request":{"effective_scope":scope,"grant_ids":["component-grant"]},"active":material(True),"inactive":material(False),"still_inactive":material(False),
                    "revoke_preview_request":{"component":"preview"},"revoke_preview":{"revoke_plan":plan},"revoke_request":revoke_request,"revoke_key":"component-revoke-key",
                    "revoked":outcome,"revoke_replay":outcome,"invalid_material_signature":{"status":401,"problem":{"status":401,"type":"https://arkret.org/problems/http_signature_invalid"}}}
        exchanges = []
        def exchange(operation, body, response, status=200, headers=None):
            raw = json.dumps(body,sort_keys=True,separators=(",",":")).encode()
            h = dict(headers or {})
            if operation=="ak.self.applet.authority.read.material.v1":
                h.update({"source-service-id":"component-service","destination-service-id":"component-station",
                          "signature-input":'sig1=();keyid="component-service#key"',"signature":"component-only-not-crypto-proof",
                          "content-digest":"sha-256=:"+base64.b64encode(hashlib.sha256(raw).digest()).decode()+":"})
            exchanges.append({"operation_id":operation,"request_body":body,"response_body":response,"response_status":status,
                              "explicit_request_headers":h,"request_json_base64url":base64.urlsafe_b64encode(raw).decode().rstrip("=")})
        exchange("ak.self.applet.install.command.preview.v1",{"authoring_request_basis":basis},{"plan":{"plan_digest":"component-plan"}})
        for status in [201,200,200]:exchange("ak.self.applet.command.install.v1",request,install,status,{"idempotency-key":"component-install-key"})
        for name in ["active","inactive","still_inactive"]:exchange("ak.self.applet.authority.read.material.v1",evidence["material_request"],evidence[name])
        exchange("ak.self.applet.revoke.command.preview.v1",evidence["revoke_preview_request"],evidence["revoke_preview"])
        for _ in range(2):exchange("ak.self.applet.command.revoke.v1",revoke_request,outcome,headers={"idempotency-key":"component-revoke-key"})
        evidence["observations"]={"exchanges":exchanges}
        # Keep each snapshot/response independent so a single mutation cannot
        # accidentally repair the linked value it is meant to falsify.
        return json.loads(json.dumps(evidence))

    def test_applet_installation_component_bindings_and_all_five_real_exchange_requirements(self):
        evidence=self.component()
        gate.applet_installations(evidence)
        operations={x["operation_id"] for x in evidence["observations"]["exchanges"]}
        self.assertEqual(len(operations),5)
        for operation in operations:
            changed=copy.deepcopy(evidence)
            changed["observations"]["exchanges"]=[x for x in changed["observations"]["exchanges"] if x["operation_id"]!=operation]
            with self.subTest(operation=operation),self.assertRaises(ValueError):gate.applet_installations(changed)

    def test_applet_source_instance_original_current_and_replay_mutations_refuse(self):
        evidence=self.component()
        changes=[
            lambda x:x["snapshots"]["installed"]["sources"][0].update(install_id="other-instance"),
            lambda x:x["snapshots"]["revoked"]["grants"][0].update(status="active"),
            lambda x:x["snapshots"]["after_replays"]["events"].append({"unexpected":"queued"}),
            lambda x:x["inactive"]["current_binding"].update(status="active"),
            lambda x:x["grant"]["commit"].update(commit_id="other-original"),
            lambda x:x["revoke_request"]["capability_revoke_events"][0]["event"]["payload"].update(expected_commit_id="other-cid"),
            lambda x:x["revoked"].update(status="in_progress"),
            lambda x:x["snapshots"]["after_preview"]["events"].append({"unexpected":"preview-effect"}),
            lambda x:x["observations"]["exchanges"][1]["explicit_request_headers"].update({"idempotency-key":"new-key"}),
            lambda x:x["observations"]["exchanges"][4]["explicit_request_headers"].update({"source-service-id":"borrowed-station"}),
            lambda x:x["invalid_material_signature"].update(status=200),
        ]
        for mutate in changes:
            changed=copy.deepcopy(evidence); mutate(changed)
            with self.subTest(mutation=changes.index(mutate)),self.assertRaises(ValueError):gate.applet_installations(changed)


def push_gateway_component_fixture():
    # Structural oracle input only. No producer is launched and no component
    # value, fake signature or receipt here can earn native operation credit.
    source, other, destination, device = "component-A", "component-B", "component-G", "component-device"
    method, did = "did:key:component-gateway#receipt", "did:key:component-gateway"
    request = {"registration_id":"registration_component_0000000000","push_target_id":"component-target","device_id":device,
               "state":"active","push_key":"component-provider-token","app_id":"org.arkret.native-push","visible_notification_opt_in":False}
    def response(body):
        receipt = {key:body[key] for key in ("registration_id","push_target_id","device_id","state")}
        receipt.update(request_digest="sha256:"+gate.canonical_digest(body),source_station_id=source,destination_gateway_id=destination,
                       stored_at="2026-11-16T00:00:00.000Z",proof={"verification_method":method,"audience":source,
                       "created_at":"2026-11-16T00:00:00.000Z","jws":"component-only-not-native-signature"})
        return {"receipt":receipt}
    accepted = response(request)
    original = {"state":{"id":did,"assertionMethod":[method]}}
    gateway_process = {"origin":"https://127.0.0.1:1234","component":"not-a-native-process"}
    gateway = {"gateway_resolution":{"service_id":destination,"service_kind":"push_gateway",
               "method_history_evidence":{"log_entries":[copy.deepcopy(original)]},"normalized_did_document":{"did":did}},
               "gateway_history":{"did":did,"native_history":True,"entries":[copy.deepcopy(original)]},
               "onboarded_station_resolution":{"service_id":source},"process":gateway_process}
    initial = {"gateway_registrations":[],"push_devices":[],"push_registration_handoff_intents":[],
               "canonical_events":[{"component":"event-original"}],"realm_commits":[{"component":"commit-original"}],
               "pcr_device_authorization_current_states":[{"component":"actual-selector-placeholder"}]}
    installed = copy.deepcopy(initial)
    installed["gateway_registrations"] = [{"source_station_id":source,"registration_id":request["registration_id"],
        "push_target_id":request["push_target_id"],"device_id":device,"state":"active",
        "request_digest":accepted["receipt"]["request_digest"],"receipt_json":json.dumps(accepted["receipt"]),"route_ciphertext":"component-opaque-ciphertext"}]
    installed["push_registration_handoff_intents"] = [{"source_station_id":source,"registration_id":request["registration_id"],
        "request_digest":accepted["receipt"]["request_digest"],"receipt":copy.deepcopy(accepted["receipt"]),"status":"receipt_verified",
        "destination_gateway_id":destination,"canonical_request":"\\x"+json.dumps(request,sort_keys=True,separators=(",", ":")).encode().hex()}]
    installed["push_devices"] = [{"public_handoff":True,"device_id":device,"payload":{
        "registration_id":request["registration_id"],"push_target_id":request["push_target_id"]}}]
    notify = {"notification":{"push_target_id":request["push_target_id"],"wakeup_kind":"message","devices":[{"device_id":device}]}}
    notified = {"push_target_id":request["push_target_id"],"outcomes":[{"device_id":device,"gateway_status":"accepted"}]}
    provider_body = {"app_id":"org.arkret.native-push","push_target_id":request["push_target_id"],"wakeup_kind":"message"}
    encoded = lambda value:base64.b64encode(json.dumps(value,sort_keys=True,separators=(",", ":")).encode()).decode()
    provider = {"deployment":"explicit_operator_connect_proxy","declared_provider_url":"https://1.1.1.1/deliver/{push_key}",
                "connect_observations":[{"accepted":True,"request":"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n"}],
                "provider_received":[{"method":"POST","uri":"https://1.1.1.1/deliver/"+request["push_key"],
                                      "raw_body_base64":encoded(provider_body),"body":provider_body}]}
    gateway["provider"] = copy.deepcopy(provider)
    revoked = {field:request[field] for field in ("registration_id","push_target_id","device_id")} | {"state":"revoked"}
    revoked_response = response(revoked)
    terminal = copy.deepcopy(installed)
    terminal["gateway_registrations"][0].update(state="revoked",route_ciphertext=None,receipt_json=json.dumps(revoked_response["receipt"]))
    changed = copy.deepcopy(request)
    changed["push_key"] = "different-provider-token"
    problem = {"type":"https://arkret.org/problems/duplicate_conflict","status":409}
    denied = {"type":"https://arkret.org/problems/unauthenticated","status":401}
    rejected = {"push_target_id":request["push_target_id"],"outcomes":[{"device_id":device,"gateway_status":"rejected","reason_code":"push_target_unknown"}]}
    value = {"source_station":source,"other_station":other,"device":device,"gateway":gateway,
             "accepted_request":request,"accepted":accepted,"registered":{key:request[key] for key in ("registration_id","push_target_id")},
             "registration":{key:request[key] for key in ("device_id","push_key","app_id")},"initial":initial,"installed":installed,
             "after_replay":copy.deepcopy(installed),"after_changed":copy.deepcopy(installed),"after_notify":copy.deepcopy(installed),
             "replay":copy.deepcopy(accepted),"notify":notify,"notified":notified,"duplicate":copy.deepcopy(notified),"notify_key":"component-notify-key",
             "provider_after_notify":copy.deepcopy(provider),"provider_after_duplicate":copy.deepcopy(provider),
             "wrong_before":copy.deepcopy(installed),"wrong_after":copy.deepcopy(installed),
             "revoked":revoked,"revoked_response":revoked_response,"after_revoke":terminal,"after_revive":copy.deepcopy(terminal),
             "revoked_notify":rejected,"processes":[{"component":str(index)} for index in range(4)]+[gateway_process],
             "observations":{"issuer_bindings":[{"component":"A"},{"component":"B"}],"exchanges":[]}}
    def actual(name, operation, body, result, status=200, sender=source):
        path = "/_arkret/edge/push/registrations:apply" if operation.endswith("apply_registration.v1") else "/_arkret/edge/push/notify"
        url = gateway_process["origin"] + path
        headers = {"host":"127.0.0.1:1234","arkret-operation":operation,"source-service-id":sender,
                   "destination-service-id":destination,"signature":"component-signature","signature-input":"component-signature-input"}
        if operation.endswith("notify.v1"):
            headers["idempotency-key"] = value["notify_key"]
        ingress = {"public_target":url,"private_request_target":url,"request_headers":[[key,base64.b64encode(item.encode()).decode()] for key,item in headers.items()],
                   "request_body_base64":encoded(body),"response_body_base64":encoded(result),"response_status":status}
        value[name] = [{"ingress":ingress,"request":copy.deepcopy(body),"response":copy.deepcopy(result),"status":status}]
        if 200 <= status < 300:
            value["observations"]["exchanges"].append({"operation_id":operation,"request_body":copy.deepcopy(body),"response_body":copy.deepcopy(result),
                "url":url,"response_status":status,"explicit_request_headers":copy.deepcopy(headers)})
    apply, wakeup = "ak.edge.push.command.apply_registration.v1", "ak.edge.push.command.notify.v1"
    actual("apply",apply,request,accepted)
    actual("replay_exchange",apply,request,accepted)
    actual("changed_exchange",apply,changed,problem,409)
    actual("notify_exchange",wakeup,notify,notified)
    actual("duplicate_exchange",wakeup,notify,notified)
    actual("wrong_exchange",wakeup,notify,denied,401,other)
    actual("revoke_exchange",apply,revoked,revoked_response)
    actual("revive_exchange",apply,request,problem,409)
    actual("revoked_notify_exchange",wakeup,notify,rejected)
    return value


class NativePushGatewayProofGates(unittest.TestCase):
    def test_component_shape_is_accepted_without_any_native_execution_credit(self):
        gate.push_gateway(push_gateway_component_fixture())

    def test_http2_authority_is_the_original_public_uri_without_a_synthetic_host_header(self):
        value = push_gateway_component_fixture()
        # HTTP/2 carries authority in its pseudo-header/URI. Preserve that
        # actual representation instead of inventing a received Host header.
        for name in ("apply","replay_exchange","changed_exchange","notify_exchange","duplicate_exchange",
                     "wrong_exchange","revoke_exchange","revive_exchange","revoked_notify_exchange"):
            value[name][0]["ingress"]["request_headers"] = [[key,item] for key,item in value[name][0]["ingress"]["request_headers"] if key != "host"]
        for exchange in value["observations"]["exchanges"]:
            exchange["explicit_request_headers"].pop("host")
        gate.push_gateway(value)

    def test_ack_or_cache_cannot_replace_the_actual_authority_provider_or_immutable_receipt(self):
        def change_tenant(value):
            value["installed"]["gateway_registrations"][0]["source_station_id"] = "other-tenant"
        def remove_provider(value):
            value["provider_after_notify"]["provider_received"] = []
        def double_dispatch(value):
            value["provider_after_notify"]["provider_received"] *= 2
        def plaintext_route(value):
            value["installed"]["gateway_registrations"][0]["route_ciphertext"] = value["accepted_request"]["push_key"]
        def rewrite_receipt(value):
            receipt = json.loads(value["installed"]["gateway_registrations"][0]["receipt_json"])
            receipt["proof"]["jws"] = "changed-original-signature"
            value["installed"]["gateway_registrations"][0]["receipt_json"] = json.dumps(receipt)
        def change_canonical_request(value):
            value["installed"]["push_registration_handoff_intents"][0]["canonical_request"] = "\\x00"
        def lose_source_identity(value):
            value["registered"].pop("registration_id")
        def swap_private_target(value):
            value["apply"][0]["ingress"]["private_request_target"] = "http://127.0.0.1:1234/_arkret/edge/push/registrations:apply"
        def mutate_actual_bytes(value):
            value["apply"][0]["ingress"]["request_body_base64"] = base64.b64encode(b"{}").decode()
        def borrow_other_station(value):
            value["other_station"] = value["source_station"]
        def revive_terminal(value):
            value["after_revoke"]["gateway_registrations"][0]["route_ciphertext"] = "reanimated-route"
        def substitute_cache_key(value):
            value["notify_key"] = "another-key"
        def leak_private_body(value):
            value["provider_after_notify"]["provider_received"][0]["body"]["actor_id"] = "private-account"
        def lose_native_gateway(value):
            value["gateway"]["gateway_history"]["entries"] = []
        for mutate in (change_tenant, remove_provider, double_dispatch, plaintext_route, rewrite_receipt, change_canonical_request,
                       lose_source_identity, swap_private_target, mutate_actual_bytes, borrow_other_station, revive_terminal,
                       substitute_cache_key, leak_private_body, lose_native_gateway):
            value = push_gateway_component_fixture()
            mutate(value)
            with self.subTest(mutation=mutate.__name__), self.assertRaises((ValueError, KeyError, IndexError, TypeError)):
                gate.push_gateway(value)


if __name__ == "__main__":
    unittest.main()
