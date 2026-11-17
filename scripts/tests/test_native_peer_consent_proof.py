"""Structural mutations only. Component data supplies no native/crypto credit."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_peer_consent_proof as proof


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")


def decode(value):
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def require(value, message):
    if not value:
        raise ValueError(message)


def component():
    h, g = "H", "G"
    def process(pid, label):
        return {"pid": pid, "origin": "https://" + label + ".example", "executable": "D:/component/coland", "sha256": "sha256:component"}
    processes = [process(1, "haa"), process(2, "h"), process(3, "gaa"), process(4, "g")]
    e = {"case": "peer_consent", "scope": proof.OPERATIONS[:], "hosting_service": h, "governor_service": g,
         "hosting_resolution": {"service_id": h}, "governor_resolution": {"service_id": g},
         "processes": processes, "cold_processes": [process(5, "h"), process(6, "g")],
         "organizations": [], "observations": {"exchanges": []}}
    actor = {"kind": "account", "account_id": {"principal_id": "requester", "station_id": h}}
    def cli(operation, report):
        return {"report": report, "cli": {"operation": operation, "exit_code": 0, "pid": 9,
                "sha256": processes[1]["sha256"], "executable": processes[1]["executable"]}}
    def exchange(op, request, response):
        source, destination = (g, h) if op == proof.OPERATIONS[2] else (h, g)
        path = dict(zip(proof.OPERATIONS, ("current", "proxy", "effects")))[op]
        e["observations"]["exchanges"].append({"operation_id": op, "method": "POST",
            "url": "https://" + destination.lower() + ".example/_arkret/peer/consent/" + path,
            "response_status": 200, "explicit_request_headers": {"source-service-id": source,
                "destination-service-id": destination, "arkret-operation": op,
                "signature": "component", "signature-input": "component", "content-digest": "component"},
            "request_body": request, "request_json_base64url": encoded(request),
            "response_body": response, "decoded_response_bytes_base64url": encoded(response)})
    for producer in ("service", "device"):
        holder = {"principal_id": producer, "station_id": h}
        realm = "realm-" + producer
        event = {"event_id": "event-" + producer, "realm_id": realm,
                 "actor_id": {"kind": "account", "account_id": holder}, "producer_proof": {"jws": "component"}}
        commit = {"event_ref": event["event_id"], "stream_position": "0", "governance_generation": "0"}
        original = {"event": event, "approval_signatures": [{"signed": "finite-original"}]}
        fact = {"event_id": event["event_id"], "method_history_evidence": {"kind": "webvh_log"},
                "approval_signatures": original["approval_signatures"]}
        fact["producer_resolution" if producer == "service" else "public_key_base64url"] = {"service_id": g} if producer == "service" else "component"
        bundle = {"realm_id": realm, "genesis_event": event, "genesis_commit": commit, "producer_signer_fact": fact,
                  "current_service_id": g, "current_generation": "0", "authority_transitions": [],
                  "realm_stream_head": {"commit_id": "commit-" + producer, "stream_position": "0"}}
        report = {"holder_account_id": holder, "realm_id": realm, "outcome": {"status": "committed", "commit": commit}}
        request = {"holder_account_id": holder, "consent_scope": "voice_call"}
        accepted = {"accepted_for_processing": True}
        state = {key: [] for key in proof.IMMUTABLE}
        state.update({"accounts": [{"principal_id": producer}], "events": [event], "commits": [commit],
                      "quarantine": [], "jobs": [], "effect_fences": [], "effect_cuts": []})
        before = {"h": copy.deepcopy(state), "g": copy.deepcopy(state)}
        before["h"]["h_original"] = [{"original": original}]
        before["h"]["facts"] = [fact]
        before["g"]["g_sources"] = [{"source_service_id": h}]
        before["g"]["g_approval_audit"] = [{"nonce": "finite"}]
        settled = copy.deepcopy(before)
        cell = {"payload": {"quarantine_entries": [{"account_id": holder, "source_peer_actor_id": actor, "surface_kind": "consent_request", "consent_scope": "voice_call"}]}, "revision": 1}
        for role in ("h", "g"):
            settled[role]["quarantine"] = [cell]
        settled["h"]["effect_fences"] = [{"nonce": "publication"}]
        settled["h"]["effect_cuts"] = [{"realm_id": realm}]
        case = {"producer": producer, "bundle": bundle, "original_submission": original,
                "admission_cli": cli("accept-hosting", report), "admission_retry_cli": cli("accept-hosting", report),
                "self_request": request, "accepted": accepted, "repeated": accepted, "requester": actor,
                "before": before, "settled": settled, "replayed": copy.deepcopy(settled),
                "after": copy.deepcopy(settled), "cold": copy.deepcopy(settled), "currents": []}
        for i in range(3):
            current = {"holder_account_id": holder, "peer": {"kind": "actor", "actor_id": actor},
                       "audience_actor_id": {"kind": "service", "service_id": h}, "nonce": producer + str(i)}
            response = {"realm_id": realm, "governance_generation": "0", "current": {"state": "never_written"},
                        "proof": {"jws": "component"}, "request_digest": "sha256:" + digest(current),
                        "effective_stream_head": bundle["realm_stream_head"]}
            case["currents"].append({"request": current, "response": response, "cli": cli("inspect-consent", response)})
            exchange(proof.OPERATIONS[0], current, response)
        for i in range(2):
            proxy = {"holder_account_id": holder, "realm_id": realm, "nonce": str(i),
                     "command": {"kind": "request", "body": {"requester_actor_id": actor, "request": request}},
                     "context": {"kind": "station", "actor_id": {"kind": "service", "service_id": h}}}
            response = {"realm_id": realm, "request_digest": "sha256:" + digest(proxy),
                        "effective_stream_head": bundle["realm_stream_head"],
                        "response_body": {"kind": "request", "body": accepted}}
            exchange(proof.OPERATIONS[1], proxy, response)
        publication = {"holder_account_id": holder, "realm_id": realm,
                       "effective_stream_head": bundle["realm_stream_head"],
                       "effects": {"holder_quarantine": {"content": cell["payload"], "revision": "1"}}}
        exchange(proof.OPERATIONS[2], publication, {"request_digest": "sha256:" + digest(publication), "status": "applied"})
        e["organizations"].append(case)
    return e


class PeerConsentStructuralProof(unittest.TestCase):
    def check(self, value):
        proof.check(value, require=require, decode=decode, digest=digest)

    def test_structural_component(self):
        self.check(component())

    def test_mutations_reject_false_provenance(self):
        def missing_current(e):
            e["observations"]["exchanges"] = [x for x in e["observations"]["exchanges"] if x["operation_id"] != proof.OPERATIONS[0]]
        def missing_effect(e):
            e["observations"]["exchanges"] = [x for x in e["observations"]["exchanges"] if x["operation_id"] != proof.OPERATIONS[2]]
        mutations = {
            "same_H_G": lambda e: e.update(governor_service=e["hosting_service"]),
            "missing_device_branch": lambda e: e["organizations"].pop(),
            "missing_current": missing_current,
            "missing_worker": missing_effect,
            "wrong_source": lambda e: e["observations"]["exchanges"][0]["explicit_request_headers"].update({"source-service-id": "other"}),
            "wrong_destination": lambda e: e["observations"]["exchanges"][0]["explicit_request_headers"].update({"destination-service-id": "other"}),
            "wrong_https_origin": lambda e: e["observations"]["exchanges"][0].update(url="https://other.example/_arkret/peer/consent/current"),
            "raw_request": lambda e: e["observations"]["exchanges"][0].update(request_json_base64url=encoded({})),
            "raw_response": lambda e: e["observations"]["exchanges"][0].update(decoded_response_bytes_base64url=encoded({})),
            "wrong_cli_product": lambda e: e["organizations"][0]["admission_cli"]["cli"].update(sha256="different"),
            "wrong_G_original": lambda e: e["organizations"][0]["admission_retry_cli"].update(report={}),
            "wrong_proof": lambda e: e["organizations"][0]["original_submission"].update(event={"producer_proof": "other"}),
            "missing_public_fact": lambda e: e["organizations"][0]["bundle"].pop("producer_signer_fact"),
            "wrong_finite_votes": lambda e: e["organizations"][0]["bundle"]["producer_signer_fact"].update(approval_signatures=[]),
            "H_private_audit_fallback": lambda e: e["organizations"][0]["before"]["h"].update(g_sources=[{"copied": True}]),
            "no_G_private_source": lambda e: e["organizations"][0]["before"]["g"].update(g_sources=[]),
            "canonical_write": lambda e: e["organizations"][0]["after"]["g"].update(commits=[{"new": True}]),
            "consent_invention": lambda e: e["organizations"][0]["after"]["g"].update(consents=[{"granted": True}]),
            "unacked_job": lambda e: e["organizations"][0]["settled"]["g"].update(jobs=[{"pending": True}]),
            "changed_live_revision": lambda e: e["organizations"][0]["cold"]["h"]["quarantine"][0].update(revision=2),
            "missing_exact_current": lambda e: e["organizations"][0]["currents"][0]["response"].update(request_digest="other"),
            "duplicate_nonce": lambda e: e["organizations"][0]["currents"][1].update(request=copy.deepcopy(e["organizations"][0]["currents"][0]["request"])),
            "wrong_live_scope": lambda e: e["organizations"][0]["settled"]["h"]["quarantine"][0]["payload"]["quarantine_entries"][0].update(consent_scope="text"),
            "no_cold_restart": lambda e: e["cold_processes"][0].update(pid=e["processes"][1]["pid"]),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = component()
                mutate(value)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    self.check(value)


if __name__ == "__main__":
    unittest.main()
