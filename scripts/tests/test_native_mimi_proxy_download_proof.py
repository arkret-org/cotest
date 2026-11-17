"""Structural mutation tests only; these component objects earn no native credit."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_mimi_proxy_download_proof as proof


def encoded(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def require(value, message):
    if not value:
        raise ValueError(message)


def component():
    station, realm, strand = "component-station", "component-realm", "component-strand"
    provider = "mimi://component.example"
    room = provider + "/rooms/" + strand
    content = b"component actual public bytes"
    bodies = [content, b"private", b"unlisted", b"orphan"]
    refs = ["ak:blob:sha256:" + hashlib.sha256(value).hexdigest() for value in bodies]
    times = ["2026-11-16T00:00:00Z", "2026-11-16T00:05:00Z"]
    request = {"asset_ref": refs[0], "requester_id": station, "strand_id": strand}
    binding = {"profile": "ak.profile.mimi_interop.v1", "mimi_room_uri": room,
               "binding_scope": {"realm_id": realm, "strand_id": strand},
               "status": "accepted", "hub_provider_id": station, "local_provider_role": "hub"}
    def original(label, kind, position, payload):
        return {"event": {"event_id": label, "realm_id": realm, "kind": kind, "payload": payload},
                "commit": {"event_ref": label, "commit_id": "commit-" + label, "realm_id": realm,
                           "governance_generation": "0", "stream_position": str(position)}}
    originals = {
        "genesis": original("genesis", "ak.realm.create", 0, {}),
        "allowed": original("allowed", "ak.realm.asset_privacy_policy", 1, {"value": {"download_mode": "direct", "direct_download_allowed": True}}),
        "message": original("message", "ak.message.create", 2, {"strand_id": strand, "track_name": "discussion", "content": {"body": "asset"}, "blob_refs": refs[:3]}),
        "binding": original("binding", "ak.mimi.room_binding", 3, binding),
        "tightened": original("tightened", "ak.realm.asset_privacy_policy", 4, {"value": {"download_mode": "provider_proxy", "direct_download_allowed": False}}),
        "restored": original("restored", "ak.realm.asset_privacy_policy", 5, {"value": {"download_mode": "direct", "direct_download_allowed": True}}),
        "revoked": original("revoked", "ak.mimi.room_binding", 6, dict(binding, status="revoked")),
    }
    def current(label):
        item = originals[label]
        return {"current_commit_id": item["commit"]["commit_id"], "current_event_id": label,
                "value": item["event"]["payload"].get("value", item["event"]["payload"])}
    blobs = [{"id": ref, "size_bytes": len(body), "realm_id": realm if i == 1 else None,
              "visibility": "realm_bound" if i == 1 else "public", "payload": {"encryption": None},
              "redacted": False, "legal_hold": False} for i, (ref, body) in enumerate(zip(refs, bodies))]
    before = {"blobs": blobs, "committed": [originals[name] for name in ("genesis", "allowed", "message", "binding")],
              "binding": [current("binding")], "policy": [current("allowed")], "download_audits": []}
    payload = {"scheme": "ak.blob.presign.v1", "blob_ref": refs[0], "issuer_id": station,
               "audience_hint": station, "issued_at": times[0], "expires_at": times[1], "purpose": "download",
               "nonce": encoded(b"1234567890123456"), "access_scope": {"method": ["GET", "HEAD"]}}
    envelope = {"payload": payload, "proof": {"kind": "detached_jws", "kid": station + "#notary-key", "jws": "component-signature"}}
    presign = encoded(envelope)
    url = "https://component.example/_arkret/self/blob/get?" + urlencode({"blob_ref": refs[0], "purpose": "download", "presign": presign})
    response = {"download_ref": url, "expires_at": times[1]}
    audit = {"id": "component-audit-row", "action": "mimi.public_asset_download",
             "actor_id": station, "outcome": "accepted"}
    after = copy.deepcopy(before)
    after["download_audits"] = [audit]
    final = copy.deepcopy(after)
    final.update(committed=list(originals.values()), binding=[current("revoked")], policy=[current("restored")])
    directory = {"service_id": station, "mimi": {"provider_id": provider, "features": ["consent", "proxy_download"],
                 "endpoints": [{"endpoint_id": "consent", "relative_path": "/consent"},
                               {"endpoint_id": "proxy_download", "relative_path": "/_arkret/open/mimi/proxy-download"}]}}
    empty = copy.deepcopy(directory)
    empty["mimi"].update(features=["consent"], endpoints=[directory["mimi"]["endpoints"][0]])
    exchange = {"operation_id": proof.OPERATION, "method": "POST", "url": "https://component.example/_arkret/open/mimi/proxy-download",
                "response_status": 200, "request_body": request, "request_json_base64url": encoded(request),
                "response_body": response, "decoded_response_bytes_base64url": encoded(response),
                "explicit_request_headers": {"arkret-operation": proof.OPERATION, "provider-id": provider,
                                             "source-service-id": station, "destination-service-id": station,
                                             "mimi-room-uri": room, "signature": "component", "signature-input": "component"}}
    failures = []
    for name, (status, code) in proof.REFUSALS.items():
        negative = copy.deepcopy(request)
        if name in ("unlisted", "private", "unreferenced"):
            negative["asset_ref"] = refs[{"unlisted": 2, "private": 1, "unreferenced": 3}[name]]
        if name == "requester": negative["requester_id"] = "different-component-station"
        if name == "range": negative["range"] = "bytes=0-3"
        if name == "ohttp": negative["ohttp_context"] = {"context_id": "component"}
        if name == "egress": negative["asset_ref"] = "file:///component-private"
        if name == "missing_room": negative.pop("strand_id")
        snapshot = copy.deepcopy(after)
        if name == "unapproved_room": snapshot["binding"] = []
        if name == "policy": snapshot["policy"] = [current("tightened")]
        if name == "revoked_room": snapshot["binding"] = [current("revoked")]
        failures.append({"name": name, "request": negative, "status": status, "body": {"type": "https://arkret.org/problems/" + code},
                         "before": snapshot, "after": copy.deepcopy(snapshot)})
    result = dict(originals, case="mimi_proxy_download", scope=[proof.OPERATION], station=station,
                  realm_id=realm, strand_id=strand, room=room, directory=directory, empty_directory=empty,
                  cold_directory=copy.deepcopy(empty), allowlist=[refs[0], refs[1], refs[3]],
                  content_base64url=encoded(content), content_digest="sha256:" + hashlib.sha256(content).hexdigest(),
                  request=request, response=response, observations={"exchanges": [exchange]}, before=before, after=after,
                  final_originals=final, cold_originals=copy.deepcopy(final), refusals=failures,
                  withdrawn_get_at="2026-11-16T00:01:00Z", withdrawn_get_status=404,
                  withdrawn_get_body={"type": "https://arkret.org/problems/not_found"},
                  download={"url": url, "envelope": envelope, "get_status": 200, "repeated_status": 200, "head_status": 200,
                            "fetched_base64url": encoded(content), "repeated_base64url": encoded(content), "head_length": len(content),
                            "anonymous_request_headers": {}})
    for name, ref, body in zip(("upload", "private_upload", "unlisted_upload", "orphan_upload"), refs, bodies):
        result[name] = {"blob_ref": ref, "size_bytes": len(body), "upload_receipt": {"blob_ref": ref, "size_bytes": len(body),
                         "issuer_id": station, "signature": {"signature": "component"}}}
    return result


class ProxyProofTests(unittest.TestCase):
    def run_check(self, value):
        proof.check(value, require=require, digest=lambda obj: hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest(),
                    decode=lambda value: json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))))

    def test_component_links(self):
        self.run_check(component())

    def test_independent_mutations_refuse(self):
        def replace_object(e): e["download"]["fetched_base64url"] = encoded(b"other object")
        def external_url(e): e["response"]["download_ref"] = "https://object-store.example/private"
        def absent_advertisement(e): e["directory"]["mimi"]["features"].remove("proxy_download")
        def wrong_provider(e): e["observations"]["exchanges"][0]["explicit_request_headers"]["source-service-id"] = "other"
        def private_public(e): e["before"]["blobs"][0]["visibility"] = "realm_bound"
        def implicit_allowlist(e): e["allowlist"].append(e["unlisted_upload"]["blob_ref"])
        def missing_reference(e): e["message"]["event"]["payload"]["blob_refs"].pop()
        def invented_current(e): e["before"]["policy"][0]["current_commit_id"] = "uncovered"
        def quota_alias(e): e["request"]["requester_id"] = "another full source"
        def weak_busy(e): e["refusals"][0]["status"] = 200
        def hidden_effect(e): e["refusals"][0]["after"]["download_audits"].append({"late": True})
        def dropped_negative(e): e["refusals"].pop()
        def lost_original(e): e["final_originals"]["committed"].pop()
        def cold_rewrite(e): e["cold_originals"]["blobs"].pop()
        def credential(e): e["download"]["anonymous_request_headers"]["Authorization"] = "private"
        def expired_instead_of_revoked(e): e["withdrawn_get_at"] = "2026-11-16T00:06:00Z"
        for mutation in (replace_object, external_url, absent_advertisement, wrong_provider, private_public,
                         implicit_allowlist, missing_reference, invented_current, quota_alias, weak_busy,
                         hidden_effect, dropped_negative, lost_original, cold_rewrite, credential, expired_instead_of_revoked):
            with self.subTest(mutation=mutation.__name__):
                value = component()
                mutation(value)
                with self.assertRaises((ValueError, KeyError, IndexError, TypeError)):
                    self.run_check(value)


if __name__ == "__main__":
    unittest.main()
