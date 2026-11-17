"""Link actual MIMI exchanges, public objects and current authority originals.

Cryptographic verification belongs to the source-fenced Rust driver and SDK.
This structural checker supplies no native credit without owning execution.
"""
import base64
import hashlib
import json
from datetime import datetime
from urllib.parse import parse_qsl, urlsplit

OPERATION = "ak.open.mimi.command.proxy_download.v1"
REFUSALS = {
    "empty_configuration": (501, "unsupported_feature"),
    "unapproved_room": (404, "not_found"),
    "unsigned_session": (401, "http_signature_required"),
    "unlisted": (501, "unsupported_feature"),
    "private": (404, "not_found"),
    "unreferenced": (404, "not_found"),
    "requester": (403, "capability_denied"),
    "range": (501, "unsupported_feature"),
    "ohttp": (501, "unsupported_feature"),
    "egress": (403, "capability_denied"),
    "missing_room": (501, "unsupported_feature"),
    "policy": (404, "not_found"),
    "revoked_room": (404, "not_found"),
    "withdrawn_configuration": (501, "unsupported_feature"),
}


def check(e, *, require, digest, decode):
    def raw(value):
        require(isinstance(value, str) and "=" not in value, "asset bytes are not canonical base64url")
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        require(base64.urlsafe_b64encode(result).decode().rstrip("=") == value,
                "asset bytes use a noncanonical base64url spelling")
        return result

    def instant(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    require(e["case"] == "mimi_proxy_download" and e["scope"] == [OPERATION],
            "proxy evidence changed its exact operation scope")
    station, realm, strand, room = (e[name] for name in ("station", "realm_id", "strand_id", "room"))
    directory = e["directory"]
    provider = directory["mimi"]["provider_id"]
    require(directory["service_id"] == station and room == provider + "/rooms/" + strand,
            "actual provider or Room identity changed")
    rows = [row for row in directory["mimi"]["endpoints"] if row["endpoint_id"] == "proxy_download"]
    require(len(rows) == 1 and directory["mimi"]["features"].count("proxy_download") == 1,
            "proxy was used without one signed advertised capability and endpoint")
    for name in ("empty_directory", "cold_directory"):
        empty = e[name]
        require(empty["service_id"] == station and empty["mimi"]["provider_id"] == provider and
                "proxy_download" not in empty["mimi"]["features"] and
                not any(row["endpoint_id"] == "proxy_download" for row in empty["mimi"]["endpoints"]),
                "empty deployment advertised an unavailable asset capability")
        require([row for row in directory["mimi"]["endpoints"] if row["endpoint_id"] != "proxy_download"] == empty["mimi"]["endpoints"] and
                [value for value in directory["mimi"]["features"] if value != "proxy_download"] == empty["mimi"]["features"],
                "asset configuration changed unrelated provider capabilities")
    exchanges = [row for row in e["observations"]["exchanges"] if row["operation_id"] == OPERATION]
    require(len(exchanges) == 1, "proxy requires one actual successful provider exchange")
    exchange = exchanges[0]
    headers = exchange["explicit_request_headers"]
    require(exchange["response_status"] == 200 and exchange["method"] == "POST" and
            exchange["request_body"] == e["request"] == decode(exchange["request_json_base64url"]) and
            exchange["response_body"] == e["response"] == decode(exchange["decoded_response_bytes_base64url"]) and
            urlsplit(exchange["url"]).path == rows[0]["relative_path"] and
            headers["arkret-operation"] == OPERATION and headers["provider-id"] == provider and
            headers["source-service-id"] == headers["destination-service-id"] == station and
            headers["mimi-room-uri"] == room and bool(headers["signature"]) and bool(headers["signature-input"]),
            "proxy substituted an unsigned source, unadvertised route or invented response")
    require(e["request"] == {"asset_ref": e["upload"]["blob_ref"], "requester_id": station, "strand_id": strand},
            "proxy request did not bind the exact public asset and Room")
    content = raw(e["content_base64url"])
    reference = "ak:blob:sha256:" + hashlib.sha256(content).hexdigest()
    require(e["upload"]["blob_ref"] == reference and e["content_digest"] == "sha256:" + hashlib.sha256(content).hexdigest(),
            "uploaded public reference is not the real returned content address")
    refs = [e[name]["blob_ref"] for name in ("upload", "private_upload", "unlisted_upload", "orphan_upload")]
    require(len(set(refs)) == 4 and e["allowlist"] == [refs[0], refs[1], refs[3]] and refs[2] not in e["allowlist"],
            "exact public deployment list was replaced by an implicit realm-less permission")
    before, after = e["before"], e["after"]
    for key in ("blobs", "committed", "binding", "policy"):
        require(before[key] == after[key], "download issuance changed its " + key + " originals")
    blobs = {row["id"]: row for row in before["blobs"]}
    require(set(blobs) == set(refs), "native asset originals are missing or unscoped")
    for name, ref in zip(("upload", "private_upload", "unlisted_upload", "orphan_upload"), refs):
        upload, blob = e[name], blobs[ref]
        receipt = upload["upload_receipt"]
        require(receipt["blob_ref"] == ref and receipt["issuer_id"] == station and
                receipt["size_bytes"] == upload["size_bytes"] == blob["size_bytes"] and
                bool(receipt["signature"]["signature"]), "asset receipt does not cover its actual durable object")
        require(blob["payload"]["encryption"] is None and not blob["redacted"] and not blob["legal_hold"],
                "proxy fixture silently relabeled encrypted or withheld material")
        if name == "private_upload":
            require(blob["realm_id"] == realm and blob["visibility"] == "realm_bound",
                    "private negative is not a real Realm-bound object")
        else:
            require(blob["realm_id"] is None and blob["visibility"] == "public",
                    "public asset was inferred from absent metadata alone")
    require(blobs[reference]["size_bytes"] == len(content), "public object length changed")
    originals = {item["event"]["event_id"]: item for item in e["final_originals"]["committed"]}
    for name in ("genesis", "binding", "message", "allowed", "tightened", "restored", "revoked"):
        item = e[name]
        require(originals.get(item["event"]["event_id"]) == item and
                item["commit"]["event_ref"] == item["event"]["event_id"] and
                item["event"]["realm_id"] == item["commit"]["realm_id"] == realm and
                item["commit"]["governance_generation"] in (0, "0"),
                "asset authority state lacks the real accepted original: " + name)
    require(not any(item["event"]["kind"] in {"ak.mls.genesis", "ak.mls.commit"} for item in originals.values()),
            "plaintext public fixture bypassed an already activated MLS scope")
    binding = e["binding"]["event"]["payload"]
    require(binding["mimi_room_uri"] == room and binding["binding_scope"] == {"realm_id": realm, "strand_id": strand} and
            binding["status"] == "accepted" and binding["local_provider_role"] == "hub" and
            binding["hub_provider_id"] == station and "mls_group_id" not in binding,
            "native Room was not explicitly accepted for its real provider and content scope")
    def current(snapshot, field, original):
        cells = snapshot[field]
        require(len(cells) == 1 and cells[0]["current_commit_id"] == original["commit"]["commit_id"] and
                cells[0]["value"] == original["event"]["payload"].get("value", original["event"]["payload"]),
                "asset current no longer covers its real accepted original: " + field)
        if field == "binding":
            require(cells[0]["current_event_id"] == original["event"]["event_id"], "Room current source Event changed")
    current(before, "binding", e["binding"])
    current(before, "policy", e["allowed"])
    message = e["message"]["event"]["payload"]
    require(message["strand_id"] == strand and message["track_name"] == "discussion" and
            message["blob_refs"] == refs[:3] and "encrypted_content" not in message,
            "proxy object is not referenced by the actual accepted discussion message")
    require(e["allowed"]["event"]["payload"]["value"]["download_mode"] == "direct" and
            e["allowed"]["event"]["payload"]["value"]["direct_download_allowed"] is True and
            e["tightened"]["event"]["payload"]["value"]["download_mode"] == "provider_proxy" and
            e["tightened"]["event"]["payload"]["value"]["direct_download_allowed"] is False and
            e["restored"]["event"]["payload"]["value"]["download_mode"] == "direct" and
            e["restored"]["event"]["payload"]["value"]["direct_download_allowed"] is True and
            int(e["allowed"]["commit"]["stream_position"]) < int(e["tightened"]["commit"]["stream_position"]) < int(e["restored"]["commit"]["stream_position"]),
            "current asset policy was not changed through its accepted native owner")
    revoked = e["revoked"]["event"]["payload"]
    require(dict(binding, status="revoked") == revoked and
            int(e["revoked"]["commit"]["stream_position"]) > int(e["binding"]["commit"]["stream_position"]),
            "Room revocation did not preserve its exact accepted subject")
    download, response = e["download"], e["response"]
    require(response["download_ref"] == download["url"] and not response.get("download_request_headers", {}),
            "asset download borrowed a user/provider private credential")
    url, ingress = urlsplit(download["url"]), urlsplit(exchange["url"])
    require(url.scheme == ingress.scheme == "https" and url.netloc == ingress.netloc and
            url.path.endswith("/_arkret/self/blob/get") and not url.username and not url.password and not url.fragment,
            "proxy returned an external object-store target or insecure download")
    pairs = parse_qsl(url.query, strict_parsing=True)
    query = dict(pairs)
    require(len(query) == len(pairs) == 3 and query["blob_ref"] == reference and query["purpose"] == "download",
            "public bearer URL changed its object or read purpose")
    envelope = download["envelope"]
    require(json.loads(raw(query["presign"])) == envelope, "proxy replaced the actual URL envelope")
    payload = envelope["payload"]
    require(payload["blob_ref"] == reference and payload["issuer_id"] == payload["audience_hint"] == station and
            "realm_id" not in payload and payload["scheme"] == "ak.blob.presign.v1" and payload["purpose"] == "download" and
            payload["access_scope"] == {"method": ["GET", "HEAD"]} and len(raw(payload["nonce"])) >= 16 and
            envelope["proof"]["kind"] == "detached_jws" and envelope["proof"]["kid"] == station + "#notary-key" and
            bool(envelope["proof"]["jws"]) and response["expires_at"] == payload["expires_at"] and
            (instant(payload["expires_at"]) - instant(payload["issued_at"])).total_seconds() == 300,
            "public presign widened its read permission, source, object or finite window")
    require(download["get_status"] == download["repeated_status"] == download["head_status"] == 200 and
            raw(download["fetched_base64url"]) == raw(download["repeated_base64url"]) == content and
            download["head_length"] == len(content), "actual anonymous GET/HEAD did not serve the accepted bytes")
    audits = after["download_audits"]
    require(len(audits) == len(before["download_audits"]) + 1 and audits[:-1] == before["download_audits"],
            "download lacks exactly one actual outer diagnostic row")
    require(set(audits[-1]) == {"id", "action", "actor_id", "outcome"} and
            isinstance(audits[-1]["id"], str) and bool(audits[-1]["id"]) and
            audits[-1]["action"] == "mimi.public_asset_download" and
            audits[-1]["actor_id"] == station and audits[-1]["outcome"] == "accepted",
            "outer diagnostic has the wrong source or revived an erasable business body")
    failures = {item["name"]: item for item in e["refusals"]}
    require(len(failures) == len(e["refusals"]) == len(REFUSALS) and set(failures) == set(REFUSALS),
            "required independent proxy refusals are missing or replaced")
    for name, (status, code) in REFUSALS.items():
        failure = failures[name]
        require(failure["status"] == status and failure["body"]["type"] == "https://arkret.org/problems/" + code and
                "download_ref" not in failure["body"] and failure["before"] == failure["after"],
                "proxy refusal changed typed classification or had effects: " + name)
    for name in ("empty_configuration", "unapproved_room", "unsigned_session", "policy", "revoked_room", "withdrawn_configuration"):
        require(failures[name]["request"] == e["request"], "refusal changed the actual business request: " + name)
    for name, ref in (("unlisted", refs[2]), ("private", refs[1]), ("unreferenced", refs[3])):
        require(failures[name]["request"] == dict(e["request"], asset_ref=ref), "asset negative does not isolate its real object")
    require(not failures["unapproved_room"]["before"]["binding"] and
            failures["unapproved_room"]["before"]["committed"] and failures["unapproved_room"]["before"]["blobs"],
            "unapproved Room refusal was replaced by a missing object shortcut")
    require(failures["requester"]["request"]["requester_id"] != station and
            {key: value for key, value in failures["requester"]["request"].items() if key != "requester_id"} ==
            {key: value for key, value in e["request"].items() if key != "requester_id"} and
            failures["range"]["request"] == dict(e["request"], range="bytes=0-3") and
            failures["ohttp"]["request"]["ohttp_context"] and failures["egress"]["request"]["asset_ref"].startswith("file:") and
            "strand_id" not in failures["missing_room"]["request"], "provider/mode/egress negatives lost their original input boundary")
    current(failures["policy"]["before"], "policy", e["tightened"])
    current(failures["revoked_room"]["before"], "binding", e["revoked"])
    current(e["final_originals"], "policy", e["restored"])
    current(e["final_originals"], "binding", e["revoked"])
    require(not any(key.lower() in {"authorization", "cookie"} for key in download["anonymous_request_headers"]),
            "actual public GET used a private credential")
    require(e["cold_originals"] == e["final_originals"] and e["withdrawn_get_status"] == 404 and
            e["withdrawn_get_body"]["type"] == "https://arkret.org/problems/not_found" and
            instant(e["withdrawn_get_at"]) < instant(payload["expires_at"]),
            "configuration withdrawal rewrote originals or was confused with presign expiration")
