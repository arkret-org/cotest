"""Bind real H operator originals to the three actual peer operations.

Cryptographic and native-execution credit remains with the source-fenced Rust
driver, the original process supply and the strict execution ledger.
"""
from urllib.parse import urlsplit

OPERATIONS = ["ak.peer.consent.read.current.v1", "ak.peer.consent.command.proxy.v1",
              "ak.peer.consent.command.publish_effects.v1"]
IMMUTABLE = ["accounts", "events", "commits", "authority", "typed_resolution",
             "g_sources", "g_approval_audit", "h_original", "facts", "consents"]


def check(e, *, require, decode, digest):
    require(e["case"] == "peer_consent" and e["scope"] == OPERATIONS,
            "peer Consent evidence changed its exact scope")
    h, g = e["hosting_service"], e["governor_service"]
    require(h != g and e["hosting_resolution"]["service_id"] == h and
            e["governor_resolution"]["service_id"] == g,
            "peer Consent requires independently authenticated H and G")
    processes = e["processes"]
    require(len(processes) == 4 and len(e["cold_processes"]) == 2 and
            len({p["pid"] for p in processes}) == 4,
            "two real AA/Station deployments are absent")
    for before, after in zip((processes[1], processes[3]), e["cold_processes"]):
        require(before["pid"] != after["pid"] and
                all(before[k] == after[k] for k in ("origin", "executable", "sha256")),
                "cold check did not restart the same owned Station product")
    origins = {h: urlsplit(processes[1]["origin"]), g: urlsplit(processes[3]["origin"])}
    exchanges = [x for x in e["observations"]["exchanges"] if x["operation_id"] in OPERATIONS]
    require(set(x["operation_id"] for x in exchanges) == set(OPERATIONS),
            "a required actual peer operation was not observed")
    for x in exchanges:
        source, destination = (g, h) if x["operation_id"] == OPERATIONS[2] else (h, g)
        headers, target = x["explicit_request_headers"], urlsplit(x["url"])
        path = dict(zip(OPERATIONS, ("current", "proxy", "effects")))[x["operation_id"]]
        require(x["method"] == "POST" and x["response_status"] == 200 and
                headers["source-service-id"] == source and headers["destination-service-id"] == destination and
                headers["arkret-operation"] == x["operation_id"] and
                target.scheme == "https" and target.netloc == origins[destination].netloc and
                target.path == "/_arkret/peer/consent/" + path and not target.query and not target.fragment and
                all(headers.get(k) for k in ("signature", "signature-input", "content-digest")) and
                decode(x["request_json_base64url"]) == x["request_body"] and
                decode(x["decoded_response_bytes_base64url"]) == x["response_body"],
                "peer exchange changed real transport, exact raw bytes or successful outcome")
    cases = e["organizations"]
    require(len(cases) == 2 and [c["producer"] for c in cases] == ["service", "device"],
            "both legal Org producer branches must use the real H CLI")
    require(cases[0]["bundle"]["realm_id"] != cases[1]["bundle"]["realm_id"],
            "the two original Org inceptions were conflated")
    for c in cases:
        original, bundle = c["original_submission"], c["bundle"]
        event, commit = bundle["genesis_event"], bundle["genesis_commit"]
        holder, realm = c["self_request"]["holder_account_id"], bundle["realm_id"]
        require(holder["station_id"] == h and event == original["event"] and
                event["actor_id"] == {"kind": "account", "account_id": holder} and
                event["realm_id"] == realm and commit["event_ref"] == event["event_id"] and
                int(commit["stream_position"]) == int(commit["governance_generation"]) == 0 and
                bundle["current_service_id"] == g and int(bundle["current_generation"]) == 0 and
                bundle["authority_transitions"] == [] and original["approval_signatures"],
                "an arbitrary public bundle substituted for the H accepted exact Org source")
        fact = bundle["producer_signer_fact"]
        require(fact["event_id"] == event["event_id"] and
                fact["approval_signatures"] == original["approval_signatures"] and
                bool(fact["method_history_evidence"]) and
                ((c["producer"] == "service" and "producer_resolution" in fact and
                  "public_key_base64url" not in fact) or
                 (c["producer"] == "device" and "public_key_base64url" in fact and
                  "producer_resolution" not in fact)),
                "public Org Genesis source changed the exact approval vector or producer branch")
        for name in ("admission_cli", "admission_retry_cli"):
            command = c[name]
            require(command["cli"]["operation"] == "accept-hosting" and command["cli"]["exit_code"] == 0 and
                    command["cli"]["pid"] > 0 and command["cli"]["sha256"] == processes[1]["sha256"] and
                    command["cli"]["executable"] == processes[1]["executable"] and
                    command["report"]["holder_account_id"] == holder and
                    command["report"]["realm_id"] == realm and
                    command["report"]["outcome"] == {"status": "committed", "commit": commit},
                    "real H CLI did not retain the original G Committed result")
        require(c["admission_cli"]["report"] == c["admission_retry_cli"]["report"],
                "exact local hosting replay changed its first original")
        require(c["accepted"] == c["repeated"] == {"accepted_for_processing": True},
                "self Consent request changed its fixed anti-enumeration response")
        before = c["before"]
        require(len(before["h"]["h_original"]) == len(before["h"]["facts"]) == 1 and
                before["h"]["g_sources"] == [] and len(before["g"]["g_sources"]) == 1 and
                before["g"]["g_approval_audit"],
                "H public provenance was confused with G private approval ownership")
        for phase in ("settled", "replayed", "after", "cold"):
            for role in ("h", "g"):
                state = c[phase][role]
                require(all(state[k] == before[role][k] for k in IMMUTABLE) and state["consents"] == [],
                        "private current/request changed canonical authority or invented Consent")
                require(len(state["quarantine"]) == 1 and
                        state["quarantine"] == c["settled"][role]["quarantine"],
                        "exact replay or cold restart changed the live quarantine current")
        current_cell = c["settled"]["h"]["quarantine"][0]
        require(current_cell["payload"] == c["settled"]["g"]["quarantine"][0]["payload"] and
                current_cell["revision"] == c["settled"]["g"]["quarantine"][0]["revision"] and
                c["settled"]["g"]["jobs"] == [] and c["settled"]["h"]["effect_fences"] and
                len(c["settled"]["h"]["effect_cuts"]) == 1,
                "real G worker publication and durable H acknowledgement did not settle")
        entries = current_cell["payload"]["quarantine_entries"]
        require(len(entries) == 1 and entries[0]["account_id"] == holder and
                entries[0]["source_peer_actor_id"] == c["requester"] and
                entries[0]["surface_kind"] == "consent_request" and
                entries[0]["consent_scope"] == c["self_request"]["consent_scope"],
                "the current private cell does not contain the exact live requester/scope")
        currents = c["currents"]
        require(len(currents) == 3 and len({p["request"]["nonce"] for p in currents}) == 3,
                "current before/request/cold cuts need independent exact nonces")
        for cut in currents:
            request, response, command = cut["request"], cut["response"], cut["cli"]
            require(request["holder_account_id"] == holder and
                    request["peer"] == {"kind": "actor", "actor_id": c["requester"]} and
                    request["audience_actor_id"] == {"kind": "service", "service_id": h} and
                    response["realm_id"] == realm and int(response["governance_generation"]) == 0 and
                    response["effective_stream_head"] == bundle["realm_stream_head"] and
                    response["current"] == {"state": "never_written"} and response["proof"]["jws"] and
                    response["request_digest"] == "sha256:" + digest(request) and
                    command["report"] == response and command["cli"]["operation"] == "inspect-consent" and
                    command["cli"]["exit_code"] == 0 and command["cli"]["pid"] > 0 and
                    command["cli"]["sha256"] == processes[1]["sha256"] and
                    command["cli"]["executable"] == processes[1]["executable"] and
                    any(x["operation_id"] == OPERATIONS[0] and x["request_body"] == request and
                        x["response_body"] == response for x in exchanges),
                    "local inspection lacks its exact typed, signed real H to G current exchange")
        proxies = [x for x in exchanges if x["operation_id"] == OPERATIONS[1] and
                   x["request_body"]["holder_account_id"] == holder]
        require(len(proxies) >= 2, "both true self requests must reach the private G owner")
        for x in proxies:
            request, response = x["request_body"], x["response_body"]
            require(request["realm_id"] == response["realm_id"] == realm and
                    response["effective_stream_head"] == bundle["realm_stream_head"] and
                    request["command"] == {"kind": "request", "body": {
                        "requester_actor_id": c["requester"], "request": c["self_request"]}} and
                    request["context"] == {"kind": "station", "actor_id": {"kind": "service", "service_id": h}} and
                    response["response_body"] == {"kind": "request", "body": c["accepted"]} and
                    response["request_digest"] == "sha256:" + digest(request),
                    "unrelated private request was substituted for the real session requester")
        publications = [x for x in exchanges if x["operation_id"] == OPERATIONS[2] and
                        x["request_body"]["holder_account_id"] == holder]
        require(publications, "G worker did not send a real peer effects publication")
        for x in publications:
            request, response = x["request_body"], x["response_body"]
            cell = request["effects"]["holder_quarantine"]
            require(request["realm_id"] == realm and
                    request["effective_stream_head"] == bundle["realm_stream_head"] and
                    cell["content"] == current_cell["payload"] and
                    int(cell["revision"]) == current_cell["revision"] and
                    response["request_digest"] == "sha256:" + digest(request) and response["status"] in ("applied", "duplicate"),
                    "effects response did not acknowledge the actual H/G current cell")
