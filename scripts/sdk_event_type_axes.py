"""Execute SDK023 fragments against a supplied immutable Rust SDK artifact.

This adapter never invokes Cargo or rebuilds the SDK. Private compiler diagnostics
are archived for diagnosis; only compile exit and executed assertions decide cases.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def check_artifact(manifest):
    for item in [manifest["sdk"], *manifest["dependencies"]]:
        if digest(item["path"]) != item["sha256"]:
            raise ValueError(f"artifact bytes changed: {item['path']}")
    if not {"client", "mls", "signer"}.issubset(manifest["sdk"]["features"]):
        raise ValueError("SDK artifact omits a required actual API feature")
    if set(manifest["externs"]) != {"arkret", "chrono", "serde", "serde_json", "ed25519_dalek"}:
        raise ValueError("explicit same-build extern inventory is incomplete")
    known = {str(Path(item["path"]).resolve()) for item in [manifest["sdk"], *manifest["dependencies"]]}
    if not all(str(Path(path).resolve()) in known for path in manifest["externs"].values()):
        raise ValueError("an extern is outside the artifact inventory")


def axes(root, output):
    sources = ["registry/contract-registry.json", "registry/event-kind-registry.json",
               "schemas/event-envelope.schema.json", "schemas/realm-commit.schema.json"]
    contract = read(root / sources[0])
    registry = read(root / sources[1])
    canonical = contract["event_kind_registry"]
    if isinstance(canonical, dict):
        canonical = canonical.get("event_kinds", canonical.get("entries"))
    if not isinstance(canonical, list):
        raise ValueError("canonical Event kind registry shape changed")
    by_kind = {row["event_kind"]: row for row in registry["event_kinds"]}
    if {row["event_kind"] for row in canonical} != set(by_kind):
        raise ValueError("derived Event registry differs from its canonical source")
    payloads = {}
    for kind, row in by_kind.items():
        if row.get("wire_scope") != "durable_event":
            continue
        ref = row["payload_schema_ref"]
        source, _, pointer = ref.partition("#")
        schema = read(root / source)
        for part in pointer.strip("/").split("/") if pointer else []:
            schema = schema[part.replace("~1", "/").replace("~0", "~")]
        payloads[kind] = {"schema_ref": ref, "schema": schema}
        sources.append(source)
    sources.extend(str(path.relative_to(root)).replace("\\", "/") for path in (root / "schemas").glob("*.json"))
    hashes = {path: digest(root / path) for path in sorted(set(sources))}
    result = {"source_sha256": hashes, "durable_payloads": payloads}
    write(output / "axes.json", result)
    return result


def run(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = Path(args.artifacts).resolve()
    fixture = read(root / "fixtures/sdk-event-type-axes-fixture.json")
    manifest = read(args.artifact_manifest)
    check_artifact(manifest)
    axis = axes(root, output)
    common = Path(__file__).with_name("sdk_event_type_axes_contract.rs").read_text(encoding="utf-8")
    expected = fixture["cases"]
    if len(expected) != 9:
        raise ValueError("canonical SDK023 case inventory changed")
    fragments = [
        "fn invalid(value: VerifiedProducerEvent) -> VerifiedRealmCommit { value }\nfn main() {}",
        "fn invalid(value: PlainPayload<ContentBlock>) -> MlsEncryptedPayload<ContentBlock> { value }\nfn main() {}",
        'fn main() { let _ = MessageCreatePayload::with_encrypted_content(strand(), "discussion", plain()); }',
        "fn invalid(payload: MlsCommitPayload) { let _ = TypedEventDraft::<event_spec::MessageCreate>::new(scope(), actor(), payload); }\nfn main() {}",
        "async fn invalid(client: &arkret::Client, bytes: &[u8]) { let wire = Event::from_canonical_json_slice(bytes).unwrap(); let _ = client.submit_event(&EventAdmissionSubmission::new(wire)).await; }\nfn main() {}",
        'fn main() { let mut value = verified(plaintext_event()); value.event.payload.insert("content".to_owned(), json!({})); }',
        "fn main() { assert_event(plaintext_event()); }",
        "fn main() { assert_event(encrypted_event()); }",
        '''fn main() {
            let (wire, verified) = verified_commit();
            let input = canonical::canonical_json_bytes(&wire).unwrap();
            assert_eq!(canonical::canonical_json_bytes(&verified).unwrap(), input);
            assert_eq!(canonical::canonical_json_bytes(&verified).unwrap(), input);
            let preimage = canonical::canonical_json_bytes(&canonical::unsigned_value(&wire, &["commit_id", "signature"]).unwrap()).unwrap();
            assert_eq!(verified.canonical_id_bytes().unwrap(), preimage);
            assert_eq!(wire.canonical_id_bytes().unwrap(), preimage);
            println!("{}", canonical::canonical_sha256(&verified).unwrap());
        }''',
    ]
    names = [
        "the_outer_types_are_not_interchangeable",
        "the_payload_protection_types_are_not_interchangeable",
        "an_invalid_outer_by_payload_combination_fails_before_the_network",
        "an_mls_protocol_payload_cannot_be_submitted_as_a_plaintext_kind",
        "unverified_wire_bytes_cannot_reach_the_submission_entry_point",
        "a_verified_submission_cannot_be_mutated_in_place",
        "a_legal_combination_compiles_and_serializes_through_the_canonical_contract",
        "a_legal_mls_protected_combination_compiles_and_serializes",
        "a_realm_commit_value_serializes_through_its_own_canonical_contract",
    ]
    fragments = dict(zip(names, fragments))
    if [case["name"] for case in expected] != names:
        raise ValueError("canonical SDK023 cases changed; explicitly bind every new fragment")
    compiler = subprocess.check_output(["rustc", "-vV"], text=True)
    (output / "rustc.txt").write_text(compiler, encoding="utf-8")
    base = ["rustc", "--edition=2024"]
    for name, path in manifest["externs"].items():
        base += ["--extern", f"{name}={path}"]
    for directory in manifest["dependency_search"]:
        base += ["-L", f"dependency={directory}"]

    def compile_run(name, fragment, compiles):
        check_artifact(manifest)
        source = output / f"{name}.rs"
        binary = output / (name + (".exe" if sys.platform == "win32" else ""))
        source.write_text(common + "\n" + fragment + "\n", encoding="utf-8")
        command = [*base, "--crate-name", name, str(source), "-o", str(binary)]
        with (output / f"{name}.compile.stdout").open("wb") as stdout, (output / f"{name}.compile.stderr").open("wb") as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
        item = {"case_id": name, "command": command, "expected_compiles": compiles,
                "compile_exit_code": result.returncode, "assertions": 1, "passed": (result.returncode == 0) == compiles}
        if result.returncode == 0 and compiles:
            with (output / f"{name}.run.stdout").open("wb") as stdout, (output / f"{name}.run.stderr").open("wb") as stderr:
                executed = subprocess.run([str(binary)], stdout=stdout, stderr=stderr, check=False)
            item.update(run_exit_code=executed.returncode, output_sha256=digest(output / f"{name}.run.stdout"), binary_sha256=digest(binary))
            item["passed"] = item["passed"] and executed.returncode == 0
            item["assertions"] += 1
        check_artifact(manifest)
        return item

    inventory = compile_run("api_inventory", '''fn main() {
        let bindings: Vec<_> = EVENT_PAYLOAD_BINDINGS.iter().map(|b| json!({"kind":b.kind.as_str(),"payload_type":b.payload_type})).collect();
        println!("{}", json!({"bindings":bindings,"message_kind":event_spec::MessageCreate::KIND_STR,"protocol_kind":event_spec::MlsCommit::KIND_STR,"mls_content_type":encrypted().envelope().content_type}));
    }''', True)
    cases = []
    result = {"entrypoint": fixture["runner"]["entrypoint"], "fixture": "sdk-event-type-axes-fixture.json",
              "fixture_sha256": digest(root / "fixtures/sdk-event-type-axes-fixture.json"),
              "artifact": manifest, "axis_source_sha256": axis["source_sha256"],
              "inventory": inventory, "cases": cases, "complete": False, "formal_signed_claim": False,
              "adapter_sha256": digest(__file__), "fragment_support_sha256": digest(Path(__file__).with_name("sdk_event_type_axes_contract.rs"))}
    write(output / "result.json", result)
    if not inventory["passed"]:
        return 1
    sdk = read(output / "api_inventory.run.stdout")
    bindings = {item["kind"]: item["payload_type"] for item in sdk["bindings"]}
    if not set(axis["durable_payloads"]).issubset(bindings):
        raise ValueError("actual SDK omits canonical durable Event type bindings")
    message = axis["durable_payloads"][sdk["message_kind"]]["schema"]
    if not {"content", "encrypted_content"}.issubset(message["properties"]):
        raise ValueError("selected canonical payload no longer has both protection slots")
    message_ref = axis["durable_payloads"][sdk["message_kind"]]["schema_ref"]
    payload_file = root / message_ref.split("#", 1)[0]
    payload_schema = read(payload_file)
    protected = payload_schema
    for part in message["properties"]["encrypted_content"]["$ref"].strip("#/").split("/"):
        protected = protected[part]
    alternatives = protected["allOf"]
    envelope_refs = [node["$ref"] for node in alternatives if "$ref" in node]
    if not envelope_refs or not any((payload_file.parent / ref).resolve() == (root / "schemas/encrypted-envelope.schema.json").resolve() for ref in envelope_refs):
        raise ValueError("selected protected slot no longer binds the canonical MLS envelope")
    content_types = [node.get("properties", {}).get("content_type", {}).get("const") for node in alternatives]
    if sdk["mls_content_type"] not in content_types:
        raise ValueError("actual SDK protection type disagrees with the canonical protected slot")
    protocol = axis["durable_payloads"][sdk["protocol_kind"]]
    if "MlsCommitPayload" not in bindings[sdk["protocol_kind"]]:
        raise ValueError("actual concrete MLS protocol binding changed")
    for case in expected:
        item = compile_run(case["name"], fragments[case["name"]], case["expected"]["compiles"])
        cases.append(item)
        write(output / "result.json", result)
    supplements = []
    for name, expression in [
        ("raw_generic_post", 'client.post("/_arkret/self/events", &body)'),
        ("raw_generic_put", 'client.put("/_arkret/self/events", &body)'),
        ("raw_generic_delete_body", 'client.delete_with_body("/_arkret/self/events", &body)'),
    ]:
        supplements.append(compile_run(name, f'''async fn invalid(client: &arkret::Client, body: EventAdmissionSubmission) {{
            let _: arkret::http_client::Result<AuthoritySubmitOutcome> = {expression}.await;
        }}\nfn main() {{}}''', False))
    supplements.append(compile_run("raw_peer_watch", """async fn invalid(client: &arkret::Client, bytes: &[u8]) {
        let request: PeerWatchAuditReadRequest = serde_json::from_slice(bytes).unwrap();
        let _ = client.peer_strand_watch_audit_read(&request, 0).await;
    }\nfn main() {}""", False))
    supplements.append(compile_run("raw_security_create", """async fn invalid(client: &Client, request: &SecurityTransactionCreateRequest) {
        let _ = client.create_security_transaction(request).await;
    }\nfn main() {}""", False))
    controls = [compile_run("prepared_batch_canonical_preserves_approval", "fn main() { assert_deferred_batch(); }", True)]
    result["consumer_controls"] = controls
    result["bypass_supplements"] = supplements
    result["complete"] = all(item["passed"] for item in [inventory, *cases, *supplements, *controls])
    write(output / "result.json", result)
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--artifact-manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        sys.exit(run(args))
    except Exception as error:
        print(f"SDK023 adapter failed: {error}", file=sys.stderr)
        sys.exit(1)
