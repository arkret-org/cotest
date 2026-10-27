"""Offline schema diagnostics over every observed native request and response.

This audit grants no native coverage. Failed executions remain failed even if
all their observed JSON satisfies schemas; admission and effects are separate.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


ARTIFACTS = Path(__file__).resolve().parents[2] / "arkret-spec/spec/v1/artifacts"


def audit(document: dict, observations: Path) -> dict:
    registry = Registry()
    ids = set()
    for path in sorted((ARTIFACTS / "schemas").rglob("*.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        identifier = schema.get("$id")
        if identifier is None:
            continue
        if identifier in ids:
            raise ValueError(f"duplicate native schema id: {identifier}")
        ids.add(identifier)
        registry = registry.with_resource(identifier, Resource.from_contents(schema, default_specification=DRAFT202012))
    validators = {}
    bindings = {row["operation_id"]: row for row in document["operations"]}
    checked = 0
    findings = []
    for path in sorted(observations.glob("attempt-*.json")):
        captured = json.loads(path.read_text(encoding="utf-8"))["observations"]
        for index, exchange in enumerate(captured["exchanges"]):
            binding = bindings.get(exchange["operation_id"])
            if binding is None:
                continue
            for side, encoded in (("request", "request_json_base64url"), ("response", "decoded_response_bytes_base64url")):
                reference = binding[f"{side}_schema_ref"]
                value = exchange[f"{side}_body"]
                where = {"artifact": path.name, "exchange": index, "operation_id": exchange["operation_id"], "side": side}
                checked += 1
                if reference is None:
                    raw = exchange[encoded]
                    if value is not None or base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)):
                        findings.append({**where, "keyword": "registered_empty_body", "path": []})
                    continue
                if reference not in validators:
                    filename, _, fragment = reference.partition("#")
                    source = (ARTIFACTS / filename).resolve()
                    if not source.is_relative_to(ARTIFACTS.resolve()):
                        raise ValueError("operation schema escaped the Spec artifacts")
                    schema = json.loads(source.read_text(encoding="utf-8"))
                    uri = schema["$id"] + ("#" + fragment if fragment else "")
                    validators[reference] = Draft202012Validator({"$ref": uri}, registry=registry)
                for error in validators[reference].iter_errors(value):
                    # Do not copy tokens, private values or whole response JSON
                    # into diagnostics. The executed raw artifact stays intact.
                    findings.append({**where, "schema_ref": reference, "keyword": error.validator,
                                     "path": list(error.absolute_path), "schema_path": list(error.absolute_schema_path)})
    return {"native_coverage": False, "checked_bodies": checked,
            "schema_valid": not findings, "findings": findings}
