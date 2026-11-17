#!/usr/bin/env python3
"""Build native authorities and verify all registered operation contracts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import check_native_operation_contracts as gate
import audit_native_operation_schemas


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def execute(output, name, repository, command, environment, *, require_success=True):
    before = gate.source_fence()
    fence = output / f"{name}-sources.json"
    write(fence, before)
    metadata = subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
                              cwd=repository, env=environment, check=True, capture_output=True,
                              text=True, encoding="utf-8", timeout=1800)
    (output / f"{name}-metadata.json").write_text(metadata.stdout, encoding="utf-8")
    started = time.monotonic()
    log = output / f"{name}.log"
    try:
        with log.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(command, cwd=repository, env=environment, stdout=stream,
                                       stderr=subprocess.STDOUT, timeout=7200)
        code = completed.returncode
    except subprocess.TimeoutExpired:
        code = 124
    result = {"command": command, "exit_code": code, "seconds": round(time.monotonic() - started, 2),
              "sources_unchanged": gate.source_fence() == before, "source_fence": fence.name,
              "log": log.name, "target_directory": json.loads(metadata.stdout)["target_directory"]}
    write(output / f"{name}-result.json", result)
    if require_success:
        gate.require(code == 0 and result["sources_unchanged"], f"{name} failed or its source inputs changed; see {log}")
    return result


def build(output, name, environment):
    command = (gate.coland_custody_build_command() if name == "coland" else
               ["cargo", "build", "--locked", "-p", name, "--bin", name, "--message-format=json-render-diagnostics"])
    result = execute(output, name, gate.ROOT / name, command, environment)
    cargo_log = (output / result["log"]).read_text(encoding="utf-8")
    custody_artifact = None
    if name == "coland":
        server, custody_artifact = gate.coland_custody_artifacts(cargo_log)
        executables = [Path(server["executable"])]
    else:
        executables = []
        for line in cargo_log.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("reason") == "compiler-artifact" and record.get("target", {}).get("name") == name and record.get("executable"):
                executables.append(Path(record["executable"]))
    gate.require(len(executables) == 1, f"Cargo did not report exactly one {name} executable")
    frozen = output / "tools" / executables[0].name
    frozen.parent.mkdir(exist_ok=True)
    shutil.copyfile(executables[0], frozen)
    shutil.copymode(executables[0], frozen)
    result.update(executable=str(frozen), sha256=digest(frozen))
    product = {"producer_result": f"{name}-result.json", "executable": str(frozen), "sha256": result["sha256"]}
    if custody_artifact is not None:
        original = Path(custody_artifact["executable"])
        custody_frozen = frozen.with_name(original.name)
        shutil.copyfile(original, custody_frozen)
        shutil.copymode(original, custody_frozen)
        result.update(custody_cli={"executable": str(custody_frozen), "sha256": digest(custody_frozen)},
                      metadata=f"{name}-metadata.json")
        # Validate both actual Cargo products before any owned fixture can run
        # the custody CLI, then revalidate the same frozen bytes at publication.
        inputs = gate.read(output / result["source_fence"])
        gate.verify_coland_custody_product(product, result, inputs, inputs,
                                          gate.read(output / result["metadata"]), cargo_log)
    write(output / f"{name}-result.json", result)
    return product


def build_managed_applet_host(output, environment):
    name = gate.APPLET_HOST_TARGET
    command = ["cargo", "build", "--locked", "--bin", name,
               "--message-format=json-render-diagnostics"]
    result = execute(output, name, gate.REPO, command, environment)
    cargo_log = (output / result["log"]).read_text(encoding="utf-8")
    artifact = gate.managed_applet_host_artifact(cargo_log)
    # Keep the exact artifact Cargo reported. A copied or inferred executable
    # cannot substitute for this test product's full source/build provenance.
    executable = Path(artifact["executable"]).resolve(strict=True)
    result.update(role=gate.APPLET_HOST_ROLE, executable=str(executable), sha256=digest(executable),
                  compiler_target=artifact["target"], metadata=f"{name}-metadata.json")
    product = {"role": gate.APPLET_HOST_ROLE, "producer_result": f"{name}-result.json",
               "executable": str(executable), "sha256": result["sha256"]}
    gate.verify_managed_applet_host_product(
        product, result, gate.read(output / result["source_fence"]), gate.source_fence(),
        gate.read(output / result["metadata"]), cargo_log)
    write(output / f"{name}-result.json", result)
    write(output / f"{name}-product.json", product)
    return product


def native_service_names(selected_cases):
    return ("coland", "coauth", "floria") if selected_cases is None or "push_gateway" in selected_cases or "account_erasure_status" in selected_cases else ("coland", "coauth")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="A new directory inside Cotest artifacts.")
    parser.add_argument("--case", choices=sorted(gate.declarations()["cases"]), action="append",
                        help="Development execution only; a selected case never certifies full acceptance.")
    args = parser.parse_args()
    output = args.output.resolve()
    gate.require(output.is_relative_to((gate.REPO / "artifacts").resolve()), "native evidence must stay in owning ignored artifacts")
    output.mkdir(parents=True, exist_ok=False)
    observations = output / "observations"
    observations.mkdir()
    environment = os.environ.copy()
    database_variables = ["COTEST_COAUTH_DATABASE_URL", "COTEST_COLAND_DATABASE_URL"]
    if "floria" in native_service_names(args.case):
        database_variables.append("COTEST_FLORIA_DATABASE_URL")
    for variable in database_variables:
        gate.require(bool(environment.get(variable)), f"{variable} is required; a missing native database cannot be skipped")
    environment.setdefault("COLAND_TEST_DATABASE_URL", environment["COTEST_COLAND_DATABASE_URL"])
    environment["COTEST_NATIVE_OPERATION_EVIDENCE_DIR"] = str(observations)
    environment["COTEST_SERVICE_LOG_DIR"] = str(output / "services")
    environment["COTEST_TRANSCRIPT_PATH"] = str(output / "transcript.ndjson")
    execute(output, "service-isolation", gate.REPO,
            [sys.executable, "-B", str(gate.REPO / "scripts/check_service_isolation.py")], environment)
    products = []
    for name in native_service_names(args.case):
        print(f"Building native {name}", flush=True)
        product = build(output, name, environment)
        products.append(product)
        environment[name.upper() + "_BIN"] = product["executable"]
    print("Building the owned production managed Applet host worker", flush=True)
    products.append(build_managed_applet_host(output, environment))
    environment["COTEST_NATIVE_APPLET_HOST_PRODUCT"] = str(output / f"{gate.APPLET_HOST_TARGET}-product.json")
    # Failure locations are private diagnostics, never observations or proof.
    diagnostics = output / "diagnostics"
    diagnostics.mkdir(mode=0o700)
    environment["COTEST_NATIVE_FAILURE_DIAGNOSTICS_DIR"] = str(diagnostics)
    document = gate.declarations()
    command = [sys.executable, "-B", str(gate.REPO / "scripts/run-native-rust-tests.py"), "--",
               "cargo", "test", "--locked", "--test", "native_operation_contracts", "--", "--nocapture", "--test-threads=1"]
    if args.case:
        for identifier, case in document["cases"].items():
            if identifier not in args.case:
                command.extend(["--skip", case["test"]])
    print("Executing native operation contracts", flush=True)
    execution = execute(output, "native", gate.REPO, command, environment, require_success=False)
    execution.update(native_products=products, evidence_directory=str(observations),
                     evidence_sha256={path.name: digest(path) for path in observations.glob("*.json")})
    result = output / "native-result.json"
    write(result, execution)
    schema_audit = audit_native_operation_schemas.audit(document, observations)
    write(output / "schema-audit.json", schema_audit)
    gate.require(execution["exit_code"] == 0 and execution["sources_unchanged"],
                 f"native failed or its source inputs changed; see {output / 'native.log'}")
    gate.require(schema_audit["schema_valid"], "observed native bodies violate their registered schemas")
    try:
        covered = gate.evidence_coverage(document, observations, result)
    except ValueError as error:
        # Preserve a machine-readable zero-credit result for an invalid
        # authority foundation or proof, even when the Rust scenarios succeeded.
        write(output / "coverage.json", {
            "scope": len(document["operations"]), "native_covered": 0, "remaining": len(document["operations"]),
            "uncovered_operations": sorted(row["operation_id"] for row in document["operations"]),
            "acceptance": False, "blocker": str(error),
        })
        raise

    missing = sorted(row["operation_id"] for row in document["operations"] if row["operation_id"] not in covered)
    summary = {"scope": len(document["operations"]), "native_covered": len(covered), "remaining": len(missing),
               "uncovered_operations": missing, "acceptance": not missing and args.case is None}
    write(output / "coverage.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if args.case is None:
        gate.require(not missing, "native operation contracts are incomplete")


if __name__ == "__main__":
    main()
