#!/usr/bin/env python3
"""Run native tests with isolated TLS authority and per-process client trust."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib


CLIENT_CONFIG_SCOPE = "COTEST_NATIVE_CLIENT_CONFIG_ROOT"


def native_child(command: list[str]) -> int:
    if not command:
        raise RuntimeError("native child requires an executable")
    inherited = os.environ.get(CLIENT_CONFIG_SCOPE)
    if inherited is not None:
        root = Path(inherited)
        if (not root.is_dir()
                or os.environ.get("INKSON_CONFIG_PATH") != str(root / "inkson" / "config.json")):
            raise RuntimeError("native client configuration scope is inconsistent")
        return subprocess.run(command, check=False).returncode
    with tempfile.TemporaryDirectory(prefix="cotest-native-client-") as scratch:
        root = Path(scratch)
        environment = os.environ.copy()
        environment.setdefault("COTEST_PYTHON_BIN", sys.executable)
        environment.update({
            CLIENT_CONFIG_SCOPE: str(root),
            "INKSON_CONFIG_PATH": str(root / "inkson" / "config.json"),
        })
        return subprocess.run(command, env=environment, check=False).returncode


def cargo_native_runner(command: list[str], directory: Path) -> list[str]:
    if Path(command[0]).stem.lower() != "cargo":
        return command
    offset = 2 if len(command) > 1 and command[1].startswith("+") else 1
    compiler = [shutil.which("rustc") or "rustc"]
    if offset == 2:
        compiler.append(command[1])
    version = subprocess.run(
        [*compiler, "-vV"], check=True, capture_output=True, text=True,
    ).stdout
    host = next((line.removeprefix("host: ") for line in version.splitlines()
                 if line.startswith("host: ")), None)
    if not host:
        raise RuntimeError("rustc did not report its native host target")
    runner_variable = "CARGO_TARGET_" + host.upper().replace("-", "_") + "_RUNNER"
    if os.environ.get(runner_variable):
        raise RuntimeError("native tests cannot replace an existing Cargo runner")
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    roots = [*(parent / ".cargo" for parent in (Path.cwd(), *Path.cwd().parents)), cargo_home]
    configurations = []
    for root in roots:
        legacy = root / "config"
        current = root / "config.toml"
        if legacy.is_file() or current.is_file():
            configurations.append(legacy if legacy.is_file() else current)
    for index, argument in enumerate(command[offset:], start=offset):
        if argument == "--config" and index + 1 < len(command):
            value = command[index + 1]
        elif argument.startswith("--config="):
            value = argument.removeprefix("--config=")
        else:
            continue
        if "runner" in value:
            raise RuntimeError("native tests cannot replace an explicit Cargo runner")
        if Path(value).is_file():
            configurations.append(Path(value))
    for path in configurations:
        configuration = tomllib.loads(path.read_text(encoding="utf-8"))
        for target, settings in configuration.get("target", {}).items():
            if (target == host or target.startswith("cfg(")) and "runner" in settings:
                raise RuntimeError("native tests cannot replace a configured Cargo runner")
        if "include" in configuration:
            raise RuntimeError("native runner requires explicit review of included Cargo configuration")
    runner = [sys.executable, "-B", str(Path(__file__).resolve()), "--native-child"]
    configuration = directory / "native-runner.toml"
    configuration.write_text(
        f"[target.{host}]\nrunner = {json.dumps(runner)}\n", encoding="utf-8",
    )
    return [*command[:offset], "--config", str(configuration), *command[offset:]]


def openssl(executable: str, *arguments: str) -> None:
    subprocess.run(
        [executable, *arguments], check=True, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def run(command: list[str]) -> int:
    executable = shutil.which("openssl")
    if executable is None:
        raise RuntimeError("openssl is required to create native test TLS credentials")
    with tempfile.TemporaryDirectory(prefix="cotest-native-tls-") as scratch:
        directory = Path(scratch)
        ca = directory / "ca.pem"
        ca_key = directory / "ca-key.pem"
        key = directory / "server-key.pem"
        request = directory / "server.csr"
        leaf = directory / "server.pem"
        chain = directory / "server-chain.pem"
        extensions = directory / "server.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=IP:127.0.0.1\n",
            encoding="ascii",
        )
        openssl(
            executable, "req", "-x509", "-newkey", "rsa:3072", "-nodes",
            "-sha256", "-days", "2", "-subj", "/CN=Cotest native test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(ca_key), "-out", str(ca),
        )
        openssl(
            executable, "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-sha256", "-subj", "/CN=Cotest native test server",
            "-keyout", str(key), "-out", str(request),
        )
        openssl(
            executable, "x509", "-req", "-in", str(request),
            "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial",
            "-sha256", "-days", "2", "-extfile", str(extensions),
            "-out", str(leaf),
        )
        openssl(
            executable, "verify", "-CAfile", str(ca),
            "-purpose", "sslserver", "-verify_ip", "127.0.0.1", str(leaf),
        )
        chain.write_bytes(leaf.read_bytes() + ca.read_bytes())
        for private_key in (key, ca_key):
            private_key.chmod(0o600)
        environment = os.environ.copy()
        environment.setdefault("COTEST_PYTHON_BIN", sys.executable)
        environment.update({
            "COLAND_TLS_CERT_PATH": str(chain),
            "COLAND_TLS_KEY_PATH": str(key),
            "COTEST_RUN_SCOPED_CA_PEM": str(ca),
            "SSL_CERT_FILE": str(ca),
            "INKSON_CONFIG_PATH": str(directory / "inkson" / "config.json"),
        })
        environment.pop(CLIENT_CONFIG_SCOPE, None)
        command = cargo_native_runner(command, directory)
        return subprocess.run(command, env=environment, check=False).returncode


def main() -> int:
    command = sys.argv[1:]
    if command[:1] == ["--native-child"]:
        return native_child(command[1:])
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        print("usage: run-native-rust-tests.py [--] command [arguments ...]", file=sys.stderr)
        return 2
    try:
        return run(command)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"native test TLS setup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
