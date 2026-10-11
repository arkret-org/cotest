#!/usr/bin/env python3
"""Run native tests with one explicit, isolated TLS authority per invocation."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


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
        environment.update({
            "COLAND_TLS_CERT_PATH": str(chain),
            "COLAND_TLS_KEY_PATH": str(key),
            "COTEST_RUN_SCOPED_CA_PEM": str(ca),
            "SSL_CERT_FILE": str(ca),
        })
        return subprocess.run(command, env=environment, check=False).returncode


def main() -> int:
    command = sys.argv[1:]
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
