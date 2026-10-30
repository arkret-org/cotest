#!/usr/bin/env python3
"""Prepare verified tools for the existing owned loopback SFU tests, not a server."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


REQUIREMENTS = Path(__file__).with_name("requirements-native-media.txt")
SERVER_VERSION = "1.13.11"
SERVER_URL = "https://github.com/livekit/livekit/releases/download/v1.13.11/livekit_1.13.11_linux_amd64.tar.gz"
ARCHIVE_SHA256 = "1e9ee90ca301e1842b2887fc77cb122759756a9c8aeb4334ee91de3325ec43fb"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024
PACKAGES = {"livekit": "1.2.0", "protobuf": "7.36.2", "types-protobuf": "7.35.1.20260906",
            "aiofiles": "25.1.0", "numpy": "2.5.4"}
RTC_API = ("AudioFrame", "AudioSource", "AudioStream", "ConnectionState", "E2EEOptions",
           "EncryptionType", "LocalAudioTrack", "LocalVideoTrack", "Room", "RoomOptions",
           "TrackKind", "TrackPublishOptions", "TrackSource", "VideoBufferType", "VideoFrame",
           "VideoSource", "VideoStream")


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def canonical_path(path):
    absolute = path.absolute()
    if any(character in str(absolute) for character in "\r\n\x00") or absolute.resolve() != absolute:
        raise ValueError("invalid runtime path")
    return absolute


def check_platform():
    if (platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}
            or sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 12)):
        raise ValueError("native media tools require Linux x86_64 CPython 3.12")


def run(command, *, timeout=180, capture=False):
    return subprocess.run(command, check=True, timeout=timeout, capture_output=capture,
                          text=True, encoding="utf-8")


def download(destination):
    # The source and all accepted bytes are fixed. curl cannot read a user config
    # or follow a redirect to an insecure transport; it has a total time limit.
    run(["curl", "-q", "--fail", "--silent", "--show-error", "--location",
         "--proto", "=https", "--proto-redir", "=https", "--max-time", "180",
         "--max-filesize", str(MAX_ARCHIVE), "--output", str(destination), SERVER_URL], timeout=190)
    if not 0 < destination.stat().st_size <= MAX_ARCHIVE or digest(destination) != ARCHIVE_SHA256:
        raise ValueError("LiveKit archive verification failed")


def extract_binary(archive_path, destination):
    # Never use extractall, even for the pinned official archive. Validate the
    # complete member set before opening the only output file.
    with tarfile.open(archive_path, "r:gz") as archive:
        members = {}
        for member in archive:
            name = member.name
            if (name not in {"LICENSE", "livekit-server"} or name in members
                    or PurePosixPath(name).parts != (name,) or "\\" in name
                    or member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE} or member.mode & 0o7022
                    or not 0 < member.size <= (MAX_BINARY if name == "livekit-server" else 128 * 1024)):
                raise ValueError("unexpected LiveKit archive member")
            members[name] = member
        if set(members) != {"LICENSE", "livekit-server"} or not members["livekit-server"].mode & 0o111:
            raise ValueError("missing executable LiveKit server")
        member = members["livekit-server"]
        with archive.extractfile(member) as source, destination.open("xb") as output:
            shutil.copyfileobj(source, output)
        if destination.stat().st_size != member.size:
            raise ValueError("incomplete LiveKit executable")
        with destination.open("rb") as file:
            if file.read(4) != b"\x7fELF":
                raise ValueError("unexpected LiveKit executable format")
        os.chmod(destination, member.mode & 0o777)


def prepare(runner_temp, github_env):
    check_platform()
    temporary, environment_file = canonical_path(runner_temp), canonical_path(github_env)
    if not temporary.is_dir() or not environment_file.is_file() or environment_file.stat().st_nlink != 1:
        raise ValueError("missing owned runtime paths")
    runtime = Path(tempfile.mkdtemp(prefix="cotest-native-media-", dir=temporary))
    archive = runtime / "livekit.tar.gz"
    download(archive)
    binary = runtime / "livekit-server"
    extract_binary(archive, binary)
    version = run([str(binary), "--version"], timeout=20, capture=True).stdout.strip()
    if version != "livekit-server version " + SERVER_VERSION:
        raise ValueError("unexpected LiveKit executable version")
    venv = runtime / "venv"
    run([sys.executable, "-I", "-m", "venv", "--copies", str(venv)], timeout=120)
    python = canonical_path(venv / "bin/python")
    if not python.is_relative_to(runtime) or not stat.S_ISREG(python.stat().st_mode):
        raise ValueError("invalid isolated Python interpreter")
    run([str(python), "-I", "-m", "pip", "--isolated", "install", "--require-hashes",
         "--only-binary=:all:", "--no-cache-dir", "--index-url", "https://pypi.org/simple",
         "--requirement", str(REQUIREMENTS)], timeout=300)
    run([str(python), "-I", "-m", "pip", "--isolated", "check"], timeout=30)
    check = ("from importlib.metadata import version; from livekit import rtc; "
             f"assert all(version(k) == v for k,v in {PACKAGES!r}.items()); "
             f"assert all(hasattr(rtc, name) for name in {RTC_API!r}); "
             "print('verified livekit RTC 1.2.0')")
    run([str(python), "-I", "-c", check], timeout=30)
    manifest = {"livekit_server_version": SERVER_VERSION, "archive_sha256": ARCHIVE_SHA256,
                "executable_sha256": digest(binary), "packages": PACKAGES,
                "requirements_sha256": digest(REQUIREMENTS)}
    (runtime / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    # Only the tested tools are exported. The individual tests own each server
    # process, temporary config, port lease, frame proof and shutdown.
    with environment_file.open("a", encoding="utf-8") as output:
        output.write(f"COLAND_TEST_SFU_PYTHON={python}\nCOLAND_TEST_LIVEKIT_BIN={binary}\n")
    print("verified native media runtime: LiveKit server " + SERVER_VERSION + "; RTC 1.2.0")
    return runtime


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-temp", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        prepare(args.runner_temp, args.github_env)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError, tarfile.TarError):
        print("native media runtime preparation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
