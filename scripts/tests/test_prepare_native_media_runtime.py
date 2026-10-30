"""Pure transport/resource tests; never install a package or execute native media."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "native_media", Path(__file__).resolve().parents[1] / "prepare-native-media-runtime.py")
media = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(media)
PRIVATE = "PRIVATE_PATH_token_https_secret"


class MediaRuntimeResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cotest-media-resource-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.archive = self.root / "synthetic.tar.gz"
        self.environment = self.root / "github-env"
        self.environment.write_text("EXISTING=value\n", encoding="utf-8")
        self.commands = []
        self.make_archive()

    def make_archive(self, members=None):
        if members is None:
            members = [("LICENSE", b"synthetic resource fixture", 0o644, tarfile.REGTYPE),
                       ("livekit-server", b"\x7fELFsynthetic-not-executable", 0o755, tarfile.REGTYPE)]
        with tarfile.open(self.archive, "w:gz") as output:
            for name, body, mode, kind in members:
                member = tarfile.TarInfo(name)
                member.mode, member.type = mode, kind
                member.size = len(body) if kind == tarfile.REGTYPE else 0
                member.linkname = PRIVATE
                output.addfile(member, io.BytesIO(body) if member.size else None)

    def process(self, command, **kwargs):
        self.commands.append((command, kwargs))
        self.assertTrue(kwargs["check"])
        self.assertLessEqual(kwargs["timeout"], 300)
        if command[0] == "curl":
            Path(command[command.index("--output") + 1]).write_bytes(self.archive.read_bytes())
        elif "venv" in command:
            python = Path(command[-1]) / "bin/python"
            python.parent.mkdir(parents=True)
            python.write_bytes(b"synthetic Python resource; never executed")
        stdout = "livekit-server version 1.13.11\n" if command[1:] == ["--version"] else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    def prepared(self):
        with patch.object(media, "check_platform"), \
                patch.object(media, "ARCHIVE_SHA256", hashlib.sha256(self.archive.read_bytes()).hexdigest()), \
                patch.object(media.subprocess, "run", side_effect=self.process), \
                contextlib.redirect_stdout(io.StringIO()):
            return media.prepare(self.root, self.environment)

    def test_complete_preparation_exports_only_verified_isolated_paths(self):
        runtime = self.prepared()
        self.assertTrue(runtime.is_relative_to(self.root))
        exports = self.environment.read_text().splitlines()
        self.assertEqual(exports[0], "EXISTING=value")
        expected = {"COLAND_TEST_SFU_PYTHON": runtime / "venv/bin/python",
                    "COLAND_TEST_LIVEKIT_BIN": runtime / "livekit-server"}
        self.assertEqual({k: Path(v) for k, v in (row.split("=", 1) for row in exports[1:])}, expected)
        self.assertTrue(all(path.is_absolute() and path.is_file() for path in expected.values()))
        manifest = json.loads((runtime / "manifest.json").read_text())
        self.assertEqual(manifest["packages"], media.PACKAGES)
        self.assertEqual(manifest["executable_sha256"], media.digest(expected["COLAND_TEST_LIVEKIT_BIN"]))
        install = next(command for command, _ in self.commands if "install" in command)
        for flag in ("-I", "--isolated", "--require-hashes", "--only-binary=:all:", "--no-cache-dir"):
            self.assertIn(flag, install)
        self.assertEqual(install[install.index("--index-url") + 1], "https://pypi.org/simple")
        self.assertEqual(install[install.index("--requirement") + 1], str(media.REQUIREMENTS))
        self.assertTrue(any(command[-1] == "check" and "pip" in command for command, _ in self.commands))
        self.assertTrue(any("--copies" in command for command, _ in self.commands))
        probe = next(command[-1] for command, _ in self.commands if "-c" in command)
        self.assertIn("from livekit import rtc", probe)
        self.assertNotIn("Popen", probe)
        self.assertNotIn("--config", str(self.commands))

    def test_download_requires_fixed_https_bytes_and_bounds(self):
        destination = self.root / "download.tar.gz"
        with patch.object(media, "ARCHIVE_SHA256", hashlib.sha256(self.archive.read_bytes()).hexdigest()), \
                patch.object(media.subprocess, "run", side_effect=self.process):
            media.download(destination)
        command, _ = self.commands[0]
        self.assertEqual(command[-1], media.SERVER_URL)
        self.assertEqual(command[command.index("--proto") + 1], "=https")
        self.assertEqual(command[command.index("--proto-redir") + 1], "=https")
        self.assertEqual(command[1], "-q")
        with patch.object(media.subprocess, "run", side_effect=self.process), \
                patch.object(media, "ARCHIVE_SHA256", "0" * 64), self.assertRaises(ValueError):
            media.download(destination)
        with patch.object(media.subprocess, "run", side_effect=self.process), \
                patch.object(media, "MAX_ARCHIVE", 4), self.assertRaises(ValueError):
            media.download(destination)

    def test_archive_rejects_links_traversal_duplicate_or_special_members(self):
        valid = [("LICENSE", b"fixture", 0o644, tarfile.REGTYPE),
                 ("livekit-server", b"\x7fELFfixture", 0o755, tarfile.REGTYPE)]
        bad = [("../" + PRIVATE, b"x", 0o644, tarfile.REGTYPE),
               ("/" + PRIVATE, b"x", 0o644, tarfile.REGTYPE),
               ("folder\\" + PRIVATE, b"x", 0o644, tarfile.REGTYPE),
               ("livekit-server", b"", 0o755, tarfile.SYMTYPE),
               ("livekit-server", b"", 0o755, tarfile.LNKTYPE),
               ("livekit-server", b"", 0o755, tarfile.FIFOTYPE),
               ("livekit-server", b"", 0o755, tarfile.GNUTYPE_SPARSE),
               ("livekit-server", b"x", 0o4755, tarfile.REGTYPE),
               ("livekit-server", b"x", 0o777, tarfile.REGTYPE)]
        for index, member in enumerate(bad):
            with self.subTest(index=index):
                self.make_archive([valid[0], member] if member[0] == "livekit-server" else [*valid, member])
                output = self.root / f"rejected-{index}"
                with self.assertRaises(ValueError):
                    media.extract_binary(self.archive, output)
                self.assertFalse(output.exists())
        self.make_archive([*valid, valid[1]])
        with self.assertRaises(ValueError):
            media.extract_binary(self.archive, self.root / "duplicate")

    def test_archive_requires_one_bounded_regular_executable_without_overwrite(self):
        for index, mode in enumerate((0o644, 0o2755, 0o757)):
            self.make_archive([("LICENSE", b"fixture", 0o644, tarfile.REGTYPE),
                               ("livekit-server", b"\x7fELFfixture", mode, tarfile.REGTYPE)])
            with self.subTest(index=index), self.assertRaises(ValueError):
                media.extract_binary(self.archive, self.root / f"bad-mode-{index}")
        self.make_archive()
        with patch.object(media, "MAX_BINARY", 1), self.assertRaises(ValueError):
            media.extract_binary(self.archive, self.root / "large")
        self.assertFalse((self.root / "large").exists())
        destination = self.root / "existing"
        destination.write_text(PRIVATE)
        with self.assertRaises(FileExistsError):
            media.extract_binary(self.archive, destination)
        self.assertEqual(destination.read_text(), PRIVATE)
        self.make_archive([("LICENSE", b"fixture", 0o644, tarfile.REGTYPE),
                           ("livekit-server", b"#!/bin/sh\necho synthetic", 0o755, tarfile.REGTYPE)])
        with self.assertRaises(ValueError):
            media.extract_binary(self.archive, self.root / "not-elf")

    def test_failures_never_export_tools_or_start_shared_media(self):
        for index, failure in enumerate(("hash", "version", "pip", "import")):
            before = self.environment.read_bytes()
            def failing(command, **kwargs):
                if ((failure == "pip" and "install" in command)
                        or (failure == "import" and "-c" in command)):
                    raise subprocess.CalledProcessError(1, PRIVATE)
                value = self.process(command, **kwargs)
                if failure == "version" and command[1:] == ["--version"]:
                    value.stdout = "livekit-server version 1.13.10\n"
                return value
            expected = "0" * 64 if failure == "hash" else hashlib.sha256(self.archive.read_bytes()).hexdigest()
            with self.subTest(index=index), patch.object(media, "check_platform"), \
                    patch.object(media, "ARCHIVE_SHA256", expected), \
                    patch.object(media.subprocess, "run", side_effect=failing):
                with self.assertRaises((ValueError, subprocess.SubprocessError)):
                    media.prepare(self.root, self.environment)
            self.assertEqual(self.environment.read_bytes(), before)

    def test_invalid_executable_is_never_invoked_even_after_a_matching_download(self):
        self.make_archive([("LICENSE", b"fixture", 0o644, tarfile.REGTYPE),
                           ("livekit-server", b"#!/bin/sh\necho synthetic", 0o755, tarfile.REGTYPE)])
        before = self.environment.read_bytes()
        with patch.object(media, "check_platform"), \
                patch.object(media, "ARCHIVE_SHA256", hashlib.sha256(self.archive.read_bytes()).hexdigest()), \
                patch.object(media.subprocess, "run", side_effect=self.process), self.assertRaises(ValueError):
            media.prepare(self.root, self.environment)
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(self.commands[0][0][0], "curl")
        self.assertEqual(self.environment.read_bytes(), before)

    def test_platform_and_environment_path_guards_fail_before_preparation(self):
        for system, machine, version in (("Windows", "x86_64", (3, 12)), ("Linux", "aarch64", (3, 12)),
                                         ("Linux", "x86_64", (3, 13))):
            python = SimpleNamespace(implementation=SimpleNamespace(name="cpython"), version_info=version)
            with self.subTest(system=system, machine=machine, version=version), \
                    patch.object(media.platform, "system", return_value=system), \
                    patch.object(media.platform, "machine", return_value=machine), patch.object(media, "sys", python):
                with self.assertRaises(ValueError):
                    media.check_platform()
        for value in (self.root / "missing", self.root / "new\nCOLAND_TEST_SFU_PYTHON=bad"):
            with patch.object(media, "check_platform"), patch.object(media.subprocess, "run") as command, \
                    self.assertRaises(ValueError):
                media.prepare(self.root, value)
            command.assert_not_called()

    def test_runtime_cli_errors_do_not_expose_private_paths(self):
        capture = io.StringIO()
        with patch.object(media, "prepare", side_effect=RuntimeError(PRIVATE)), contextlib.redirect_stderr(capture):
            code = media.main(["--runner-temp", str(self.root), "--github-env", str(self.environment)])
        self.assertEqual(code, 1)
        self.assertNotIn(PRIVATE, capture.getvalue())

    def test_requirements_pin_the_entire_wheel_dependency_closure(self):
        lines = media.REQUIREMENTS.read_text().replace("\\\n", " ").splitlines()
        packages = {}
        for line in lines:
            if not line.strip() or line.startswith("#"):
                continue
            match = re.fullmatch(r"([a-z-]+)==([0-9.]+)\s+--hash=sha256:([0-9a-f]{64})", line)
            self.assertIsNotNone(match, line)
            self.assertNotIn(match[1], packages)
            packages[match[1]] = match[2]
        self.assertEqual(packages, media.PACKAGES)
        self.assertEqual(set(packages), {"livekit", "protobuf", "types-protobuf", "aiofiles", "numpy"})


if __name__ == "__main__":
    unittest.main()
