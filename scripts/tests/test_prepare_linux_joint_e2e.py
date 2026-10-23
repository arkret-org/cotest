"""Exercise the real cold-runner adapter with mocked external commands."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith("linux"), "Runs the Linux Bash provisioning adapter")
class PrepareLinuxJointTests(unittest.TestCase):
    def invoke(self, sdk_lock=False, missing_application=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = ("arkret-rust-sdk", "floria", "coland", "coauth", "garth", "chime", "inkson", "cotest")
            for name in names:
                repository = root / name
                repository.mkdir()
                (repository / "Cargo.toml").write_text("[workspace]\n")
                if (name != "arkret-rust-sdk" or sdk_lock) and name != missing_application:
                    (repository / "Cargo.lock").write_text("fixture lock\n")
            scripts = root / "cotest/scripts"
            scripts.mkdir()
            adapter = scripts / "prepare-linux-joint-e2e.sh"
            shutil.copyfile(Path(__file__).resolve().parents[1] / adapter.name, adapter)
            commands = root / "commands"
            commands.mkdir()
            cargo = commands / "cargo"
            cargo.write_text('''#!/usr/bin/env bash
set -euo pipefail
printf '%s|%s\\n' "${PWD##*/}" "$*" >> "$TEST_CARGO_TRACE"
if [[ $1 == generate-lockfile ]]; then
  touch Cargo.lock
elif [[ $1 == fetch && ! -f Cargo.lock ]]; then
  exit 37
fi
''')
            cargo.chmod(0o755)
            curl = commands / "curl"
            curl.write_text("#!/usr/bin/env bash\nexit 42\n")
            curl.chmod(0o755)
            trace = root / "cargo-trace.txt"
            environment = dict(os.environ, GITHUB_ACTIONS="true", RUNNER_TEMP=str(root / "runner"),
                               GITHUB_PATH=str(root / "paths"), GITHUB_ENV=str(root / "environment"),
                               TEST_CARGO_TRACE=str(trace), PATH=str(commands) + os.pathsep + os.environ["PATH"])
            result = subprocess.run(["bash", str(adapter), "setup"], env=environment, capture_output=True, text=True)
            return result.returncode, trace.read_text().splitlines()

    def test_cold_sdk_gets_a_lock_before_every_locked_fetch(self):
        status, calls = self.invoke()
        self.assertEqual(status, 42, "The adapter must reach the mocked Caddy download")
        self.assertEqual(calls[:2], ["arkret-rust-sdk|generate-lockfile --manifest-path Cargo.toml",
                                    "arkret-rust-sdk|fetch --locked --manifest-path Cargo.toml"])
        self.assertEqual(len(calls), 9)
        self.assertEqual(sum("generate-lockfile" in call for call in calls), 1)

    def test_existing_sdk_lock_is_preserved(self):
        status, calls = self.invoke(sdk_lock=True)
        self.assertEqual(status, 42)
        self.assertEqual(len(calls), 8)
        self.assertFalse(any("generate-lockfile" in call for call in calls))

    def test_missing_application_lock_fails_without_regeneration(self):
        status, calls = self.invoke(missing_application="coauth")
        self.assertEqual(status, 37)
        self.assertEqual(calls[-1], "coauth|fetch --locked --manifest-path Cargo.toml")
        self.assertEqual(sum("generate-lockfile" in call for call in calls), 1)


if __name__ == "__main__":
    unittest.main()
