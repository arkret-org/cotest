"""Exercise build environments against Cargo configuration and caller overrides."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

WORKSPACE = Path(__file__).resolve().parents[3]


def module_at(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BuildEnvironmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for repo in ('inkson', 'coauth', 'flagon'):
            if not (WORKSPACE / repo / 'scripts/ui_dependencies.py').is_file():
                raise unittest.SkipTest('Sibling UI checkouts are required for build environment integration')
        base = WORKSPACE / 'cotest/artifacts/build-environment-tests'
        base.mkdir(parents=True, exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(dir=base)
        cls.fixture = Path(cls.temporary.name)
        (cls.fixture / 'src').mkdir()
        (cls.fixture / '.cargo').mkdir()
        (cls.fixture / 'src/lib.rs').write_text('', encoding='utf-8')
        (cls.fixture / 'Cargo.toml').write_text(
            '[package]\nname="build-path-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n',
            encoding='utf-8')
        (cls.fixture / 'Cargo.lock').write_text(
            'version = 4\n[[package]]\nname = "build-path-fixture"\nversion = "0.1.0"\n',
            encoding='utf-8')
        (cls.fixture / '.cargo/config.toml').write_text(
            '[build]\ntarget-dir="configured-output"\n', encoding='utf-8')
        cls.helpers = {
            repo: module_at(f'{repo}_ui_dependencies', WORKSPACE / repo / 'scripts/ui_dependencies.py')
            for repo in ('inkson', 'coauth', 'flagon')
        }

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def environment(self):
        env = os.environ.copy()
        env.pop('CARGO_TARGET_DIR', None)
        env.pop('CARGO_HOME', None)
        return env

    def test_dependency_helpers_preserve_the_callers_environment(self):
        for repo, helper in self.helpers.items():
            for configured in (False, True):
                with self.subTest(repo=repo, configured=configured):
                    env = self.environment()
                    env['TEMP'] = str(self.fixture / 'caller-temporary')
                    env['WSL_DISTRO_NAME'] = 'caller-distribution'
                    if configured:
                        env['CARGO_HOME'] = str(self.fixture / 'caller-home')
                        env['CARGO_TARGET_DIR'] = str(self.fixture / 'caller-output')
                    result = helper.cargo_environment(self.fixture, env)
                    self.assertEqual(result, env)
                    self.assertIsNot(result, env)

    def test_web_builders_preserve_the_same_environment(self):
        for repo, filename in (('inkson', 'build_web.py'), ('coauth', 'build-frontend.py')):
            with self.subTest(repo=repo):
                env = self.environment()
                env['CARGO_TARGET_DIR'] = str(self.fixture / 'caller-output')
                env['WSL_DISTRO_NAME'] = 'caller-distribution'
                scripts = WORKSPACE / repo / 'scripts'
                with patch.dict(os.environ, env, clear=True), patch.dict(
                    sys.modules, {'ui_dependencies': self.helpers[repo]}
                ), patch.object(sys, 'path', [str(scripts), *sys.path]):
                    builder = module_at(f'{repo}_web_builder', scripts / filename)
                    self.assertEqual(builder.build_environment(), env)

    def test_actual_cargo_config_and_environment_select_identical_targets(self):
        for repo, helper in self.helpers.items():
            for configured in (False, True):
                with self.subTest(repo=repo, configured=configured):
                    env = self.environment()
                    expected = self.fixture / 'configured-output'
                    if configured:
                        expected = self.fixture / 'caller-output'
                        env['CARGO_TARGET_DIR'] = str(expected)
                    metadata = helper.cargo_metadata(self.fixture, env)
                    self.assertEqual(Path(metadata['target_directory']).resolve(), expected.resolve())

    def test_savfox_resolves_the_same_cargo_configuration(self):
        helper = WORKSPACE.parent / 'savfox-ai/savfox/scripts/cargo-target.cjs'
        if not helper.is_file():
            self.skipTest('Savfox checkout is not present')
        code = 'console.log(JSON.stringify(require(process.argv[1]).cargoTargetDirectory(process.argv[2])))'
        for configured in (False, True):
            with self.subTest(configured=configured):
                env = self.environment()
                expected = self.fixture / 'configured-output'
                if configured:
                    expected = self.fixture / 'caller-output'
                    env['CARGO_TARGET_DIR'] = str(expected)
                result = subprocess.check_output(
                    ['node', '-e', code, str(helper), str(self.fixture)],
                    env=env, text=True, encoding='utf-8')
                self.assertEqual(Path(json.loads(result)).resolve(), expected.resolve())

    def test_powershell_helper_resolves_relative_repository_paths(self):
        if not shutil.which('pwsh'):
            self.skipTest('PowerShell is not installed')
        helper = WORKSPACE / 'inkson/scripts/lib/cargo.ps1'
        relative = self.fixture.relative_to(WORKSPACE)
        command = ". '{0}'; Get-CargoTargetDirectory -RepositoryRoot '{1}'".format(
            str(helper).replace("'", "''"), str(relative).replace("'", "''"))
        for configured in (False, True):
            with self.subTest(configured=configured):
                env = self.environment()
                expected = self.fixture / 'configured-output'
                if configured:
                    expected = self.fixture / 'caller-output'
                    env['CARGO_TARGET_DIR'] = str(expected)
                result = subprocess.check_output(
                    ['pwsh', '-NoProfile', '-Command', command], cwd=WORKSPACE,
                    env=env, text=True, encoding='utf-8')
                self.assertEqual(Path(result.strip()).resolve(), expected.resolve())


if __name__ == '__main__':
    unittest.main()
