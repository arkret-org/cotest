"""Execute assigned Cargo children and retain complete, private scope receipts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid


PLAN_ENV = 'COTEST_NATIVE_WORKSPACE_PLAN'
DOC_ENV = 'COTEST_NATIVE_DOC_CONTEXT'
REAL_DOC_ENV = 'COTEST_NATIVE_REAL_RUSTDOC'
OLD_DOC_ENV = 'COTEST_NATIVE_ORIGINAL_RUSTDOC'
REPOSITORIES = {'cotest', 'arkret-spec', 'arkret-rust-sdk', 'inkson', 'coland',
                'coauth', 'floria', 'flagon', 'chime', 'garth', 'bridges', 'savfox'}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False)


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def source_snapshot(workspace_root: Path, source_refs: dict) -> str:
    """Bind the frozen HEADs and actual tracked bytes, including file links."""
    if set(source_refs) != REPOSITORIES:
        raise RuntimeError('incomplete workspace source set')
    workspace = Path(workspace_root).resolve().parent
    records = []
    try:
        for name, expected in sorted(source_refs.items()):
            if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{40}', expected):
                raise RuntimeError('invalid workspace source commit')
            root = workspace.parent / 'savfox-ai/savfox' if name == 'savfox' else workspace / name
            actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root,
                                             text=True).strip()
            if actual != expected:
                raise RuntimeError('workspace source commit changed')
            entries = subprocess.check_output(['git', 'ls-files', '--stage', '-z'], cwd=root)
            for entry in entries.split(b'\0'):
                if not entry:
                    continue
                header, raw_path = entry.split(b'\t', 1)
                mode, _, stage = header.decode('ascii').split(' ')
                relative = raw_path.decode('utf-8', errors='strict')
                path = Path(relative)
                if (stage != '0' or mode == '160000' or path.is_absolute()
                        or '..' in path.parts):
                    raise RuntimeError('unreviewed workspace source entry')
                source = root / path
                link = os.readlink(source) if source.is_symlink() else None
                content = file_sha256(source) if source.exists() else None
                records.append([name, relative, mode, link, content])
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError):
        raise RuntimeError('workspace source inventory is unreadable') from None
    return hashlib.sha256(_canonical(records).encode('utf-8')).hexdigest()


def _directory(path):
    path = Path(path).absolute()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.resolve() != path:
        raise RuntimeError('linked workspace receipt directory')
    if os.name != 'nt':
        path.chmod(0o700)
    return path


def _json(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path or path.stat().st_size > 32 * 1024 * 1024:
        raise RuntimeError('invalid private workspace record')
    return json.loads(path.read_text(encoding='utf-8'))


def _save(path, value, *, initial=False):
    path = Path(path)
    _directory(path.parent)
    if initial:
        with path.open('x', encoding='utf-8') as stream:
            stream.write(_canonical(value) + '\n')
    else:
        temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
        with temporary.open('x', encoding='utf-8') as stream:
            stream.write(_canonical(value) + '\n')
        os.replace(temporary, path)
    if os.name != 'nt':
        path.chmod(0o600)


def load_plan(environment):
    from native_workspace_scope import public_plan

    path = Path(environment[PLAN_ENV])
    plan = _json(path)
    public_plan(plan)
    return path, plan


def verify_sources(plan):
    expected = plan['build_context']['source_snapshot_sha256']
    if source_snapshot(Path(plan['workspace_root']), plan['source_refs']) != expected:
        raise RuntimeError('workspace inputs changed after the full compilation')


def configure_environment(environment):
    """Wrap rustdoc transparently so dynamic doctest children have provenance."""
    if os.name != 'posix':
        raise RuntimeError('workspace sharding requires the configured POSIX runner')
    _, plan = load_plan(environment)
    verify_sources(plan)
    wrapper = Path(__file__).with_name('run-native-rustdoc.py').resolve()
    original = environment.get('RUSTDOC')
    real = shutil.which(original or 'rustdoc')
    if not real or Path(real).resolve() == wrapper:
        raise RuntimeError('missing or recursive real rustdoc')
    environment[REAL_DOC_ENV] = str(Path(real).absolute())
    environment[OLD_DOC_ENV] = json.dumps(original)
    environment['RUSTDOC'] = str(wrapper)


def _child_environment(environment):
    child = environment.copy()
    original = json.loads(child.get(OLD_DOC_ENV, 'null'))
    for key in (PLAN_ENV, DOC_ENV, REAL_DOC_ENV, OLD_DOC_ENV):
        child.pop(key, None)
    if original is None:
        child.pop('RUSTDOC', None)
    elif isinstance(original, str):
        child['RUSTDOC'] = original
    else:
        raise RuntimeError('invalid inherited rustdoc configuration')
    return child


def _verify_wrapper_pid(context):
    try:
        if os.name != 'posix' or type(context.get('wrapper_pid')) is not int or context['wrapper_pid'] <= 0:
            raise RuntimeError('invalid rustdoc wrapper process')
        os.kill(context['wrapper_pid'], 0)
    except (OSError, TypeError, KeyError):
        raise RuntimeError('rustdoc compilation context is no longer active') from None


def _doc_context(command, environment, plan_path, plan):
    context_path = Path(environment.get(DOC_ENV, ''))
    root = plan_path.parent / 'runtime' / 'doc-contexts'
    if (not context_path.is_absolute() or context_path.parent.parent != root
            or context_path.name != 'context.json'):
        raise RuntimeError('unknown native executable has no owned rustdoc context')
    context = _json(context_path)
    if (context.get('plan_sha256') != file_sha256(plan_path)
            or context.get('shard_index') != plan['shard_index']):
        raise RuntimeError('rustdoc context does not match the compiled plan')
    identities = {row['identity_sha256'] for row in plan['doctest_targets']}
    if context.get('target_identity_sha256') not in identities:
        raise RuntimeError('rustdoc context is outside the declared workspace')
    executable = Path(command[0]).absolute()
    scratch = context_path.parent / 'scratch'
    if (executable.resolve() != executable or not executable.is_file()
            or not executable.is_relative_to(scratch)):
        raise RuntimeError('rustdoc executable is outside its fresh compilation directory')
    # A live wrapper owns the scratch directory until the real rustdoc exits.
    _verify_wrapper_pid(context)
    return context_path.parent


def run_child(command, environment, execute):
    """Preserve the existing native isolation; delegation never means a pass."""
    if PLAN_ENV not in environment:
        return execute(environment)
    plan_path, plan = load_plan(environment)
    try:
        return _run_planned_child(command, environment, execute, plan_path, plan)
    except BaseException:
        # Rustdoc may accept a nonzero child as a should_panic success. Adapter
        # failures are separate from that real test outcome and cannot be hidden.
        _save(plan_path.parent / 'runtime' / 'adapter-failed.json', {'failed': True})
        raise


def _run_planned_child(command, environment, execute, plan_path, plan):
    executable = Path(command[0]).absolute()
    matches = [row for row in plan['native_targets']
               if Path(row['executable']).absolute() == executable]
    if not matches:
        context = _doc_context(command, environment, plan_path, plan)
        record_path = context / 'children' / (uuid.uuid4().hex + '.json')
        record = {'status': 'started', 'exit_code': None}
    else:
        if len(matches) != 1 or DOC_ENV in environment:
            raise RuntimeError('ambiguous workspace native invocation')
        target = matches[0]
        record_path = plan_path.parent / 'runtime' / 'native' / (target['identity_sha256'] + '.json')
        record = {'shard_index': plan['shard_index'],
                  'target_identity_sha256': target['identity_sha256'],
                  'status': 'started', 'exit_code': None, 'executable_sha256': None}
        if target['assigned_shard'] != plan['shard_index']:
            record['status'] = 'delegated'
            _save(record_path, record, initial=True)
            print('workspace target delegated; execution credit=0: ' + target['identity_sha256'])
            return 0
        if (executable.resolve() != executable or not executable.is_file()
                or not executable.is_relative_to(Path(plan['target_directory']))
                or file_sha256(executable) != target['executable_sha256']):
            raise RuntimeError('compiled workspace executable changed before execution')
        record['executable_sha256'] = target['executable_sha256']
    _save(record_path, record, initial=True)
    try:
        code = execute(_child_environment(environment))
    except BaseException:
        record['status'] = 'launch_failed'
        _save(record_path, record)
        raise
    record.update(status='completed', exit_code=code)
    _save(record_path, record)
    return code


def run_rustdoc(arguments, environment):
    """Forward every real rustdoc argument and record each declared --test call."""
    plan_path, plan = load_plan(environment)
    real = environment.get(REAL_DOC_ENV)
    if not real or Path(real).resolve() == Path(__file__).with_name('run-native-rustdoc.py').resolve():
        raise RuntimeError('invalid real rustdoc executable')
    if '--test' not in arguments:
        return subprocess.run([real, *arguments], env=environment, check=False).returncode
    def option(name):
        values = [arguments[i + 1] for i, value in enumerate(arguments[:-1]) if value == name]
        values += [value[len(name) + 1:] for value in arguments if value.startswith(name + '=')]
        if len(values) != 1:
            raise RuntimeError('ambiguous rustdoc crate identity')
        return values[0]
    crate = option('--crate-name')
    run_directory = Path(option('--test-run-directory')).resolve()
    if Path.cwd().resolve() != Path(plan['workspace_root']).resolve():
        raise RuntimeError('rustdoc compilation is outside the workspace root')
    candidates = []
    for row in plan['doctest_targets']:
        if row['identity']['name'] != crate or Path(row['package_manifest_dir']).resolve() != run_directory:
            continue
        expected = Path(row['src_path']).resolve()
        if any(not arg.startswith('-') and arg.endswith('.rs')
               and Path(arg).resolve() == expected for arg in arguments):
            candidates.append(row)
    if len(candidates) != 1:
        raise RuntimeError('rustdoc test is not a unique declared workspace library')
    target = candidates[0]
    receipt = plan_path.parent / 'runtime' / 'docs' / (target['identity_sha256'] + '.json')
    record = {'shard_index': plan['shard_index'],
              'target_identity_sha256': target['identity_sha256'],
              'status': 'started', 'exit_code': None}
    _save(receipt, record, initial=True)
    contexts = _directory(plan_path.parent / 'runtime' / 'doc-contexts')
    with tempfile.TemporaryDirectory(prefix='doc-', dir=contexts) as scratch_root:
        context_root = Path(scratch_root).resolve()
        scratch = _directory(context_root / 'scratch')
        _save(context_root / 'context.json', {
            'plan_sha256': file_sha256(plan_path), 'shard_index': plan['shard_index'],
            'target_identity_sha256': target['identity_sha256'], 'wrapper_pid': os.getpid(),
        }, initial=True)
        child = environment.copy()
        child[DOC_ENV] = str(context_root / 'context.json')
        child.update(TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch))
        try:
            code = subprocess.run([real, *arguments], env=child, check=False).returncode
            children = list((context_root / 'children').glob('*.json'))
            completed = [_json(path) for path in children]
            if (any(row.get('status') != 'completed' or type(row.get('exit_code')) is not int
                    for row in completed)
                    or (plan_path.parent / 'runtime' / 'adapter-failed.json').exists()):
                # The real rustdoc, including should_panic and compile_fail,
                # decides whether a completed child's exit was expected.
                code = code or 1
        except BaseException:
            record['status'] = 'launch_failed'
            _save(receipt, record)
            raise
    record.update(status='completed', exit_code=code)
    _save(receipt, record)
    return code
