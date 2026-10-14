"""Execute the canonical abstract and schema vectors without a live claim."""
import json
from pathlib import Path
import sys

artifacts = Path(sys.argv[1]).resolve()
spec = artifacts.parents[2]
sys.path.insert(0, str(spec))
from tools.artifact_lint.core import Lint
from tools.artifact_lint import peer_watch_current as watch

if watch.ARTIFACTS.resolve() != artifacts:
    raise RuntimeError('Canonical evaluator and requested artifact root differ')
lint = Lint()
watch.check_peer_watch_current(lint)
if lint.errors:
    raise RuntimeError('Canonical Watch evaluator failed: ' + repr(lint.errors))
fixture = json.loads((artifacts / 'fixtures/strand-watch-current-read-fixture.json').read_text(encoding='utf-8'))
cases = []
for section in ('schema_validation_cases', 'cross_station_cases', 'submit_cas_cases'):
    for case in fixture[section]:
        if section == 'cross_station_cases':
            assert watch.evaluate_read(watch.case_input(fixture, case)) == case['expected'], case['name']
        elif section == 'submit_cas_cases':
            assert watch.evaluate_cas(case) == case['expected'], case['name']
        cases.append({'case_id': case['name'], 'assertions': 1})
if len({case['case_id'] for case in cases}) != len(cases):
    raise RuntimeError('Duplicate canonical case IDs')
print(json.dumps({'cases': cases, 'evidence_kind': 'schema_and_abstract_vectors',
                  'production_e2e_claim': False, 'independent_runner_claim': False}))
