"""Guard the IVS clean break and link ownership; static checks grant no runtime coverage."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RETIRED = frozenset({
    'ak.open.third_party_invite.command.activate.v1',
    'ak.open.third_party_invite.command.present_token.v1',
    'ak.open.third_party_invite.command.provision.v1',
    'ak.open.third_party_invite.read.provisioning_status.v1',
    'ak.self.third_party_invite.read.acceptance_attestation.v1',
})


def check(root: Path = ROOT) -> dict:
    contract = json.loads((root / 'arkret-spec/spec/v1/artifacts/registry/contract-registry.json').read_text(encoding='utf-8'))
    operations = {row['operation_id'] for row in contract['operation_registry']['operations']}
    assert not (operations & RETIRED), 'withdrawn HTTP operation returned'
    assert 'ak.peer.invites.command.submit.v1' in operations, 'directed private delivery was removed with IVS'
    events = {row['event_kind'] for row in contract['event_kind_registry']['event_kinds']}
    assert not (events & {'ak.invite.claim', 'ak.invite.third_party'}), 'withdrawn provider Event returned'
    assert {'ak.realm_invite_link.' + action for action in ('create', 'revoke', 'accept')} <= events
    retired_source = re.compile(r'ThirdPartyInvite|InviteClaim|third_party_invite|ak\.invite\.(?:claim|third_party)\b')
    for owner in ('arkret-rust-sdk', 'coland', 'coauth', 'garth', 'inkson'):
        for folder in ('src', 'crates'):
            base = root / owner / folder
            if not base.exists():
                continue
            for path in base.rglob('*.rs'):
                if any(part in {'tests', 'generated-test'} for part in path.relative_to(base).parts):
                    continue
                source = path.read_text(encoding='utf-8')
                source = re.split(r'#\[cfg\(test\)\]\s*(?:mod\s+\w+\s*\{)', source, maxsplit=1)[0]
                assert not retired_source.search(source), f'withdrawn production owner: {path.relative_to(root)}'
    for owner in ('coland', 'coauth'):
        for path in (root / owner / 'crates').rglob('*.sql'):
            assert not re.search(r'CREATE\s+TABLE[^;]*(?:third_party_invite|invite_third_party)', path.read_text(encoding='utf-8'), re.I), f'withdrawn storage owner: {path}'
    review = json.loads((root / 'inkson/tests/contract/mock-operation-review.json').read_text(encoding='utf-8'))
    review_ids = {row['operation_id'] for row in review['operations']}
    assert len(review_ids) == len(review['operations'])
    assert 'ak.peer.invites.command.submit.v1' in review_ids and not (review_ids & RETIRED)
    native = json.loads((root / 'cotest/tests/fixtures/native-operation-contracts.json').read_text(encoding='utf-8'))
    assert len({row['operation_id'] for row in native['operations']}) == len(native['operations'])
    assert not ({row['operation_id'] for row in native['operations']} & RETIRED)
    return {'withdrawn_operations': len(RETIRED), 'review_scope': len(review_ids), 'native_inventory_scope': len(native['operations']), 'native_coverage': False}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
