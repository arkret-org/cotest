"""Mutation tests for the structural oracle only; these objects earn no native credit."""
import base64
import copy
import hashlib
import json
import unittest

from native_circle_rotation_proof import check

ERROR_REGISTRY = {'codes': [
    {'code': 'duplicate_conflict', 'type_uri': 'https://arkret.org/problems/duplicate_conflict', 'http_status': 409},
    {'code': 'schema_violation', 'type_uri': 'https://arkret.org/problems/schema_violation', 'http_status': 422},
]}


def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def decode(value):
    return json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))


def structural_sample():
    # Deliberately not a signed SDK fixture or a callable HTTP producer.
    scope = {'kind': 'circle', 'realm_id': 'realm', 'circle_id': 'ak:circle:create'}
    out = {'realm_id': 'realm', 'circle_id': scope['circle_id'], 'scope_ref': scope,
           'group_id': 'actual-group', 'circle_creation': {'event': {'event_id': 'ak:event:create'}},
           'observations': {'accepted_identity_material': [{}, {}]},
           'circle_genesis': {'event': {'kind': 'ak.mls.genesis', 'scope_ref': scope, 'event_id': 'genesis'},
                              'commit': {'event_ref': 'genesis'}},
           'parent_genesis': {'event': {'scope_ref': {'kind': 'realm', 'realm_id': 'realm'}, 'event_id': 'parent'}},
           'parent_current': {'current_mls_commit_event_ref': 'parent'},
           'originals': {'canonical_events': [], 'idempotency_keys': []}}
    states = [{'epoch': str(i), 'effective_scope': scope, 'genesis_event_ref': 'genesis',
               'current_mls_commit_event_ref': ('genesis', 'add', 'update')[i],
               'public_tree_ref': 'tree-' + str(i)} for i in range(3)]
    out.update(zip(('before', 'after_add', 'after_update'), states))
    out['circle_read'] = {'circle_id': scope['circle_id'], 'realm_id': 'realm', 'mls_group_id': out['group_id']}
    out['final_current'] = states[2]
    welcome = {'welcome_id': 'welcome', 'effective_scope': scope, 'keypackage_claim_ref': 'claim',
               'recipient_actor_id': {'kind': 'account'}, 'commit_event_ref': 'add'}
    out['welcome'] = welcome
    out['queue'] = [welcome]
    for index, label in enumerate(('add', 'update')):
        event = {'event_id': label, 'kind': 'ak.mls.commit', 'scope_ref': scope, 'realm_id': 'realm',
                 'payload': {'base_group_state_ref': states[index]['current_mls_commit_event_ref'],
                             'previous_epoch': str(index), 'next_epoch': str(index + 1),
                             'ratchet_tree_ref': states[index + 1]['public_tree_ref']}}
        commit = {'event_ref': label, 'stream_ref': scope}
        request = {'commit_event': event, 'welcomes': [welcome] if index == 0 else [], 'idempotency_key': label}
        outcome = {'status': 'committed', 'commit': commit}
        out[label + '_request'] = request
        out[label + '_outcome'] = outcome
        out[label + '_committed'] = {'event': event, 'commit': commit}
        out[label + '_request_base64url'] = encode(request)
        out[label + '_response_base64url'] = encode(outcome)
        out[label + '_retry'] = {'status': 200, 'body_base64url': encode(outcome), 'before': {'actual-source': []}, 'after': {'actual-source': []}}
        out['originals']['canonical_events'].append({'pk': index + 1, 'state': 'committed', 'envelope': event})
        out['originals']['idempotency_keys'].append({'idempotency_key': label, 'operation_id': 'ak.self.events.command.submit.v1',
                                                    'source_event_pk': index + 1, 'request_hash': 'sha256:' + digest(request),
                                                    'response_status': 200, 'response_body': outcome})
    out['recipient_commit'] = out['add_committed']
    out['recipient_update'] = out['update_committed']
    claim = {'claims': [{'claim_id': 'claim', 'actor_id': welcome['recipient_actor_id']}]}
    out['claim_request'] = {'effective_scope': scope, 'mls_group_id': out['group_id']}
    out['claim'] = claim
    out['originals']['mls_welcome_deliveries'] = [{'welcome_id': 'welcome', 'delivery_json': welcome}]
    out['originals']['keypackage_claim_welcome_bindings'] = [{'welcome_id': 'welcome', 'claim_id': 'claim',
                                                           'commit_event_ref': 'add', 'source_id': 'S', 'claim_request_id': 'R'}]
    out['originals']['peer_keypackage_claims'] = [{'source_id': 'S', 'claim_request_id': 'R', 'outcome': claim}]
    for label, status, code in (('changed_body', 409, 'duplicate_conflict'), ('changed_key', 409, 'duplicate_conflict'),
                                ('wrong_path', 422, 'schema_violation')):
        request = copy.deepcopy(out['add_request'])
        if label == 'changed_body':
            request['welcomes'] = []
        elif label == 'changed_key':
            request['idempotency_key'] = 'another-key'
        body = {'type': 'https://arkret.org/problems/' + code, 'status': status,
                'title': code.replace('_', ' ').capitalize(), 'detail': 'Component refusal'}
        out[label] = {'request': request, 'status': status, 'body': body, 'body_base64url': encode(body),
                      'before': {'actual-source': []}, 'after': {'actual-source': []}}
    encrypted = {'scheme': 'epoch_content_aead', 'group_id': out['group_id'], 'epoch': '2',
                 'content_type': 'application/vnd.arkret.message+json', 'ciphertext': 'original-bytes',
                 'pre_encryption_header': {
                     'envelope_version': '1.0', 'scheme': 'epoch_content_aead',
                     'content_type': 'application/vnd.arkret.message+json',
                     'effective_scope': scope, 'event_kind': 'ak.message.create',
                     'mls_group_id': out['group_id'], 'epoch': '2', 'group_state_ref': 'update',
                     'routing_context': {'kind': 'none'},
                     'material': {'content_context': {'content_key_salt': 'salt', 'root_ref': 'root'},
                                  'key_commitment': 'key', 'protection': {'root_refs': ['root']}}}}
    envelope = {'version': '1.0', 'content_type': 'application/vnd.arkret.message+json',
                'encryption_scheme': 'epoch_content_aead',
                'encryption_context': {'epoch': '2', 'group_state_ref': 'update',
                                       'content_key_salt': 'salt', 'root_ref': 'root',
                                       'key_commitment': 'key', 'protection': {'root_refs': ['root']}},
                'ciphertext': 'original-bytes'}
    out['encrypted'] = encrypted
    out['message_committed'] = {'event': {'scope_ref': scope, 'payload': {'encrypted_content': envelope}}}
    out['processes'] = [{'origin': 'https://issuer.example/'}, {'origin': 'https://station.example/'}]
    out['observations']['exchanges'] = [
        {'operation_id': 'ak.self.circle.command.rotate_scope.v1', 'method': 'POST',
         'url': 'https://station.example/_arkret/self/circles/' + scope['circle_id'] + '/scope-rotate',
         'explicit_request_headers': {'arkret-operation': 'ak.self.circle.command.rotate_scope.v1'},
         'response_status': 200, 'request_body': copy.deepcopy(out[label + '_request']),
         'request_json_base64url': out[label + '_request_base64url'],
         'response_body': copy.deepcopy(out[label + '_outcome']),
         'decoded_response_bytes_base64url': out[label + '_response_base64url']}
        for label in ('add', 'update', 'add', 'update')]
    out['opened_base64url'] = out['expected_plaintext_base64url'] = encode({'text': 'sample'})
    for name in ('old_state_before_digest', 'old_state_after_digest', 'old_checkpoint_digest', 'old_checkpoint_after_digest'):
        out[name] = 'sha256:' + '1' * 64
    return out


class CircleStructuralProofTests(unittest.TestCase):
    def test_complete_structural_sample_is_only_a_component_oracle(self):
        check(structural_sample(), require=require, decode=decode, digest=digest, error_registry=ERROR_REGISTRY)

    def test_missing_or_changed_originals_and_crypto_cut_are_rejected(self):
        mutations = [
            lambda x: x['originals']['idempotency_keys'][0].update(source_event_pk=None),
            lambda x: x['originals']['idempotency_keys'][0].update(request_hash='sha256:' + '0' * 64),
            lambda x: x['originals']['keypackage_claim_welcome_bindings'].clear(),
            lambda x: x['originals']['peer_keypackage_claims'].clear(),
            lambda x: x['add_outcome'].update(status='duplicate'),
            lambda x: x['queue'].clear(),
            lambda x: x['after_update'].update(epoch='3'),
            lambda x: x.update(old_state_after_digest='sha256:' + '2' * 64),
            lambda x: x.update(old_checkpoint_after_digest='sha256:' + '2' * 64),
            lambda x: x.update(opened_base64url='different'),
            lambda x: x['changed_body'].update(status=200),
            lambda x: x['changed_key']['request'].update(idempotency_key='add'),
            lambda x: x['add_retry']['after'].update(extra='effect'),
            lambda x: x['update_request'].update(recovery_source=None),
        ]
        # A mutation must change input. Keep these explicit, not self-derived
        # from proof field enumeration or the implementation's condition list.
        for mutate in mutations:
            sample = structural_sample()
            mutate(sample)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, KeyError)):
                check(sample, require=require, decode=decode, digest=digest, error_registry=ERROR_REGISTRY)

    def test_wire_and_recorded_exchange_substitutions_are_rejected(self):
        def replace_observed_original(sample):
            request = copy.deepcopy(sample['add_request'])
            request['commit_event']['event_id'] = 'different-source'
            sample['observations']['exchanges'][0]['request_body'] = request
            sample['observations']['exchanges'][0]['request_json_base64url'] = encode(request)

        def legacy_problem(sample):
            body = {'code': 'schema_violation', 'status': 422}
            sample['wrong_path']['body'] = body
            sample['wrong_path']['body_base64url'] = encode(body)

        mutations = [
            lambda x: x['observations']['exchanges'].pop(),
            lambda x: x['observations']['exchanges'].__setitem__(0, copy.deepcopy(x['observations']['exchanges'][1])),
            lambda x: x['observations']['exchanges'][2].update(url='https://unowned.example/_arkret/self/circles/ak:circle:create/scope-rotate'),
            lambda x: x['observations']['exchanges'][3].update(decoded_response_bytes_base64url=encode({'status': 'duplicate'})),
            replace_observed_original,
            lambda x: x['message_committed']['event']['payload'].__setitem__('encrypted_content', copy.deepcopy(x['encrypted'])),
            lambda x: x['message_committed']['event']['payload']['encrypted_content'].update(ciphertext='another-wire-ciphertext'),
            lambda x: x['encrypted']['pre_encryption_header']['material']['content_context'].update(root_ref='different-root'),
            legacy_problem,
            lambda x: x['wrong_path'].update(status=400),
        ]
        for mutate in mutations:
            sample = structural_sample()
            mutate(sample)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, KeyError)):
                check(sample, require=require, decode=decode, digest=digest, error_registry=ERROR_REGISTRY)


if __name__ == '__main__':
    unittest.main()
