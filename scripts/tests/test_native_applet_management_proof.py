"""Component-only adversarial proof checks; synthetic objects earn no native credit."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_applet_management_proof import check


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def encode(value):
    return base64.urlsafe_b64encode(canonical(value)).decode().rstrip('=')


def decode(value):
    return json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fixture():
    realm, governor, station, service, applet = 'realm', 'governor', 'account-station', 'applet-service', 'applet'
    scope = {'kind': 'realm', 'realm_id': realm}
    control = {'kind': 'realm_control', 'realm_id': realm}
    actor = {'kind': 'service', 'service_id': service}
    administrator = {'kind': 'account', 'account_id': {'principal_id': 'principal', 'station_id': station}}
    operations = [
        'ak.self.applet.ghost.command.preview.v1', 'ak.self.applet.bot.command.preview.v1',
        'ak.edge.applet.managed_actor.command.author.v1', 'ak.self.applet.configuration.command.submit.v1',
        'ak.peer.applet.configuration.command.submit.v1', 'ak.edge.applet.configuration.command.execute.v1',
        'ak.edge.applet.command.transaction.v1', 'ak.self.management_review.command.request.v1',
        'ak.self.management_review.command.decide.v1', 'ak.self.management_review.read.status.v1',
    ]
    package = {'applet_id': applet, 'service_id': service, 'registration_epoch': 'epoch',
               'package_digest': 'package-digest', 'requested_scopes': ['ghost', 'bot']}
    install = {'applet_id': applet, 'service_id': service, 'registration_epoch': 'epoch',
               'effective_scope': scope, 'rejections': [], 'registration_event_ref': 'registration',
               'capability_grant_refs': ['grant']}
    quota = {'constraint_kind': 'quota', 'max_operation_count': 3, 'period': 'P1D', 'constraint_scope': 'per_realm'}
    registration = {'event': {'event_id': 'registration'}, 'commit': {'commit_id': 'registration-commit'}}
    grant = {'event': {'event_id': 'grant', 'payload': {'grant': {'subject': actor,
             'actions': package['requested_scopes'], 'constraints': [quota]}}}, 'commit': {'commit_id': 'grant-commit'}}

    def original(role):
        event = {'event_id': role + '-event', 'kind': 'ak.realm.actor.create', 'scope_ref': control,
                 'realm_id': realm, 'actor_id': actor, 'payload': {'actor_role': role, 'creation_scope': scope,
                 'actor_id': {'kind': 'realm', 'realm_actor_id': {'realm_id': realm, 'principal_id': role}}}}
        return {'event': event, 'commit': {'event_ref': event['event_id'], 'stream_ref': control, 'commit_id': role + '-commit'}}

    ghost, bot = original('ghost'), original('bot')
    def preview(name):
        return {'authoring_request': {'purpose': 'provision_' + name, 'governance_station_id': governor,
                'basis': {'applet_id': applet, 'service_id': service, 'effective_scope': scope,
                          'target_station_id': governor, 'registration_event_ref': 'registration',
                          'authorization_ref': 'grant', 'package_digest': 'package-digest'},
                'proof': {'audience_id': service, 'jws': 'synthetic-component-proof'}}}

    review = {'request_id': 'review', 'effective_scope': scope, 'management_operation': 'map_ghost',
              'requester_actor_id': actor, 'target': {'kind': 'event', 'event': ghost['event']}}
    target = 'sha256:' + digest(ghost['event'])
    vote = {'input': {'approval_context': {'context_kind': 'management', 'request_id': 'review',
            'management_operation': 'map_ghost', 'effective_scope': scope},
            'approval_target': {'target_kind': 'event', 'event_id': ghost['event']['event_id']},
            'request_canonical_digest': target, 'operation': 'ak.self.events.command.submit.v1',
            'action': 'ak.applet.ghost.provision', 'initiating_actor_id': actor},
            'proof': {'verification_method': 'accepted-device-method', 'jws': 'component-vote'}}
    states = {status: {'request_id': 'review', 'status': status, 'target_digest': target,
                      'approval_signatures': [vote] if status in ('approved', 'consumed') else []}
              for status in ('pending', 'approved', 'consumed')}
    decision = {'request_id': 'review', 'expected_status': 'pending', 'decision': 'approve', 'approval_signatures': [vote]}
    configuration = {'command': 'recover', 'intent': {'request_id': 'configuration', 'service_id': service,
                     'effective_scope': scope, 'selection': {'kind': 'new_bot', 'display_name': 'native'}}, 'approval_signatures': []}
    execution = {'command': 'configure', 'intent': {'request_id': 'configuration', 'service_id': service,
                 'registration_ref': {'event_id': 'registration'}, 'registration_epoch': 'epoch',
                 'originating_actor_id': administrator}}
    source = {'service_id': service, 'intent_digest': 'sha256:' + digest(execution['intent']),
              'create_event': bot['event'], 'proof': {'jws': 'component-source-proof'}}
    configured = {'request_id': 'configuration', 'admission_status': 'accepted', 'source_response_body': source}
    origin = 'https://127.0.0.1:19091/'
    worker = {'pid': 12, 'origin': origin, 'executable': 'worker.exe', 'sha256': 'sha256:' + '0' * 64,
              'role': 'cotest_managed_applet_host_worker'}
    cold = {'stopped': {'waited': True, 'before': worker | {'pid': 11}}, 'restarted': worker,
            'records': {'originals': [], 'configurations': [['config-key', '1' * 64]]}}
    exchanges = []
    def exchange(operation, request, response, source_id=governor, destination=service):
        exchanges.append({'operation_id': operation, 'request_body': copy.deepcopy(request),
                          'response_body': copy.deepcopy(response), 'response_status': 200,
                          'request_json_base64url': encode(request), 'decoded_response_bytes_base64url': encode(response),
                          'url': origin + operation, 'explicit_request_headers': {'arkret-operation': operation,
                          'source-service-id': source_id, 'destination-service-id': destination}})
    e = {'scope': operations, 'realm_id': realm, 'governor': governor, 'account_station': station,
         'installed': install, 'package': package, 'administrator': administrator,
         'service_resolution': {'service_id': service, 'service_kind': 'applet_service'},
         'governor_resolution': {'service_id': governor, 'service_kind': 'station'},
         'registration': registration, 'grant': grant, 'ghost_preview': preview('ghost'),
         'bot_preview': preview('bot'), 'ghost_preview_request': {'external_ref': 'ghost'},
         'bot_preview_request': {'request_id': 'preview-bot'}, 'ghost_event': ghost['event'],
         'ghost_author_replay': ghost['event'], 'review_request': review, 'pending': states['pending'],
         'pending_status': states['pending'], 'approved': states['approved'], 'consumed': states['consumed'],
         'decision': decision, 'approver_method': 'accepted-device-method', 'unapproved': {'status': 403},
         'admitted': {'outcome': 'accepted'}, 'admission_replay': {'outcome': 'accepted'},
         'configuration_request': configuration, 'configured': configured, 'source_execution': execution,
         'cold_source_request': execution, 'cold_source_response': source, 'not_started': {'admission_status': 'not_started'},
         'replay': configured, 'recover': configured, 'cold_recover': configured, 'conflict': {'status': 409},
         'ghost_committed': ghost, 'bot_committed': bot, 'cold': cold,
         'processes': [{'origin': 'issuer-g'}, {'origin': 'station-g'}, {'origin': 'issuer-a'}, {'origin': 'station-a'}, worker],
         'observations': {'exchanges': exchanges}}
    exchange(operations[0], e['ghost_preview_request'], e['ghost_preview'], service, governor)
    exchange(operations[1], e['bot_preview_request'], e['bot_preview'], service, governor)
    for _ in range(2):
        exchange(operations[2], {'authoring_request': e['ghost_preview']['authoring_request']}, {'create_event': ghost['event']})
    exchange(operations[7], review, states['pending'], service, governor)
    exchange(operations[8], decision, states['approved'])
    exchange(operations[9], {'request_id': 'review'}, states['pending'], service, governor)
    exchange(operations[9], {'request_id': 'review'}, states['consumed'], service, governor)
    configure = configuration | {'command': 'configure'}
    exchange(operations[3], configure, configured)
    exchange(operations[4], {'requester_account_id': administrator['account_id'], 'request': configure}, configured, station, governor)
    for _ in range(2):
        exchange(operations[5], execution, source)
    for item in (ghost, bot):
        body = {'applet_id': applet, 'source_id': governor, 'authoring_context': {'material': {'material': item}}}
        exchange(operations[6], body, {'committed_event_refs': []})
        cold['records']['originals'].append([item['event']['event_id'], json.dumps(body)])
    common = {'events': ['registration', 'grant', 'policy'], 'committed': [registration, grant],
              'actors': [], 'actor_current': [], 'installations': ['installation'], 'registration_instances': ['I'],
              'registration_current': ['I'], 'sources': ['source'], 'grants': ['grant'],
              'quota_counters': [], 'quota_buckets': [], 'quota_consumptions': [], 'completions': []}
    final = copy.deepcopy(common)
    final['events'].extend(['ghost', 'bot'])
    final['committed'].extend([ghost, bot])
    final['actors'] = [{'event_id': x['event']['event_id'], 'commit_id': x['commit']['commit_id']} for x in (ghost, bot)]
    final['completions'] = [{'creation_ref': {'event_id': x['event']['event_id']}, 'delivered_at': 'actual-time'} for x in (ghost, bot)]
    final['quota_consumptions'] = [{'grant_id': 'grant', 'operation_identity': x} for x in ('ghost', 'bot')]
    final['quota_counters'] = [{'grant_id': 'grant', 'consumed': 2}]
    e['snapshots'] = {key: copy.deepcopy(common) for key in ('before_previews', 'after_previews', 'before_pending', 'pending', 'approved')}
    e['snapshots'].update({key: copy.deepcopy(final) for key in ('completed', 'before_conflict', 'after_conflict')})
    return json.loads(json.dumps(e))


class NativeAppletManagementProofTests(unittest.TestCase):
    def check(self, value):
        check(value, require=require, digest=digest, decode=decode)

    def test_complete_structural_probe_is_not_native_execution(self):
        self.check(fixture())

    def test_orthogonal_link_and_effect_corruptions_are_rejected(self):
        changes = [
            lambda e: e['scope'].pop(),
            lambda e: e.update(governor=e['account_station']),
            lambda e: e['installed'].update(registration_epoch='different-epoch'),
            lambda e: e['ghost_author_replay'].update(event_id='changed-original'),
            lambda e: e['decision']['approval_signatures'][0]['input'].update(request_canonical_digest='wrong-target'),
            lambda e: e['consumed'].update(status='approved'),
            lambda e: e['snapshots']['pending']['events'].append('unaccepted-event'),
            lambda e: e['snapshots']['after_conflict']['quota_counters'].append({'consumed': 1}),
            lambda e: e['observations']['exchanges'].__setitem__(slice(None), [x for x in e['observations']['exchanges'] if x['operation_id'] != 'ak.peer.applet.configuration.command.submit.v1']),
            lambda e: e['cold']['stopped'].update(waited=False),
            lambda e: e['cold']['records']['originals'].pop(),
            lambda e: e['cold_source_request'].update(command='recover'),
            lambda e: e['conflict'].update(status=200),
        ]
        for index, change in enumerate(changes):
            evidence = copy.deepcopy(fixture())
            change(evidence)
            with self.subTest(mutation=index), self.assertRaises((ValueError, KeyError)):
                self.check(evidence)


if __name__ == '__main__':
    unittest.main()
