"""Independent links between native Applet exchanges, originals and effects.

The source-fenced Rust driver uses the SDK for cryptographic verification.
This module accepts no verified flags and cannot grant runtime credit alone.
"""
import json
import re
from urllib.parse import urlsplit


def check(e, *, require, digest, decode):
    scope = e['scope']
    exchanges = e['observations']['exchanges']
    realm, governor, account_station = e['realm_id'], e['governor'], e['account_station']
    install, package = e['installed'], e['package']
    applet, service = install['applet_id'], install['service_id']
    effective_scope = {'kind': 'realm', 'realm_id': realm}
    control_scope = {'kind': 'realm_control', 'realm_id': realm}
    service_actor = {'kind': 'service', 'service_id': service}
    require(governor != account_station and governor != service and account_station != service and
            install['effective_scope'] == effective_scope and not install['rejections'] and
            package['service_id'] == service and package['applet_id'] == applet and
            package['registration_epoch'] == install['registration_epoch'] and
            e['service_resolution']['service_id'] == service and
            e['service_resolution']['service_kind'] == 'applet_service' and
            e['governor_resolution']['service_id'] == governor and
            e['governor_resolution']['service_kind'] == 'station',
            'Applet management lacks three independent actual Service/Station identities')

    def rows(operation, request=None, response=None):
        found = [row for row in exchanges if row['operation_id'] == operation and
                 (request is None or row['request_body'] == request) and
                 (response is None or row['response_body'] == response)]
        require(bool(found), 'Applet management lacks an exact real exchange for ' + operation)
        for row in found:
            require(200 <= row['response_status'] < 300 and
                    row['explicit_request_headers']['arkret-operation'] == operation and
                    decode(row['request_json_base64url']) == row['request_body'] and
                    decode(row['decoded_response_bytes_base64url']) == row['response_body'],
                    'Applet operation changed its actual request/response originals')
        return found

    ghost_operation = 'ak.self.applet.ghost.command.preview.v1'
    bot_operation = 'ak.self.applet.bot.command.preview.v1'
    author_operation = 'ak.edge.applet.managed_actor.command.author.v1'
    self_operation = 'ak.self.applet.configuration.command.submit.v1'
    peer_operation = 'ak.peer.applet.configuration.command.submit.v1'
    execute_operation = 'ak.edge.applet.configuration.command.execute.v1'
    transaction_operation = 'ak.edge.applet.command.transaction.v1'
    review_operation = 'ak.self.management_review.command.request.v1'
    decision_operation = 'ak.self.management_review.command.decide.v1'
    status_operation = 'ak.self.management_review.read.status.v1'
    require(set(scope) == {ghost_operation, bot_operation, author_operation, self_operation,
                          peer_operation, execute_operation, transaction_operation,
                          review_operation, decision_operation, status_operation},
            'Applet management scope omitted a registered operation')
    registration, grant = e['registration'], e['grant']
    require(install['registration_event_ref'] == registration['event']['event_id'] and
            len(install['capability_grant_refs']) == 1 and
            grant['event']['payload']['grant']['subject'] == service_actor and
            grant['event']['payload']['grant']['actions'] == package['requested_scopes'],
            'Applet management changed its accepted installation originals')
    quota = [c for c in grant['event']['payload']['grant']['constraints'] if c['constraint_kind'] == 'quota']
    require(len(quota) == 1 and quota[0]['max_operation_count'] == 3 and
            quota[0]['period'] == 'P1D' and quota[0]['constraint_scope'] == 'per_realm',
            'Applet management lacks a real finite creation quota')
    for name, operation in [('ghost', ghost_operation), ('bot', bot_operation)]:
        preview = e[name + '_preview']
        rows(operation, e[name + '_preview_request'], preview)
        token = preview['authoring_request']
        basis = token['basis']
        require(basis['applet_id'] == applet and basis['service_id'] == service and
                basis['effective_scope'] == effective_scope and
                basis['target_station_id'] == token['governance_station_id'] == governor and
                basis['registration_event_ref'] == registration['event']['event_id'] and
                basis['authorization_ref'] == install['capability_grant_refs'][0] and
                basis['package_digest'] == package['package_digest'] and
                token['proof']['audience_id'] == service and bool(token['proof']['jws']),
                'managed preview lost the exact governor, installation, Grant or package')
    ghost = e['ghost_event']
    authored = rows(author_operation, {'authoring_request': e['ghost_preview']['authoring_request']},
                    {'create_event': ghost})
    require(len(authored) >= 2 and e['ghost_author_replay'] == ghost,
            'managed authoring replay changed the frozen original Event')
    request = e['review_request']
    target_digest = 'sha256:' + digest(ghost)
    require(request['target'] == {'kind': 'event', 'event': ghost} and
            request['requester_actor_id'] == service_actor and
            request['effective_scope'] == effective_scope and request['management_operation'] == 'map_ghost',
            'management review does not bind the exact Service-authored target')
    rows(review_operation, request, e['pending'])
    for name, status in [('pending', 'pending'), ('pending_status', 'pending'),
                         ('approved', 'approved'), ('consumed', 'consumed')]:
        require(e[name]['request_id'] == request['request_id'] and e[name]['status'] == status and
                e[name]['target_digest'] == target_digest, 'management review changed its exact private target/state')
    lookup = {'request_id': request['request_id']}
    rows(status_operation, lookup, e['pending_status'])
    rows(status_operation, lookup, e['consumed'])
    decision = e['decision']
    rows(decision_operation, decision, e['approved'])
    require(decision['request_id'] == request['request_id'] and decision['expected_status'] == 'pending' and
            decision['decision'] == 'approve' and len(decision['approval_signatures']) == 1 and
            e['approved']['approval_signatures'] == decision['approval_signatures'],
            'native administrator decision changed its exact original vote')
    vote = decision['approval_signatures'][0]
    require(vote['input']['approval_context'] == {'context_kind': 'management', 'request_id': request['request_id'],
                'management_operation': 'map_ghost', 'effective_scope': effective_scope} and
            vote['input']['approval_target'] == {'target_kind': 'event', 'event_id': ghost['event_id']} and
            vote['input']['request_canonical_digest'] == target_digest and
            vote['input']['operation'] == 'ak.self.events.command.submit.v1' and
            vote['input']['action'] == 'ak.applet.ghost.provision' and
            vote['input']['initiating_actor_id'] == service_actor and
            vote['proof']['verification_method'] == e['approver_method'] and bool(vote['proof']['jws']) and
            e['unapproved']['status'] == 403 and e['admission_replay'] == e['admitted'],
            'review approval substituted its accepted native Device, action or target')

    configuration = e['configuration_request']
    configure = configuration | {'command': 'configure'}
    rows(self_operation, configure, e['configured'])
    peer_request = {'requester_account_id': e['administrator']['account_id'], 'request': configure}
    peers = rows(peer_operation, peer_request, e['configured'])
    require(all(row['explicit_request_headers']['source-service-id'] == account_station and
                row['explicit_request_headers']['destination-service-id'] == governor for row in peers),
            'configuration did not traverse the actual Account Station to governor peer route')
    execution = e['source_execution']
    source = e['configured']['source_response_body']
    sources = rows(execute_operation, execution, source)
    require(execution == e['cold_source_request'] and e['cold_source_response'] == source and
            e['configured']['admission_status'] == 'accepted' and
            e['configured']['request_id'] == configuration['intent']['request_id'] == execution['intent']['request_id'] and
            execution['intent']['registration_ref']['event_id'] == registration['event']['event_id'] and
            execution['intent']['registration_epoch'] == install['registration_epoch'] and
            execution['intent']['originating_actor_id'] == e['administrator'] and
            execution['intent']['service_id'] == source['service_id'] == service and
            source['intent_digest'] == 'sha256:' + digest(execution['intent']) and
            source['create_event'] == e['bot_committed']['event'] and bool(source['proof']['jws']) and
            e['not_started']['admission_status'] == 'not_started' and
            all(e[name] == e['configured'] for name in ['replay', 'recover', 'cold_recover']) and
            e['conflict']['status'] == 409 and len(sources) >= 2,
            'configuration or actual cold Applet replay changed immutable source bytes/proof/intent')
    state = e['snapshots']
    require(state['before_previews'] == state['after_previews'] and
            state['before_conflict'] == state['after_conflict'],
            'native preview/replay/conflict wrote business effects')
    canonical = ['events', 'committed', 'actors', 'actor_current', 'installations', 'registration_instances',
                 'registration_current', 'sources', 'grants', 'quota_counters', 'quota_buckets', 'quota_consumptions']
    for left, right in [('before_pending', 'pending'), ('pending', 'approved'), ('completed', 'after_conflict')]:
        require(all(state[left][key] == state[right][key] for key in canonical),
                'private review or configuration replay altered actual canonical/current/quota effects')
    final = state['after_conflict']
    require(len(final['actors']) == len(final['completions']) == len(final['quota_consumptions']) == 2 and
            sum(row['consumed'] for row in final['quota_counters']) == 2 and
            all(row['grant_id'] == install['capability_grant_refs'][0] for row in final['quota_consumptions']) and
            len(final['committed']) == len(state['approved']['committed']) + 2 and
            len(final['events']) == len(state['approved']['events']) + 2,
            'native creation/quota charged or accepted another operation')
    completion_exchanges = rows(transaction_operation)
    cold_rows = [json.loads(row[1]) for row in e['cold']['records']['originals']]
    for name, role in [('ghost_committed', 'ghost'), ('bot_committed', 'bot')]:
        original = e[name]
        event, commit = original['event'], original['commit']
        actor = event['payload']['actor_id']
        require(event['scope_ref'] == control_scope and commit['stream_ref'] == control_scope and
                event['kind'] == 'ak.realm.actor.create' and event['actor_id'] == service_actor and
                event['payload']['actor_role'] == role and actor['kind'] == 'realm' and
                actor['realm_actor_id']['realm_id'] == realm and event['payload']['creation_scope'] == effective_scope and
                commit['event_ref'] == event['event_id'] and final['committed'].count(original) == 1,
                'accepted native creation changed its full Realm identity or original Event/Commit')
        require(sum(row['event_id'] == event['event_id'] and row['commit_id'] == commit['commit_id'] for row in final['actors']) == 1 and
                any(row['creation_ref']['event_id'] == event['event_id'] and row['delivered_at'] for row in final['completions']),
                'native identity/delivery was not durably installed exactly once')
        for collection in (cold_rows, [row['request_body'] for row in completion_exchanges]):
            require(any(body['applet_id'] == applet and body['source_id'] == governor and
                        body['authoring_context']['material']['material']['event'] == event and
                        body['authoring_context']['material']['material']['commit'] == commit
                        for body in collection), 'actual completion/cold journal lost an accepted original')
    require(e['ghost_committed']['event'] == ghost and
            e['ghost_committed']['event']['payload']['actor_id'] != e['bot_committed']['event']['payload']['actor_id'],
            'independent Ghost and Bot collapsed into one identity')
    cold = e['cold']
    stopped, restarted = cold['stopped']['before'], cold['restarted']
    require(cold['stopped']['waited'] is True and stopped['pid'] != restarted['pid'] and
            stopped['executable'] == restarted['executable'] and stopped['sha256'] == restarted['sha256'] and
            stopped['origin'] == restarted['origin'] and
            stopped['role'] == restarted['role'] == 'cotest_managed_applet_host_worker' and
            restarted in e['processes'] and len(e['processes']) == 5 and
            len(cold['records']['originals']) == 2 and len(cold['records']['configurations']) == 1 and
            re.fullmatch('[0-9a-f]{64}', cold['records']['configurations'][0][1]) is not None,
            'cold Applet recovery lacks an actual kill/wait/restart with durable original records')
    origin = urlsplit(restarted['origin'])
    require(all(urlsplit(row['url']).netloc == origin.netloc and
                row['explicit_request_headers']['source-service-id'] == governor and
                row['explicit_request_headers']['destination-service-id'] == service
                for row in authored + sources + completion_exchanges),
            'Edge operations reached a different host or substituted their actual governor source')
