#!/usr/bin/env python3
"""Mandatory M7 acceptance: external CI identity -> durable automation -> M3/M1/M6/M2/M5 ->
approval -> stable -> M4, with signed outbound events, retries, replay and crash recovery.

Everything between the two external parties (a GitHub-style OIDC issuer and an HTTPS webhook
receiver) is the real LibreHub stack: real API process, real Git over HTTPS, real Flatpak build,
signed flat-manager publication and a normal Flatpak client. Without a configured publishing
stack (LIBREHUB_FLAT_MANAGER_URL) the script runs only the stages that need no Flatpak build and
says so explicitly in its proof file; it never reports a stage it did not execute as passed.
"""
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from m7_fixtures import FakeGitHub, HttpsReceiver
from source_fixture import REPOSITORY, SourceFixture

ROOT = Path(__file__).resolve().parents[1]
API = 'http://127.0.0.1:8080'
PUBLIC = os.environ.get('LIBREHUB_PUBLIC_BASE_URL', 'http://localhost:8090').rstrip('/')
APP = 'org.librehub.ProjectHello'
AUDIENCE = 'librehub-m7-acceptance'
FULL = bool(os.environ.get('LIBREHUB_FLAT_MANAGER_URL'))
CLI = ROOT / 'target/debug/librehub'
ADMIN = ROOT / 'target/debug/librehub-admin'
PROOF_DIR = ROOT / 'data/m7-proof'

RELEASE_PIPELINE = {
    'name': 'Release Pipeline',
    'triggers': [{'type': 'ci'}, {'type': 'manual'}],
    'steps': [
        {'id': 'build', 'uses': 'librehub/build'},
        {'id': 'verify', 'uses': 'librehub/verify-provenance', 'needs': ['build']},
        {'id': 'publish-beta', 'uses': 'librehub/publish', 'needs': ['verify'], 'with': {'channel': 'beta'}},
        {'id': 'security', 'uses': 'librehub/check-security', 'needs': ['publish-beta']},
        {'id': 'approval', 'uses': 'librehub/approval', 'needs': ['security'], 'with': {'required': True}},
        {'id': 'publish-stable', 'uses': 'librehub/promote', 'needs': ['approval'], 'with': {'channel': 'stable'}},
    ],
    'policy': {'require_valid_build_attestation': True, 'require_security_analysis_complete': True},
}
STACKLESS_PIPELINE = {
    'name': 'Release Pipeline',
    'triggers': [{'type': 'ci'}, {'type': 'manual'}],
    'steps': [{'id': 'build', 'uses': 'librehub/build'}],
}
PROBE = {'name': 'Probe', 'triggers': [{'type': 'manual'}], 'steps': [{'id': 'build', 'uses': 'librehub/build'}]}

proof = {'mode': 'full-stack' if FULL else 'stackless (no Flatpak publishing stack configured)', 'stages': {}, 'skipped': []}


def stage(name, detail=True):
    proof['stages'][name] = detail
    print(f'[m7] {name}: ok', flush=True)


def skip(name, reason):
    proof['skipped'].append({'stage': name, 'reason': reason})
    print(f'[m7] SKIPPED {name}: {reason}', flush=True)


def run(args, env, timeout=1800, **kw):
    return subprocess.check_output([str(a) for a in args], env=env, text=True, timeout=timeout, **kw).strip()


def wait_for(predicate, timeout=1200, what='condition', interval=0.3):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except (urllib.error.URLError, ConnectionError, AssertionError):
            pass
        time.sleep(interval)
    raise TimeoutError(what)


class Server:
    def __init__(self, env, log):
        self.env, self.log, self.process = env, log, None
        self.token = None

    def start(self, automation_stage=None, source_stage=None):
        env = self.env.copy()
        for name, value in [('LIBREHUB_TEST_AUTOMATION_FAULT_STAGE', automation_stage), ('LIBREHUB_TEST_SOURCE_FAULT_STAGE', source_stage)]:
            if value:
                env[name] = value
            else:
                env.pop(name, None)
        self.process = subprocess.Popen([str(ROOT / 'target/debug/librehub-api')], env=env, stdout=self.log, stderr=self.log)
        wait_for(self.ready, 300, 'API readiness')

    def ready(self):
        if self.process.poll() is not None:
            raise RuntimeError('API process exited; see api.log')
        try:
            with urllib.request.urlopen(API + '/ready', timeout=10) as response:
                value = json.load(response)
        except urllib.error.HTTPError as e:
            value = json.load(e)
        parts = value['components']
        local = all(parts[k] in ('ok',) for k in ['database', 'automation_worker', 'outbound_delivery']) and parts['scheduler'] in ('ok', 'disabled')
        return value['ready'] if FULL else local

    def stop(self, crash=False):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
            self.process.wait(timeout=120)

    def call(self, method, path, body=None, token='default', timeout=60):
        token = self.token if token == 'default' else token
        data = None if body is None else json.dumps(body).encode()
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request(API + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            return e.code, (json.loads(raw) if raw else None)

    def ok(self, method, path, body=None, token='default'):
        status, value = self.call(method, path, body, token)
        assert 200 <= status < 300, (method, path, status, value)
        return value


def marker(work, stage_name, server, timeout=300):
    path = work / 'data' / f'automation-fault-{stage_name}'
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        if server.process.poll() is not None:
            raise RuntimeError(f'API stopped before fault barrier {stage_name}')
        time.sleep(0.05)
    assert path.exists(), stage_name
    path.unlink()


def db(work):
    return sqlite3.connect(f'file:{work / "data/builds.sqlite3"}?mode=ro', uri=True, timeout=30)


def main():
    PROOF_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='librehub-m7-') as temporary:
        work = Path(temporary)
        fixture = SourceFixture(work / 'git')
        github = FakeGitHub(work, AUDIENCE)
        receiver = HttpsReceiver(work)
        log = open(PROOF_DIR / 'api.log', 'w+')
        env = os.environ.copy()
        env.update(fixture.env())
        env.update({
            'LIBREHUB_DATA_DIR': str(work / 'data'),
            'LIBREHUB_OIDC_AUDIENCE': AUDIENCE, 'LIBREHUB_OIDC_ISSUER': github.issuer,
            'LIBREHUB_OIDC_JWKS_URL': github.issuer + '/.well-known/jwks', 'LIBREHUB_OIDC_INSECURE_FOR_TESTS': '1',
            'LIBREHUB_WEBHOOK_ALLOW_LOOPBACK_FOR_TESTS': '1', 'LIBREHUB_WEBHOOK_CA_FILE': str(receiver.ca),
            'LIBREHUB_WEBHOOK_BACKOFF_BASE_SECONDS': '2',
            'LIBREHUB_TEST_VULNERABILITY_FIXTURE': '[]',
            'LIBREHUB_AUTOMATION_MAX_RUNS_PER_HOUR': '600',
        })
        if FULL:
            env['LIBREHUB_ATTESTOR_KEY_FILE'] = str(work / 'attestor.seed')
            env['LIBREHUB_ATTESTOR_KEYS_FILE'] = str(work / 'trusted-keys.json')
            env['LIBREHUB_SUPPLY_CHAIN_POLICY'] = 'audit_only'
            runtime = env.get('LIBREHUB_DOCKER', 'docker')
            image = env.get('LIBREHUB_WORKER_IMAGE', 'librehub-worker:m1')
            image_id = run([runtime, 'image', 'inspect', '--format={{.Id}}', image], env)
            env['LIBREHUB_ALLOWED_WORKER_IMAGE_IDS'] = image_id if image_id.startswith('sha256:') else 'sha256:' + image_id
            keys = json.loads(run([ADMIN, 'attestor', 'provision', env['LIBREHUB_ATTESTOR_KEY_FILE'], env['LIBREHUB_ATTESTOR_KEYS_FILE']], env))
            (PROOF_DIR / 'trusted-keys.json').write_text(json.dumps(keys))
        else:
            stub = work / 'docker-stub'
            stub.write_text('#!/bin/sh\ncase "$1" in container) exit 0;; *) echo "no container runtime in stackless mode" >&2; exit 1;; esac\n')
            stub.chmod(0o755)
            env['LIBREHUB_DOCKER'] = str(stub)
        developer = json.loads(run([ADMIN, 'create-developer', 'M7 acceptance'], env))
        other = json.loads(run([ADMIN, 'create-developer', 'M7 other developer'], env))
        token = json.loads(run([ADMIN, 'create-token', developer['id'], 'M7 acceptance'], env))['token']
        other_token = json.loads(run([ADMIN, 'create-token', other['id'], 'M7 other'], env))['token']
        server = Server(env, log)
        server.token = token
        secrets = [token, other_token]

        def cli(args, mode='oidc', check=True, extra=None, timeout=1800):
            cli_env = {'PATH': os.environ['PATH'], 'HOME': str(work), 'LIBREHUB_URL': API,
                       'LIBREHUB_CONFIG_DIR': str(work / 'cli-config'), 'LIBREHUB_TIMEOUT': '1500'}
            outputs = work / 'github-output'
            outputs.write_text('')
            if mode == 'oidc':
                cli_env.update(github.cli_env(project, outputs))
            elif mode == 'token':
                cli_env['LIBREHUB_TOKEN'] = token
            elif mode == 'other':
                cli_env['LIBREHUB_TOKEN'] = other_token
            cli_env.update(extra or {})
            result = subprocess.run([str(CLI), *args], env=cli_env, capture_output=True, text=True, timeout=timeout)
            if check and result.returncode != 0:
                raise AssertionError(f'librehub {args} exited {result.returncode}\n{result.stdout}\n{result.stderr}')
            written = dict(line.split('=', 1) for line in outputs.read_text().splitlines() if '=' in line)
            for secret in secrets:
                assert secret not in result.stdout and secret not in result.stderr, 'CLI leaked a token'
            return result, written

        project = None
        try:
            server.start()
            project = server.ok('POST', '/api/v1/projects', {
                'slug': 'm7-hello', 'display_name': 'M7 Hello', 'repository': {'provider': 'git', 'url': REPOSITORY},
                'default_branch': 'main', 'auto_build': False, 'build_branches': ['main'], 'build_tags': True})['project']['id']
            github.sha = fixture.commit1

            # --- Trusted GitHub Actions identity, registered through the CLI --------------------------------
            policy_file = work / 'policy.json'
            policy_file.write_text(json.dumps(github.policy()))
            cli(['integration', 'oidc-add', '--project', project, '--name', 'gha', '--policy', policy_file], mode='token')
            who, _ = cli(['--json', 'auth', 'status'])
            identity = json.loads(who.stdout)
            assert identity['source'] == 'github-oidc' and identity['federated'] and identity['project_id'] == project
            for forbidden in ['publishes:write', 'releases:approve', 'automations:write', 'tokens:write', 'operator']:
                assert forbidden not in identity['scopes'], forbidden
            assert not (work / 'cli-config').exists() or not list((work / 'cli-config').iterdir()), 'CI credential must not be persisted'
            stage('oidc_identity_registered_and_exchanged_through_production_verifier')

            # --- OIDC negative cases against the live verifier --------------------------------------------------
            def exchange(jwt):
                request = urllib.request.Request(API + '/api/v1/integrations/github/oidc/exchange', data=json.dumps({'project_id': project}).encode(),
                                                 headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + jwt})
                try:
                    with urllib.request.urlopen(request, timeout=30) as response:
                        return response.status, json.load(response)
                except urllib.error.HTTPError as e:
                    return e.code, json.load(e)
            denied = {
                'wrong_audience': exchange(github.mint(audience='https://github.com/octo')),
                'wrong_repository': exchange(github.mint(repository_id='1', sub='repo:octo/hello:ref:refs/heads/main')),
                'wrong_owner': exchange(github.mint(repository_owner_id='1')),
                'wrong_branch': exchange(github.mint(ref='refs/heads/evil', sub='repo:octo/hello:ref:refs/heads/evil')),
                'wrong_workflow': exchange(github.mint(workflow_ref='octo/hello/.github/workflows/evil.yml@refs/heads/main')),
                'expired': exchange(github.mint(exp=int(time.time()) - 600, iat=int(time.time()) - 900, nbf=int(time.time()) - 900)),
                'pull_request': exchange(github.mint(event_name='pull_request', ref='refs/pull/1/merge', sub='repo:octo/hello:pull_request')),
            }
            for name, (status, body) in denied.items():
                assert status in (401, 403), (name, status, body)
                assert 'token' not in body, name
            replayed = github.mint()
            first_status, first = exchange(replayed)
            assert first_status == 200, first
            assert exchange(replayed)[0] == 403, 'an identity token can be exchanged once'
            federated = first['token']
            status, body = server.call('POST', '/api/v1/approvals/00000000-0000-0000-0000-000000000000/approve', token=federated)
            assert status == 403, (status, body)
            assert server.call('GET', '/api/v1/tokens', token=federated)[0] == 403
            assert server.call('GET', '/api/v1/projects', token=federated)[0] == 403
            secrets.append(federated)
            stage('oidc_denials_replay_and_scope_confinement', {k: v[0] for k, v in denied.items()})

            # --- Automation + outbound webhook ----------------------------------------------------------------
            created = server.ok('POST', f'/api/v1/projects/{project}/automations', {'spec': RELEASE_PIPELINE if FULL else STACKLESS_PIPELINE})
            automation = created['id']
            assert created['current_version'] == 1
            server.ok('POST', f'/api/v1/projects/{project}/automations', {'spec': PROBE})
            hook = server.ok('POST', f'/api/v1/projects/{project}/integrations/webhooks', {
                'url': receiver.url, 'description': 'M7 acceptance receiver',
                'event_types': ['automation.started', 'automation.completed', 'automation.failed', 'automation.approval_required',
                                'build.started', 'build.succeeded', 'build.failed', 'publication.started', 'publication.succeeded',
                                'security.analysis_ready', 'attestation.ready']})
            receiver.secret = hook['secret']
            secrets.append(receiver.secret)
            assert 'whsec_' in receiver.secret and receiver.secret not in json.dumps(
                server.ok('GET', f'/api/v1/projects/{project}/integrations/webhooks'))
            stage('automation_and_signed_webhook_configured')

            # --- Release run #1: external CI identity drives the whole pipeline -------------------------
            if not FULL:
                result, out = cli(['ci', 'build', '--project', project, '--automation', 'Release Pipeline'])
                run_one = server.ok('GET', f'/api/v1/projects/{project}/runs?limit=10')[0]
                assert run_one['source_commit'] == fixture.commit1 and run_one['trigger'] == 'ci'
                failed = wait_for(lambda: (lambda r: r if r['status'] in ('failed', 'completed') else None)(
                    server.ok('GET', f'/api/v1/projects/{project}/automations/runs/{run_one["id"]}')), 300, 'stackless run to finish')
                assert failed['status'] == 'failed' and failed['error']['code'] in ('build_failed', 'source_failed'), failed
                stage('ci_run_resolves_pinned_commit_and_fails_closed_without_builder', failed['error']['code'])
                for name in ['m3_to_m1_flatpak_build', 'm6_provenance_verification', 'm2_beta_publication', 'signed_installation',
                             'm5_security_analysis_gate', 'approval_and_stable_promotion', 'm6_stable_release_attestation',
                             'm4_catalog_update', 'failure_injection_after_build']:
                    skip(name, 'requires the Flatpak build and publishing stack (LIBREHUB_FLAT_MANAGER_URL)')
            else:
                full_stack_flow(work, fixture, github, receiver, server, cli, project, automation, env, token, other_token, secrets)

            # --- Webhook receiver: HMAC, outage, bounded retry and recovery --------------------------------
            webhook_resilience(work, server, receiver, project, cli, github, fixture)
            # --- Outbound crash boundaries -------------------------------------------------------------------
            outbound_crashes(work, server, receiver, project, fixture.commit1)

            # Replay of an already processed external trigger changes nothing.
            before = counts(work)
            github.run_id = 9000
            github.sha = fixture.commit1
            cli(['ci', 'build', '--project', project, '--automation', 'Release Pipeline'])
            after = counts(work)
            assert before == after, (before, after)
            stage('replayed_external_trigger_creates_no_duplicate_work', after)

            proof['counts'] = counts(work)
            proof['receiver_event_types'] = sorted({e['event_type'] for e in receiver.events()})
            proof['receiver_signed_requests'] = sum(1 for r in receiver.received if r['verified'])
            proof['receiver_unverified_requests'] = sum(1 for r in receiver.received if not r['verified'])
            assert proof['receiver_unverified_requests'] == 0
            for secret in secrets:
                assert secret not in json.dumps(proof)
            (PROOF_DIR / 'm7-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
            (ROOT / 'data/m7-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
            print(json.dumps(proof, indent=2))
        except BaseException:
            log.flush()
            log.seek(0)
            text = log.read()[-20000:]
            for secret in secrets:
                text = text.replace(secret, '[REDACTED]')
            print(text)
            raise
        finally:
            server.stop()
            receiver.stop()
            github.close()
            fixture.close()
            log.close()


def counts(work):
    with db(work) as c:
        return {
            'runs': c.execute('SELECT count(*) FROM automation_runs').fetchone()[0],
            'source_events': c.execute('SELECT count(*) FROM source_events').fetchone()[0],
            'builds': c.execute('SELECT count(*) FROM builds').fetchone()[0],
            'publications': c.execute('SELECT count(*) FROM publishes').fetchone()[0],
        }


def webhook_resilience(work, server, receiver, project, cli, github, fixture):
    """Receiver outage and 5xx: bounded retries, stable identity, recovery, replay."""
    probe = next(a['id'] for a in server.ok('GET', f'/api/v1/projects/{project}/automations') if a['name'] == 'Probe')

    def newest_delivery(event_type):
        rows = server.ok('GET', f'/api/v1/projects/{project}/integrations/deliveries?limit=100')
        return next((d for d in rows if d['event_type'] == event_type), None)

    # 1. The receiver answers 503: LibreHub retries with bounded backoff and keeps the identity stable.
    receiver.mode = 'status:503'
    started = server.ok('POST', f'/api/v1/projects/{project}/automations/{probe}/run', {'idempotency_key': 'outage-1', 'commit': fixture.commit1})
    run_id = started['run']['id']
    delivery = wait_for(lambda: (lambda d: d if d and d['attempts'] >= 2 else None)(newest_delivery('automation.started')), 120, 'retry after 503')
    assert delivery['status'] in ('retry_wait', 'delivering', 'pending'), delivery
    # 2. The receiver disappears entirely (connection refused), then comes back.
    receiver.stop()
    time.sleep(5)
    receiver.mode = 'ok'
    receiver.start()
    delivered = wait_for(lambda: (lambda d: d if d and d['status'] == 'delivered' else None)(newest_delivery('automation.started')), 180, 'recovery after outage')
    assert 2 <= delivered['attempts'] <= 8, delivered
    received = [e for e in receiver.events('automation.started') if e['data']['run_id'] == run_id]
    assert len(received) == 1, ('the receiver processed the event exactly once after retries', len(received), [(r['status'], r['verified']) for r in receiver.received][-8:])
    assert received[0]['event_id'] and received[0]['delivery_id'] == delivered['id']
    assert received[0]['origin']['kind'] == 'automation' and received[0]['project_id'] == project
    # 3. Manual replay: a new delivery of the same event; the receiver deduplicates by event ID.
    replay = server.ok('POST', f'/api/v1/projects/{project}/integrations/deliveries/{delivered["id"]}/replay')
    assert replay['id'] != delivered['id'] and replay['event_id'] == delivered['event_id']
    wait_for(lambda: len([e for e in receiver.events('automation.started') if e['data']['run_id'] == run_id]) == 2, 120, 'replay delivery')
    again = [e for e in receiver.events('automation.started') if e['data']['run_id'] == run_id]
    assert len({e['event_id'] for e in again}) == 1 and len({e['delivery_id'] for e in again}) == 2
    # 4. A rotated secret takes effect immediately; the old one no longer verifies.
    old = receiver.secret
    rotated = server.ok('POST', f'/api/v1/projects/{project}/integrations/webhooks/{server.ok("GET", f"/api/v1/projects/{project}/integrations/webhooks")[0]["id"]}/rotate')
    receiver.secret = rotated['secret']
    assert receiver.secret != old
    rotated_run = server.ok('POST', f'/api/v1/projects/{project}/automations/{probe}/run', {'idempotency_key': 'after-rotation', 'commit': fixture.commit1})['run']['id']
    wait_for(lambda: any(e['data'].get('run_id') == rotated_run for e in receiver.events('automation.started')), 120, 'delivery signed with the rotated secret')
    assert sum(1 for r in receiver.received if not r['verified']) == 0
    stage('signed_outbound_events_retry_outage_recovery_replay_rotation', {'attempts_to_deliver': delivered['attempts']})


def outbound_crashes(work, server, receiver, project, commit):
    """Crash at the two outbound boundaries: after event admission and during delivery."""
    probe = next(a['id'] for a in server.ok('GET', f'/api/v1/projects/{project}/automations') if a['name'] == 'Probe')
    for index, boundary in enumerate(['after_event_admission', 'during_delivery']):
        server.stop(crash=True)
        server.start(automation_stage=boundary)
        key = f'crash-{boundary}'
        status, started = server.call('POST', f'/api/v1/projects/{project}/automations/{probe}/run', {'idempotency_key': key, 'commit': commit})
        assert status == 202, started
        marker(work, boundary, server)
        server.stop(crash=True)
        server.start()
        run_id = started['run']['id']
        wait_for(lambda: any(e['data'].get('run_id') == run_id for e in receiver.events('automation.started')), 180, f'event delivered after crash at {boundary}')
        matching = [e for e in receiver.events('automation.started') if e['data'].get('run_id') == run_id]
        assert len({e['event_id'] for e in matching}) == 1, 'one event identity regardless of retries'
        with db(work) as c:
            assert c.execute("SELECT count(*) FROM integration_deliveries WHERE event_id=?", (matching[0]['event_id'],)).fetchone()[0] == 1
    stage('outbound_crash_boundaries_after_event_admission_and_during_delivery')


def full_stack_flow(work, fixture, github, receiver, server, cli, project, automation, env, token, other_token, secrets):
    client = env.copy()
    for name in list(client):
        if name.startswith(('LIBREHUB_', 'REPO_')):
            client.pop(name)

    def flatpak_client(name):
        c = client.copy()
        for key, relative in [('HOME', name), ('XDG_DATA_HOME', name + '/data'), ('XDG_CACHE_HOME', name + '/cache'),
                              ('XDG_CONFIG_HOME', name + '/config'), ('XDG_RUNTIME_DIR', name + '/run')]:
            c[key] = str(work / relative)
            Path(c[key]).mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(c['XDG_RUNTIME_DIR'], 0o700)
        run(['flatpak', 'remote-add', '--user', '--if-not-exists', 'flathub', os.environ.get('LIBREHUB_RUNTIME_REPO_URL', 'https://dl.flathub.org/repo/flathub.flatpakrepo')], c)
        run(['flatpak', 'install', '--user', '--noninteractive', '--no-related', 'flathub', 'org.freedesktop.Platform//25.08'], c)
        return c

    trusted = PROOF_DIR / 'trusted-keys.json'
    github.sha = fixture.commit1
    github.run_id = 9000

    # 7-11: trigger through the CLI with the OIDC identity, build via M1, verify M6, publish beta via M2.
    _, beta = cli(['ci', 'build-and-publish-beta', '--project', project, '--automation', 'Release Pipeline'])
    assert beta['source_commit'] == fixture.commit1 and beta['build_status'] == 'succeeded', beta
    assert beta['publication_status'] == 'succeeded' and beta['flatpak_ref'].startswith('app/' + APP), beta
    runs = server.ok('GET', f'/api/v1/projects/{project}/runs')
    assert len(runs) == 1 and runs[0]['trigger'] == 'ci' and runs[0]['trigger_detail']['repository_id'] == github.repository_id
    build = server.ok('GET', '/api/v1/builds/' + beta['build_id'])
    assert build['provenance']['revision']['commit'] == fixture.commit1
    assert build['provenance']['trigger'] == 'automation'
    _, verified = cli(['ci', 'verify-provenance', '--project', project, '--automation', 'Release Pipeline'])
    assert verified['attestation_status'] == 'verified', verified
    stage('ci_identity_to_pinned_commit_m3_m1_build_m6_provenance_m2_beta', {'source_commit': beta['source_commit']})

    # 12: install the signed beta with a normal Flatpak client and verify beta attestation independently.
    beta_pub = server.ok('GET', '/api/v1/publishes/' + beta['publication_id'])
    beta_client = flatpak_client('client-beta')
    run(['flatpak', 'remote-add', '--user', 'librehub-beta', PUBLIC + '/librehub-beta.flatpakrepo'], beta_client)
    run(['flatpak', 'install', '--user', '--noninteractive', '--no-related', 'librehub-beta', APP], beta_client)
    assert run(['flatpak', 'info', '--user', '--show-commit', APP], beta_client) == beta_pub['result']['published_ref']['commit']
    assert 'revision 1!' in run(['flatpak', 'run', '--user', APP], beta_client)

    def evidence(publication):
        status, body = server.call('GET', f'/api/v1/catalog/apps/{APP}/releases/{publication}/provenance', token=None)
        return body if status == 200 and body['verification']['verified'] else None
    beta_evidence = wait_for(lambda: evidence(beta['publication_id']), 900, 'beta release attestation')
    result, _ = cli(['--json', 'verify', '--app', APP, '--release', beta['publication_id'], '--trusted-keys', trusted], mode='none')
    assert json.loads(result.stdout)['independent_trust_root'] is True
    stage('signed_beta_installation_and_independent_attestation_verification')

    # 13-14: M5 analysis completes; ask for promotion.
    cli(['ci', 'wait-for-security', '--project', project, '--automation', 'Release Pipeline'])
    _, promotion = cli(['ci', 'request-promotion', '--project', project, '--automation', 'Release Pipeline'])
    approval = promotion['approval_id']
    assert approval
    assert server.call('GET', f'/api/v1/projects/{project}/approvals?status=requested')[1][0]['candidate']['source_commit'] == fixture.commit1
    stable_calls = server.ok('GET', f'/api/v1/builds/{beta["build_id"]}/publishes')
    assert [p['channel'] for p in stable_calls] == ['beta'], 'nothing is promoted before approval'
    stage('security_gate_and_promotion_requested')

    # 15: unauthorized approval attempts.
    limited = server.ok('POST', '/api/v1/tokens', {'name': 'cannot approve', 'scopes': ['automations:read', 'automations:run', 'builds:read']})['token']
    secrets.append(limited)
    _, _ = cli(['approval', 'list'], mode='token')
    for who, value in [('other developer', other_token), ('token without releases:approve', limited)]:
        status, body = server.call('POST', f'/api/v1/approvals/{approval}/approve', token=value)
        assert status in (403, 404), (who, status, body)
    ci_token = exchange_token(github, project)
    secrets.append(ci_token)
    assert server.call('POST', f'/api/v1/approvals/{approval}/approve', token=ci_token)[0] == 403
    assert server.ok('GET', f'/api/v1/projects/{project}/approvals')[0]['status'] == 'requested'
    stage('unauthorized_approval_attempts_rejected_server_side')

    # 16-18: authorized approval, stable publication through M2 with its own M6 release attestation.
    cli(['approval', 'approve', approval, '--reason', 'M7 acceptance'], mode='token')
    _, stable = cli(['ci', 'wait-for-publication', '--project', project, '--automation', 'Release Pipeline'])
    assert stable['publication_status'] == 'succeeded' and stable['attestation_status'] == 'verified', stable
    assert stable['publication_id'] != beta['publication_id']
    final = server.ok('GET', f'/api/v1/projects/{project}/automations/runs/{runs[0]["id"]}')
    assert final['status'] == 'completed' and final['stable_publication_id'] == stable['publication_id']
    stable_pub = server.ok('GET', '/api/v1/publishes/' + stable['publication_id'])
    publishes = server.ok('GET', f'/api/v1/builds/{beta["build_id"]}/publishes')
    assert sorted(p['channel'] for p in publishes) == ['beta', 'stable'], 'same validated build, two independent publications'
    stable_evidence = wait_for(lambda: evidence(stable['publication_id']), 900, 'stable release attestation')
    result, _ = cli(['--json', 'verify', '--app', APP, '--release', stable['publication_id'], '--trusted-keys', trusted,
                     '--checksum', stable_pub['result']['published_ref']['commit']], mode='none')
    assert json.loads(result.stdout)['checksum'] == stable_pub['result']['published_ref']['commit']
    assert stable_evidence['release']['predicate']['publicationId'] == stable['publication_id']
    assert beta_evidence['release']['predicate']['publicationId'] == beta['publication_id']
    assert stable_evidence['release']['predicate']['publicationId'] != beta_evidence['release']['predicate']['publicationId'], \
        'the stable release has its own attestation'
    with db(work) as c:
        consumed = c.execute('SELECT status,consumed_at IS NOT NULL FROM automation_approvals WHERE id=?', (approval,)).fetchone()
        assert consumed == ('approved', 1), consumed
    stage('authorized_approval_stable_promotion_with_own_release_attestation')

    # 19: M4 discovery and normal signed installation from the stable remote.
    page = server.ok('GET', f'/api/v1/catalog/apps/{APP}', token=None)
    assert page['current_stable_release']['publication_id'] == stable['publication_id']
    stable_client = flatpak_client('client-stable')
    run(['flatpak', 'remote-add', '--user', 'librehub', PUBLIC + '/librehub.flatpakrepo'], stable_client)
    run(['flatpak', 'install', '--user', '--noninteractive', '--no-related', 'librehub', APP], stable_client)
    assert run(['flatpak', 'info', '--user', '--show-commit', APP], stable_client) == stable_pub['result']['published_ref']['commit']
    stage('m4_catalog_reflects_stable_release_and_signed_stable_installation')

    # 20-21: signed outbound events for this run reached the receiver.
    wait_for(lambda: receiver.events('automation.completed'), 120, 'automation.completed delivery')
    types = {e['event_type'] for e in receiver.events()}
    for expected in ['automation.started', 'build.succeeded', 'publication.succeeded', 'automation.approval_required', 'automation.completed']:
        assert expected in types, (expected, types)
    publication_events = [e for e in receiver.events('publication.succeeded')]
    assert {e['data']['channel'] for e in publication_events} >= {'beta', 'stable'}
    stage('signed_outbound_events_delivered_and_hmac_verified_by_receiver')

    # Run #2 on a new commit with a crash at every automation boundary.
    commit2 = fixture.update('Hello from LibreHub project revision 2!')
    github.sha = commit2
    github.run_id = 9001
    failure_injection(work, server, cli, project, github, commit2, other_token, secrets)


def exchange_token(github, project):
    request = urllib.request.Request(API + '/api/v1/integrations/github/oidc/exchange', data=json.dumps({'project_id': project}).encode(),
                                     headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + github.mint()})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)['token']


def failure_injection(work, server, cli, project, github, commit2, other_token, secrets):
    stages = ['trigger_admitted', 'before_source_bind', 'after_build_bound', 'after_build_complete', 'before_beta_publication',
              'after_beta_publication', 'awaiting_approval', 'after_approval_decision', 'before_stable_publication']
    crashed = []

    def invariants(expect_stable, expect_beta_max):
        with db(work) as c:
            sources = c.execute("SELECT count(*) FROM source_events WHERE json_extract(record,'$.revision.commit')=?", (commit2,)).fetchone()[0]
            builds = c.execute("SELECT count(*) FROM builds b JOIN source_events e ON e.build_id=b.id WHERE json_extract(e.record,'$.revision.commit')=?", (commit2,)).fetchone()[0]
            runs = c.execute("SELECT count(*) FROM automation_runs WHERE source_commit=?", (commit2,)).fetchone()[0]
            beta = c.execute("SELECT count(*) FROM publishes p JOIN builds b ON b.id=p.build_id JOIN source_events e ON e.build_id=b.id WHERE p.channel='beta' AND json_extract(e.record,'$.revision.commit')=?", (commit2,)).fetchone()[0]
            stable = c.execute("SELECT count(*) FROM publishes p JOIN builds b ON b.id=p.build_id JOIN source_events e ON e.build_id=b.id WHERE p.channel='stable' AND json_extract(e.record,'$.revision.commit')=?", (commit2,)).fetchone()[0]
        assert sources <= 1 and builds <= 1 and runs <= 1, (sources, builds, runs)
        assert beta <= expect_beta_max and stable == expect_stable, (beta, stable)

    server.stop(crash=True)
    server.start(automation_stage=stages[0])
    started = None
    for index, boundary in enumerate(stages):
        if boundary == 'trigger_admitted':
            result, _ = cli(['ci', 'build', '--project', project, '--automation', 'Release Pipeline'])
        if boundary == 'after_approval_decision':
            approval = wait_for(lambda: (lambda a: a[0]['id'] if a else None)(server.ok('GET', f'/api/v1/projects/{project}/approvals?status=requested')), 60, 'approval after restart')
            for value in [other_token]:
                assert server.call('POST', f'/api/v1/approvals/{approval}/approve', token=value)[0] in (403, 404)
            threading.Thread(target=lambda: server.call('POST', f'/api/v1/approvals/{approval}/approve', {'reason': 'crash test'}, timeout=8), daemon=True).start()
        marker(work, boundary, server, timeout=1500)
        server.stop(crash=True)
        crashed.append(boundary)
        stable_expected = 0
        invariants(stable_expected, 1)
        if boundary == 'after_approval_decision':
            with db(work) as c:
                row = c.execute("SELECT status,consumed_at FROM automation_approvals ORDER BY rowid DESC LIMIT 1").fetchone()
                assert row[0] == 'approved' and row[1] is None, 'approval persisted before the crash and not yet consumed'
        next_stage = stages[index + 1] if index + 1 < len(stages) else None
        server.start(automation_stage=next_stage)
        # Beta publication and the MODEL's own source handoff cross a restart: M3's source worker boundary too.
    # Final recovery: no more faults; the run must complete with exactly one stable publication.
    run_view = wait_for(lambda: (lambda rs: rs[0] if rs and rs[0]['status'] == 'completed' else None)(
        server.ok('GET', f'/api/v1/projects/{project}/runs?limit=1')), 1800, 'run #2 completion after recovery')
    invariants(1, 1)
    assert run_view['source_commit'] == commit2
    stage('failure_injection_at_every_automation_boundary_recovers_without_duplicates', crashed)


if __name__ == '__main__':
    sys.exit(main())
