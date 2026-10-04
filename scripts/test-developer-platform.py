#!/usr/bin/env python3
"""Mandatory M3 real HTTPS Git -> M1 -> signed M2 -> normal Flatpak client."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from source_fixture import REPOSITORY, SourceFixture

ROOT = Path(__file__).resolve().parents[1]
API = 'http://127.0.0.1:8080'
PUBLIC = os.environ.get('LIBREHUB_PUBLIC_BASE_URL', 'http://localhost:8090').rstrip('/')
APP = 'org.librehub.ProjectHello'

class Api:
    def __init__(self, env, log):
        self.env = env
        self.log = log
        self.process = None
        self.token = None
    def start(self, stage=None):
        env = self.env.copy()
        if stage:
            env['LIBREHUB_TEST_SOURCE_FAULT_STAGE'] = stage
        else:
            env.pop('LIBREHUB_TEST_SOURCE_FAULT_STAGE', None)
        self.process = subprocess.Popen([str(ROOT / 'target/debug/librehub-api')], env=env, stdout=self.log, stderr=self.log)
        self.wait('/ready', lambda value: value.get('ready'))
    def stop(self, crash=False):
        if self.process is None or self.process.poll() is not None:
            return
        self.process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
        self.process.wait(timeout=90)
    def request(self, path, data=None):
        raw = None if data is None else json.dumps(data).encode()
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        with urllib.request.urlopen(urllib.request.Request(API + path, data=raw, headers=headers), timeout=90) as response:
            return json.load(response)
    def wait(self, path, predicate, timeout=1200):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('API process stopped')
            try:
                value = self.request(path)
                if predicate(value):
                    return value
                if value.get('status') in ['failed', 'cancelled'] or value.get('needs_attention'):
                    raise AssertionError(value)
            except (urllib.error.URLError, ConnectionResetError, ConnectionRefusedError):
                pass
            time.sleep(0.2)
        raise TimeoutError(path)
    def successful_build(self, project, trigger):
        event = self.wait(f'/api/v1/projects/{project}/source-events/{trigger["source_event_id"]}', lambda e: e['status'] == 'completed')
        build = self.wait('/api/v1/builds/' + trigger['build_id'], lambda b: b['status'] == 'succeeded')
        assert event['build_id'] == build['id']
        assert build['provenance']['snapshot']['sha256']
        return build

def run(args, env, timeout=900):
    return subprocess.check_output(args, env=env, text=True, timeout=timeout).strip()

def wait_marker(path, process):
    end = time.monotonic() + 180
    while not path.exists() and time.monotonic() < end:
        if process.poll() is not None:
            raise RuntimeError('API stopped before fault barrier')
        time.sleep(0.05)
    assert path.exists(), path.name

with tempfile.TemporaryDirectory(prefix='librehub-m3-') as temporary:
    work = Path(temporary)
    fixture = SourceFixture(work / 'git')
    env = os.environ.copy()
    env.update(fixture.env())
    env['LIBREHUB_DATA_DIR'] = str(work / 'data')
    admin = str(ROOT / 'target/debug/librehub-admin')
    developer = json.loads(run([admin, 'create-developer', 'M3 acceptance developer'], env))
    token = json.loads(run([admin, 'create-token', developer['id'], 'M3 acceptance'], env))['token']
    log = open(work / 'api.log', 'w+')
    api = Api(env, log)
    api.token = token
    try:
        api.start('queued')
        created = api.request('/api/v1/projects', {'slug': 'project-hello', 'display_name': 'Project Hello',
                       'repository': {'provider': 'git', 'url': REPOSITORY}, 'default_branch': 'main',
                       'auto_build': True, 'build_branches': ['main'], 'build_tags': True})
        project = created['project']['id']
        secret = created['webhook_secret']
        manual = api.request(f'/api/v1/projects/{project}/builds', {'ref': 'main'})
        crashes = []
        # One source event crosses three real process crashes before a single M1 handoff.
        for stage, following in [('queued', 'fetching'), ('fetching', 'handoff'), ('handoff', None)]:
            wait_marker(work / 'data' / ('source-fault-' + stage), api.process)
            api.stop(crash=True)
            crashes.append(stage)
            api.start(following)
        first = api.successful_build(project, manual)
        assert first['provenance']['revision']['commit'] == fixture.commit1
        assert first['provenance']['manifest_path'] == 'org.librehub.ProjectHello.json'
        history = api.request(f'/api/v1/projects/{project}/builds')
        assert len(history) == 1
        with sqlite3.connect(work / 'data/builds.sqlite3') as db:
            assert db.execute('SELECT count(*) FROM builds WHERE id=?', (first['id'],)).fetchone()[0] == 1
        publish1 = api.request(f'/api/v1/builds/{first["id"]}/publish', {'channel': 'beta'})
        publish1 = api.wait('/api/v1/publishes/' + publish1['id'], lambda p: p['status'] == 'succeeded')

        client = env.copy()
        for name in list(client):
            if name.startswith(('LIBREHUB_', 'REPO_')):
                client.pop(name)
        for key, relative in [('HOME', 'client'), ('XDG_DATA_HOME', 'client/data'), ('XDG_CACHE_HOME', 'client/cache'),
                              ('XDG_CONFIG_HOME', 'client/config'), ('XDG_RUNTIME_DIR', 'client/run')]:
            client[key] = str(work / relative)
            Path(client[key]).mkdir(parents=True, exist_ok=True, mode=0o700)
        run(['flatpak', 'remote-add', '--user', 'flathub', 'https://dl.flathub.org/repo/flathub.flatpakrepo'], client)
        run(['flatpak', 'install', '--user', '--noninteractive', '--no-related', 'flathub', 'org.freedesktop.Platform//25.08'], client)
        run(['flatpak', 'remote-add', '--user', 'librehub-beta', PUBLIC + '/librehub-beta.flatpakrepo'], client)
        run(['flatpak', 'install', '--user', '--noninteractive', '--no-related', 'librehub-beta', APP], client)
        installed1 = run(['flatpak', 'info', '--user', '--show-commit', APP], client)
        assert installed1 == publish1['result']['published_ref']['commit']
        assert 'revision 1!' in run(['flatpak', 'run', '--user', APP], client)

        # Enable event-snapshotted beta automation, then commit and sign a real GitHub push.
        patch = json.dumps({'auto_publish_channel': 'beta'}).encode()
        with urllib.request.urlopen(urllib.request.Request(API + f'/api/v1/projects/{project}', data=patch, method='PATCH', headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})) as response:
            assert json.load(response)['auto_publish_channel'] == 'beta'
        commit2 = fixture.update('Hello from LibreHub project revision 2!')
        delivery = str(uuid.uuid4())
        payload = json.dumps({'ref': 'refs/heads/main', 'before': fixture.commit1, 'after': commit2, 'deleted': False,
                              'repository': {'clone_url': REPOSITORY, 'full_name': 'librehub/fixture'}}).encode()
        headers = {'Content-Type': 'application/json', 'X-GitHub-Event': 'push', 'X-GitHub-Delivery': delivery,
                   'X-Hub-Signature-256': 'sha256=' + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()}
        webhook_url = API + f'/api/v1/webhooks/github/{project}'
        with urllib.request.urlopen(urllib.request.Request(webhook_url, data=payload, headers=headers)) as response:
            pushed = json.load(response)
        second = api.successful_build(project, pushed)
        assert second['provenance']['revision']['commit'] == commit2
        assert second['provenance']['snapshot']['sha256'] != first['provenance']['snapshot']['sha256']
        assert second['provenance']['revision']['source_ref'] == 'refs/heads/main'
        deadline = time.monotonic() + 1200
        publish2 = None
        while time.monotonic() < deadline:
            publications = api.request(f'/api/v1/builds/{second["id"]}/publishes')
            if publications:
                publish2 = api.wait('/api/v1/publishes/' + publications[0]['id'], lambda p: p['status'] == 'succeeded')
                break
            time.sleep(0.5)
        assert publish2 is not None, 'Auto-publication must complete'
        # Retry after response loss and after restart: exactly one second source/build.
        api.stop(crash=True)
        api.start()
        with urllib.request.urlopen(urllib.request.Request(webhook_url, data=payload, headers=headers)) as response:
            duplicate = json.load(response)
        assert duplicate['status'] == 'duplicate'
        assert duplicate['source_event_id'] == pushed['source_event_id']
        history = api.request(f'/api/v1/projects/{project}/builds')
        assert len(history) == 2, history
        with sqlite3.connect(work / 'data/builds.sqlite3') as db:
            assert db.execute('SELECT count(*) FROM webhook_deliveries WHERE delivery_id=?', (delivery,)).fetchone()[0] == 1
            assert db.execute('SELECT count(*) FROM source_events WHERE build_id=?', (second['id'],)).fetchone()[0] == 1
        run(['flatpak', 'update', '--user', '--noninteractive', '--no-related', APP], client)
        installed_ref = run(['flatpak', 'info', '--user', '--show-ref', APP], client)
        installed2 = run(['flatpak', 'info', '--user', '--show-commit', APP], client)
        assert installed2 == publish2['result']['published_ref']['commit']
        assert installed2 != installed1
        signature = run(['ostree', '--repo=' + str(Path(client['XDG_DATA_HOME']) / 'flatpak/repo'), 'show', '--gpg-verify-remote=librehub-beta', installed2], client)
        assert 'signature' in signature.lower()
        assert 'revision 2!' in run(['flatpak', 'run', '--user', APP], client)
        assert run(['flatpak', 'info', '--user', '--show-origin', APP], client) == 'librehub-beta'
        proof = {'developer_id': developer['id'], 'project_id': project, 'source_commits': [fixture.commit1, commit2],
                 'build_ids': [first['id'], second['id']], 'publish_ids': [publish1['id'], publish2['id']],
                 'snapshot_sha256': [first['provenance']['snapshot']['sha256'], second['provenance']['snapshot']['sha256']],
                 'webhook_delivery_id': delivery, 'installed_ref': installed_ref, 'published_checksum': installed2,
                 'installed_checksum': installed2, 'normal_client_installed': True, 'updated_app_executed': True,
                 'gpg_verified': True, 'duplicate_source_builds': 0, 'source_recovery_stages': crashes,
                 'manifest_path': first['provenance']['manifest_path'], 'transport': 'HTTPS smart Git with disposable CA'}
        assert token not in json.dumps(proof) and secret not in json.dumps(proof)
        (ROOT / 'data/m3-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
        print(json.dumps(proof, indent=2))
    except BaseException:
        log.flush()
        log.seek(0)
        diagnostic = log.read()[-16000:].replace(token, '[REDACTED]').replace(locals().get('secret', 'UNSET-SECRET'), '[REDACTED]')
        print(diagnostic)
        raise
    finally:
        api.stop()
        fixture.close()
        log.close()
