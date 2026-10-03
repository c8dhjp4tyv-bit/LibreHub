#!/usr/bin/env python3
"""Mandatory real M1 build -> flat-manager -> signed repository -> Flatpak install."""
import configparser
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.request
from publishing_faults import PublishingFaults

ROOT = Path(__file__).resolve().parents[1]
API = 'http://127.0.0.1:8080'
PUBLIC = os.environ.get('LIBREHUB_PUBLIC_BASE_URL', 'http://localhost:8090').rstrip('/')

def request(path, data=None):
    faults.reconcile_process()
    raw = None if data is None else json.dumps(data).encode()
    with urllib.request.urlopen(urllib.request.Request(API + path, data=raw, headers={'Content-Type': 'application/json'}), timeout=90) as response:
        return json.load(response)

def wait(path, terminal=True):
    end = time.monotonic() + 1200
    while time.monotonic() < end:
        try:
            record = request(path)
        except (urllib.error.URLError, ConnectionResetError, ConnectionRefusedError):
            time.sleep(0.5)
            continue
        if terminal and record['status'] in ['succeeded', 'failed', 'cancelled']:
            assert record['status'] == 'succeeded', record
            return record
        if not terminal and record.get('ready'):
            return record
        if record.get('needs_attention'):
            raise AssertionError(record)
        time.sleep(0.5)
    raise TimeoutError(path)

def fetch(path):
    with urllib.request.urlopen(PUBLIC + path, timeout=30) as response:
        return response.read()

def run(args, env, timeout=900):
    result = subprocess.run(args, env=env, check=True, text=True, stdout=subprocess.PIPE, timeout=timeout)
    return result.stdout.strip()

with tempfile.TemporaryDirectory(prefix='librehub-e2e-') as temp:
    work = Path(temp)
    env = os.environ.copy()
    env['LIBREHUB_DATA_DIR'] = str(work / 'data')
    log = open(work / 'api.log', 'w+')
    faults = PublishingFaults(env['LIBREHUB_FLAT_MANAGER_URL'], str(ROOT / 'target/debug/librehub-api'), env, log)
    try:
        for _ in range(120):
            if faults.process.poll() is not None:
                raise RuntimeError('LibreHub API stopped')
            try:
                if request('/ready')['ready']:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        else:
            raise TimeoutError('Readiness')
        before = hashlib.sha256(fetch('/repo/stable/summary')).hexdigest()
        build = request('/api/v1/builds', json.loads((ROOT / 'examples/org.librehub.Hello.json').read_text()))
        build = wait('/api/v1/builds/' + build['id'])
        publication = request(f'/api/v1/builds/{build["id"]}/publish', {'channel': 'stable'})
        publication = wait('/api/v1/publishes/' + publication['id'])
        assert faults.crashes == ['preparing', 'uploading', 'committing', 'publishing'], faults.crashes
        assert faults.restarts == 4
        # Query the actual backend: lost create replies must not produce duplicate builds.
        token_path = env.get('LIBREHUB_FLAT_MANAGER_TOKEN_FILE')
        token = Path(token_path).read_text().strip() if token_path else env['LIBREHUB_FLAT_MANAGER_TOKEN']
        query = urllib.request.Request(f'{faults.manager_url}/api/v1/build?app-id=org.librehub.Hello', headers={'Authorization': 'Bearer ' + token})
        with urllib.request.urlopen(query, timeout=30) as response:
            remote_builds = json.load(response)
        marker = 'librehub://publication/' + publication['id']
        assert len([b for b in remote_builds if b.get('build_log_url') == marker]) == 1
        duplicate = request(f'/api/v1/builds/{build["id"]}/publish', {'channel': 'stable'})
        assert duplicate['id'] == publication['id']
        after = hashlib.sha256(fetch('/repo/stable/summary')).hexdigest()
        assert before != after, 'Publication must refresh the public summary'
        assert fetch('/repo/stable/summary.sig'), 'Repository summary must be signed'
        repo = configparser.ConfigParser()
        repo.read_string(fetch('/librehub.flatpakrepo').decode())
        assert repo['Flatpak Repo']['GPGKey']
        with urllib.request.urlopen(API + '/librehub.flatpakrepo') as response:
            assert response.read() == fetch('/librehub.flatpakrepo'), 'API and static trust descriptors must agree'

        client = env.copy()
        for name in list(client):
            if name.startswith(('LIBREHUB_', 'REPO_')):
                client.pop(name)
        client.update(HOME=str(work / 'client'), XDG_DATA_HOME=str(work / 'client/data'),
                      XDG_CACHE_HOME=str(work / 'client/cache'), XDG_CONFIG_HOME=str(work / 'client/config'),
                      XDG_RUNTIME_DIR=str(work / 'client/run'))
        for name in ['HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'XDG_RUNTIME_DIR']:
            Path(client[name]).mkdir(parents=True, exist_ok=True, mode=0o700)
        run(['flatpak', 'remote-add', '--user', '--if-not-exists', 'flathub', 'https://dl.flathub.org/repo/flathub.flatpakrepo'], client)
        run(['flatpak', 'install', '--user', '--noninteractive', '--no-related', 'flathub', 'org.freedesktop.Platform//25.08'], client)
        run(['flatpak', 'remote-add', '--user', '--if-not-exists', 'librehub', PUBLIC + '/librehub.flatpakrepo'], client)
        run(['flatpak', 'install', '--user', '--noninteractive', '--no-related', 'librehub', 'org.librehub.Hello'], client)
        ref = run(['flatpak', 'info', '--user', '--show-ref', 'org.librehub.Hello'], client)
        commit = run(['flatpak', 'info', '--user', '--show-commit', 'org.librehub.Hello'], client)
        assert ref == publication['result']['published_ref']['ref_name']
        assert commit == publication['result']['published_ref']['commit']
        assert run(['flatpak', 'info', '--user', '--show-origin', 'org.librehub.Hello'], client) == 'librehub'
        signature = run(['ostree', '--repo=' + str(Path(client['XDG_DATA_HOME']) / 'flatpak/repo'), 'show', '--gpg-verify-remote=librehub', commit], client)
        assert 'signature' in signature.lower(), signature
        assert 'Hello from LibreHub!' in run(['flatpak', 'run', '--user', 'org.librehub.Hello'], client)
        # Beta uses the same publishing and signing implementation with independent repository state.
        beta = request(f'/api/v1/builds/{build["id"]}/publish', {'channel': 'beta'})
        beta = wait('/api/v1/publishes/' + beta['id'])
        run(['flatpak', 'remote-add', '--user', 'librehub-beta', PUBLIC + '/librehub-beta.flatpakrepo'], client)
        assert run(['flatpak', 'remote-info', '--user', '--show-commit', 'librehub-beta', 'org.librehub.Hello'], client) == beta['result']['published_ref']['commit']
        proof = {'build_id': build['id'], 'publication_id': publication['id'], 'flat_manager_build_id': publication['flat_manager_build_id'], 'ref': ref, 'commit': commit, 'signing_fingerprint': publication['result']['signing']['fingerprint'], 'summary_before': before, 'summary_after': after, 'installed': True, 'executed': True, 'signature_verified': True, 'beta_verified': True, 'recovered_after_crashes': faults.crashes, 'remote_create_count': 1}
        (ROOT / 'data/e2e-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
        print(json.dumps(proof, indent=2))
    except BaseException:
        log.flush()
        log.seek(0)
        print(log.read()[-16000:])
        raise
    finally:
        faults.process.send_signal(signal.SIGTERM)
        try:
            faults.process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            faults.process.kill()
            faults.process.wait()
        faults.close()
        log.close()
