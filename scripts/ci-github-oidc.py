#!/usr/bin/env python3
"""Real GitHub Actions OIDC proof: the job's own identity token is verified against GitHub's
published JWKS by a locally started LibreHub, exchanged for a short-lived project credential and
used by the composite action. No LibreHub secret is stored in GitHub.

`prepare` starts LibreHub and trusts this repository; `verify` inspects the outcome.
On pull_request events the policy (push only) must DENY the exchange.
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = 'http://127.0.0.1:8080'
AUDIENCE = 'librehub-ci-github'
STATE = Path(os.environ.get('RUNNER_TEMP', tempfile.gettempdir())) / 'librehub-oidc-job'


def call(method, path, body=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(API + path, data=None if body is None else json.dumps(body).encode(), method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, (json.loads(raw) if raw else None)


def prepare():
    STATE.mkdir(parents=True, exist_ok=True)
    data = STATE / 'data'
    env = os.environ.copy()
    env.update({'LIBREHUB_DATA_DIR': str(data), 'LIBREHUB_OIDC_AUDIENCE': AUDIENCE})
    stub = STATE / 'docker-stub'
    stub.write_text('#!/bin/sh\ncase "$1" in container) exit 0;; *) exit 1;; esac\n')
    stub.chmod(0o755)
    env['LIBREHUB_DOCKER'] = str(stub)
    admin = ROOT / 'target/debug/librehub-admin'
    developer = json.loads(subprocess.check_output([admin, 'create-developer', 'GitHub OIDC job'], env=env, text=True))
    token = json.loads(subprocess.check_output([admin, 'create-token', developer['id'], 'job'], env=env, text=True))['token']
    print(f'::add-mask::{token}')
    log = open(STATE / 'api.log', 'w')
    process = subprocess.Popen([str(ROOT / 'target/debug/librehub-api')], env=env, stdout=log, stderr=log, start_new_session=True)
    (STATE / 'pid').write_text(str(process.pid))
    for _ in range(300):
        try:
            if call('GET', '/health')[0] == 200:
                break
        except OSError:
            time.sleep(0.2)
    repo = os.environ['GITHUB_REPOSITORY']
    status, project = call('POST', '/api/v1/projects', {'slug': 'oidc-job', 'display_name': 'OIDC job', 'default_branch': 'main',
                           'repository': {'provider': 'github', 'url': f'https://github.com/{repo}'}, 'auto_build': False}, token)
    assert status == 201, project
    project_id = project['project']['id']
    policy = {
        'repository_id': os.environ['GITHUB_REPOSITORY_ID'], 'repository_owner_id': os.environ['GITHUB_REPOSITORY_OWNER_ID'],
        'repository': repo, 'allowed_refs': ['refs/heads/*', 'refs/tags/*'],
        'allowed_workflows': [f'{repo}/.github/workflows/ci.yml@*'], 'allowed_event_types': ['push'],
        'allowed_permissions': ['projects:read', 'builds:read', 'automations:read', 'automations:run'], 'token_ttl_seconds': 300,
    }
    status, connection = call('POST', f'/api/v1/projects/{project_id}/integrations/oidc', {'name': 'this repository', 'policy': policy}, token)
    assert status == 201, connection
    spec = {'name': 'Release Pipeline', 'triggers': [{'type': 'ci'}], 'steps': [{'id': 'build', 'uses': 'librehub/build'}]}
    status, automation = call('POST', f'/api/v1/projects/{project_id}/automations', {'spec': spec}, token)
    assert status == 201, automation
    with open(os.environ['GITHUB_ENV'], 'a') as env_file:
        env_file.write(f'LIBREHUB_JOB_PROJECT={project_id}\nLIBREHUB_JOB_URL={API}\n')
    (STATE / 'owner-token').write_text(token)
    (STATE / 'owner-token').chmod(0o600)


def verify():
    token = (STATE / 'owner-token').read_text()
    project = os.environ['LIBREHUB_JOB_PROJECT']
    event = os.environ['GITHUB_EVENT_NAME']
    outcome = os.environ.get('ACTION_OUTCOME', '')
    runs = call('GET', f'/api/v1/projects/{project}/runs', token=token)[1]
    summary = {'event': event, 'action_outcome': outcome, 'runs': len(runs)}
    try:
        if event == 'push':
            assert outcome == 'success', 'the composite action must authenticate with the real GitHub OIDC token'
            assert len(runs) == 1, runs
            run = runs[0]
            assert run['trigger'] == 'ci' and run['source_commit'] == os.environ['GITHUB_SHA'], run
            assert run['trigger_detail']['repository_id'] == os.environ['GITHUB_REPOSITORY_ID'], run
            assert os.environ.get('ACTION_COMMIT') == os.environ['GITHUB_SHA'], 'action output source_commit'
            summary.update({'run_id': run['id'], 'source_commit': run['source_commit'], 'run_status': run['status']})
            # Cancel through the API; history is preserved.
            status, cancelled = call('POST', f'/api/v1/projects/{project}/automations/runs/{run["id"]}/cancel', token=token)
            assert status in (200, 202), cancelled
            audit = call('GET', f'/api/v1/projects/{project}/integrations/audit', token=token)[1]
            assert any(e['action'] == 'oidc.exchange_succeeded' for e in audit), audit
        else:
            # Untrusted pull-request identities must be denied by the deny-by-default policy.
            assert outcome == 'failure', 'pull_request identities must not receive a LibreHub credential'
            assert runs == [], runs
            audit = call('GET', f'/api/v1/projects/{project}/integrations/audit', token=token)[1]
            assert any(e['action'] == 'oidc.exchange_denied' for e in audit), audit
            summary['denied'] = True
        print(json.dumps(summary))
        Path(os.environ.get('RUNNER_TEMP', '.'), 'github-oidc-proof.json').write_text(json.dumps(summary, indent=2))
    finally:
        pid = int((STATE / 'pid').read_text())
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        print((STATE / 'api.log').read_text()[-3000:].replace(token, '[REDACTED]'))


def claims():
    """Print the non-secret claims of this job's identity token (never the token itself)."""
    import base64
    url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'] + '&audience=' + AUDIENCE
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    with urllib.request.urlopen(request, timeout=30) as response:
        token = json.loads(response.read())['value']
    head, payload, _ = token.split('.')
    pad = lambda part: part + '=' * (-len(part) % 4)
    print('header', json.loads(base64.urlsafe_b64decode(pad(head))))
    print('claims', json.dumps(json.loads(base64.urlsafe_b64decode(pad(payload))), indent=1, sort_keys=True))


if __name__ == '__main__':
    {'prepare': prepare, 'verify': verify, 'claims': claims}[sys.argv[1]]()
