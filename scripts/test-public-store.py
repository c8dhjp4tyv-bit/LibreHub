#!/usr/bin/env python3
"""Mandatory M4: real M3 Git + M1 build + signed M2 + catalog + browser + client install."""
import base64
import json
import os
from pathlib import Path
import signal
import sqlite3
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zlib
from source_fixture import SourceFixture, REPOSITORY, git
ROOT = Path(__file__).resolve().parents[1]
API = 'http://127.0.0.1:8080'
WEB = os.environ.get('LIBREHUB_WEB_PUBLIC_URL', 'http://127.0.0.1:3000')
PUBLIC = os.environ.get('LIBREHUB_PUBLIC_BASE_URL', 'http://localhost:8090').rstrip('/')
APP = 'org.librehub.CatalogHello'
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


def public(path):
    with urllib.request.urlopen(API + path, timeout=30) as response:
        return json.load(response)

def assert_hidden(app_id):
    try:
        public('/api/v1/catalog/apps/' + app_id)
        raise AssertionError('Unpublished app became public')
    except urllib.error.HTTPError as error:
        assert error.code == 404

def png():
    def chunk(kind, value):
        return struct.pack('>I', len(value)) + kind + value + struct.pack('>I', zlib.crc32(kind + value))
    scanlines = (b'\x00' + b'\x17\x6a\x50' * 64) * 64
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 64, 64, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(scanlines)) + chunk(b'IEND', b'')

with tempfile.TemporaryDirectory(prefix='librehub-m4-') as temporary:
    work = Path(temporary)
    fixture = SourceFixture(work / 'git')
    # A real committed standard AppStream file, desktop file and PNG, installed by flatpak-builder.
    (fixture.repo / 'org.librehub.ProjectHello.json').unlink()
    manifest = json.loads((ROOT / 'examples/org.librehub.Hello.json').read_text())
    manifest['app-id'] = APP
    manifest['finish-args'] = ['--share=network', '--socket=wayland', '--device=dri']
    manifest['modules'][0]['sources'] = [{'type': 'file', 'path': name} for name in ['hello.sh', APP + '.metainfo.xml', APP + '.desktop', APP + '.png']]
    manifest['modules'][0]['build-commands'].extend([
        f'install -Dm644 {APP}.metainfo.xml /app/share/metainfo/{APP}.metainfo.xml',
        f'install -Dm644 {APP}.desktop /app/share/applications/{APP}.desktop',
        f'install -Dm644 {APP}.png /app/share/icons/hicolor/64x64/apps/{APP}.png'])
    (fixture.repo / (APP + '.json')).write_text(json.dumps(manifest))
    (fixture.repo / (APP + '.metainfo.xml')).write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>{APP}</id><name>Catalog Hello</name><summary>A real signed LibreHub catalog acceptance app</summary>
  <metadata_license>CC0-1.0</metadata_license><project_license>MIT</project_license>
  <developer id="org.librehub"><name>LibreHub acceptance</name></developer>
  <description><p>Published from an immutable Git commit through the real LibreHub stack.</p></description>
  <url type="homepage">https://github.com/c8dhjp4tyv-bit/LibreHub</url>
  <launchable type="desktop-id">{APP}.desktop</launchable>
  <categories><category>Utility</category><category>Development</category></categories>
  <keywords><keyword>catalog-proof</keyword></keywords>
  <screenshots><screenshot type="default"><caption>Acceptance image</caption><image type="source">https://raw.githubusercontent.com/github/explore/main/topics/linux/linux.png</image></screenshot></screenshots>
  <releases><release version="1.4.0" date="2026-01-01"><description><p>First catalog proof release.</p></description></release></releases>
  <content_rating type="oars-1.1"/>
</component>''')
    (fixture.repo / (APP + '.desktop')).write_text(f'[Desktop Entry]\nType=Application\nName=Catalog Hello\nExec=hello\nIcon={APP}\nCategories=Utility;Development;\n')
    (fixture.repo / (APP + '.png')).write_bytes(png())
    source_commit = fixture.update('Hello from LibreHub M4!')
    env = os.environ.copy()
    env.update(fixture.env())
    env['LIBREHUB_DATA_DIR'] = str(work / 'data')
    admin = str(ROOT / 'target/debug/librehub-admin')
    developer = json.loads(run([admin, 'create-developer', 'M4 public publisher'], env))
    token = json.loads(run([admin, 'create-token', developer['id'], 'M4 acceptance'], env))['token']
    api_log = open(work / 'api.log', 'w+')
    web_log = open(work / 'web.log', 'w+')
    api = Api(env, api_log)
    api.token = token
    web = None
    try:
        api.start()
        project = api.request('/api/v1/projects', {'slug': 'catalog-hello', 'display_name': 'Catalog Hello',
                   'repository': {'provider': 'git', 'url': REPOSITORY}, 'default_branch': 'main'})['project']
        trigger = api.request(f'/api/v1/projects/{project["id"]}/builds', {'ref': 'main'})
        build = api.successful_build(project['id'], trigger)
        assert_hidden(APP)  # successful build without stable publication must not leak
        publication = api.request(f'/api/v1/builds/{build["id"]}/publish', {'channel': 'stable'})
        publication = api.wait('/api/v1/publishes/' + publication['id'], lambda p: p['status'] == 'succeeded')
        app = api.wait('/api/v1/catalog/apps/' + APP, lambda a: a.get('current_stable_release'))
        assert app['name'] == 'Catalog Hello' and app['license'] == 'MIT'
        assert 'immutable Git commit' in app['description']
        assert app['categories'] == ['Development', 'Utility']
        assert app['screenshots'] and app['icon'].startswith('/api/v1/catalog/')
        release = app['current_stable_release']
        checksum = publication['result']['published_ref']['commit']
        assert release['source_commit'] == source_commit
        assert release['publication_id'] == publication['id'] and release['build_id'] == build['id']
        assert release['ostree_checksum'] == checksum and release['version'] == '1.4.0'
        assert release['permissions']['network'] and 'wayland' in release['permissions']['sockets']
        assert app['publisher']['id'] == developer['id']
        assert public('/api/v1/catalog/search?q=Catalog%20Hello')['items'][0]['app_id'] == APP
        assert public('/api/v1/catalog/apps?category=Utility')['items'][0]['app_id'] == APP
        # Failed M1 fixture is real admission/execution, never a manually fabricated publication.
        failed = json.loads((ROOT / 'examples/org.librehub.Hello.json').read_text())
        failed['app-id'] = 'org.librehub.CatalogFailed'
        failed['modules'][0]['build-commands'] = ['exit 23']
        failed_build = api.request('/api/v1/builds', failed)
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            value = api.request('/api/v1/builds/' + failed_build['id'])
            if value['status'] == 'failed': break
            time.sleep(0.2)
        assert value['status'] == 'failed'
        assert_hidden('org.librehub.CatalogFailed')
        try:
            public('/api/v1/projects')
            raise AssertionError('Private developer API must require authentication')
        except urllib.error.HTTPError as error: assert error.code == 401
        # Persistent indexing recovery and offline idempotent rebuild of the same publication.
        api.stop(crash=True)
        with sqlite3.connect(work / 'data/builds.sqlite3') as db:
            db.execute("UPDATE catalog_jobs SET state='indexing' WHERE publication_id=?", (publication['id'],))
        api.start()
        api.wait('/api/v1/catalog/apps/' + APP, lambda a: a['current_stable_release']['ostree_checksum'] == checksum)
        api.stop()
        run([admin, 'catalog', 'rebuild'], env)
        api.start()
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            with sqlite3.connect(work / 'data/builds.sqlite3') as db:
                state = db.execute('SELECT state FROM catalog_jobs WHERE publication_id=?', (publication['id'],)).fetchone()
                if state and state[0] == 'ready': break
            time.sleep(0.2)
        assert state == ('ready',)
        assert public('/api/v1/catalog/apps/' + APP + '/releases')['total'] == 1
        web_env = env.copy()
        web_env.update({'LIBREHUB_API_URL': API, 'LIBREHUB_API_PUBLIC_URL': API,
                        'LIBREHUB_WEB_PUBLIC_URL': WEB, 'NEXT_TELEMETRY_DISABLED': '1'})
        web = subprocess.Popen(['npm', 'run', 'start'], cwd=ROOT / 'apps/web', env=web_env, stdout=web_log, stderr=web_log, start_new_session=True)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(WEB + '/health', timeout=5) as response:
                    if response.status == 200: break
            except urllib.error.URLError: pass
            time.sleep(0.2)
        else:
            raise TimeoutError('Store did not return HTTP 200 from /health before the deadline')
        with urllib.request.urlopen(WEB + '/apps/' + APP) as response:
            html = response.read().decode()
            assert 'Catalog Hello' in html and source_commit[:12] in html and 'Install with Flatpak' in html
            policy = response.headers['Content-Security-Policy']
            print('Store screenshot policy:', policy, flush=True)
            assert "frame-ancestors 'none'" in policy
            assert 'https://raw.githubusercontent.com' in policy
        browser_env = web_env.copy()
        browser_env['LIBREHUB_E2E_APP_ID'] = APP
        subprocess.run(['npm', 'run', 'test:e2e'], cwd=ROOT / 'apps/web', env=browser_env, check=True, timeout=180)
        reference = work / (APP + '.flatpakref')
        with urllib.request.urlopen(API + '/api/v1/catalog/apps/' + APP + '/flatpakref') as response:
            reference.write_bytes(response.read())
        assert 'GPGKey=' in reference.read_text() and f'Url={PUBLIC}/repo/stable/' in reference.read_text()
        client = env.copy()
        for name in list(client):
            if name.startswith(('LIBREHUB_', 'REPO_')): client.pop(name)
        for key, relative in [('HOME', 'client'), ('XDG_DATA_HOME', 'client/data'), ('XDG_CACHE_HOME', 'client/cache'),
                              ('XDG_CONFIG_HOME', 'client/config'), ('XDG_RUNTIME_DIR', 'client/run')]:
            client[key] = str(work / relative)
            Path(client[key]).mkdir(parents=True, exist_ok=True, mode=0o700)
        run(['flatpak', 'remote-add', '--user', 'flathub', 'https://dl.flathub.org/repo/flathub.flatpakrepo'], client)
        run(['flatpak', 'install', '--user', '--noninteractive', '--no-related', 'flathub', 'org.freedesktop.Platform//25.08'], client)
        run(['flatpak', 'install', '--user', '--noninteractive', '--no-related', str(reference)], client)
        installed = run(['flatpak', 'info', '--user', '--show-commit', APP], client)
        installed_ref = run(['flatpak', 'info', '--user', '--show-ref', APP], client)
        assert installed == checksum and installed_ref == release['flatpak_ref']
        origin = run(['flatpak', 'info', '--user', '--show-origin', APP], client)
        signature = run(['ostree', '--repo=' + str(Path(client['XDG_DATA_HOME']) / 'flatpak/repo'), 'show', '--gpg-verify-remote=' + origin, installed], client)
        assert 'signature' in signature.lower()
        assert 'LibreHub M4' in run(['flatpak', 'run', '--user', APP], client)
        proof = {'app_id': APP, 'project_id': project['id'], 'publisher_id': developer['id'],
                 'build_id': build['id'], 'publication_id': publication['id'], 'source_commit': source_commit,
                 'catalog_version': release['version'], 'published_checksum': checksum, 'installed_checksum': installed,
                 'installed_ref': installed_ref, 'appstream_extracted': True, 'permissions_from_signed_commit': True,
                 'public_catalog_without_auth': True, 'unpublished_and_failed_hidden': True,
                 'private_api_requires_auth': True, 'real_web_rendered': True, 'real_browser_search_and_install': True,
                 'normal_flatpakref_install': True, 'gpg_verified': True, 'restart_and_rebuild_idempotent': True,
                 'fixture_source_url': REPOSITORY, 'fixture_private_dns_link_omitted': app['source_url'] is None}
        assert token not in json.dumps(proof)
        (ROOT / 'data/m4-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
        print(json.dumps(proof, indent=2))
    except BaseException:
        for log in [api_log, web_log]:
            log.flush(); log.seek(0)
            print(log.read()[-16000:].replace(token, '[REDACTED]'))
        raise
    finally:
        if web is not None:
            os.killpg(web.pid, signal.SIGTERM)
            web.wait(timeout=30)
        api.stop()
        fixture.close()
        api_log.close(); web_log.close()
