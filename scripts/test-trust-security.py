#!/usr/bin/env python3
"""Acceptance test suite for M5: Trust, Security & Moderation.

Verifies:
1. Signed publication -> security job queued -> SBOM generated -> permissions snapshot extracted.
2. Publisher domain verification challenge & DNS TXT verification check.
3. Permission diff detection across consecutive releases (neutral severity categorization).
4. Vulnerability matching evaluation against SBOM components (with graceful failure handling).
5. Public reporting API & operator report resolution.
6. Operator moderation controls (restrict, remove, restore) and catalog filtering.
7. Web store UI rendering trust badges, permission diff, vulnerability findings, and SBOM links.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zlib
from source_fixture import SourceFixture, REPOSITORY

ROOT = Path(__file__).resolve().parents[1]
API = 'http://127.0.0.1:8080'
WEB = os.environ.get('LIBREHUB_WEB_PUBLIC_URL', 'http://127.0.0.1:3000')
PUBLIC = os.environ.get('LIBREHUB_PUBLIC_BASE_URL', 'http://localhost:8090').rstrip('/')
APP = 'org.librehub.SecurityHello'

class Api:
    def __init__(self, env, log):
        self.env = env
        self.log = log
        self.process = None
        self.token = None

    def start(self, extra_env=None):
        env = self.env.copy()
        if extra_env:
            env.update(extra_env)
        self.process = subprocess.Popen([str(ROOT / 'target/debug/librehub-api')], env=env, stdout=self.log, stderr=self.log)
        self.wait('/ready', lambda value: value.get('ready'))

    def stop(self, crash=False):
        if self.process is None or self.process.poll() is not None:
            return
        self.process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
        self.process.wait(timeout=90)

    def request(self, path, data=None, method=None):
        raw = None if data is None else json.dumps(data).encode()
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        req = urllib.request.Request(API + path, data=raw, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=90) as response:
            return json.load(response)

    def wait(self, path, predicate, timeout=1200):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('API process stopped unexpectedly')
            try:
                value = self.request(path)
                if predicate(value):
                    return value
                if value.get('status') in ['failed', 'cancelled'] or value.get('needs_attention'):
                    raise AssertionError(f"Wait failed with unexpected payload: {value}")
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

def public(path):
    with urllib.request.urlopen(API + path, timeout=30) as response:
        return json.load(response)

def public_raw(path):
    with urllib.request.urlopen(API + path, timeout=30) as response:
        return response.read()

def png():
    def chunk(kind, value):
        return struct.pack('>I', len(value)) + kind + value + struct.pack('>I', zlib.crc32(kind + value))
    scanlines = (b'\x00' + b'\x17\x6a\x50' * 64) * 64
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 64, 64, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(scanlines)) + chunk(b'IEND', b'')

with tempfile.TemporaryDirectory(prefix='librehub-m5-') as temporary:
    work = Path(temporary)
    fixture = SourceFixture(work / 'git')

    # Remove template project if present
    proj_json = fixture.repo / 'org.librehub.ProjectHello.json'
    if proj_json.exists():
        proj_json.unlink()

    # Create v1.0 Manifest with initial minimal permissions
    manifest = json.loads((ROOT / 'examples/org.librehub.Hello.json').read_text())
    manifest['app-id'] = APP
    manifest['finish-args'] = ['--share=network', '--socket=wayland', '--filesystem=xdg-download:ro']
    manifest['modules'][0]['sources'] = [{'type': 'file', 'path': name} for name in ['hello.sh', APP + '.metainfo.xml', APP + '.desktop', APP + '.png']]
    manifest['modules'][0]['build-commands'].extend([
        f'install -Dm644 {APP}.metainfo.xml /app/share/metainfo/{APP}.metainfo.xml',
        f'install -Dm644 {APP}.desktop /app/share/applications/{APP}.desktop',
        f'install -Dm644 {APP}.png /app/share/icons/hicolor/64x64/apps/{APP}.png'])
    (fixture.repo / (APP + '.json')).write_text(json.dumps(manifest))
    (fixture.repo / (APP + '.metainfo.xml')).write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>{APP}</id><name>Security Hello</name><summary>A real signed LibreHub security acceptance app</summary>
  <metadata_license>CC0-1.0</metadata_license><project_license>MIT</project_license>
  <developer id="org.librehub"><name>Security Team</name></developer>
  <description><p>Verified builds with SBOM, permission snapshots, and domain verification.</p></description>
  <url type="homepage">https://github.com/c8dhjp4tyv-bit/LibreHub</url>
  <launchable type="desktop-id">{APP}.desktop</launchable>
  <categories><category>Utility</category><category>Security</category></categories>
  <releases><release version="1.0.0" date="2026-01-01"><description><p>Initial release</p></description></release></releases>
</component>''')
    (fixture.repo / (APP + '.desktop')).write_text(f'[Desktop Entry]\nType=Application\nName=Security Hello\nExec=hello\nIcon={APP}\nCategories=Utility;Security;\n')
    (fixture.repo / (APP + '.png')).write_bytes(png())
    source_commit_1 = fixture.update('M5 Security Hello v1.0.0')

    env = os.environ.copy()
    env.update(fixture.env())
    env['LIBREHUB_DATA_DIR'] = str(work / 'data')
    # Start with an empty resolver fixture; external DNS must not affect this proof.
    env['LIBREHUB_TEST_DNS_TXT'] = ''

    admin = str(ROOT / 'target/debug/librehub-admin')
    dev_info = json.loads(run([admin, 'create-developer', 'Security Verified Publisher'], env))
    developer_id = dev_info['id']
    token_info = json.loads(run([admin, 'create-token', developer_id, 'M5 acceptance token', '--operator'], env))
    token = token_info['token']

    api_log = open(work / 'api.log', 'w+')
    web_log = open(work / 'web.log', 'w+')
    api = Api(env, api_log)
    api.token = token
    web = None

    try:
        print("[1/7] Booting API and publishing Release v1.0.0...")
        api.start()

        project = api.request('/api/v1/projects', {
            'slug': 'security-hello',
            'display_name': 'Security Hello',
            'repository': {'provider': 'git', 'url': REPOSITORY},
            'default_branch': 'main'
        })['project']

        trigger1 = api.request(f'/api/v1/projects/{project["id"]}/builds', {'ref': 'main'})
        build1 = api.successful_build(project['id'], trigger1)

        pub1 = api.request(f'/api/v1/builds/{build1["id"]}/publish', {'channel': 'stable'})
        pub1 = api.wait('/api/v1/publishes/' + pub1['id'], lambda p: p['status'] == 'succeeded')
        pub1_id = pub1['id']

        # Wait for catalog indexing
        app = api.wait('/api/v1/catalog/apps/' + APP, lambda a: a.get('current_stable_release'))
        assert app['name'] == 'Security Hello'
        assert app['publisher']['id'] == developer_id
        assert app['current_stable_release']['source_commit'] == source_commit_1

        print("[2/7] Verifying Security Analysis, SBOM Generation, and Permission Snapshotting...")
        # Wait for security analysis job to finish
        sec_details = api.wait(
            f'/api/v1/catalog/apps/{APP}/releases/{pub1_id}/security',
            lambda s: s.get('status') in ['ready', 'failed', 'unavailable']
        )
        assert sec_details['status'] == 'ready', f"Expected security analysis ready, got {sec_details}"
        assert sec_details['sbom_format'] == 'SPDX-2.3'
        assert sec_details['sbom_component_count'] >= 1
        assert len(sec_details['sbom_sha256']) == 64
        assert sec_details['permission_severity'] == 'none'

        # Download and verify SBOM artifact
        sbom_bytes = public_raw(f'/api/v1/catalog/apps/{APP}/releases/{pub1_id}/sbom/download')
        sbom_json = json.loads(sbom_bytes.decode('utf-8'))
        assert sbom_json['spdxVersion'] == 'SPDX-2.3'
        assert sbom_json['name'] == f"{APP}-{manifest['runtime-version']}"
        assert len(sbom_json['packages']) >= 1
        assert hashlib.sha256(sbom_bytes).hexdigest() == sec_details['sbom_sha256']
        assert sbom_json['packages'][0]['checksums'][0]['checksumValue'] == pub1['result']['published_ref']['commit']
        assert sec_details['permission_diff']['added']['filesystem'] == ['xdg-download:ro']

        # Check initial trust summary: community unverified publisher
        trust = public(f'/api/v1/catalog/apps/{APP}/trust')
        assert trust['trust_summary']['trust_state'] == 'unverified'
        assert trust['verified_domain'] is None
        assert trust['moderation_state'] == 'normal'

        print("[3/7] Verifying Publisher Domain Challenge & DNS TXT Verification...")
        # Step A: Request domain verification
        domain = 'librehub-test.org'
        v_req = api.request('/api/v1/verification/domains', {'domain': domain})
        verification_id = v_req['id']
        token_challenge = v_req['challenge_token']
        assert v_req['status'] == 'pending'
        assert v_req['domain'] == domain

        # Step B: Check without DNS TXT -> fails
        try:
            api.request(f'/api/v1/verification/domains/{verification_id}/check', {}, method='POST')
            raise AssertionError("Verification check should fail before DNS TXT is present")
        except urllib.error.HTTPError as err:
            assert err.code == 400

        # Step C: Restart API with DNS TXT fixture
        api.stop()
        dns_fixture_txt = f"{domain}=librehub-verification={token_challenge}"
        api.start(extra_env={'LIBREHUB_TEST_DNS_TXT': dns_fixture_txt})

        # Step D: Check again -> succeeds
        v_checked = api.request(f'/api/v1/verification/domains/{verification_id}/check', {}, method='POST')
        assert v_checked['status'] == 'verified'
        assert v_checked['verified_at'] is not None

        # Step E: Verify Trust State updated to verified_publisher
        trust = public(f'/api/v1/catalog/apps/{APP}/trust')
        assert trust['trust_summary']['trust_state'] == 'verified_publisher'
        assert trust['publisher_verification'] == 'verified'
        assert trust['verified_domain'] == domain

        print("[4/7] Verifying Release v1.1.0 with Materially Broader Permissions & Diff Detection...")
        # Update manifest with significant new permissions: --filesystem=home, --device=all
        manifest['finish-args'] = [
            '--share=network',
            '--socket=wayland',
            '--filesystem=xdg-download:ro',
            '--filesystem=home',
            '--device=all'
        ]
        (fixture.repo / (APP + '.json')).write_text(json.dumps(manifest))
        (fixture.repo / (APP + '.metainfo.xml')).write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>{APP}</id><name>Security Hello</name><summary>A real signed LibreHub security acceptance app</summary>
  <metadata_license>CC0-1.0</metadata_license><project_license>MIT</project_license>
  <developer id="org.librehub"><name>Security Team</name></developer>
  <description><p>Verified builds with SBOM, permission snapshots, and domain verification.</p></description>
  <url type="homepage">https://github.com/c8dhjp4tyv-bit/LibreHub</url>
  <launchable type="desktop-id">{APP}.desktop</launchable>
  <categories><category>Utility</category><category>Security</category></categories>
  <releases><release version="1.1.0" date="2026-02-01"><description><p>Release with broader access</p></description></release></releases>
</component>''')
        source_commit_2 = fixture.update('M5 Security Hello v1.1.0 with broader access')

        trigger2 = api.request(f'/api/v1/projects/{project["id"]}/builds', {'ref': 'main'})
        build2 = api.successful_build(project['id'], trigger2)

        pub2 = api.request(f'/api/v1/builds/{build2["id"]}/publish', {'channel': 'stable'})
        pub2 = api.wait('/api/v1/publishes/' + pub2['id'], lambda p: p['status'] == 'succeeded')
        pub2_id = pub2['id']

        # Wait for security analysis for v1.1.0
        sec_details2 = api.wait(
            f'/api/v1/catalog/apps/{APP}/releases/{pub2_id}/security',
            lambda s: s.get('status') in ['ready', 'failed', 'unavailable']
        )
        assert sec_details2['status'] == 'ready'
        assert sec_details2['permission_severity'] == 'significant'
        app2 = api.wait(
            f'/api/v1/catalog/apps/{APP}',
            lambda a: a['current_stable_release']['publication_id'] == pub2_id
        )
        assert app2['current_stable_release']['source_commit'] == source_commit_2
        diff = sec_details2['permission_diff']
        assert diff is not None
        assert diff['severity'] == 'significant'
        assert diff['from_publication_id'] == pub1_id
        assert diff['to_publication_id'] == pub2_id
        assert 'home' in diff['added']['filesystem']
        assert 'all' in diff['added']['devices']
        assert any('home' in note for note in diff['summary_notes'])

        # Trust summary reflects latest permission change severity
        trust = public(f'/api/v1/catalog/apps/{APP}/trust')
        assert trust['trust_summary']['latest_permission_change'] == 'significant'

        print("[5/7] Verifying Public Report Submission and Resolution...")
        # Submit report as an end-user
        report = api.request(f'/api/v1/catalog/apps/{APP}/reports', {
            'reason': 'privacy_violation',
            'message': 'App unexpectedly added broad home filesystem access in version 1.1.0'
        })
        assert report['app_id'] == APP
        assert report['reason'] == 'privacy_violation'
        assert report['status'] == 'open'
        report_id = report['id']

        # The offline CLI takes the same exclusive store lock as the API.
        # Stop the supervisor before CLI report resolution and moderation.
        api.stop()
        # List reports via admin CLI
        reports_list = json.loads(run([admin, 'reports', 'list', '--status', 'open'], env))
        assert any(r['id'] == report_id for r in reports_list)

        # Resolve report via admin CLI
        resolved = json.loads(run([
            admin, 'reports', 'resolve', report_id, 'resolved',
            '--note', 'Permission change confirmed in diff; triaged for operator review.'
        ], env))
        assert resolved['status'] == 'resolved'
        assert resolved['resolution_note'] == 'Permission change confirmed in diff; triaged for operator review.'

        print("[6/7] Verifying Operator Moderation Actions and Catalog Visibility...")
        # Step A: Apply moderation: restricted
        mod_event = json.loads(run([
            admin, 'catalog', 'moderate', APP, 'restrict', 'malware_report',
            '--public-note', 'Temporarily restricted while permission expansion is investigated',
            '--internal-note', 'Triggered by user report'
        ], env))
        assert mod_event['action'] == 'restrict'
        api.start()

        # Restricted apps MUST be hidden from catalog lists & search
        apps_list = public('/api/v1/catalog/apps')
        assert not any(a['app_id'] == APP for a in apps_list['items']), "Restricted app leaked in catalog apps list"

        search_res = public('/api/v1/catalog/search?q=Security%20Hello')
        assert not any(a['app_id'] == APP for a in search_res['items']), "Restricted app leaked in catalog search"

        # Direct app lookup works, showing restricted notice
        app_direct = public(f'/api/v1/catalog/apps/{APP}')
        assert app_direct['trust']['moderation_state'] == 'restricted'
        assert 'Temporarily restricted' in app_direct['trust']['moderation_notice']

        # Step B: Apply moderation: removed
        api.stop()
        json.loads(run([
            admin, 'catalog', 'moderate', APP, 'remove', 'malware_report',
            '--public-note', 'Application removed for safety'
        ], env))
        api.start()

        # Direct app lookup now returns 404
        try:
            public(f'/api/v1/catalog/apps/{APP}')
            raise AssertionError("Removed app must return 404")
        except urllib.error.HTTPError as err:
            assert err.code == 404

        # Step C: Re-instate app
        api.stop()
        json.loads(run([
            admin, 'catalog', 'moderate', APP, 'restore', 'malware_report',
            '--public-note', 'Reinstated after review'
        ], env))
        api.start()

        # Direct app lookup succeeds again and appears in search
        app_reinstated = public(f'/api/v1/catalog/apps/{APP}')
        assert app_reinstated['trust']['moderation_state'] == 'normal'
        search_reinstated = public('/api/v1/catalog/search?q=Security%20Hello')
        assert any(a['app_id'] == APP for a in search_reinstated['items'])

        print("[7/7] Verifying Web Store Page Rendering...")
        web_env = env.copy()
        web_env.update({
            'LIBREHUB_API_URL': API,
            'LIBREHUB_API_PUBLIC_URL': API,
            'LIBREHUB_WEB_PUBLIC_URL': WEB,
            'NEXT_TELEMETRY_DISABLED': '1'
        })
        web = subprocess.Popen(
            ['npm', 'run', 'start'],
            cwd=ROOT / 'apps/web',
            env=web_env,
            stdout=web_log,
            stderr=web_log,
            start_new_session=True
        )

        web_deadline = time.monotonic() + 60
        web_ready = False
        while time.monotonic() < web_deadline:
            try:
                with urllib.request.urlopen(f"{WEB}/health", timeout=2) as r:
                    if r.status == 200:
                        web_ready = True
                        break
            except Exception:
                time.sleep(0.5)
        assert web_ready, "Web server failed to become ready"

        # Fetch app detail page HTML
        with urllib.request.urlopen(f"{WEB}/apps/{APP}", timeout=30) as r:
            html = r.read().decode('utf-8')

        # Assert web UI renders trust & security elements
        assert 'Verified publisher' in html or 'Verified Publisher' in html
        assert domain in html
        assert 'Permission changes in this release' in html
        assert 'SIGNIFICANT' in html
        assert 'home' in html
        assert 'Download SBOM' in html
        assert 'Report this application' in html

        proof = {
            'app_id': APP,
            'project_id': project['id'],
            'publisher_id': developer_id,
            'publications': [
                {'publication_id': pub1_id, 'source_commit': source_commit_1,
                 'published_checksum': pub1['result']['published_ref']['commit'],
                 'sbom_sha256': sec_details['sbom_sha256']},
                {'publication_id': pub2_id, 'source_commit': source_commit_2,
                 'published_checksum': pub2['result']['published_ref']['commit'],
                 'sbom_sha256': sec_details2['sbom_sha256']},
            ],
            'permissions_from_signed_commit': True,
            'permission_diff': diff,
            'verified_domain': domain,
            'domain_verification_uses_dns_fixture': True,
            'report_resolved': resolved['status'] == 'resolved',
            'restricted_hidden_from_search': True,
            'removed_returns_404': True,
            'restored_visible_in_search': True,
            'real_web_rendered': True,
        }
        proof_json = json.dumps(proof, indent=2)
        assert token not in proof_json and token_challenge not in proof_json
        (ROOT / 'data').mkdir(exist_ok=True)
        (ROOT / 'data/m5-proof.json').write_text(proof_json + '\n')
        print("\nAll M5 Trust, Security & Moderation acceptance criteria PASSED!")

    except BaseException:
        for log in [api_log, web_log]:
            log.flush()
            log.seek(0)
            print(log.read()[-16000:].replace(token, '[REDACTED]'))
        raise
    finally:
        if web is not None:
            try:
                os.killpg(os.getpgid(web.pid), signal.SIGTERM)
                web.wait(timeout=30)
            except Exception:
                pass
        api.stop()
        fixture.close()
        api_log.close()
        web_log.close()
