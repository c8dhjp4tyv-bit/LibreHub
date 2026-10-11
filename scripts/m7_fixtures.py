"""Deterministic local stand-ins for the two external parties of the M7 acceptance:

* FakeGitHub: an OpenID Connect issuer (JWKS + signed tokens) and the Actions runtime token
  endpoint. LibreHub verifies these tokens through its production verification path; only the
  issuer URL differs from github.com.
* HttpsReceiver: a TLS webhook receiver that verifies LibreHub's HMAC signature.
"""
import base64
import hashlib
import hmac
import json
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def openssl(*args, stdin=None):
    return subprocess.run(['openssl', *args], input=stdin, check=True, capture_output=True).stdout


class FakeGitHub:
    REQUEST_TOKEN = 'runtime-request-token-for-tests'

    def __init__(self, work: Path, audience: str, repository_id='424242', owner_id='4242'):
        self.audience = audience
        self.key = work / 'oidc-key.pem'
        openssl('genrsa', '-out', str(self.key), '2048')
        modulus = openssl('rsa', '-in', str(self.key), '-noout', '-modulus').decode().strip().split('=', 1)[1]
        self.kid = 'm7-test-key'
        self.jwk = {'kty': 'RSA', 'kid': self.kid, 'use': 'sig', 'alg': 'RS256',
                    'n': b64url(bytes.fromhex(modulus)), 'e': b64url((65537).to_bytes(3, 'big'))}
        self.repository_id = repository_id
        self.owner_id = owner_id
        self.repository = 'octo/hello'
        self.sha = '0' * 40
        self.ref = 'refs/heads/main'
        self.event_name = 'push'
        self.workflow = 'octo/hello/.github/workflows/release.yml@refs/heads/main'
        self.run_id = 9000
        self.run_attempt = 1
        self.minted = 0
        self.requests = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, status, body):
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                parsed = urlsplit(self.path)
                if parsed.path == '/.well-known/jwks':
                    return self.reply(200, {'keys': [fake.jwk]})
                if parsed.path == '/token':
                    if self.headers.get('Authorization') != 'bearer ' + FakeGitHub.REQUEST_TOKEN:
                        return self.reply(401, {'message': 'bad runtime token'})
                    audience = parse_qs(parsed.query).get('audience', [''])[0]
                    fake.requests.append(audience)
                    return self.reply(200, {'value': fake.mint(audience=audience)})
                self.reply(404, {})

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def issuer(self):
        return f'http://127.0.0.1:{self.port}'

    def mint(self, audience=None, **override):
        now = int(time.time())
        self.minted += 1
        claims = {
            'iss': self.issuer, 'aud': audience or self.audience,
            'sub': f'repo:{self.repository}:ref:{self.ref}',
            'jti': f'jti-{self.minted}-{time.time_ns()}', 'iat': now, 'nbf': now - 5, 'exp': now + 300,
            'repository': self.repository, 'repository_id': self.repository_id,
            'repository_owner': 'octo', 'repository_owner_id': self.owner_id,
            'ref': self.ref, 'ref_type': 'branch', 'sha': self.sha, 'event_name': self.event_name,
            'workflow_ref': self.workflow, 'job_workflow_ref': self.workflow,
            'run_id': str(self.run_id), 'run_attempt': str(self.run_attempt), 'actor_id': '1',
            'runner_environment': 'github-hosted',
        }
        claims.update(override)
        header = {'alg': 'RS256', 'typ': 'JWT', 'kid': self.kid}
        signing_input = b64url(json.dumps(header).encode()) + '.' + b64url(json.dumps(claims).encode())
        signature = openssl('dgst', '-sha256', '-sign', str(self.key), stdin=signing_input.encode())
        return signing_input + '.' + b64url(signature)

    def cli_env(self, project, output_file):
        """Environment a GitHub Actions job exposes to the librehub CLI."""
        return {
            'GITHUB_ACTIONS': 'true',
            'ACTIONS_ID_TOKEN_REQUEST_URL': f'http://127.0.0.1:{self.port}/token',
            'ACTIONS_ID_TOKEN_REQUEST_TOKEN': FakeGitHub.REQUEST_TOKEN,
            'LIBREHUB_OIDC_PROJECT': project, 'LIBREHUB_OIDC_AUDIENCE': self.audience,
            'GITHUB_OUTPUT': str(output_file), 'GITHUB_RUN_ID': str(self.run_id),
        }

    def policy(self):
        return {
            'repository_id': self.repository_id, 'repository_owner_id': self.owner_id, 'repository': self.repository,
            'allowed_refs': ['refs/heads/main'], 'allowed_workflows': ['octo/hello/.github/workflows/release.yml@*'],
            'allowed_event_types': ['push', 'workflow_dispatch'],
            'allowed_permissions': ['projects:read', 'builds:read', 'automations:read', 'automations:run'],
            'token_ttl_seconds': 600,
        }

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def verify_signature(secret: str, headers, body: bytes, tolerance=300):
    headers = {k.lower(): v for k, v in headers.items()}
    timestamp = headers.get('x-librehub-timestamp', '')
    delivery = headers.get('x-librehub-delivery', '')
    expected = 'v1=' + hmac.new(secret.encode(), timestamp.encode() + b'.' + delivery.encode() + b'.' + body, hashlib.sha256).hexdigest()
    return (hmac.compare_digest(expected, headers.get('x-librehub-signature', ''))
            and abs(time.time() - int(timestamp)) <= tolerance)


class HttpsReceiver:
    """TLS receiver on a fixed port (so it can be stopped and restarted). `mode` selects the reply."""

    def __init__(self, work: Path, port=0):
        self.dir = work / 'receiver'
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ca = self.dir / 'ca.pem'
        ca_key = self.dir / 'ca.key'
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(ca_key), '-out', str(self.ca),
                '-days', '1', '-subj', '/CN=LibreHub M7 receiver CA')
        key, csr, cert, ext = (self.dir / n for n in ['server.key', 'server.csr', 'server.pem', 'ext.cnf'])
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n'
                       'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(csr), '-subj', '/CN=localhost')
        openssl('x509', '-req', '-in', str(csr), '-CA', str(self.ca), '-CAkey', str(ca_key), '-CAcreateserial',
                '-out', str(cert), '-days', '1', '-extfile', str(ext))
        self.cert, self.key = cert, key
        self.secret = None
        self.mode = 'ok'            # ok | status:<code>
        self.received = []          # every request, verified or not
        self.lock = threading.Lock()
        self.port = port
        self.server = None
        self.start()

    def start(self):
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                headers = {k: v for k, v in self.headers.items()}
                with receiver.lock:
                    verified = bool(receiver.secret) and verify_signature(receiver.secret, headers, body)
                    receiver.received.append({'headers': headers, 'body': body, 'verified': verified, 'mode': receiver.mode, 'status': 0})
                    mode = receiver.mode
                status = int(mode.split(':')[1]) if mode.startswith('status:') else 200
                with receiver.lock:
                    receiver.received[-1]['status'] = status
                self.send_response(status)
                self.send_header('Content-Length', '0')
                self.end_headers()

        class Server(ThreadingHTTPServer):
            allow_reuse_address = True

        self.server = Server(('127.0.0.1', self.port), Handler)
        self.port = self.server.server_port
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    @property
    def url(self):
        return f'https://localhost:{self.port}/librehub'

    def events(self, event_type=None):
        with self.lock:
            rows = [json.loads(r['body']) for r in self.received if r['verified'] and 200 <= r.get('status', 0) < 300]
        return [r for r in rows if event_type is None or r['event_type'] == event_type]
