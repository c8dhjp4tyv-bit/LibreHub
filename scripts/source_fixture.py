#!/usr/bin/env python3
"""Disposable real HTTPS smart-Git fixture; no provider account or credentials."""
import argparse
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'https://git.librehub.test/fixture.git'

def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()

class SourceFixture:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.repo = self.root / 'fixture.git'
        self.repo.mkdir()
        git(self.repo, 'init', '-b', 'main')
        git(self.repo, 'config', 'user.name', 'LibreHub CI')
        git(self.repo, 'config', 'user.email', 'ci@example.invalid')
        git(self.repo, 'config', 'uploadpack.allowReachableSHA1InWant', 'true')
        manifest = json.loads((ROOT / 'examples/org.librehub.Hello.json').read_text())
        manifest['app-id'] = 'org.librehub.ProjectHello'
        manifest['modules'][0]['sources'] = [{'type': 'file', 'path': 'hello.sh'}]
        (self.repo / 'org.librehub.ProjectHello.json').write_text(json.dumps(manifest))
        self.commit1 = self.update('Hello from LibreHub project revision 1!')
        self.ca = self.root / 'fixture.pem'
        self.key = self.root / 'fixture.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(self.key), '-out', str(self.ca), '-days', '1',
                        '-subj', '/CN=LibreHub CI root'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server_key = self.root / 'server.key'
        server_cert = self.root / 'server.pem'
        csr = self.root / 'server.csr'
        extensions = self.root / 'extensions.cnf'
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:git.librehub.test\n')
        subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(server_key), '-out', str(csr), '-subj', '/CN=git.librehub.test'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(self.ca), '-CAkey', str(self.key), '-CAcreateserial', '-out', str(server_cert), '-days', '1', '-extfile', str(extensions)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        fixture = self
        backend = subprocess.check_output(['git', '--exec-path'], text=True).strip() + '/git-http-backend'
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                self.handle_git()
            def do_POST(self):
                self.handle_git()
            def handle_git(self):
                parsed = urlsplit(self.path)
                if parsed.path not in ['/fixture.git/info/refs', '/fixture.git/git-upload-pack']:
                    self.send_error(404)
                    return
                count = int(self.headers.get('Content-Length', 0))
                if count > 1024 * 1024:
                    self.send_error(413)
                    return
                env = {'PATH': os.environ['PATH'], 'GIT_PROJECT_ROOT': str(fixture.root),
                       'GIT_HTTP_EXPORT_ALL': '1', 'PATH_INFO': parsed.path,
                       'REQUEST_METHOD': self.command, 'QUERY_STRING': parsed.query,
                       'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                       'REMOTE_ADDR': '127.0.0.1'}
                raw = subprocess.run([backend], input=self.rfile.read(count), env=env,
                                     check=True, stdout=subprocess.PIPE, timeout=30).stdout
                headers, payload = raw.split(b'\r\n\r\n', 1)
                status = 200
                lines = []
                for line in headers.decode().split('\r\n'):
                    key, value = line.split(':', 1)
                    if key.lower() == 'status':
                        status = int(value.strip().split()[0])
                    else:
                        lines.append((key, value.strip()))
                self.send_response(status)
                for key, value in lines:
                    self.send_header(key, value)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(server_cert, server_key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def update(self, message):
        (self.repo / 'hello.sh').write_text("#!/bin/sh\necho '" + message + "'\n")
        git(self.repo, 'add', '.')
        git(self.repo, 'commit', '-m', message)
        return git(self.repo, 'rev-parse', 'HEAD')
    def env(self):
        return {'LIBREHUB_TEST_SOURCE_REPOSITORY': REPOSITORY,
                'LIBREHUB_TEST_SOURCE_CA_FILE': str(self.ca),
                'LIBREHUB_TEST_SOURCE_PORT': str(self.server.server_port)}
    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    args = parser.parse_args()
    fixture = SourceFixture(args.root)
    print(json.dumps({'env': fixture.env(), 'commit': fixture.commit1, 'repo': str(fixture.repo)}), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        fixture.close()
