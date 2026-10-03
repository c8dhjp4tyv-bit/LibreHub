"""Real backend fault injection: lose replies by SIGKILLing only the LibreHub API."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import threading
import urllib.error
import urllib.request


class PublishingFaults:
    def __init__(self, manager_url, executable, env, log):
        self.manager_url = manager_url.rstrip('/')
        self.executable = executable
        self.env = env
        self.log = log
        self.lock = threading.Lock()
        self.crashes = []
        self.restarts = 0
        self.process = None
        owner = self

        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass  # Never log headers, tokens or backend bodies.

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                length = int(self.headers.get('Content-Length', '0'))
                if length > 8 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                headers = {name: self.headers[name] for name in ['Authorization', 'Content-Type'] if name in self.headers}
                request = urllib.request.Request(owner.manager_url + self.path, data=body if body else None,
                                                 headers=headers, method=self.command)
                try:
                    response = urllib.request.urlopen(request, timeout=60)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    data = response.read(1024 * 1024 + 1)
                    status = response.status
                phase = None
                if self.command == 'POST' and status == 200:
                    if self.path == '/api/v1/build':
                        phase = 'preparing'
                    elif self.path.endswith('/upload'):
                        phase = 'uploading'
                    elif self.path.endswith('/commit'):
                        phase = 'committing'
                    elif self.path.endswith('/publish'):
                        phase = 'publishing'
                with owner.lock:
                    if phase and phase not in owner.crashes:
                        # The backend accepted the request, but the API cannot
                        # journal its reply. This proves actual restart reconciliation.
                        owner.crashes.append(phase)
                        owner.process.kill()
                        owner.process.wait(timeout=10)
                        print('Injected API crash after accepted backend operation:', phase, flush=True)
                try:
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.env['LIBREHUB_FLAT_MANAGER_URL'] = 'http://127.0.0.1:' + str(self.server.server_port)
        self.start()

    def start(self):
        self.process = subprocess.Popen([self.executable], env=self.env, stdout=self.log, stderr=subprocess.STDOUT)

    def reconcile_process(self):
        with self.lock:
            if self.process.poll() is not None:
                if self.restarts >= len(self.crashes):
                    raise RuntimeError('LibreHub API stopped unexpectedly')
                self.restarts += 1
                self.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)
