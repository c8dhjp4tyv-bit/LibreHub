#!/usr/bin/env python3
"""Development/CI ONLY. No production keys or credentials are accepted here."""
import base64
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess

os.umask(0o077)
state = Path('/state')
public = Path('/repositories')
host = Path('/host-output/dev')
for directory in [state, public, host, state / 'gnupg', state / 'builds']:
    directory.mkdir(parents=True, exist_ok=True)
base = os.environ.get('LIBREHUB_PUBLIC_BASE_URL', 'http://localhost:8090').rstrip('/')
if '\n' in base or '\r' in base or not base.startswith(('http://', 'https://')):
    raise SystemExit('Invalid development public base URL')
gpg = ['gpg', '--homedir', str(state / 'gnupg'), '--batch']
listing = subprocess.check_output(gpg + ['--with-colons', '--list-secret-keys'], stderr=subprocess.DEVNULL).decode()
if 'fpr:' not in listing:
    subprocess.run(gpg + ['--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                        'LibreHub DEVELOPMENT ONLY (ephemeral) <development@librehub.invalid>', 'rsa2048', 'sign', '1d'], check=True)
    listing = subprocess.check_output(gpg + ['--with-colons', '--list-secret-keys'], stderr=subprocess.DEVNULL).decode()
fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
key = subprocess.check_output(gpg + ['--export', fingerprint])
if not key:
    raise SystemExit('Public signing key export failed')
secret_file = state / 'token-secret'
if not secret_file.exists():
    secret_file.write_text(base64.b64encode(secrets.token_bytes(32)).decode())
secret = secret_file.read_text().strip()
repos = {}
for channel in ['stable', 'beta']:
    path = public / 'repo' / channel
    path.parent.mkdir(parents=True, exist_ok=True)
    if not (path / 'config').exists():
        subprocess.run(['ostree', f'--repo={path}', 'init', '--mode=archive-z2'], check=True)
    subprocess.run(['flatpak', 'build-update-repo', f'--gpg-homedir={state / "gnupg"}',
                    f'--gpg-sign={fingerprint}', str(path)], check=True)
    repos[channel] = {'path': str(path), 'gpg-key': fingerprint, 'collection-id': None,
                      'suggested-repo-name': 'librehub' if channel == 'stable' else 'librehub-beta',
                      'runtime-repo-url': 'https://dl.flathub.org/repo/flathub.flatpakrepo',
                      'base-url': f'{base}/repo/{channel}/', 'subsets': {}}
    filename = 'librehub.flatpakrepo' if channel == 'stable' else 'librehub-beta.flatpakrepo'
    (public / filename).write_text(f'''[Flatpak Repo]
Version=1
Title=LibreHub ({channel})
Url={base}/repo/{channel}/
Homepage={base}
Comment=Open application distribution for Linux
Description=LibreHub Flatpak repository
DefaultBranch=master
GPGKey={base64.b64encode(key).decode()}
RuntimeRepo=https://dl.flathub.org/repo/flathub.flatpakrepo
''')
(public / 'repository.gpg').write_bytes(key)
config = {'host': '0.0.0.0', 'port': 8080, 'base-url': 'http://flat-manager:8080',
          'database-url': 'postgres://librehub:development-only@postgres/librehub',
          'secret': secret, 'repos': repos, 'build-repo-base': str(state / 'builds'),
          'build-gpg-key': fingerprint, 'gpg-homedir': str(state / 'gnupg'),
          'delay-update-secs': 0, 'workers': 2}
(state / 'config.json').write_text(json.dumps(config))
token = subprocess.check_output(['flat-manager-client', 'gentoken', '--base64', '--secret-file', str(secret_file),
                                '--name', 'librehub-development-publisher', '--duration', '86400',
                                '--scope', 'build', '--scope', 'upload', '--scope', 'publish',
                                '--repo', 'stable', '--repo', 'beta', '--branch', '']).decode().strip()
(host / 'publisher.token').write_text(token)
(host / 'repository.gpg').write_bytes(key)
# Host API receives a scoped token and public key ONLY. Signing private keys remain in /state.
host.chmod(0o755)
owner = int(os.environ.get('LIBREHUB_DEV_UID', '1000'))
group = int(os.environ.get('LIBREHUB_DEV_GID', '1000'))
for file in host.iterdir():
    os.chown(file, owner, group)
os.chown(host, owner, group)
os.chown(host.parent, owner, group)
host.parent.chmod(0o755)
# Repositories and trust files are public; nginx must be able to traverse/read them.
for root, dirs, files in os.walk(public):
    Path(root).chmod(0o755)
    for name in files:
        (Path(root) / name).chmod(0o644)
(host / 'publisher.env').write_text(f'''export LIBREHUB_FLAT_MANAGER_URL=http://127.0.0.1:8081
export LIBREHUB_FLAT_MANAGER_TOKEN_FILE='{host.resolve() / "publisher.token"}'
export LIBREHUB_SIGNING_PUBLIC_KEY_FILE='{host.resolve() / "repository.gpg"}'
export LIBREHUB_SIGNING_FINGERPRINT={fingerprint}
export LIBREHUB_PUBLIC_BASE_URL={shlex.quote(base)}
''')
# Replace container paths by the caller's absolute host directory without shell interpolation.
host_path = os.environ.get('LIBREHUB_HOST_OUTPUT', '')
if not host_path or any(c in host_path for c in "'\n\r"):
    raise SystemExit('LIBREHUB_HOST_OUTPUT must be a safe absolute host directory')
env_file = host / 'publisher.env'
env_file.write_text(env_file.read_text().replace('/host-output/dev', host_path))
os.chown(env_file, owner, group)
print('Development repositories initialized; signing key stays in the trusted manager volume.')
