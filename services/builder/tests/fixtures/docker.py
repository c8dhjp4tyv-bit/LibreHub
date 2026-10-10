#!/usr/bin/env python3
"""Fake Docker protocol with a real independently killable child process."""
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import time
root = Path(__file__).parent
args = sys.argv[1:]
mode = (root / "mode").read_text()
with (root / "calls").open("a") as calls:
    calls.write(json.dumps(args) + "\n")
if args[0] == "image":
    print("sha256:" + "a" * 64)
elif args[0] == "run":
    print("flatpak-builder 1.4.4\n" + "b" * 64 + "\n" + "c" * 64)
elif args[0] == "create":
    (root / "container").write_text(args[args.index("--name") + 1])
elif args[0] == "start":
    if mode in ("wait", "timeout"):
        process = subprocess.Popen([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root / "pid").write_text(str(process.pid))
        # Let the child install its handler before indicating build start.
        time.sleep(0.1)
        (root / "started").touch()
        print("building", flush=True)
        print("compiler stderr", file=sys.stderr, flush=True)
        process.wait()
    else:
        print("compiled", flush=True)
        print("warning", file=sys.stderr, flush=True)
        # Simulate start -a succeeding despite a nonzero container exit code.
elif args[0] == "inspect":
    print("sha256:" + "a" * 64 if "--format={{.Image}}" in args else ("23" if mode == "failure" else "0"))
elif args[0] == "cp" and args[-1] == "-":
    if mode == "oversize":
        for _ in range(10000):
            sys.stdout.buffer.write(b"x" * 8192)
            sys.stdout.buffer.flush()
        sys.exit(0)
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
        data = b"Flatpak bundle"
        entry = tarfile.TarInfo("application.flatpak")
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
elif args[0:2] == ["container", "ls"]:
    if (root / "container").exists():
        print((root / "container").read_text())
elif args[0] == "stop":
    if (root / "pid").exists():
        try:
            os.kill(int((root / "pid").read_text()), signal.SIGTERM)
        except ProcessLookupError:
            pass
    # Force the executor down its fallback removal path.
    sys.exit(1 if mode in ("wait", "timeout") else 0)
elif args[0] == "rm":
    if (root / "pid").exists():
        try:
            os.kill(int((root / "pid").read_text()), signal.SIGKILL)
        except ProcessLookupError:
            pass
    (root / "container").unlink(missing_ok=True)
    (root / "removed").touch()
