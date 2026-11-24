"""Run Bazaar's permission contract and Guardian's offline replay."""
from hashlib import sha1
from pathlib import Path
import shutil
import subprocess

from eduflow.demo import replay

WORKLOAD = Path(__file__).resolve().parent / "bazaar"

if __name__ == "__main__":
    source = (WORKLOAD / "permissions.ts").read_bytes()
    blob = b"blob " + str(len(source)).encode("ascii") + b"\0" + source
    if sha1(blob, usedforsecurity=False).hexdigest() != "ba193dc01b3d5407ac3b8a9ccea57533f70bbcec":
        raise SystemExit("Bazaar permissions.ts differs from the upstream Git blob.")
    node = shutil.which("node")
    if not node:
        raise SystemExit("Node.js 24+ is required for Bazaar's TypeScript permissions check.")
    print("[1/3] Bazaar inventory permission check (upstream TypeScript)", flush=True)
    subprocess.run([node, str(WORKLOAD / "check.mts")], check=True)
    replay(b"bazaar-demo", b"/usr/bin/node")
