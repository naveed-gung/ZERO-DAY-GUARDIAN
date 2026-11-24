"""Verify a real EduFlow asset and replay two safe records through Guardian."""
from hashlib import sha1, sha256
import os
from pathlib import Path
import shutil
import struct
import subprocess
from tempfile import TemporaryDirectory
from io import BytesIO
from wsgiref.handlers import SimpleHandler

DEMO = Path(__file__).resolve().parent
ENGINE = DEMO.parents[1] / "detection-engine/src/main/java/com/zerodayguardian/detector"
ASSET = "eduflow-favicon.svg"
EVENT = struct.Struct("<IBBHQIIII16s256sQ64sIi")


def verify_workload():
    asset = (DEMO / ASSET).read_bytes()
    blob = b"blob " + str(len(asset)).encode("ascii") + b"\0" + asset
    if sha1(blob, usedforsecurity=False).hexdigest() != "a103d755ce09e9e89e897dadbf2bdc16cab42b8e":
        raise RuntimeError("EduFlow asset differs from the referenced upstream Git blob")

    def serve_asset(environ, start_response):
        if environ["REQUEST_METHOD"] != "GET" or environ["PATH_INFO"] != "/favicon.svg":
            start_response("404 Not Found", [("Content-Length", "0")])
            return [b""]
        start_response("200 OK", [("Content-Type", "image/svg+xml")])
        return [asset]

    response = BytesIO()
    SimpleHandler(BytesIO(), response, BytesIO(), {
        "REQUEST_METHOD": "GET", "PATH_INFO": "/favicon.svg", "SERVER_PROTOCOL": "HTTP/1.1"
    }).run(serve_asset)
    headers, separator, body = response.getvalue().partition(b"\r\n\r\n")
    if not separator or not headers.startswith(b"HTTP/1.0 200 OK\r\n") or body != asset:
        raise RuntimeError("EduFlow asset response verification failed")
    print(f"[1/3] EduFlow favicon: in-process HTTP 200, {len(asset)} bytes, SHA-256 {sha256(asset).hexdigest()[:12]}", flush=True)


def record(event_type, filename, process_name):
    # The baseline and alert are data fixtures. No kernel operations are attempted.
    return EVENT.pack(0xDEADBEEF, 1, event_type, 1, 1, 42, 42, 1000, 1000,
                      process_name, filename, 1, b"a" * 64, 0, -1)


def jdk_tool(name):
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / (name + (".exe" if os.name == "nt" else ""))
        if candidate.is_file():
            return str(candidate)
    command = shutil.which(name)
    if not command:
        raise SystemExit("A free JDK 21 is required. Set JAVA_HOME or add its bin directory to PATH.")
    return command


def replay(process_name, executable):
    with TemporaryDirectory(prefix="guardian-replay-") as temporary:
        output = Path(temporary)
        fixture = output / "events.bin"
        fixture.write_bytes(record(1, executable, process_name) + record(7, b"", process_name))
        sources = [ENGINE / name for name in ("event/EventType.java", "event/SyscallEvent.java",
                   "detection/DetectionResult.java", "detection/ContainerEscapeRules.java")]
        subprocess.run([jdk_tool("javac"), "-Xlint:all", "-Werror", "-d", str(output),
                        *map(str, sources), str(DEMO / "EduFlowReplay.java")], check=True)
        subprocess.run([jdk_tool("java"), "-cp", str(output), "EduFlowReplay", str(fixture)], check=True)


if __name__ == "__main__":
    verify_workload()
    replay(b"eduflow-demo", b"/usr/bin/python3")
