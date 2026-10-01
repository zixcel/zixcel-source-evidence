"""Bounded client for a trusted Rust language server, never a project command.

The server sees an empty private workspace and explicitly supplied virtual files.
Cargo discovery/checking, build scripts and proc macros are disabled. This is a
source-only compiler query: absent crates/sysroot remain unresolved, not guessed.
"""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time
from .model import Code, EvidenceError, canonical


class RustSession:
    def __init__(self, executable, seconds=20, max_bytes=8*1024*1024, files=None, roots=None,
                 memory_bytes=512*1024*1024, edition="2021"):
        self.seconds, self.max_bytes, self.sequence = seconds, max_bytes, 0
        self.memory_bytes, self.peak_rss = memory_bytes, 0
        self.buffer = bytearray()
        self.workspace = tempfile.TemporaryDirectory(prefix="source-evidence-rust-")
        self.root = Path(self.workspace.name)
        self.files = files or {}
        self.process = None
        self.selector = selectors.DefaultSelector()
        try:
            for name, text in self.files.items():
                self._snapshot(name, text)
            # Do not inherit RUSTC_WRAPPER, project hooks, logs or client secrets.
            self.process = subprocess.Popen(["/usr/bin/prlimit", "--cpu="+str(seconds),
                "--", str(Path(executable).absolute())], cwd=self.root,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "RAYON_NUM_THREADS": "1"}, start_new_session=True)
            os.set_blocking(self.process.stdout.fileno(), False)
            os.set_blocking(self.process.stdin.fileno(), False)
            self.selector.register(self.process.stdout, selectors.EVENT_READ)
            initialized = self.request("initialize", {"processId": os.getpid(), "rootUri": self.root.as_uri(),
                "capabilities": {"general": {"positionEncodings": ["utf-8"]},
                                 "experimental": {"serverStatusNotification": True}},
                "initializationOptions": {"linkedProjects": [{"crates": [
                    {"root_module": str(self.root/name), "edition": edition, "deps": [], "cfg": [], "env": {}}
                    for name in (roots or self.files)]}] if self.files else [], "checkOnSave": False,
                    "check": {"enable": False}, "cargo": {"buildScripts": {"enable": False}},
                    "procMacro": {"enable": False}, "files": {"watcher": "client"},
                    "diagnostics": {"enable": False}, "numThreads": 1}})
            if initialized.get("capabilities", {}).get("positionEncoding") != "utf-8":
                raise EvidenceError(Code.AnalyzerUnavailable, "compiler must negotiate UTF-8 source offsets")
            self.notify("initialized", {})
            if self.files:
                deadline = time.monotonic()+self.seconds
                while True:
                    reply = self._receive(deadline)
                    if reply.get("method") == "experimental/serverStatus" and reply.get("params", {}).get("health") == "error":
                        raise EvidenceError(Code.ResolutionFailure, "compiler workspace initialization")
                    if reply.get("method") == "experimental/serverStatus" and reply.get("params", {}).get("quiescent"):
                        break
        except Exception:
            self.close()
            raise

    def _send(self, payload):
        raw = canonical(payload).encode()
        if len(raw) > self.max_bytes:
            raise EvidenceError(Code.ResourceLimitExceeded, "compiler request bytes")
        message = memoryview(b"Content-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw)
        deadline = time.monotonic() + self.seconds
        with selectors.DefaultSelector() as writable:
            writable.register(self.process.stdin, selectors.EVENT_WRITE)
            while message:
                if not writable.select(max(0, deadline-time.monotonic())):
                    raise EvidenceError(Code.ResourceLimitExceeded, "compiler write deadline")
                try:
                    message = message[os.write(self.process.stdin.fileno(), message):]
                except BlockingIOError:
                    continue
                except OSError as error:
                    raise EvidenceError(Code.AnalyzerUnavailable, "compiler stdin closed") from error

    def _receive(self, deadline):
        while True:
            try:
                status = Path(f"/proc/{self.process.pid}/status").read_text()
                rss = next((int(line.split()[1])*1024 for line in status.splitlines() if line.startswith("VmRSS:")), 0)
                self.peak_rss = max(self.peak_rss, rss)
                if rss > self.memory_bytes:
                    raise EvidenceError(Code.ResourceLimitExceeded, "compiler RSS")
            except FileNotFoundError:
                raise EvidenceError(Code.AnalyzerUnavailable, "compiler process exited") from None
            marker = self.buffer.find(b"\r\n\r\n")
            if marker >= 0:
                try:
                    headers = dict(line.split(b":", 1) for line in bytes(self.buffer[:marker]).split(b"\r\n"))
                    size = int(headers[b"Content-Length"].strip())
                    if size < 0 or size > self.max_bytes:
                        raise EvidenceError(Code.ResourceLimitExceeded, "compiler reply bytes")
                except (ValueError, KeyError) as error:
                    raise EvidenceError(Code.InvalidEvidence, "compiler frame") from error
                end = marker+4+size
                if len(self.buffer) >= end:
                    raw = bytes(self.buffer[marker+4:end])
                    del self.buffer[:end]
                    try:
                        return json.loads(raw)
                    except ValueError as error:
                        raise EvidenceError(Code.InvalidEvidence, "compiler reply") from error
            if len(self.buffer) > self.max_bytes+8192:
                raise EvidenceError(Code.ResourceLimitExceeded, "compiler buffer")
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise EvidenceError(Code.ResourceLimitExceeded, "compiler response deadline")
            if not self.selector.select(min(0.1, remaining)):
                continue
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise EvidenceError(Code.AnalyzerUnavailable, "compiler stdout closed")
            self.buffer.extend(chunk)

    def notify(self, method, params):
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method, params, remaining_updates=2):
        self.sequence += 1
        wanted = self.sequence
        self._send({"jsonrpc": "2.0", "id": wanted, "method": method, "params": params})
        deadline = time.monotonic()+self.seconds
        while time.monotonic() < deadline:
            reply = self._receive(deadline)
            if reply.get("id") == wanted and "method" not in reply:
                if "error" in reply:
                    code = reply["error"].get("code")
                    # LSP ContentModified rejects an obsolete analysis snapshot.
                    # Reissue only pure source queries, with a strict retry cap.
                    if code == -32801 and remaining_updates and method in {"textDocument/definition", "textDocument/hover", "textDocument/documentSymbol"}:
                        return self.request(method, params, remaining_updates-1)
                    raise EvidenceError(Code.ResolutionFailure, "compiler request rejected: "+str(code))
                return reply.get("result")
            if "id" in reply and "method" in reply:
                # Never execute server requests, including applyEdit or commands.
                self._send({"jsonrpc": "2.0", "id": reply["id"], "error": {
                    "code": -32601, "message": "Client mutations and discovery are disabled"}})
        raise EvidenceError(Code.ResourceLimitExceeded, "compiler request deadline")

    def _snapshot(self, name, text):
        if Path(name).is_absolute() or ".." in Path(name).parts or not name.endswith(".rs"):
            raise EvidenceError(Code.UnsafePath, "compiler virtual file")
        if len(text.encode()) > self.max_bytes:
            raise EvidenceError(Code.ResourceLimitExceeded, "compiler source bytes")
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as file:
            file.write(text)
        return path.as_uri()

    def open(self, name, text):
        uri = (self.root/name).as_uri() if name in self.files else self._snapshot(name, text)
        self.notify("textDocument/didOpen", {"textDocument": {
            "uri": uri, "languageId": "rust", "version": 1, "text": text}})
        return uri

    def definition(self, uri, line, byte_column):
        result = self.request("textDocument/definition", {"textDocument": {"uri": uri},
                              "position": {"line": line, "character": byte_column}})
        return result or []

    def close(self):
        if self.process:
            # Close/kill the owned process group; no other user processes touched.
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=1)
            for pipe in (self.process.stdin, self.process.stdout):
                if pipe:
                    pipe.close()
        self.selector.close()
        self.workspace.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
