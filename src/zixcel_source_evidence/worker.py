"""One supervised parser process, no project execution, bounded IPC and memory."""
import multiprocessing
import resource
from .model import Code, EvidenceError, pack, unpack

MAX_REPLY = 64 * 1024 * 1024


def serve(channel, limits):
    try:
        ceiling = limits.memory_bytes // 2
        resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))
        from .language import SyntaxAdapter
        channel.send_bytes(pack({"ready": True}))
        while True:
            request = unpack(channel.recv_bytes(MAX_REPLY))
            if request.get("close"):
                break
            try:
                result = SyntaxAdapter(request["language"]).analyze(request["path"], request["raw"].encode(),
                          request["file"], request["owner"], limits)
                reply = pack({"value": result})
                if len(reply) > MAX_REPLY:
                    raise EvidenceError(Code.ResourceLimitExceeded, "parser reply bytes")
            except EvidenceError as error:
                reply = pack(error.wire())
            except MemoryError:
                reply = pack(EvidenceError(Code.ResourceLimitExceeded, "parser memory").wire())
            except Exception:
                reply = pack(EvidenceError(Code.InternalFailure, "parser worker").wire())
            channel.send_bytes(reply)
    except (EOFError, BrokenPipeError, OSError):
        pass
    finally:
        channel.close()


class ParserWorker:
    def __init__(self, limits):
        self.limits, self.closed = limits, False
        context = multiprocessing.get_context("spawn")
        self.channel, child = context.Pipe()
        self.process = context.Process(target=serve, args=(child, limits), daemon=True)
        self.process.start()
        child.close()
        try:
            self._receive()
        except Exception:
            self.close()
            raise

    def _receive(self):
        if not self.channel.poll(self.limits.parser_seconds):
            self.close()
            raise EvidenceError(Code.ResourceLimitExceeded, "parser deadline")
        try:
            result = unpack(self.channel.recv_bytes(MAX_REPLY))
        except (EOFError, OSError) as error:
            self.close()
            raise EvidenceError(Code.ResourceLimitExceeded, "parser process unavailable") from error
        if "error" in result:
            raise EvidenceError(Code(result["error"]), result.get("detail", ""))
        return result

    def analyze(self, language, path, raw, file_id, owner):
        if self.closed:
            raise EvidenceError(Code.AnalyzerUnavailable, "closed parser")
        message = pack({"language": language, "path": path, "raw": raw.decode(), "file": file_id, "owner": owner})
        if len(message) > MAX_REPLY:
            raise EvidenceError(Code.ResourceLimitExceeded, "parser request bytes")
        try:
            self.channel.send_bytes(message)
            return self._receive()["value"]
        except (BrokenPipeError, OSError) as error:
            raise EvidenceError(Code.AnalyzerUnavailable, "parser IPC") from error

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.channel.close()
        self.process.join(timeout=0.2)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=1)
        if self.process.is_alive():
            self.process.kill()
            self.process.join()
        self.process.close()
