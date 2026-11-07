"""Bounded HTTP over AF_UNIX for a long-lived local inference process.

No prompt, response body or child output is logged. Production admission is
owned by locald; constructing this handle does not admit a runtime.
"""
from __future__ import annotations

import json
import errno
import stat
import threading
import math
import socket
import select
from contextlib import nullcontext
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from azazel_nexus.local_advisory import advisory_response_format
from azazel_nexus.model_runtime import RuntimeBinary
from azazel_nexus.runtime_lifecycle import BudgetLedger, LifecycleState, RestartBudget

from .mio_supervisor import ServingProcess, SupervisorRefused, StopResult, StopState, _write_stop_fence

MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024


def _decode_document(raw):
    def pairs(items):
        result = {}
        for key,value in items:
            if key in result:
                raise ValueError('duplicate response key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('non-finite response value')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)


class LocalServerRefused(SupervisorRefused):
    """A local process or its HTTP response failed, without carrying text."""


@dataclass(frozen=True)
class LocalInferenceRequest:
    prompt_messages: tuple[tuple[str, str], ...] = field(repr=False)
    max_tokens: int = 256
    temperature: float = 0.0
    response_format: dict | None = None

    def __post_init__(self) -> None:
        if self.response_format is not None and type(self.response_format) is not dict:
            raise LocalServerRefused("invalid inference constraint")
        if type(self.max_tokens) is not int or not 1 <= self.max_tokens <= 32768:
            raise LocalServerRefused("invalid token limit")
        if (isinstance(self.temperature, bool)
                or not isinstance(self.temperature, (int, float))
                or not math.isfinite(self.temperature) or not 0 <= self.temperature <= 2):
            raise LocalServerRefused("invalid temperature")
        if not self.prompt_messages or len(self.prompt_messages) > 128:
            raise LocalServerRefused("invalid message count")
        size = 0
        for message in self.prompt_messages:
            if not isinstance(message, (tuple, list)) or len(message) != 2:
                raise LocalServerRefused("invalid message")
            role, text = message
            if role not in ("system", "user", "assistant") or not isinstance(text, str):
                raise LocalServerRefused("invalid message")
            size += len(text)
        if size > MAX_REQUEST_BYTES:
            raise LocalServerRefused("request exceeds byte ceiling")


def inference_document(request: LocalInferenceRequest, *, stream: bool = False) -> dict:
    """The common chat request for serving and the bench's streaming observer."""
    document = {
        "messages": [{"role": role, "content": text} for role, text in request.prompt_messages],
        "max_tokens": request.max_tokens, "temperature": request.temperature,
        "stream": stream, "response_format": advisory_response_format(),
        "cache_prompt": False,
    }
    if request.response_format is not None:
        document['response_format'] = request.response_format
    if stream:
        document["stream_options"] = {"include_usage": True}
    return document


@dataclass(frozen=True)
class LocalInferenceResult:
    text: str = field(repr=False)
    tokens_in: int | None
    tokens_out: int | None
    timings: dict[str, float]
    finish_reason: str | None = None
    context_integrity: str = 'unknown'


@dataclass(frozen=True)
class NativePrompt:
    tokens: tuple[int,...] = field(repr=False)
    request_digest: str
    tuple_id: str


class TokenCountUnknown(LocalServerRefused):
    pass


def request_digest(request):
    from azazel_nexus.generation_budget import canonical_digest
    return canonical_digest(inference_document(request))


def native_result(data, elapsed_ms):
    if type(data) is not dict or type(data.get('content')) is not str:
        raise LocalServerRefused('invalid native content')
    integrity = ('preserved' if data.get('truncated') is False else
                 'truncated' if data.get('truncated') is True else 'unknown')
    tokens_in,tokens_out = data.get('tokens_evaluated'),data.get('tokens_predicted')
    if any(type(v) is not int or v<0 for v in (tokens_in,tokens_out)):
        tokens_in=tokens_out=None
    stop=data.get('stop_type')
    finish=('stop' if data.get('stop') is True and stop in ('eos','word') else
            'length' if stop=='limit' else None)
    if stop is None:
        if data.get('stopped_limit') is True:finish='length'
        elif data.get('stop') is True and (data.get('stopped_eos') is True or data.get('stopped_word') is True):finish='stop'
    raw=data.get('timings',{})
    if type(raw) is not dict:raise LocalServerRefused('invalid native timings')
    timings={'total_ms':elapsed_ms}
    for key in ('prompt_n','prompt_ms','predicted_n','predicted_ms','predicted_per_second'):
        if key in raw:
            v=raw[key]
            if type(v) not in (int,float) or not math.isfinite(v) or v<0:
                raise LocalServerRefused('invalid native timings')
            timings[key]=v
    return LocalInferenceResult(data['content'],tokens_in,tokens_out,timings,finish,integrity)


def _response_integrity(data: dict) -> str:
    """Read request-scoped truncation evidence; absence is not evidence of preservation."""
    timings = data.get('timings', {})
    if type(timings) is not dict:
        raise ValueError('invalid timings')
    values = [source['truncated'] for source in (data, timings) if 'truncated' in source]
    if any(value is True for value in values):
        return 'truncated'
    if values and all(value is False for value in values):
        return 'preserved'
    return 'unknown'


def _deadline(seconds: float) -> float:
    if isinstance(seconds, bool) or not math.isfinite(seconds) or seconds <= 0:
        raise LocalServerRefused("deadline must be finite and positive")
    return time.monotonic() + seconds


class LocalServer:
    """One serving process, explicitly restarted under the existing budget.

    start() is idempotent while healthy. Calling it after a crash or failed
    startup spends a restart. Inference is never replayed automatically.
    An optional ledger persists each spend before the next process starts.
    """

    def __init__(
        self, record: RuntimeBinary, *, root: Path, socket_path: Path,
        start_deadline_s: float = 10, budget: RestartBudget | None = None,
        ledger: BudgetLedger | None = None,
        on_budget_spent: Callable[[str], None] | None = None,
        descriptors=None,
    ) -> None:
        from azazel_nexus import model_admission

        if model_admission.LOCAL_MODEL_ADMISSION_ENABLED is not True:
            raise LocalServerRefused("ADMISSION_DISABLED")
        if descriptors is None:
            raise LocalServerRefused("held verified descriptors required")
        _deadline(start_deadline_s)
        self.record = record
        self.descriptors = descriptors
        self.socket_path = Path(socket_path)
        if not self.socket_path.is_absolute() or not str(self.socket_path).endswith(".sock"):
            raise LocalServerRefused("an absolute .sock path is required")
        self.start_deadline_s = start_deadline_s
        self.budget = budget if budget is not None else RestartBudget(generation=0)
        self.ledger = ledger
        self.on_budget_spent = on_budget_spent
        self._child = ServingProcess(record, root=Path(root), descriptors=descriptors)
        self._started = False
        self.state = LifecycleState.ABSENT
        self._socket_identity = None
        self._stop_lock = threading.RLock()
        self._fence_lock = threading.Lock()
        self._fence_path = (ledger.path.parent if ledger is not None else self.socket_path.parent) / "stop-fence.json"
        self._nexus_stop_unconfirmed = False
        self._last_stop = None
        self._restore_stop_fence()

    def _restore_stop_fence(self):
        try:
            fence = json.loads(self._fence_path.read_text())
            self._nexus_stop_unconfirmed = (fence.get("socket_path") == str(self.socket_path)
                                            and fence.get("state") == "unconfirmed")
        except FileNotFoundError:
            # A crash during the atomic fence write is uncertainty, never clearance.
            self._nexus_stop_unconfirmed = self._fence_path.with_suffix(".json.pending").exists()
        except (OSError, ValueError, AttributeError):
            self._nexus_stop_unconfirmed = True
        if self._nexus_stop_unconfirmed:
            self.state = LifecycleState.FENCED

    def _spend(self) -> None:
        verdict = self.budget.spend()
        if self.ledger is not None:
            self.ledger.save(self.budget, runtime_id=self.record.runtime_id)
        if not verdict.may_restart:
            self.state = LifecycleState.FENCED
            if self.on_budget_spent is not None:
                self.on_budget_spent("mio-local")
            raise LocalServerRefused("restart budget spent; provider fenced")

    def _check_admission(self):
        if any(getattr(self, name, False) for name in
               ('_nexus_stop_unconfirmed', '_nexus_stop_pending', '_nexus_stopped')):
            raise LocalServerRefused("provider stop gate closed")
        from azazel_nexus import model_admission

        if model_admission.LOCAL_MODEL_ADMISSION_ENABLED is not True:
            raise LocalServerRefused("ADMISSION_DISABLED")
        if self.descriptors is None:
            raise LocalServerRefused("held verified descriptors required")
        self.descriptors.recheck()

    def start(self, deadline_s: float | None = None) -> None:
        if self._nexus_stop_unconfirmed:
            raise LocalServerRefused("stop unconfirmed; provider fenced")
        self._check_admission()
        end = _deadline(self.start_deadline_s)
        if deadline_s is not None:
            end = min(end, _deadline(deadline_s))
        if self.budget.fenced:
            self.state = LifecycleState.FENCED
            raise LocalServerRefused("provider fenced")
        if self._child.alive and self.health(deadline_s=min(0.2, max(0.001, end - time.monotonic()))):
            return
        if self._child.process is not None:
            if self.stop().state is not StopState.CONFIRMED:
                raise LocalServerRefused("prior provider stop unconfirmed")
        if self._started:
            self._spend()
        # Refuse existing paths rather than probing or deleting somebody
        # else's socket. Only stop() removes the socket this child created.
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise LocalServerRefused("serving socket already exists")
        self._started = True
        try:
            self._child.start()
            self._last_stop = None
            self._socket_identity = None
            self.state = LifecycleState.STARTED
            while self._child.alive:
                self._capture_socket()
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("local server readiness deadline exceeded")
                if self.health(deadline_s=min(remaining, 0.2)):
                    self._capture_socket()
                    self.state = LifecycleState.SERVING
                    return
                time.sleep(min(0.02, max(0, end - time.monotonic())))
            raise LocalServerRefused("serving process exited before readiness")
        except BaseException:
            self.stop()
            raise

    def health(self, deadline_s: float = 0.2) -> bool:
        if self._nexus_stop_unconfirmed:
            return False
        if not self._child.alive:
            if self._started and self.state is not LifecycleState.STOPPED:
                self.state = LifecycleState.CRASHED
            return False
        try:
            body = self._http("GET", "/health", b"", _deadline(deadline_s))
            ready = json.loads(body)
            return isinstance(ready, dict) and ready.get("status") == "ok"
        except (OSError, ValueError, LocalServerRefused):
            return False

    def infer(self, request: LocalInferenceRequest, deadline_s: float, *,
              allow_unknown_usage: bool = False, on_dispatch: Callable[[], None] | None = None) -> LocalInferenceResult:
        end = _deadline(deadline_s)
        if getattr(self, "_nexus_stop_unconfirmed", False) or not self._child.alive or self.state is not LifecycleState.SERVING:
            raise LocalServerRefused("local server is not serving")
        body = json.dumps(inference_document(request), ensure_ascii=False).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise LocalServerRefused("request exceeds byte ceiling")
        began = time.monotonic()
        if on_dispatch is None:
            raw = self._http("POST", "/v1/chat/completions", body, end)
        else:
            raw = self._http("POST", "/v1/chat/completions", body, end, on_dispatch=on_dispatch)
        try:
            data = _decode_document(raw)
            choice = data["choices"][0]
            text = choice["message"]["content"]
            finish_reason = choice.get('finish_reason')
            if type(finish_reason) is not str or finish_reason not in ('stop', 'length', 'content_filter', 'tool_calls'):
                finish_reason = None
            integrity = _response_integrity(data)
            usage = data.get("usage")
            tokens_in = tokens_out = None
            if usage is not None:
                tokens_in, tokens_out = usage["prompt_tokens"], usage["completion_tokens"]
                if (type(tokens_in) is not int or type(tokens_out) is not int
                        or min(tokens_in, tokens_out) < 0):
                    raise ValueError
            elif not allow_unknown_usage:
                raise ValueError
            if not isinstance(text, str):
                raise ValueError
            timings = {"total_ms": (time.monotonic() - began) * 1000}
            for key, value in data.get("timings", {}).items():
                if key in ("prompt_n", "prompt_ms", "predicted_n", "predicted_ms", "predicted_per_second"):
                    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                        raise ValueError
                    timings[key] = float(value)
            return LocalInferenceResult(text, tokens_in, tokens_out, timings,
                                        finish_reason, integrity)
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise LocalServerRefused("invalid inference response") from None

    def context_limit(self, deadline_s: float) -> int:
        """Read the running server's effective context through the admitted socket."""
        end = _deadline(deadline_s)
        if getattr(self, "_nexus_stop_unconfirmed", False) or not self._child.alive or self.state is not LifecycleState.SERVING:
            raise LocalServerRefused("local server is not serving")
        try:
            data = _decode_document(self._http("GET", "/props", b"", end))
            count = data['default_generation_settings']['n_ctx']
            if type(count) is not int or not 0 < count <= 2**31 - 1:
                raise ValueError
            return count
        except (ValueError, KeyError, TypeError, RecursionError):
            raise LocalServerRefused("invalid context limit") from None

    def tokenize_rendered(self, text: str, deadline_s: float) -> int:
        """Count an already template-rendered prompt; caller must prove rendering identity."""
        return self._tokenize_rendered(text, _deadline(deadline_s))

    def _tokenize_rendered(self, text: str, end: float) -> int:
        if getattr(self, "_nexus_stop_unconfirmed", False) or not self._child.alive or self.state is not LifecycleState.SERVING:
            raise LocalServerRefused("local server is not serving")
        if type(text) is not str:
            raise LocalServerRefused("invalid tokenization input")
        body = json.dumps({'content': text, 'add_special': True}, ensure_ascii=False).encode('utf-8')
        if len(body) > MAX_REQUEST_BYTES:
            raise LocalServerRefused("request exceeds byte ceiling")
        try:
            data = _decode_document(self._http('POST', '/tokenize', body, end))
            tokens = data['tokens']
            if (type(tokens) is not list or not tokens or len(tokens) > MAX_RESPONSE_BYTES // 2
                    or any(type(token) is not int or token < 0 for token in tokens)):
                raise ValueError
            return len(tokens)
        except (ValueError, KeyError, TypeError, RecursionError):
            raise LocalServerRefused("invalid tokenization response") from None

    def count_chat_tokens(self, request: LocalInferenceRequest, deadline_s: float) -> int:
        """Render and tokenize using this same server under one total deadline.

        Callers must still establish that the admitted runtime's template and
        tokenization settings match its chat-completion path before relying on
        the count as exact.
        """
        end = _deadline(deadline_s)
        if getattr(self, "_nexus_stop_unconfirmed", False) or not self._child.alive or self.state is not LifecycleState.SERVING:
            raise LocalServerRefused("local server is not serving")
        body = json.dumps(inference_document(request), ensure_ascii=False).encode('utf-8')
        if len(body) > MAX_REQUEST_BYTES:
            raise LocalServerRefused("request exceeds byte ceiling")
        try:
            data = _decode_document(self._http('POST', '/apply-template', body, end))
            prompt = data['prompt']
            if type(prompt) is not str:
                raise ValueError
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('tokenization deadline exceeded')
            return self._tokenize_rendered(prompt, end)
        except (ValueError, KeyError, TypeError, RecursionError):
            raise LocalServerRefused("invalid rendered prompt") from None

    def _verified_tuple(self, end):
        from azazel_nexus.generation_budget import verified_tuple_from_props
        if getattr(self, "_nexus_stop_unconfirmed", False) or not self._child.alive or self.state is not LifecycleState.SERVING:
            raise TokenCountUnknown('server_tuple_unavailable')
        try:
            props=_decode_document(self._http('GET','/props',b'',end))
            return verified_tuple_from_props(props)
        except TimeoutError:
            raise
        except (KeyError,TypeError,ValueError,RecursionError,LocalServerRefused,OSError):
            raise TokenCountUnknown('server_tuple_unavailable') from None

    def verified_tuple(self, deadline_s):
        return self._verified_tuple(_deadline(deadline_s))

    def prepare_native(self, request, deadline_s, *, expected_tuple):
        end=_deadline(deadline_s)
        try:
            if self._verified_tuple(end)!=expected_tuple:raise TokenCountUnknown('server_tuple_changed')
            body=json.dumps(inference_document(request),ensure_ascii=False).encode()
            if len(body)>MAX_REQUEST_BYTES:raise TokenCountUnknown('request_ceiling')
            prompt=_decode_document(self._http('POST','/apply-template',body,end))['prompt']
            if type(prompt) is not str:raise TokenCountUnknown('template_unknown')
            body=json.dumps({'content':prompt,'add_special':True},ensure_ascii=False).encode()
            if len(body)>MAX_REQUEST_BYTES:raise TokenCountUnknown('request_ceiling')
            tokens=_decode_document(self._http('POST','/tokenize',body,end))['tokens']
            if (type(tokens) is not list or not tokens or len(tokens)>MAX_RESPONSE_BYTES//2
                    or any(type(v) is not int or v<0 for v in tokens)):
                raise TokenCountUnknown('tokens_unknown')
            if self._verified_tuple(end)!=expected_tuple:raise TokenCountUnknown('server_tuple_changed')
            return NativePrompt(tuple(tokens),request_digest(request),expected_tuple['tuple_id'])
        except (KeyError,TypeError,ValueError,RecursionError,LocalServerRefused):
            raise TokenCountUnknown('native_count_unknown') from None

    def infer_native(self, request, deadline_s, *, prepared, expected_tuple,
                     allow_unknown_usage=True, on_dispatch=None, before_dispatch=None, dispatch_guard=None):
        end=_deadline(deadline_s)
        if (type(prepared) is not NativePrompt or prepared.request_digest!=request_digest(request)
                or prepared.tuple_id!=expected_tuple['tuple_id']
                or self._verified_tuple(end)!=expected_tuple):
            raise TokenCountUnknown('server_tuple_changed')
        if not prepared.tokens or any(type(v) is not int or v<0 for v in prepared.tokens):
            raise TokenCountUnknown('native_count_unknown')
        try:
            schema=request.response_format['json_schema']['schema']
            if type(schema) is not dict:raise ValueError
        except (KeyError,TypeError,ValueError):
            raise LocalServerRefused('native_schema_unknown') from None
        body=json.dumps(dict(prompt=list(prepared.tokens),n_predict=request.max_tokens,
            temperature=request.temperature,stream=False,cache_prompt=False,json_schema=schema),ensure_ascii=False).encode()
        if len(body)>MAX_REQUEST_BYTES:raise LocalServerRefused('request exceeds byte ceiling')
        began=time.monotonic()
        kwargs={} if on_dispatch is None else {'on_dispatch':on_dispatch}
        if before_dispatch is not None:kwargs['before_dispatch']=before_dispatch
        if dispatch_guard is not None:kwargs['dispatch_guard']=dispatch_guard
        raw=self._http('POST','/completion',body,end,**kwargs)
        try:
            result=native_result(_decode_document(raw),(time.monotonic()-began)*1000)
            if not allow_unknown_usage and result.tokens_in is None:raise ValueError
            return result
        except (KeyError,TypeError,ValueError,RecursionError):
            raise LocalServerRefused('invalid native response') from None

    def embed(self, texts, deadline_s):
        end = _deadline(deadline_s)
        if getattr(self, "_nexus_stop_unconfirmed", False) or not self._child.alive or self.state is not LifecycleState.SERVING:
            raise LocalServerRefused("local server is not serving")
        if (type(texts) is not list or not 1 <= len(texts) <= 8
                or any(type(t) is not str or not t for t in texts)):
            raise LocalServerRefused("invalid embedding input")
        body = json.dumps({'input': texts}, ensure_ascii=False).encode('utf-8')
        if len(body) > MAX_REQUEST_BYTES:
            raise LocalServerRefused("request exceeds byte ceiling")
        try:
            data = _decode_document(self._http("POST", "/v1/embeddings", body, end))['data']
            if (type(data) is not list or len(data) != len(texts)
                    or any(type(item['index']) is not int for item in data)
                    or sorted(item['index'] for item in data) != list(range(len(texts)))):
                raise ValueError
            from .mio_embedding import normalized

            return [normalized(item['embedding']) for item in sorted(data, key=lambda i: i['index'])]
        except (ValueError, KeyError, TypeError, RecursionError):
            raise LocalServerRefused("invalid embedding response") from None

    def _http(self, method: str, path: str, body: bytes, end: float, *, on_dispatch=None, before_dispatch=None, dispatch_guard=None) -> bytes:
        self._check_admission()

        def remaining() -> float:
            value = end - time.monotonic()
            if value <= 0:
                raise TimeoutError("local HTTP deadline exceeded")
            return value

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(remaining())
            peer.connect(str(self.socket_path))
            head = (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n"
                    f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n").encode("ascii")
            peer.settimeout(remaining())
            self._check_admission()
            if before_dispatch is not None:
                before_dispatch()
            payload=memoryview(head+body)
            sent=0
            while sent<len(payload):
                # The accounting/freeze gate never covers a blocking socket wait.
                peer.settimeout(0 if dispatch_guard is not None else remaining())
                try:
                    with dispatch_guard() if dispatch_guard is not None else nullcontext() as record_sent:
                        remaining()
                        count=peer.send(payload[sent:])
                        if type(count) is not int or count<=0:
                            raise LocalServerRefused('HTTP send made no progress')
                        first=sent==0
                        sent+=count
                        if first and record_sent is not None:
                            record_sent()
                except BlockingIOError:
                    if not select.select([], [peer], [], remaining())[1]:
                        raise TimeoutError('local HTTP write deadline exceeded')
                    continue
                if first and on_dispatch is not None:
                    on_dispatch()
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                if len(header) >= MAX_HEADER_BYTES:
                    raise LocalServerRefused("HTTP headers exceed ceiling")
                peer.settimeout(remaining())
                chunk = peer.recv(1)
                if not chunk:
                    raise LocalServerRefused("incomplete HTTP headers")
                header.extend(chunk)
            try:
                lines = header.decode("ascii").split("\r\n")
                version, status, *_ = lines[0].split(" ")
                if version not in ("HTTP/1.0", "HTTP/1.1") or status != "200":
                    raise ValueError
                headers = {}
                for line in lines[1:-2]:
                    key, value = line.split(":", 1)
                    key = key.lower()
                    if key in headers:
                        raise ValueError
                    headers[key] = value.strip()
                if "transfer-encoding" in headers:
                    raise ValueError
                length = int(headers["content-length"])
                if not 0 <= length <= MAX_RESPONSE_BYTES:
                    raise ValueError
            except (ValueError, KeyError):
                raise LocalServerRefused("invalid or oversized HTTP response") from None
            result = bytearray()
            while len(result) < length:
                peer.settimeout(remaining())
                chunk = peer.recv(min(65536, length - len(result)))
                if not chunk:
                    raise LocalServerRefused("incomplete HTTP body")
                result.extend(chunk)
            remaining()
            return bytes(result)

    def _capture_socket(self) -> None:
        if self._socket_identity is not None:
            return
        try:
            observed = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(observed.st_mode):
            raise LocalServerRefused("owned socket is not a socket")
        self._socket_identity = (observed.st_dev, observed.st_ino)

    def fence_stop(self) -> None:
        """Persist uncertainty. No automatic clear, including after a late stop."""
        self._nexus_stop_unconfirmed = True
        self.state = LifecycleState.FENCED
        process = self._child.process
        value = dict(socket_path=str(self.socket_path), pid=process.pid if process else getattr(self, "_server_pid", None),
                     start_identity=self._child.start_identity, state="unconfirmed", time=time.time())
        # A failed write leaves this instance fenced and is surfaced to its caller.
        with self._fence_lock:
            _write_stop_fence(self._fence_path, value)

    def _socket_stop_state(self) -> StopResult:
        # An escaped child can retain the listener even after the owned group
        # disappears. Unlinking its pathname would hide that live endpoint.
        # Probe only this recorded local socket, nonblocking, without sending.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.setblocking(False)
            code = probe.connect_ex(str(self.socket_path))
        if code in (errno.ECONNREFUSED, errno.ENOENT):
            return StopResult(StopState.CONFIRMED, "owned_socket_inactive")
        if code in (0, errno.EAGAIN, errno.EWOULDBLOCK, errno.EINPROGRESS, errno.EALREADY):
            return StopResult(StopState.UNCONFIRMED, "owned_socket_active")
        return StopResult(StopState.UNKNOWN, "socket_observation_failed")

    def stop(self) -> StopResult:
        with self._stop_lock:
            if self._last_stop is not None and self._last_stop.state is StopState.CONFIRMED:
                return self._last_stop
            if self._child.process is not None:
                self._server_pid = self._child.process.pid
            result = self._child.stop(retain=True)
            if result.state is StopState.CONFIRMED:
                try:
                    try:
                        observed = self.socket_path.lstat()
                    except FileNotFoundError:
                        observed = None
                    if observed is not None:
                        identity = (observed.st_dev, observed.st_ino)
                        if self._socket_identity is None:
                            result = StopResult(StopState.UNKNOWN, "socket_identity_unknown")
                        elif identity == self._socket_identity:
                            result = self._socket_stop_state()
                            if result.state is StopState.CONFIRMED:
                                self.socket_path.unlink()
                                # Verify absence; never unlink a replacement.
                                try:
                                    after = self.socket_path.lstat()
                                except FileNotFoundError:
                                    after = None
                                if after is not None and (after.st_dev, after.st_ino) == identity:
                                    result = StopResult(StopState.UNCONFIRMED, "socket_remaining")
                except OSError:
                    result = StopResult(StopState.UNKNOWN, "socket_observation_failed")
            if result.state is StopState.CONFIRMED:
                self._child.process = None
                if not self._nexus_stop_unconfirmed:
                    self.state = LifecycleState.STOPPED
            else:
                try:
                    self.fence_stop()
                except OSError:
                    result = StopResult(StopState.UNKNOWN, "fence_write_failed")
            self._last_stop = result
            return result
