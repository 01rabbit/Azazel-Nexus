"""Bounded HTTP over AF_UNIX for a long-lived local inference process.

No prompt, response body or child output is logged. Production admission is
owned by locald; constructing this handle does not admit a runtime.
"""
from __future__ import annotations

import json
import math
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from azazel_nexus.local_advisory import advisory_response_format
from azazel_nexus.model_runtime import RuntimeBinary
from azazel_nexus.runtime_lifecycle import BudgetLedger, LifecycleState, RestartBudget

from .mio_supervisor import ServingProcess, SupervisorRefused

MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024


class LocalServerRefused(SupervisorRefused):
    """A local process or its HTTP response failed, without carrying text."""


@dataclass(frozen=True)
class LocalInferenceRequest:
    prompt_messages: tuple[tuple[str, str], ...] = field(repr=False)
    max_tokens: int = 256
    temperature: float = 0.0

    def __post_init__(self) -> None:
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
    if stream:
        document["stream_options"] = {"include_usage": True}
    return document


@dataclass(frozen=True)
class LocalInferenceResult:
    text: str = field(repr=False)
    tokens_in: int
    tokens_out: int
    timings: dict[str, float]


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
    ) -> None:
        _deadline(start_deadline_s)
        self.record = record
        self.socket_path = Path(socket_path)
        if not self.socket_path.is_absolute() or not str(self.socket_path).endswith(".sock"):
            raise LocalServerRefused("an absolute .sock path is required")
        self.start_deadline_s = start_deadline_s
        self.budget = budget if budget is not None else RestartBudget(generation=0)
        self.ledger = ledger
        self.on_budget_spent = on_budget_spent
        self._child = ServingProcess(record, root=Path(root))
        self._started = False
        self.state = LifecycleState.ABSENT

    def _spend(self) -> None:
        verdict = self.budget.spend()
        if self.ledger is not None:
            self.ledger.save(self.budget, runtime_id=self.record.runtime_id)
        if not verdict.may_restart:
            self.state = LifecycleState.FENCED
            if self.on_budget_spent is not None:
                self.on_budget_spent("mio-local")
            raise LocalServerRefused("restart budget spent; provider fenced")

    def start(self) -> None:
        if self.budget.fenced:
            self.state = LifecycleState.FENCED
            raise LocalServerRefused("provider fenced")
        if self._child.alive and self.health():
            return
        if self._child.process is not None:
            self.stop()
        if self._started:
            self._spend()
        # Refuse existing paths rather than probing or deleting somebody
        # else's socket. Only stop() removes the socket this child created.
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise LocalServerRefused("serving socket already exists")
        self._started = True
        end = _deadline(self.start_deadline_s)
        try:
            self._child.start()
            self.state = LifecycleState.STARTED
            while self._child.alive:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("local server readiness deadline exceeded")
                if self.health(deadline_s=min(remaining, 0.2)):
                    self.state = LifecycleState.SERVING
                    return
                time.sleep(min(0.02, max(0, end - time.monotonic())))
            raise LocalServerRefused("serving process exited before readiness")
        except BaseException:
            self.stop()
            self.state = LifecycleState.CRASHED
            raise

    def health(self, deadline_s: float = 0.2) -> bool:
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

    def infer(self, request: LocalInferenceRequest, deadline_s: float) -> LocalInferenceResult:
        end = _deadline(deadline_s)
        if not self._child.alive or self.state is not LifecycleState.SERVING:
            raise LocalServerRefused("local server is not serving")
        body = json.dumps(inference_document(request), ensure_ascii=False).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise LocalServerRefused("request exceeds byte ceiling")
        began = time.monotonic()
        raw = self._http("POST", "/v1/chat/completions", body, end)
        try:
            data = json.loads(raw)
            text = data["choices"][0]["message"]["content"]
            usage = data["usage"]
            tokens_in, tokens_out = usage["prompt_tokens"], usage["completion_tokens"]
            if (not isinstance(text, str) or type(tokens_in) is not int
                    or type(tokens_out) is not int or min(tokens_in, tokens_out) < 0):
                raise ValueError
            timings = {"total_ms": (time.monotonic() - began) * 1000}
            for key, value in data.get("timings", {}).items():
                if key in ("prompt_n", "prompt_ms", "predicted_n", "predicted_ms", "predicted_per_second"):
                    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                        raise ValueError
                    timings[key] = float(value)
            return LocalInferenceResult(text, tokens_in, tokens_out, timings)
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise LocalServerRefused("invalid inference response") from None

    def _http(self, method: str, path: str, body: bytes, end: float) -> bytes:
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
            peer.sendall(head + body)
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

    def stop(self) -> None:
        owned = self._child.process is not None
        self._child.stop()
        if owned:
            try:
                if self.socket_path.is_socket():
                    self.socket_path.unlink()
            except FileNotFoundError:
                pass
        if self.state is not LifecycleState.FENCED:
            self.state = LifecycleState.STOPPED
