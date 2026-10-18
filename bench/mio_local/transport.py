"""Bench-only streaming observer, using HTTP over a local Unix socket."""
from __future__ import annotations

import http.client
import json
import math
import socket
import threading
import time
from dataclasses import dataclass

from azazel_nexus_runtime.mio_serve import LocalInferenceRequest, inference_document


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.peer = self.sock
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect(self.host)
        except BaseException:
            self.sock.close()
            raise


    def abort(self):
        peer = getattr(self, "peer", None)
        if peer is not None:
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.close()


@dataclass(frozen=True)
class Observation:
    text: str
    ttft_ms: float | None
    total_ms: float
    tokens_in: int | None
    tokens_out: int | None
    generation_ms: float | None


def stream(socket_path, messages, *, max_tokens, deadline_s):
    started = time.monotonic()
    connection = UnixHTTP(str(socket_path), timeout=deadline_s)
    text = []
    ttft = None
    usage = {}
    timings = {}
    size = 0
    done = False
    # An absolute watchdog also bounds a peer that trickles bytes inside one line.
    watchdog = threading.Timer(deadline_s, getattr(connection, "abort", connection.close))
    watchdog.daemon = True
    watchdog.start()
    try:
        connection.request("POST", "/v1/chat/completions", body=json.dumps(inference_document(
            LocalInferenceRequest(messages, max_tokens, 0), stream=True,
        )).encode(), headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("inference HTTP status")
        while True:
            remaining = deadline_s - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("inference deadline")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            line = response.readline(65537)
            if time.monotonic() - started >= deadline_s:
                raise TimeoutError("inference deadline")
            size += len(line)
            if size > 1024 * 1024 or len(line) > 65536:
                raise ValueError("stream byte ceiling")
            if not line:
                break
            if not line.startswith(b"data:"):
                continue
            payload = line[5:].strip()
            if payload == b"[DONE]":
                done = True
                break
            data = json.loads(payload)
            usage.update(data.get("usage") or {})
            timings.update(data.get("timings") or {})
            for choice in data.get("choices", []):
                content = choice.get("delta", {}).get("content")
                if content:
                    if ttft is None:
                        ttft = (time.monotonic() - started) * 1000
                    text.append(content)
        if not done:
            raise ValueError("incomplete SSE stream")
        for key in ("prompt_tokens", "completion_tokens"):
            value = usage.get(key)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError("invalid token count")
        generation_ms = timings.get("predicted_ms")
        if generation_ms is not None and (
            type(generation_ms) not in (int, float)
            or not math.isfinite(generation_ms) or generation_ms < 0
        ):
            raise ValueError("invalid generation timing")
        return Observation("".join(text), ttft, (time.monotonic() - started) * 1000,
                           usage.get("prompt_tokens"), usage.get("completion_tokens"),
                           generation_ms)
    except (OSError, ValueError, http.client.HTTPException):
        if time.monotonic() - started >= deadline_s:
            raise TimeoutError("inference deadline") from None
        raise
    finally:
        watchdog.cancel()
        connection.close()
