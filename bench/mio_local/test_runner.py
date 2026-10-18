"""Fake lifecycle and HTTP responses: no loopback or Unix bind required."""
from __future__ import annotations

import ast
import io
import json
import threading
import time
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest

from azazel_nexus.advisory_response import read_advisory
from bench.mio_local.load import EdgeLoad, LoadConfig
from bench.mio_local.metrics import distribution, memory_limit, percentile
from bench.mio_local.runner import FRAMES, SCHEMA, Condition, run_cell
from bench.mio_local.summary import summarize
from bench.mio_local.transport import Observation, stream


class FakeServer:
    socket_path = "/tmp/fake.sock"

    def __init__(self, fail_start=False):
        self.stopped = False
        self.fail_start = fail_start

    def start(self):
        if self.fail_start:
            raise TimeoutError("secret server output")

    def health(self):
        return True

    def stop(self):
        self.stopped = True


FRAMES_DATA = json.loads(FRAMES.read_text())
GOOD = Observation('{"advice":"Further context may clarify the pattern."}', 5, 20, 8, 4, 10)


def run(server=None, condition=None, observer=None):
    return run_cell(server or FakeServer(), condition or Condition(1, False), FRAMES_DATA,
                    prompt_builder=lambda frame: (("user", frame["question"]),),
                    advisory_reader=lambda text: read_advisory(text.encode()),
                    observer=observer or (lambda *args, **kwargs: GOOD))


def test_nearest_rank_requires_twenty():
    assert percentile(list(range(1, 21)), 50) == 10
    assert percentile(list(range(1, 21)), 95) == 19
    assert percentile(list(range(19)), 95) is None
    assert distribution([]) == {"n": 0, "p50": None, "p95": None}


@pytest.mark.parametrize("kwargs", [{"requests": 19}, {"requests": 10001},
    {"concurrency": 3}, {"deadline_s": 0}, {"deadline_s": 601}, {"max_tokens": 4097}])
def test_condition_bounds(kwargs):
    with pytest.raises(ValueError):
        replace(Condition(1, False), **kwargs)


def test_success_counts_fixed_frames_and_no_text_retention():
    server = FakeServer()
    record = run(server)
    assert server.stopped
    assert record["valid_advisory_rate"] == 1
    assert record["total_ms"] == {"n": 20, "p50": 20, "p95": 20}
    assert record["tokens_per_s"]["p50"] == 200
    assert record["generation_tokens_per_s"]["p50"] == 400
    assert [row["frame_id"] for row in record["requests"]] == [
        FRAMES_DATA[i % 4]["request_id"] for i in range(20)]
    assert "Further context" not in json.dumps(record)


def test_refusals_and_timeouts_stay_in_denominator():
    calls = iter(range(20))

    def observer(*args, **kwargs):
        index = next(calls)
        if index == 0:
            raise TimeoutError("secret response")
        if index == 1:
            return replace(GOOD, text="invalid JSON")
        return GOOD

    record = run(observer=observer)
    assert record["valid_advisory_rate"] == 18 / 20
    assert record["total_ms"]["n"] == 19
    assert record["total_ms"]["p95"] is None
    assert "secret response" not in json.dumps(record)


def test_cold_failure_stops_server_and_has_no_percentiles():
    server = FakeServer(fail_start=True)
    record = run(server)
    assert server.stopped
    assert record["error"] == "TimeoutError"
    assert record["attempted"] == 0
    assert record["valid_advisory_rate"] == 0
    assert record["cold_start_ms"] is None
    assert "secret server" not in json.dumps(record)


def test_two_simultaneous_requests_are_bounded():
    lock = threading.Lock()
    gate = threading.Barrier(2)
    active = peak = 0

    def observer(*args, **kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        gate.wait(timeout=2)
        time.sleep(0.001)
        with lock:
            active -= 1
        return GOOD

    record = run(condition=Condition(2, True), observer=observer)
    assert peak == 2
    assert record["stream_completed"] == 20


class FakeHTTP:
    status = 200

    def __init__(self, data):
        self.response = io.BytesIO(data)
        self.closed = False
        self.sock = None

    def request(self, method, path, body, headers):
        self.body = json.loads(body)
        assert method == "POST" and path == "/v1/chat/completions"

    def getresponse(self):
        return self

    def readline(self, limit):
        return self.response.readline(limit)

    def close(self):
        self.closed = True


def test_stream_ttft_usage_and_cleanup(monkeypatch):
    http = FakeHTTP(b'data: {"choices":[{"delta":{"role":"assistant"}}]}\n\n'
                    b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
                    b'data: {"usage":{"prompt_tokens":8,"completion_tokens":4},'
                    b'"timings":{"predicted_ms":10}}\n\ndata: [DONE]\n\n')
    monkeypatch.setattr("bench.mio_local.transport.UnixHTTP", lambda *args, **kwargs: http)
    result = stream("/fake.sock", (("user", "question"),), max_tokens=12, deadline_s=1)
    assert result.text == "hello"
    assert result.ttft_ms is not None and result.total_ms >= result.ttft_ms
    assert result.tokens_out == 4 and result.generation_ms == 10
    assert http.closed and http.body["cache_prompt"] is False


@pytest.mark.parametrize("data", [b"", b"data: bad\n", b"data: " + b"x" * 65536])
def test_stream_rejects_incomplete_invalid_or_oversized_data(monkeypatch, data):
    http = FakeHTTP(data)
    monkeypatch.setattr("bench.mio_local.transport.UnixHTTP", lambda *args, **kwargs: http)
    with pytest.raises(ValueError):
        stream("/fake.sock", (), max_tokens=12, deadline_s=1)
    assert http.closed


def test_missing_tokens_not_estimated():
    record = run(observer=lambda *args, **kwargs: replace(GOOD, tokens_out=None))
    assert record["tokens_per_s"]["n"] == 0


def test_summary_refuses_production_records_and_reports_missing_metrics():
    record = run()
    record.update(schema=SCHEMA, provenance="bench", not_hg05=True,
                  model={"name": "fake"}, resources={"peak_rss_bytes": None,
                                                    "cpu_percent_one_core": None})
    result = summarize([record])
    assert "not_hg05=true" in result and "n/a" in result
    record["not_hg05"] = False
    with pytest.raises(ValueError):
        summarize([record])


def test_frames_are_synthetic_bilingual_and_fixed():
    assert len(FRAMES_DATA) == 4
    assert len({frame["request_id"] for frame in FRAMES_DATA}) == 4
    assert any("認証" in frame["question"] for frame in FRAMES_DATA)
    assert all(frame["privacy_class"] == "P0-public" for frame in FRAMES_DATA)


@pytest.mark.parametrize("kwargs", [{"workers": 0}, {"workers": 5},
    {"cpu_fraction": 1.1}, {"memory_mib": 1025}, {"duration_s": 21601}])
def test_load_bounds(kwargs):
    with pytest.raises(ValueError):
        LoadConfig(**kwargs)


def test_load_children_are_reaped():
    with EdgeLoad(LoadConfig(cpu_fraction=0, memory_mib=1, duration_s=1)) as load:
        assert len(load.processes) == 1
    assert all(not process.is_alive() for process in load.processes)


def test_bench_is_not_a_package_or_source_dependency():
    root = Path(__file__).resolve().parents[2]
    for manifest in (root / "pyproject.toml", root / "runtime/pyproject.toml"):
        config = tomllib.loads(manifest.read_text())
        assert config["tool"]["setuptools"]["packages"]["find"]["where"] == ["src"]
    for source in (root / "src", root / "runtime/src"):
        for path in source.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Import):
                    assert all(alias.name.split(".")[0] != "bench" for alias in node.names)
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert node.module.split(".")[0] != "bench"


def test_memory_limit_is_positive_or_unavailable():
    value = memory_limit()
    assert value is None or value > 0


def test_fixed_frames_use_contract_privacy_classes():
    from azazel_nexus.sanitizer import PrivacyClass
    assert all(PrivacyClass(frame["privacy_class"]) for frame in FRAMES_DATA)


def test_runtime_adapter_uses_public_builder(monkeypatch):
    import sys
    import types

    from azazel_nexus import model_runtime
    from bench.mio_local.runner import runtime_server

    called = {}

    def builder(binary, **kwargs):
        called.update(kwargs)
        return replace(binary, argv=(*binary.argv, "--host", str(kwargs["socket_path"])))

    def server(record, **kwargs):
        called["record"] = record
        called["server"] = kwargs
        return FakeServer()

    monkeypatch.setattr(model_runtime, "llama_server_record", builder, raising=False)
    module = types.ModuleType("azazel_nexus_runtime.mio_serve")
    module.LocalServer = server
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr("bench.mio_local.runner.digest", lambda path: "sha256:" + "0" * 64)
    runtime_server("/usr/libexec/azazel/llama-server", Path("/model.gguf"), Path("/tmp/s.sock"),
                   threads=2, context=2048, max_tokens=256, start_deadline_s=120)
    assert called["threads"] == 2 and called["max_tokens"] == 256
    assert called["record"].argv[-4:] == ("-ngl", "0", "--parallel", "2")
    assert called["server"]["root"] == Path("/")


def test_stream_absolute_deadline(monkeypatch):
    http = FakeHTTP(b"data: [DONE]\n")
    original_read = http.readline

    def delayed_read(limit):
        time.sleep(0.03)
        return original_read(limit)

    http.readline = delayed_read
    monkeypatch.setattr("bench.mio_local.transport.UnixHTTP", lambda *args, **kwargs: http)
    with pytest.raises(TimeoutError):
        stream("/fake.sock", (), max_tokens=12, deadline_s=0.01)
    assert http.closed


def test_proc_meter_tracks_only_socket_owner_and_hwm(monkeypatch, tmp_path):
    from bench.mio_local import metrics

    proc = tmp_path / "proc"
    process = proc / "123"
    process.mkdir(parents=True)
    (process / "cmdline").write_bytes(b"llama-server\0--host\0/tmp/unique.sock\0")
    fields = ["0"] * 40
    fields[0], fields[11], fields[12] = "S", "120", "30"
    (process / "stat").write_text("123 (llama server) " + " ".join(fields))
    (process / "status").write_text("VmRSS:\t1024 kB\nVmHWM:\t2048 kB\n")
    monkeypatch.setattr(metrics, "Path", lambda path: proc if str(path) == "/proc" else Path(path))
    monkeypatch.setattr(metrics.os, "sysconf", lambda name: 100)
    meter = metrics.ProcessMeter("/tmp/unique.sock")
    meter._sample()
    meter.elapsed = 2
    assert meter.record()["peak_rss_bytes"] == 2 * 1024 ** 2
    assert meter.record()["cpu_seconds"] == 1.5
    assert meter.record()["cpu_percent_one_core"] == 75
    other = metrics.ProcessMeter("/tmp/other.sock")
    other._sample()
    assert other.record()["peak_rss_bytes"] is None


def test_cleanup_failure_preserves_rows():
    class StopFailure(FakeServer):
        def stop(self):
            raise RuntimeError("private detail")

    record = run(StopFailure())
    assert record["error"] == "RuntimeError"
    assert record["stream_completed"] == 20
    assert "private detail" not in json.dumps(record)


@pytest.mark.parametrize("usage", [{"completion_tokens": -1}, {"prompt_tokens": "8"}])
def test_stream_rejects_malformed_usage(monkeypatch, usage):
    http = FakeHTTP(b"data: " + json.dumps({"usage": usage}).encode() + b"\ndata: [DONE]\n")
    monkeypatch.setattr("bench.mio_local.transport.UnixHTTP", lambda *args, **kwargs: http)
    with pytest.raises(ValueError):
        stream("/fake.sock", (), max_tokens=12, deadline_s=1)
