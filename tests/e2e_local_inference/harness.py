"""One isolated real-model scenario. See README.md for composition details.

Only constructor injection is used. No production attribute, allowlist, path
constant, parser, transport, or process launcher is replaced at runtime.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

QUESTION = "QUESTION_SENTINEL_72ef"
CONTEXT = "CONTEXT_SENTINEL_a41b"
RESPONSE = "RESPONSE_SENTINEL_b3ce"
MODEL_ID = "e2e-model"
RUNTIME_ID = "e2e-llama"


def stage(source: Path, destination: Path) -> None:
    """Keep the actual GGUF, with no multi-GiB copy on the same filesystem."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, destination)
    except OSError:
        shutil.copyfile(source, destination)


def record_for(root: Path, binary: Path, model: Path, sock: Path):
    from azazel_nexus.model_runtime import RuntimeBinary, llama_server_record

    executable = "/usr/libexec/azazel/llama-server"
    target = root / executable.lstrip("/")
    target.parent.mkdir(parents=True)
    # Preserve the real executable and adjacent shared-library lookup. The
    # container supplies the plan's static b11716 binary.
    target.symlink_to(binary)
    artifact = root / "var/lib/azazel/mio" / f"{MODEL_ID}.model"
    stage(model, artifact)
    with binary.open("rb") as stream:
        digest = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    binary_record = RuntimeBinary(
        runtime_id=RUNTIME_ID, executable=executable, version="b11716",
        digest=digest, argv=(executable,),
    )
    record = llama_server_record(
        binary_record, model_path=artifact, socket_path=sock, ctx=2048,
        threads=2, max_tokens=512,
    )
    return replace(record, argv=(*record.argv, "-ngl", "0"))


class ObservedServer:
    """Documented server injection; corrupt only a REAL inference result.

    This is fault evidence at the server/result boundary, not evidence that
    a particular model naturally emits an instruction or 64 KiB response.
    """

    def __init__(self, server):
        self.server = server
        self.mode = "advice"
        self.results = []
        self.emitted_text = []
        self.calls = 0

    def start(self):
        return self.server.start()

    def health(self):
        return self.server.health()

    def stop(self):
        return self.server.stop()

    def infer(self, request, deadline_s):
        self.calls += 1
        # Force a deadline against the actual Unix HTTP client. No sleep and
        # no synthetic TimeoutError. Selection still sees a viable deadline.
        result = self.server.infer(
            request, deadline_s=0.000001 if self.mode == "deadline" else deadline_s,
        )
        self.results.append(result)
        faults = {
            "instruction": json.dumps({"advice": "block host 192.0.2.1", "fields": {}}),
            "oversized": json.dumps({"advice": "x" * (65 * 1024), "fields": {}}),
            "broken_json": '{"advice": "' + RESPONSE,
        }
        if self.mode in faults:
            result = replace(result, text=faults[self.mode])
        self.emitted_text.append(result.text)
        return result


class FixturePreHTTPRefusal(Exception):
    """The test UDS connect failed before any HTTP request bytes were sent."""


class DirectLlamaFixture:
    """Start only the isolated test binary and speak HTTP over its AF_UNIX socket.

    This does not call Nexus LocalServer/ServingProcess or alter their closed
    admission gates. It exercises the real b11716 model wire from the
    GenerationLane fixture, not production model admission or lifecycle.
    """

    def __init__(self, record, *, root: Path, socket_path: Path):
        self.record, self.root, self.socket_path = record, root, socket_path
        self.process = None

    def _http(self, method: str, path: str, body: bytes, deadline_s: float) -> bytes:
        from azazel_nexus_runtime.mio_serve import (
            MAX_HEADER_BYTES, MAX_RESPONSE_BYTES, LocalServerRefused,
        )

        if type(deadline_s) not in (int, float) or deadline_s <= 0:
            raise TimeoutError("fixture HTTP deadline elapsed")
        end = time.monotonic() + deadline_s

        def remaining() -> float:
            value = end - time.monotonic()
            if value <= 0:
                raise TimeoutError("fixture HTTP deadline elapsed")
            return value

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(remaining())
            try:
                peer.connect(str(self.socket_path))
            except OSError:
                raise FixturePreHTTPRefusal("fixture UDS unavailable") from None
            header = (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n"
                      f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                      "Connection: close\r\n\r\n").encode("ascii")
            peer.settimeout(remaining())
            peer.sendall(header + body)
            response_header = bytearray()
            while not response_header.endswith(b"\r\n\r\n"):
                if len(response_header) >= MAX_HEADER_BYTES:
                    raise LocalServerRefused("fixture HTTP headers exceed ceiling")
                peer.settimeout(remaining())
                chunk = peer.recv(1)
                if not chunk:
                    raise LocalServerRefused("fixture HTTP headers incomplete")
                response_header.extend(chunk)
            try:
                lines = response_header.decode("ascii").split("\r\n")
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
                raise LocalServerRefused("fixture HTTP response refused") from None
            response = bytearray()
            while len(response) < length:
                peer.settimeout(remaining())
                chunk = peer.recv(min(65536, length - len(response)))
                if not chunk:
                    raise LocalServerRefused("fixture HTTP body incomplete")
                response.extend(chunk)
            remaining()
            return bytes(response)

    def start(self):
        executable = Path(self.record.argv[0])
        if executable.is_absolute():
            executable = self.root / executable.relative_to("/")
        self.process = subprocess.Popen(
            self.record.argv, executable=str(executable),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env={"PATH": "/nonexistent", "LC_ALL": "C"},
            cwd=str(self.root), close_fds=True, start_new_session=True,
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("fixture model process exited during startup")
            try:
                if self.health():
                    return
            except (OSError, TimeoutError, ValueError, RuntimeError,
                    FixturePreHTTPRefusal):
                pass
            time.sleep(0.1)
        raise TimeoutError("fixture model process readiness deadline elapsed")

    def health(self):
        from azazel_nexus_runtime.mio_serve import LocalServerRefused

        try:
            value = json.loads(self._http("GET", "/health", b"", 1.0))
            return type(value) is dict and value.get("status") == "ok"
        except (OSError, TimeoutError, ValueError, LocalServerRefused,
                FixturePreHTTPRefusal):
            return False

    def infer(self, request, deadline_s, *, allow_unknown_usage=False):
        from azazel_nexus_runtime.mio_serve import (
            MAX_REQUEST_BYTES, LocalInferenceResult, inference_document,
        )

        body = json.dumps(inference_document(request), ensure_ascii=False).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise ValueError("fixture inference request too large")
        began = time.monotonic()
        data = json.loads(self._http("POST", "/v1/chat/completions", body, deadline_s))
        try:
            text = data["choices"][0]["message"]["content"]
            usage = data.get("usage")
            tokens_in = tokens_out = None
            if usage is not None:
                tokens_in, tokens_out = usage["prompt_tokens"], usage["completion_tokens"]
                if (type(tokens_in) is not int or type(tokens_out) is not int
                        or min(tokens_in, tokens_out) < 0):
                    raise ValueError
            elif not allow_unknown_usage:
                raise ValueError
            if type(text) is not str:
                raise ValueError
            timings = {"total_ms": (time.monotonic() - began) * 1000}
            for key, value in data.get("timings", {}).items():
                if key in ("prompt_n", "prompt_ms", "predicted_n", "predicted_ms",
                           "predicted_per_second"):
                    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                        raise ValueError
                    timings[key] = float(value)
            return LocalInferenceResult(text, tokens_in, tokens_out, timings)
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise ValueError("fixture model response invalid") from None

    def stop(self):
        process, self.process = self.process, None
        if process is None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


class NoRemote:
    """Fail loudly if a local-only scenario dispatches remote content."""

    def observe(self, **_):
        return "remote_unavailable"

    def handle(self, *args, **kwargs):
        raise AssertionError("local-only E2E attempted remote inference")


def compose(root: Path, record, observed, *, model_id="e2e-model", runtime_id="e2e-llama",
            generation_lane=None, generation_id="uncommissioned",
            local_route_admitted=True):
    """Compose the real A/B APIs using only trusted constructor injections."""
    from azazel_nexus_runtime.mio_entryd import MioEntryService
    from azazel_nexus_runtime.mio_locald import LocalRuntimeService
    from azazel_nexus_runtime.mio_router import MioRouter

    from azazel_nexus.core_reserve import CoreReserve
    from azazel_nexus.mio_profile import MioProfile
    from azazel_nexus.resource_profile import ResourceProfile
    from azazel_nexus.route_evidence import Prediction
    from azazel_nexus.routing import Route

    reserve = CoreReserve(
        profile=ResourceProfile.STANDARD, reserve_mib=512,
        host_digest="sha256:" + "0" * 64,
        harness_version="e2e-fixture-not-HG-05", sample_count=64, duration_seconds=3600,
    )

    def runtime(identity):
        assert identity == runtime_id
        return record

    local = LocalRuntimeService(
        staging=root / "var/lib/azazel/mio", reserve=reserve,
        admitted=lambda identity: identity == model_id,
        runtime=runtime, server=observed, model_id=model_id, runtime_id=runtime_id,
        generation_lane=generation_lane, generation_id=generation_id,
    )
    router = MioRouter(local=local, remote=NoRemote())
    entry = MioEntryService(
        router=router, profile_reader=lambda: MioProfile.LOCAL_ONLY,
        local_admitted=lambda: local_route_admitted,
        predictions_reader=lambda: {Route.LOCAL: Prediction(
            Route.LOCAL.value, True, 100, 100, 100, False, "e2e fixture prediction",
        )},
    )
    if generation_lane is not None:
        # Test adapter only (in-process): entryd's ordinary fast-assess call -> locald service.
        entry.local = InProcessLocaldAdapter(local)
    return entry, router


def frame(privacy):
    return {
        "request_id": "e2e-request", "privacy_class": privacy,
        "question": QUESTION + ': Return exactly {"advice":"Observation may help.","fields":{}}',
        "context": [{"kind": "observation", "text": CONTEXT + ": the node is quiet."}],
    }


def invoke(entry, privacy):
    from azazel_nexus_runtime.mio_entryd import REGISTRY
    from azazel_nexus_runtime.principal import Principal, PrincipalClass
    from azazel_nexus_runtime.transport import Request

    principal = Principal(os.getuid(), os.getgid(), os.getpid(),
                          frozenset({PrincipalClass.OPERATOR}))
    verb = REGISTRY.resolve("mio.advise", principal)
    assert verb.accepts_payload and verb.payload_contract
    values = {
        "model_id": MODEL_ID, "runtime_id": RUNTIME_ID,
        "request_id": "e2e-request", "privacy_class": privacy,
        "deadline_ms": 60_000,
    }
    arguments = verb.bind({argument.name: values[argument.name] for argument in verb.arguments})
    return entry.handle(Request(
        verb=verb, arguments=arguments, payload=frame(privacy), principal=principal,
    ))


def events(router):
    from azazel_nexus.route_ledger import RouteChain

    # The whole retained chain, so a run across UTC midnight still verifies.
    ledger = RouteChain(router.ledger.directory)
    ledger.verify()
    return [item.event for item in ledger]


def assert_terminal(recorded, terminal):
    from azazel_nexus.routing import Route

    local = [e for e in recorded if e["event_type"] == "mio.route.terminal"
             and e["route"] == Route.LOCAL.value]
    assert local and local[-1]["terminal_event"] == terminal.value, recorded


def assert_fallback(recorded):
    from azazel_nexus.routing import Route

    fallbacks = [e for e in recorded if e["event_type"] == "mio.route.fallback"]
    assert len(fallbacks) == 1, recorded
    assert fallbacks[0]["spent"] is True
    terminals = [e for e in recorded if e["event_type"] == "mio.route.terminal"]
    assert terminals[-1]["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert not any(e.get("outcome") == "answered" for e in terminals)


def assert_no_content(root: Path, observed, extra=()):
    # Scan every persisted file except immutable runtime/model assets. This
    # catches service refusals as well as the verified route chain.
    needles = [QUESTION, CONTEXT, RESPONSE]
    needles.extend(result.text for result in observed.results if result.text)
    needles.extend(observed.emitted_text)
    needles.extend(text for text in extra if text)
    paths = [p for p in root.rglob("*") if p.is_file() and not p.is_symlink()
             and p.suffix != ".model"]
    assert paths, "no persisted audit evidence"
    for path in paths:
        content = path.read_bytes()
        for needle in needles:
            assert needle.encode() not in content, f"content persisted in {path.name}"


def edge_reading():
    from azazel_nexus.cognition import CognitionReading, CognitionState, RemoteState

    return CognitionReading(
        state=CognitionState.CORE_ONLY, remote=RemoteState.DISABLED,
        resource_reason="fixture", topology_reason="fixture",
        asset_reason="fixture", trust_health_reason="fixture",
    )


def authority_snapshot(root):
    """Observe actual persistent state outside the model and M.I.O. ledgers."""
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (root / "var/lib/azazel/state").rglob("*")
        if path.is_file() and "mio" not in path.relative_to(root / "var/lib/azazel/state").parts
    }


def kill_real_server(sock):
    # Observe the PID from an actual kernel peer, rather than accessing the
    # LocalServer's private Popen. Linux is the declared execution container.
    import socket
    import struct

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(str(sock))
        pid, uid, _ = struct.unpack("3i", connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"),
        ))
    assert uid == os.getuid() and pid != os.getpid()
    command = Path(f"/proc/{pid}/cmdline").read_bytes()
    assert b"llama-server" in command and str(sock).encode() in command
    os.kill(pid, signal.SIGKILL)


def crash_scenario(root, record, observed, sock):
    from azazel_nexus.route_selection import TerminalEvent

    entry, router = compose(root, record, observed)
    invoke(entry, "P0-public")
    assert_terminal(events(router), TerminalEvent.ANSWERED)
    ledger = observed.server.ledger
    for _ in range(2):
        kill_real_server(sock)
        until = time.monotonic() + 5
        while observed.health() and time.monotonic() < until:
            time.sleep(0.01)
        assert not observed.health(), "SIGKILL did not remove health"
        if observed.server.budget.remaining:
            observed.start()
            assert observed.health()
        else:
            from azazel_nexus_runtime.mio_serve import LocalServerRefused

            try:
                observed.start()
            except LocalServerRefused:
                pass
            else:
                raise AssertionError("exhausted server restarted")
    reloaded = ledger.load(generation=1, runtime_id=RUNTIME_ID, limit=1)
    assert reloaded.fenced and reloaded.remaining == 0
    assert not reloaded.spend().may_restart
    assert not observed.health()


# ---------------------------------------------------------------------------
# Fixture-authorized MIO shared generation scenario (LAB EVIDENCE ONLY).
#
# Nothing here is HG or production admission evidence. GENERATION_ADMISSION_ENABLED
# and LOCAL_MODEL_ADMISSION_ENABLED are never set or patched, no sealed
# capability is minted, and production files/constants are unchanged. The
# subclass below exists solely so a software test can exercise the real
# GenerationLane -> pinned azazel_mio AssistantCore -> real llama-server path.
# ---------------------------------------------------------------------------
GENERATION_ID = "e2e-fixture-generation"
GENERATION_SCENARIOS = ("generation", "generation_degraded")


def fixture_generation_lane(server):
    """A GenerationLane whose gate honours only an unsealed, test-only capability."""
    from datetime import UTC, datetime, timedelta

    from azazel_nexus_runtime.mio_generation import GenerationCapability, GenerationLane

    class FixtureOnlyGenerationLane(GenerationLane):
        """TEST-ONLY. The production gate (`authorized`) stays closed for this."""

        def _authorized(self, generation_id):
            cap = self.capability
            return (type(cap) is GenerationCapability and cap._seal is None
                    and cap.role == "generation" and cap.generation_id == generation_id
                    and datetime.now(UTC) < datetime.fromisoformat(
                        cap.expires_at.replace("Z", "+00:00")))

    capability = GenerationCapability(
        generation_id=GENERATION_ID, model_id=MODEL_ID, reserve_mib=512,
        expires_at=(datetime.now(UTC) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        recheck=lambda: True,
    )
    lane = FixtureOnlyGenerationLane(capability=capability, server=server, deadline_s=30.0)
    return lane, capability


class GenerationProbe:
    """Record infer-boundary attempts/results; content is held only for leak scans."""

    def __init__(self, server):
        self.server = server
        self.infer_attempts = 0
        self.pre_http_refusals = 0
        self.other_errors = 0
        self.results = []
        self.emitted_text = []

    def infer(self, request, deadline_s, **kwargs):
        self.infer_attempts += 1
        try:
            result = self.server.infer(request, deadline_s, **kwargs)
        except FixturePreHTTPRefusal:
            self.pre_http_refusals += 1
            raise
        except Exception:
            self.other_errors += 1
            raise
        self.results.append(result)
        self.emitted_text.append(result.text)
        return result

    def stop(self):
        return self.server.stop()


class InProcessLocaldAdapter:
    """Smallest test adapter: entryd's ordinary fast-assess call -> LocalRuntimeService.

    This stays IN-PROCESS (service composition only). It is NOT a production
    socket/process test: no azmio account, AF_UNIX service socket, or peer
    credential check is exercised. Only llama-server is a separate OS process.
    """

    def __init__(self, service):
        self.service = service
        self.last_slow_analysis = {"state": "closed", "usage": "unknown"}

    def observe(self, *, deadline_s):
        """Report this fixture's boundary accurately: local execution is not admitted."""
        return "local_not_admitted" if deadline_s > 0 else "local_unavailable"

    def _request(self, verb, arguments, payload=None):
        from azazel_nexus_runtime.principal import Principal, PrincipalClass
        from azazel_nexus_runtime.transport import Request

        principal = Principal(os.getuid(), os.getgid(), os.getpid(),
                              frozenset({PrincipalClass.SERVICE}))
        return Request(verb=verb, arguments=verb.bind(arguments), payload=payload,
                       principal=principal)

    def assess(self, frame, *, deadline_s):
        from azazel_nexus_runtime.mio_generation import read_slow_analysis
        from azazel_nexus_runtime.mio_locald import FAST_ASSESS_VERB

        reply = self.service.handle(self._request(
            FAST_ASSESS_VERB, {"deadline_ms": max(1, min(60_000, int(deadline_s * 1000)))},
            frame))
        assert reply["outcome"] == "assessed", reply.get("outcome")
        self.last_slow_analysis = read_slow_analysis(reply["slow_analysis"])
        return reply["fast_assistance"]

    def generation_result(self, receipt):
        from azazel_nexus_runtime.mio_generation import read_slow_analysis
        from azazel_nexus_runtime.mio_locald import GENERATION_RESULT_VERB

        reply = self.service.handle(self._request(GENERATION_RESULT_VERB, {
            key: receipt[key] for key in ("result_handle", "generation_id", "trace_id")}))
        return read_slow_analysis(reply["slow_analysis"])


class LogCapture:
    """Collect log records so the scenario can prove none carry content."""

    def __init__(self):
        import logging

        self.records = []
        outer = self

        class Handler(logging.Handler):
            def emit(self, record):
                outer.records.append(self.format(record))

        self.handler = Handler(level=logging.DEBUG)
        self.root = logging.getLogger()
        self.previous = self.root.level
        self.root.addHandler(self.handler)
        self.root.setLevel(logging.DEBUG)

    def close(self):
        self.root.removeHandler(self.handler)
        self.root.setLevel(self.previous)


def generation_scenario(root, record, observed, privacy, *, degraded):
    from azazel_nexus_runtime import mio_generation
    from azazel_nexus_runtime.mio_generation import authorized

    from azazel_nexus import model_admission
    from azazel_nexus.routing import Route

    probe = GenerationProbe(observed.server)
    lane, capability = fixture_generation_lane(probe)
    # Production gate evidence: constants untouched, fixture capability not production-valid.
    assert mio_generation.GENERATION_ADMISSION_ENABLED is False
    assert model_admission.LOCAL_MODEL_ADMISSION_ENABLED is False
    assert authorized(capability, GENERATION_ID) is False
    before = edge_reading()
    before_authority = authority_snapshot(root)
    logs = LogCapture()
    try:
        entry, router = compose(root, record, observed,
                                generation_lane=lane, generation_id=GENERATION_ID,
                                local_route_admitted=False)
        if degraded:
            # Real failure: the actual llama-server process is gone before dispatch.
            observed.stop()
        reply = invoke(entry, privacy)
        assert "fast_assistance" in reply
        assert reply["fast_assistance"]["generation_method"] == "static_reference"
        assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
        queued = reply["slow_analysis"]
        if degraded:
            assert queued["state"] in {"queued", "degraded"}, queued["state"]
        else:
            assert queued["state"] == "queued", queued["state"]
        final = queued
        until = time.monotonic() + 90
        while final["state"] == "queued" and time.monotonic() < until:
            time.sleep(0.1)
            final = entry.local.generation_result(queued)
        if degraded:
            assert final["state"] == "degraded", final["state"]
            assert final["usage"] == "unknown" and "assistance" not in final
            assert (probe.infer_attempts == 1 and probe.pre_http_refusals == 1
                    and probe.other_errors == 0 and not probe.results)
        else:
            assert final["state"] == "complete", final["state"]
            assert final["assistance"]["generation_method"] == "model"
            assert probe.pre_http_refusals == 0 and probe.other_errors == 0
            assert probe.infer_attempts >= 1
            assert len(final["calls"]) == probe.infer_attempts == len(probe.results)
            known = all(r.tokens_in is not None and r.tokens_out is not None
                        for r in probe.results)
            assert (final["usage"] == "known") is known
            for call, result in zip(final["calls"], probe.results):
                assert call["timings"].get("total_ms", -1) >= 0
                if result.tokens_in is None or result.tokens_out is None:
                    assert call["usage"] is None  # unknown stays unknown
                else:
                    assert call["usage"] == {"tokens_in": result.tokens_in,
                                             "tokens_out": result.tokens_out}
        assert_no_content(root, observed, probe.emitted_text)
        needles = (QUESTION, CONTEXT, RESPONSE, *probe.emitted_text, *observed.emitted_text)
        for message in logs.records:
            for needle in needles:
                assert not needle or needle not in message, "content reached logging"
        assert edge_reading() == before
        assert authority_snapshot(root) == before_authority
        assert mio_generation.GENERATION_ADMISSION_ENABLED is False
        assert model_admission.LOCAL_MODEL_ADMISSION_ENABLED is False
        route_events = events(router)  # route chain still verifies
        selected = [event for event in route_events
                    if event.get("event_type") == "mio.route.selected"]
        assert selected and selected[-1]["route"] == Route.DETERMINISTIC_HANDOFF.value
        tokens_in = [r.tokens_in for r in probe.results] or "unknown"
        tokens_out = [r.tokens_out for r in probe.results] or "unknown"
        timings = [c["timings"].get("total_ms") for c in final.get("calls", [])]
        # Numbers and labels only; never request or response content.
        print("FIXTURE-AUTHORIZED LAB EVIDENCE ONLY (not HG, not production admission); "
              "entryd->locald adapter is in-process, llama-server is a separate process: "
              f"{'generation_degraded' if degraded else 'generation'}/{privacy} "
              f"state={final['state']} infer_attempts={probe.infer_attempts} "
              f"pre_http_refusals={probe.pre_http_refusals} other_errors={probe.other_errors} "
              f"usage={final['usage']} tokens_in={tokens_in} tokens_out={tokens_out} "
              f"total_ms={timings}")
    finally:
        try:
            lane.cancel()
        finally:
            logs.close()


def main():
    from azazel_nexus_runtime.mio_serve import LocalServer

    from azazel_nexus.route_selection import TerminalEvent
    from azazel_nexus.runtime_lifecycle import BudgetLedger, RestartBudget

    def terminate(signum, frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    scenario, privacy, binary, model = sys.argv[1:]
    root = Path(os.environ["AZAZEL_ROOT"])
    sock = root / "llama.sock"
    (root / "var/lib/azazel/state/mio").mkdir(parents=True)
    record = record_for(root, Path(binary), Path(model), sock)
    if scenario in GENERATION_SCENARIOS:
        # Test-only direct process: production LocalServer admission stays closed.
        provider = DirectLlamaFixture(record, root=root, socket_path=sock)
    else:
        provider = LocalServer(
            record, root=root, socket_path=sock, start_deadline_s=90,
            budget=RestartBudget(generation=1, limit=1),
            ledger=BudgetLedger(root / "var/lib/azazel/state/mio/restarts.json"),
        )
    observed = ObservedServer(provider)
    before = edge_reading()
    authority = root / "var/lib/azazel/state/activation/e2e-authority.json"
    authority.parent.mkdir(parents=True)
    authority.write_text(json.dumps({
        "fixture": True, "edge_authority": "deterministic-arbiter",
        "lease_expires_at": "2000-01-01T00:00:00Z", "enforcement": False,
    }))
    before_authority = authority_snapshot(root)
    try:
        observed.start()
        assert observed.health(), "real llama-server did not become healthy"
        if scenario in GENERATION_SCENARIOS:
            generation_scenario(root, record, observed, privacy,
                                degraded=scenario == "generation_degraded")
            return
        if scenario == "crash":
            crash_scenario(root, record, observed, sock)
        else:
            modes = ["advice", "deadline", "instruction"] if scenario == "edge" else [scenario]
            for mode in modes:
                entry, router = compose(root, record, observed)
                prior = len(events(router))
                prior_calls = observed.calls
                observed.mode = mode
                if mode == "socket_absent":
                    observed.stop()
                    # A missing socket after a real successful health probe.
                    sock.unlink(missing_ok=True)
                reply = invoke(entry, privacy)
                assert observed.calls == prior_calls + 1, "local provider retried"
                recorded = events(router)[prior:]
                expected = {
                    "deadline": TerminalEvent.TIMED_OUT,
                    "instruction": TerminalEvent.NOT_ADVICE,
                    "oversized": TerminalEvent.NOT_ADVICE,
                    "broken_json": TerminalEvent.NOT_ADVICE,
                    "socket_absent": TerminalEvent.FAILED,
                }.get(mode, TerminalEvent.ANSWERED)
                assert_terminal(recorded, expected)
                if expected is TerminalEvent.ANSWERED:
                    assert reply["outcome"] == "answered", reply
                    assert observed.results and observed.results[-1].tokens_out > 0
                    assert any(e["event_type"] == "mio.local.request" for e in recorded)
                    assert any(e["event_type"] == "mio.local.advisory.read" for e in recorded)
                else:
                    assert_fallback(recorded)
                assert_no_content(root, observed)
                assert edge_reading() == before
                assert authority_snapshot(root) == before_authority
                assert before.blocks_deterministic_path() is False
                if mode == "deadline":
                    # A timed-out client can leave generation running briefly;
                    # stop before the next Edge scenario to bound resource use.
                    observed.stop()
                    if scenario == "edge":
                        observed.start()
        assert edge_reading() == before
        assert authority_snapshot(root) == before_authority
        assert_no_content(root, observed)
        print(f"PASS real llama-server: {scenario}/{privacy}")
    finally:
        observed.stop()


if __name__ == "__main__":
    main()
