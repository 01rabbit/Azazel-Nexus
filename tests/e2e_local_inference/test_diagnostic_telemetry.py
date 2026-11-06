"""Small, model-free checks for diagnostic recording and failure isolation."""
import importlib.util
import json
import socket
import sys
import types
from pathlib import Path
from unittest import TestCase, mock

spec = importlib.util.spec_from_file_location("diagnostic_harness", Path(__file__).with_name("harness.py"))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class FakeSocket:
    def __init__(self, response, failure=None):
        self.response, self.failure = response, failure
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def settimeout(self, value): pass
    def connect(self, path): pass
    def sendall(self, value): self.sent = value
    def recv(self, count):
        if self.response:
            chunk, self.response = self.response[:count], self.response[count:]
            return chunk
        if self.failure:
            raise self.failure
        return b""


class TelemetryChecks(TestCase):
    def exchange(self, response, failure=None, broken_telemetry=False):
        fake = FakeSocket(response, failure)
        module = types.ModuleType("azazel_nexus_runtime.mio_serve")
        module.MAX_HEADER_BYTES, module.MAX_RESPONSE_BYTES = 8192, 65536
        module.LocalServerRefused = type("LocalServerRefused", (Exception,), {})
        server = harness.DirectLlamaFixture(None, root=Path("/"), socket_path=Path("/unused"))
        server.telemetry.directory = Path("/unused")
        if broken_telemetry:
            server.telemetry.write = mock.Mock(side_effect=OSError("recording failed"))
        else:
            server.telemetry.write = mock.Mock()
        with mock.patch.dict(sys.modules, {"azazel_nexus_runtime.mio_serve": module}), \
             mock.patch.object(harness.socket, "socket", return_value=fake):
            if failure:
                with self.assertRaises(type(failure)):
                    server._http("POST", "/v1/chat/completions", b"{}", 1)
            else:
                self.assertEqual(server._http("POST", "/v1/chat/completions", b"{}", 1), b"ok")
        return server.telemetry.data["requests"][-1], fake

    def test_complete_phases_and_telemetry_failure_does_not_change_result(self):
        metric, fake = self.exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", broken_telemetry=True)
        self.assertEqual((metric["phase"], metric["status"], metric["response_body_bytes"]), ("complete", "200", 2))
        self.assertEqual(metric["sent_bytes"], len(fake.sent))
        self.assertLessEqual(metric["connect_s"], metric["send_complete_s"])
        self.assertLessEqual(metric["headers_complete_s"], metric["body_complete_s"])

    def test_header_timeout_remains_failure_with_partial_counts(self):
        metric, _ = self.exchange(b"HTTP/1.1 200", socket.timeout("late"))
        self.assertEqual(metric["phase"], "headers")
        self.assertEqual(metric["error"], "TimeoutError")
        self.assertEqual(metric["response_header_bytes"], 12)
        self.assertEqual(metric["response_body_bytes"], 0)
        self.assertIsNone(metric["status"])

    def test_resource_sampling_unavailable_does_not_raise(self):
        process = mock.Mock(pid=-1)
        process.poll.return_value = 1
        telemetry = harness.DiagnosticTelemetry(None)
        telemetry.sample(process)
        self.assertFalse(telemetry.data["samples"][0]["alive"])
        self.assertIsNone(telemetry.safely(lambda: 1 / 0))
