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

    def test_inflight_request_is_flushed_before_headers_arrive(self):
        snapshots = []
        server = harness.DirectLlamaFixture(None, root=Path("/"), socket_path=Path("/unused"))
        server.telemetry.directory = Path("/unused")
        server.telemetry.write = mock.Mock(side_effect=lambda: snapshots.append(
            json.loads(json.dumps(server.telemetry.data))))
        class WaitingSocket(FakeSocket):
            def recv(self, count):
                saved = snapshots[-1]["requests"][0]
                self_test.assertEqual(saved["phase"], "headers")
                self_test.assertEqual(saved["sent_bytes"], len(self.sent))
                self_test.assertEqual(saved["response_header_bytes"], 0)
                raise socket.timeout("waiting")
        self_test = self
        fake = WaitingSocket(b"")
        module = types.ModuleType("azazel_nexus_runtime.mio_serve")
        module.MAX_HEADER_BYTES, module.MAX_RESPONSE_BYTES = 8192, 65536
        module.LocalServerRefused = type("LocalServerRefused", (Exception,), {})
        with mock.patch.dict(sys.modules, {"azazel_nexus_runtime.mio_serve": module}), \
             mock.patch.object(harness.socket, "socket", return_value=fake):
            with self.assertRaises(TimeoutError):
                server._http("POST", "/v1/chat/completions", b"{}", 1)
        self.assertEqual(snapshots[-1]["requests"][0]["error"], "TimeoutError")

    def test_observation_extracts_rates_and_window_is_separate(self):
        module = types.ModuleType("azazel_nexus_runtime.mio_serve")
        module.MAX_REQUEST_BYTES = 65536
        module.inference_document = lambda request: {"messages": [request]}
        request = "same fixture prompt"
        body = json.dumps(module.inference_document(request), ensure_ascii=False).encode()
        import hashlib
        accepted = json.dumps({"requests": [{"method": "POST", "path": "/v1/chat/completions",
                         "request_body_sha256": hashlib.sha256(body).hexdigest()}]})
        response = {"usage": {"prompt_tokens": 10, "completion_tokens": 4},
                    "timings": {"prompt_n": 10, "prompt_ms": 2000,
                                "predicted_n": 4, "predicted_ms": 1000}}
        server = mock.Mock()
        server._http.return_value = json.dumps(response).encode()
        with mock.patch.dict(sys.modules, {"azazel_nexus_runtime.mio_serve": module}), \
             mock.patch.object(Path, "read_text", return_value=accepted), \
             mock.patch.object(Path, "write_text") as write:
            result = harness.run_observation(server, request, "/unused/out", "/unused/acceptance")
        self.assertEqual(result["prompt_eval_tokens_per_s"], 5)
        self.assertEqual(result["decode_tokens_per_s"], 4)
        self.assertEqual((result["prompt_tokens"], result["completion_tokens"]), (10, 4))
        self.assertFalse(result["acceptance"])
        self.assertTrue(result["matches_acceptance_request"])
        self.assertEqual(server._http.call_args.args[-1], 240.0)
        self.assertEqual(json.loads(write.call_args.args[0])["server_timings"], response["timings"])

    def test_observation_rejects_changed_prompt_and_records_timeout(self):
        module = types.ModuleType("azazel_nexus_runtime.mio_serve")
        module.MAX_REQUEST_BYTES = 65536
        module.inference_document = lambda request: {"prompt": request}
        import hashlib
        body = json.dumps({"prompt": "same"}, ensure_ascii=False).encode()
        accepted = json.dumps({"requests": [{"method": "POST", "path": "/v1/chat/completions",
                         "request_body_sha256": hashlib.sha256(body).hexdigest()}]})
        server = mock.Mock()
        server._http.side_effect = TimeoutError("window expired")
        with mock.patch.dict(sys.modules, {"azazel_nexus_runtime.mio_serve": module}), \
             mock.patch.object(Path, "read_text", return_value=accepted), \
             mock.patch.object(Path, "write_text"):
            mismatch = harness.run_observation(server, "changed", "/unused/out", "/unused/acceptance")
            server._http.assert_not_called()
            timeout = harness.run_observation(server, "same", "/unused/out", "/unused/acceptance")
        self.assertEqual((mismatch["outcome"], mismatch["error"]), ("measurement_failed", "ValueError"))
        self.assertEqual((timeout["outcome"], timeout["error"]), ("measurement_failed", "TimeoutError"))
        self.assertFalse(timeout["acceptance"])

    def test_missing_timings_are_incomplete_not_success(self):
        result = harness.observation_metrics({"usage": {"prompt_tokens": 5,
                                                       "completion_tokens": 1}}, 3.0)
        self.assertEqual(result["outcome"], "measurement_incomplete")
        self.assertIsNone(result["prompt_eval_tokens_per_s"])
        self.assertIsNone(result["decode_tokens_per_s"])

    def test_exact_replay_uses_original_and_rejects_wrong_saved_body(self):
        import hashlib
        module = types.ModuleType("azazel_nexus_runtime.mio_serve")
        module.MAX_REQUEST_BYTES = 65536
        module.inference_document = lambda request: {"prompt": request}
        saved = b'{"prompt":"original", "max_tokens":768}'
        accepted = json.dumps({"requests": [{"method": "POST", "path": "/v1/chat/completions",
                    "request_body_sha256": hashlib.sha256(saved).hexdigest()}]})
        server = mock.Mock()
        server._http.return_value = json.dumps({"usage": {"prompt_tokens": 5, "completion_tokens": 2},
            "timings": {"prompt_n": 5, "prompt_ms": 1000,
                        "predicted_n": 2, "predicted_ms": 1000}}).encode()
        with mock.patch.dict(sys.modules, {"azazel_nexus_runtime.mio_serve": module}), \
             mock.patch.dict(harness.os.environ, {"AZ_E2E_ACCEPTANCE_BODY": "/saved"}), \
             mock.patch.object(Path, "read_text", return_value=accepted), \
             mock.patch.object(Path, "read_bytes", return_value=saved), \
             mock.patch.object(Path, "write_text"):
            result = harness.run_observation(server, "different reconstruction", "/out", "/telemetry")
        self.assertEqual(result["outcome"], "complete")
        self.assertEqual(result["comparison"], "exact_body_replay")
        self.assertEqual(result["excluded_keys"], [])
        self.assertEqual(server._http.call_args.args[2], saved)
        server.reset_mock()
        with mock.patch.dict(sys.modules, {"azazel_nexus_runtime.mio_serve": module}), \
             mock.patch.dict(harness.os.environ, {"AZ_E2E_ACCEPTANCE_BODY": "/saved"}), \
             mock.patch.object(Path, "read_text", return_value=accepted), \
             mock.patch.object(Path, "read_bytes", return_value=b'{"prompt":"modified"}'), \
             mock.patch.object(Path, "write_text"):
            result = harness.run_observation(server, "same", "/out", "/telemetry")
        self.assertEqual(result["outcome"], "measurement_failed")
        server._http.assert_not_called()

    def test_missing_original_replay_fails_closed(self):
        module = types.ModuleType("azazel_nexus_runtime.mio_serve")
        module.MAX_REQUEST_BYTES = 65536
        module.inference_document = lambda request: {"prompt": request}
        server = mock.Mock()
        with mock.patch.dict(sys.modules, {"azazel_nexus_runtime.mio_serve": module}), \
             mock.patch.dict(harness.os.environ, {"AZ_E2E_ACCEPTANCE_BODY": "/missing"}), \
             mock.patch.object(Path, "read_bytes", side_effect=FileNotFoundError), \
             mock.patch.object(Path, "write_text"):
            result = harness.run_observation(server, "text", "/out", "/telemetry")
        self.assertEqual((result["outcome"], result["error"]), ("measurement_failed", "FileNotFoundError"))
        server._http.assert_not_called()
