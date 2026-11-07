"""Closed production control and pre-send count refusal; no model is started."""
from pathlib import Path
import importlib.util
import time

from azazel_nexus import model_admission
from azazel_nexus_runtime import mio_generation
from azazel_nexus_runtime.mio_generation import GenerationLane
from test_budget_api import ControlledServer, inputs, run


def test_same_unsealed_capability_is_rejected_by_production_lane():
    path = Path(__file__).parents[1] / 'e2e_local_inference/harness.py'
    spec = importlib.util.spec_from_file_location('weekend_fixture_harness', path)
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    server = ControlledServer()
    fixture, cap = harness.fixture_generation_lane(server)
    frame, _ = inputs()
    assert fixture._authorized(cap.generation_id) is True
    assert mio_generation.authorized(cap, cap.generation_id) is False
    production = GenerationLane(capability=cap, server=server, budget_enabled=True)
    result = production.submit({'request_id': 'production-control'}, frame, cap.generation_id)
    assert result['state'] == 'closed'
    assert not server.requests
    assert production._worker is None
    assert mio_generation.GENERATION_ADMISSION_ENABLED is False
    assert model_admission.LOCAL_MODEL_ADMISSION_ENABLED is False


def test_exact_counter_unknown_is_zero_send_with_real_mio_budget_api():
    class UnknownCounter(ControlledServer):
        def count_chat_tokens(self, request, deadline_s):
            return None
    started = time.monotonic()
    lane, server, result = run(UnknownCounter())
    assert result['state'] == 'degraded'
    assert not server.requests
    assert result['generation_budget']['job_calls'] == 0
    assert result['generation_budget']['primary_outcome'] == 'token_count_unknown'
    assert time.monotonic() - started < 5
