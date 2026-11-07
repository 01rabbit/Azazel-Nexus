"""Test-only weekend serving composition, next to the existing E2E seam.

Not installed in the lab distribution. No production gate or issuer is changed.
The only authorization override remains harness.fixture_generation_lane.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def harness(repo):
    return load_file('weekend_existing_e2e', Path(repo) / 'tests/e2e_local_inference/harness.py')


def fixture_lane(repo, server, *, short=False):
    """Reuse precisely the existing unsealed capability's test-only seam."""
    from azazel_nexus_runtime.mio_budget_session import BudgetSession
    from azazel_nexus_runtime.mio_serve import LocalInferenceRequest

    base, cap = harness(repo).fixture_generation_lane(server)

    class ShortSession(BudgetSession):
        def request(self, task, prompt):
            return LocalInferenceRequest((('user', prompt),), max_tokens=100,
                response_format={'type': 'json_schema', 'json_schema': {
                    'name': task, 'strict': True, 'schema': SHORT_SCHEMA}})

    class ShortLane(type(base)):
        def _make_budget_session(self, job, api):
            return ShortSession(self, job, api)

        def _execute_budget(self, job, core_type, api):
            return super()._execute_budget(job, ShortCore, api)

    cls = ShortLane if short else type(base)
    lane = cls(capability=cap, server=server, deadline_s=30.0, budget_enabled=True,
               **({'output_caps': (100, 100, 100)} if short else {}))
    return lane, cap


SHORT_SCHEMA = {'type': 'object', 'properties': {'ok': {'type': 'boolean', 'const': True}},
                'required': ['ok'], 'additionalProperties': False}
SHORT_PROMPT = ('Return only the JSON object {"ok":true}. Synthetic transport fixture; '
                'no security recommendation or operational authority. ' +
                'The supplied observation is explicitly unverified. ' * 13)


class ShortCore:
    """Reuse U2's fixed three-task transport fixture; never semantic acceptance."""
    def __init__(self, model):
        self.model = model

    def explain(self, frame, *, generation_budget, **kwargs):
        from azazel_mio import budget as api
        from azazel_mio.assistant import Assistance
        from azazel_nexus.generation_budget import TASKS
        calls = dict.fromkeys(TASKS, 0)
        states = dict.fromkeys(TASKS, 'not_started')
        selections = {}
        for task in TASKS:
            budget = generation_budget(task)
            count = budget.count_tokens(SHORT_PROMPT)
            if (count is None or count > budget.input_tokens or
                    count + budget.output_tokens + budget.safety_margin > budget.context_limit):
                break
            selections[task] = api.PromptSelection(
                'full', ('synthetic-fixture',), (), count, 'transport-fixture-v1')

            def notified(task=task):
                if calls[task]:
                    raise RuntimeError('duplicate dispatch')
                calls[task] = 1
                states[task] = 'sent'

            value = self.model.invoke_budgeted(task, SHORT_PROMPT, notified)
            if type(value) is not dict or value != {'ok': True} or type(value['ok']) is not bool:
                break
            states[task] = 'validated'
        receipt = api.GenerationOutcome('partial' if sum(calls.values()) else 'failed', states,
            calls, {task: self.model.usage_for_task(task) for task in TASKS},
            'insufficient_evidence', selections)
        return Assistance(dict(schema_version='mio.assistance.v1', generation_method='static_reference',
            state='insufficient_evidence', frame_id=frame.frame_id, trace_id=frame.trace_id,
            hypotheses=[], unknowns=['Meaning was not validated'], next_checks=[]), receipt)


def production_control(cap, server, frame):
    from azazel_nexus import model_admission
    import azazel_nexus_runtime.mio_generation as generation
    lane = generation.GenerationLane(capability=cap, server=server, budget_enabled=True)
    reply = lane.submit({'request_id': 'same-cap-production'}, frame, cap.generation_id)
    assert reply['state'] == 'closed' and lane._worker is None
    assert generation.authorized(cap, cap.generation_id) is False
    assert generation.GENERATION_ADMISSION_ENABLED is False
    assert model_admission.LOCAL_MODEL_ADMISSION_ENABLED is False
    return {'state': 'closed', 'worker_created': False, 'same_cap': True}


class NativeFixtureWire:
    """Existing owned model fixture plus unchanged product native/count/HTTP methods.

    This object is a lab provider, never a LocalServer instance or admission
    decision. The production positive-send callback remains at socket.send.
    """
    def __init__(self, direct):
        self.direct = direct
        self.socket_path = direct.socket_path
        self.requests = []

    @property
    def _child(self):
        from types import SimpleNamespace
        return SimpleNamespace(alive=self.direct.process is not None and self.direct.process.poll() is None)

    @property
    def state(self):
        from azazel_nexus.runtime_lifecycle import LifecycleState
        return LifecycleState.SERVING if self._child.alive else LifecycleState.STOPPED

    def _check_admission(self):
        if not self._child.alive:
            raise RuntimeError('owned fixture is not serving')

    def _http(self, method, path, body, end, **kwargs):
        from azazel_nexus_runtime.mio_serve import LocalServer
        item = {'method': method, 'path': path, 'positive_send': False}
        if path == '/completion':
            original = kwargs.get('on_dispatch')
            def sent():
                item['positive_send'] = True
                if original is not None:
                    original()
            kwargs['on_dispatch'] = sent
            self.requests.append(item)
        return LocalServer._http(self, method, path, body, end, **kwargs)

    def stop(self):
        return self.direct.stop()

    # Function reuse on this lab object, without assigning anything to LocalServer.
    from azazel_nexus_runtime.mio_serve import LocalServer as _Product
    _verified_tuple = _Product._verified_tuple
    verified_tuple = _Product.verified_tuple
    prepare_native = _Product.prepare_native
    infer_native = _Product.infer_native
    context_limit = _Product.context_limit
