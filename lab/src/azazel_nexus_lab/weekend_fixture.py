"""Explicit bridge to repository test fixtures; no serving adapter lives in lab.

The weekend acceptance launcher requires the source test harness. These helpers
are not an installed serving implementation or a production admission path.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import time


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def harness(repo):
    return load_file('weekend_existing_e2e', Path(repo) / 'tests/e2e_local_inference/harness.py')


def _fixture_support(repo):
    return load_file('weekend_test_support', Path(repo) / 'tests/e2e_local_inference/weekend_fixture.py')


def fixture_lane(repo, server, *, short=False):
    return _fixture_support(repo).fixture_lane(repo, server, short=short)


def submit_product_fixture(repo, server, source):
    """Drive the product budget path with a validated synthetic fixture input.

    The caller owns the fixture server and polls the returned lane. This uses
    only the existing unsealed test capability; production admission is closed.
    """
    from azazel_nexus.local_advisory import read_frame
    from azazel_nexus_runtime.mio_fast_assistance import _frame
    source = read_frame(source)
    frame, selection = _frame(source, with_selection=True)
    lane, cap = fixture_lane(repo, server, short=False)
    first = lane.submit(source, frame, cap.generation_id,
                        upstream_coverage=selection['coverage'], upstream_selection=selection)
    return lane, cap, frame, first


def production_control(cap, server, frame):
    repo = Path(__file__).resolve().parents[3]
    return _fixture_support(repo).production_control(cap, server, frame)


def native_fixture_wire(repo, direct):
    return _fixture_support(repo).NativeFixtureWire(direct)


def poll(lane, first, generation_id, trace_id):
    end = time.monotonic() + 30
    value = first
    while value['state'] == 'queued' and time.monotonic() < end:
        time.sleep(.002)
        value = lane.poll(first['result_handle'], generation_id, trace_id)
    if value['state'] == 'queued':
        raise AssertionError('fixture job exceeded 30 seconds')
    return value
