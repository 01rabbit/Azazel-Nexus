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
