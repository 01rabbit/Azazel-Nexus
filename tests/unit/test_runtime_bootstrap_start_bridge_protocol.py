"""Synthetic protocol tests for the owned-loop bootstrap start bridge."""

import asyncio
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_start_bridge import _StartCheckpointBridge
from azazel_nexus_runtime.units import UnitOperationFailed


PHASES = ("before_observation", "before_submission", "after_completion")


def _bridge():
    loop = asyncio.new_event_loop()
    observer = SimpleNamespace(_usable=True)
    return loop, observer, _StartCheckpointBridge(loop, observer)


def _run_rejection(loop, observer, bridge, operation):
    try:
        with pytest.raises(UnitOperationFailed):
            bridge.run(operation(bridge, loop), lambda: None)
        # Let cancellation of the bridge's worker task run to completion.
        loop.run_until_complete(asyncio.sleep(0))
        assert not [task for task in asyncio.all_tasks(loop) if not task.done()]
        assert observer._usable is False
    finally:
        loop.close()


def test_fixed_checkpoint_sequence_is_accepted_and_single_use():
    loop, observer, bridge = _bridge()

    async def operation():
        deadline = loop.time() + 1
        for phase in PHASES:
            await bridge.checkpoint(phase, deadline)

    try:
        assert bridge.run(operation(), lambda: None) is None
        assert observer._usable is True
        with pytest.raises(UnitOperationFailed, match="single-use"):
            bridge.run(object(), lambda: None)
    finally:
        loop.close()


@pytest.mark.parametrize("attempt", [
    "wrong_phase",
    "duplicate_phase",
    "out_of_order",
    "stale_phase",
])
def test_checkpoint_phase_protocol_refuses_invalid_sequence_and_cleans_task(attempt):
    loop, observer, bridge = _bridge()

    async def operation(bridge, loop):
        deadline = loop.time() + 1
        if attempt == "wrong_phase":
            await bridge.checkpoint("not_a_phase", deadline)
        elif attempt == "duplicate_phase":
            await bridge.checkpoint(PHASES[0], deadline)
            await bridge.checkpoint(PHASES[0], deadline)
        elif attempt == "out_of_order":
            await bridge.checkpoint(PHASES[1], deadline)
        else:
            for phase in PHASES:
                await bridge.checkpoint(phase, deadline)
            await bridge.checkpoint(PHASES[0], deadline)

    _run_rejection(loop, observer, bridge, operation)


@pytest.mark.parametrize("deadline_kind", ["string", "bool", "nan", "infinity", "expired"])
def test_checkpoint_rejects_malformed_or_expired_deadline_and_cleans_task(deadline_kind):
    loop, observer, bridge = _bridge()

    async def operation(bridge, loop):
        deadline = {
            "string": "later",
            "bool": True,
            "nan": float("nan"),
            "infinity": float("inf"),
            "expired": loop.time() - 1,
        }[deadline_kind]
        await bridge.checkpoint(PHASES[0], deadline)

    _run_rejection(loop, observer, bridge, operation)


def test_completion_without_all_phases_is_refused_and_cleans_task():
    loop, observer, bridge = _bridge()

    async def operation(_bridge, _loop):
        return None

    _run_rejection(loop, observer, bridge, operation)


@pytest.mark.parametrize("result", [True, "completed", 0])
def test_non_none_completion_is_refused_and_cleans_task(result):
    loop, observer, bridge = _bridge()

    async def operation(bridge, loop):
        deadline = loop.time() + 1
        for phase in PHASES:
            await bridge.checkpoint(phase, deadline)
        return result

    _run_rejection(loop, observer, bridge, operation)


@pytest.mark.parametrize("delta", [-0.1, 0.1])
def test_original_deadline_cannot_change_between_checkpoints(delta):
    loop, observer, bridge = _bridge()

    async def operation(bridge, loop):
        deadline = loop.time() + 1
        await bridge.checkpoint(PHASES[0], deadline)
        await bridge.checkpoint(PHASES[1], deadline + delta)

    _run_rejection(loop, observer, bridge, operation)
