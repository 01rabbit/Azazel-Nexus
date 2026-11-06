"""Pure fixture checks; this does not exercise a provider or grant admission."""
import pytest

from azazel_nexus_runtime.mio_generation_budget import (
    BudgetPlanner, BudgetProfile, BudgetReason, BudgetRefused, CleanupState,
    settle_cleanup, TaskBudget, TASKS, mio_budget_for_task,
)


def profile(context=200, input_limit=100):
    return BudgetProfile('fixture-only', context, tuple(
        TaskBudget(name, input_limit, 68, 40, .1) for name in TASKS))


def planner(counter=lambda task, prompt: 100, clock=lambda: 0., context=200):
    return BudgetPlanner(profile(context), submitted=0, deadline_s=30,
                         counter=counter, clock=clock)


def test_exact_context_boundary_and_task_allocations():
    p = planner()
    first = p.plan(TASKS[0], 'prompt')
    assert first.input_tokens + first.output_cap + first.context_slack == 200
    assert first.provider_seconds == pytest.approx(12.15)
    p.completed(TASKS[0])
    second = p.plan(TASKS[1], 'prompt')
    assert second.provider_seconds == pytest.approx(5.4)
    p.completed(TASKS[1])
    assert p.plan(TASKS[2], 'prompt').task == TASKS[2]
    p.completed(TASKS[2])
    with pytest.raises(BudgetRefused):
        p.plan(TASKS[0], 'prompt')


def test_context_overflow_and_input_limit_refuse_before_dispatch():
    for p in (planner(context=199), planner(counter=lambda *_: 101, context=300)):
        with pytest.raises(BudgetRefused) as error:
            p.plan(TASKS[0], 'prompt')
        assert error.value.reason is BudgetReason.BUDGET_EXHAUSTED


@pytest.mark.parametrize('count', [None, True, -1, 1.0, float('nan')])
def test_unknown_count_does_not_become_zero(count):
    p = planner(counter=lambda *_: count)
    with pytest.raises(BudgetRefused) as error:
        p.plan(TASKS[0], 'unicode and \\ escapes')
    assert error.value.reason is BudgetReason.COUNT_UNKNOWN


def test_count_time_is_charged_and_future_minimum_reserved():
    ticks = iter((0., 29.))
    p = planner(clock=lambda: next(ticks))
    with pytest.raises(BudgetRefused) as error:
        p.plan(TASKS[0], 'prompt')
    assert error.value.reason is BudgetReason.BUDGET_EXHAUSTED


def test_unknown_counter_and_order_do_not_dispatch():
    p = planner(counter=None)
    with pytest.raises(BudgetRefused) as error:
        p.plan(TASKS[0], 'prompt')
    assert error.value.reason is BudgetReason.COUNT_UNKNOWN
    with pytest.raises(BudgetRefused):
        p.completed(TASKS[0])
    with pytest.raises(BudgetRefused):
        p.plan(TASKS[1], 'prompt')


def test_profile_rejects_boolean_and_caps_above_existing_limit():
    with pytest.raises(ValueError):
        TaskBudget(TASKS[0], True, 68, 40, .1)
    with pytest.raises(ValueError):
        TaskBudget(TASKS[0], 100, 769, 40, .1)


def test_cleanup_is_monotonic_and_confirmation_at_deadline_is_too_late():
    assert settle_cleanup(CleanupState.PENDING, 'stop_confirmed', now=9, end=10) is CleanupState.CONFIRMED
    assert settle_cleanup(CleanupState.PENDING, 'stop_confirmed', now=10, end=10) is CleanupState.UNCONFIRMED
    assert settle_cleanup(CleanupState.PENDING, 'restart_unconfirmed', now=1, end=10) is CleanupState.UNCONFIRMED
    with pytest.raises(ValueError):
        settle_cleanup(CleanupState.UNCONFIRMED, 'stop_confirmed', now=2, end=10)


def test_mio_budget_tuple_uses_final_count_callback_without_importing_mio():
    p = planner(counter=lambda task, prompt: 4 if prompt == 'exact' else None)
    budget = mio_budget_for_task(p, TASKS[0], budget_type=lambda **kw: kw)
    assert budget['input_tokens'] == 100
    assert budget['output_tokens'] == 68
    assert budget['context_limit'] == 200 and budget['safety_margin'] == 32
    assert budget['count_tokens']('exact') == 4
    assert budget['count_tokens']('unknown') is None
    with pytest.raises(BudgetRefused):
        mio_budget_for_task(p, TASKS[1], budget_type=lambda **kw: kw)
