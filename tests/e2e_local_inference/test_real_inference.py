"""Real b11716 llama-server evidence, never a fake HTTP server."""

import sys

import pytest

pytestmark = pytest.mark.real_process


@pytest.mark.parametrize("privacy", [
    "P0-public", "P1-sanitized", "P2-mission", "P3-restricted",
])
def test_entry_to_real_model_returns_advice_for_each_privacy_class(run_real, privacy):
    run_real("advice", privacy)


def test_real_inference_deadline_records_timeout_and_one_fallback(run_real):
    run_real("deadline")


@pytest.mark.parametrize("scenario", ["instruction", "oversized", "broken_json"])
def test_untrusted_output_never_becomes_an_answer(run_real, scenario):
    run_real(scenario)


def test_absent_inference_socket_falls_back_without_answer(run_real):
    run_real("socket_absent")


def test_audit_contains_metadata_and_no_question_context_or_response(run_real):
    run_real("audit")


def test_edge_authority_is_identical_after_answer_timeout_and_refusal(run_real):
    run_real("edge")


@pytest.mark.skipif(sys.platform != "linux", reason="crash PID observation uses Linux /proc")
def test_real_crash_exhausts_persisted_restart_budget_and_fences(run_real):
    run_real("crash")
