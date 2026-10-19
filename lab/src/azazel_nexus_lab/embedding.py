"""The shipped lab has no embedding serving or admission adapter."""

from .refusal import LabRefused

MESSAGE = (
    "LAB: embedding serving is unavailable; use tests/e2e_local_inference/harness.py "
    "for test-only inference. Production admission remains closed; "
    "this lab path is not an admission and is not hardware evidence."
)


def refuse_embedding():
    raise LabRefused(MESSAGE)
