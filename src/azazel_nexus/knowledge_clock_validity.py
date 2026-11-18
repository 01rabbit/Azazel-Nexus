"""Local verified wrapper; signed peer timestamps are never rewritten."""
from dataclasses import dataclass
from datetime import timedelta

from .knowledge_context_adapter import _instant

VALIDITY_SCHEMA = "azazel-knowledge-clock-validity/1"


def read_validity(value):
    keys = {"schema", "contract_id", "signed_expires_at", "semantic_expires_at",
            "effective_expires_at", "adopted_at", "skew_budget_us", "health_generation"}
    if type(value) is not dict or set(value) != keys or value["schema"] != VALIDITY_SCHEMA:
        raise ValueError("clock validity shape")
    import re
    if (type(value["contract_id"]) is not str
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["contract_id"])
            or type(value["skew_budget_us"]) is not int or value["skew_budget_us"] != 5000):
        raise ValueError("clock validity policy")
    generation = value["health_generation"]
    if (type(generation) is not list or len(generation) != 4
            or any(type(x) is not str or not x for x in generation[:2])
            or any(type(x) is not int or x < 0 for x in generation[2:])):
        raise ValueError("clock validity generation")
    sig, sem, eff, adopted = (_instant(value[k]) for k in (
        "signed_expires_at", "semantic_expires_at", "effective_expires_at", "adopted_at"))
    if eff != min(sig, sem) - timedelta(microseconds=value["skew_budget_us"]) or adopted >= eff:
        raise ValueError("clock validity interval")
    return dict(value)


@dataclass(frozen=True)
class VerifiedContext:
    response: object
    contract_id: str
    signed_expires_at: str
    semantic_expires_at: str
    skew_budget_us: int
    health_generation: tuple
    deadline: float
    guard: object

    def model_dump(self, **kwargs):
        return self.response.model_dump(**kwargs)

    def adoption_validity(self, *, utc_now, monotonic, grant_check=lambda: None,
                          caller_deadline=None):
        # Suppliers are deliberately required: sampling before a blocking health
        # or marker read could turn an expired response into a current one.
        if not callable(utc_now) or not callable(monotonic) or not callable(grant_check):
            raise TypeError("adoption clocks must be suppliers")

        def finalize(revalidate_health):
            grant_check()
            revalidate_health()
            now = utc_now()
            mono = monotonic()
            effective = min(_instant(self.signed_expires_at), _instant(self.semantic_expires_at)) - timedelta(
                microseconds=self.skew_budget_us)
            deadline = self.deadline if caller_deadline is None else min(self.deadline, caller_deadline)
            if mono >= deadline or _instant(now) >= effective:
                raise ValueError("clock adoption expired")
            return read_validity({"schema": VALIDITY_SCHEMA, "contract_id": self.contract_id,
                                 "signed_expires_at": self.signed_expires_at,
                                 "semantic_expires_at": self.semantic_expires_at,
                                 "effective_expires_at": effective.isoformat().replace("+00:00", "Z"),
                                 "adopted_at": now, "skew_budget_us": self.skew_budget_us,
                                 "health_generation": list(self.health_generation)})
        return self.guard.run_validated(finalize, expected_generation=self.health_generation)
