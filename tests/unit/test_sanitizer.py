"""The deterministic sanitizer (#5, E2).

Four claims, and each has a way of passing for the wrong reason.

*Deny is the default.* Easy to satisfy with a test that only supplies denied
input. The tests here also supply allowed input, so a `sanitize` that denied
everything would fail too.

*Removed, never transformed.* A masked value passes "the secret is not
readable" and fails "the field is absent". Absence is what is asserted.

*Aliases are mission-scoped.* An alias that is stable everywhere satisfies
"the same subject gets the same alias" perfectly. The second half -- a
different mission gives a different alias -- is the half that matters.

*Byte-identical output.* Comparing a call to itself proves nothing about
determinism. The frozen bytes below were produced once and are now a fixture:
a change in field order, separator or key set breaks them.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

from azazel_nexus import sanitizer as sanitizer_module
from azazel_nexus.sanitizer import (
    NEVER_REMOTE,
    PrivacyClass,
    SanitizerPolicy,
    SanitizerRefused,
    count_bucket,
    sanitize,
    time_bucket,
)

ALIAS_KEY = bytes(range(32))
OTHER_KEY = bytes(range(32, 64))

POLICY_MAPPING = {
    "version": "v1",
    "remote_default": "deny",
    "classes": {
        "P0-public": {"remote": "allow", "fields": ["product_version", "technique"]},
        "P1-sanitized": {
            "remote": "allow",
            "fields": ["event_class", "role", "count", "time_bucket", "subject"],
        },
        "P2-mission": {"remote": "deny"},
        "P3-restricted": {"remote": "deny"},
    },
    "redactions": ["ip_address", "hostname", "account", "credential", "secret", "payload", "location"],
    "aliases": ["subject", "role"],
    "time_buckets": ["time_bucket"],
    "count_buckets": ["count"],
    "limits": {"max_bytes": 16384},
}


@pytest.fixture()
def policy() -> SanitizerPolicy:
    return SanitizerPolicy.from_mapping(POLICY_MAPPING)


def run(frame, policy, *, privacy_class=PrivacyClass.P1_SANITIZED, mission="mission-a", key=ALIAS_KEY):
    return sanitize(
        frame, privacy_class=privacy_class, policy=policy, mission=mission, alias_key=key
    )


# -- deny is the default, and allow really happens --------------------------


def test_an_allowed_class_with_allowlisted_fields_produces_a_frame(policy) -> None:
    decision = run({"event_class": "scan", "count": 7}, policy)
    assert decision.allowed is True
    assert decision.frame is not None
    body = json.loads(decision.frame)["body"]
    assert body["event_class"] == "scan"


@pytest.mark.parametrize("privacy_class", sorted(NEVER_REMOTE, key=lambda c: c.value))
def test_a_never_remote_class_produces_zero_egress(policy, privacy_class) -> None:
    """Not an empty frame. No frame."""

    decision = run({"event_class": "scan"}, policy, privacy_class=privacy_class)
    assert decision.allowed is False
    assert decision.frame is None
    assert decision.redaction is None
    assert decision.request_fingerprint is None
    assert "no egress occurs at all" in decision.reason


def test_a_field_outside_the_allowlist_denies_the_whole_frame(policy) -> None:
    """Not dropped quietly. Anything unlisted is denied."""

    decision = run({"event_class": "scan", "internal_note": "anything"}, policy)
    assert decision.allowed is False
    assert decision.frame is None
    assert "not in the allowlist" in decision.reason


def test_a_class_the_policy_does_not_mention_is_denied() -> None:
    minimal = SanitizerPolicy.from_mapping(
        {
            **POLICY_MAPPING,
            "classes": {"P1-sanitized": POLICY_MAPPING["classes"]["P1-sanitized"]},
        }
    )
    decision = run({"product_version": "1"}, minimal, privacy_class=PrivacyClass.P0_PUBLIC)
    assert decision.allowed is False
    assert "anything unlisted is denied" in decision.reason


@pytest.mark.parametrize("mission", ["", "   "])
def test_an_undeclared_mission_scope_denies(policy, mission: str) -> None:
    decision = run({"event_class": "scan"}, policy, mission=mission)
    assert decision.allowed is False
    assert "declared scope" in decision.reason


def test_no_alias_key_denies(policy) -> None:
    decision = run({"event_class": "scan"}, policy, key=b"")
    assert decision.allowed is False
    assert "alias key" in decision.reason


# -- removed, never transformed --------------------------------------------


@pytest.mark.parametrize(
    "field", ["ip_address", "hostname", "account", "credential", "secret", "payload", "location"]
)
def test_a_redacted_field_is_absent_from_the_frame(policy, field: str) -> None:
    """Absent. Not masked, not hashed, not a placeholder.

    A masked value still says the field was present and how long it was.
    """

    decision = run({"event_class": "scan", field: "10.1.2.3-or-whatever"}, policy)
    assert decision.allowed is True
    text = decision.frame.decode("utf-8")
    body = json.loads(text)["body"]
    assert field not in body
    assert "10.1.2.3-or-whatever" not in text
    assert decision.redaction.removed == (field,)


def test_a_redacted_field_does_not_deny_the_frame(policy) -> None:
    """Redaction is checked before the allowlist, and that ordering is the rule.

    `ip_address` is not in any allowlist. If the allowlist ran first, every
    real frame carrying one would be denied instead of cleaned.
    """

    decision = run({"event_class": "scan", "ip_address": "10.0.0.1"}, policy)
    assert decision.allowed is True
    assert "ip_address" not in json.loads(decision.frame)["body"]


def test_only_the_redaction_record_reference_travels(policy) -> None:
    decision = run({"event_class": "scan", "secret": "hunter2"}, policy)
    frame = json.loads(decision.frame)
    assert frame["redaction_record_id"] == decision.redaction.record_id
    assert "removed" not in frame
    assert "hunter2" not in decision.frame.decode("utf-8")
    # The record itself is local and names what went.
    assert decision.redaction.removed == ("secret",)


# -- aliases are mission-scoped --------------------------------------------


def test_the_same_subject_in_one_mission_gets_one_alias(policy) -> None:
    first = run({"subject": "workstation-7"}, policy, mission="mission-a")
    second = run({"subject": "workstation-7"}, policy, mission="mission-a")
    assert first.frame == second.frame


def test_the_same_subject_in_another_mission_gets_another_alias(policy) -> None:
    """The half that matters. A globally stable alias would join two missions."""

    here = run({"subject": "workstation-7"}, policy, mission="mission-a")
    there = run({"subject": "workstation-7"}, policy, mission="mission-b")
    assert json.loads(here.frame)["body"]["subject"] != json.loads(there.frame)["body"]["subject"]


def test_a_different_alias_key_gives_a_different_alias(policy) -> None:
    here = run({"subject": "workstation-7"}, policy, key=ALIAS_KEY)
    there = run({"subject": "workstation-7"}, policy, key=OTHER_KEY)
    assert here.frame != there.frame


def test_the_alias_does_not_contain_the_subject(policy) -> None:
    decision = run({"subject": "workstation-7"}, policy)
    alias = json.loads(decision.frame)["body"]["subject"]
    assert alias.startswith("alias:")
    assert "workstation-7" not in alias


def test_a_scope_boundary_cannot_be_shifted_into_the_subject(policy) -> None:
    """Length-prefixed, so two (mission, subject) pairs cannot collide.

    With a separator-joined derivation, mission `"a"` + subject `"b|c"` and
    mission `"a|b"` + subject `"c"` would hash the same bytes -- handing one
    subject the alias belonging to another mission.
    """

    left = run({"subject": "b|c"}, policy, mission="a")
    right = run({"subject": "c"}, policy, mission="a|b")
    assert json.loads(left.frame)["body"]["subject"] != json.loads(right.frame)["body"]["subject"]


# -- coarse time and counts ------------------------------------------------


@pytest.mark.parametrize(
    "instant, expected",
    [
        ("2026-09-20T23:47:13Z", "2026-09-20T23:00:00Z"),
        ("2026-09-20T23:00:00Z", "2026-09-20T23:00:00Z"),
        ("2026-09-20T23:59:59.999Z", "2026-09-20T23:00:00Z"),
        ("2026-09-21T01:30:00+02:00", "2026-09-20T23:00:00Z"),
    ],
)
def test_a_timestamp_is_coarsened_to_its_utc_hour(instant: str, expected: str) -> None:
    assert time_bucket(instant) == expected


def test_an_exact_timestamp_does_not_reach_the_frame(policy) -> None:
    decision = run({"time_bucket": "2026-09-20T23:47:13Z"}, policy)
    text = decision.frame.decode("utf-8")
    assert "23:47:13" not in text
    assert "2026-09-20T23:00:00Z" in text


@pytest.mark.parametrize(
    "count, expected",
    [(0, "0"), (1, "1"), (2, "2-5"), (5, "2-5"), (6, "6-20"), (20, "6-20"), (21, "21-100"), (100, "21-100"), (101, ">100"), (10_000, ">100")],
)
def test_a_count_is_coarsened_to_its_bucket(count: int, expected: str) -> None:
    assert count_bucket(count) == expected


def test_an_exact_count_does_not_reach_the_frame(policy) -> None:
    decision = run({"count": 4711}, policy)
    assert "4711" not in decision.frame.decode("utf-8")
    assert json.loads(decision.frame)["body"]["count"] == ">100"


@pytest.mark.parametrize("value", [-1, True, "seven", 1.5])
def test_a_value_that_cannot_be_coarsened_denies_rather_than_passing_through(
    policy, value
) -> None:
    decision = run({"count": value}, policy)
    assert decision.allowed is False
    assert "could not be coarsened" in decision.reason


def test_an_unparseable_instant_denies(policy) -> None:
    decision = run({"time_bucket": "yesterday"}, policy)
    assert decision.allowed is False
    assert decision.frame is None


# -- byte-identical --------------------------------------------------------

#: Produced once by this implementation and frozen. A change in field order,
#: separator or key set breaks it, which is the point: comparing a call to
#: itself would prove nothing.
FROZEN_FRAME = (
    b'{"body":{"count":"6-20","event_class":"scan","subject":"alias:7b5ed52163d1448d"},'
    b'"redaction_record_id":"sha256:d252b3df62cb6e3176d0ac7cba317a878b46d3325c991903e75daaf5ac911150",'
    b'"remote_privacy_class":"P1-sanitized","sanitizer_policy_version":"v1"}'
)


def test_the_same_inputs_produce_the_same_bytes(policy) -> None:
    frame = {"event_class": "scan", "count": 9, "subject": "workstation-7"}
    first = run(dict(frame), policy)
    second = run(dict(reversed(list(frame.items()))), policy)
    assert first.frame == second.frame, "insertion order changed the output"
    assert first.request_fingerprint == second.request_fingerprint


def test_insertion_order_does_not_reach_the_redaction_record(policy) -> None:
    """`sorted()` over the frame's keys, and why it is load-bearing.

    `json.dumps(sort_keys=True)` already orders the *body*, so a test with one
    removed field passes whether or not the loop sorts. The removed, aliased
    and bucketed lists are built in iteration order and feed the redaction
    record id -- which travels inside the frame. Two removed fields is the
    smallest case that can tell the difference.
    """

    fields = {"event_class": "scan", "secret": "a", "credential": "b"}
    forward = run(dict(fields), policy)
    backward = run(dict(reversed(list(fields.items()))), policy)

    assert forward.redaction.removed == backward.redaction.removed == ("credential", "secret")
    assert forward.redaction.record_id == backward.redaction.record_id
    assert forward.frame == backward.frame


def test_the_output_matches_the_frozen_bytes(policy) -> None:
    decision = run({"event_class": "scan", "count": 9, "subject": "workstation-7"}, policy)
    assert decision.frame == FROZEN_FRAME


def test_the_module_reads_no_clock_no_randomness_and_no_environment() -> None:
    """A sanitizer that is not reproducible cannot be audited."""

    tree = ast.parse(pathlib.Path(sanitizer_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {"random", "secrets", "os", "time", "uuid"} == set()

    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "now" not in calls and "utcnow" not in calls and "today" not in calls


def test_the_module_contains_no_egress_path() -> None:
    tree = ast.parse(pathlib.Path(sanitizer_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {"socket", "ssl", "http", "urllib", "requests", "httpx", "subprocess"} == set()


# -- a budget is not a truncation ------------------------------------------


def test_a_frame_over_budget_is_denied_whole(policy) -> None:
    tight = SanitizerPolicy.from_mapping({**POLICY_MAPPING, "limits": {"max_bytes": 64}})
    decision = run({"event_class": "x" * 200}, tight)
    assert decision.allowed is False
    assert decision.frame is None
    assert "never a truncation" in decision.reason


def test_a_frame_within_budget_is_allowed(policy) -> None:
    """So the test above is about the budget and not about the frame."""

    roomy = SanitizerPolicy.from_mapping({**POLICY_MAPPING, "limits": {"max_bytes": 16384}})
    assert run({"event_class": "x" * 200}, roomy).allowed is True


def test_a_value_that_does_not_serialize_denies(policy) -> None:
    decision = run({"event_class": {1, 2, 3}}, policy)
    assert decision.allowed is False
    assert decision.frame is None


# -- loading the policy ----------------------------------------------------


def test_an_allowed_class_with_no_field_allowlist_is_refused() -> None:
    """The contract's own example, refused rather than resolved.

    `P0-public: {remote: allow}` could mean every field or no field. Ambiguity
    denies; it does not pick the friendlier reading.
    """

    with pytest.raises(SanitizerRefused) as caught:
        SanitizerPolicy.from_mapping(
            {**POLICY_MAPPING, "classes": {"P0-public": {"remote": "allow"}}}
        )
    assert "could mean every field or no field" in str(caught.value)


@pytest.mark.parametrize("never", ["P2-mission", "P3-restricted"])
def test_a_policy_that_allows_a_never_remote_class_is_refused(never: str) -> None:
    """A policy cannot configure its way past the contract."""

    with pytest.raises(SanitizerRefused) as caught:
        SanitizerPolicy.from_mapping(
            {**POLICY_MAPPING, "classes": {never: {"remote": "allow", "fields": ["x"]}}}
        )
    assert "contradicts the contract rather than configuring it" in str(caught.value)


@pytest.mark.parametrize(
    "override, expected",
    [
        ({"version": "  "}, "names its version"),
        ({"remote_default": "allow"}, "must be 'deny'"),
        ({"remote_default": None}, "must be 'deny'"),
        ({"classes": []}, "maps privacy classes"),
        ({"classes": {"P9-imaginary": {"remote": "deny"}}}, "not a privacy class"),
        ({"classes": {"P0-public": {"remote": "maybe"}}}, "ambiguity denies"),
        ({"classes": {"P0-public": {"remote": "allow", "fields": []}}}, "could mean every field"),
        ({"classes": {"P0-public": {"remote": "allow", "fields": [7]}}}, "names strings"),
        ({"limits": {}}, "limits.max_bytes"),
        ({"limits": {"max_bytes": 0}}, "positive number of bytes"),
        ({"redactions": "secret"}, "list of field names"),
        ({"aliases": [""]}, "list of field names"),
    ],
)
def test_every_malformed_policy_is_refused_with_its_own_reason(
    override: dict, expected: str
) -> None:
    with pytest.raises(SanitizerRefused) as caught:
        SanitizerPolicy.from_mapping({**POLICY_MAPPING, **override})
    assert expected in str(caught.value)


def test_a_denied_class_needs_no_field_list() -> None:
    loaded = SanitizerPolicy.from_mapping(
        {**POLICY_MAPPING, "classes": {"P2-mission": {"remote": "deny"}}}
    )
    assert loaded.allowed == {}


# -- the audit events ------------------------------------------------------


def test_the_decision_event_counts_bytes_and_carries_no_frame_content(policy) -> None:
    decision = run({"event_class": "scan", "secret": "hunter2"}, policy)
    event = decision.as_event()
    assert event["allowed"] is True
    assert event["frame_bytes"] == len(decision.frame)
    assert event["redaction_record_id"] == decision.redaction.record_id
    assert "hunter2" not in json.dumps(event)
    assert "scan" not in json.dumps(event)


def test_a_denial_event_records_zero_bytes_and_no_record(policy) -> None:
    event = run({"event_class": "scan"}, policy, privacy_class=PrivacyClass.P3_RESTRICTED).as_event()
    assert event["allowed"] is False
    assert event["frame_bytes"] == 0
    assert event["redaction_record_id"] is None


def test_the_redaction_event_names_what_went_and_not_what_it_was(policy) -> None:
    decision = run(
        {"event_class": "scan", "secret": "hunter2", "subject": "workstation-7", "count": 3},
        policy,
    )
    event = decision.redaction.as_event()
    assert event["removed"] == ["secret"]
    assert event["aliased"] == ["subject"]
    assert event["bucketed"] == ["count"]
    assert "hunter2" not in json.dumps(event)
    assert "workstation-7" not in json.dumps(event)
