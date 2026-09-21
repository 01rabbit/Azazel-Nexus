"""Verifying the local Edge Core package, and the tie to the contract Edge ships (#44).

Two halves.

**The contract tie.** `contract/azazel-edge-core/` is a copy of what
Azazel-Edge commits ([Azazel-Edge#426](https://github.com/01rabbit/Azazel-Edge/pull/426)).
Every constant in `edge_package.py` is asserted against it here, so a pin that
drifts from the producer's contract fails on this side while a manifest field
added without regenerating the contract fails on Edge's. Neither repository
imports the other.

**The five checks.** They fail separately, they are reported separately, and
only `passed` counts. `not-checked` is a third answer, because a node that
reported a health failure it never attempted would have an operator chasing a
fault that does not exist.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from azazel_nexus.activation import EdgeBaselineState
from azazel_nexus.edge_package import (
    CHECKS,
    PROBE_CONTRACT,
    ProbeResult,
    load_probe_result,
    parse_probe_result,
    HEALTHY_STATUS,
    PIN,
    REQUIRED_HEALTH_KEYS,
    REQUIRED_MANIFEST_KEYS,
    UNSIGNED_CAVEAT,
    EdgeInspection,
    EdgePackageRefused,
    Evidence,
    Finding,
    HealthAnswer,
    inspect,
    no_health_probe,
    no_running_probe,
    presence_of,
)
from azazel_nexus.integration import EdgePresence

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contract" / "azazel-edge-core"


def _contract(name: str) -> dict:
    return json.loads((CONTRACT / name).read_text(encoding="utf-8"))


# -- the tie to the contract Azazel-Edge ships -----------------------------


def test_every_pinned_field_is_what_the_vendored_pin_says():
    """A pin that drifted from the producer's contract would verify a fiction."""

    pin = _contract("pin.json")
    assert PIN.package == pin["package"]
    assert PIN.version == pin["version"]
    assert PIN.architecture == pin["architecture"]
    assert PIN.manifest_contract == pin["manifest_contract"]
    assert PIN.health_contract == pin["health_contract"]
    assert PIN.signed is pin["signed"] is False


def test_the_filenames_this_node_looks_for_are_the_ones_edge_writes():
    pin = _contract("pin.json")
    assert PIN.manifest_name == pin["manifest"]
    assert PIN.artifact_name == pin["artifact"]


def test_every_manifest_field_read_here_is_one_edge_promises():
    """Reading a field the producer does not promise is verifying nobody's output."""

    promised = set(_contract("manifest-schema.json")["keys"])
    assert set(REQUIRED_MANIFEST_KEYS) <= promised, (
        f"{sorted(set(REQUIRED_MANIFEST_KEYS) - promised)} are read here and "
        "are not in the manifest schema Azazel-Edge commits"
    )
    assert REQUIRED_MANIFEST_KEYS, "a vacuous subset check proves nothing"


def test_every_health_field_read_here_is_one_edge_promises():
    promised = set(_contract("health-schema.json")["keys"])
    assert set(REQUIRED_HEALTH_KEYS) <= promised
    assert REQUIRED_HEALTH_KEYS


def test_the_healthy_word_is_the_one_edge_uses():
    schema = _contract("health-schema.json")
    assert HEALTHY_STATUS == schema["healthy_status"]
    assert HEALTHY_STATUS != schema["unhealthy_status"]


def test_the_contract_demands_four_health_conditions_and_all_four_are_checked(tmp_path):
    """Named individually, because "we check health" is not a condition."""

    conditions = _contract("health-schema.json")["healthy_when"]
    assert len(conditions) == 4
    checked = (
        _health_finding(tmp_path, _report(), exit_code=3).evidence,     # exits 0
        _health_finding(tmp_path, "not json").evidence,                 # parses as JSON
        _health_finding(tmp_path, _report(contract="other")).evidence,  # contract matches
        _health_finding(tmp_path, _report(status="unhealthy")).evidence,  # status healthy
    )
    assert checked == (Evidence.FAILED,) * 4
    assert _health_finding(tmp_path, _report()).evidence is Evidence.PASSED


def test_the_contract_demands_six_separate_findings_and_six_words_exist():
    must = " ".join(_contract("pin.json")["consumer_must"])
    assert "six separate findings" in must
    words = {
        EdgePresence.ABSENT,
        EdgePresence.CORRUPT,
        EdgePresence.VERSION_MISMATCH,
        EdgePresence.DIGEST_MISMATCH,
        EdgePresence.UNHEALTHY,
        EdgePresence.NOT_RUNNING,
    }
    assert len({word.value for word in words}) == 6


def test_the_contract_forbids_claiming_baseline_ready_from_the_package_alone():
    must = " ".join(_contract("pin.json")["consumer_must"])
    assert "not claim edge-baseline-ready" in must


def test_the_provenance_note_says_where_the_copy_came_from():
    text = (CONTRACT / "PROVENANCE.md").read_text(encoding="utf-8")
    assert "Azazel-Edge" in text
    assert "copied, never edited here" in text


# -- fixtures: a package on disk -------------------------------------------


def _report(**overrides) -> str:
    report = {
        "contract": PIN.health_contract,
        "status": HEALTHY_STATUS,
        "version": PIN.version,
        "observe_only": True,
        "checks": [],
    }
    report.update(overrides)
    return json.dumps(report)


def _health_finding(tmp_path: Path, stdout: str, exit_code: int = 0) -> Finding:
    """Run one health answer through a complete inspection of a good package.

    Through a whole inspection rather than against the health function alone:
    what is being asserted is what an operator ends up reading, and a helper
    that reached past the assembly could pass while the assembly dropped the
    finding.
    """

    return inspect(
        _package(tmp_path), health=lambda: HealthAnswer(exit_code=exit_code, stdout=stdout)
    ).finding("health_endpoint_healthy")


def _manifest(**overrides) -> dict:
    manifest = {
        "contract": PIN.manifest_contract,
        "package": PIN.package,
        "version": PIN.version,
        "architecture": PIN.architecture,
        "artifact": PIN.artifact_name,
        "digest": "",
        "signed": False,
        "health": {"contract": PIN.health_contract},
        "posture": {"observe_only": True, "enforcement": False},
    }
    manifest.update(overrides)
    return manifest


def _package(
    tmp_path: Path,
    *,
    payload: bytes = b"edge-core-payload",
    digest: str | None = None,
    manifest: dict | None = None,
    write_manifest: bool = True,
    write_artifact: bool = True,
    manifest_text: str | None = None,
) -> Path:
    root = tmp_path / "edge"
    root.mkdir(exist_ok=True)
    if write_artifact:
        (root / PIN.artifact_name).write_bytes(payload)
    document = _manifest() if manifest is None else manifest
    if digest is None:
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if isinstance(document, dict) and document.get("digest") == "":
        document = {**document, "digest": digest}
    if write_manifest:
        (root / PIN.manifest_name).write_text(
            manifest_text if manifest_text is not None else json.dumps(document),
            encoding="utf-8",
        )
    return root


def _all_passing(root: Path) -> EdgeInspection:
    return inspect(
        root,
        health=lambda: HealthAnswer(exit_code=0, stdout=_report()),
        running=lambda: True,
    )


# -- the shape of an inspection --------------------------------------------


def test_the_five_checks_are_reported_in_a_fixed_order(tmp_path):
    inspection = _all_passing(_package(tmp_path))
    assert tuple(f.check for f in inspection.findings) == CHECKS


def test_the_five_checks_are_the_five_the_baseline_state_holds():
    """Same five, same order: `state()` builds the state positionally."""

    fields = tuple(EdgeBaselineState.__dataclass_fields__)
    assert fields == CHECKS


def test_all_five_passing_is_verified_ready(tmp_path):
    inspection = _all_passing(_package(tmp_path))
    assert inspection.ready is True
    assert inspection.presence is EdgePresence.VERIFIED_READY
    assert inspection.state().ready is True


def test_a_passing_inspection_still_carries_the_unsigned_caveat(tmp_path):
    """The limit of a verification belongs beside its result, not in a design doc."""

    inspection = _all_passing(_package(tmp_path))
    assert UNSIGNED_CAVEAT in inspection.caveats
    assert "not authenticity" in UNSIGNED_CAVEAT
    assert UNSIGNED_CAVEAT in json.dumps(inspection.as_event())


def test_an_inspection_with_no_caveat_is_refused(tmp_path):
    findings = _all_passing(_package(tmp_path)).findings
    with pytest.raises(EdgePackageRefused, match="no caveat"):
        EdgeInspection(findings=findings, presence=EdgePresence.VERIFIED_READY)


def test_an_inspection_missing_a_check_is_refused(tmp_path):
    findings = _all_passing(_package(tmp_path)).findings
    with pytest.raises(EdgePackageRefused, match="five checks"):
        EdgeInspection(
            findings=findings[:-1],
            presence=EdgePresence.VERIFIED_READY,
            caveats=(UNSIGNED_CAVEAT,),
        )


def test_an_inspection_whose_checks_are_reordered_is_refused(tmp_path):
    findings = _all_passing(_package(tmp_path)).findings
    with pytest.raises(EdgePackageRefused, match="five checks"):
        EdgeInspection(
            findings=findings[::-1],
            presence=EdgePresence.VERIFIED_READY,
            caveats=(UNSIGNED_CAVEAT,),
        )


def test_a_display_word_that_disagrees_with_the_decision_is_refused(tmp_path):
    """Both directions: the screen and the decision describe one node."""

    findings = _all_passing(_package(tmp_path)).findings
    with pytest.raises(EdgePackageRefused, match="disagree"):
        EdgeInspection(
            findings=findings,
            presence=EdgePresence.ABSENT,
            caveats=(UNSIGNED_CAVEAT,),
        )
    failing = (Finding("package_present", Evidence.FAILED, "nothing there"),) + findings[1:]
    with pytest.raises(EdgePackageRefused, match="verified-ready"):
        EdgeInspection(
            findings=failing,
            presence=EdgePresence.VERIFIED_READY,
            caveats=(UNSIGNED_CAVEAT,),
        )


# -- findings --------------------------------------------------------------


def test_a_finding_for_an_unknown_check_is_refused():
    with pytest.raises(EdgePackageRefused, match="five checks"):
        Finding("edge_is_fine", Evidence.PASSED, "reason")


def test_a_finding_with_no_reason_is_refused():
    with pytest.raises(EdgePackageRefused, match="no reason"):
        Finding("running", Evidence.PASSED, "   ")


@pytest.mark.parametrize("evidence", [Evidence.PASSED, Evidence.NOT_CHECKED])
def test_a_security_finding_that_did_not_fail_is_refused(evidence):
    """A check nobody ran has found nothing."""

    with pytest.raises(EdgePackageRefused, match="found nothing"):
        Finding("digest_matches", evidence, "reason", security=True)


def test_only_passed_counts_as_held():
    assert Finding("running", Evidence.PASSED, "r").held is True
    assert Finding("running", Evidence.FAILED, "r").held is False
    assert Finding("running", Evidence.NOT_CHECKED, "r").held is False


# -- no root configured ----------------------------------------------------


def test_an_unconfigured_node_reports_unknown_rather_than_absent():
    """Not configured and looked-for-and-missing are different facts."""

    inspection = inspect(None)
    assert inspection.presence is EdgePresence.UNKNOWN
    assert inspection.unchecked == CHECKS
    assert inspection.ready is False
    assert "not configured is not the same fact" in inspection.finding(
        "package_present"
    ).reason.lower()


# -- package_present -------------------------------------------------------


def test_an_empty_root_is_absent_and_not_a_security_finding(tmp_path):
    root = tmp_path / "edge"
    root.mkdir()
    inspection = inspect(root)
    assert inspection.presence is EdgePresence.ABSENT
    assert inspection.security_findings == ()
    assert "deployment step" in inspection.finding("package_present").reason


def test_an_artifact_with_no_manifest_is_corrupt_not_absent(tmp_path):
    root = _package(tmp_path, write_manifest=False)
    assert inspect(root).presence is EdgePresence.CORRUPT


def test_a_manifest_with_no_artifact_is_corrupt_not_absent(tmp_path):
    root = _package(tmp_path, write_artifact=False)
    inspection = inspect(root)
    assert inspection.presence is EdgePresence.CORRUPT
    assert "verifies nothing" in inspection.finding("package_present").reason


def test_a_manifest_that_is_not_json_is_corrupt(tmp_path):
    root = _package(tmp_path, manifest_text="{ truncated")
    inspection = inspect(root)
    assert inspection.presence is EdgePresence.CORRUPT
    assert "reported rather than repaired" in inspection.finding("package_present").reason


def test_a_manifest_that_is_json_but_not_an_object_is_corrupt(tmp_path):
    root = _package(tmp_path, manifest_text="[1, 2, 3]")
    assert inspect(root).presence is EdgePresence.CORRUPT


@pytest.mark.parametrize("dropped", REQUIRED_MANIFEST_KEYS)
def test_a_manifest_missing_any_field_this_node_reads_is_corrupt(tmp_path, dropped):
    document = _manifest()
    head, _, tail = dropped.partition(".")
    if tail:
        document[head] = {k: v for k, v in document[head].items() if k != tail}
    else:
        document.pop(head)
    root = _package(tmp_path, manifest=document)
    assert inspect(root).presence is EdgePresence.CORRUPT


def test_a_manifest_in_another_contract_is_corrupt(tmp_path):
    root = _package(tmp_path, manifest=_manifest(contract="something/else/v9"))
    inspection = inspect(root)
    assert inspection.presence is EdgePresence.CORRUPT
    assert "something/else/v9" in inspection.finding("package_present").reason


@pytest.mark.parametrize(
    "field,value",
    [("package", "azazel-edge-lite"), ("architecture", "aarch64")],
)
def test_a_manifest_for_another_package_or_architecture_is_corrupt(tmp_path, field, value):
    root = _package(tmp_path, manifest=_manifest(**{field: value}))
    assert inspect(root).presence is EdgePresence.CORRUPT


def test_a_manifest_declaring_another_health_contract_is_corrupt(tmp_path):
    root = _package(tmp_path, manifest=_manifest(health={"contract": "health/v2"}))
    inspection = inspect(root)
    assert inspection.presence is EdgePresence.CORRUPT
    assert "health/v2" in inspection.finding("package_present").reason


def test_a_manifest_claiming_to_be_signed_is_refused_as_a_security_finding(tmp_path):
    """A claim of authenticity this node cannot check is worse than none.

    An absent claim denies reliance. A claim nothing verifies invites it.
    """

    root = _package(tmp_path, manifest=_manifest(signed=True))
    inspection = inspect(root)
    assert inspection.presence is EdgePresence.CORRUPT
    finding = inspection.finding("package_present")
    assert finding.security is True
    assert "cannot check" in finding.reason
    assert inspection.ready is False


@pytest.mark.parametrize(
    "posture",
    [
        {"observe_only": False, "enforcement": False},
        {"observe_only": True, "enforcement": True},
    ],
)
def test_a_package_declaring_an_enforcing_posture_is_refused(tmp_path, posture):
    """Nexus accepts no Edge package that says it enforces."""

    root = _package(tmp_path, manifest=_manifest(posture=posture))
    inspection = inspect(root)
    assert inspection.presence is EdgePresence.CORRUPT
    assert inspection.finding("package_present").security is True


def test_a_failed_package_check_leaves_the_rest_not_checked_rather_than_failed(tmp_path):
    """Four failures nobody attempted would be four faults nobody has."""

    root = tmp_path / "edge"
    root.mkdir()
    inspection = inspect(root)
    assert inspection.unchecked == CHECKS[1:]
    assert inspection.finding("package_present").evidence is Evidence.FAILED


# -- version_matches -------------------------------------------------------


def test_a_version_that_is_not_the_pinned_one_fails_on_its_own(tmp_path):
    root = _package(tmp_path, manifest=_manifest(version="0.2.0"))
    inspection = inspect(root)
    assert inspection.presence is EdgePresence.VERSION_MISMATCH
    assert inspection.finding("package_present").held is True
    assert inspection.finding("version_matches").evidence is Evidence.FAILED
    assert "0.2.0" in inspection.finding("version_matches").reason


def test_a_version_mismatch_is_not_a_security_finding(tmp_path):
    root = _package(tmp_path, manifest=_manifest(version="0.2.0"))
    assert inspect(root).security_findings == ()


# -- digest_matches --------------------------------------------------------


def test_a_digest_is_re_derived_from_the_artifact_on_disk(tmp_path):
    root = _package(tmp_path, payload=b"one")
    (root / PIN.artifact_name).write_bytes(b"two")
    inspection = inspect(root)
    assert inspection.presence is EdgePresence.DIGEST_MISMATCH
    assert inspection.finding("digest_matches").evidence is Evidence.FAILED


def test_a_digest_mismatch_is_a_security_finding_and_is_not_repaired(tmp_path):
    root = _package(tmp_path, digest="sha256:" + "0" * 64)
    before = (root / PIN.manifest_name).read_bytes()
    inspection = inspect(root)
    finding = inspection.finding("digest_matches")
    assert finding.security is True
    assert inspection.security_findings == (finding,)
    assert (root / PIN.manifest_name).read_bytes() == before, (
        "the inspection rewrote the manifest; a verifier that repairs is a "
        "verifier that destroys the evidence"
    )


def test_a_matching_digest_says_it_is_integrity_and_not_authenticity(tmp_path):
    reason = _all_passing(_package(tmp_path)).finding("digest_matches").reason
    assert "not authenticity" in reason


def test_an_unreadable_artifact_is_not_checked_rather_than_mismatched(tmp_path):
    """"We could not read it" is not "it does not match"."""

    root = _package(tmp_path)
    artifact = root / PIN.artifact_name
    artifact.unlink()
    artifact.mkdir()  # a directory where a file is expected
    inspection = inspect(root)
    assert inspection.finding("digest_matches").evidence is Evidence.NOT_CHECKED
    assert inspection.security_findings == ()


# -- health_endpoint_healthy ----------------------------------------------


def test_no_probe_is_the_default_and_reports_not_checked(tmp_path):
    inspection = inspect(_package(tmp_path))
    finding = inspection.finding("health_endpoint_healthy")
    assert finding.evidence is Evidence.NOT_CHECKED
    assert "Nobody looked" in finding.reason
    assert no_health_probe() is None


def test_a_probe_that_could_not_run_is_not_checked_rather_than_unhealthy(tmp_path):
    root = _package(tmp_path)
    inspection = inspect(
        root, health=lambda: HealthAnswer(exit_code=None, stdout="", reason="no such file")
    )
    finding = inspection.finding("health_endpoint_healthy")
    assert finding.evidence is Evidence.NOT_CHECKED
    assert "no such file" in finding.reason


def test_a_non_zero_exit_is_unhealthy(tmp_path):
    root = _package(tmp_path)
    inspection = inspect(
        root, health=lambda: HealthAnswer(exit_code=1, stdout=_report()), running=lambda: True
    )
    assert inspection.presence is EdgePresence.UNHEALTHY


def test_exit_zero_with_output_that_is_not_json_is_unhealthy(tmp_path):
    finding = _health_finding(tmp_path, "<html>gateway</html>", 0)
    assert finding.evidence is Evidence.FAILED
    assert "not the contract" in finding.reason


def test_exit_zero_with_json_that_is_not_an_object_is_unhealthy(tmp_path):
    assert _health_finding(tmp_path, "[]", 0).evidence is Evidence.FAILED


@pytest.mark.parametrize("dropped", REQUIRED_HEALTH_KEYS)
def test_a_health_report_missing_any_field_this_node_reads_is_unhealthy(tmp_path, dropped):
    report = json.loads(_report())
    report.pop(dropped)
    assert _health_finding(tmp_path, json.dumps(report), 0).evidence is Evidence.FAILED


def test_a_health_report_in_another_dialect_is_unhealthy(tmp_path):
    finding = _health_finding(tmp_path, _report(contract="edge/health/v9"), 0)
    assert finding.evidence is Evidence.FAILED
    assert "unknown dialect" in finding.reason


def test_a_health_report_saying_unhealthy_is_unhealthy(tmp_path):
    finding = _health_finding(tmp_path, _report(status="unhealthy"), 0)
    assert finding.evidence is Evidence.FAILED
    assert "unhealthy" in finding.reason


def test_a_healthy_report_from_another_version_is_a_security_finding(tmp_path):
    """The binary that answered is not the one the manifest describes."""

    finding = _health_finding(tmp_path, _report(version="0.9.9"), 0)
    assert finding.evidence is Evidence.FAILED
    assert finding.security is True


def test_all_four_conditions_together_are_what_passes(tmp_path):
    finding = _health_finding(tmp_path, _report(), 0)
    assert finding.evidence is Evidence.PASSED
    assert "All four conditions" in finding.reason


# -- running ---------------------------------------------------------------


def test_running_is_not_checked_by_default_and_names_the_gate(tmp_path):
    root = _package(tmp_path)
    inspection = inspect(
        root, health=lambda: HealthAnswer(exit_code=0, stdout=_report())
    )
    finding = inspection.finding("running")
    assert finding.evidence is Evidence.NOT_CHECKED
    assert "HG-01" in finding.reason
    assert no_running_probe() is None


def test_a_healthy_answer_does_not_fill_in_the_running_check(tmp_path):
    """One-shot health says nothing about a daemon, and Edge's manifest says so."""

    root = _package(tmp_path)
    inspection = inspect(
        root, health=lambda: HealthAnswer(exit_code=0, stdout=_report())
    )
    assert inspection.finding("health_endpoint_healthy").held is True
    assert inspection.finding("running").held is False
    assert inspection.ready is False


def test_a_probe_reporting_not_running_fails_rather_than_not_checked(tmp_path):
    root = _package(tmp_path)
    inspection = inspect(
        root,
        health=lambda: HealthAnswer(exit_code=0, stdout=_report()),
        running=lambda: False,
    )
    assert inspection.presence is EdgePresence.NOT_RUNNING
    assert inspection.finding("running").evidence is Evidence.FAILED


# -- the leading word ------------------------------------------------------


def test_the_leading_word_names_the_earliest_failure_not_the_last(tmp_path):
    """A digest mismatch must not be buried under a consequence found later."""

    root = _package(tmp_path, digest="sha256:" + "0" * 64)
    inspection = inspect(
        root,
        health=lambda: HealthAnswer(exit_code=0, stdout=_report(status="unhealthy")),
        running=lambda: False,
    )
    assert inspection.presence is EdgePresence.DIGEST_MISMATCH
    assert inspection.security_findings != ()


@pytest.mark.parametrize(
    "check,word",
    [
        ("package_present", EdgePresence.ABSENT),
        ("version_matches", EdgePresence.VERSION_MISMATCH),
        ("digest_matches", EdgePresence.DIGEST_MISMATCH),
        ("health_endpoint_healthy", EdgePresence.UNHEALTHY),
        ("running", EdgePresence.NOT_RUNNING),
    ],
)
def test_each_check_failing_alone_produces_its_own_word(check, word):
    findings = tuple(
        Finding(
            name,
            Evidence.FAILED if name == check else Evidence.PASSED,
            "held" if name != check else "did not hold",
        )
        for name in CHECKS
    )
    assert presence_of(findings) is word


def test_a_check_nobody_ran_leads_with_unknown_rather_than_a_failure_word():
    findings = tuple(
        Finding(
            name,
            Evidence.NOT_CHECKED if name == "running" else Evidence.PASSED,
            "reason",
        )
        for name in CHECKS
    )
    assert presence_of(findings) is EdgePresence.UNKNOWN


# -- what the state hands the activation decision --------------------------


def test_not_checked_becomes_false_in_the_baseline_state(tmp_path):
    """Unknown never grants, and the reason stays in the finding."""

    state = inspect(_package(tmp_path)).state()
    assert state == EdgeBaselineState(True, True, True, False, False)
    assert state.ready is False
    assert "health_endpoint_healthy" in state.missing()


def test_this_repository_cannot_reach_baseline_ready_on_its_own(tmp_path):
    """Stated as a test, because it is a property of the shipped node.

    No runner is shipped for either probe (the package may not import
    `subprocess`), so both are `not-checked` and `ready` is unreachable
    without a deployment that crosses that boundary -- Nexus#72.
    """

    assert inspect(_package(tmp_path)).ready is False


# -- static guards ---------------------------------------------------------


def test_the_verifier_writes_nothing():
    """A verifier that repairs is a verifier that destroys the evidence."""

    module = ROOT / "src" / "azazel_nexus" / "edge_package.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    forbidden = {"write_text", "write_bytes", "mkdir", "unlink", "rmdir", "replace", "rename", "chmod"}
    offenders = [
        f"{node.func.attr}:{node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden
    ]
    assert offenders == [], f"{offenders} would change what is being verified"
    assert forbidden, "a vacuous name set would pass over any module"


def test_the_verifier_runs_no_process():
    """The boundary in `test_boundary_static.py`, asserted where it matters.

    The consequence is that health and running are always `not-checked` on a
    node built from this repository, which `inspect` reports rather than
    hides.
    """

    module = ROOT / "src" / "azazel_nexus" / "edge_package.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "subprocess" not in imported
    assert "os" not in imported


def test_nothing_reads_the_startup_block_of_an_edge_manifest():
    """#44's last criterion, held mechanically rather than in prose.

    Edge's manifest carries `startup.command` and `startup.observe_only_env`.
    Nexus does not read either. A consumer that read a command would be one
    step from running it, and the acceptance criterion this closes is that
    **no network-configuration path exists** on this node.

    The rest of that argument is import-level and lives in
    `test_boundary_static.py`: with no `socket` and no `subprocess`, there is
    nothing here that could carry out a startup instruction even if it read
    one. This test covers the half that guard cannot see -- a field read now
    and acted on later.
    """

    read_here = {key.split(".")[0] for key in REQUIRED_MANIFEST_KEYS}
    assert "startup" not in read_here

    module = ROOT / "src" / "azazel_nexus" / "edge_package.py"
    source = module.read_text(encoding="utf-8")
    body = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    # The docstring names the fields to explain why they are not read, so the
    # search is for a *lookup*, not for the words.
    for field in ("startup.command", "startup.observe_only_env", "observe_only_env"):
        assert f'"{field}"' not in body, (
            f"{field} is read from the Edge manifest; a startup instruction "
            "this node reads is a startup instruction this node may one day act on"
        )
    assert '"posture.observe_only"' in body, (
        "a vacuous scan: no manifest field is looked up at all, so the "
        "assertions above would pass over an empty module"
    )


# -- the probe's result, read and never trusted further --------------------
#
# Nexus#72. `az-edge-probed` supplies `health_endpoint_healthy` and `running`
# and nothing else: package, version and digest stay derived here, from the
# files, on every read. These hold the three ways a result supplies nothing
# and the one way it supplies something.


def _result(**overrides) -> ProbeResult:
    fields = {
        "contract": PROBE_CONTRACT,
        "observed_at": "2026-09-21T03:00:00Z",
        "ttl_seconds": 300,
        "package_version": PIN.version,
        "package_digest": "sha256:" + "ab" * 32,
        "health": Evidence.PASSED,
        "health_reason": "all four conditions held",
        "running": Evidence.PASSED,
        "running_reason": "the unit is active/running",
    }
    fields.update(overrides)
    return ProbeResult(**fields)


def _digest_of(tmp_path, payload=b"edge-core-payload") -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def test_a_fresh_matching_result_supplies_both_findings(tmp_path):
    root = _package(tmp_path)
    inspection = inspect(
        root,
        probe=_result(package_digest=_digest_of(tmp_path)),
        now="2026-09-21T03:01:00Z",
    )
    assert inspection.ready is True
    assert inspection.presence is EdgePresence.VERIFIED_READY
    assert "az-edge-probed at 2026-09-21T03:00:00Z" in inspection.finding("running").reason


def test_a_result_about_another_version_supplies_nothing(tmp_path):
    root = _package(tmp_path)
    inspection = inspect(
        root,
        probe=_result(package_version="9.9.9", package_digest=_digest_of(tmp_path)),
        now="2026-09-21T03:01:00Z",
    )
    assert inspection.unchecked == ("health_endpoint_healthy", "running")
    assert "A result about a different package" in inspection.finding("running").reason


def test_a_result_about_another_digest_supplies_nothing(tmp_path):
    root = _package(tmp_path)
    inspection = inspect(
        root,
        probe=_result(package_digest="sha256:" + "0" * 64),
        now="2026-09-21T03:01:00Z",
    )
    assert inspection.unchecked == ("health_endpoint_healthy", "running")


def test_a_stale_result_supplies_nothing_and_is_not_a_failure(tmp_path):
    """An operator sent to restart a healthy Edge is an operator doing harm."""

    root = _package(tmp_path)
    inspection = inspect(
        root,
        probe=_result(package_digest=_digest_of(tmp_path)),
        now="2026-09-21T03:06:00Z",
    )
    assert inspection.unchecked == ("health_endpoint_healthy", "running")
    assert inspection.finding("running").evidence is not Evidence.FAILED
    assert "stale" in inspection.finding("running").reason
    assert inspection.ready is False


def test_the_boundary_of_freshness_is_the_ttl(tmp_path):
    root = _package(tmp_path)
    probe = _result(package_digest=_digest_of(tmp_path))
    assert probe.expires_at() == "2026-09-21T03:05:00Z"
    assert inspect(root, probe=probe, now="2026-09-21T03:04:59Z").ready is True
    assert inspect(root, probe=probe, now="2026-09-21T03:05:00Z").ready is False


def test_a_result_agreeing_with_a_tampered_manifest_supplies_nothing(tmp_path):
    """Agreement between two suspect things is not evidence about either."""

    root = _package(tmp_path, digest="sha256:" + "0" * 64)
    inspection = inspect(
        root,
        probe=_result(package_digest="sha256:" + "0" * 64),
        now="2026-09-21T03:01:00Z",
    )
    assert inspection.presence is EdgePresence.DIGEST_MISMATCH
    assert inspection.unchecked == ("health_endpoint_healthy", "running")


def test_a_probe_result_can_only_withhold_never_invent_a_package(tmp_path):
    """The reason the probe is trusted with only two of the five checks."""

    empty = tmp_path / "edge"
    empty.mkdir()
    inspection = inspect(
        empty,
        probe=_result(package_digest="sha256:" + "0" * 64),
        now="2026-09-21T03:01:00Z",
    )
    assert inspection.presence is EdgePresence.ABSENT
    assert inspection.ready is False


def test_a_probe_result_and_a_callable_together_are_refused(tmp_path):
    with pytest.raises(EdgePackageRefused, match="one source too many"):
        inspect(
            _package(tmp_path),
            probe=_result(),
            now="2026-09-21T03:01:00Z",
            running=lambda: True,
        )


def test_a_probe_result_with_no_instant_is_refused(tmp_path):
    """An answer with no age is an answer that never goes stale."""

    with pytest.raises(EdgePackageRefused, match="never goes stale"):
        inspect(_package(tmp_path), probe=_result())


def test_a_failed_probe_verdict_is_carried_through_with_its_reason(tmp_path):
    root = _package(tmp_path)
    inspection = inspect(
        root,
        probe=_result(
            package_digest=_digest_of(tmp_path),
            running=Evidence.FAILED,
            running_reason="the unit is inactive/dead, which is not running",
        ),
        now="2026-09-21T03:01:00Z",
    )
    assert inspection.presence is EdgePresence.NOT_RUNNING
    assert "inactive/dead" in inspection.finding("running").reason


def test_a_probe_security_finding_survives_into_the_inspection(tmp_path):
    root = _package(tmp_path)
    inspection = inspect(
        root,
        probe=_result(
            package_digest=_digest_of(tmp_path),
            health=Evidence.FAILED,
            health_reason="the health report is from version 9.9.9",
            health_security=True,
        ),
        now="2026-09-21T03:01:00Z",
    )
    assert inspection.security_findings != ()
    assert inspection.presence is EdgePresence.UNHEALTHY


# -- parsing the state file ------------------------------------------------


def test_a_result_in_another_contract_is_refused():
    with pytest.raises(EdgePackageRefused, match="declares contract"):
        _result(contract="something/else/v1")


@pytest.mark.parametrize("ttl", [0, -1, 3601, True, "300"])
def test_an_unbounded_or_absurd_ttl_is_refused(ttl):
    with pytest.raises(EdgePackageRefused):
        _result(ttl_seconds=ttl)


def test_a_result_with_no_reason_is_refused():
    with pytest.raises(EdgePackageRefused, match="reads as agreement"):
        _result(running_reason="   ")


def test_a_security_finding_on_a_check_nobody_ran_is_refused():
    with pytest.raises(EdgePackageRefused, match="found nothing"):
        _result(health=Evidence.NOT_CHECKED, health_security=True)


def test_an_instant_with_no_time_zone_is_refused():
    with pytest.raises(EdgePackageRefused, match="time zone"):
        _result(observed_at="2026-09-21T03:00:00")


def test_a_state_file_larger_than_the_ceiling_is_refused():
    """A reader with no ceiling has its memory decided by whatever wrote it."""

    with pytest.raises(EdgePackageRefused, match="larger than"):
        parse_probe_result("x" * 20000)


@pytest.mark.parametrize("text", ["not json", "[]", "{}"])
def test_a_state_file_that_is_not_a_result_is_refused(text):
    with pytest.raises(EdgePackageRefused):
        parse_probe_result(text)


def test_an_unknown_evidence_word_is_refused():
    document = json.loads(json.dumps(_result(package_digest="d").as_event()))
    document["running"] = "probably"
    with pytest.raises(EdgePackageRefused, match="unknown evidence"):
        parse_probe_result(json.dumps(document))


def test_an_absent_state_file_is_none_rather_than_an_error(tmp_path):
    """A node where the probe has never run is not a node with a broken probe."""

    assert load_probe_result(tmp_path / "nothing.json") is None


def test_a_state_file_that_exists_and_is_garbage_raises(tmp_path):
    """Something wrote it; ignoring that would hide the one case worth seeing."""

    path = tmp_path / "edge-probe.json"
    path.write_text("{ truncated", encoding="utf-8")
    with pytest.raises(EdgePackageRefused):
        load_probe_result(path)


def test_a_result_round_trips_through_its_own_event(tmp_path):
    original = _result(package_digest=_digest_of(tmp_path))
    assert parse_probe_result(json.dumps(original.as_event())) == original
