"""`az-activation` (#206 P3): temporary roots and in-memory ephemeral keys only.

Every fixed path is resolved under a temporary root owned by the test user;
the protected readers each command composes (policy, declaration, node,
commissioning evidence, operator trust) are replaced by in-memory values that
their own tests cover. No real key, host path or service manager is touched.
"""

import hashlib
import io
import json
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_nexus.activation_approval_v2 import _parse
from azazel_nexus.activation_policy import decode_activation_policy
from azazel_nexus.audit import AuditLedger
from azazel_nexus.bootstrap_deployment import BootstrapDeployment, declared_node_digest
from azazel_nexus.commissioning_evidence import CommissioningEvidence
from azazel_nexus.edge_package import PIN
from azazel_nexus.generation import GenerationStore, tree_digest
from azazel_nexus.observe_baseline import build_observe_baseline
from azazel_nexus.operator_trust import ApprovalPurpose, OperatorTrust, approval_message
from azazel_nexus_runtime import activation_cli as cli
from azazel_nexus_runtime import activation_high_water as hw
from azazel_nexus_runtime import activation_unit_files as scoped_unit_files
from azazel_nexus_runtime.activation_high_water import HighWater, encode_high_water
from azazel_nexus_runtime.node_config import DeclaredNode

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from tools import operator_sign  # noqa: E402
from _edge_package_fixture import archive, write_package  # noqa: E402

LOOP = ("azazel-edge-intaked.service", "azazel-edge-probed.service",
        "azazel-incident-explaind.service", "azazel-knowledge-lited.service",
        "azazel-mio-entryd.service")
EDGE = "azazel-edge-core.service"
NOW = "2027-01-10T00:00:00Z"
D = "sha256:" + "d" * 64
BINDING = "hmac-sha256:" + "c" * 64
PROPOSAL = b'{"schema":"synthetic-full-proposal"}'


def _policy(units=LOOP, *, operators=("operator-a",), max_lease=72 * 3600, skew=120):
    raw = json.dumps({
        "schema": "azazel-nexus/activation-policy/v1",
        "operators": sorted(operators), "max_lease_seconds": max_lease,
        "units": sorted(units), "max_clock_skew_seconds": skew,
        "state_floors": {"audit_bytes": 1, "audit_inodes": 1,
                         "bootstrap_bytes": 1, "bootstrap_inodes": 1},
        "resource_floors": {"min_mission_available_mib": 1, "min_online_logical_cpus": 1,
                            "min_usable_memory_mib": 1},
    }, sort_keys=True, separators=(",", ":")).encode()
    return decode_activation_policy(raw)


def _declaration(epoch=2, node="node-a"):
    return BootstrapDeployment(node_digest=declared_node_digest(node), security_epoch=epoch,
                               revocation_digest=D, policy_digest=D,
                               approval_policy_digest=D, operator="operator-a")


def _evidence(binding=BINDING, proposal=PROPOSAL):
    return CommissioningEvidence(proposal, b"s" * 64, b"{}", binding)


class Tty:
    """A terminal whose typed lines are known in advance."""

    def __init__(self, *lines, tty=True):
        self.buffer = io.BytesIO(b"".join(line.encode() + b"\n" for line in lines))
        self._tty = tty

    def isatty(self):
        return self._tty


class Node:
    """A temporary node root plus the in-memory protected inputs."""

    def __init__(self, root, monkeypatch):
        self.root = root
        self.key = SigningKey.generate()
        self.policy = _policy()
        self.declaration = _declaration()
        self.node = DeclaredNode("node-a")
        self.evidence = _evidence()
        self.trust = OperatorTrust({"operator-a": bytes(self.key.verify_key)})
        self.now = NOW
        self.root_user = True
        for name, getter in (("_load_policy", lambda: self.policy),
                             ("_load_declaration", lambda: self.declaration),
                             ("_load_node", lambda: self.node),
                             ("_load_trust", lambda: self.trust),
                             ("_now", lambda: self.now),
                             ("_is_root", lambda: self.root_user)):
            monkeypatch.setattr(cli, name, getter)
        monkeypatch.setattr(cli, "_load_evidence", self._evidence)

    def _evidence(self):
        if self.evidence is None:
            raise RuntimeError("no commissioning evidence")
        return self.evidence

    @property
    def units_dir(self):
        return self.root / "usr/lib/systemd/system"

    @property
    def approvals(self):
        return self.root / "etc/azazel/activation"

    @property
    def state(self):
        return self.root / "var/lib/azazel/state"

    @property
    def store(self):
        return GenerationStore(self.root / "var/lib/azazel/generations")

    @property
    def ledger(self):
        return AuditLedger(self.state / "activation.jsonl")

    def events(self):
        return [entry.event for entry in self.ledger]

    def unit_files(self):
        return {unit: (self.units_dir / unit).read_bytes() for unit in self.policy.units}

    def package(self, **contents):
        """The archive, its manifest and the extracted binary and redirect policy."""
        digest, self.components = write_package(self.root / "opt/azazel/edge-core",
                                                **contents)
        return digest

    def expected_digest(self, package=None):
        return tree_digest(build_observe_baseline(
            units=list(self.policy.units), unit_files=self.unit_files(),
            package_digest=package,
            package_components=self.components if package is not None else None))

    # -- the three commands --------------------------------------------------

    def publish(self, *lines, digest=None, tty=True):
        if not lines:
            lines = (digest or self.expected_digest(), "PUBLISH")
        out = io.StringIO()
        return cli.run_generation_publish(source=Tty(*lines, tty=tty), out=out), out.getvalue()

    def request(self, *, operator="operator-a", approval_id="approval-1", seq=5,
                valid_for=3600, units=None, out=None, summary_only=False):
        """Runs `request`; returns (code, the bytes written to --out, stderr).

        Without an explicit ``out`` a fresh private file is used, since the
        payload is only ever written to ``--out`` (#251 L-4).
        """
        stderr = io.StringIO()
        target = out
        if out is None and not summary_only:
            directory = self.root.parent / "requests"
            directory.mkdir(mode=0o755, exist_ok=True)
            self._requests = getattr(self, "_requests", 0) + 1
            target = str(directory / f"request-{self._requests}.json")
        code = cli.run_request(operator=operator, approval_id=approval_id, seq=seq,
                               valid_for=valid_for, units=units, out_path=target,
                               stderr=stderr)
        written = b""
        if target is not None and out is None and Path(target).exists():
            written = Path(target).read_bytes()
        return code, written, stderr.getvalue()

    def sign(self, payload, key=None):
        return (key or self.key).sign(approval_message(ApprovalPurpose.ACTIVATION, payload)).signature

    def files(self, payload, signature, name="incoming"):
        directory = self.root.parent / name
        directory.mkdir(exist_ok=True)
        (directory / "approval.json").write_bytes(payload)
        (directory / "approval.sig").write_bytes(signature)
        return directory / "approval.json", directory / "approval.sig"

    def install(self, payload, signature, *lines, replace=False, recover=None,
                confirm=None, name="incoming"):
        payload_path, signature_path = self.files(payload, signature, name)
        out = io.StringIO()
        code = cli.run_install(
            payload_path=str(payload_path), signature_path=str(signature_path),
            confirm_sha256=confirm or hashlib.sha256(payload).hexdigest(),
            replace=replace, recover=recover, source=Tty(*lines), out=out)
        return code, out.getvalue()

    def approved(self, **request):
        code, payload, _ = self.request(**request)
        assert code == 0
        return payload, self.sign(payload)


@pytest.fixture
def node(tmp_path, monkeypatch):
    root = tmp_path / "root"
    for directory, mode in (("usr/lib/systemd/system", 0o755), ("etc/azazel/activation", 0o700),
                            ("var/lib/azazel/state", 0o755)):
        (root / directory).mkdir(parents=True)
    for path in [root, *root.rglob("*")]:
        path.chmod(0o700 if path.name == "activation" else 0o755)
    for unit in (*LOOP, EDGE):
        unit_file = root / "usr/lib/systemd/system" / unit
        unit_file.write_text(f"[Unit]\nDescription={unit}\n")
        unit_file.chmod(0o644)

    @contextmanager
    def state_directory():
        fd = os.open(root / "var/lib/azazel/state", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(cli, "_ROOT", root)
    monkeypatch.setattr(cli, "_OWNER", os.getuid())
    monkeypatch.setattr(scoped_unit_files, "_ROOT", root)
    monkeypatch.setattr(scoped_unit_files, "_OWNER", os.getuid())
    monkeypatch.setattr(hw, "_OWNER", os.getuid())
    monkeypatch.setattr(hw, "_state_directory", state_directory)
    return Node(root, monkeypatch)


@pytest.fixture
def published(node):
    assert node.publish()[0] == 0
    return node


def _high_water(node):
    return json.loads((node.state / "activation/high-water.json").read_bytes())


# -- generation-publish --------------------------------------------------------


def test_publish_writes_an_ordinary_generation_the_verifier_accepts(node):
    code, out = node.publish()
    assert code == 0, out
    generation = node.store.verify(1)
    assert generation.digest == node.expected_digest()
    assert generation.commissioning_digest == "sha256:" + hashlib.sha256(PROPOSAL).hexdigest()
    assert generation.commissioning_evidence_binding == BINDING
    assert set(node.store.read_tree(1)) == {"baseline.json"}
    assert "NOT admission" in out and BINDING not in out
    assert node.events()[-1]["event_type"] == "activation.generation_published"
    assert node.events()[-1]["generation"] == 1
    # Publishing is not admission: nothing is placed and no floor exists.
    assert not (node.approvals / "approval.json").exists()
    assert not (node.state / "activation").exists()


def test_publish_is_a_no_op_when_the_current_generation_already_matches(published):
    code, out = published.publish()
    assert code == 0 and "nothing published" in out
    assert published.store.numbers() == (1,)


def test_publish_binds_the_installed_edge_package_when_edge_core_is_in_scope(node):
    node.policy = _policy((*LOOP, EDGE))
    digest = node.package()
    code, out = node.publish(digest=node.expected_digest(digest))
    assert code == 0, out
    document = json.loads(node.store.read_tree(1)["baseline.json"])
    assert document["edge_pin"]["package_digest"] == digest
    assert document["edge_pin"]["components"] == node.components
    assert set(node.components) == {"bin/azazel-edge-core", "config/redirect_policy.yaml"}


@pytest.mark.parametrize("damage", ["extracted-bin", "extracted-config", "archive-member",
                                    "manifest-component", "linked-bin", "writable-config"])
def test_publish_refuses_extracted_components_that_do_not_match(node, damage):
    """The unit runs the extracted binary and reads the extracted policy: both
    must equal the manifest's component digest and the archive's member."""
    node.policy = _policy((*LOOP, EDGE))
    node.package()
    package = node.root / "opt/azazel/edge-core"
    binary, config = package / "bin/azazel-edge-core", package / "config/redirect_policy.yaml"
    if damage == "extracted-bin":
        binary.write_bytes(binary.read_bytes() + b"rewritten")
    elif damage == "extracted-config":
        config.write_bytes(b"redirect: everything\n")
    elif damage == "archive-member":
        # Archive and manifest re-made consistently, with another binary inside;
        # the manifest's component digests still describe the extracted files.
        manifest = json.loads((package / PIN.manifest_name).read_text())
        data = archive({"bin/azazel-edge-core": b"another", "config/redirect_policy.yaml":
                        config.read_bytes()})
        (package / PIN.artifact_name).write_bytes(data)
        manifest["digest"] = "sha256:" + hashlib.sha256(data).hexdigest()
        (package / PIN.manifest_name).write_text(json.dumps(manifest))
    elif damage == "manifest-component":
        manifest = json.loads((package / PIN.manifest_name).read_text())
        manifest["components"] = [c for c in manifest["components"]
                                  if c["path"] != "config/redirect_policy.yaml"]
        (package / PIN.manifest_name).write_text(json.dumps(manifest))
    elif damage == "linked-bin":
        target = node.root / "elsewhere"
        target.write_bytes(binary.read_bytes())
        binary.unlink()
        binary.symlink_to(target)
    else:
        config.chmod(0o666)
    code, out = node.publish("sha256:" + "0" * 64, "PUBLISH")
    assert code == 1 and "Edge package" in out
    assert node.store.numbers() == ()


@pytest.mark.parametrize("damage", ["absent", "artifact", "enforcing"])
def test_publish_refuses_when_the_package_checks_do_not_pass(node, damage):
    node.policy = _policy((*LOOP, EDGE))
    if damage != "absent":
        node.package()
        package = node.root / "opt/azazel/edge-core"
        if damage == "artifact":
            (package / PIN.artifact_name).write_bytes(b"tampered")
        else:
            manifest = json.loads((package / PIN.manifest_name).read_text())
            manifest["posture"] = {"observe_only": False, "enforcement": True}
            (package / PIN.manifest_name).write_text(json.dumps(manifest))
    code, out = node.publish("sha256:" + "0" * 64, "PUBLISH")
    assert code == 1 and "Edge package" in out
    assert node.store.numbers() == ()


def test_publish_refuses_without_commissioning_evidence(node):
    node.evidence = None
    code, out = node.publish("x", "PUBLISH")
    assert code == 1 and "commissioning evidence" in out
    assert node.store.numbers() == ()


@pytest.mark.parametrize("lines,label", [
    (("sha256:" + "0" * 64, "PUBLISH"), "digest confirmation differs"),
    ((None, "publish"), "not confirmed"),
    ((None,), "bounded complete input"),
])
def test_publish_requires_both_typed_confirmations(node, lines, label):
    lines = tuple(node.expected_digest() if line is None else line for line in lines)
    code, out = node.publish(*lines)
    assert code == 1 and label in out
    assert node.store.numbers() == ()


def test_publish_refuses_non_root_and_non_terminal(node):
    assert node.publish(tty=False)[0] == 1
    node.root_user = False
    code, out = node.publish()
    assert code == 1 and "requires root" in out
    assert node.store.numbers() == ()


@pytest.mark.parametrize("damage", ["symlink", "group-writable", "missing", "hardlink"])
def test_publish_refuses_unprotected_or_linked_unit_files(node, tmp_path, damage):
    target = node.units_dir / LOOP[0]
    if damage == "symlink":
        elsewhere = tmp_path / "elsewhere.service"
        elsewhere.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(elsewhere)
    elif damage == "group-writable":
        target.chmod(0o664)
    elif damage == "missing":
        target.unlink()
    else:
        os.link(target, tmp_path / "second-name")
    code, out = node.publish("sha256:" + "0" * 64, "PUBLISH")
    assert code == 1 and ("unit files" in out or "file protection refused" in out)
    assert node.store.numbers() == ()


def test_publish_refuses_a_symlinked_unit_directory(node, tmp_path):
    real = tmp_path / "real-units"
    (node.units_dir).rename(real)
    node.units_dir.symlink_to(real)
    code, out = node.publish("sha256:" + "0" * 64, "PUBLISH")
    assert code == 1 and "unit files" in out and node.store.numbers() == ()


def test_publish_refuses_when_inputs_change_during_confirmation(node, monkeypatch):
    original = cli._measure_baseline
    calls = []

    def measure():
        calls.append(1)
        if len(calls) == 2:
            (node.units_dir / LOOP[0]).write_text("[Unit]\nDescription=changed\n")
        return original()

    monkeypatch.setattr(cli, "_measure_baseline", measure)
    code, out = node.publish()
    assert code == 1 and "changed" in out
    assert node.store.numbers() == ()


# -- request -------------------------------------------------------------------


def test_request_prints_canonical_v2_bytes_the_signer_accepts(published):
    code, payload, err = published.request(units="azazel-mio-entryd.service,azazel-edge-intaked.service")
    assert code == 0, err
    document = _parse(payload)
    assert document["units"] == ["azazel-edge-intaked.service", "azazel-mio-entryd.service"]
    assert document["generation"] == 1
    assert document["generation_digest"] == published.store.current().digest
    assert document["node_digest"] == declared_node_digest("node-a")
    assert document["security_epoch"] == 2 and document["approval_seq"] == 5
    assert document["policy_digest"] == published.policy.policy_digest
    assert (document["granted_at"], document["expires_at"]) == (NOW, "2027-01-10T01:00:00Z")
    assert not payload.endswith(b"\n")
    summary = operator_sign.activation_summary(payload)
    assert summary["validity_seconds"] == 3600
    sha = hashlib.sha256(payload).hexdigest()
    assert f"payload_sha256: {sha}" in err
    # The binding and the raw commissioning digest never reach the terminal.
    assert BINDING not in err and document["commissioning_digest"] not in err
    assert not (published.approvals / "approval.json").exists()


def test_request_without_out_prints_only_a_summary(published, capsys):
    """#251 L-4: no --out, no payload: the evidence binding never reaches a terminal."""
    code, written, err = published.request(summary_only=True)
    assert code == 1 and written == b""
    assert "payload was NOT written" in err and "--out" in err
    assert "payload_sha256: " in err and "approval_seq: 5" in err
    assert BINDING not in err and '"schema"' not in err
    assert capsys.readouterr().out == ""
    assert not (published.approvals / "approval.json").exists()


def test_request_main_without_out_writes_no_payload_to_stdout(published, capsys):
    code = cli.main(["request", "--operator", "operator-a", "--approval-id", "approval-1",
                     "--seq", "5", "--valid-for", "3600"])
    captured = capsys.readouterr()
    assert code == 1 and captured.out == ""
    assert BINDING not in captured.err and "payload was NOT written" in captured.err


def test_request_writes_a_create_only_private_file(published, tmp_path):
    out = tmp_path / "request.json"
    code, _, _ = published.request(out=str(out))
    assert code == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    _parse(out.read_bytes())
    code, _, err = published.request(out=str(out))
    assert code == 1 and "must not exist" in err
    link = tmp_path / "link.json"
    link.symlink_to(tmp_path / "nowhere.json")
    assert published.request(out=str(link))[0] == 1
    assert not (tmp_path / "nowhere.json").exists()


@pytest.mark.parametrize("change,label", [
    (dict(operator="operator-b"), "not authorized"),
    (dict(valid_for=72 * 3600 + 1), "lease cap"),
    (dict(valid_for=0), "lease cap"),
    (dict(seq=-1), "non-negative"),
    (dict(units="azazel-edge-core.service"), "subset"),
    (dict(units="azazel-mio-entryd.service,azazel-mio-entryd.service"), "subset"),
    (dict(approval_id="Not Valid"), "payload refused"),
])
def test_request_refuses_bad_arguments(published, change, label):
    code, payload, err = published.request(**change)
    assert code == 1 and label in err and payload == b""


def test_request_refuses_a_revoked_operator(published):
    published.trust = OperatorTrust(published.trust.public_keys, frozenset({"operator-a"}))
    code, _, err = published.request()
    assert code == 1 and "active enrolled key" in err


def test_request_refuses_without_a_generation(node):
    code, _, err = node.request()
    assert code == 1 and "no generation is published" in err


def test_request_refuses_without_commissioning_evidence(published):
    published.evidence = None
    code, _, err = published.request()
    assert code == 1 and "commissioning evidence" in err


def test_request_refuses_a_generation_bound_to_other_evidence(published):
    published.evidence = _evidence(binding="hmac-sha256:" + "e" * 64)
    code, _, err = published.request()
    assert code == 1 and "bound to other commissioning evidence" in err


def test_request_refuses_a_tampered_generation_tree(published):
    tree = published.root / "var/lib/azazel/generations/1/tree/baseline.json"
    tree.write_bytes(tree.read_bytes().replace(b"azazel", b"azazeL", 1))
    code, _, err = published.request()
    assert code == 1 and "observe baseline" in err


def test_request_refuses_after_a_unit_file_changes(published):
    (published.units_dir / LOOP[1]).write_text("[Unit]\nDescription=edited\n")
    assert published.request()[0] == 1


def test_request_refuses_when_the_policy_scope_differs_from_the_generation(published):
    published.policy = _policy(LOOP[:4])
    assert published.request()[0] == 1


def test_request_refuses_a_node_that_differs_from_the_declaration(published):
    published.node = DeclaredNode("node-b")
    code, _, err = published.request()
    assert code == 1 and "declared node differs" in err


# -- install -------------------------------------------------------------------


def test_install_places_the_pair_and_initializes_the_floor(published):
    payload, signature = published.approved()
    code, out = published.install(payload, signature)
    assert code == 0, out
    for name, data in (("approval.json", payload), ("approval.sig", signature)):
        info = os.stat(published.approvals / name)
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
        assert (published.approvals / name).read_bytes() == data
    assert _high_water(published) == {
        "schema": "azazel-nexus/activation-high-water/v1", "security_epoch": 2,
        "approval_seq": 5, "generation": 1, "time_floor": NOW}
    event = published.events()[-1]
    assert event["event_type"] == "activation.approval_installed"
    assert event["high_water"]["mode"] == "initialized" and event["replaced"] is False
    assert BINDING not in json.dumps(event) and "NOT a grant" in out


def test_round_trip_with_the_off_host_signer(published, tmp_path):
    out = tmp_path / "request.json"
    assert published.request(out=str(out), seq=7)[0] == 0
    payload = out.read_bytes()
    signature, facts = operator_sign.sign(
        purpose="activation", payload=payload,
        expect_payload_sha256=hashlib.sha256(payload).hexdigest(),
        seed=bytes(published.key), expect_public=bytes(published.key.verify_key).hex())
    assert facts["approval_seq"] == 7
    code, text = published.install(payload, signature)
    assert code == 0, text
    assert _high_water(published)["approval_seq"] == 7


def test_install_raises_an_existing_floor_and_replaces_only_when_confirmed(published):
    payload, signature = published.approved(seq=5)
    assert published.install(payload, signature)[0] == 0
    published.now = "2027-01-10T00:10:00Z"
    newer, newer_sig = published.approved(seq=6, approval_id="approval-2")
    code, out = published.install(newer, newer_sig)
    assert code == 1 and "already installed" in out
    code, out = published.install(newer, newer_sig, "replace", replace=True)
    assert code == 1 and "not confirmed" in out
    assert (published.approvals / "approval.json").read_bytes() == payload
    assert _high_water(published)["approval_seq"] == 5
    code, out = published.install(newer, newer_sig, "REPLACE", replace=True)
    assert code == 0, out
    assert (published.approvals / "approval.json").read_bytes() == newer
    assert _high_water(published) | {"schema": None} == {
        "schema": None, "security_epoch": 2, "approval_seq": 6, "generation": 1,
        "time_floor": "2027-01-10T00:10:00Z"}
    assert published.events()[-1]["replaced"] is True
    assert published.events()[-1]["high_water"]["mode"] == "raised"


def test_install_refuses_a_sequence_below_the_floor(published):
    payload, signature = published.approved(seq=5)
    assert published.install(payload, signature)[0] == 0
    older, older_sig = published.approved(seq=4, approval_id="approval-0")
    code, out = published.install(older, older_sig, "REPLACE", replace=True)
    assert code == 1 and "sequence below the local floor" in out
    assert (published.approvals / "approval.json").read_bytes() == payload


def test_install_refuses_another_approval_at_the_floor_sequence(published):
    """#251 L-3: a sequence equal to the floor is spent once a floor exists."""
    payload, signature = published.approved(seq=5)
    assert published.install(payload, signature)[0] == 0
    other, other_sig = published.approved(seq=5, approval_id="approval-other")
    assert other != payload
    code, out = published.install(other, other_sig, "REPLACE", replace=True)
    assert code == 1 and "not above the high-water floor" in out
    assert (published.approvals / "approval.json").read_bytes() == payload
    assert (published.approvals / "approval.sig").read_bytes() == signature


def test_install_of_the_identical_installed_pair_is_idempotent(published):
    payload, signature = published.approved(seq=5)
    assert published.install(payload, signature)[0] == 0
    code, out = published.install(payload, signature, "REPLACE", replace=True)
    assert code == 0, out
    assert (published.approvals / "approval.json").read_bytes() == payload
    assert _high_water(published)["approval_seq"] == 5
    # The same bytes with another signature file are another pair.
    code, out = published.install(payload, bytes(64), "REPLACE", replace=True)
    assert code == 1


def test_an_identical_reinstall_refuses_if_the_pair_changes_before_placement(published,
                                                                           monkeypatch):
    payload, signature = published.approved(seq=5)
    assert published.install(payload, signature)[0] == 0
    original = cli._place_approval

    def swapped(*args, **kwargs):
        (published.approvals / "approval.sig").write_bytes(bytes(64))
        return original(*args, **kwargs)

    monkeypatch.setattr(cli, "_place_approval", swapped)
    code, out = published.install(payload, signature, "REPLACE", replace=True)
    assert code == 2 and "installed approval changed after confirmation" in out


def test_a_floor_at_the_installed_sequence_still_admits_it_and_its_reinstall(published):
    """The pass raises the floor to the installed sequence; that pair stays valid."""
    payload, signature = published.approved(seq=5)
    assert published.install(payload, signature)[0] == 0
    assert _high_water(published)["approval_seq"] == 5
    from azazel_nexus.activation_approval_v2 import verify_observe_baseline_approval
    collected = cli._collect_context()
    approved = verify_observe_baseline_approval(
        trust=published.trust, expected=collected.context, policy=collected.approval_policy,
        payload=payload, signature=signature, now=published.now,
        security_epoch_floor=2, approval_seq_floor=5)
    assert approved.approval_seq == 5
    assert published.install(payload, signature, "REPLACE", replace=True)[0] == 0


def test_install_refuses_an_expired_approval(published):
    payload, signature = published.approved(valid_for=60)
    published.now = "2027-01-10T00:01:00Z"
    code, out = published.install(payload, signature)
    assert code == 1 and "time policy" in out
    assert not (published.approvals / "approval.json").exists()
    assert not (published.state / "activation").exists()


def test_install_refuses_a_signature_for_another_context(published):
    payload, signature = published.approved()
    published.declaration = _declaration(epoch=3)
    code, out = published.install(payload, signature)
    assert code == 1 and "expected context" in out
    assert not (published.approvals / "approval.json").exists()


def test_install_refuses_after_the_policy_changes(published):
    payload, signature = published.approved()
    published.policy = _policy(operators=("operator-a", "operator-c"))
    assert published.install(payload, signature)[0] == 1


def test_install_refuses_another_key_and_a_wrong_confirmation(published):
    payload, _ = published.approved()
    stranger = SigningKey.generate()
    assert published.install(payload, published.sign(payload, stranger))[0] == 1
    code, out = published.install(payload, published.sign(payload), confirm="0" * 64)
    assert code == 1 and "differs from --confirm-sha256" in out
    assert not (published.approvals / "approval.json").exists()


def test_install_refuses_a_tampered_generation(published):
    payload, signature = published.approved()
    tree = published.root / "var/lib/azazel/generations/1/tree/baseline.json"
    tree.write_bytes(tree.read_bytes().replace(b"azazel", b"azazeL", 1))
    code, out = published.install(payload, signature)
    assert code == 1 and "observe baseline" in out


def test_install_refuses_without_commissioning_evidence(published):
    payload, signature = published.approved()
    published.evidence = None
    assert published.install(payload, signature)[0] == 1


def test_install_refuses_non_root(published):
    payload, signature = published.approved()
    published.root_user = False
    code, out = published.install(payload, signature)
    assert code == 1 and "requires root" in out


def test_install_refuses_symlinked_inputs_and_approval_entries(published, tmp_path):
    payload, signature = published.approved()
    payload_path, signature_path = published.files(payload, signature)
    link = tmp_path / "payload-link.json"
    link.symlink_to(payload_path)
    out = io.StringIO()
    assert cli.run_install(payload_path=str(link), signature_path=str(signature_path),
                           confirm_sha256=hashlib.sha256(payload).hexdigest(), replace=False,
                           recover=None, source=Tty(), out=out) == 1
    (published.approvals / "approval.json").symlink_to(tmp_path / "elsewhere.json")
    code, _ = published.install(payload, signature, "REPLACE", replace=True)
    assert code == 1 and not (tmp_path / "elsewhere.json").exists()
    assert not (published.state / "activation").exists()


def test_install_refuses_a_non_private_approval_directory(published):
    payload, signature = published.approved()
    published.approvals.chmod(0o755)
    assert published.install(payload, signature)[0] == 1
    assert not (published.state / "activation").exists()


def test_install_refuses_a_clock_behind_the_floor(published):
    payload, signature = published.approved()
    assert published.install(payload, signature)[0] == 0
    published.now = "2027-01-09T23:50:00Z"
    newer, newer_sig = published.approved(seq=6, approval_id="approval-2")
    published.now = "2027-01-09T23:50:00Z"
    code, out = published.install(newer, newer_sig, "REPLACE", replace=True)
    assert code == 1 and "behind the high-water time floor" in out


def test_install_refuses_a_generation_below_the_floor(published):
    payload, signature = published.approved()
    (published.state / "activation").mkdir(mode=0o700)
    floor = HighWater(security_epoch=0, approval_seq=0, generation=4,
                      time_floor="2027-01-01T00:00:00Z")
    (published.state / "activation/high-water.json").write_bytes(encode_high_water(floor))
    (published.state / "activation/high-water.json").chmod(0o600)
    code, out = published.install(payload, signature)
    assert code == 1 and "generation below" in out


# -- high-water initialization and the §7 recovery -------------------------------


def _with_history(node, payload, signature):
    assert node.install(payload, signature)[0] == 0
    live = node.state / "activation/high-water.json"
    live.rename(node.state / "activation/high-water.json.retained")


def test_initialization_is_refused_on_a_node_with_floor_history(published):
    payload, signature = published.approved()
    _with_history(published, payload, signature)
    code, out = published.install(payload, signature, "REPLACE", replace=True)
    assert code == 1 and "recovery procedure" in out
    assert not (published.state / "activation/high-water.json").exists()


def test_pass_records_without_a_floor_do_not_block_initialization(published):
    published.ledger.append({"event_type": "activation.inputs_incomplete",
                             "occurred_at": NOW, "actor": "azazel-activated"})
    payload, signature = published.approved()
    assert published.install(payload, signature)[0] == 0


def test_a_broken_ledger_refuses_initialization(published):
    payload, signature = published.approved()
    (published.state / "activation.jsonl").write_text("not a chain\n")
    (published.state / "activation.jsonl").chmod(0o600)
    code, out = published.install(payload, signature)
    assert code == 1 and "ledger" in out
    assert not (published.state / "activation").exists()


def test_recovery_reinitializes_never_below_the_retained_floor(published):
    payload, signature = published.approved(seq=5)
    _with_history(published, payload, signature)
    retained = published.state / "activation/high-water.json.retained"
    # A floor set far ahead (the §7 situation), retained as moved aside.
    ahead = HighWater(security_epoch=2, approval_seq=8, generation=1,
                      time_floor="2030-01-01T00:00:00Z")
    retained.write_bytes(encode_high_water(ahead))
    published.now = "2027-01-10T00:05:00Z"
    stale, stale_sig = published.approved(seq=7, approval_id="approval-7")
    code, out = published.install(stale, stale_sig, "REPLACE", "RECOVER", replace=True,
                                  recover="high-water.json.retained")
    assert code == 1 and "sequence below the local floor" in out
    fresh, fresh_sig = published.approved(seq=9, approval_id="approval-9")
    code, out = published.install(fresh, fresh_sig, "REPLACE", "recover", replace=True,
                                  recover="high-water.json.retained")
    assert code == 1 and "not confirmed" in out
    assert not (published.state / "activation/high-water.json").exists()
    code, out = published.install(fresh, fresh_sig, "REPLACE", "RECOVER", replace=True,
                                  recover="high-water.json.retained")
    assert code == 0, out
    assert _high_water(published) | {"schema": None} == {
        "schema": None, "security_epoch": 2, "approval_seq": 9, "generation": 1,
        "time_floor": "2027-01-10T00:05:00Z"}
    recovered, installed = published.events()[-2:]
    assert recovered["event_type"] == "activation.high_water_recovered"
    assert recovered["retained"]["time_floor"] == "2030-01-01T00:00:00Z"
    assert installed["high_water"]["mode"] == "recovered"
    assert retained.exists()  # kept for the record


def test_recovery_counts_floors_recorded_in_the_ledger(published):
    payload, signature = published.approved(seq=9)
    _with_history(published, payload, signature)
    retained = published.state / "activation/high-water.json.retained"
    retained.write_bytes(encode_high_water(HighWater(0, 0, 0, "2027-01-01T00:00:00Z")))
    older, older_sig = published.approved(seq=6, approval_id="approval-6")
    code, out = published.install(older, older_sig, "REPLACE", "RECOVER", replace=True,
                                  recover="high-water.json.retained")
    assert code == 1 and "sequence below the local floor" in out


@pytest.mark.parametrize("name", ["high-water.json", "../high-water.json", "missing"])
def test_recovery_refuses_bad_retained_names(published, name):
    payload, signature = published.approved()
    _with_history(published, payload, signature)
    code, out = published.install(payload, signature, "REPLACE", "RECOVER", replace=True,
                                  recover=name)
    assert code == 1 and "retained high-water" in out


def test_recovery_refuses_a_linked_retained_file(published, tmp_path):
    payload, signature = published.approved()
    _with_history(published, payload, signature)
    (published.state / "activation/linked").symlink_to(
        published.state / "activation/high-water.json.retained")
    code, out = published.install(payload, signature, "REPLACE", "RECOVER", replace=True,
                                  recover="linked")
    assert code == 1 and "retained high-water" in out


def test_recovery_is_refused_while_a_floor_exists(published):
    payload, signature = published.approved()
    assert published.install(payload, signature)[0] == 0
    code, out = published.install(payload, signature, "REPLACE", "RECOVER", replace=True,
                                  recover="high-water.json")
    assert code == 1 and "only while high-water.json is absent" in out


# -- boundaries ------------------------------------------------------------------


@pytest.mark.parametrize("argv", [
    ["generation-publish", "--root", "/tmp/x"],
    ["install", "--payload", "a", "--signature", "b", "--confirm-sha256", "c", "--force"],
    ["request", "--operator", "a", "--approval-id", "b", "--seq", "1", "--valid-for", "1",
     "--generation", "3"],
    ["sign"],
])
def test_no_path_override_or_extra_operation_is_accepted(argv):
    with pytest.raises(SystemExit) as result:
        cli.main(argv)
    assert result.value.code == 2


def test_the_tool_creates_no_key_and_contacts_no_service_manager():
    source = Path(cli.__file__).read_text(encoding="utf-8")
    for forbidden in ("SigningKey", "systemd_bus", "DbusUnitManager", "unmask_and_enable",
                      "os.environ", "getenv", "subprocess"):
        assert forbidden not in source, forbidden


# -- overrides and drop-ins ------------------------------------------------------


def _override(node, kind):
    etc = node.root / "etc/systemd/system"
    etc.mkdir(parents=True, exist_ok=True)
    for path in (node.root / "etc", node.root / "etc/systemd", etc):
        path.chmod(0o755)
    if kind == "drop-in":
        (etc / "azazel-edge-intaked.service.d").mkdir()
        (etc / "azazel-edge-intaked.service.d/override.conf").write_text("[Service]\n")
    elif kind == "full":
        (etc / "azazel-edge-intaked.service").write_text("[Service]\nExecStart=/bin/true\n")
    else:
        (etc / "azazel-edge-intaked.service").symlink_to("/dev/null")


@pytest.mark.parametrize("kind", ["drop-in", "full"])
def test_publish_refuses_overrides_and_drop_ins(node, kind):
    _override(node, kind)
    code, out = node.publish("sha256:" + "0" * 64, "PUBLISH")
    assert code == 1 and "override" in out
    assert node.store.numbers() == ()


def test_publish_accepts_the_masked_state(node):
    _override(node, "mask")
    assert node.publish()[0] == 0


def test_request_and_install_refuse_a_drop_in_added_after_publication(published):
    payload, signature = published.approved()
    _override(published, "drop-in")
    code, _, err = published.request()
    assert code == 1 and "drop-in" in err
    code, out = published.install(payload, signature)
    assert code == 1 and "drop-in" in out
    assert not (published.approvals / "approval.json").exists()


# -- interrupted and racing paths ------------------------------------------------


def test_publish_reports_a_published_but_unverified_generation(node, monkeypatch):
    def unreadable(*args, **kwargs):
        raise OSError("read-back failed")

    original = cli._current_baseline
    monkeypatch.setattr(cli, "_current_baseline", unreadable)
    code, out = node.publish()
    monkeypatch.setattr(cli, "_current_baseline", original)
    assert code == 2 and "Generation 1 published, NOT verified" in out
    assert "Nothing published" not in out and "read-back failed" not in out
    assert node.store.numbers() == (1,)
    event = node.events()[-1]
    assert event["event_type"] == "activation.generation_published"
    assert event["verified"] is False


def test_publish_reports_a_missing_record_after_publication(node, monkeypatch):
    def broken(event):
        raise OSError("disk full")

    monkeypatch.setattr(cli, "_append", broken)
    code, out = node.publish()
    assert code == 2 and "did not record it" in out and node.store.numbers() == (1,)


def test_publish_hides_unexpected_errors_before_publication(node, monkeypatch):
    def explode():
        raise ValueError("secret detail")

    monkeypatch.setattr(cli, "_store", explode)
    code, out = node.publish()
    assert code == 1 and "secret detail" not in out


def test_published_event_is_verified_on_success(published):
    assert published.events()[-1]["verified"] is True


def test_install_refuses_context_that_changes_during_confirmation(published, monkeypatch):
    payload, signature = published.approved()
    original = cli._collect_context
    calls = []

    def collect():
        calls.append(1)
        if len(calls) == 2:
            published.declaration = _declaration(epoch=7)
        return original()

    monkeypatch.setattr(cli, "_collect_context", collect)
    code, out = published.install(payload, signature)
    assert code == 1 and "changed during confirmation" in out
    assert not (published.approvals / "approval.json").exists()
    assert not (published.state / "activation").exists()


def test_install_refuses_an_approval_that_appears_during_confirmation(published, monkeypatch):
    payload, signature = published.approved()
    original = cli._collect_context
    calls = []

    def collect():
        calls.append(1)
        if len(calls) == 2:
            for name in ("approval.json", "approval.sig"):
                (published.approvals / name).write_bytes(b"x")
                (published.approvals / name).chmod(0o600)
        return original()

    monkeypatch.setattr(cli, "_collect_context", collect)
    code, out = published.install(payload, signature, replace=True)
    assert code == 1 and "changed during confirmation" in out
    assert (published.approvals / "approval.json").read_bytes() == b"x"


def test_placement_refuses_a_pair_that_appears_after_the_last_check(published, monkeypatch):
    payload, signature = published.approved()
    original = cli.initialize_high_water

    def initialize(*args, **kwargs):
        result = original(*args, **kwargs)
        for name in ("approval.json", "approval.sig"):
            (published.approvals / name).write_bytes(b"x")
            (published.approvals / name).chmod(0o600)
        return result

    monkeypatch.setattr(cli, "initialize_high_water", initialize)
    code, out = published.install(payload, signature, replace=True)
    assert code == 2 and "changed after confirmation" in out
    assert (published.approvals / "approval.json").read_bytes() == b"x"


def test_install_exit_two_when_the_record_is_missing(published, monkeypatch):
    payload, signature = published.approved()

    def broken(event):
        raise OSError("disk full")

    monkeypatch.setattr(cli, "_append", broken)
    code, out = published.install(payload, signature)
    assert code == 2 and "ledger record missing" in out and "disk full" not in out
    assert (published.approvals / "approval.json").read_bytes() == payload


def test_install_exit_two_when_placement_is_unconfirmed(published, monkeypatch):
    payload, signature = published.approved()

    def uncertain(*args, **kwargs):
        raise cli._PlacementUncertain()

    monkeypatch.setattr(cli, "_place_approval", uncertain)
    code, out = published.install(payload, signature)
    assert code == 2 and "UNCONFIRMED" in out
    assert _high_water(published)["approval_seq"] == 5


def test_request_refuses_a_shared_output_directory(published, tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    code, _, err = published.request(out=str(shared / "request.json"))
    assert code == 1 and not (shared / "request.json").exists()
    linked = tmp_path / "linked"
    linked.symlink_to(tmp_path)
    assert published.request(out=str(linked / "request.json"))[0] == 1
    assert not (tmp_path / "request.json").exists()


# -- P4: the pass consumes exactly what az-activation produced -----------------


def test_a_pass_floor_event_blocks_low_reinitialization_and_low_recovery(published):
    """`activation.high_water_raised` (the pass) is a floor like install's own."""
    assert "activation.high_water_raised" in cli.FLOOR_EVENTS
    published.ledger.append({
        "event_type": "activation.high_water_raised",
        "high_water": {"security_epoch": 2, "approval_seq": 9, "generation": 1,
                       "time_floor": NOW},
        "occurred_at": NOW, "actor": "azazel-activated"})
    older, older_sig = published.approved(seq=6, approval_id="approval-6")
    code, out = published.install(older, older_sig)
    assert code == 1 and "recovery procedure" in out
    (published.state / "activation").mkdir(mode=0o700, exist_ok=True)
    retained = published.state / "activation/high-water.json.retained"
    retained.write_bytes(encode_high_water(HighWater(0, 0, 0, "2027-01-01T00:00:00Z")))
    retained.chmod(0o600)
    code, out = published.install(older, older_sig, "RECOVER", recover="high-water.json.retained")
    assert code == 1 and "sequence below the local floor" in out


def test_publish_request_sign_install_then_one_pass_grants_exactly_the_scope(node, monkeypatch):
    """End to end on one temporary root: the CLI's outputs are the pass's inputs.

    generation-publish -> request -> operator_sign (ephemeral key) -> install ->
    one controller pass with the real unit-file, high-water and approval
    readers; it grants exactly the requested units and marks exactly them.
    """
    from azazel_nexus.activation import CORE_UNITS, EdgeBaselineState, UnitState
    from azazel_nexus.activation_approval_v2 import verify_observe_baseline_approval
    from azazel_nexus.activation_store import _read_at
    from azazel_nexus_runtime import activated, activation_markers
    from azazel_nexus_runtime.activation_pass import PassProducers
    from azazel_nexus_runtime.units import RecordingUnitManager

    requested = LOOP[:3]
    assert node.publish()[0] == 0
    code, payload, _ = node.request(units=",".join(requested))
    assert code == 0
    signature, _facts = operator_sign.sign(
        purpose="activation", payload=payload,
        expect_payload_sha256=hashlib.sha256(payload).hexdigest(),
        seed=bytes(node.key), expect_public=bytes(node.key.verify_key).hex())
    code, out = node.install(payload, signature)
    assert code == 0, out

    def approval(**kwargs):
        fd = os.open(node.approvals, os.O_RDONLY | os.O_DIRECTORY)
        try:
            stored, stored_signature = _read_at(fd, owner=os.getuid())
        finally:
            os.close(fd)
        return verify_observe_baseline_approval(
            trust=node.trust, payload=stored, signature=stored_signature, **kwargs)

    producers = PassProducers(
        commissioning_evidence=lambda: node.evidence,
        declared_node=lambda: node.node,
        deployment=lambda: node.declaration,
        policy=lambda: node.policy,
        high_water=hw.require_high_water_for_pass,
        unit_files=scoped_unit_files.measure_scoped_unit_files,
        approval=approval,
        health=lambda policy, ledger: (True, (("state_capacity", "ok"),)),
        raise_high_water=hw.raise_high_water,
        edge_package_digest=lambda: pytest.fail("edge-core is not in this scope"),
        edge_state=lambda *, now: EdgeBaselineState(False, False, False, False, False),
        edge_components=lambda: pytest.fail("edge-core is not in this scope"),
    )
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    (node.root / "run/azazel-activation").mkdir(parents=True)
    (node.root / "run/azazel-activation").chmod(0o755)
    manager = RecordingUnitManager(d.name for d in CORE_UNITS)
    for definition in CORE_UNITS:
        manager.unmask_and_enable(definition.name)

    outcome = activated._run_once(manager=manager, root=node.root, now=NOW,
                                  actor="azazel-activated", producers=producers)

    assert sorted(outcome.granted) == sorted(requested)
    for definition in CORE_UNITS:
        expected = UnitState.ENABLED if definition.name in requested else UnitState.MASKED
        assert manager.state(definition.name) is expected, definition.name
    granted = node.root / "run/azazel-activation/granted"
    assert sorted(p.name for p in granted.iterdir()) == sorted(requested)
    events = node.events()
    assert events[-1]["event_type"] == "activation.inputs_incomplete"
    assert set(events[-1]["observed_inputs"]["producers"].values()) == {"verified"}
    assert any(e["event_type"] == "activation.high_water_raised" for e in events)
    assert _high_water(node)["approval_seq"] == 5

    # A drop-in placed afterwards (the same reader az-activation uses) withholds
    # everything on the next pass and leaves no marker.
    drop_in = node.root / "etc/systemd/system/azazel-mio-entryd.service.d"
    drop_in.mkdir(parents=True)
    for path in (node.root / "etc", node.root / "etc/systemd",
                 node.root / "etc/systemd/system", drop_in):
        path.chmod(0o755)
    (drop_in / "override.conf").write_text("[Service]\nExecStartPre=/bin/true\n")
    outcome = activated._run_once(manager=manager, root=node.root, now=NOW,
                                  actor="azazel-activated", producers=producers)
    assert outcome.granted == ()
    assert not granted.exists()
    assert node.events()[-1]["missing_producers"][-1] == "operational_generation_publisher"


def test_publish_request_with_edge_core_sign_install_then_one_pass_grants_it(node, monkeypatch):
    """P5 end to end: edge-core in the policy, the published generation (with
    the installed package digest), the request and the signature; one pass
    with the real `edge_package` readers over the tmp root's package, this
    boot's id and the boot preflight's fresh result grants and marks it beside
    the SUPPORTING units. Then the next boot, whose preflight left no result,
    withholds only edge-core.
    """
    from azazel_nexus import edge_package
    from azazel_nexus.activation import CORE_UNITS, UnitState
    from azazel_nexus.activation_approval_v2 import verify_observe_baseline_approval
    from azazel_nexus.activation_store import _read_at
    from azazel_nexus.edge_package import (
        PROBE_CONTRACT, Evidence, ProbeResult, installed_baseline_state, installed_package_digest,
        measure_extracted_components)
    from azazel_nexus_runtime import activated, activation_markers
    from azazel_nexus_runtime.activation_pass import PassProducers
    from azazel_nexus_runtime.units import RecordingUnitManager

    scope = tuple(sorted((*LOOP, EDGE)))
    node.policy = _policy(scope)
    digest = node.package()
    assert node.publish(digest=node.expected_digest(digest))[0] == 0
    document = json.loads(node.store.read_tree(1)["baseline.json"])
    assert document["edge_pin"]["package_digest"] == digest
    code, payload, _ = node.request(units=",".join(scope))
    assert code == 0 and json.loads(payload)["units"] == list(scope)
    signature, _facts = operator_sign.sign(
        purpose="activation", payload=payload,
        expect_payload_sha256=hashlib.sha256(payload).hexdigest(),
        seed=bytes(node.key), expect_public=bytes(node.key.verify_key).hex())
    code, out = node.install(payload, signature)
    assert code == 0, out

    boot = "0f0e0d0c-0b0a-4908-8706-050403020100"
    boot_path = node.root / "proc-boot_id"
    boot_path.write_text(boot + "\n")
    boot_path.chmod(0o444)
    probe_path = node.root / "var/lib/azazel/run/edge-probe/edge-probe.json"
    probe_path.parent.mkdir(parents=True)
    probe_path.write_text(json.dumps(ProbeResult(
        contract=PROBE_CONTRACT, boot_id=boot, observed_at="2027-01-09T23:59:30Z",
        ttl_seconds=300, package_version=PIN.version, package_digest=digest,
        health=Evidence.PASSED, health_reason="az-edge-probed --health",
        running=Evidence.FAILED, running_reason="not started at boot").as_event()))
    probe_path.chmod(0o644)
    read_probe, read_boot = edge_package.load_probe_result, edge_package.read_current_boot_id
    monkeypatch.setattr(edge_package, "load_probe_result",
                        lambda path: read_probe(path, owner_uid=os.geteuid()))
    monkeypatch.setattr(edge_package, "read_current_boot_id",
                        lambda path: read_boot(path, owner_uid=os.geteuid()))

    def approval(**kwargs):
        fd = os.open(node.approvals, os.O_RDONLY | os.O_DIRECTORY)
        try:
            stored, stored_signature = _read_at(fd, owner=os.getuid())
        finally:
            os.close(fd)
        return verify_observe_baseline_approval(
            trust=node.trust, payload=stored, signature=stored_signature, **kwargs)

    package_root = node.root / "opt/azazel/edge-core"
    producers = PassProducers(
        commissioning_evidence=lambda: node.evidence,
        declared_node=lambda: node.node,
        deployment=lambda: node.declaration,
        policy=lambda: node.policy,
        high_water=hw.require_high_water_for_pass,
        unit_files=scoped_unit_files.measure_scoped_unit_files,
        approval=approval,
        health=lambda policy, ledger: (True, (("state_capacity", "ok"),)),
        raise_high_water=hw.raise_high_water,
        edge_package_digest=lambda: installed_package_digest(package_root=package_root),
        edge_state=lambda *, now: installed_baseline_state(
            now=now, package_root=package_root, probe_path=probe_path,
            boot_id_path=boot_path),
        edge_components=lambda: measure_extracted_components(
            package_root=package_root, owner_uid=os.getuid()),
    )
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    (node.root / "run/azazel-activation").mkdir(parents=True)
    (node.root / "run/azazel-activation").chmod(0o755)
    manager = RecordingUnitManager(d.name for d in CORE_UNITS)
    for definition in CORE_UNITS:
        manager.unmask_and_enable(definition.name)

    outcome = activated._run_once(manager=manager, root=node.root, now=NOW,
                                  actor="azazel-activated", producers=producers)

    assert sorted(outcome.granted) == list(scope)
    for definition in CORE_UNITS:
        expected = UnitState.ENABLED if definition.name in scope else UnitState.MASKED
        assert manager.state(definition.name) is expected, definition.name
    granted = node.root / "run/azazel-activation/granted"
    assert sorted(p.name for p in granted.iterdir()) == list(scope)
    last = node.events()[-1]
    assert last["observed_inputs"]["edge_evidence"] == "launchable"
    assert last["observed_inputs"]["edge_package_binding"] == "bound"
    assert "edge_evidence" not in last["missing_producers"]

    # The next boot: the preflight failed or timed out and left no result.
    # Edge-core is withheld; the SUPPORTING units are still granted.
    probe_path.unlink()
    outcome = activated._run_once(manager=manager, root=node.root, now=NOW,
                                  actor="azazel-activated", producers=producers)
    assert sorted(outcome.granted) == list(LOOP)
    assert manager.state(EDGE) is UnitState.MASKED
    assert sorted(p.name for p in granted.iterdir()) == list(LOOP)
    verdict = next(v for v in outcome.verdicts if v.unit == EDGE)
    # No result names no probed package either, which is never bound.
    assert verdict.reason == "edge_not_ready: digest_matches,health_endpoint_healthy"

    # The extracted binary rewritten after the signature refuses the lease,
    # although the archive is intact.
    probe_path.write_text(json.dumps(ProbeResult(
        contract=PROBE_CONTRACT, boot_id=boot, observed_at="2027-01-09T23:59:30Z",
        ttl_seconds=300, package_version=PIN.version, package_digest=digest,
        health=Evidence.PASSED, health_reason="az-edge-probed --health",
        running=Evidence.FAILED, running_reason="not started at boot").as_event()))
    binary = package_root / "bin/azazel-edge-core"
    original = binary.read_bytes()
    binary.write_bytes(original + b"rewritten")
    outcome = activated._run_once(manager=manager, root=node.root, now=NOW,
                                  actor="azazel-activated", producers=producers)
    assert outcome.granted == ()
    assert node.events()[-1]["missing_producers"][-1] == "operational_generation_publisher"
    binary.write_bytes(original)

    # A different package installed after the signature refuses the lease.
    node.package(binary=b"a-different-edge-core")
    outcome = activated._run_once(manager=manager, root=node.root, now=NOW,
                                  actor="azazel-activated", producers=producers)
    assert outcome.granted == ()
    assert not granted.exists()
    assert node.events()[-1]["missing_producers"][-1] == "operational_generation_publisher"
