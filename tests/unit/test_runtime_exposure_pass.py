"""The exposure tier in one pass: stages P1 to P11, the scope files, the tripwire (#196 G6).

`docs/deception-exposure-wiring.md` §4 (the order), §5.3 (the scope files),
§6 (the tripwire) and §7 items 1, 3, 4, 8 and 9. A commissioned, published,
approved and healthy node in a tmp root (`test_runtime_activation_pass.World`)
whose policy names the three exposure units, with a v3 commissioning
proposal (the pinned Fabric's golden inventory, `test_exposure_interfaces`),
a v2 generation carrying the exposure section, and a v3 approval signed with
a key generated for the test under `ACTIVATION_EXPOSURE`. The host readers
of step 10 are in-memory fixtures (`ExposureReaders`); the parts they feed
are the real ones. None of this is VM or hardware evidence (§8).
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import replace

import pytest

from azazel_nexus.activation import CORE_UNITS, DECEPTION_EXPOSURE_UNITS, UnitState
from azazel_nexus.activation_approval_v2 import ObserveBaselineApproval
from azazel_nexus.activation_approval_v3 import activation_approval_v3_payload
from azazel_nexus.commissioning_evidence import CommissioningEvidence
from azazel_nexus.decoy_scope import DecoyScopeRefused, parse_scope_file, render_scope_file
from azazel_nexus.exposure_admission import EXPOSURE_STAGES, ExposureEvidence
from azazel_nexus.observe_baseline import build_observe_baseline, evidence_commissioning_digest
from azazel_nexus.operator_trust import ApprovalPurpose, approval_message
from azazel_nexus_runtime import activated, activation_markers, activation_pass, exposure_pass
from azazel_nexus_runtime.activation_pass import EXPOSURE_EVIDENCE
from azazel_nexus_runtime.activation_unit_files import WATCH_UNITS
from azazel_nexus_runtime.decoy_apparmor import REQUIRED_ENFORCED_PROFILES
from azazel_nexus_runtime.exposure_generation import build_exposure_section
from azazel_nexus_runtime.exposure_pass import ExposureReaders
from azazel_nexus_runtime.netlink import LinkRecord
from azazel_nexus_runtime.units import RecordingUnitManager

import test_decoy_reachability as reach
import test_exposure_interfaces as roles
import test_runtime_activation_pass as trap

pytestmark = roles.needs_fabric

EXPOSURE = tuple(DECEPTION_EXPOSURE_UNITS)
SUPPORTING = trap.SCOPE
UNITS = tuple(sorted(SUPPORTING + EXPOSURE))
INGRESS = ("lan0",)
POLICY_HASH = "ab" * 32
SCOPE_FILES = ("decoy-scope.json", "decoy-scope.digest")


def _canonical_inventory(inventory) -> bytes:
    """What `verify_commissioning_evidence` retains as the current inventory."""
    return json.dumps(inventory.model_dump(mode="json"), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _profiles_listing() -> bytes:
    return b"".join(name.encode() + b" (enforce)\n" for name in REQUIRED_ENFORCED_PROFILES)


class ExposureWorld(trap.World):
    """`trap.World` whose policy, generation and approval name the exposure tier."""

    def __init__(self, root):
        super().__init__(root)
        from azazel_nexus.commissioning_approval import commissioning_proposal_payload

        self.node_context = roles._node()
        self.proposal = commissioning_proposal_payload(
            **self.node_context, mio_profile="FULL",
            deception_scope=json.loads(json.dumps(roles.SCOPE)))
        self.current = roles._current()
        self.evidence = CommissioningEvidence(
            self.proposal, b"\x01" * 64, _canonical_inventory(self.current),
            "hmac-sha256:" + "c" * 64)
        self.units = UNITS
        self.policy = trap.make_policy(units=UNITS)
        scope = roles._scope(self.node_context)
        self.scope_file = render_scope_file(scope, INGRESS)
        self.scope_digest = parse_scope_file(self.scope_file).scope_digest
        self.exposure_unit_files = {u: f"[Unit]\nDescription={u}\n".encode() for u in EXPOSURE}
        self.watch_unit_files = {u: f"[Unit]\nDescription={u}\n".encode() for u in WATCH_UNITS}
        self.profile_files = {name: f"profile {name} {{}}\n".encode()
                              for name in REQUIRED_ENFORCED_PROFILES}
        self.section = build_exposure_section(
            unit_files=self.exposure_unit_files, watch_unit_files=self.watch_unit_files,
            apparmor_profiles=self.profile_files,
            apparmor_policy_hashes={name: POLICY_HASH for name in REQUIRED_ENFORCED_PROFILES},
            scope_file=self.scope_file)
        self.generation = self.store.create(
            build_observe_baseline(
                units=list(UNITS), unit_files={u: self.unit_files[u] for u in SUPPORTING},
                exposure=self.section),
            created_at="2026-10-20T00:00:01Z",
            commissioning_digest=evidence_commissioning_digest(self.evidence),
            commissioning_evidence_binding=self.evidence.binding)
        self.sign_v3()
        self.host = self.clean_host()
        self.read: list[str] = []

    def sign_v3(self, *, purpose=ApprovalPurpose.ACTIVATION_EXPOSURE, **overrides):
        fields = dict(approval_id="approval-1", operator="operator-a", approval_seq=5,
                      units=UNITS, granted_at="2026-10-20T12:00:00Z",
                      expires_at="2026-10-22T00:00:00Z",
                      exposure_scope_digest=self.scope_digest, exposure_prefix_count=2,
                      exposure_ingress_count=1) | overrides
        self.payload = activation_approval_v3_payload(context=self.context(), **fields)
        self.signature = self.key.sign(approval_message(purpose, self.payload)).signature

    def clean_host(self) -> dict:
        """What a host configured as reachability §8 says reads, by reader."""
        links = (LinkRecord(1, "lo", None, "loopback"), LinkRecord(2, "lan0", None, "x"),
                 LinkRecord(3, "mgmt0", None, "x"), LinkRecord(4, "mon0", None, "x"))
        ipv4 = {name: {"forwarding": 0} for name in ("default", "lo", "mgmt0", "mon0")}
        ipv4 |= {"all": {"forwarding": 0, "proxy_arp": 0},
                 "lan0": {"forwarding": 1, "proxy_arp": 0}}
        ipv6 = {name: {"forwarding": 0}
                for name in ("all", "default", "lo", "lan0", "mgmt0", "mon0")}
        return dict(
            fb_tunnels=b"2\n",
            lsm=(b"lockdown,capability,landlock,yama,apparmor\n", _profiles_listing()),
            host_firewall={u: None for u in ("nftables.service", "firewalld.service",
                                             "netfilter-persistent.service")},
            exposure_units={u: {"LoadState": "masked", "UnitFileState": "masked",
                                "ActiveState": "inactive"} for u in EXPOSURE},
            netns=(0, None),
            links=links,
            sysctls=(ipv4, ipv6),
            rules=reach._rule_list(ingress=INGRESS),
            routes=json.loads(reach._routes()[1]),
            section_inputs=(dict(self.exposure_unit_files), dict(self.watch_unit_files),
                            dict(self.profile_files)),
            loaded_profiles={
                **{u: {"LoadState": "masked", "AppArmorProfile": (False, "")}
                   for u in EXPOSURE},
                "azazel-decoy-verify.service": {
                    "LoadState": "loaded", "AppArmorProfile": (False, "azazel-decoy-verify")}},
            policy_hashes=tuple((name.encode() + b"\n", POLICY_HASH.encode() + b"\n")
                                for name in REQUIRED_ENFORCED_PROFILES),
        )

    def readers(self) -> ExposureReaders:
        def reader(name, *, argument=False):
            def read(*args):
                self.read.append(name)
                value = self.host[name]
                if isinstance(value, Exception):
                    raise value
                return value
            return read

        return ExposureReaders(**{name: reader(name) for name in (
            "fb_tunnels", "lsm", "host_firewall", "exposure_units", "netns", "links",
            "sysctls", "rules", "routes", "section_inputs", "loaded_profiles",
            "policy_hashes")})

    def producers(self, **replaced):
        replaced.setdefault("exposure", self.readers())
        return super().producers(**replaced)

    def scope_files(self):
        directory = self.root / "run/azazel-activation"
        return {name: directory / name for name in SCOPE_FILES if (directory / name).exists()}


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    trap._owned_by_the_test(monkeypatch)
    return ExposureWorld(tmp_path)


def _reasons(outcome):
    return {v.unit: v.reason for v in outcome.verdicts}


def _assert_tier_withheld(world, outcome, stage, code):
    """Withheld with `code` at `stage`; the SUPPORTING units granted as before."""
    assert sorted(outcome.granted) == list(SUPPORTING)
    reasons = _reasons(outcome)
    assert {reasons[unit].split(":", 1)[0] for unit in EXPOSURE} == {code}
    for unit in EXPOSURE:
        assert world.manager.state(unit) is UnitState.MASKED
    assert world.markers() == list(SUPPORTING)
    assert world.scope_files() == {}
    event = world.inputs_event()
    observed = event["observed_inputs"]
    assert observed["exposure_evidence"] == "withheld"
    assert observed["exposure_stage"] == stage
    assert observed["exposure_code"] == code
    assert EXPOSURE_EVIDENCE in event["missing_producers"]
    assert set(observed["producers"].values()) == {"verified"}


# -- a full grant (§7 item 3) ---------------------------------------------------


def test_every_stage_holds_and_the_three_are_granted_with_their_scope_files(world):
    old = os.umask(0o000)
    try:
        outcome = world.run()
    finally:
        os.umask(old)
    assert sorted(outcome.granted) == list(UNITS)
    for unit in EXPOSURE:
        assert world.manager.state(unit) is UnitState.ENABLED
    assert world.markers() == list(UNITS)
    files = world.scope_files()
    assert set(files) == set(SCOPE_FILES)
    for path in files.values():
        info = path.stat()
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid()
        assert info.st_nlink == 1
    assert files["decoy-scope.json"].read_bytes() == world.scope_file
    assert files["decoy-scope.digest"].read_bytes() == (world.scope_digest + "\n").encode()
    event = world.inputs_event()
    assert event["observed_inputs"]["exposure_evidence"] == "established"
    assert "exposure_stage" not in event["observed_inputs"]
    assert EXPOSURE_EVIDENCE not in event["missing_producers"]
    assert event["grant_markers"] == list(UNITS)
    # Every reader was asked once, in the order of the stages.
    assert world.read == ["fb_tunnels", "lsm", "host_firewall", "exposure_units", "netns",
                          "links", "sysctls", "rules", "routes", "section_inputs",
                          "loaded_profiles", "policy_hashes"]
    # No name, prefix or address in the ledger.
    text = world.ledger_path.read_text()
    for leak in ("lan0", "mgmt0", "10.20.0.0", "192.168.10.0", world.scope_digest):
        assert leak not in text, leak


def test_the_scope_files_are_written_after_the_high_water_and_before_the_markers(
        world, monkeypatch):
    order = []
    real_scope, real_markers = activated.write_scope_files, activated.write_grant_markers
    real_raise = world.producers().raise_high_water

    def scope(*args, **kwargs):
        order.append("scope")
        return real_scope(*args, **kwargs)

    def markers(*args, **kwargs):
        order.append("markers")
        return real_markers(*args, **kwargs)

    def high_water(*args, **kwargs):
        order.append("high_water")
        return real_raise(*args, **kwargs)

    monkeypatch.setattr(activated, "write_scope_files", scope)
    monkeypatch.setattr(activated, "write_grant_markers", markers)
    world.run(raise_high_water=high_water)
    assert order == ["high_water", "scope", "markers"]
    kinds = [e["event_type"] for e in world.events()]
    assert kinds.index("activation.high_water_raised") < kinds.index(
        "activation.inputs_incomplete")


# -- the order: each stage alone (§7 item 1) -------------------------------------

#: The readers of each stage; a stage must not reach a later stage's readers.
_STAGE_READERS = {
    "P2": ("fb_tunnels",), "P3": ("lsm",), "P4": ("host_firewall",),
    "P5": ("exposure_units", "netns", "links"), "P7": ("sysctls", "rules", "routes"),
    "P9": ("section_inputs",), "P11": ("loaded_profiles", "policy_hashes"),
}
#: The parts each stage calls inside `exposure_pass`, poisoned after it.
_STAGE_PARTS = {
    "P2": ("fb_tunnels_refusal",), "P3": ("exposure_lsm_refusal",),
    "P4": ("host_firewall_refusal",), "P5": ("exposure_residue_departures",),
    "P6": ("resolve_role_interfaces",), "P7": ("pass_reachability_departures",),
    "P8": ("render_scope_file",), "P9": ("verify_exposure_section",),
    "P11": ("loaded_unit_profile_refusal", "policy_hash_refusal"),
}


def _later(stage):
    return EXPOSURE_STAGES[EXPOSURE_STAGES.index(stage) + 1:]


def _poison_later_parts(monkeypatch, stage):
    called = []
    for later in _later(stage):
        for name in _STAGE_PARTS.get(later, ()):
            def poisoned(*args, _name=name, **kwargs):
                called.append(_name)
                raise AssertionError(f"{_name} called after an earlier stage refused")
            monkeypatch.setattr(exposure_pass, name, poisoned)
    return called


def _fail_p1(world, monkeypatch):
    real = world.producers().approval

    def as_v2(**kwargs):
        verified = real(**kwargs)
        return ObserveBaselineApproval(lease=verified.lease, approval_id=verified.approval_id,
                                       approval_seq=verified.approval_seq,
                                       security_epoch=verified.security_epoch)
    return dict(approval=as_v2)


def _fail_p6(world, monkeypatch):
    renamed = roles._current({"if-a": "mon0", "if-b": "lan5", "if-c": "mgmt0"})
    world.evidence = replace(world.evidence, current_inventory=_canonical_inventory(renamed))
    return {}


def _fail_p8(world, monkeypatch):
    def refuse(*args, **kwargs):
        raise DecoyScopeRefused("the scope file exceeds its bound")
    monkeypatch.setattr(exposure_pass, "render_scope_file", refuse)
    return {}


def _fail_p9(world, monkeypatch):
    files, watch, profiles = world.host["section_inputs"]
    changed = dict(files)
    changed[EXPOSURE[2]] = changed[EXPOSURE[2]] + b"#"
    world.host["section_inputs"] = (changed, watch, profiles)
    return {}


def _fail_p10(world, monkeypatch):
    world.sign_v3(exposure_prefix_count=3)
    return {}


def _host(name, value):
    def change(world, monkeypatch):
        world.host[name] = value
        return {}
    return change


_ORDER = [
    ("P1", "exposure_approval_not_v3", _fail_p1),
    ("P2", "fb_tunnels_not_init_net_only", _host("fb_tunnels", b"0\n")),
    ("P3", "lsm_apparmor_disabled", _host("lsm", (b"capability,yama\n", None))),
    ("P4", "host_firewall_enabled", _host("host_firewall", {
        "nftables.service": {"UnitFileState": "enabled", "ActiveState": "inactive"},
        "firewalld.service": None, "netfilter-persistent.service": None})),
    ("P5", "exposure_leftovers_present", _host("netns", (0, stat.S_IFREG | 0o444))),
    ("P6", "role_inventory_changed", _fail_p6),
    ("P7", "forwarding_host_wide", None),
    ("P8", "decoy_scope_unrenderable", _fail_p8),
    ("P9", "exposure_generation_differs", _fail_p9),
    ("P10", "exposure_approval_binding_differs", _fail_p10),
    ("P11", "lsm_policy_differs", _host("policy_hashes", tuple(
        (name.encode() + b"\n", b"cd" * 32 + b"\n") for name in REQUIRED_ENFORCED_PROFILES))),
]


@pytest.mark.parametrize("stage,code,fail", _ORDER, ids=[item[0] for item in _ORDER])
def test_each_stage_alone_withholds_the_tier_with_its_code_and_reads_nothing_later(
        world, monkeypatch, stage, code, fail):
    if fail is None:  # P7: IPv4 forwarding host wide
        ipv4, ipv6 = world.host["sysctls"]
        world.host["sysctls"] = ({**ipv4, "all": {"forwarding": 1, "proxy_arp": 0}}, ipv6)
        replaced = {}
    else:
        replaced = fail(world, monkeypatch)
    called = _poison_later_parts(monkeypatch, stage)
    outcome = world.run(**replaced)
    _assert_tier_withheld(world, outcome, stage, code)
    assert called == []
    later = {name for s in _later(stage) for name in _STAGE_READERS.get(s, ())}
    assert not later & set(world.read), sorted(later & set(world.read))


def test_a_changed_exposure_unit_file_withholds_the_tier_alone(world):
    """Finding 1 of the review of #301: the observe scope's generation is not
    refused; only P9 sees the exposure unit file."""
    _fail_p9(world, None)
    outcome = world.run()
    _assert_tier_withheld(world, outcome, "P9", "exposure_generation_differs")
    assert world.inputs_event()["observed_inputs"]["producers"][
        "operational_generation_publisher"] == "verified"


@pytest.mark.parametrize("name", ["fb_tunnels", "lsm", "host_firewall", "exposure_units",
                                  "sysctls", "section_inputs", "loaded_profiles",
                                  "policy_hashes"])
def test_an_exception_in_any_stage_is_unreadable_and_the_other_tiers_are_unchanged(
        world, name):
    world.host[name] = RuntimeError("reader failed")
    outcome = world.run()
    # P9's reader has its own code (wiring §4.3); every other is unreadable.
    code = ("exposure_files_unreadable" if name == "section_inputs"
            else "exposure_stage_unreadable")
    assert sorted(outcome.granted) == list(SUPPORTING)
    assert {_reasons(outcome)[unit].split(":", 1)[0] for unit in EXPOSURE} == {code}
    assert world.scope_files() == {}
    assert world.inputs_event()["observed_inputs"]["exposure_code"] == code


def test_without_readers_the_tier_is_withheld_and_the_rest_granted(world):
    outcome = world.run(exposure=None)
    assert sorted(outcome.granted) == list(SUPPORTING)
    observed = world.inputs_event()["observed_inputs"]
    assert observed["exposure_stage"] == "P2"
    assert observed["exposure_code"] == "exposure_stage_unreadable"


def test_a_lease_without_the_tier_reads_nothing_for_it(world):
    world.sign(units=SUPPORTING)  # a v2 approval of the SUPPORTING units
    outcome = world.run()
    assert sorted(outcome.granted) == list(SUPPORTING)
    assert world.read == []
    observed = world.inputs_event()["observed_inputs"]
    assert observed["exposure_evidence"] == "not_in_scope"
    assert EXPOSURE_EVIDENCE not in world.inputs_event()["missing_producers"]
    assert {_reasons(outcome)[unit].split(":", 1)[0] for unit in EXPOSURE} == {
        "outside_lease_scope"}


# -- approval and policy (§7 items 4 and 5) --------------------------------------


def test_a_v3_signed_under_activation_is_refused_and_nothing_is_granted(world):
    world.sign_v3(purpose=ApprovalPurpose.ACTIVATION)
    outcome = world.run()
    assert outcome.granted == ()
    assert world.scope_files() == {}
    assert world.markers() is None


def test_a_v3_naming_part_of_the_tier_cannot_be_made(world):
    from azazel_nexus.operator_trust import ApprovalRefused

    with pytest.raises(ApprovalRefused, match="approval_v3_exposure_partial"):
        world.sign_v3(units=SUPPORTING + EXPOSURE[:2])


def test_a_v2_approval_still_grants_the_rest_under_a_policy_naming_the_tier(world):
    world.sign(units=SUPPORTING)
    outcome = world.run()
    assert sorted(outcome.granted) == list(SUPPORTING)
    assert world.scope_files() == {}


def test_the_floors_are_raised_by_a_v3_approval(world):
    world.sign_v3(approval_seq=9)
    world.run()
    assert world.raised and world.raised[-1].approval_seq == 9
    assert world.raised[-1].generation == world.generation.number


def test_a_policy_without_the_tier_refuses_a_v3_approval(world):
    world.policy = trap.make_policy(units=SUPPORTING)
    outcome = world.run()
    assert outcome.granted == ()


# -- the scope files (§5.3, §7 item 8) -------------------------------------------


def _parent(world):
    return world.root / "run/azazel-activation"


def test_stale_scope_files_and_temporaries_are_removed_before_any_decision(world):
    parent = _parent(world)
    for name in SCOPE_FILES + tuple(f"{n}.tmp" for n in SCOPE_FILES):
        (parent / name).write_bytes(b"stale")
    world.sign(units=SUPPORTING)
    world.run()
    assert sorted(p.name for p in parent.iterdir()) == ["granted"]


@pytest.mark.parametrize("name", SCOPE_FILES)
def test_a_non_regular_object_at_a_scope_name_refuses_the_pass(world, name):
    (_parent(world) / name).mkdir()
    (_parent(world) / "granted").mkdir()
    (_parent(world) / "granted" / "azazel-mio-entryd.service").write_bytes(b"")
    with pytest.raises(RuntimeError, match="stale activation grant markers"):
        world.run()
    # The markers were removed all the same; every governed unit masked.
    assert world.markers() is None
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert "activation.grant_markers_unclean" in [e["event_type"] for e in world.events()]


def test_the_scope_files_go_before_the_markers_at_reset(world, monkeypatch):
    """A failure while removing the markers leaves no scope file behind."""
    parent = _parent(world)
    for name in SCOPE_FILES:
        (parent / name).write_bytes(b"stale")
    (parent / "granted").mkdir()
    (parent / "granted" / "nested").mkdir()  # makes the marker removal refuse
    with pytest.raises(activation_markers.GrantMarkerRefused):
        activation_markers.reset_grant_markers(world.root)
    assert not any((parent / name).exists() for name in SCOPE_FILES)


def test_a_failed_scope_write_narrows_everything_and_removes_files_and_markers(
        world, monkeypatch):
    def broken(scope_file, digest, root):
        (_parent(world) / "decoy-scope.json").write_bytes(b"partial")
        raise OSError("disk full")

    monkeypatch.setattr(activated, "write_scope_files", broken)
    with pytest.raises(RuntimeError, match="decoy scope files could not be written"):
        world.run()
    assert world.scope_files() == {}
    assert world.markers() is None
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert "activation.decoy_scope_unwritten" in [e["event_type"] for e in world.events()]


@pytest.mark.parametrize("change", ["scope", "digest"])
def test_a_read_back_that_differs_narrows_everything(world, monkeypatch, change):
    real = activated.read_scope_files

    def differing(root):
        scope_file, digest_file = real(root)
        if change == "scope":
            return scope_file.replace(b"lan0", b"lan1"), digest_file
        return scope_file, b"sha256:" + b"0" * 64 + b"\n"

    monkeypatch.setattr(activated, "read_scope_files", differing)
    with pytest.raises(RuntimeError, match="decoy scope files could not be written"):
        world.run()
    assert world.scope_files() == {}
    assert world.markers() is None


def test_the_emergency_narrowing_removes_the_scope_files_even_if_the_markers_refuse(
        world, monkeypatch):
    parent = _parent(world)
    for name in SCOPE_FILES:
        (parent / name).write_bytes(b"x")

    def refuse(root):
        raise activation_markers.GrantMarkerRefused("refused")

    monkeypatch.setattr(activated, "reset_grant_markers", refuse)
    with pytest.raises(RuntimeError):
        activated._emergency_narrow(world.manager, world.root, "test")
    assert world.scope_files() == {}


def test_a_rolled_back_pass_writes_no_scope_file(world):
    world.manager = RecordingUnitManager((d.name for d in CORE_UNITS), fail_on=EXPOSURE[2])
    with pytest.raises(RuntimeError, match="Deception Lite exposure tier"):
        world.run()
    assert world.scope_files() == {}
    assert world.markers() is None


# -- the tripwire (§6, §7 item 9) ------------------------------------------------


def _forge_grant(monkeypatch, units=EXPOSURE):
    """A library that granted `units` whatever the evidence said."""
    from azazel_nexus.activation import ActivationOutcome, UnitVerdict

    original = activated.ActivationDaemon.activate

    def forged(self, **kwargs):
        outcome = original(self, **kwargs)
        verdicts = tuple(
            UnitVerdict(v.unit, v.unit in units, "granted" if v.unit in units else "forged")
            if v.unit in EXPOSURE else v for v in outcome.verdicts)
        return ActivationOutcome(outcome.generation, verdicts, edge=outcome.edge)

    monkeypatch.setattr(activated.ActivationDaemon, "activate", forged)


def _with_inputs(monkeypatch, change):
    real = activation_pass.collect_pass_inputs

    def collect(**kwargs):
        inputs = real(**kwargs)
        change(inputs)
        return inputs

    monkeypatch.setattr(activation_pass, "collect_pass_inputs", collect)


def _evidence(inputs, **changes):
    values = dict(generation_digest=inputs.exposure.generation_digest,
                  scope_digest=inputs.exposure.scope_digest, refusal=None,
                  stages=EXPOSURE_STAGES) | changes
    return ExposureEvidence(**values)


_TRIPS = {
    "partial": (EXPOSURE[:2], None),
    "refusal": (EXPOSURE, lambda i: setattr(i, "exposure", _evidence(
        i, refusal="host_firewall_enabled: x", stages=EXPOSURE_STAGES[:3]))),
    "stage missing": (EXPOSURE, lambda i: setattr(i, "exposure", _evidence(
        i, refusal="exposure_stage_unreadable: x", stages=EXPOSURE_STAGES[:10]))),
    "other generation": (EXPOSURE, lambda i: setattr(i, "exposure", _evidence(
        i, generation_digest="sha256:" + "9" * 64))),
    "no evidence": (EXPOSURE, lambda i: setattr(i, "exposure", None)),
    "label": (EXPOSURE, lambda i: setattr(i, "exposure_evidence", "withheld")),
    "no rendering": (EXPOSURE, lambda i: setattr(i, "exposure_scope_file", None)),
    "other rendering": (EXPOSURE, lambda i: setattr(
        i, "exposure_scope_file", i.exposure_scope_file.replace(b"lan0", b"lan1"))),
}


@pytest.mark.parametrize("case", sorted(_TRIPS))
def test_each_tripwire_condition_violated_alone_narrows_everything(world, monkeypatch, case):
    units, change = _TRIPS[case]
    _forge_grant(monkeypatch, units)
    if change is not None:
        _with_inputs(monkeypatch, change)
    with pytest.raises(RuntimeError, match="Deception Lite exposure tier"):
        world.run()
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.markers() is None
    assert world.scope_files() == {}


def test_a_v2_approval_with_a_forged_grant_trips_the_wire(world, monkeypatch):
    _forge_grant(monkeypatch)
    world.sign(units=SUPPORTING)
    with pytest.raises(RuntimeError, match="production activation granted"):
        world.run()
    assert world.scope_files() == {}
