"""Decoys that really listen, and that cannot reach past this host (#69, E3-F).

Everything here runs against a real socket. A test that asserted the runtime's
intentions would pass on a runtime that bound nothing, which is precisely the
state this issue exists to leave behind.

The discipline being checked is not "it only binds loopback". It is stronger
and structural: **nothing in the runtime distribution can bind an address or
a port at all.** `test_runtime_boundary.py` scans for `AF_INET`, `AF_INET6`,
`AF_PACKET` and `create_connection` across the whole distribution, so external
exposure is not refused here -- it is absent from the code that would do it.
"""

from __future__ import annotations

import ast
import socket
import stat
from pathlib import Path

import pytest

from azazel_nexus.decoy import MAX_DECOYS
from azazel_nexus_runtime.decoy_loopback import (
    LOOPBACK_ONLY,
    MAX_READ_BYTES,
    RESPONDERS,
    LoopbackCatalogue,
    LoopbackDecoy,
    LoopbackRefused,
    LoopbackRuntime,
    Observation,
    ResponderState,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "runtime" / "src" / "azazel_nexus_runtime" / "decoy_loopback.py"
GENERATION = "sha256:" + "ab" * 32


def _clock():
    """A fixed instant. An observation's time is an input, never a reading."""

    ticks = iter(f"2026-09-21T00:00:{second:02d}Z" for second in range(60))
    return lambda: next(ticks)


def _catalogue(*names: str) -> LoopbackCatalogue:
    responders = sorted(RESPONDERS)
    return LoopbackCatalogue.of(
        [
            LoopbackDecoy(name=name, responder=responders[index % len(responders)])
            for index, name in enumerate(names or ("alpha",))
        ]
    )


@pytest.fixture
def runtime(tmp_path):
    made = LoopbackRuntime(
        tmp_path / "decoys",
        catalogue=_catalogue("alpha", "bravo"),
        generation_digest=GENERATION,
        clock=_clock(),
    )
    yield made
    made.stop()


def _connect(path: Path) -> socket.socket:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    client.connect(str(path))
    return client


# -- the entry, which has no address and no port to get wrong ---------------


def test_a_loopback_decoy_has_no_address_and_no_port():
    """Not refused -- **absent**. A field that does not exist cannot be set."""

    fields = set(LoopbackDecoy.__dataclass_fields__)
    assert fields == {"name", "responder"}
    for forbidden in ("listen_address", "port", "image", "image_digest", "command", "bridge"):
        assert forbidden not in fields


def test_a_responder_is_selected_and_never_supplied():
    with pytest.raises(LoopbackRefused, match="never supplied"):
        LoopbackDecoy(name="alpha", responder="/bin/sh")
    assert LoopbackDecoy(name="alpha", responder="ssh-banner").banner in RESPONDERS.values()


def test_every_responder_is_a_constant_byte_string():
    """Nothing formats, templates or interpolates: no argument can enter."""

    assert RESPONDERS
    for name, banner in RESPONDERS.items():
        assert isinstance(banner, bytes), name
        assert b"{" not in banner and b"%" not in banner, name


@pytest.mark.parametrize(
    "name",
    ["../escape", "a/b", "alpha.sock", "-dash", "", "A", "x" * 32, "al pha"],
)
def test_a_name_that_could_become_a_path_is_refused(name):
    with pytest.raises(LoopbackRefused, match="not a decoy name"):
        LoopbackDecoy(name=name, responder="ssh-banner")


def test_the_loopback_type_is_not_the_exposed_type():
    """One permission must never be read as the other.

    `azazel_nexus.decoy.DecoyEntry` refuses loopback, correctly: a decoy an
    attacker cannot reach is not an exposed decoy. That discipline is not
    inverted here -- a different type is used, with no field in common beyond
    a name.
    """

    from azazel_nexus.decoy import DecoyEntry

    shared = set(LoopbackDecoy.__dataclass_fields__) & set(DecoyEntry.__dataclass_fields__)
    assert shared == {"name"}


# -- the catalogue ---------------------------------------------------------


def test_an_empty_catalogue_is_refused():
    with pytest.raises(LoopbackRefused, match="starts nothing"):
        LoopbackCatalogue.of([])


def test_more_than_the_ceiling_is_refused_rather_than_truncated():
    entries = [
        LoopbackDecoy(name=f"d{index}", responder="ssh-banner")
        for index in range(MAX_DECOYS + 1)
    ]
    with pytest.raises(LoopbackRefused, match="rather than truncated"):
        LoopbackCatalogue.of(entries)


def test_two_decoys_may_not_share_a_name():
    with pytest.raises(LoopbackRefused, match="share a name"):
        LoopbackCatalogue.of(
            [
                LoopbackDecoy(name="alpha", responder="ssh-banner"),
                LoopbackDecoy(name="alpha", responder="smtp-banner"),
            ]
        )


def test_a_name_outside_the_catalogue_starts_nothing(runtime):
    with pytest.raises(LoopbackRefused, match="nothing else"):
        runtime.catalogue.entry("charlie")


# -- binding ---------------------------------------------------------------


def test_starting_binds_a_unix_socket_for_every_decoy(runtime):
    assert runtime.start() == ("alpha", "bravo")
    for name in ("alpha", "bravo"):
        path = runtime.path_for(name)
        assert path.is_socket(), name
        assert runtime.state(name) is ResponderState.LISTENING


def test_the_directory_is_private_and_the_socket_is_owner_only(runtime):
    runtime.start()
    assert stat.S_IMODE(runtime.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(runtime.path_for("alpha").stat().st_mode) == 0o600


def test_a_socket_path_stays_inside_the_runtime_directory(runtime):
    runtime.start()
    assert runtime.root.resolve() in runtime.path_for("alpha").parents


def test_starting_twice_rebinds_rather_than_failing_on_a_stale_socket(runtime):
    runtime.start()
    assert runtime.start() == ("alpha", "bravo")
    assert runtime.state("alpha") is ResponderState.LISTENING


def test_a_runtime_with_no_generation_is_refused(tmp_path):
    """An observation nobody can attribute is an observation nobody can replay."""

    with pytest.raises(LoopbackRefused, match="verified generation"):
        LoopbackRuntime(
            tmp_path,
            catalogue=_catalogue("alpha"),
            generation_digest="  ",
            clock=_clock(),
        )


# -- serving ---------------------------------------------------------------


def test_a_connection_gets_the_responder_the_catalogue_names(runtime):
    runtime.start()
    client = _connect(runtime.path_for("alpha"))
    try:
        observation = runtime.serve_once("alpha")
        assert client.recv(1024) == runtime.catalogue.entry("alpha").banner
    finally:
        client.close()
    assert observation is not None
    assert observation.decoy_name == "alpha"


def test_being_reached_is_recorded_as_an_observation(runtime):
    runtime.start()
    client = _connect(runtime.path_for("alpha"))
    try:
        client.sendall(b"hunter2\n")
        client.shutdown(socket.SHUT_WR)
        observation = runtime.serve_once("alpha")
    finally:
        client.close()
    assert observation.bytes_received == 8
    assert observation.generation_digest == GENERATION
    assert runtime.observations == [observation]


def test_an_observation_records_that_it_happened_and_never_what_was_sent(runtime):
    """A decoy exists to be reached by someone hostile.

    What they send is not this node's to keep. The field list *is* the record,
    so it is asserted: a field able to hold a payload is how a decoy's audit
    becomes a credential store.
    """

    assert set(Observation.__dataclass_fields__) == {
        "decoy_name",
        "at",
        "generation_digest",
        "bytes_received",
        "responder",
        "truncated",
    }
    runtime.start()
    secret = b"password=correct-horse-battery-staple"
    client = _connect(runtime.path_for("alpha"))
    try:
        client.sendall(secret)
        client.shutdown(socket.SHUT_WR)
        observation = runtime.serve_once("alpha")
    finally:
        client.close()
    rendered = repr(observation) + repr(observation.as_event())
    assert b"correct-horse" not in rendered.encode()
    assert "password" not in rendered
    assert observation.bytes_received == len(secret)


def test_a_peer_that_sends_too_much_is_truncated_rather_than_read_forever(runtime):
    """A decoy is bait, not an ingestion path."""

    runtime.start()
    client = _connect(runtime.path_for("alpha"))
    try:
        client.sendall(b"x" * (MAX_READ_BYTES * 2))
        observation = runtime.serve_once("alpha")
    finally:
        client.close()
    assert observation.bytes_received == MAX_READ_BYTES
    assert observation.truncated is True


def test_serving_a_decoy_that_is_not_listening_returns_nothing(runtime):
    assert runtime.serve_once("alpha") is None


def test_every_event_the_runtime_records_names_the_generation(tmp_path):
    recorded = []
    made = LoopbackRuntime(
        tmp_path / "decoys",
        catalogue=_catalogue("alpha"),
        generation_digest=GENERATION,
        clock=_clock(),
        recorder=recorded.append,
    )
    made.start()
    client = _connect(made.path_for("alpha"))
    try:
        client.sendall(b"hello")
        client.shutdown(socket.SHUT_WR)
        made.serve_once("alpha")
    finally:
        client.close()
        made.stop()
    assert recorded
    for event in recorded:
        assert event["generation_digest"] == GENERATION
        assert event["decoy_name"] == "alpha"


# -- a crash stops one decoy and nothing else ------------------------------


def test_a_responder_that_fails_quarantines_that_decoy_alone(runtime, monkeypatch):
    """The exception does not leave the module, and `bravo` keeps listening."""

    runtime.start()
    client = _connect(runtime.path_for("alpha"))

    def explode(*args, **kwargs):
        raise RuntimeError("the responder fell over")

    monkeypatch.setattr(socket.socket, "sendall", explode)
    try:
        assert runtime.serve_once("alpha") is None
    finally:
        client.close()
    monkeypatch.undo()
    assert runtime.state("alpha") is ResponderState.QUARANTINED
    assert runtime.state("bravo") is ResponderState.LISTENING
    assert runtime.listening() == ("bravo",)


def test_a_quarantined_decoy_is_stopped_unlinked_and_explained(runtime):
    runtime.start()
    runtime.quarantine("alpha", "the responder fell over")
    assert runtime.state("alpha") is ResponderState.QUARANTINED
    assert not runtime.path_for("alpha").exists()
    assert "stopped and isolated" in runtime.reason("alpha")
    assert "deterministic path is untouched" in runtime.reason("alpha")


def test_a_quarantine_is_recorded_and_says_the_deterministic_path_is_unaffected(tmp_path):
    recorded = []
    made = LoopbackRuntime(
        tmp_path / "decoys",
        catalogue=_catalogue("alpha"),
        generation_digest=GENERATION,
        clock=_clock(),
        recorder=recorded.append,
    )
    made.start()
    made.quarantine("alpha", "fell over")
    made.stop()
    event = next(e for e in recorded if e["event_type"].endswith("quarantined"))
    assert event["reason"] == "fell over"
    assert event["deterministic_path_affected"] is False


def test_restarting_does_not_revive_a_quarantined_decoy(runtime):
    """It was stopped because it is not trusted; a restart is not a pardon."""

    runtime.start()
    runtime.quarantine("alpha", "fell over")
    assert runtime.start() == ("bravo",)
    assert runtime.state("alpha") is ResponderState.QUARANTINED


def test_a_decoy_failing_never_raises_for_the_node(runtime):
    """CORE and Edge do not know this module exists, which is the point.

    The strongest form of "a decoy failure does not stop the node" is that
    nothing the node depends on is in this call path at all. What is checked
    here is the weaker, closer thing: the failure does not propagate.
    """

    runtime.start()
    runtime.quarantine("alpha", "fell over")
    assert runtime.serve_once("alpha") is None
    assert runtime.listening() == ("bravo",)
    assert runtime.as_event()["externally_reachable"] is False


# -- what is never granted -------------------------------------------------


def test_redirect_is_never_eligible(runtime):
    assert runtime.redirect_eligible is False
    assert runtime.as_event()["redirect_eligible"] is False
    runtime.start()
    runtime.quarantine("alpha", "fell over")
    assert runtime.redirect_eligible is False


def test_the_runtime_reports_that_nothing_outside_this_host_can_reach_it(runtime):
    runtime.start()
    event = runtime.as_event()
    assert event["namespace"] == "unix-socket"
    assert event["externally_reachable"] is False
    assert "this host alone" in runtime.reason("alpha")


def test_the_word_is_not_available_and_not_control_plane_only():
    from azazel_nexus.functional_readiness import CONTROL_PLANE_ONLY, readiness_for

    assert LOOPBACK_ONLY not in (CONTROL_PLANE_ONLY, "available")
    readiness = readiness_for("deception_lite")
    assert readiness.value == LOOPBACK_ONLY
    assert readiness.functional is False


# -- static guards ---------------------------------------------------------


def test_the_module_names_no_address_family_that_leaves_this_host():
    """Asserted here too, close to the code, and not only distribution-wide."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    families = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    }
    assert "AF_UNIX" in families, "a vacuous scan: no address family is named at all"
    for leaves in ("AF_INET", "AF_INET6", "AF_PACKET", "create_connection"):
        assert leaves not in families


def test_the_module_starts_no_process_and_accepts_no_command():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for spawning in ("subprocess", "multiprocessing", "ctypes", "pty", "shutil"):
        assert spawning not in imported
    assert "socket" in imported, "a vacuous scan: the module imports nothing at all"


def test_no_input_path_carries_a_port_an_address_an_image_or_a_command():
    """The absence that makes 'it only binds loopback' unnecessary to promise."""

    source = MODULE.read_text(encoding="utf-8")
    body = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    # Docstrings explain why these are absent, so the search is for a
    # parameter or an attribute, not for the words.
    for forbidden in ("self.port", "self.listen_address", "self.image", "self.command", "entry.port"):
        assert forbidden not in body, f"{forbidden} is read somewhere in the runtime"
    assert "self.catalogue" in body, "a vacuous scan: no attribute is read at all"
