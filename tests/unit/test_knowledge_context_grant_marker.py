"""The broker re-reads its grant marker when it accepts and before it adopts.

Stop contract (docs/knowledge-context-consumer.md): once the controller
removes the broker's marker, the broker accepts nothing new and adopts no
peer answer that arrives afterwards, even before the manager has stopped it.
These tests go through `KnowledgeContextBroker.handle` (the transport) with
the real marker inspector over a tmp root.

Negative check: a broker that does not re-read the marker before adoption
(`_adopts_without_recheck`) returns the answer, and the scenario assertions
fail for it.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import pytest

from azazel_nexus_runtime import activation_markers, hardening
from azazel_nexus_runtime.activation_markers import (
    MarkerIdentity, inspect_grant_marker, remove_contextd_marker,
)
from azazel_nexus_runtime.knowledge_contextd import KnowledgeContextBroker

from test_knowledge_contextd import _policy, _request

CTX = "azazel-knowledge-contextd.service"
REPO = Path(__file__).resolve().parents[2]
ANSWER = {"authority": "advisory_only"}


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    parent = tmp_path / "run" / "azazel-activation"
    parent.mkdir(parents=True)
    parent.chmod(0o755)
    return tmp_path


def write_marker(root: Path, *, mode=0o644) -> Path:
    directory = root / "run/azazel-activation/granted"
    directory.mkdir(exist_ok=True)
    directory.chmod(0o755)
    marker = directory / CTX
    marker.write_text("")
    marker.chmod(mode)
    return marker


class Peer:
    """The Knowledge peer client; `during` runs while the peer is answering."""

    def __init__(self, during=None):
        self.during = during
        self.calls = 0

    def request_context(self, **kwargs):
        self.calls += 1
        if self.during is not None:
            self.during()
        return dict(ANSWER)


def broker_for(root, peer, events, **kw):
    return KnowledgeContextBroker(
        client=peer, policy=_policy(), mission="lab", alias_key=b"x" * 32,
        enabled=True, audit=events.append,
        grant_marker=lambda: inspect_grant_marker(CTX, root), **kw)


def completed(events):
    return [e for e in events if e["event_type"] == "knowledge.context.completed"]


# -- the inspector --------------------------------------------------------------------


def test_a_marker_the_pass_wrote_has_an_identity(root):
    marker = write_marker(root)
    identity = inspect_grant_marker(CTX, root)
    info = marker.stat()
    assert identity == MarkerIdentity(info.st_dev, info.st_ino, info.st_ctime_ns)


@pytest.mark.parametrize("damage", [
    "absent", "directory-missing", "mode", "symlink", "second-link", "directory-mode",
    "not-a-file", "owner",
])
def test_anything_but_the_exact_marker_is_no_grant(root, monkeypatch, damage):
    if damage == "directory-missing":
        assert inspect_grant_marker(CTX, root) is None
        return
    marker = write_marker(root)
    if damage == "absent":
        marker.unlink()
    elif damage == "mode":
        marker.chmod(0o664)
    elif damage == "symlink":
        marker.unlink()
        (root / "elsewhere").write_text("")
        (root / "elsewhere").chmod(0o644)
        marker.symlink_to(root / "elsewhere")
    elif damage == "second-link":
        os.link(marker, root / "second")
    elif damage == "directory-mode":
        marker.parent.chmod(0o775)
    elif damage == "not-a-file":
        marker.unlink()
        marker.mkdir()
    else:
        monkeypatch.setattr(activation_markers, "_OWNER", os.getuid() + 1)
    assert inspect_grant_marker(CTX, root) is None


def test_a_symlinked_directory_on_the_way_is_no_grant(root):
    write_marker(root)
    (root / "run/azazel-activation/granted").rename(root / "real")
    (root / "run/azazel-activation/granted").symlink_to(root / "real")
    assert inspect_grant_marker(CTX, root) is None


# The kernel stamps ctime from a coarse clock (a few milliseconds), and a
# filesystem may hand the freed inode number to the next file. So a marker
# removed and written again inside one clock tick can keep its (dev, ino,
# ctime). A real re-grant is a whole later pass (reset, decisions, a reload,
# then the write), far longer than a tick; these tests wait past one, and the
# documentation states the limit.
TICK = 0.05


def test_the_identity_changes_when_the_marker_is_written_again(root):
    marker = write_marker(root)
    first = inspect_grant_marker(CTX, root)
    marker.unlink()
    time.sleep(TICK)
    write_marker(root)
    second = inspect_grant_marker(CTX, root)
    assert first is not None and second is not None and first != second


# -- admission ---------------------------------------------------------------------------


def test_with_the_marker_in_place_the_answer_is_adopted(root):
    write_marker(root)
    events, peer = [], Peer()
    broker = broker_for(root, peer, events)
    assert broker.handle(_request()) == {"response": ANSWER}
    assert [e["outcome"] for e in completed(events)] == ["verified_advisory"]
    assert peer.calls == 1


def test_without_the_marker_nothing_is_accepted_and_the_peer_is_not_asked(root):
    events, peer = [], Peer()
    broker = broker_for(root, peer, events)
    assert broker.handle(_request()) == {"refusal": "unavailable"}
    assert peer.calls == 0
    [done] = completed(events)
    assert done["outcome"] == "unavailable" and done["reason_code"] == "withdrawn"
    assert not any(e["event_type"] == "knowledge.context.requested" for e in events)


def test_a_marker_removed_by_the_controller_closes_the_next_request(root):
    write_marker(root)
    events, peer = [], Peer()
    broker = broker_for(root, peer, events)
    assert broker.handle(_request()) == {"response": ANSWER}
    remove_contextd_marker(root)
    assert broker.handle(_request()) == {"refusal": "unavailable"}
    assert peer.calls == 1


# -- adoption ----------------------------------------------------------------------------


def _answers_with_marker_removed_meanwhile(root):
    marker = write_marker(root)
    events = []
    peer = Peer(during=marker.unlink)  # the controller withdraws while the peer answers
    result = broker_for(root, peer, events).handle(_request())
    return result, events, peer


def _blocked(result, events, peer) -> bool:
    """What a withdrawal during the exchange must produce."""
    done = completed(events)
    return (result == {"refusal": "unavailable"}
            and "response" not in result
            and peer.calls == 1
            and [e["outcome"] for e in done] == ["unavailable"]
            and done[0].get("reason_code") == "withdrawn"
            and not any(e.get("outcome") == "verified_advisory" for e in events))


def test_a_marker_removed_while_the_peer_answers_adopts_nothing(root):
    result, events, peer = _answers_with_marker_removed_meanwhile(root)
    assert _blocked(result, events, peer)
    assert "response_bytes" not in str(events)


def test_a_marker_removed_and_written_again_is_another_grant(root):
    """ABA: a later pass wrote a new marker; the answer was asked for under the old one."""
    marker = write_marker(root)

    def regrant():
        marker.unlink()
        time.sleep(TICK)  # a later pass is much slower than the clock tick
        write_marker(root)

    events, peer = [], Peer(during=regrant)
    result = broker_for(root, peer, events).handle(_request())
    assert inspect_grant_marker(CTX, root) is not None  # a marker exists again
    assert _blocked(result, events, peer)


def test_a_marker_replaced_by_a_loose_file_adopts_nothing(root):
    marker = write_marker(root)
    events, peer = [], Peer(during=lambda: marker.chmod(0o666))
    result = broker_for(root, peer, events).handle(_request())
    assert _blocked(result, events, peer)


def test_an_answer_after_a_marker_removal_does_not_reach_the_audit_as_verified(root):
    result, events, _peer = _answers_with_marker_removed_meanwhile(root)
    assert result == {"refusal": "unavailable"}
    assert [e["event_type"] for e in events] == [
        "knowledge.context.requested", "knowledge.context.completed"]


def test_the_recheck_is_the_last_step_before_the_record(root):
    """The marker is read after the peer, the size checks and the encoding."""
    marker = write_marker(root)
    order = []
    events = []

    def audit(event):
        order.append(event["event_type"] + ":" + str(event.get("outcome")))
        events.append(event)

    peer = Peer()
    reads = []

    def grant_marker():
        reads.append(len(order))
        return inspect_grant_marker(CTX, root)

    broker = KnowledgeContextBroker(
        client=peer, policy=_policy(), mission="lab", alias_key=b"x" * 32,
        enabled=True, audit=audit, grant_marker=grant_marker)
    assert broker.handle(_request()) == {"response": ANSWER}
    # read once before the `requested` record, once after it and before `completed`
    assert reads == [0, 1]
    assert marker.exists()


# -- negative checks: the source with a check removed fails the scenarios ---------------------


def _mutant_broker_class(old: str, new: str):
    """`KnowledgeContextBroker` from the module source with one line changed."""
    import types
    import azazel_nexus_runtime.knowledge_contextd as module
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert source.count(old) == 1, old
    mutant = types.ModuleType("azazel_nexus_runtime._mutant_contextd")
    mutant.__package__ = "azazel_nexus_runtime"
    exec(compile(source.replace(old, new), "<mutant>", "exec"), mutant.__dict__)
    return mutant.KnowledgeContextBroker


def test_removing_the_recheck_before_adoption_is_caught(root):
    mutant = _mutant_broker_class("if self._grant_marker() != admitted:", "if False:")
    marker = write_marker(root)
    events, peer = [], Peer(during=marker.unlink)
    broker = mutant(client=peer, policy=_policy(), mission="lab", alias_key=b"x" * 32,
                    enabled=True, audit=events.append,
                    grant_marker=lambda: inspect_grant_marker(CTX, root))
    result = broker.handle(_request())
    assert result == {"response": ANSWER}  # it adopted after the withdrawal ...
    assert not _blocked(result, events, peer)  # ... which the scenario refuses
    # and the unmodified class passes the same scenario
    assert _blocked(*_answers_with_marker_removed_meanwhile_fresh(root))


def _answers_with_marker_removed_meanwhile_fresh(root):
    return _answers_with_marker_removed_meanwhile(root)


def test_removing_the_admission_check_is_caught(root):
    mutant = _mutant_broker_class("if admitted is None:", "if False:")
    events, peer = [], Peer()
    broker = mutant(client=peer, policy=_policy(), mission="lab", alias_key=b"x" * 32,
                    enabled=True, audit=events.append,
                    grant_marker=lambda: inspect_grant_marker(CTX, root))
    # no marker at all: the mutant still asks the peer (admitted is None, then
    # the recheck sees None == None), which the real broker never does
    result = broker.handle(_request())
    assert peer.calls == 1
    real = broker_for(root, Peer(), [])
    assert real.handle(_request()) == {"refusal": "unavailable"}


# -- the unit's stop profile ---------------------------------------------------------------


def test_the_broker_unit_carries_the_stop_profile():
    text = (REPO / "packaging/systemd" / CTX).read_text(encoding="utf-8")
    assert text == dict(hardening.packaged_unit_files())[CTX]
    for line in ("KillMode=control-group", "TimeoutStopSec=10s", "KillSignal=SIGTERM",
                 "FinalKillSignal=SIGKILL", "SendSIGKILL=yes"):
        assert text.splitlines().count(line) == 1, line
    # the same stop settings the controller's own unit carries
    controller = (REPO / "packaging/systemd/azazel-activated.service").read_text()
    for line in ("KillMode=control-group", "TimeoutStopSec=10s", "KillSignal=SIGTERM",
                 "FinalKillSignal=SIGKILL", "SendSIGKILL=yes"):
        assert line in controller.splitlines()


def test_the_marker_condition_and_the_default_inspector_use_the_same_unit():
    import azazel_nexus_runtime.knowledge_contextd as module
    assert module._UNIT == CTX == activation_markers.CONTEXTD_MARKER_UNIT
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert re.search(r"def _production_grant_marker\(\):\n.*inspect_grant_marker\(_UNIT\)",
                     source, re.S)
