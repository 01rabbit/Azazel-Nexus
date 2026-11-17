"""UNIT 3: the shipped context observation unit with its shipped budget (ADR-0010).

Runs only in the isolated root container runner. The caller side is the shipped
`azazel_nexus_runtime.mio_contextobsd.main()` started as a real process under
the real azmioctx uid/gid with only the broker's client group, behind the
shipped entryd, asked by the explainer's `mio.context.observe` (350 ms end to
end; the broker wait is capped at the shipped 250 ms). No budget change, no
client injection, no authentication/transport monkeypatch. The Knowledge side
is the shipped contextd started from the commissioning bundle, plus a
synthetic peer.

Until ADR-0010 this file ran the shipped `mio_locald.main()` (as azmio) as the
broker's client; locald no longer asks the broker anything.

Not real here: systemd, AZAZEL_ROOT relocation, non-root-/ paths.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from test_knowledge_context_official_entry import (  # noqa: F401  (fixtures + helpers)
    Official, pki_dir, official, _degraded)
from test_knowledge_context_process_interop import (  # noqa: F401
    ROOT, _assert_technique_received, _observe_via_entry, _start_entryd, _wait_socket, pytestmark)

SHIPPED_MAIN = ("from azazel_nexus_runtime.mio_contextobsd import main; "
                "raise SystemExit(main())")


def start_shipped_chain(o: Official) -> None:
    """Shipped contextobsd main() (setpriv, real uid/gid) + shipped entryd."""
    o.contextobsd = subprocess.Popen(
        ["setpriv", f"--reuid={o.ctx.pw_uid}", f"--regid={o.ctx.pw_gid}",
         f"--groups={o.ctx_gid}", "--no-new-privs", "--inh-caps=-all",
         "sh", "-c", f"umask 0027; exec {sys.executable} -B -c '{SHIPPED_MAIN}'"],
        cwd=ROOT, env=o.env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _wait_socket(o.service_root / "var/lib/azazel/run/mio-contextobs/mio-contextobs.sock",
                 o.contextobsd)
    o.entryd = _start_entryd(o.service_root, o.env)


def _assert_shipped_identity(o: Official) -> None:
    pid = o.contextobsd.pid
    status = Path(f"/proc/{pid}/status").read_text()
    assert f"Uid:\t{o.ctx.pw_uid}\t{o.ctx.pw_uid}" in status, status
    assert f"Gid:\t{o.ctx.pw_gid}\t{o.ctx.pw_gid}" in status, status
    groups = next(line for line in status.splitlines() if line.startswith("Groups:"))
    assert groups.split()[1:] == [str(o.ctx_gid)], groups   # the client group alone
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    assert b"mio_contextobsd" in cmdline and b"mio_locald" not in cmdline, cmdline


def test_u3_shipped_main_observation_query_is_received(official: Official):
    official.start_peer("valid")
    official.make_bundle()
    official.start_daemon()
    start_shipped_chain(official)
    _assert_shipped_identity(official)
    observed = _observe_via_entry(official.service_root)
    _assert_technique_received(observed)
    counters = official.peer.counters()
    assert counters["requests"] == 1 and counters["handshakes"] >= 1, counters
    assert official.events("knowledge.context.completed")[-1]["outcome"] == "verified_advisory"
    print("U3-OBS a peer", counters, "hop", observed["hop_timing"])


def test_u3_shipped_budget_unavailable_then_recovers(official: Official):
    DELAY = 3.0                                    # >> the shipped 250 ms broker wait
    official.start_peer("delay", delay_s=DELAY)
    official.make_bundle()
    official.start_daemon()
    start_shipped_chain(official)
    _assert_shipped_identity(official)
    began = time.monotonic()
    entry = _observe_via_entry(official.service_root)
    elapsed = time.monotonic() - began
    late_already_sent = official.peer.sent_after_delay
    print("U3-OBS b elapsed_s", round(elapsed, 3), "late_sent_at_reply", late_already_sent)
    # context unavailable, late answer not adopted, the core still answered
    _degraded(entry)
    assert late_already_sent is False, "reply waited for the delayed peer (budget not applied)"
    assert official.peer.counters()["requests"] >= 1       # the request really reached the peer
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and not official.peer.sent_after_delay:
        time.sleep(0.1)
    assert official.peer.sent_after_delay, "peer never produced the late answer (not exercised)"
    # the delayed valid answer must not have been adopted by anything
    assert not any(e.get("outcome") == "verified_advisory"
                   for e in official.events("knowledge.context.completed")), official.ledger()
    # recovery by an ordinary request
    official.peer.mode = "valid"
    _assert_technique_received(_observe_via_entry(official.service_root))
