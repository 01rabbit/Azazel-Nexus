"""UNIT 3: the shipped `mio_locald.main()` with its shipped 250 ms Knowledge budget.

Runs only in the isolated root container runner. Unlike the UNIT 1 chain, the
MIO side here is the shipped `azazel_nexus_runtime.mio_locald.main()` started as
a real process under the real azmio uid/gid, NOT `_mio_locald_context_process.py`
(whose KNOWLEDGE_MAX_S = 8.0 override is not used). No budget change, no client
injection, no authentication/transport monkeypatch. The Knowledge side is the
shipped contextd started from the commissioning bundle, plus a synthetic peer.

Not real here: systemd, admission (disabled in product: LOCAL_MODEL_ADMISSION_ENABLED
is False, so no model/embedding is used), AZAZEL_ROOT relocation, non-root-/ paths.
The shipped locald (packaging/systemd/azazel-mio-locald.service:21) also carries the
supplementary groups azknowledge-read and azmission-read; this test does not grant them.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from test_knowledge_context_official_entry import (  # noqa: F401  (fixtures + helpers)
    Official, pki_dir, official, _degraded)
from test_knowledge_context_process_interop import (  # noqa: F401
    ROOT, _normal_entry_advisory, _ready, pytestmark)
from test_knowledge_context_linux_acceptance import _assert_advisory_only, _wait_socket

SHIPPED_MAIN = ("from azazel_nexus_runtime.mio_locald import main; "
                "raise SystemExit(main())")


def start_shipped_chain(o: Official) -> None:
    """Shipped locald main() (setpriv, real uid/gid) + shipped entryd."""
    mio_state = o.service_root / "var/lib/azazel/mio"
    mio_state.mkdir()
    mio_state.chmod(0o700)
    os.chown(mio_state, o.mio.pw_uid, o.mio.pw_gid)
    o.locald = subprocess.Popen(
        ["setpriv", f"--reuid={o.mio.pw_uid}", f"--regid={o.mio.pw_gid}",
         f"--groups={o.ctx_gid}", "--no-new-privs", "--inh-caps=-all",
         "sh", "-c", f"umask 0022; exec {sys.executable} -B -c '{SHIPPED_MAIN}'"],
        cwd=ROOT, env=o.env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _wait_socket(o.service_root / "var/lib/azazel/run/mio/mio.sock", o.locald)
    o.entryd = subprocess.Popen(
        [sys.executable, "-B", "-c",
         "from azazel_nexus_runtime.mio_entryd import main; raise SystemExit(main())"],
        cwd=ROOT, env=o.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
        preexec_fn=o.credentials(o.entry, (o.operator_gid,)))
    _wait_socket(o.service_root / "var/lib/azazel/run/mio-advise/mio-advise.sock", o.entryd)


def _assert_shipped_identity(o: Official) -> None:
    pid = o.locald.pid
    status = Path(f"/proc/{pid}/status").read_text()
    assert f"Uid:\t{o.mio.pw_uid}\t{o.mio.pw_uid}" in status, status
    assert f"Gid:\t{o.mio.pw_gid}\t{o.mio.pw_gid}" in status, status
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    assert b"mio_locald" in cmdline and b"_mio_locald_context_process" not in cmdline, cmdline


def test_u3_shipped_main_normal_entry_received_advisory_only(official: Official):
    official.start_peer("valid")
    official.make_bundle()
    official.start_daemon()
    start_shipped_chain(official)
    _assert_shipped_identity(official)
    _assert_advisory_only(_normal_entry_advisory(official.service_root))
    counters = official.peer.counters()
    assert counters["requests"] == 1 and counters["handshakes"] >= 1, counters
    assert official.events("knowledge.context.completed")[-1]["outcome"] == "verified_advisory"
    print("U3-OBS a peer", counters)


def test_u3_shipped_250ms_budget_unavailable_then_recovers(official: Official):
    DELAY = 3.0                                    # >> 250 ms shipped budget
    official.start_peer("delay", delay_s=DELAY)
    official.make_bundle()
    official.start_daemon()
    start_shipped_chain(official)
    _assert_shipped_identity(official)
    began = time.monotonic()
    entry = _normal_entry_advisory(official.service_root)
    elapsed = time.monotonic() - began
    late_already_sent = official.peer.sent_after_delay
    print("U3-OBS b elapsed_s", round(elapsed, 3), "late_sent_at_reply", late_already_sent)
    # context unavailable, late answer not adopted, local evaluation still answered
    _degraded(entry)
    assert entry["state"] and entry["route"], entry
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
    _assert_advisory_only(_normal_entry_advisory(official.service_root))
