"""SO-06 `enforcement_lease_records`: an enforcing Edge Core in a harness netns.

Azazel-Edge#412 settled where enforcement lives: Edge's Rust core decides and
applies (`maybe_enforce`). The lease it holds for each disruptive action is the
release task in its release ledger (`release.rs`): written `prepared` before
the first command runs, `active` once the commands succeeded, and released
when `due_epoch` passes.

The shipped Edge unit is observe-only and Nexus refuses anything else; neither
changes here. Only this harness, only for the Edge process it starts, lays an
enforcing posture over the shipped unit's environment (`ENFORCE_POSTURE`), and
only inside isolation it creates and removes itself (`Netns`):

- a fresh network namespace, so no rule ever reaches the host's stack;
- a dummy interface there, standing in for the shipped `defense_iface`;
- an empty `inet azazel_edge` table there, which Edge inserts its rules into;
- a temporary state directory holding `eve.json`, the release ledger and the
  forward socket (the `so06_edge` run, unchanged).

That needs root and `CAP_NET_ADMIN`, as the root E2E job does; where they are
missing the run is refused, never replaced by a stand-in.

The lease run's observations are not evidence and do not reach the intake:
`refused_by_intake` checks that the production parser still rejects every one
of them with `EDGE_NOT_OBSERVE_ONLY`. What the path records is the ledger.

What Edge does with the lease is recorded, not required (`lease_states`).
On nftables 1.1 (Debian 13) the apply of an isolate or redirect lease fails:
Edge passes the owner token to `nft` as an unquoted `comment` argument, which
nft does not parse (`unexpected colon`), so Edge cancels the lease
(`cancelled`, `provider_apply_failed`) and nothing is installed. That is Edge's
outcome on this host, the same in every run; `lease_expected` checks that the
ledger, Edge's report and the netns agree on it, and an `active` lease is held
to its rule being in the netns.

The clock is the `so06_edge` pin. A pinned clock never lets a release fall due,
and nothing here needs it to: every run lasts seconds and the lease is
300 s, so on the real clock no release falls due inside a run either.
`lease_ignores_clock` checks that on a real binary: pinned and wall-clock
ledgers agree on everything but the four epoch fields, every task still
`active`.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from tools import so06_edge

#: Laid over the shipped unit's environment for the lease run only. The
#: interface is the netns's dummy; full-auto is Edge's own level for "apply
#: what policy permits" and needs no high-impact approval flag.
LEASE_IFACE = "azso06l0"
ENFORCE_POSTURE = {
    "AZAZEL_DEFENSE_ENFORCE": "true",
    "AZAZEL_DEFENSE_DRY_RUN": "false",
    "AZAZEL_DEFENSE_ENFORCE_LEVEL": "full-auto",
    "AZAZEL_DEFENSE_IFACE": LEASE_IFACE,
    # Edge runs `nft`/`tc` by name; the unit's search path has no sbin.
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
#: The table Edge inserts into. Created empty in the netns, never on a host.
NFT_TABLE = """\
table inet azazel_edge {
  chain input { type filter hook input priority 0; policy accept; }
  chain prerouting { type nat hook prerouting priority -100; policy accept; }
}
"""
LEDGER = "release-ledger.json"
#: The ledger fields that read the wall clock.
LEASE_CLOCK_FIELDS = ("due_epoch", "next_attempt_epoch", "created_epoch", "updated_epoch")
#: Every field of a release task this harness knows: the clock fields above,
#: which the pin fixes, and fields no clock reaches. A task with any other
#: field is refused, not compared: a later Edge adds a `CLOCK_BOOTTIME`
#: deadline (`due_boottime_ns`, Azazel-Edge#439), which the pin does not fix
#: and which would differ in every run. Whether to pin that clock too or to
#: exclude the field is the owner's decision; neither is made here.
LEDGER_FIELDS = frozenset(LEASE_CLOCK_FIELDS) | {
    "task_id", "trace_id", "action", "resource_key", "owner_token", "iface", "tc_handle",
    "source_ip", "destination_port", "redirect_port", "expected_rate_bps",
    "expected_burst_bytes", "expected_latency_us", "status", "attempts", "last_error",
}


class Netns:
    """A network namespace this harness creates, configures and deletes."""

    def __init__(self):
        self.ip = shutil.which("ip")
        self.nft = shutil.which("nft")
        self.name = f"azso06l-{secrets.token_hex(4)}"
        self.created = False

    def _run(self, argv: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=30)

    def __enter__(self) -> Netns:
        if os.geteuid() != 0 or self.ip is None or self.nft is None:
            raise so06_edge.EdgeUnavailable(
                "the lease run needs root, `ip` and `nft` to build its own network namespace")
        if self._run([self.ip, "netns", "add", self.name]).returncode != 0:
            raise so06_edge.EdgeUnavailable("cannot create a network namespace (CAP_NET_ADMIN)")
        self.created = True
        try:
            for argv in (
                [self.ip, "-n", self.name, "link", "set", "lo", "up"],
                [self.ip, "-n", self.name, "link", "add", LEASE_IFACE, "type", "dummy"],
                [self.ip, "-n", self.name, "link", "set", LEASE_IFACE, "up"],
            ):
                out = self._run(argv)
                if out.returncode != 0:
                    raise so06_edge.EdgeUnavailable(
                        f"netns setup failed: {out.stderr.strip()[:200]}")
            out = self._run(self.wrap([self.nft, "-f", "-"]), stdin=NFT_TABLE)
            if out.returncode != 0:
                raise so06_edge.EdgeUnavailable(f"nft table setup failed: {out.stderr.strip()[:200]}")
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def wrap(self, argv: list[str]) -> list[str]:
        return [self.ip, "netns", "exec", self.name, *argv]

    def owned_tokens(self) -> list[str]:
        """The rule comments in the netns's table: the state Edge says it owns."""
        out = self._run(self.wrap([self.nft, "-j", "list", "table", "inet", "azazel_edge"]))
        if out.returncode != 0:
            raise so06_edge.EdgeUnavailable(f"nft readback failed: {out.stderr.strip()[:200]}")
        return sorted(item["rule"]["comment"] for item in json.loads(out.stdout)["nftables"]
                      if "rule" in item and "comment" in item["rule"])

    def __exit__(self, *exc) -> None:
        if self.created:
            self._run([self.ip, "netns", "del", self.name])
            self.created = False


def read_ledger(directory: Path) -> list[dict]:
    """The release tasks Edge wrote, in ledger order. No ledger is no lease."""
    path = directory / LEDGER
    if not path.is_file():
        return []
    return json.loads(path.read_bytes())["tasks"]


def require_pinned_ledger(tasks: list[dict]) -> None:
    """Refuse a ledger whose epochs are not the pinned instant (and its TTL).

    And one with a field the pin is not known to fix (`LEDGER_FIELDS`).
    """
    now, due = so06_edge.PINNED_EPOCH, so06_edge.PINNED_EPOCH + so06_edge.EDGE_ACTION_TTL_S
    for task in tasks:
        unknown = sorted(set(task) - LEDGER_FIELDS)
        if unknown:
            raise so06_edge.EdgeUnavailable(
                f"the lease carries {unknown}, which the pinned clock does not fix; "
                "it is refused rather than compared")
        if (task["created_epoch"] != now or task["updated_epoch"] != now
                or task["due_epoch"] != due or task["next_attempt_epoch"] != due):
            raise so06_edge.EdgeUnavailable(
                "Edge's clock was not pinned in the lease run: the ledger carries another instant")


def run_lease(binary: Path, events: list[dict], *, expected: int, shim: Path | None,
              isolation=None) -> dict:
    """One enforcing Edge run on fresh state, inside `isolation` (a `Netns`).

    Returns the observations, the ledger's tasks and the owned-state readback.
    `shim=None` is the wall clock, for the mutation and clock checks only.
    """
    with (isolation or Netns()) as netns:
        def collect(directory: Path) -> tuple[list[dict], list[str]]:
            return read_ledger(directory), netns.owned_tokens()

        lines, (tasks, owned) = so06_edge.run_edge_in(
            binary, events, expected=expected, shim=shim,
            environment=ENFORCE_POSTURE, wrap=netns.wrap, collect=collect)
    if shim is not None:
        require_pinned_ledger(tasks)
    return {"observations": lines, "tasks": tasks, "owned": owned}


def refused_by_intake(lines: list[bytes]) -> bool:
    """Nexus's production intake refuses every observation of an enforcing Edge."""
    from azazel_nexus.edge_intake import EdgeEventRefused, parse_edge_event

    for line in lines:
        try:
            parse_edge_event(line)
        except EdgeEventRefused as refused:
            if "EDGE_NOT_OBSERVE_ONLY" not in str(refused):
                return False
            continue
        return False
    return bool(lines)


def lease_expected(run: dict) -> bool:
    """The ledger, Edge's report and the netns agree; the intake refuses.

    Every lease an observation names is in the ledger in the state the
    observation reports, and nothing else is; the owner tokens on rules in the
    netns are exactly those of the `active` leases. Whether the apply
    succeeded is recorded (`lease_states`), not required: that is Edge's
    outcome, and a lease Edge cancelled is still the lease it wrote.
    """
    named = {}
    for line in run["observations"]:
        enforcement = json.loads(line)["enforcement"]
        metadata = enforcement["metadata"]
        if metadata["release_task_id"] is None:
            continue
        if enforcement["mode"] != "enforced":
            return False
        named[metadata["release_task_id"]] = metadata["release_ledger_state"]
    tasks = run["tasks"]
    return (bool(named)
            and named == {t["task_id"]: t["status"] for t in tasks}
            and len(tasks) == len(named)
            and sorted(t["owner_token"] for t in tasks if t["status"] == "active")
            == run["owned"]
            and refused_by_intake(run["observations"]))


def lease_states(tasks: list[dict]) -> list[list[str]]:
    """What became of each lease: `[action, status, last_error]`, ledger order."""
    return [[t["action"], t["status"], t["last_error"]] for t in tasks]


def without_lease_clock(tasks: list[dict]) -> list[dict]:
    return [{k: v for k, v in task.items() if k not in LEASE_CLOCK_FIELDS} for task in tasks]


def lease_ignores_clock(pinned: list[dict], wall: list[dict]) -> bool:
    """The pinned and the wall-clock ledgers differ only in their epochs.

    In particular no release was attempted in either (`attempts` 0, nothing
    `released`): no lease fell due inside a run on the real clock, so the pin
    hides no release.
    """
    return (bool(pinned) and without_lease_clock(pinned) == without_lease_clock(wall)
            and all(t["attempts"] == 0 and t["status"] != "released" for t in pinned + wall))


def main(argv: list[str] | None = None) -> int:
    """Check one Edge binary: pinned lease runs match, wall-clock ones do not."""
    from tools.e2e_loop import eve_events

    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("--edge-core", type=Path, required=True)
    args = parser.parse_args(argv)
    events = eve_events()
    alerts = sum(e["event_type"] == "alert" for e in events)
    with tempfile.TemporaryDirectory(prefix="azso06l-") as temporary:
        shim = so06_edge.build_shim(Path(temporary))
        pinned = [run_lease(args.edge_core, events, expected=alerts, shim=shim) for _ in range(2)]
        wall = [run_lease(args.edge_core, events, expected=alerts, shim=None) for _ in range(2)]
    report = {
        "pinned_identical": pinned[0]["tasks"] == pinned[1]["tasks"],
        "wall_identical": wall[0]["tasks"] == wall[1]["tasks"],
        "lease_ignores_clock": lease_ignores_clock(pinned[0]["tasks"], wall[0]["tasks"]),
        "lease_expected": all(lease_expected(run) for run in pinned + wall),
        "leases": len(pinned[0]["tasks"]),
        "lease_states": lease_states(pinned[0]["tasks"]),
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if (report["pinned_identical"] and not report["wall_identical"]
                 and report["lease_ignores_clock"] and report["lease_expected"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
