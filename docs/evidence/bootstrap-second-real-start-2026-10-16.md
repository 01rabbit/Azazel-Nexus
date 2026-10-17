# Bootstrap second real start of azazel-activated.service (build c822c9b) - run record

Date: 2026-10-16. Status: the real controller reached READY and heartbeat for the first time, and the real `azazel-auditd.service` was started and became active. Right after that the controller refused inside its loaded-unit inspection (`UnitOperationFailed: loaded bootstrap observation refused`), contained the pair and exited 1. No genesis. Contained.
Raw outputs (realstart-out2 tar: before listings, `run/events.log`, `run/timeline.log`, `run/cgroups.log`, PID 1 / unit / full journals, monitor state, journal window, diagnosis README) are retained in the operator's scratch area; this record cites them by name only.
Related: `docs/evidence/bootstrap-first-real-start-2026-10-16.md` (run 1, ee5cdd2), `docs/evidence/bootstrap-factory-switch-rereview-2026-10-16.md`, `docs/evidence/bootstrap-qualification-q4r4-ee5cdd2-2026-10-16.md`.

## 1. What this is, and what it is not

Reached for the first time on a real host (test VM):
- real READY (`READY=1`, controller `active/running`) within `TimeoutStartSec` 30 s;
- real watchdog heartbeats;
- real `StartUnit` of `azazel-auditd.service` and its activation (`active/running`, pid 5287, `/var/lib/azazel/run/audit/audit.sock` created).

Not reached: auditd peer proof / identity capture as accepted, genesis, commissiond start, steady both-helper loop, operator stop (controller-first).

- Approval is synthetic (test VM only). VM only; not a hardware result. Issue #93 remains open.
- The refusal is a product design gap found only by a real start (section 7), not a record error and not a race.

## 2. Setup (as observed)

| Item | Value |
|---|---|
| Target | test VM, Debian 13, systemd 257 |
| Product build | c822c9b (condition-state fix on top of ee5cdd2) |
| Boot | `41691eae-805f-4e63-b921-fa99043b0e52` |
| Loaded-units record | `sha256:305fc910...` (unchanged from run 1; digest as reported by the operator, not re-derivable from the tar) |
| Dependency re-measurement | identical, 0 differences; loaded-units digest unchanged |
| Installed-files | `sha256:dffc57e3...` (`/etc/azazel/bootstrap/installed-files.json`, matches `before/digests.txt`) |
| Approval payload | `sha256:317f5261...` (synthetic, owner-signed; matches `before/sums.txt`) |
| Preflight | 0 failures; fresh precondition (no prior journal) |
| Substitutions | none: real inspector, real sd_notify, real manager, real start bridge |

Preparation: the owner approved a second full records quarantine (18 files moved, nothing deleted, test VM only; test scaffolding, not precedent) and a reboot into the boot above. The boot-time controller run without a selection took the ordinary path with `granted=0` (`Result=protocol`), leaving no grant. `/data` tmpfs remounted (`size=512M`, `noexec,nosuid,nodev`). The owner placed the records and signed. Mask symlinks for all seven non-pair units point to `/dev/null` as before. The first start attempt was refused by the tool's own preflight because a transient systemd job was queued; nothing was consumed and the start was retried.

Tool fixes since run 1 (`realstart.sh`): fresh-precondition support and the Reload count pattern `Reload(ing)? requested`. The Reload count is now correct: 15 (monitor and PID 1 journal agree), so the Gate A stop condition 3 limit (15) was live and was not exceeded.

T0 = `systemctl start --no-block azazel-activated.service`, controller pid 3849.

## 3. Timeline (seconds from T0, monitor at 4 Hz)

| T+ | Event | Stage / verdict |
|---|---|---|
| 0.004 | T0 returned (rc 0); controller `activating/start`; helpers inactive, `masked` | |
| 0.009 | `/proc` evidence for controller pid 3849 | R1 literal |
| 0.36 | first PID 1 Reload (controller startup close) | |
| 1.26 | tree note: `/run/azazel` added (unit RuntimeDirectory) | not a stop condition |
| 5.5 | grant `pair_grant_intent`, `initial.json` / `checkpoint.json` present | S1 OK (expected 6..9) |
| 10.5 | journal `intent` | |
| 12.25 / 15.75 | auditd overlay file (2106 bytes) / commissiond overlay file (2299 bytes) | |
| 17.5 | journal `published` | S2 OK |
| 19.0 | Reload; both helpers `LoadState=loaded` from `/run/systemd/system.control` | S3 OK |
| 21.0 | grant `pair_grant_opened` | |
| 22.75 | controller `active/running` (READY=1) | S4 OK (within 30 s) |
| 29.5 | first heartbeat, gap 6.76 s | S5 OK |
| 31.25 | grant `auditd_start_intent` | |
| 34.5 / 36.26 / 38.26 / 40.26 | heartbeats 2-5, gaps 5.08 / 1.80 / 1.90 / 1.91 s (max gap 6.76 s, limit alert 28 s) | |
| 40.25 | `azazel-auditd.service` `active/running`, pid 5287; `/proc` evidence captured | S6 OK (first real helper start) |
| 40.5 | PID 1: auditd stopped (`inactive/dead`), Reload; journal `closing`, grant `closing`; overlay files emptied; helpers `masked` again | containment |
| 40.76 | tree note: `/var/lib/azazel/run/audit/audit.sock` added | helper-declared path |
| 41.0 - 44.0 | further Reloads (total 15 by T+44.0); journal `withdrawing` at 41.5; auditd overlay file unlinked at 43.0 | |
| 43.75 | journal `closed` | |
| 44.25 | controller `failed`, `Result=exit-code`, status 1; grant `closed` | |
| 44.26 | monitor: `FAIL: controller left active/activating unexpectedly` | |
| 44.76 | controller journal: refusal line | |
| 56.28 | monitor done: controller failed, helpers inactive, overlay empty, journal closed, grant closed | |

Journal text: `az-activated failed before completing a safe pass: UnitOperationFailed: loaded bootstrap observation refused` (the new allowlisted static message; run 1 logged only the class). The unit started at 19:11:24.406 and the first containment Reload followed at 19:11:24.470, i.e. the refusal came about 64 ms after the helper became active. Auditd ran about 240 ms before it was stopped (journal 24.644). The monitor sent no signal.

## 4. End state

- Overlay directory empty; journal `closed`, bound to this boot; grant for this boot `closed`.
- Controller `failed` (`Result=exit-code`, status 1), cgroup empty; helpers `inactive`, `LoadState=masked`, mask symlinks `-> /dev/null`.
- Audit ledger (`state/audit`): EMPTY. No genesis. The auditd process never touched the ledger.
- Reload count 15.
- A dbus_next `BrokenPipeError` ("Future exception was never retrieved") was printed after the refusal line. It is a teardown artifact (diagnosis README section 4): the in-flight start task is cancelled, the owned bus is disconnected, and a queued write hits the closed socket. Containment was complete before it was emitted and before exit 1. Cosmetic follow-up only.
- Manager `degraded` (only the failed controller). Controller not `reset-failed`.

## 5. B1 and R1 cgroup literals

| Unit | Source | `/proc/<pid>/cgroup` literal |
|---|---|---|
| azazel-activated.service | pid 3849, T+0.009 | `0::/system.slice/azazel-activated.service` |
| azazel-auditd.service | pid 5287, T+40.256 | `0::/system.slice/azazel-auditd.service` (B1 helper literal captured; first time) |
| azazel-commissiond.service | never started | not captured |

Further auditd observations from `run/cgroups.log`: uid/gid 996/985, `CapEff` and `CapBnd` all zero, `NoNewPrivs` 1, `Seccomp` 2 (filter), own mount namespace (`mnt:[4026532664]`, others shared with PID 1), cmdline `/opt/azazel-nexus/venv/bin/python -IS /usr/libexec/azazel/az-auditd`. These are raw observations; they are not an acceptance of the peer proof.

## 6. Tree changes outside the Gate A four

`/run/azazel` (controller RuntimeDirectory) and `/var/lib/azazel/run/audit/audit.sock` (created by the real auditd, left behind after stop) were recorded as tree notes by the monitor. Both are helper-declared paths, not stop conditions. The socket path is new relative to run 1 and should be added to the declared-path list in the next Gate A revision. No change in `/opt/azazel-nexus`, `/etc`, unit directories or the venv was observed.

## 7. Diagnosis

Source: diagnosis README in the scratch area (read-only VM evidence); the inner exception text is suppressed, so the mechanism is shown by evidence, not by a log line. Confidence high, residual uncertainty "another field also differs".

Failing check: the loaded-unit inspector, run on `azazel-auditd.service` while it is active (start bridge `after_completion` -> `check_start` -> `retained_check` -> loaded inspector), compares `WatchdogUSec` to the pinned record value infinity (2^64-1). A started unit reports 0.

Mechanism: systemd 257 initialises the original watchdog value to infinity at unit load and copies the configured `WatchdogSec` (unset = 0) at `service_start()`. For a unit without `WatchdogSec`, `WatchdogUSec` reads infinity before its first start and 0 after it. The record was measured on never-started fixtures, so it correctly pins infinity for that state but cannot hold the post-start value.

VM evidence (other units, `systemctl show` only): never started (alsa-state, bluetooth, bolt, azazel units pre-run) -> infinity; running (cron, ssh) -> 0; started once and inactive but still loaded (anacron) -> 0.

Class: design gap (one static expectation for a value that depends on whether the loaded object has been started). Not a race, not a record error. Consequence: every later inspection of an active auditd, and of commissiond after its start, fails the same way.

Other compared fields checked on running units (timesyncd, cron) were unchanged. This is the same field that affected the owner tool earlier (`docs/evidence/bootstrap-qualification-q4r4-ee5cdd2-2026-10-16.md`).

## 8. Next steps (owner decision pending)

1. Fix proposal (product): in the loaded-unit inspector, when the pinned `WatchdogUSec` is infinity, accept the observed value in {infinity, 0} and canonicalise it to the pin so snapshots and the fingerprint stay phase-independent. A finite pin stays exact. The loaded-units record is unchanged. Tests: infinity pin accepts 0 and infinity and rejects 1, 999, 2^64; a finite pin rejects 0; fingerprints equal for both observations.
2. Observability: replace the suppressed `from None` at `bootstrap_loaded.py:241-243` with a fixed, non-secret label naming the failing property (for example `loaded bootstrap observation refused: property WatchdogUSec`).
3. Cosmetic: retrieve or ignore the cancelled dbus write future in session cleanup.
4. Then: a new build (the build digest changes), a records quarantine and reboot, new records and approval, and one more real start. The one-use marker makes a second start in this boot impossible.

Until the owner decides: no retry in place; the VM keeps the failed controller, pair masked, ledger empty.
