# Live issue map and evidence status

Checked: 2026-09-26. Open-issue state is a point-in-time GitHub snapshot;
recheck issue comments, linked PRs, acceptance checkboxes, and current CI before
changing a label or closing an issue. At the check time there were **19 open
issues and no open pull requests**. Classifications below describe the
remaining acceptance work, not just whether code exists.

## Repository and CI evidence

The audited baseline `main` is `375695a39ed52a53dc6dcaccfb6eacfad08cb96c`.
The worktree now contains uncommitted documentation and CI changes. The latest
`main` runs for the baseline commit both succeeded:
[CI](https://github.com/01rabbit/Azazel-Nexus/actions/runs/35676550679) and
[Docs](https://github.com/01rabbit/Azazel-Nexus/actions/runs/35676550659).
These establish the declared Linux CI checks only. They do not establish
systemd enforcement, hardware admission, external network behavior, or HIL.

This audit machine is macOS. A local Python 3.11 run reported 3,158 passed,
4 skipped, and 41 failures. The failures are platform-bound: the installer
test deliberately gives its subprocess a fixed system PATH and encounters
macOS Python 3.9; Linux-only runtime tests require `/proc` and
`SO_PEERCRED`; the HIL fixture's `st_dev`/`os.makedev` assumptions are Linux
device-number semantics. The Unix-socket tests passed (38/38) after using a
short temporary path. Do not represent this macOS run as a Linux CI failure or
as a full local pass.

## Current open issues

| Issue | Classification | Evidence and remaining condition |
| --- | --- | --- |
| [#115](https://github.com/01rabbit/Azazel-Nexus/issues/115) | blocked by external hardware | The 8 GiB pilot has no target inventory or operator approval. Keep `hardware-unverified`; its own issue forbids fixture or laptop measurements as admission evidence. |
| [#100](https://github.com/01rabbit/Azazel-Nexus/issues/100) | blocked by external hardware | Provider admission and the six end-to-end scenarios require measured HG-05 on deployment hardware. |
| [#98](https://github.com/01rabbit/Azazel-Nexus/issues/98) | software-complete / hardware-unverified | Its 11 software criteria are met. Real endpoint identity, commissioned registry, and measured network mTLS admission remain external/HG-05 evidence; no real endpoint or credential was supplied. |
| [#97](https://github.com/01rabbit/Azazel-Nexus/issues/97) | software-complete / hardware-unverified | Latest issue comment reports its software criteria complete; the remaining condition is model-provider execution under HG-05, with runtime/registry ownership in #115/#100. |
| [#96](https://github.com/01rabbit/Azazel-Nexus/issues/96) | active implementation | Transport stages 1 and 2 exist, but plan→transport→staging is not wired end-to-end and failure-path E2E remains unproven. |
| [#93](https://github.com/01rabbit/Azazel-Nexus/issues/93) | active implementation | Installer-to-activation operator flow spans unresolved local/remote provider lifecycle work. |
| [#86](https://github.com/01rabbit/Azazel-Nexus/issues/86) | active implementation | Latest comments fix the design decision; code implementation and security verification remain. Filesystem permissions alone are not the repin authorization boundary. |
| [#85](https://github.com/01rabbit/Azazel-Nexus/issues/85) | active implementation | The design decision is fixed in the latest comments; implementation and independent security verification are not yet evidenced. |
| [#75](https://github.com/01rabbit/Azazel-Nexus/issues/75) | software-complete / hardware-unverified | The narrow status remains valid, but its reported test/E2E counts are stale and need refresh; the issue stays open pending hardware evidence. |
| [#70](https://github.com/01rabbit/Azazel-Nexus/issues/70) | design decision required | The handwritten Ed25519 verifier's supported-security claim remains contingent on independent review. Differential tests alone do not close that review. |
| [#68](https://github.com/01rabbit/Azazel-Nexus/issues/68) | software-complete / hardware-unverified | Measurement input path and software-side criteria are complete; HG-05 remains unmeasured on real hardware. |
| [#56](https://github.com/01rabbit/Azazel-Nexus/issues/56) | review / hosted CI runner unavailable | The feature branch adds a root job alongside the non-root integration job; it runs the 88-case suite and full harness and requires the install-accounts and CORE + Lite stages to execute. The recorded 88 targeted cases passed as non-root. The first PR #128 CI/Docs attempt failed before any step with `runner_id=0` and zero steps; this is infrastructure failure, not a test result. Root privileges are unavailable locally. Next: review the workflow and rerun both hosted jobs when runners are available. This does not prove systemd enforcement or live-provider behavior. |
| [#55](https://github.com/01rabbit/Azazel-Nexus/issues/55) | active implementation | Six of seven criteria are complete; recording the reason for audit state transitions remains. #5 shares the missing route/provenance/fallback-to-AuditLedger wiring. |
| [#53](https://github.com/01rabbit/Azazel-Nexus/issues/53) | active implementation | Its own status says the Lite control/state surfaces are implemented, but children #5, #6, #55, #56 and hardware-dependent #68 remain open; the parent must remain open. |
| [#44](https://github.com/01rabbit/Azazel-Nexus/issues/44) | software-complete / hardware-unverified | All software integration criteria are checked; its unchecked final item is real Edge startup under HG-07. |
| [#17](https://github.com/01rabbit/Azazel-Nexus/issues/17) | software-complete / hardware-unverified | SO-06 has software evidence; SO-01/SO-10 and other named measures still need field measurement. |
| [#16](https://github.com/01rabbit/Azazel-Nexus/issues/16) | active implementation | The external defensive-platform broker still needs admitted adapters, confinement, egress limits, credential rotation, rollback, and HIL. |
| [#6](https://github.com/01rabbit/Azazel-Nexus/issues/6) | active implementation | Knowledge Lite bundle import/claim serving is complete; AZ-04 full-node discovery, mTLS, fail-closed responses, and routing are not implemented. |
| [#5](https://github.com/01rabbit/Azazel-Nexus/issues/5) | active implementation | M.I.O. control-plane exists; route/provenance/fallback decisions still need AuditLedger wiring. |
| [#4](https://github.com/01rabbit/Azazel-Nexus/issues/4) | blocked by external hardware | Rugged x86_64 HIL and degraded-mode measurements require eligible target hardware and operator authorization. |
| [#3](https://github.com/01rabbit/Azazel-Nexus/issues/3) | active implementation | Other artifact slices are not Mission Pack evidence; signed offline Mission Pack lifecycle and atomic stage/activate/rollback remain unimplemented. |

## Evidence boundary

The software-only product state is stronger than a documentation scaffold:
the repository contains the CLI, commissioning and activation control plane,
audit/watchdog logic, advisory Knowledge Lite import/serving, Deception Lite
loopback runtime, M.I.O. routing/control plane, Edge package checks, and a
target-local `hil-preflight`. M.I.O. providers remain unavailable pending
integration and HG-05. Deception Lite stays loopback-only. No systemd
enforcement or hardware gate is claimed as verified until its named gate has
external evidence.

No issue should be closed solely because a PR merged, CI passed, or a local
test passed. In particular, no HIL issue may be closed using this machine's
macOS run, synthetic data, or CI fixtures.
