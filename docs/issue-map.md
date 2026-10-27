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

HIL ownership rows #4/#115/#100/#68 were reconciled locally on 2026-10-18
against the campaign preparation plan; no live issue state was changed or
re-fetched for this update. The older snapshot above remains historical.

## Current open issues

| Issue | Classification | Evidence and remaining condition |
| --- | --- | --- |
| [#115](https://github.com/01rabbit/Azazel-Nexus/issues/115) | blocked by external hardware | Child of campaign parent #4: first 8 GiB pilot performs preflight, HG-05, HG-01/02/04 and SO-01 on the same DUT. Edge Core installation/running load, eligible target inventory and operator approval are prerequisites. Keep `hardware-unverified`; fixtures/laptop runs cannot qualify. See the [campaign](hil-campaign.md). |
| [#100](https://github.com/01rabbit/Azazel-Nexus/issues/100) | blocked by external hardware | Child of #4: admission after attested class-specific HG-05 reserve, then local inference, one remote fallback, network loss, crash, shed order and revocation on deployment hardware. CI and HIL archives are separate ([AC4 record contract](hil-evidence-records.md)). Later 16/32 GiB classes require separate child issues; preparation does not satisfy hardware acceptance. |
| [#98](https://github.com/01rabbit/Azazel-Nexus/issues/98) | software-complete / hardware-unverified | Its 11 software criteria are met. Real endpoint identity, commissioned registry, and measured network mTLS admission remain external/HG-05 evidence; no real endpoint or credential was supplied. |
| [#97](https://github.com/01rabbit/Azazel-Nexus/issues/97) | software-complete / hardware-unverified | Latest issue comment reports its software criteria complete; the remaining condition is model-provider execution under HG-05, with runtime/registry ownership in #115/#100. |
| [#96](https://github.com/01rabbit/Azazel-Nexus/issues/96) | software path composed / deployment pending | `model_fetch.acquire` wires plan → registry → transport → #95 import, with loopback-TLS E2E including failure paths. The daemon still refuses to start (commissioning formats and the inbox hand-off are owner decisions); no real endpoint, credential or download. |
| [#93](https://github.com/01rabbit/Azazel-Nexus/issues/93) | active implementation | Read-only `azazel-nexus setup` now guides installation through activation; M.I.O. entry and Knowledge Lite daemons are implemented. Installed lifecycle evidence and local/remote provider admission remain open. |
| [#86](https://github.com/01rabbit/Azazel-Nexus/issues/86) | active implementation | Latest comments fix the design decision; code implementation and security verification remain. Filesystem permissions alone are not the repin authorization boundary. |
| [#85](https://github.com/01rabbit/Azazel-Nexus/issues/85) | active implementation | The design decision is fixed in the latest comments; implementation and independent security verification are not yet evidenced. |
| [#75](https://github.com/01rabbit/Azazel-Nexus/issues/75) | software-complete / hardware-unverified | The narrow status remains valid, but its reported test/E2E counts are stale and need refresh; the issue stays open pending hardware evidence. |
| [#70](https://github.com/01rabbit/Azazel-Nexus/issues/70) | design decision required | The handwritten Ed25519 verifier's supported-security claim remains contingent on independent review. Differential tests alone do not close that review. |
| [#68](https://github.com/01rabbit/Azazel-Nexus/issues/68) | software-complete / hardware-unverified | Consumer waiting for HG-05 from #4/#115; measurement input and software-side criteria are complete. HG-05 remains `unmeasured`; this issue neither owns the campaign nor bypasses attested reserve admission. |
| [#56](https://github.com/01rabbit/Azazel-Nexus/issues/56) | review / hosted CI runner unavailable | The feature branch adds a root job alongside the non-root integration job; it runs the 88-case suite and full harness and requires the install-accounts and CORE + Lite stages to execute. The recorded 88 targeted cases passed as non-root. The first PR #128 CI/Docs attempt failed before any step with `runner_id=0` and zero steps; this is infrastructure failure, not a test result. Root privileges are unavailable locally. Next: review the workflow and rerun both hosted jobs when runners are available. This does not prove systemd enforcement or live-provider behavior. |
| [#55](https://github.com/01rabbit/Azazel-Nexus/issues/55) | active implementation | Six of seven criteria are complete; recording the reason for audit state transitions remains. #5 shares the missing route/provenance/fallback-to-AuditLedger wiring. |
| [#53](https://github.com/01rabbit/Azazel-Nexus/issues/53) | active implementation | Its own status says the Lite control/state surfaces are implemented, but children #5, #6, #55, #56 and hardware-dependent #68 remain open; the parent must remain open. |
| [#44](https://github.com/01rabbit/Azazel-Nexus/issues/44) | software-complete / hardware-unverified | All software integration criteria are checked; its unchecked final item is real Edge startup under HG-07. |
| [#17](https://github.com/01rabbit/Azazel-Nexus/issues/17) | software-complete / hardware-unverified | SO-06 has software evidence; SO-01/SO-10 and other named measures still need field measurement. |
| [#16](https://github.com/01rabbit/Azazel-Nexus/issues/16) | local assurance implemented / transport and HIL open | [Integration broker](integration-broker.md): signed admission, shared states/leases, atomic records, audit, rendered confinement/scoped references, sanitized routing, fail-closed intent gates, withdrawal, read-only status/review/setup and a 21st e2e stage. Destination-port enforcement, runtime mTLS/rotation/watchdog installation, device rollback and management-failsafe HIL remain unproven; Fabric#25 is open. No adapter/provider wire protocol or automation bus. |
| [#6](https://github.com/01rabbit/Azazel-Nexus/issues/6) | active implementation | Knowledge Lite bundle import/claim serving is complete; AZ-04 full-node discovery, mTLS, fail-closed responses, and routing are not implemented. |
| [#5](https://github.com/01rabbit/Azazel-Nexus/issues/5) | active implementation | Metadata-only `az-mio-entryd` composes MioRouter and records route/handoff decisions in its AuditLedger; `az-knowledge-lited` serves read-only status. Installed systemd lifecycle and provider admission remain unverified. |
| [#4](https://github.com/01rabbit/Azazel-Nexus/issues/4) | blocked by external hardware | Campaign parent for rugged x86_64 HIL and degraded-mode drills; [gate-to-issue map](hil-campaign.md#ownership-and-scope). Children #115 (8 GiB pilot), #100 (post-reserve admission/E2E); HG-06 and HG-07 need explicit child issues (numbers unassigned). HG-03 shares SO-10/#17. Later 16/32 GiB campaigns need class children. Eligible hardware and operator authorization remain outstanding. |
| [#3](https://github.com/01rabbit/Azazel-Nexus/issues/3) | active implementation | Other artifact slices are not Mission Pack evidence; signed offline Mission Pack lifecycle and atomic stage/activate/rollback remain unimplemented. |

## Remote inference: what it waits on (not Fabric#25)

The online-AI entry path (remote inference, #98 / #100) does **not** depend on
[Fabric#25](https://github.com/01rabbit/Azazel-Fabric/issues/25). Fabric#25 is
what the integration broker's transport waits on (#16):
`integration_broker/routing.py` `deliver()` returns
`transport unavailable: Fabric#25` for every intent, and the status and CLI
lines repeat that reason. Nothing on the remote inference path names it.

Remote inference waits on three separate things, none of which this
repository can settle by code alone:

| Waits on | Owner / when | Where it is recorded |
| --- | --- | --- |
| Adopting Fabric `mio_contracts` (published in the pinned Fabric, not adopted here) | owner decision | [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §6.3, [contract ownership](contract-ownership.md) §3.3 |
| Commissioning the sanitizer signer and the Provider Registry | after the target hardware; #115 lists both as not to be created or installed until then | [remote commissioning](remote-commissioning.md) §3 (decisions 1–9, sanitizer key = decision 7) |
| The form in which the runtime reads the operator's remote consent | owner decision; today `az-mio-entryd` always passes `NO_OPT_IN` | `mio_profile.py`, `mio_entryd.py` |

Until all three exist, the shipped `mio_remoted.TRANSPORT` stays `None` and
nothing can be sent (see [the sanitizer](mio-sanitizer.md) §5 and
[remote inference](remote-inference.md) §12). Fabric#25 closing would not
change any of this.

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
