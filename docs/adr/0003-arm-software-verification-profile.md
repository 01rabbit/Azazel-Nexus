# ADR-0003 — Arm is a software-verification profile, not a deployment baseline

Status: **proposed (2026-10-28)**, with defaults adopted by the implementing
change; the owner may change any of them · Supersedes nothing · Leaves
[ADR-0002](0002-debian-13-baseline.md) unchanged

## Context

The deployment baseline is **Debian 13 / amd64**
([program plan §15 OF-07](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md),
adopted in [ADR-0002](0002-debian-13-baseline.md)). The target machine is not
yet available. What is available is an Arm (aarch64) Linux VM, and the
mechanics rehearsals already run there:

- [commissioning rehearsal](../hil-runbooks/commissioning-rehearsal.md) (2026-10-19),
- [integration-loop rehearsal](../hil-runbooks/integration-loop-rehearsal.md) (2026-10-20, 2026-10-24),
- [activation rehearsal](../hil-runbooks/activation-rehearsal.md) (2026-10-23),
- [milestone 1 real-systemd smoke](../evidence/milestone1-real-systemd-smoke-2026-10-18.md) (2026-10-18).

Each of them already says "mechanics only, never evidence". What did not exist
was a name for the category those runs belong to, or a place in the code that
says which CPU a host is and what that CPU may be used for. The CPU was
spelled three ways — `x86_64`/`aarch64` (kernel), `amd64`/`arm64` (Debian and
Fabric), `x86-64`/`arm64` (systemd) — and normalised by three separate tables
(`model_runtime`, `resource_assessment`, the lab `unit_sandbox`), each with
its own behaviour for an unknown name.

## Decision

**D1. The deployment baseline does not move.** ADR-0002 D1, D4 and D6 stand
as written. `hil_preflight.BASELINE_ARCHITECTURE` and
`compatibility.ADMITTED_ARCHITECTURE` keep the value `x86_64`; HIL preflight
`A-2`, product admission and model admission continue to refuse any other
CPU. Nothing in this ADR makes Arm a supported deployment target.

**D2. One module names the CPUs.**
[`platform_profile.py`](../../src/azazel_nexus/platform_profile.py) is a pure
library (no I/O, no dependencies). Its canonical names are Fabric's
(`amd64`, `arm64`: `provisioning_contracts.Architecture`), and it holds the
one table from each canonical name to each boundary's spelling: kernel
`uname -m`, Debian/dpkg, systemd, the Python SOABI multiarch triplet, and
Fabric. Each boundary has an exact reader; a spelling no table lists is
refused with the reason `UNKNOWN_ARCHITECTURE`, never passed through or folded
into a neighbour. The three existing normalisations and the LP64 allow-list
in `bootstrap_cgroup_mount` now read this table **without changing what they
accept** (the existing tests are unchanged). The `SO_PEERGROUPS` table in
`principal.py` is a kernel-ABI list wider than the reviewed CPUs and stays
where it is; a test holds that it covers every reviewed CPU.

**D3. A platform profile is a reviewed combination with a purpose.**
`REVIEWED_PROFILES` holds exactly two:

| Profile | OS | CPU | Python ABI | Purpose |
| --- | --- | --- | --- | --- |
| `debian-13-amd64-cp313` | Debian 13 | amd64 | `cpython-313-x86_64-linux-gnu` | `deployment-baseline` (ADR-0002) |
| `debian-13-arm64-cp313-lab` | Debian 13 | arm64 | `cpython-313-aarch64-linux-gnu` | `lab-software-verification` |

`select_profile` matches `os-release` `ID` and `VERSION_ID`, the kernel
machine name and the SOABI exactly, and refuses anything else with the first
field no profile has (`UNKNOWN_ARCHITECTURE`, `UNREVIEWED_OS`,
`UNREVIEWED_PYTHON_ABI`). A lab profile's identifier ends in `-lab`, so a
record that carries only the identifier is still distinguishable.

**D4. A lab profile cannot back a production use.** `DeploymentBaseline` — the
value a production consumer takes — refuses, on its ordinary construction
paths (the constructor, `require_deployment_baseline`, `copy` and `pickle`,
which go back through the constructor), a lab profile, an unreviewed
look-alike whose purpose merely claims the baseline, and a use outside
`PRODUCTION_USES` (model admission, product admission, HIL preflight, a
hardware-gate record, a core-reserve record); the class cannot be subclassed.
Tests fix this for every listed use. Python cannot stop
`object.__new__` plus `object.__setattr__`, so the type is not by itself
proof: a consumer that acts on a value checks `type(x) is
DeploymentBaseline` and re-runs the checks, which
`verify_deployment_baseline` does. This is a check that refuses; it is not an
approval flag, and nothing in this change adds a switch, environment variable
or setting that would accept Arm in production.

**D5. Arm VM results are "VM software-integration evidence", a category
separate from the hardware gates.** A run on `debian-13-arm64-cp313-lab` can
show that the software installs, starts, stops, restarts, keeps state, audits
and refuses as designed under a real systemd. It never closes, partially
closes or substitutes for any `HG-*` in [hardware gates](../hardware-gates.md),
and it says nothing about the target's memory headroom, performance, power
loss, TPM or Secure Boot, physical NIC silence or physical separation. The
existing aarch64 rehearsals listed above are in this category, retroactively
and without change to their records.

**D6. The core is one CPU-independent implementation, checked by shared
vectors.** Decision, authorization, contracts, audit, deadlines and
cryptography (the pure-integer Ed25519 verifier, canonical JSON and sha256)
have no CPU branch and must not gain one. Shared test vectors with injected
clocks and identifiers are run on both CPUs and compared byte for byte. A
vector that has not been run on a CPU is recorded as **not run** on that CPU —
never as passed, and never inferred from the other CPU. An x86_64 run under
Rosetta or qemu is recorded as emulated, not as an amd64 host.

**D7. What legitimately differs per CPU is pinned per CPU, never substituted.**

- *Binary and asset digests* (the llama runtime, the `_bootstrap_deadline`
  native extension, wheels, Edge Core binaries) differ. Each is pinned per
  CPU in the module that owns it, keyed by that module's boundary name, and a
  CPU without a pin is refused. An amd64 artifact is never accepted on arm64,
  and no placeholder digest stands in for a missing build.
- *ABI constants* (LP64, `SO_PEERGROUPS`) are recorded as reviewed per CPU; an
  unreviewed CPU falls to the narrower behaviour.
- *Performance and resource measurements* are not compared across CPUs. Only
  their schema and stated limitations are.
- *Model output*, including embedding similarity, is not promised to match.
  Cross-CPU comparisons of advisory gates use only inputs at least a stated
  ε from a threshold (R8 below).

## Known differences and follow-up changes

These are open, recorded from the code at `ee52a38`, and not fixed by this
ADR. None of them widens production admission on Arm today, because model
admission refuses a non-`x86_64` host first.

| # | Difference | Follow-up |
| --- | --- | --- |
| R1 | The `cpu_hypervisor` virtualization sensor relies on an x86-only cpuinfo flag; on aarch64 it always reads `clear`, so the negative virtualization finding is weaker for `core_reserve_probe` and `hil_capture`. | Treat the sensor as not-applicable on arm64 and gate both tools on a deployment-baseline profile; confirm alternative signals on a real Arm VM first. |
| R2 | A core-reserve record carries no architecture. | Add it to the record and check it on read. |
| R3 | A HIL record's `platform` is a declared string, not an observation. | Record the observed profile in `hil_capture` and compare. |
| R4 | The Edge package check compares the manifest with the pin, not with the host CPU. | Pin per CPU and add an architecture-mismatch finding (with Edge). |
| R5 | `mission_pack_cli` builds `HostFacts.architecture` from configuration. | Use the observed value. |
| R6 | `install.sh` does not evaluate the CPU. | Extend the install profile to refuse an unreviewed CPU with a reason. |
| R7 | `principal._GENERIC_SOCKET_MACHINES` lists CPUs beyond the reviewed two. | None needed: an unlisted CPU loses supplementary groups, which narrows access. |
| R8 | Embedding similarity may differ between CPUs near `SCOPE_MIN`. | Shared vectors exclude inputs within ε of the threshold; advisory only, never Edge's decision. |

Host observation (uname, `os-release`, SOABI, LP64, byte order) feeding
`select_profile`, the arm64 offline-bundle target and lock, and the cross-CPU
vector runner are further follow-ups.

## Alternatives considered

**Make Arm a second deployment baseline.** A campaign run across two
platforms produces evidence for neither (ADR-0002 D6), and no Arm target has
been chosen or measured.

**Keep three local tables.** They already disagreed on unknown names; a fourth
caller would have written a fourth.

**Canonical names from the kernel (`x86_64`/`aarch64`).** Every Fabric
contract that carries a CPU uses `amd64`/`arm64`; using the kernel spelling
internally would put a translation at every contract boundary instead of at
the host boundary.

## What this ADR does not establish

- That anything runs on an Arm host other than the recorded VM rehearsals.
- That any shared vector has been run on an amd64 host. Until it has, it is
  recorded as not run there.
- That an Arm VM result is evidence for any hardware gate.
