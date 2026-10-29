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
([ADR-0006](0006-tested-tuple-fabric-and-arm-lab.md) derives
`ADMITTED_ARCHITECTURE` from the deployment-baseline profile; its value is
unchanged.)

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

These were recorded from the code at `ee52a38` and are not fixed by this
ADR; rows marked **Done** were closed by later changes. None of them widens production admission on Arm today, because model
admission refuses a non-`x86_64` host first.

| # | Difference | Follow-up |
| --- | --- | --- |
| R1 | The `cpu_hypervisor` virtualization sensor relies on an x86-only cpuinfo flag; on aarch64 it read `clear`, so the negative virtualization finding was weaker for `core_reserve_probe` and `hil_capture`. | **Done** (2026-10-30 委任された技術判断で決定): without an x86 `flags` line the sensor reads `unobservable`, never `clear`. `virtualization_not_observed` is read for the observed CPU: on arm64 it accepts only `unobservable` there and refuses `clear`; `dmi_vendor`, `dmi_product` and `init_cgroup` must read `clear` on every CPU, so a host where they cannot be observed (an Arm board without DMI) is refused. The VMware Fusion V3 observation is not generalized to other platforms. Both tools refuse a non-baseline profile before acquiring (`hil_capture` now as `core_reserve_probe` did); `hil_records` and `core_reserve` read a capture's / v4 record's filter for its CPU. No schema version changed: the new value fails closed in older readers. Further Arm signals (device tree, ACPI) wait for measurements on those platforms. |
| R2 | A core-reserve record carries no architecture. | **Done**: `core-reserve/4` records the observed `architecture` and `platform_profile_id`; the reader checks they agree and that the profile is the deployment baseline. v1-v3 records still parse and are refused as `ARCHITECTURE_UNKNOWN`; both HIL campaigns require v4; the probe refuses to sample on a non-baseline profile. |
| R3 | A HIL record's `platform` is a declared string, not an observation. | **Done** for the records that carry an observation: `hil_capture` (schema `/2`) records `platform_profile_id` and `uname_machine`; HG-01/HG-04 records must embed it, and the declared platform must name the observed deployment-baseline profile. Campaign runs are compared through their v4 measurement. HG-02/06/07, behaviour and drill records have no capture tool and still carry only the declared string. |
| R4 | The Edge package check compares the manifest with the pin, not with the host CPU. | Pin per CPU and add an architecture-mismatch finding (with Edge). |
| R5 | `mission_pack_cli` builds `HostFacts.architecture` from configuration. | **Done**: the kernel's `uname` machine is used; a configured value that differs is refused, and a CPU outside the table is refused by name. |
| R6 | `install.sh` does not evaluate the CPU. | **Done** (host observation): `install.sh` refuses an unreviewed CPU, an unreadable dpkg, a foreign dpkg userland, a non-LP64 libc or another byte order with a reason code, and identifies arm64 as `lab-software-verification` without refusing it. |
| R7 | `principal._GENERIC_SOCKET_MACHINES` lists CPUs beyond the reviewed two. | None needed: an unlisted CPU loses supplementary groups, which narrows access. |
| R8 | Embedding similarity may differ between CPUs near `SCOPE_MIN`. | Shared vectors exclude inputs within ε of the threshold; advisory only, never Edge's decision. |

Host observation is implemented in
[`platform_observation.py`](../../runtime/src/azazel_nexus_runtime/platform_observation.py):
`observe()` reads `uname`, `os-release` (`ID`, `VERSION_ID`), the interpreter
SOABI, LP64, the byte order and dpkg's native architecture (`unavailable`
when dpkg cannot be read), and `select(observed)` returns the reviewed profile
or refuses with the first failing check (`UNREVIEWED_KERNEL`,
`UNKNOWN_ARCHITECTURE`, `LP64_NOT_OBSERVED`, `UNREVIEWED_BYTE_ORDER`,
`DPKG_UNOBSERVED`, `DPKG_ARCHITECTURE_MISMATCH`, `UNREVIEWED_OS`,
`UNREVIEWED_PYTHON_ABI`). Every reviewed profile is Debian, so a dpkg that
cannot be read (missing, refused, unparseable) is treated as an anomaly and
refused as `DPKG_UNOBSERVED` -- by `select`, and therefore by every path
that selects the deployment baseline, and by `install.sh` for both profiles,
lab included. Without it a foreign userland (armhf on arm64, i386 on amd64)
would pass unseen. This default may be revisited by the owner; it is not
relaxed by any setting.
Selecting the lab profile identifies the host; it is not an admission. The
arm64 offline-bundle target and lock are now
[ADR-0005](0005-arm-lab-offline-target.md) (`debian-13-aarch64-cp313`,
purpose `lab-software-verification`; the baseline target is unchanged); the
cross-CPU vector runner is a further follow-up.

## Limits of host observation

An observed value is what the running kernel, libc, interpreter and package
database **report**. It is not attestation and it cannot be made unforgeable
by this code:

- root on the host can change `/etc/os-release`, the dpkg database, or the
  interpreter, and a modified kernel can report any `uname`;
- an emulator reports the emulated CPU: an x86_64 process under Rosetta or
  qemu-user observes `x86_64` on Arm hardware (D6 already records such a run
  as emulated, not as an amd64 host);
- a container observes its image's `os-release` and the host's kernel.

What observation does buy is narrower and still worth having: an honest tool
on an Arm VM can no longer write a record that *says* amd64, so a lab run is
not turned into deployment evidence by a declared string or a copied
configuration. Proof that a record came from the target hardware remains the
operator attestation and the hardware gates, which observation does not
replace, partially satisfy or weaken.

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
