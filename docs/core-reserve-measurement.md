# Measuring the Core reserve

**No measurement has been taken.** [`HG-05`](hardware-gates.md) is open, every
local model provider is refused at the resource gate, and
`core_reserve.load_reserve()` returns `None` on every node this build runs on.

This document is the procedure that would close it, and the shape the result
has to take. It exists because the alternative — deciding the number when the
hardware finally appears — is how an invented threshold gets written down
under time pressure.

Related: [M.I.O. runtime control plane](mio-runtime.md) §3 ·
[hardware gates](hardware-gates.md) · [capability model](capability-model.md) ·
[inventory confidentiality](inventory-confidentiality.md) ·
[HIL preflight](hil-preflight.md) ·
[Nexus #68](https://github.com/01rabbit/Azazel-Nexus/issues/68)

## 1. What the number is

The Core reserve is what the node needs **before any optional workload**: the
arbiter, audit, the lease journal, evidence capture, the operator plane, and
the kernel's own working set under load.

It is not a headroom allowance and not a safety margin. It is the floor under
which the node stops doing the work it exists to do — so a local model
admitted below it does not run slowly, it displaces the deterministic path.

**It is not one number.** `IMPLEMENTATION_SPEC.md` §2.1 says the reserve
scales with retention and concurrency, so it is measured per memory class and
a record carries the class it was measured on. `cognition.admit_local_model`
refuses a reserve from another class rather than scaling it.

## 2. What is measured, and what is not

| measured | not measured |
| --- | --- |
| the resident set of the cgroup the Azazel units live in | this process's own resident set, which would measure the harness |
| the node's usable memory, to classify it | a nominal module size, which is always above usable RAM |
| a span of load, sampled | a moment, sampled many times |

## 3. The harness

`az-core-reserve-probe`, from the runtime distribution
(`runtime/src/azazel_nexus_runtime/core_reserve_probe.py`).

It takes **no arguments**. There is no `--cgroup`, no `--unit`, no
`--samples`, no `--interval` and no `--output`, and
`tests/unit/test_core_reserve_probe.py` asserts that `main` declares none. A
harness that accepted a cgroup path would be a harness that could be pointed
at any cgroup on the host and have the answer recorded as the Core reserve.

**It is a console script and not a systemd unit.** Every node probes its Edge
package, so `az-edge-probed` is a unit; a measurement campaign happens once
per hardware class, so a masked unit for it would sit on every node
describing work no node performs.

It runs nothing. Subsystem liveness is read over D-Bus through a two-method
read-only allowlist, and everything else is a file read under `/sys` and
`/proc`.

## 4. What it refuses

A number produced by the wrong run is worse than no number, because it looks
like the one that was missing. The run refuses — it does not warn and
continue — and **a refusal writes nothing**, because a record holding some of
the samples is a measurement of a shorter run that does not say so.

| refusal | why |
| --- | --- |
| no connection to the service manager | a reserve measured without knowing what was running is a measurement of an unknown node |
| a required subsystem was not active **when the run began** | the reserve is what the node needs before optional work |
| a required subsystem was not active **when the run ended** | a run that passed the first check and failed the second produced samples of two different nodes, and there is no way to tell which sample was the last of the first node |
| a sample could not be read | a run with a hole in it is a shorter run that does not say so |
| a sample is not a positive quantity | a broken reader must not be averaged into a threshold |
| the memory class changed during the run | the reserve is per class, so samples spanning two are of neither |
| the completed run does not pass §6 | a record that fails validation on disk is a record somebody will eventually relax the validator for |

## 5. The procedure

1. Install both distributions on the target host and complete commissioning.
   The host runs **Debian 13 / amd64**, the program's initial platform
   baseline — a reserve measured on another distribution is a reserve of
   another platform ([program plan §15 OF-07](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md), adopted in
   [ADR-0002](adr/0002-debian-13-baseline.md)).
   The target host is **a generic rugged x86_64 Linux PC at the resource class
   being measured** ([hardware gates](hardware-gates.md), *What "the target
   hardware" means here*). A Raspberry-Pi-class device, a laptop or a
   workstation may exercise the harness; a record from one is a development
   reference and is not admissible as this class's reserve, because the
   resident set it measures is another machine's.
2. **Edge Core must already be installed and running through the approved
   deployment path.** `azazel-arbiter`, `azazel-evidence`,
   `azazel-leasejournal`, `azazel-operator` and `azazel.slice` are supplied by
   the Edge Core deployment; installing Nexus alone does not provide them.
   The Nexus `azazel-auditd` unit is also mandatory. Use the read-only readiness command **added in this change**
   ([integration references](hil-evidence-records.md#tools-and-trust)) to identify
   missing units, slice, commissioning key or target class. A ready result
   establishes presence/readiness only, not load or a reserve. Do not remove a
   required unit, create dummy units or bypass activation to make the probe run.
   Bring up the node's own subsystems and confirm all five are `active
   (running)`: `azazel-arbiter`, `azazel-auditd`, `azazel-evidence`,
   `azazel-leasejournal`, `azazel-operator`.
3. Put the node **under load** — the reserve is what it needs while working,
   not while idle. Audit writing, evidence capture and the lease journal must
   be doing their work, not merely running.
4. Run `az-core-reserve-probe`. It samples 60 times at 10-second intervals, so
   a run spans roughly ten minutes.
5. Repeat on each memory class the product supports (8, 16 and 32 GB). A
   record is per class and one class's record says nothing about another's.
6. Repeat each class at least three times, on separate boots. A single run
   observes one boot's fragmentation and one set of transient allocations.
   Take the **highest** reserve across the runs of a class, by the policy in
   §7.
7. Record which workload was applied, alongside the records. The harness
   cannot observe what load the node was under, so that fact travels in the
   campaign notes and not in the record — and a campaign whose load is not
   written down is one nobody can repeat.
8. Keep the campaign's notes under
   [inventory confidentiality](inventory-confidentiality.md). The notes
   identify a machine — the record does not — so what they may hold, and what
   a report drawn from them may say, is fixed there and not per campaign.

## 6. What makes a record admissible

`core_reserve.validate` reports **every** reason a record is not, not the
first — an operator who fixes one refusal and is then told about the next has
been sent round twice.

| refusal | floor |
| --- | --- |
| provenance is not `measured` | a `fixture` record exercises the reader, the validator and the gate wiring, and is refused for admission by name |
| a subsystem in `REQUIRED_SUBSYSTEMS` was not active | all five |
| too few samples | `MIN_SAMPLES` = 30 |
| the samples span too little time | `MIN_DURATION_SECONDS` = 300 |
| a non-positive sample, or a negative offset | — |

The harness's own constants clear these with room to spare (60 samples over
590 seconds), and `test_the_harness_constants_clear_the_validator_s_floors`
checks the arithmetic so the two cannot drift apart unnoticed.

## 7. The reserve is the maximum observed

A **declared policy**, stated here so it is argued with rather than
discovered.

The reserve is a floor the node must always have. A percentile admits a
provider on the strength of the samples below the tail — and the tail is
exactly the load under which the node sheds the work the reserve exists to
protect. Taking the maximum can only refuse a provider that would have fit;
taking a percentile can admit one that does not.

A later campaign may argue for a maximum plus a margin. That would be a change
of policy, and it changes no number this build has.

## 8. Where an admissible record goes

The existing consumer path is `/var/lib/azazel/run/core-reserve.json`.
Probe v2 **added in this change** retains a distinct file for each run rather
than overwriting previous observations, with boot HMAC fingerprint, sequence,
commit and protected kernel context. See [HIL evidence records](hil-evidence-records.md)
for archive, confidentiality, attestation and campaign validation. Do not copy
an arbitrary run to the consumer path: first validate at least three attested
runs on distinct boots of the same class/harness with workload notes and select
the maximum of their maxima, then use the integrated approved consumption path.
The reader continues to support v1; that alone does not establish v2 campaign
provenance. Runtime state, never a packaged file:
`tests/unit/test_core_reserve.py::test_no_measurement_is_committed_anywhere`
offers every JSON file in the distribution to the reader and fails if one is
accepted as a `measured` record.

## 9. What changes when one exists

The resource gate decides instead of refusing. It compares the declared memory
need against the node's **measured** envelope after the reserve — never
against a class floor, because `capability-model.md` §2 is explicit that a
hardware class is never evidence that a capability fits.

The provider is then refused one gate later, at **approval**, which is not
implemented (`mio-runtime.md` §3, Nexus#68). That is deliberate: a gate that
refuses only by being unreachable starts passing the day something upstream
stops refusing, silently and without a line of code changing. Both paths are
driven in `tests/unit/test_cognition.py` and end to end by the `Core reserve
input path` stage of `tools/e2e.py`.

## 10. A synthetic record that is not a measurement

Recorded here because the next person to find one has to know what it is
worth, and because a record of this kind is only useful where the admissible
ones are described.

During development the end-to-end harness was pointed at a working tree. It
builds a synthetic node, and among the files it writes is a record whose
provenance reads `measured` — it is **not** a measurement and never was one.
The synthetic node was swept into a commit and pushed to a draft pull request
before the repository's own scan refused it.

What is true of it:

- it is **not** in `main`, in any release, in any signed artifact, or in any
  HIL evidence
- the first draft head was replaced by a force-update; **no claim is made
  that the external hosting has erased it** — a branch rewrite removes a
  commit from a branch, not from a forge's stored refs, timelines or caches
- the artifact is **invalid as HIL evidence** and **must not be cited** in
  any admission, release or document, now or later
- the harness can no longer be aimed at a Git checkout or worktree at all. It
  writes only to a dedicated directory outside version control, defaulting to
  one it creates per run
- CI verifies that the guard refuses **before the first write**, so a refused
  run leaves nothing behind

No value, record body or identifier from that artifact is reproduced here.
Repeating it to describe it would be the same mistake with a better excuse.

This is an integrity matter, not a disclosure one: nothing about it involved
real data, a credential or a secret. What it risked was a number that looks
like the one §1 says nobody has taken.

## 11. What is still not settled by any of this

Closing `HG-05` produces a number. It does not produce:

- **confinement** (`mio-runtime.md` §4) — it needs a running provider, which
  approval and staged activation have to admit first
- **the approval and staged-activation gates** — named by the contract,
  refusing for having no implementation
- **any claim about the model itself** — the reserve says a provider fits in
  memory, which is not a claim that it is useful, correct, or safe to consult

## 12. On-device readiness and capture commands

Run `az-hil-readiness` before the campaign. This separate, read-only command
reports installed/active status for the five required subsystem units and
`azazel.slice`, whether the commissioning key is usable, and whether usable
RAM selects the pilot's Core class. Missing Edge Core prerequisites are
reported explicitly. Nexus installation alone does not supply those Edge
Core units. Readiness does not replace the hardware/operator preflight.

The probe's v2 records include a domain-separated HMAC of the boot ID, a run
sequence, the full build commit, and kernel release. Provision the full source
commit used to build the installed distributions in the root-owned file
`/usr/share/azazel/build-commit` during installation. Missing build identity or
commissioning key refuses the run. Raw boot ID and machine ID are never
included. Boot/build identity is checked again after sampling.

Each run is published without replacement as
`/var/lib/azazel/run/core-reserve-run-<sequence>.json`. Keep all run files;
sequence allocation reads this archive and publication refuses a concurrent
collision. Run only one probe at a time. The sampler does not promote a run to
`core-reserve.json`; the campaign validator and attestation must precede any
operator promotion to that admission input. The reader retains v1 support.

`az-hil-capture hg-01` emits the governed unit-file list, per-unit active/sub
states, and systemd version over the system bus. An unloaded unit is reported
as unobserved rather than guessed inactive. The list covers Nexus Core units,
Edge Core prerequisites, and the slice; unrelated unit paths are omitted to
avoid exposing local identity.

`az-hil-capture hg-04` reads the existing `RTM_GETLINK` implementation. Each
NIC has an anonymous HMAC label, permanent-address presence and, when present,
a domain-separated HMAC of the permanent address. Neither NIC names nor raw
addresses are printed. Both capture commands emit JSON to stdout with host
and boot HMACs, build commit and kernel release. Redirect output only to the
campaign directory outside version control. These are automatic acquisition
records (`azazel-nexus/hil-capture/hg-01/1` and `hg-04/1`); they assert no
hardware qualification and need reconciliation into the campaign schemas and
operator attestation before validators may accept them. HG-02 remains an
operator runbook because unmasking changes system state.

### Commissioning key initialization (root only)

Generate the key on the target device once, before preflight. Run the following
as root on the device; it prints no key material and refuses to replace an
existing key. Keep the key on that device, outside campaign records and bundles.
The root-only secrets directory must already be on the commissioned storage.
Do not paste keys into commands, tickets or shell history.

```sh
sudo python3 - <<'PY'
import os
import stat
from pathlib import Path

if os.geteuid() != 0:
    raise SystemExit("root required")
directory = Path("/var/lib/azazel/secrets")
# The installation supplies /var/lib/azazel; do not follow a secrets symlink.
directory.mkdir(mode=0o700, exist_ok=True)
info = directory.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
    raise SystemExit("secrets directory must be root-owned mode 0700")
parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    fd = os.open("commissioning.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=parent)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(os.urandom(32))
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)
finally:
    os.close(parent)
PY
```

The tools require a root-owned regular 32-byte key at
`/var/lib/azazel/secrets/commissioning.key`, mode `0600`, inside a root-owned
`0700` directory. Run them with the required local privilege to read that key.
If initialization is interrupted, investigate locally; do not overwrite or
rotate a key used by commissioning or existing fingerprints automatically.
