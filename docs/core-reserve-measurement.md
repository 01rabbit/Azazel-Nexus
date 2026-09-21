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
   The target host is **a generic rugged x86_64 Linux PC at the resource class
   being measured** ([hardware gates](hardware-gates.md), *What "the target
   hardware" means here*). A Raspberry-Pi-class device, a laptop or a
   workstation may exercise the harness; a record from one is a development
   reference and is not admissible as this class's reserve, because the
   resident set it measures is another machine's.
2. Bring up the node's own subsystems and confirm all five are `active
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

`/var/lib/azazel/run/core-reserve.json`. Runtime state, never a packaged file:
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

## 10. What is still not settled by any of this

Closing `HG-05` produces a number. It does not produce:

- **confinement** (`mio-runtime.md` §4) — it needs a running provider, which
  approval and staged activation have to admit first
- **the approval and staged-activation gates** — named by the contract,
  refusing for having no implementation
- **any claim about the model itself** — the reserve says a provider fits in
  memory, which is not a claim that it is useful, correct, or safe to consult
