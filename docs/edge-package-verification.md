# Verifying the local Edge Core package

Status: **implemented and wired** (`src/azazel_nexus/edge_package.py`,
rendered by `azazel-nexus status`), unit tested and mutation checked.
This is [#44](https://github.com/01rabbit/Azazel-Nexus/issues/44); the
producing side is
[Azazel-Edge#424](https://github.com/01rabbit/Azazel-Edge/issues/424).

Related: [the six axes](integration-display.md) ·
[hardware gates](hardware-gates.md) ·
[degradation matrix](degradation-matrix.md) ·
[contract ownership](contract-ownership.md)

## 1. What Nexus looks at, and what it may conclude

Five checks, and nothing else:

| check | what establishes it |
| --- | --- |
| `package_present` | the manifest and the artifact are both at the fixed location, and the manifest declares the pinned contract, package, architecture and an observe-only posture |
| `version_matches` | the manifest's version is the pinned one |
| `digest_matches` | the artifact re-derives to the digest the manifest declares |
| `health_endpoint_healthy` | the Edge health contract answered, and all four of its conditions held |
| `running` | a probe established that the payload is up |

`edge-baseline-ready` needs **all five**. `activation.EdgeBaselineState` holds
them, and `edge_package.py` is the only module in the product that builds one
— a static scan in `tests/unit/test_wizard_and_cli.py` keeps that true.

**Accepting the package establishes at most the first three.** Edge's own
manifest says so in `not_established_by_accepting_this_package`, and nothing
here treats a present, matched package as readiness.

## 2. Three answers, because "nobody looked" is not "it failed"

Every check reports `passed`, `failed` or `not-checked`.

`not-checked` exists because a node that reported a health failure it never
attempted would have an operator chasing a fault that does not exist. It
grants nothing either: unknown never grants, and only `passed` counts towards
ready. `EdgeInspection.state()` maps it to `False` and leaves the reason in
the finding rather than flattening it.

When `package_present` fails, the other four are `not-checked` and say so —
there was nothing to check them against. Four failures nobody attempted would
be four faults nobody has.

## 3. The digest is not signed, and a pass says so

`contract/azazel-edge-core/pin.json` carries `signed: false`. A matching
digest establishes integrity **against accidental change** — a truncated copy,
a half-written file, the wrong build put in place. It does not establish
integrity against an adversary who can rewrite the package, because that
adversary rewrites the manifest and its digest with it.

So every inspection — passing or not — carries that caveat, `as_event` carries
it, and `azazel-nexus status` prints it under the edge section. A limit
recorded only in a design document is a limit nobody reads.

A manifest that claims `signed: true` is **refused as a security finding**,
not believed. This node can verify no signature on an Edge package. An absent
claim of authenticity denies reliance; a claim nothing checks invites it.

## 4. A digest mismatch is a finding, not a failed step

"Edge is not installed" is a deployment step. "Edge is installed and its
artifact is not the one its manifest describes" is a security finding, and the
two call for opposite actions. The finding carries `security=True`, the status
screen marks the line `SECURITY FINDING`, and the edge axis leads with
`digest-mismatch` rather than a generic not-ready word.

**It is reported and never repaired.** Nothing in this module writes: a static
scan refuses `write_text`, `mkdir`, `unlink`, `replace` and their siblings,
because a verifier that repairs is a verifier that destroys the evidence.

## 5. The health contract: four conditions, all of them

Edge ships a one-shot CLI contract. A report is healthy only when the process
**exits 0** *and* stdout **parses as JSON** *and* its `contract` is the pinned
one *and* its `status` is `healthy`. All four, so a truncated or garbled
answer cannot read as healthy, and an exit code alone is not the contract.

Nexus adds one: a healthy report whose `version` is not the pinned one is a
**security finding**, because the binary that answered is not the one the
manifest describes.

A healthy answer does **not** fill in `running`. Edge's manifest says the
one-shot check establishes nothing about a daemon, and the two are separate
findings here for that reason.

## 6. Where the contract comes from

`contract/azazel-edge-core/` is a verbatim copy of what Azazel-Edge commits.
Nexus does not import the packager: the two repositories build and test
separately, and a consumer that needed the producer's source in its own CI
would be sharing an implementation rather than verifying a contract.

The three documents carry no digest and no timestamp, so the copy does not go
stale every time the Edge binary is recompiled, and a diff here always means
the contract itself changed. Both sides hold the tie mechanically:

| side | guard |
| --- | --- |
| Edge | `tests/test_nexus_contract_export.py` regenerates and asserts byte-identity |
| Nexus | `tests/unit/test_edge_package.py` asserts every constant equals what the copy says, and that every field read here is one the schema promises |

`contract/azazel-edge-core/PROVENANCE.md` records which Edge commit the copy
came from and that it is copied, never edited here.

## 7. What this node cannot reach on its own

`tests/unit/test_boundary_static.py` forbids this package from importing
`subprocess`: Nexus has not commissioned an operational surface, and a status
command that spawned the component it reports on would be a status command
with a side effect.

So no runner is shipped for either probe, and the consequence is stated rather
than hidden:

> **On a node built from this repository, `health_endpoint_healthy` and
> `running` are always `not-checked`, and `edge-baseline-ready` is therefore
> unreachable even with a present, matched package.**

What this repository does deliver is the **parser** for both answers — all
four health conditions, each tested against the contract Edge ships — and the
injection points for the probes. Who runs the Edge health contract, and what
establishes that the payload is up, crosses that boundary and is
[#72](https://github.com/01rabbit/Azazel-Nexus/issues/72) rather than
something this module decided on its own.

## 7b. No network-configuration path exists on this node

Edge's manifest carries `startup.command` and `startup.observe_only_env`.
**Nexus reads neither.** A consumer that read a command would be one step
from running it, and `tests/unit/test_edge_package.py` asserts no lookup of
either field survives in the module.

The rest of the argument is import-level: `test_boundary_static.py` refuses
`socket`, `subprocess`, `ctypes` and their siblings across the whole package,
so there is nothing here that could carry out a startup instruction even if it
read one. The two guards cover different halves — a field read now and acted
on later, and a mechanism to act at all.

The Edge side matches it: the package configures no network, declares
`network_configuration_change: false`, reads and writes nothing under
`installer/`, and starts nothing.

## 8. On the screen

```text
edge core (local): digest-mismatch  [/opt/azazel/edge-core]
    package_present: passed
        ... and its posture is observe-only
    version_matches: passed
        the manifest declares 0.1.0, which is the pinned version
    digest_matches: failed  SECURITY FINDING
        the manifest declares sha256:... and the artifact re-derives to
        sha256:... The artifact on disk is not the one the manifest
        describes. ... do not repair it by rewriting either side
    health_endpoint_healthy: not-checked
        no health probe is configured on this node ... Nobody looked, which
        is not the same fact as an unhealthy answer
    running: not-checked
        this build speaks to no service manager ... (HG-01)
    caveat: the Edge manifest is not signed, so a matching digest establishes
        integrity against accidental change and not authenticity ...
```

All five are printed whatever the leading word says. Stopping at the first
failure would leave an operator who fixed it guessing at what comes next —
and would hide a digest mismatch behind a version mismatch found first.

The section and the `edge` axis are rendered from **one** inspection, so a
screen cannot describe two nodes.

## 9. What this does not establish

- **That any of this works against a real Edge deployment.** Nothing here has
  been run against an installed Edge Core on real hardware; HG-01 through
  HG-06 stay open ([hardware gates](hardware-gates.md)).
- **Authenticity of the package.** §3.
- **`edge-baseline-ready` on a node built from this repository.** §7.
- **Anything about enforcement.** Nexus verifies a package that declares
  itself observe-only and refuses one that does not. It grants no enforcement
  authority, and the deterministic arbiter in Azazel-Edge remains the only
  thing that decides.
