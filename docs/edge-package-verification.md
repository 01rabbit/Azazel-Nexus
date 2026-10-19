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
| `running` | a probe established that the shipped `azazel-edge-core.service` payload is up |

`edge-baseline-ready` needs **all five**. `activation.EdgeBaselineState` holds
them, and `edge_package.py` is the only module in the product that builds one
— a static scan in `tests/unit/test_wizard_and_cli.py` keeps that true.

`EdgeBaselineState.launchable` requires the first four checks; only
`EDGE_BASELINE` unit admission uses it (#198). The fourth comes from the
supporting probe running the verified binary's fixed `--health` under the pinned
contract, independently of the payload unit. Running is the consequence of
starting. An activation grant permits launch and never implies readiness;
`ready`, status, projections and inspection events keep all five checks.
The lease-bearing daemon path reads the installed package and fresh probe file
on every pass. Missing, stale or unreadable probe results leave health and
running false; inspection errors establish no checks. Lease, node health and
commissioning requirements are unchanged. The boot refusing pass still supplies
no lease, no Edge evidence and `healthy=False`, and grants nothing.

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

## 7. Where health and running come from: `az-edge-probed`

`tests/unit/test_boundary_static.py` forbids the library from importing
`subprocess`: Nexus's library half has not commissioned an operational
surface, and a status command that spawned the component it reports on would
be a status command with a side effect.

So the two checks that need something run are answered by a **separate
one-shot runtime service**, `az-edge-probed`
([#72](https://github.com/01rabbit/Azazel-Nexus/issues/72)), which writes a
bounded state file the library reads. **`status` stays read-only**: it starts
nothing, stops nothing, retries nothing and probes nothing.

### The trust this places on the probe is small, on purpose

| check | who establishes it |
| --- | --- |
| `package_present` | the library, from the files, every read |
| `version_matches` | the library, from the files, every read |
| `digest_matches` | the library, from the files, every read |
| `health_endpoint_healthy` | the probe |
| `running` | the probe |

A probe result can therefore **withhold** readiness but never invent a package
that is not there. It is used only when it names the same version and the same
artifact digest the library just derived; a result about a different package
is a result about something else.

### Three ways a result supplies nothing

* **Stale** — older than its own TTL. An old answer about a running process is
  not a weak answer, it is an answer about a different moment.
* **Mismatched** — it names another version or another digest.
* **Unverifiable** — the artifact on disk does not match its own manifest, so
  a result agreeing with that manifest agrees with nothing to rely on.

All three produce `not-checked`, never `failed`. **Staleness never promotes,
and it never accuses either**: an operator sent to restart a healthy Edge
because a probe went stale is an operator doing harm on our word.

### Everything the probe touches is fixed in code

The package directory, the pinned version, the health argv, the unit whose
state is read, and the state file's path. `main` takes no path, no unit, no
command — only `--print` — and a static scan asserts it.

**The health command it runs is the one fixed in code, not the one the
manifest declares.** The manifest declares the same argv and the probe checks
that they agree, but agreement is a *verification*, not a source: a manifest
is exactly the file an adversary who can reach the package can rewrite.

Before running anything the probe requires the package present, the version
pinned, the archive digest re-derived, **and the unpacked binary about to run
to match the digest the manifest records for it** — because an intact archive
says nothing about the file next to it that actually executes.

### It starts nothing

Running state is read over D-Bus through an injected `call(method, unit)`, the
same shape `units.DbusUnitManager` uses: a typed parameter, no `systemctl`, no
`PATH` lookup, no argument splitting. The methods are an allowlist of two,
both read-only. With no D-Bus connection — a container, a host without
systemd, a permission refusal — `running` is `not-checked` with that reason.

The installed probe gets `systemd_bus.EdgeUnitStateReader`: the controller's
fixed system-bus transport (fixed socket, manager-identity check, timeouts),
narrowed to `GetUnit` plus `LoadState`/`ActiveState`/`SubState` of
`azazel-edge-core.service`'s object, connected on first read and closed after.
It has no mask, unmask or enable verb. `active`/`running` passes; any other
state, or systemd holding no unit object (`NoSuchUnit`), is `failed` because
nothing is running it; an unreachable bus or an unreadable reply is
`not-checked`. Until #195 the installed probe supplied no reader at all, so
`running` was always `not-checked` and `edge-baseline-ready` was unreachable.

`az-edge-probed` is the **one** module in the runtime distribution permitted
to start a process, contained the way `fabric_boundary.py` contains the Fabric
import. `tests/unit/test_runtime_activated.py` exempts it by name and asserts
it still needs the exemption; `tests/unit/test_edge_probed.py` holds the
narrower rules inside it — one `subprocess.run`, no shell, a fixed
environment, a deadline, and an argv built only from module constants.

### The unit

`azazel-edge-probed.service`, `Type=oneshot`, account `azprobe`, masked at
install like every other governed unit. It is `SUPPORTING` rather than
`EDGE_BASELINE`: an `EDGE_BASELINE` unit needs a verified Edge package before
it may be granted, and this is the unit that establishes whether one is
healthy and running. A probe that could only run once Edge was established
could never establish it.

The result is `/var/lib/azazel/run/edge-probe/edge-probe.json`
(`edge_package.PROBE_STATE_PATH`), in a leaf of its own that the installer
creates `azprobe:azazel-operator 2750`. It is written as a temporary file in
that leaf and renamed into place -- a rename needs the directory, not the file,
writable -- so the leaf is the unit's whole `ReadWritePaths`. Like every other
unprivileged unit, the probe no longer holds the run root (`root:root 0711`,
traversal only) at the mount layer or by ownership.

Who reads it: `azazel-nexus status` reads the fixed path, as root or as a
member of `azazel-operator`. The run root lets anyone traverse; the leaf gives
the operator group read and search; the result itself is `0644`. An absent
file is reported as `not-checked`, not as an error.

Before this leaf existed the record lived at the run root, where `azprobe`
could not create its temporary file (`Permission denied`, exit 2), so `status`
always reported `not-checked`. That file was never written on an installed
node, so there is no old location to migrate.

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
  been run against an installed Edge Core on real hardware. Every probe run
  CI exercises uses a fake health command and a fake unit reader; no real
  `azazel-edge-core --health` and no real systemd has answered. HG-01 through
  HG-07 stay open ([hardware gates](hardware-gates.md)).
- **Authenticity of the package.** §3.
- **That the probe has run.** Until it does, health and running are
  `not-checked` and `edge-baseline-ready` is withheld. §7.
- **Anything about enforcement.** Nexus verifies a package that declares
  itself observe-only and refuses one that does not. It grants no enforcement
  authority, and the deterministic arbiter in Azazel-Edge remains the only
  thing that decides.

### The Edge Core payload unit (I0)

Nexus ships `azazel-edge-core.service`, running the fixed verified-package
binary `/opt/azazel/edge-core/bin/azazel-edge-core` as `azedge`. No manifest
supplies its command or environment. The unit fixes the health contract's
observe-only posture: `AZAZEL_DEFENSE_ENFORCE=false`,
`AZAZEL_DEFENSE_DRY_RUN=true`, `AZAZEL_DEFENSE_ENFORCE_LEVEL=advisory`, and
`AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO=false`.

It reads `/var/log/suricata/eve.json` through the optional
`ReadOnlyPaths=-/var/log/suricata` (a host without Suricata yet still starts
it; Edge Core waits for the file) and the packaged `config/redirect_policy.yaml`. Deployment must provide
`azedge` narrowly scoped read/search permission on the Suricata directory and
file (including rotated files); the installer grants no broad group membership.
The installer creates `/var/lib/azazel/edge-core` as `azedge:root 0700` for
`release-ledger.json`. Only that leaf is writable;
no capabilities or internet address families are granted. The private ledger
must not be populated from an enforcing deployment: Edge reconciles due
releases at startup even when new enforcement is disabled.

`AZAZEL_FORWARD_AI=true` sends events to
`/var/lib/azazel/run/edge-intake/edge-intake.sock`. `AZAZEL_FORWARD_LOG=false`: Edge's own
JSONL copy has no rotation and no ceiling, so the bounded record is the
intake's; every event still reaches the journal through stdout, rate limited.
The unit declares no `RuntimeDirectory` (it owns nothing under `/run`, and one
would chown `/run/azazel` and remove it on stop; the intake socket
follows the node's socket layout under `/var/lib/azazel/run`) and runs with
`PrivateNetwork=yes`. Intake and its socket permissions belong to I1. No intake
receiver ships in I0, and the unit adds no dependency on it.

The installer masks the unit and its preset disables it. It is registered
only in the existing `EDGE_BASELINE` activation tier. #198 resolves first-start
admission by requiring the four package checks before enabling it; all five
readiness checks remain unchanged. The supporting probe starts no service.
Activation enables admitted units for a later boot and has no `StartUnit`
operation. Admission neither records nor displays `edge-baseline-ready`.


`health_endpoint_healthy` means the fixed `--health` of the verified binary
answered healthy under the pinned contract with the pinned version. The
observe-only posture is established by the manifest posture checked under
`package_present`; the running unit's posture is established by the fixed unit
environment (I0). Health does not observe the running process.

After admission, a unit that never becomes running (for example, a crash loop)
keeps `edge-baseline-ready` at no. The one-shot probe can still pass its health
check during a crash loop. Detecting that degradation and narrowing the unit
is degradation/watchdog work for a separate issue.
