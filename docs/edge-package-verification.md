# Verifying the local Edge Core package

Status: **implemented and wired** (`src/azazel_nexus/edge_package.py`,
rendered by `azazel-nexus status`), unit tested and mutation checked. Issuer
authentication, revocation and the rollback floor (§3a–§3c) are
**implemented, unit tested, and not configured on any node**: no issuer key
exists and Edge signs nothing yet.
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
on every pass. Missing, stale, other-boot or unreadable probe results leave
health and running false; inspection errors establish no checks. Lease, node health and
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

## 3. The digest is not authenticity, and issuer authentication is a separate fact

`contract/azazel-edge-core/pin.json` carries `signed: false`. A matching
digest establishes integrity **against accidental change** — a truncated copy,
a half-written file, the wrong build put in place. It does not establish
integrity against an adversary who can rewrite the package, because that
adversary rewrites the manifest and its digest with it.

So every inspection — passing or not — carries a caveat, `as_event` carries
it, and `azazel-nexus status` prints it under the edge section. A limit
recorded only in a design document is a limit nobody reads.

A manifest that claims `signed: true` is **refused as a security finding**,
not believed. The manifest's own claim is not what Nexus checks: an absent
claim of authenticity denies reliance; a claim nothing checks invites it.
That refusal is unchanged by §3a.

### 3a. Two facts, reported side by side (`src/azazel_nexus/edge_issuer.py`)

Status: **implemented, not configured on any node**. Unit tested with
test-only keys; no issuer key exists, no Edge package has been signed, and
nothing here has run against a real Edge deployment.

Every inspection carries an `IssuerVerification` with two booleans that are
never derived from each other:

| field | established by |
| --- | --- |
| `digest_verified` | the artifact re-derives to the digest its manifest declares (the `digest_matches` comparison, taken *before* revocation narrows it) |
| `issuer_authenticated` | a detached Ed25519 signature beside the manifest verifies over the canonical manifest under the administrator-configured issuer key |

A matching digest with no signature reports `digest_verified: true,
issuer_authenticated: false`; a valid signature over a manifest whose artifact
was replaced reports the reverse. Both appear in the inspection event
(`digest_verified`, `issuer_authenticated` and an `issuer` object), on the
status screen (§8) and, as fixed labels with no digest, version or key, in
the activation pass's `observed_inputs.edge_issuer`.

**The signature.** `<manifest>.sig` beside the manifest, exactly 64 raw bytes,
over `azazel-nexus/edge-package-manifest/v1\0` followed by the manifest's
canonical JSON: sorted keys, no insignificant whitespace, UTF-8 without
escaping; a duplicate key, a non-integer number, `NaN` or more than 64 KiB is
refused rather than canonicalised. The signature file is opened without
following links and must be a regular file of exactly that size. The bytes
signed must parse to the same manifest the package checks read, so a manifest
swapped between the two reads cannot have one version checked and another
authenticated. Verification is `signature.verify_detached`, the
standard-library verifier Knowledge Lite already uses; no dependency was
added, and Nexus still holds no signing key.

**The trust anchor.** `/etc/azazel/edge-issuer/issuer.json`:

```json
{"schema": "azazel-nexus/edge-issuer-anchor/v1", "issuer": "<name>", "public_key": "<64 lower-case hex>"}
```

Read from `/` through no-follow descriptors; every directory and the file
must be root-owned and not group or other writable, the file a single link
and at most 64 KiB, the key a canonical, non-small-order Ed25519 point
(`signature.parse_public_key`). The directory is meant to be `root 0755` and
the files `0644`: they hold nothing secret, and `status` reads them as the
operator. The installer does not create the directory.

**The anchor file decides whether anything changes.** Exactly:

| situation | effect on accept/refuse |
| --- | --- |
| no `issuer.json` and no floor (every node today) | **none**: `issuer_authenticated` is false with the fixed reason `not_configured`, the caveat is the unsigned one above, and the five checks accept and refuse exactly what they did before |
| no `issuer.json`, and a `revocations.signed` beside it | **none**: nothing can verify the list, so it carries no authority; reported as the note `revocations_present_without_anchor` |
| no `issuer.json`, and `/etc/azazel/edge-issuer` or a directory above it group/other writable, not root-owned or a link | **none**; reported as the note `config_directory_unprotected` |
| `issuer.json` present, and it or a directory above it unsafe, or it malformed | **refused** (`trust_refused`): `digest_matches` fails as a security finding, because the revocation state cannot be established |
| `/etc/azazel/edge-issuer` exists and this user cannot list it | `trust_unreadable`: whether an anchor is there is unknown, so `digest_matches` is `not-checked` *for this user* (an operator's `status`); root, which the activation pass runs as, reads the real state. Keep the directory `0755` |
| a floor is present, with or without an anchor | the floor is **enforced** (§3b). Removing the anchor does not remove the floor |

Notes appear on the status screen (`issuer notes (no effect on acceptance)`)
and in the inspection and activation records as fixed labels.

Requiring issuer authentication for admission would refuse every package that
ships today (Edge's packager writes no signature), so it is **not** a setting
here; it is an owner decision (§3c).

| `issuer_status` | when |
| --- | --- |
| `not_configured` | no anchor file (whatever else is there; see the table above) |
| `trust_refused` / `trust_unreadable` | the anchor file is unsafe or malformed / the configuration directory is not readable by this user |
| `not_inspected` / `package_refused` | no package root / the package check failed, so no manifest was examined |
| `manifest_refused` | the manifest has no canonical form, or changed between reads |
| `no_signature` | an anchor is configured and there is no `<manifest>.sig` |
| `signature_unreadable` | linked, not a regular file, or not 64 bytes |
| `signature_invalid` | the manifest changed after signing, or another key signed it |
| `authenticated` | the signature verifies under the configured key |

When the issuer is authenticated the caveat says what that does not add: it
authenticates the issuer's statement about the package, not the package's
behaviour, and it establishes no check on its own.

### 3b. Revocation and the rollback floor only narrow

Both apply whenever they are present, and each turns a check that would pass
into a **security finding**; neither can turn any failure into a pass. Both
are applied by `inspect` (so by `status` and by the activation pass's Edge
state) and by `installed_package_digest` (so a revoked or rolled-back package
is refused at `generation-publish` and binds nothing at activation).

**Revocation.** `/etc/azazel/edge-issuer/revocations.signed`, the Knowledge
Lite single-signature transport: 64 signature bytes, then the canonical
payload, signed by the configured issuer key over its own domain
(`azazel-nexus/edge-package-revocation/v1\0`):

```json
{"issued_at": "...", "package": "azazel-edge-core", "revoked_digests": ["sha256:..."], "revoked_versions": ["0.1.0"], "schema": "azazel-nexus/edge-package-revocation/v1", "sequence": 1}
```

A revoked digest fails `digest_matches` even when the artifact matches (and
`digest_verified` stays true: the refusal is the revocation's). A revoked
version fails `version_matches`. With an anchor configured, a list that does
not verify or names another package fails `digest_matches`: an unreadable
revocation state is not "nothing revoked". With no anchor, a list changes
nothing (§3a).

**The rollback floor.** `/var/lib/azazel/state/edge-issuer/floor.json`
(`root:root 0755` leaf, `root:root 0644` file, one canonical record of
`version`, `package_digest`, `revocation_sequence` and `revocation_digest`,
the SHA-256 of the accepted list's canonical payload). It is checked on every
inspection, with or without an anchor:

- a version below the floor fails `version_matches` (`below_floor`);
- the floor's version with a different digest fails `version_matches`
  (`replayed`): an older, validly signed manifest of the same version put
  back;
- a revocation list older than the floor's `revocation_sequence`, missing
  once one is held, or at that sequence with a different payload, fails
  `digest_matches` (`rolled_back`);
- a floor that exists and is not exactly one canonical, root-owned record
  fails `version_matches`; one this user may not read is `not-checked`.

Only `azazel_nexus_runtime/edge_issuer_floor.py` writes it, raise-only,
through a private temporary file, fsync, rename, directory fsync and
read-back; the leaf's mode is set explicitly, so a restrictive umask does not
hide it from the operator. The activation controller calls it only after it
has granted `azazel-edge-core.service`, written its marker **and appended the
pass record** — a grant withdrawn because its record failed never raises the
floor — and it raises the floor only when the installed package's issuer is
authenticated, its digest verified, no revocation names it, the floor held,
and its digest is the one the activation evidence was bound to. An
unauthenticated activation — every activation today — never moves it and
adds nothing to the ledger. Otherwise the outcome is recorded as its own
`activation.edge_issuer_floor` event; failing to raise, or to record that,
grants and withdraws nothing.

**Before the first authenticated activation there is no floor**, so
replaying an older, validly signed revocation list cannot be detected until
then: only the floor remembers which list was in force.

The version in force is still pinned exactly (`0.1.0`), so today the floor
can only ever hold that version; it starts to matter when the pin moves.

This is local trust: root can replace or delete any of these files. The
protection is against a rewritten package directory and against replaying
an older package, manifest or revocation list, not against the node's
administrator.

### 3c. What still needs the owner

- **Who the issuer is**, and whether revocation is signed by the issuer key
  (as implemented) or by a separate revocation role as Knowledge Lite does.
- **Issuer key creation and custody**: generation ceremony, where the private
  key lives, rotation, and what happens on compromise. Nexus holds no signing
  key and must not.
- **Edge-side signing.** Azazel-Edge's
  `packaging/nexus-core/nexus_core_package.py` hard-codes `signed: False` and
  writes no detached signature. Producing `<manifest>.sig` is an Edge change,
  out of scope here; so is any change to the manifest's own `signed` field,
  which this node still refuses when true (a change to `pin.json` and this
  refusal would have to land together).
- **Whether issuer authentication becomes required** for admission, and how
  a node is moved from "not configured" to "required" without refusing the
  package it runs.
- **Whether a recovery tool is wanted.** Today recovery is the manual root
  procedure in §3d, like the activation high-water recovery; there is no
  lowering path in code, by design.

### 3d. Recovering from a wrongly raised floor (root, manual)

There is no command that lowers or clears the floor. If it was raised wrongly
(for example by an activation of a package that should not have been
admitted), an administrator does this as root, on the node, with nothing
being activated at the time:

1. Read what is there and keep it with the incident record:
   `stat -c '%U:%G %a %h' /var/lib/azazel/state/edge-issuer /var/lib/azazel/state/edge-issuer/floor.json`
   (expected: `root:root 755` and `root:root 644 1`) and
   `cat /var/lib/azazel/state/edge-issuer/floor.json`. Anything else in the
   leaf (a `.floor.json.partial` left by a crash) may be removed with it.
2. Remove the file: `rm /var/lib/azazel/state/edge-issuer/floor.json`.
   Do not hand-edit it to a lower value: a hand-written record is either
   refused (not canonical) or is a silent lowering nobody can tell from an
   attack.
3. Record why, by whom and when in the operations log. No audit event is
   written for this; the floor's absence is visible in `status`
   (`rollback floor: absent`).

Effects, all until the next recorded, authenticated edge-core activation
raises the floor again:

- any version and digest the exact pin admits is accepted again — rollback
  protection is off;
- the revocation sequence and list digest are forgotten, so an older, validly
  signed revocation list is accepted again (§3b);
- the issuer anchor, the revocation list in force and everything else are
  unchanged.

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

### Four ways a result supplies nothing

* **Stale** — older than its own TTL. An old answer about a running process is
  not a weak answer, it is an answer about a different moment.
* **From another boot** — probe contract v2
  (`azazel-nexus/edge-probe/v2`, #206 P5) records `boot_id`, the kernel's
  `/proc/sys/kernel/random/boot_id` when the probe ran. A reader uses a result
  only when it equals the current boot's id, in addition to the TTL; the
  reason reads `stale: from another boot`. A v1 result names no boot and is
  always stale (`stale: the probe result is azazel-nexus/edge-probe/v1 ...`),
  and so is every result when the current boot's id cannot be read.
* **Mismatched** — it names another version or another digest.
* **Unverifiable** — the artifact on disk does not match its own manifest, so
  a result agreeing with that manifest agrees with nothing to rely on.

All four produce `not-checked`, never `failed`. **Staleness never promotes,
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

### The boot id is read the protected way

Both the probe and every reader use `edge_package.read_current_boot_id`: no
symlink is followed, the file must be a regular file owned by root and
writable by nobody else, the read is bounded, and the value must be a
canonical lowercase UUID. Every production caller reads the kernel's
`/proc/sys/kernel/random/boot_id` with no argument: `status` has no flag that
names another boot id file and no relaxed owner rule.
The probe reads it **before** probing; when it cannot, it probes nothing,
writes nothing and exits 2, and `write_result` refuses any outcome without a
canonical boot id. `azazel-nexus status` prints a line saying the boot id
could not be read rather than letting every result go stale silently.

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

### The boot preflight (#206 P5, design E1)

`azazel-edge-probe-preflight.service` runs the same
`/usr/libexec/azazel/az-edge-probed` as the same `azprobe`, with the same
sandbox (`RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, the shared
hardening, `ReadWritePaths` limited to the result leaf). Its profile is derived
from the governed probe's in `hardening.py`, so the two cannot drift. It is
**not governed**: it is not in `activation.CORE_UNITS`, the pass never masks
or unmasks it, and no lease admits it. It is `Type=oneshot`,
`Before=azazel-activated.service`, `WantedBy=multi-user.target`,
`TimeoutStartSec=60s`, with no `After=`/`Requires=` on the controller and no
`RuntimeDirectory=`. The installer installs it and enables it beside the
controller (the preset enables both, exactly); it is never masked.

**What it runs, and when.** It runs at **every boot, before any approval or
lease is consulted** -- it is not admitted by anything -- and it executes the
digest-verified package's `bin/azazel-edge-core --health` (the fixed argv, only
after the archive and the unpacked binary re-derive their manifest digests) as
`azprobe`, plus a read-only D-Bus property query. It **grants nothing**: it
starts, enables and unmasks no unit, and its result can only narrow what the
pass grants.

It exists because the governed probe runs only after the controller, so at the
boot pass no result from this boot existed and edge-core was always withheld
(`edge_not_ready`). With the preflight, the pass reads health from this boot.
`running` at that moment is `failed` (edge-core has not started yet), which is
expected: launch admission needs the four package checks, of which health is
the only one from the probe, and `edge-baseline-ready` still needs all five.
If the preflight fails or is slow, the controller still runs (it is ordered
after, not dependent) and Edge stays withheld. A failed preflight leaves the
unit `failed`, so systemd reports the system `degraded`; it does not block
the boot. It opens no network socket,
grants nothing and can only narrow what the pass grants.

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
    digest_verified: no
    issuer_authenticated: no (not_configured)
        no Edge issuer trust anchor is configured on this node ...
    revocation: not_configured (revoked: not_evaluated)
    rollback floor: absent
    caveat: the Edge manifest is not signed, so a matching digest establishes
        integrity against accidental change and not authenticity ...
```

`digest_verified` and `issuer_authenticated` are two lines because they are
two facts (§3a).

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
- **Authenticity of the package.** No issuer is configured on any node and
  Edge signs nothing, so `issuer_authenticated` is false everywhere today.
  Even when it is true, it authenticates the issuer's statement, not the
  package's behaviour (§3a–§3c).
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
would be chowned to it and removed on stop; no unit declares the bare
`/run/azazel` any more, #206 P6; the intake socket
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
