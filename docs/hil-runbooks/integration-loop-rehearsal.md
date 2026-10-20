# Integrated loop — VM rehearsal through the installed units (never evidence)

Owner: [#195](https://github.com/01rabbit/Azazel-Nexus/issues/195) (I5 of
[#190](https://github.com/01rabbit/Azazel-Nexus/issues/190)).
Status: **rehearsed once on a Debian 13 aarch64 VM (2026-10-20, main
`f544893`); hardware-unverified**. The run, its deviations and the answers to
the **要確認** points are recorded in
[#195](https://github.com/01rabbit/Azazel-Nexus/issues/195#issuecomment-6277975662).
It found that the installed probe never read `running`, so `verified-ready`
was unreachable; [#221](https://github.com/01rabbit/Azazel-Nexus/pull/221)
fixed that.

This runbook runs the [integrated defensive loop](../integration-loop.md) on
the rehearsal VM with the installed units instead of the harness: a real
x86_64 Edge Core package built by Edge's packager, started by systemd as
`azazel-edge-core.service`, feeding `azazel-edge-intaked.service`,
`azazel-incident-explaind.service`, auditd, `azazel-mio-entryd.service` and
`azazel-knowledge-lited.service`. It is the "same run on the rehearsal VM"
that [I5](../integration-loop.md#i5--end-to-end) names as the next step.

Like [§17 of the admission runbook](mio-admission.md#17-vm-rehearsal-never-evidence)
and the [commissioning rehearsal](commissioning-rehearsal.md), a VM rehearses
**mechanics only**. Nothing here is HIL evidence, nothing is attested for a
campaign, it is not an [HG-07](hg-07.md) record, and every artefact is
labelled `rehearsal`.

**What this run cannot show today.** The production activation pass supplies
no lease (§5), so no regular path admits the loop's units on this build
([#206](https://github.com/01rabbit/Azazel-Nexus/issues/206)). The
loop is therefore started by the rehearsal-only procedure of §6, and the
result says *activation admission: not exercised*. On real hardware that
procedure is forbidden ([HG-07](hg-07.md) step 3).

Text marked **要確認 (to confirm)** is a point this runbook could not settle
from the code or existing documents; resolve it on the VM and record the
answer with the run.

## 1. Preconditions and safety

1. **The VM.** Debian 13 x86_64 with systemd as PID 1, Nexus installed with
   `packaging/install.sh` from a reviewed checkout, and commissioned as in the
   [commissioning rehearsal](commissioning-rehearsal.md): `azazel-mio-entryd.service`
   must be able to load its `mio-node`, `mio-trust` and `mio-profile`
   credentials. The installed build must include the I0–I3 and I5 changes
   (the four loop units exist under `/lib/systemd/system`). Below, CHECKOUT is
   the reviewed source directory the VM was installed from, at the installed
   commit, and `PYTHON` is `/opt/azazel-nexus/venv/bin/python`; commands spell
   the full paths. Node commands run from `/`.
2. **Snapshot the VM** before starting. The incident ledger, the explanation
   records and the audit chain are append-only; a snapshot is the only
   complete restore. Also keep a root `0600` tarball of `/etc/azazel`,
   `/var/lib/azazel` and, if present, `/var/log/suricata` with its current
   owners and modes. `/etc/azazel` holds the node's commissioning material and
   M.I.O. credentials: write the tarball only under `/root` (for example
   `/root/azn-rehearsal/backup-<time>.tgz`, directory `0700`), never to a
   shared or user directory and never off the VM, and delete it at the end of
   the run (§10) once the VM is back in its intended state.
3. **No keys, no approvals.** Do not create, copy or edit an operator seed,
   an activation approval, a lease or a bootstrap selection for this run, and
   do not bring a real one onto the VM. Signing stays on the operator's own
   workstation with `tools/operator_sign.py` as in the
   [commissioning rehearsal](commissioning-rehearsal.md#1-keys-and-who-does-what);
   this runbook needs no signature at all.
4. **No lab marker interference.** If `/etc/azazel-lab/LAB-HOST` exists the
   VM ran lab code; follow the commissioning rehearsal's precondition 4 before
   continuing, or stop.
5. **Do not reboot** while any unit is started by §6. The boot-time
   activation pass re-masks every governed unit and, finding one still running,
   ends with `RollbackFailed` (§6.4).
6. **Not evidence.** Results are VM software rehearsal. They are never
   attested, never validated as an `azazel-nexus/hil-gate/v1` record and never
   attached to a hardware gate.

## 2. Build the Edge package (separate x86_64 host)

The package is produced by Azazel-Edge's
`packaging/nexus-core/nexus_core_package.py` at a fixed revision; Nexus does
not build it ([Edge package verification](../edge-package-verification.md#6-where-the-contract-comes-from)).
Build on a separate **x86_64** Linux host or container, for example a
`debian:trixie` amd64 container, so that the binary matches the VM's
architecture and C library. The packager labels every package `x86_64` and
does not check the build host, so a build on another architecture produces a
mislabelled package that the VM cannot run. For an aarch64 VM, build on an
aarch64 host instead; the package then carries an aarch64 binary under the
packager's fixed `x86_64` name, which the run record must state.

Revision: use an Azazel-Edge revision that includes Azazel-Edge#428 (rule
technique ids in normalized events; merge commit `2e9aab8`), otherwise every
event carries no technique id and Knowledge lookup is `skipped`. Record the
full commit id. **要確認:** whether a newer Edge revision is preferred; the
contract check below must pass for whichever is used.

In an Azazel-Edge checkout at that revision, on the build host:

```sh
cargo build --release --manifest-path rust/azazel-edge-core/Cargo.toml
file rust/azazel-edge-core/target/release/azazel-edge-core
python3 packaging/nexus-core/nexus_core_package.py --out dist/nexus-core
python3 packaging/nexus-core/nexus_core_package.py --emit-contract --contract-dir /tmp/azn-edge-contract
diff /tmp/azn-edge-contract/pin.json CHECKOUT/contract/azazel-edge-core/pin.json
diff /tmp/azn-edge-contract/manifest-schema.json CHECKOUT/contract/azazel-edge-core/manifest-schema.json
diff /tmp/azn-edge-contract/health-schema.json CHECKOUT/contract/azazel-edge-core/health-schema.json
sha256sum dist/nexus-core/*
```

`file` must report an x86-64 ELF executable. The packager refuses (exit 2,
`refused: ...`) when the binary is missing or its `--version` disagrees with
`Cargo.toml`. All three `diff`s must be empty: a difference means the Edge
contract changed and Nexus's pinned copy must be refreshed first, not this
package forced through. The output directory holds
`azazel-edge-core-0.1.0-x86_64.tar.gz`, `azazel-edge-core-0.1.0-x86_64.manifest.json`
and the manifest's `.sha256` file. Keep the `sha256sum` output with the run
record.

Copy the manifest and the archive to the VM (for example with `scp` to the
operator's home directory). Nothing else from the build host goes to the VM.

## 3. Install the package on the VM

The package location is fixed: `/opt/azazel/edge-core`
(`edge_package.EDGE_PACKAGE_ROOT`). The installer does not create it. The
library expects the manifest and the archive side by side at that root, and
the probe and the unit run the unpacked `bin/azazel-edge-core` beside them;
the unit also names the unpacked `config/redirect_policy.yaml`. Everything is
owned by root and writable by nobody else: a package an Edge or probe account
could rewrite would be verified against a manifest the same account could
rewrite.

**Verify the archive before extracting it.** The manifest's `digest` is
`sha256:<hex>`; `sha256sum` prints the bare hex, so compare without the
prefix:

```sh
sha256sum ~/azazel-edge-core-0.1.0-x86_64.tar.gz
/opt/azazel-nexus/venv/bin/python -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["digest"].removeprefix("sha256:"))' ~/azazel-edge-core-0.1.0-x86_64.manifest.json
```

The two hex strings must be equal. Stop here if they are not.

```sh
sudo install -d -m 0755 -o root -g root /opt/azazel /opt/azazel/edge-core
sudo install -m 0644 -o root -g root ~/azazel-edge-core-0.1.0-x86_64.manifest.json ~/azazel-edge-core-0.1.0-x86_64.tar.gz /opt/azazel/edge-core/
sudo sh -c 'umask 022 && tar -xzf /opt/azazel/edge-core/azazel-edge-core-0.1.0-x86_64.tar.gz -C /opt/azazel/edge-core --no-same-owner'
sudo find /opt/azazel/edge-core -exec stat -c '%U:%G %a %n' {} +
```

Expected: every entry `root:root`; directories `755`, `bin/azazel-edge-core`
`755`, the manifest, the archive and `config/redirect_policy.yaml` `644`
(the packager writes those modes into the archive).

**Verify before anything runs the binary.** Compare the archive and the
unpacked binary with the manifest:

```sh
sha256sum /opt/azazel/edge-core/azazel-edge-core-0.1.0-x86_64.tar.gz /opt/azazel/edge-core/bin/azazel-edge-core
/opt/azazel-nexus/venv/bin/python -I -c 'import json, sys; m = json.load(open(sys.argv[1])); print(m["digest"], m["artifact"]); [print(c["digest"], c["path"]) for c in m["components"]]' /opt/azazel/edge-core/azazel-edge-core-0.1.0-x86_64.manifest.json
sudo /opt/azazel-nexus/venv/bin/azazel-nexus status
```

The archive's SHA-256 must equal the manifest `digest`, and the binary's the
`bin/azazel-edge-core` component digest (compare the hex after `sha256:`). In `azazel-nexus status`, the
`edge core (local):` section must show `package_present`, `version_matches`
and `digest_matches` passed, `health_endpoint_healthy` and `running`
`not-checked`, and the unsigned-manifest caveat. A mismatch is a **security
finding**: stop, keep the files, and do not rewrite the manifest or the
archive to make them agree ([§4 of the verification contract](../edge-package-verification.md#4-a-digest-mismatch-is-a-finding-not-a-failed-step)).

## 4. Suricata `eve.json` access for `azedge`

`azazel-edge-core.service` runs as `azedge`, reads
`/var/log/suricata/eve.json` through `ReadOnlyPaths=-/var/log/suricata`, and
declares **no** `SupplementaryGroups=`. The installer grants no group
membership; deployment provides the narrowest read access
([unit description](../edge-package-verification.md#the-edge-core-payload-unit-i0)).
Use `azedge`'s own primary group and nothing broader (never `adm`):

```sh
id azedge
stat -c '%U:%G %a %n' /var/log/suricata /var/log/suricata/eve.json
```

`id` must show a primary group `azedge` and no other group. **要確認:** that
Debian 13 `useradd --system` created that group on the VM (the installer
relies on the distribution default). Record the `stat` output before
changing anything; §10 restores it.

**With Suricata installed.** Keep the existing owner, change only the group
and modes; the setgid bit makes files Suricata creates later inherit the group:

```sh
sudo chgrp azedge /var/log/suricata /var/log/suricata/eve.json
sudo chmod 2710 /var/log/suricata
sudo chmod 0640 /var/log/suricata/eve.json
sudo runuser -u azedge -- test -r /var/log/suricata/eve.json && echo readable || echo NOT-readable
```

Edge Core opens the fixed `eve.json` path and never lists the directory, so
the directory needs only search (`x`) for the group (`2710`): the other logs
in it stay unreadable to `azedge`. An ACL (`setfacl -m u:azedge:x
/var/log/suricata` and `setfacl -m u:azedge:r /var/log/suricata/eve.json`)
is an alternative that leaves the group untouched.

**要確認:** the mode Suricata gives a newly created `eve.json` and the
`create` line of the distribution's logrotate rule for Suricata; both must
keep a rotated file at `0640` with group `azedge`. Edge does not read rotated
files, and a file it cannot read is silently not read.

**Without Suricata.** Create the directory and an empty file for the
rehearsal; synthetic alerts are appended in §8.

```sh
sudo install -d -m 2710 -o root -g azedge /var/log/suricata
sudo install -m 0640 -o root -g azedge /dev/null /var/log/suricata/eve.json
sudo runuser -u azedge -- test -r /var/log/suricata/eve.json && echo readable || echo NOT-readable
```

Edge Core starts reading at the **end** of an existing file (the unit does not
set `AZAZEL_EVE_FROM_START`), so lines must be appended **after** the unit has
started; lines already present are never read.

## 5. Activation: what the regular path does today

The loop's units are governed like every other unit: installed masked and
preset-disabled, and enabled only by `azazel-activated.service` for a later
boot. A grant never starts a unit; activation has no `StartUnit` operation.

| unit | tier | what a grant needs |
| --- | --- | --- |
| `azazel-edge-intaked.service`, `azazel-incident-explaind.service`, `azazel-edge-probed.service`, `azazel-mio-entryd.service`, `azazel-knowledge-lited.service`, `azazel-auditd.service` | `SUPPORTING` | verified generation, node health, a lease for that generation |
| `azazel-edge-core.service` | `EDGE_BASELINE` | everything above, plus the four package checks (#198) |

For `EDGE_BASELINE` the lease-bearing pass reads the installed package and the
probe file on every pass (`installed_baseline_state`); `launchable` needs
`package_present`, `version_matches`, `digest_matches` and a fresh,
package-bound `health_endpoint_healthy`. Running is not required to admit the
unit, and `edge-baseline-ready` still needs all five checks
([I0](../integration-loop.md#i0--foundations)). Health comes from
`az-edge-probed` (§6.2), which is `SUPPORTING` so that it can run before Edge
is admitted. The result must also be from **this boot** (probe contract v2,
[#206](https://github.com/01rabbit/Azazel-Nexus/issues/206) P5): the
ungoverned `azazel-edge-probe-preflight.service` runs the same probe before
the controller at every boot, so the boot pass sees health from this boot.

**On this build no lease exists.** `az-activated` composes its pass with
`lease=None` and `healthy=False` (`runtime/src/azazel_nexus_runtime/activated.py`),
so it grants nothing, and it appends `activation.inputs_incomplete` naming
the producers it lacks, including `activation_approval_loader`, `node_health`
and `edge_evidence`. The approval reader in `activation_store.py`
(`/etc/azazel/activation/approval.json` and `approval.sig`) is not wired
into that pass ([runtime activation](../runtime-activation-remaining.md#activation-approval-storage-versus-independent-context)),
and `tools/operator_sign.py` can sign a v2 activation approval payload
([§3.1](../activation-observe-baseline.md#31-activation-approval-schema-v2-boot-free))
but nothing produces that payload, installs the signature or reads it into
the pass. There is no command that produces an activation approval or a
lease, and none may be hand-written for this run.

Record what the last boot's pass did:

```sh
sudo journalctl -b -u azazel-activated.service -o cat
sudo tail -n 1 /var/lib/azazel/state/activation.jsonl
```

Expect `az-activated completed safely: granted=0, ...` and, as the last
ledger entry, `activation.inputs_incomplete` whose `missing_producers`
include `activation_approval_loader`. If that name is absent, a later build
has wired the approval path: stop and revise this section before using §6
(**要確認** on every new build).

The supporting-only bootstrap covers only `azazel-auditd.service` and
`azazel-commissiond.service` (`BOOTSTRAP_UNITS`). If this boot ran one,
auditd may already be active; it never admits the loop's units. A selection
left from an earlier boot makes every pass fail closed
([§17](mio-admission.md#17-vm-rehearsal-never-evidence)).

## 6. Rehearsal-only start (alternative to activation)

This section substitutes for the activation grant that §5 cannot produce.
It is **only** for a disposable VM, and the run record must say it was used.
§17 of the admission runbook governs it:

> Units started by hand for a rehearsal (`systemctl unmask`, `--job-mode=ignore-requirements`)
> must be stopped and cleared before the next activation pass:
> `systemctl stop azazel-mio-locald azazel-mio-entryd azazel-knowledge-lited azazel-mio-remoted`,
> `systemctl reset-failed`, then re-mask. Otherwise azazel-activated's normal pass
> cannot confirm them stopped and ends with `RollbackFailed` (masking does not stop
> a running process; a `failed` unit also counts as unconfirmed).

Here the same applies to the four loop units as well (§10).
`--job-mode=ignore-requirements` is required: every loop unit has
`Requires=azazel-activated.service`, and pulling in the controller would run
an activation pass, which first re-masks every governed unit.

### 6.1 Advisory and audit daemons

```sh
systemctl is-active azazel-activated.service
sudo systemctl unmask azazel-knowledge-lited.service azazel-mio-entryd.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-edge-probed.service azazel-edge-core.service
sudo systemctl daemon-reload
sudo systemctl start --job-mode=ignore-requirements azazel-knowledge-lited.service
sudo systemctl start --job-mode=ignore-requirements azazel-mio-entryd.service
systemctl is-active azazel-auditd.service
```

The controller must be `inactive` (its boot pass finished); otherwise stop
and find out why. If auditd is `active` (a bootstrap ran this boot), use it.
Otherwise it cannot be started by hand: it has
`BindsTo=azazel-activated.service`. As §17 says, run a copy with the same
`ExecStart` and properties. Make it a unit **file** under `/run` (gone at
reboot), without the controller dependencies and the `[Install]` section:

```sh
sudo sed -e '/^Requires=azazel-activated\.service$/d' -e '/^BindsTo=azazel-activated\.service$/d' -e '/^After=azazel-activated\.service$/d' -e '/^\[Install\]$/,$d' /lib/systemd/system/azazel-auditd.service | sudo tee /run/systemd/system/azn-rehearsal-auditd.service >/dev/null
sudo systemd-analyze verify /run/systemd/system/azn-rehearsal-auditd.service
sudo systemctl daemon-reload
sudo systemctl start azn-rehearsal-auditd.service
```

`systemd-analyze verify` must print no warning for the copy. It runs the same
`/usr/libexec/azazel/az-auditd` as `azaudit` on the real chain under
`/var/lib/azazel/state/audit`; only one auditd may run at a time. **要確認:**
this copy has not yet been exercised on a VM.

### 6.2 Intake, explainer and the four-check probe

Start intake before the explainer, and both before Edge, so that the
explainer's first start seeds at the current end of the incident chain and
Edge's first connection finds the socket:

```sh
sudo systemctl start --job-mode=ignore-requirements azazel-edge-intaked.service
sudo systemctl start --job-mode=ignore-requirements azazel-incident-explaind.service
sudo systemctl start --job-mode=ignore-requirements azazel-edge-probed.service
sudo cat /var/lib/azazel/run/edge-probe/edge-probe.json
sudo /opt/azazel-nexus/venv/bin/azazel-nexus status
```

`azazel-edge-probed.service` is a one-shot: it reads this boot's id from
`/proc/sys/kernel/random/boot_id` (when it cannot, it writes nothing and
exits 2), runs the fixed `bin/azazel-edge-core --health` after re-checking the
archive and binary digests, reads the payload unit's state over D-Bus, writes
`/var/lib/azazel/run/edge-probe/edge-probe.json` (`azazel-nexus/edge-probe/v2`
with `boot_id`, `0644`, 300 s TTL) and exits. A reader uses the result only in
the boot it names; a v1 file left from an earlier build, or any file from the
previous boot, reads `stale` and is `not-checked`, never `failed`.

The boot preflight `azazel-edge-probe-preflight.service` (same binary, same
`azprobe`, same sandbox; not governed, enabled by the installer, never masked)
runs at every boot, before any approval is consulted, and executes the
digest-verified package's `bin/azazel-edge-core --health` as `azprobe`; it
grants nothing. It will already have written a result at boot, before the
controller, with `running` `failed` because Edge had not started. **`running`
keeps reading `failed` after the preflight until the governed
`azazel-edge-probed.service` runs again after edge-core has started** (§6.3);
that is expected, not a fault. A failing preflight leaves its unit `failed`
and `systemctl is-system-running` reports `degraded`, but it does not block
the boot: the controller still runs and Edge stays withheld. Record
`systemctl show -p Result,ExecMainStatus azazel-edge-probe-preflight.service`
and the result's `observed_at`; `systemctl is-enabled` must say `enabled` and
it must not appear among the masked units. Without unmasking the probe unit, the same
installed wrapper can be run as its account outside the unit sandbox:
`sudo runuser -u azprobe -- /usr/libexec/azazel/az-edge-probed --print`.
**要確認:** that this gives the same result as the unit (its sandbox and
D-Bus access differ outside the unit). Record which was used.

Expected now: `health` `passed`, `running` `failed` (the payload unit is
inactive), and in `status` the edge section reads `not-running` with
`package_present`, `version_matches`, `digest_matches` and
`health_endpoint_healthy` passed. That is the four-check state #198 admits
on; record it, and note that no pass consumed it (§5).

### 6.3 Edge Core

```sh
START=$(date '+%Y-%m-%d %H:%M:%S')
sudo systemctl start --job-mode=ignore-requirements azazel-edge-core.service
sudo journalctl -u azazel-edge-core.service --since "$START" -o cat | grep -F 'azazel-edge-core started:'
sudo systemctl start --job-mode=ignore-requirements azazel-edge-probed.service
sudo /opt/azazel-nexus/venv/bin/azazel-nexus status
```

Keep `START` in the shell for §8 and §9. The startup line must show
`defense_enforce=false`, `defense_dry_run=true`,
`defense_enforce_level=advisory`, `high_impact_auto=false`,
`ai_socket=/var/lib/azazel/run/edge-intake/edge-intake.sock` and
`from_start=false`. Record only those fields: the line also names an
interface. After the second probe, within its 300 s TTL, the edge section
must read `verified-ready` with all five checks passed.

### 6.4 While units are started by hand

Do not reboot, do not `systemctl start` any governed unit without
`--job-mode=ignore-requirements`, and do not start
`azazel-activated.service`. Any of these runs an activation pass against
running units and ends in `RollbackFailed`.

## 7. Knowledge Lite

Read the current state first:

```sh
sudo /opt/azazel-nexus/venv/bin/azazel-nexus status
sudo /opt/azazel-nexus/venv/bin/azazel-nexus setup
```

If Knowledge Lite reads `available` and its bundle carries ATT&CK
techniques, the explanations should carry citations (the harness bundle
cites `T1110` for the synthetic alerts below). Otherwise run the loop
anyway: explanation records then show `knowledge_state` `unavailable` with
failure code `knowledge_unavailable` (or `skipped` when the event has no
technique ids), the explainer's last attempt shows knowledge unavailable,
and recent rows carry no citations. Missing Knowledge never blocks the
deterministic path.

Supplying a bundle follows the existing offline route only
([offline operator import](../knowledge-lite-consumer.md#7-offline-operator-import),
[trust store](../knowledge-lite-trust.md#6-the-trust-store)): an artifact in
`/var/lib/azazel/knowledge/inbox`, imported by the store owner `azknowledge`
against commissioned trust under `/var/lib/azazel/lite-trust`. Since #186 the
import creates and tightens `admitted/`, `state/` and `quarantine/` to `0750`
whatever the umask, writes files `0600`, and records `lite.import.store_tightened`
when it had to tighten a directory; an import run as another user produces
files the daemon refuses. Since #187 the bundle is made durable before the
watermark; a crash during the very first import can still leave
`admitted/current.tar.gz` without a watermark, which reads as
`state_untrusted` until an operator moves it aside and imports again.
**要確認:** this build has no installed operator command for the trust pin or
the import (the harness drives `LiteImport` from the library); how the VM's
trust was provisioned, if at all, must be confirmed before attempting an
import. Do not pin keys generated for this run to make Knowledge read
`available`.

## 8. Drive the loop

**With Suricata,** generate traffic that raises an alert on the monitored
interface; citations need a rule whose metadata carries
`mitre_technique_id`. **Without Suricata,** append the harness's synthetic
eve lines (two alerts on one incident, the second more severe, and one flow
event Edge must drop; addresses `10.0.0.8` and `10.0.0.1`). Generate them
unprivileged from the checkout, then append as root:

```sh
cd CHECKOUT && PYTHONPATH=. /opt/azazel-nexus/venv/bin/python -c 'import json; from tools.e2e_loop import eve_events; print("".join(json.dumps(e) + "\n" for e in eve_events()), end="")' > ~/azn-rehearsal-eve.jsonl
sudo sh -c 'cat ~/azn-rehearsal-eve.jsonl >> /var/log/suricata/eve.json'
```

(`tools/e2e_loop.py` derives them from `tests/fixtures/edge/rust_event_engine_v1.jsonl`.)
Root's append keeps the file's owner, group and mode. Wait about ten seconds
before §9. The explainer calls at most six times a minute, and after a restart
with an existing cursor it waits 60 s before its first call.

## 9. Checks

Run each after the loop has settled. A ledger verification that reports a
torn final line during an append is retried after a few seconds.

**Edge decisions are dry runs.** Only Edge's journal holds its decisions:

```sh
sudo journalctl -u azazel-edge-core.service --since "$START" -o cat | grep '^{' | /opt/azazel-nexus/venv/bin/python -I -c 'import json, sys; [print(d["defense"]["action"], "dry_run=%s" % d["enforcement_status"]["dry_run"]) for d in map(json.loads, sys.stdin) if "defense" in d]'
```

Synthetic run: exactly `notify dry_run=True` then `isolate dry_run=True`; the
flow event produces no line. Every line must say `dry_run=True`.

**Intake liveness and evidence.** Status is operator-readable; evidence is
private (`0700 azintake:root`), so read it as root and print no event:

```sh
sudo cat /var/lib/azazel/run/edge-intake-status/status.json
sudo journalctl -u azazel-edge-core.service --since "$START" -o cat | grep '^{' | sudo /opt/azazel-nexus/venv/bin/python -I -c 'import json, sys; from pathlib import Path; from azazel_nexus.edge_intake import EvidenceRecord, parse_edge_event; lines = [l.rstrip("\n").encode() for l in sys.stdin]; want = [EvidenceRecord.receive(parse_edge_event(l), lambda: 0.0).digest for l in lines]; have = [json.loads(l)["digest"] for p in sorted(Path("/var/lib/azazel/edge-intake/evidence").glob("*.jsonl")) for l in p.read_text().splitlines()]; print("decisions", len(want), "evidence", len(have), "digests match", bool(want) and have[-len(want):] == want)'
```

Expect `accepted` 2 (synthetic run), an empty or all-zero `refused`,
`storage_failed` false, and `digests match True`: the stored digests are
re-derived from Edge's own lines, as the harness does. With an Edge Core that
includes Azazel-Edge#432, status also holds `edge_forward` with `dropped` 0,
`failed` 0 and `sent` 2 (Edge's own count, not evidence); with an older one the
key is absent.

**Incident ledger and audit chain verify.**

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -c 'from pathlib import Path; from azazel_nexus_runtime.auditd import SegmentedLedger
for name in ("/var/lib/azazel/edge-incidents", "/var/lib/azazel/state/audit"):
    ledger = SegmentedLedger(Path(name)); ledger.verify()
    print(name, "verified", [e.event["event_type"] for e in ledger if e.event["event_type"].startswith("edge.incident.")][-6:])'
```

Both must print `verified`. The incident ledger ends with
`edge.incident.reset` (intake start), `edge.incident.opened`,
`edge.incident.updated`; the audit chain ends with `edge.incident.opened`,
`edge.incident.escalated`. Forwarding is best effort: a missing audit record
is read together with `audit_forward_dropped` and `audit_forward_refused` in
status, not as a broken loop.

**Explanation records** (private `0700`; printed fields carry no address):

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -c 'import json; from pathlib import Path; from azazel_nexus.incident_explain import read_record
for p in sorted(Path("/var/lib/azazel/incident-explain/explanations").glob("*.jsonl")):
    for line in p.read_text().splitlines():
        r = read_record(json.loads(line)); print(r["transition"], r["edge_would"], r["mio"]["route"], r["knowledge_state"], [k["technique_id"] for k in r["knowledge_refs"]], r["failure_codes"])'
```

Expect two records, `opened` then `updated`, Edge's actions unchanged, route
`deterministic handoff` (admission is closed), and `knowledge_state` as §7
predicts.

**Recent incidents.**

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -c 'from pathlib import Path; from azazel_nexus.incident_explain import read_recent_incidents
v = read_recent_incidents(Path("/var/lib/azazel/run/incident-explain-status/recent.json").read_bytes())
print("refused" if v is None else [(r["state"], r["count"], r["edge_would"], [k["technique_id"] for k in r["explanation"]["knowledge_refs"]]) for r in v["incidents"]])'
```

Expect one `open` row with count 2 and `isolate` (synthetic run), with
citations only when Knowledge is available.

**Operator status.**

```sh
sudo /opt/azazel-nexus/venv/bin/azazel-nexus status
```

The `edge loop:` section must show intake and explainer `running` (an idle
explainer may read stale), the accepted and explained counts, and the incident
with `Edge would isolate (observe-only, not executed)` and any citation. The
edge section must still read `verified-ready` if the probe is fresh.

**No address in Nexus output; addresses in Edge's journal.**

```sh
sudo /opt/azazel-nexus/venv/bin/azazel-nexus status | grep -cwF -e 10.0.0.8 -e 10.0.0.1
sudo grep -rlwF -e 10.0.0.8 -e 10.0.0.1 /var/lib/azazel/run/incident-explain-status/recent.json /var/lib/azazel/incident-explain/explanations /var/lib/azazel/state/audit
sudo journalctl -u azazel-edge-core.service --since "$START" -o cat | grep -cwF 10.0.0.8
```

The first must print `0` and the second nothing. The third must be non-zero:
Edge's journal is Edge's record and carries addresses, targets and planned
commands ([Edge Core's own output](../integration-loop.md#i4--redirect-to-deception-lite-later));
never export it with the run record. Evidence and the incident ledger are
private and not part of this check. With real Suricata traffic, use the
addresses of that traffic and do not write them down.

**Sandbox.**

```sh
sudo systemd-analyze security --no-pager azazel-edge-core.service azazel-edge-intaked.service azazel-incident-explaind.service
systemctl show azazel-edge-core.service -p User -p SupplementaryGroups -p PrivateNetwork -p RestrictAddressFamilies -p IPAddressDeny -p CapabilityBoundingSet -p ReadWritePaths -p ReadOnlyPaths
ps -o user=,group=,supgid= -p "$(systemctl show -p MainPID --value azazel-edge-core.service)"
```

Record each unit's exposure level. **要確認:** no accepted baseline exists
yet, so the first VM run sets it. For Edge Core: `User=azedge`, empty
`SupplementaryGroups`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`,
empty capability set, writable only `/var/lib/azazel/edge-core`, and `ps`
showing no supplementary group beyond `azedge`.

## 10. Clean up and roll back

Stop Edge first, then intake, so the explainer can forward the shutdown close:

```sh
sudo systemctl stop azazel-edge-core.service
sudo systemctl stop azazel-edge-intaked.service
```

After about ten seconds, rerun the ledger verification of §9: both chains end
with `edge.incident.closed` (reason `shutdown`). Then stop the rest, clear
failed states and re-mask every unit §6 unmasked:

```sh
sudo systemctl stop azazel-incident-explaind.service azazel-mio-entryd.service azazel-knowledge-lited.service azazel-edge-probed.service
sudo systemctl stop azn-rehearsal-auditd.service
sudo systemctl reset-failed
sudo systemctl mask azazel-knowledge-lited.service azazel-mio-entryd.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-edge-probed.service azazel-edge-core.service
sudo rm -f /run/systemd/system/azn-rehearsal-auditd.service && sudo systemctl daemon-reload
systemctl is-enabled azazel-edge-core.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-edge-probed.service azazel-mio-entryd.service azazel-knowledge-lited.service
systemctl is-active azazel-edge-core.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-mio-entryd.service azazel-knowledge-lited.service azn-rehearsal-auditd.service
```

Skip the auditd copy lines if §6.1 used an auditd that was already active.
Every unit must read `masked` and `inactive`. The next boot's activation pass
must then end with `az-activated completed safely: granted=0` and not with
`RollbackFailed`; check it once after the next reboot with
`journalctl -b -u azazel-activated.service`.

On the VM, delete `~/azn-rehearsal-eve.jsonl`, the copied
`~/azazel-edge-core-0.1.0-x86_64.tar.gz` and `.manifest.json`, and the §1
backup tarball under `/root/azn-rehearsal/` once the VM is in its intended
state. On the build host, delete `/tmp/azn-edge-contract` (and `dist/` if it
is not kept). The probe result and the status snapshots under
`/var/lib/azazel/run` stay; they expire by their TTL and freshness checks.
Reverting to the snapshot undoes everything, including ledger appends.
Without a snapshot: restore `/var/log/suricata` to the recorded owner, group
and modes (or remove it if this run created it, after stopping Edge), and
either keep the verified package at `/opt/azazel/edge-core` or remove that
directory. Ledger entries, explanation records, intake evidence and the
explainer cursor stay; they are append-only history, and the explainer resumes
from its cursor next time. Never edit a ledger to remove the rehearsal.

## 11. What to record

Record in issue #195, labelled `rehearsal`:

- `activation admission: not exercised (#206)`, and the `missing_producers`
  list from the activation ledger at the time of the run.
- Nexus commit installed, Edge commit, the build host class (architecture,
  distribution, toolchain versions), and the `sha256sum` of the archive, the
  manifest and the unpacked binary.
- VM class facts only: Debian release, kernel and systemd versions,
  architecture. No hostname, address, interface name, MAC, boot id, machine
  id or serial ([inventory confidentiality](../inventory-confidentiality.md)).
- The activation outcome line and the `missing_producers` list from §5, and
  that §6 substituted for admission (plus the auditd copy, the probe method,
  and synthetic eve or Suricata).
- The probe results before and after Edge started (`health`, `running`,
  version, digest, `observed_at`) and the five edge findings from status.
- Edge's posture fields and its decision list (`notify`/`isolate`,
  `dry_run`), not its lines.
- Intake counts, explainer counts, `audit_forward_*` counters, ledger
  verification results and `edge.incident.*` sequences, explanation route and
  `knowledge_state`, recent row state and citations. Replace incident ids
  with `inc-<redacted>` in anything that leaves the VM.
- The privacy check results (Nexus outputs: no match; Edge journal: matched),
  never the matching lines.
- `systemd-analyze security` exposure levels and the `systemctl show` values.
- Every deviation and every **要確認** answered.

Never record keys, seeds, signatures, approvals, the eve file, evidence or
incident ledger contents, or any export of Edge's journal. This record is VM
software rehearsal: it is not HG-07 evidence and it does not establish
activation admission, hardware behaviour or package authenticity.

## 12. Not covered on a VM

- Activation admitting the loop's units: #198's grant path needs a lease
  producer that does not exist yet ([#206](https://github.com/01rabbit/Azazel-Nexus/issues/206)).
- HG-07 on real hardware with the real deployment path ([HG-07](hg-07.md)).
- Enforcement by the shipped Edge Core (Azazel-Edge#412) and I4 decoys.
- Real M.I.O. advice: admission is closed, so every frame is a deterministic
  handoff ([M.I.O. runtime](../mio-runtime.md)).
