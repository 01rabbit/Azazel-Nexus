# Activation at boot — VM rehearsal of #242 P1 and #206 P6 (never evidence)

Owner: [#206](https://github.com/01rabbit/Azazel-Nexus/issues/206) (P6) and
[#242](https://github.com/01rabbit/Azazel-Nexus/issues/242) (P1).
Status: **not yet run** as one sequence (written against main `c1a1117`);
hardware-unverified. Partial VM checks that shaped this runbook are in §0.

This runbook takes the rehearsal VM from encrypted commissioning storage
opened at boot to the regular activation path admitting the integrated loop's
units, in one flow:

1. **#242 P1** — the commissioning LUKS volume is opened at boot by a
   passphrase the operator types (console or `systemd-tty-ask-password-agent`
   over SSH), never by a key file
   ([commissioning storage at boot](../commissioning-storage-at-boot.md) §4);
2. **#206 P6** — `az-activation generation-publish` → `request` → signature on
   the operator's workstation → `install` → reboot (unlock) → the pass grants
   and writes `/run/azazel-activation/granted/<unit>` → reboot (unlock) → the
   granted units actually start
   ([observe-baseline activation](../activation-observe-baseline.md) §4 P6, §8);
3. the negative runs of the P6 row and of #242 P1, each leaving the units
   masked **and not started**.

Like the [commissioning rehearsal](commissioning-rehearsal.md) and the
[integrated loop rehearsal](integration-loop-rehearsal.md), a VM rehearses
**mechanics only**. This is a VM rehearsal, **not hardware evidence**: nothing
here is HIL evidence, nothing is attested for a campaign, it is not an HG-08
record, and every artefact is labelled `rehearsal`. A loop-file LUKS volume
passes the same `luks_backed` check as a real dm-crypt device but proves
nothing about real storage.

Text marked **要確認 (to confirm)** is a point this runbook could not settle
from the code or existing documents; resolve it on the VM and record the
answer with the run.

## 0. Already confirmed on the VM (mechanics only)

The coordinator checked the following on the rehearsal VM (Debian 13 aarch64,
systemd 257.13, main `c1a1117`). It is a check of the mechanism, **not
hardware evidence**, and it does not replace the full sequence below.

1. **The crypttab generator is a separate package.** On Debian 13 the
   generator ships in `systemd-cryptsetup`. With `cryptsetup-bin` alone
   `/etc/crypttab` is ignored, and the `fstab` mount only waits for a device
   that never appears. §3.1 installs `systemd-cryptsetup`.
2. **A regular-file source becomes a loop device.** For a regular-file
   crypttab source the generator adds `modprobe@loop.service` and
   `RequiresMountsFor=<image>` and sets the loop device up by itself. With
   `nofail`, `systemd-cryptsetup@azn\x2dcommissioning.service` is only
   `Wanted` by `cryptsetup.target`.
3. **Locked boot.** With the passphrase not typed, about 301 s after boot the
   unit logged `Failed to query password: Timer expired`, the mount failed with
   `Dependency failed` (result `dependency`), and `azazel-activated.service`
   started right after; the mount did not hold it back. Nothing started and
   `/run/azazel-activation/granted` was not created. `systemctl
   is-system-running` read `degraded`: the cryptsetup unit failed, and the
   controller failed for the reason in item 4.
4. **A stale bootstrap selection blocks the ordinary pass.** A selection left
   in `/etc/azazel/bootstrap` by an earlier rehearsal is bound to another
   boot, so every pass fails closed with `ApprovalRefused: optional protected
   bootstrap selection refused <- protected bootstrap selection refused: boot
   binding differs from the current boot` and never reaches the ordinary
   activation pass. With the selection moved aside under `/root`, the
   controller ended with `az-activated completed safely: granted=0,
   withheld=12, reasons=no_generation`. §2 precondition 7 covers this.

## 1. Roles and secrets

Each step below names who performs it.

| who | does |
| --- | --- |
| **Operator** (the owner, in person) | sets the LUKS passphrase and types it at every boot (console, or `sudo systemd-tty-ask-password-agent` in **their own** SSH session); signs three payloads on **their own workstation** with [`tools/operator_sign.py`](../../tools/operator_sign.py): the role draft (`commissioning`), the full proposal (`commissioning-proposal`) and the activation approval (`activation`); makes the interactive commissioning choices (roles and `CONFIRM`, ceiling and `EXPORT`); decides whether to go on at each stop point |
| **Assistant** (the worker) | deployment and file placement, `generation-publish`, `request`, `install`, reboots on the operator's go-ahead, and every status check |

Rules that hold throughout:

- **The passphrase, the seed and any key are never stored anywhere** — not on
  the node, not in a file, a shell history, a crypttab key field, a
  `systemd-creds` credential, an issue, a log or a chat — and **never given to
  the assistant**. The operator types the passphrase only at an interactive
  prompt (never as an argument, through a pipe or with `--key-file`). The
  assistant never runs `systemd-tty-ask-password-agent`, `cryptsetup open`,
  `luksFormat` or `luksAddKey`, and never reads a seed.
- **Use a VM-only rehearsal operator.** Its key is generated for this VM only,
  enrolled only here (with the existing
  [explicit administrator enrollment](../debian-live-install.md#explicit-administrator-enrollment)
  procedure, if it is not enrolled yet), never enrolled on any real node, and
  its seed is destroyed at the end (§10). Its signatures are bound to this VM's
  node identity, generation and commissioning evidence and are never reused.
  Nothing in this runbook turns a rehearsal signature into a real approval.
- Only the 64-byte signatures return to the node. Payload copies on the
  workstation live in a private `0700` directory and are deleted after
  signing. The draft and proposal contain raw interface identity
  ([inventory confidentiality](../inventory-confidentiality.md)); the
  activation payload contains the commissioning digest and evidence binding.
  None of them is pasted into an issue, a log or a chat.

Notation: node commands run as root on the node from `/`. `PYTHON` is a
**placeholder**, not a command: replace it with
`/opt/azazel-nexus/venv/bin/python` in every `sudo PYTHON ...` line; `NODE` the SSH destination, `LABEL` the
rehearsal operator's enrolled label. `az-activation` is
`sudo PYTHON -I -m azazel_nexus_runtime.activation_cli` (the console script of
the same module, `runtime/pyproject.toml`); `az-nexus-commission` is
`sudo PYTHON -I -m azazel_nexus_runtime.commission_cli`.

## 2. Preconditions and safety

1. **Snapshot S0** of the VM before anything else (assistant, with the
   operator's agreement). Ledger appends, the high-water floor, an operator
   revocation (§8 N8) and a raised deployment epoch (§8 N7) cannot be undone
   otherwise. Then create the root-only directory every later step moves
   files aside into: `sudo install -d -m 0700 /root/azn-quarantine`.
2. **Installed code** at main `c1a1117` or later (includes #246's `After=`
   lines and #247), installed with `packaging/install.sh`. Assistant:
   `systemctl cat azazel-activated.service | grep -E 'After=(etc-azazel-commissioning|var-lib-azazel-secrets)\.mount'`
   prints both lines.
3. **No lab marker.** `/etc/azazel-lab/LAB-HOST` must be absent (the health
   check `lab_marker` fails on it); see
   [commissioning rehearsal §2](commissioning-rehearsal.md#2-preconditions).
4. **Every governed unit masked and inactive, no override.** Assistant:

   ```sh
   systemctl is-enabled azazel-auditd.service azazel-commissiond.service azazel-watchdog.service azazel-model-fetchd.service azazel-mio-locald.service azazel-mio-remoted.service azazel-mio-entryd.service azazel-knowledge-lited.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-edge-probed.service azazel-edge-core.service
   systemctl is-active  azazel-mio-entryd.service azazel-knowledge-lited.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-edge-probed.service azazel-edge-core.service
   systemd-delta --no-pager | grep -i azazel
   ```

   Expected: every unit `masked` and `inactive`; `systemd-delta` shows only
   `[MASKED]` lines for them, no `[EXTENDED]` or `[OVERRIDDEN]` (a drop-in or a
   non-mask unit file makes `generation-publish` refuse). No unit may still be
   running from a hand start of another rehearsal
   ([integrated loop rehearsal §6](integration-loop-rehearsal.md#6-rehearsal-only-start-alternative-to-activation)).
5. **No watchdog fence.** `node_health` fails on any fence or an unreadable
   store. Assistant: `sudo ls -l /var/lib/azazel/state/watchdog/` (owner
   `azwatch`) and, if `fences.json` exists,
   `sudo cat /var/lib/azazel/state/watchdog/fences.json` must hold no fence.
   A fence is the watchdog's decision: stop and report it, never clear it.
6. **The controller.** On the lab VM it is masked. Record
   `systemctl is-enabled azazel-activated.service`; it is unmasked only in §7.1.
7. **No stale bootstrap selection** (§0 item 4). Assistant:
   `sudo ls -la /etc/azazel/bootstrap/`. If `selection.json` or
   `selection.pending` exists, it is bound to another boot and every pass
   fails closed before the ordinary pass. With the operator's agreement move
   it aside, keeping it for restore (VM only; on a real node this is never
   done, see [§17 of the admission runbook](mio-admission.md#17-vm-rehearsal-never-evidence)):

   ```sh
   sudo mv /etc/azazel/bootstrap/selection.json /root/azn-quarantine/
   ```

   (and `selection.pending` likewise). `deployment.json` **stays**: the pass's
   `node_identity` producer needs the administrator deployment declaration.
   **要確認:** whether any other file in that directory belongs to a stale
   bootstrap run; move only what §0 item 4 showed blocking.
8. **Mission storage at boot.** `node_health` checks `resources`, which reads
   `mission_available_mib` from a separate, writable `/data` filesystem. The
   commissioning rehearsal mounted it by hand; for a boot pass it must be
   mounted before the controller. The controller has no `After=` on `/data`;
   only `local-fs.target` (reached before `basic.target`, which the controller
   follows) orders it. So the assistant adds the existing unencrypted image
   (`DATA_IMG`, from the commissioning rehearsal) **without** `nofail`:

   ```text
   # /etc/fstab -- rehearsal substitute for the mission volume
   DATA_IMG  /data  ext4  loop,nodev,nosuid,noexec  0  2
   ```

   With `nofail` the mount would leave `local-fs.target` and could race the
   pass. Without it, a missing image drops the boot to emergency mode; keep the
   console at hand. A real node's mission volume is encrypted; how it is opened
   at boot is outside #242 (**要確認**, §11).
9. **Edge variant.** Choose one and record it:
   - **Variant A (default):** policy scope = the five SUPPORTING loop units.
   - **Variant B:** also `azazel-edge-core.service`. Only if the VM already
     holds a verified Edge package at `/opt/azazel/edge-core` with Suricata
     access ([integrated loop rehearsal §2–§4](integration-loop-rehearsal.md#2-build-the-edge-package-separate-x86_64-host)),
     and `azazel-edge-probe-preflight.service` ended with `Result=success` on
     the last boot. Needed for §8 N5.
10. **Approval window.** The whole run (two positive boots, the negative boots
   and their restore boots) must fit in one approval's validity; §6.2 uses
   24 hours. An expired approval needs a new `request` and signature.

## 3. Commissioning storage opened at boot (#242 P1)

### 3.1 Packages (assistant)

```sh
sudo apt-get install cryptsetup-bin systemd-cryptsetup
```

`systemd-cryptsetup` carries the crypttab generator on Debian 13 (§0 item 1).
Without it `/etc/crypttab` is silently ignored.

### 3.2 Option A (default): a new passphrase-only volume

A fresh image keeps the run independent of earlier rehearsals. The volume of
the 2026-10-19 commissioning rehearsal stays closed and out of `crypttab`.

Assistant: `sudo fallocate -l 64M /var/lib/azn-rehearsal-luks/commissioning-p6.img`
(directory `0700` root, as in the commissioning rehearsal).

Operator, in their own terminal on the node:

```sh
sudo cryptsetup luksFormat --type luks2 /var/lib/azn-rehearsal-luks/commissioning-p6.img
sudo cryptsetup open /var/lib/azn-rehearsal-luks/commissioning-p6.img azn-commissioning
```

Assistant, with the mapping open:

```sh
sudo mkfs.ext4 -q /dev/mapper/azn-commissioning
sudo mount -o nodev,nosuid,noexec /dev/mapper/azn-commissioning /etc/azazel/commissioning
sudo rmdir /etc/azazel/commissioning/lost+found
sudo chown root:azcommission /etc/azazel/commissioning && sudo chmod 0750 /etc/azazel/commissioning
sudo umount /etc/azazel/commissioning && sudo cryptsetup close azn-commissioning
sudo cryptsetup luksDump /var/lib/azn-rehearsal-luks/commissioning-p6.img | grep -A1 '^Keyslots:'
```

Expected: one key slot.

### 3.3 Option B: reuse a volume made with a key file

Only if the operator prefers an existing volume that was opened with a key file
(`KEYFILE`, `IMG`). Operator, in their own terminal:

```sh
sudo cryptsetup luksAddKey --key-file KEYFILE IMG     # type the new passphrase twice
sudo cryptsetup open --test-passphrase IMG            # type it once more
sudo cryptsetup luksRemoveKey IMG KEYFILE             # removes the key file's slot
sudo shred -u KEYFILE
sudo cryptsetup luksDump IMG                          # exactly one key slot left
```

Then confirm nothing names the key file any more:
`sudo grep -rn KEYFILE /etc/crypttab /etc/fstab /etc/cryptsetup-initramfs 2>/dev/null`
prints nothing. Snapshot S0 still contains the key file and its slot: keep it
on the VM host only, and decide at §10 whether to delete it. A reused volume
already holds a draft and a proposal (both create-only), so §5 becomes
reviews only, and its signer is whoever signed them; record which.

### 3.4 crypttab and fstab (assistant)

First make sure no earlier line names the same mapping, mount point or
image: `grep -nE 'azn-commissioning|/etc/azazel/commissioning|/data' /etc/crypttab /etc/fstab`
must print nothing (or only the `/data` line of §2 item 8). An older line
is removed, not left beside the new one.

```text
# /etc/crypttab -- third field "none": no key file, the passphrase is typed
azn-commissioning  /var/lib/azn-rehearsal-luks/commissioning-p6.img  none  nofail,timeout=300
```

```text
# /etc/fstab
/dev/mapper/azn-commissioning  /etc/azazel/commissioning  ext4  nodev,nosuid,noexec,nofail,x-systemd.device-timeout=300s  0  0
```

No key file, no `systemd-creds`, no other stored factor. `/var/lib/azazel/secrets`
stays on the root filesystem on this VM (a recorded substitution); the
controller's `After=var-lib-azazel-secrets.mount` is then a no-op.

```sh
sudo systemctl daemon-reload
systemctl cat 'systemd-cryptsetup@azn\x2dcommissioning.service' | grep -E 'RequiresMountsFor|modprobe@loop'
systemctl show 'systemd-cryptsetup@azn\x2dcommissioning.service' -p WantedBy -p RequiredBy
systemctl show etc-azazel-commissioning.mount -p WantedBy -p RequiredBy -p Before
```

Expected (§0 item 2): `RequiresMountsFor=` the image and `modprobe@loop.service`;
the cryptsetup unit only `WantedBy=cryptsetup.target`; the mount not
`RequiredBy` `local-fs.target`. Record the three outputs (this answers the
design's "how a `nofail` entry is ordered").

### 3.5 First unlocked boot (controller still masked)

Assistant reboots on the operator's go-ahead (`sudo systemctl reboot`).
Operator types the passphrase at the console, or over SSH:
`sudo systemd-tty-ask-password-agent --query`. The boot waits for it at most
300 s; SSH is available meanwhile (`nofail`).

Assistant checks:

```sh
findmnt -no SOURCE,FSTYPE,OPTIONS /etc/azazel/commissioning
sudo cryptsetup status azn-commissioning | grep -E 'type|device|loop'
losetup -l -O NAME,BACK-FILE
findmnt -no SOURCE /data
stat -c '%U:%G %a' /etc/azazel/commissioning
```

Expected: `/dev/mapper/azn-commissioning ext4` with `nosuid,nodev,noexec`;
type `LUKS2` on a `/dev/loopN` backed by the image (set up by systemd, not by
hand); `/data` mounted; `root:azcommission 750`. If no loop device appears,
check §3.1 first.

## 4. Commissioning

Follow [commissioning rehearsal §3–§5](commissioning-rehearsal.md#3-storage-the-commissioning-tools-require)
on this volume, with these assignments:

1. **Commissioning key** (assistant): `/var/lib/azazel/secrets/commissioning.key`
   must exist; create it only if absent, as that runbook says.
2. **Old published signature** (assistant, Option A only): with a new volume,
   `proposal-review` refuses while `/etc/azazel/mio-profile/commissioning-proposal.sig`
   from the earlier run differs. Move it aside:
   `sudo mv /etc/azazel/mio-profile/commissioning-proposal.sig /root/azn-quarantine/`.
3. **Role draft.** Operator, in an interactive session
   (`ssh -t NODE 'cd / && sudo PYTHON -I -m azazel_nexus_runtime.commission_cli commission --operator LABEL --at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --draft-output /etc/azazel/commissioning/commissioning-draft.json'`):
   assigns roles, types `CONFIRM`. Assistant prints
   `sudo sha256sum /etc/azazel/commissioning/commissioning-draft.json`.
   **Operator signs on the workstation** (`--purpose commissioning`) and
   copies back only `draft.sig`. Assistant installs it as
   `/etc/azazel/commissioning/commissioning-draft.sig` (root `0600`) and runs
   `az-nexus-commission commission-review --operator LABEL`.
   Expected: `Signed draft review: assigned bindings verified.`
4. **Full proposal.** Operator: `ssh -t NODE 'cd / && sudo PYTHON -I -m azazel_nexus_runtime.commission_cli proposal-export --operator LABEL'`,
   chooses the ceiling, types `EXPORT`. Assistant prints the SHA-256 of
   `commissioning-proposal.json`. **Operator signs** (`--purpose
   commissioning-proposal`). Assistant installs
   `/etc/azazel/commissioning/commissioning-proposal.sig` (root `0600`) and runs
   `az-nexus-commission proposal-review --operator LABEL --check-current-hardware`.
   Expected: `Full proposal signature verified; current hardware fields match
   retained evidence. ...`, and `/etc/azazel/mio-profile/` holds only the new
   `commissioning-proposal.sig`.

The operator deletes `draft.json` and `proposal.json` from the workstation.

## 5. Activation policy (assistant)

`/etc/azazel/activation` exists as root `0700` (`install.sh`). The policy is
the exact canonical bytes (sorted keys, no whitespace, **no trailing
newline**); anything else is refused
([design §7](../activation-observe-baseline.md#7-p2-readers-inert)). Choose
floors below what the VM measures now and record both:

```sh
sudo df -B1 --output=target,avail,iavail /var/lib/azazel/state/bootstrap /var/lib/azazel/state/audit
sudo PYTHON -I -m azazel_nexus_runtime.commission_cli resources
```

When both directories are on one filesystem, the byte and inode floors are
added. Variant A, with rehearsal values (not a production recommendation):

```sh
printf '%s' '{"max_clock_skew_seconds":300,"max_lease_seconds":259200,"operators":["LABEL"],"resource_floors":{"min_mission_available_mib":64,"min_online_logical_cpus":1,"min_usable_memory_mib":512},"schema":"azazel-nexus/activation-policy/v1","state_floors":{"audit_bytes":16777216,"audit_inodes":256,"bootstrap_bytes":16777216,"bootstrap_inodes":256},"units":["azazel-edge-intaked.service","azazel-edge-probed.service","azazel-incident-explaind.service","azazel-knowledge-lited.service","azazel-mio-entryd.service"]}' \
  | sudo sh -c 'umask 077 && cat > /etc/azazel/activation/policy.json'
sudo stat -c '%U:%G %a %h' /etc/azazel/activation/policy.json
sudo PYTHON -I -c 'from azazel_nexus.activation_policy import load_activation_policy as l; p = l(); print(",".join(p.units), p.max_lease_seconds)'
```

Replace `LABEL` before running. Variant B puts `"azazel-edge-core.service"`
first in `units`. Expected: `root:root 600 1`, and the loader prints the units
and `259200`; a refusal raises `ApprovalRefused: protected activation policy
refused` (check the newline, key order and the label).

## 6. Generation, request, signature, install (#206 P3b)

### 6.1 Publish the observe-baseline generation (assistant)

```sh
ssh -t NODE 'cd / && sudo PYTHON -I -m azazel_nexus_runtime.activation_cli generation-publish'
```

It needs an interactive terminal and the unlocked volume (it verifies the
commissioning evidence). It prints `Units:`, `Next generation number:`,
`Generation digest: sha256:...` and `Publishing is NOT admission ...`. The
assistant shows the digest to the operator, re-enters it, and types `PUBLISH`
only after the operator agrees. Expected:
`Generation N published (sha256:...); NOT admitted and no unit enabled.`, exit
0. If the current generation already is exactly this baseline, it prints
`Generation N already is this observe baseline (sha256:...); nothing
published.` and exits 0 without asking anything; use that generation.
Exit 2 means published but not verified or not recorded: stop and inspect.
A refusal names a fixed label, for example `a scoped unit has an override, a
non-mask unit file elsewhere or a drop-in` (go back to §2 item 4) or
`verified commissioning evidence unavailable` (volume locked or §4 incomplete).

### 6.2 Request (assistant)

```sh
ssh NODE 'cd / && sudo install -d -m 0700 /root/azn-activation && sudo PYTHON -I -m azazel_nexus_runtime.activation_cli request --operator LABEL --approval-id p6-rehearsal-1 --seq 1 --valid-for 86400 --out /root/azn-activation/request.json'
```

`--approval-id` matches `[a-z0-9][a-z0-9_-]{0,63}`; `--valid-for` must be at
most the policy's `max_lease_seconds`; `--units` is omitted (the policy
scope). Expected on stderr: `schema: azazel-nexus/activation-approval/v2`,
`units:`, `generation:`, `security_epoch:`, `approval_seq: 1`, `granted_at:`,
`expires_at:`, `payload_sha256: <hex>` and `Unsigned. ... Nothing was signed,
placed or admitted.` The assistant passes `payload_sha256` to the operator.

### 6.3 Sign (operator, own workstation)

```sh
umask 077
ssh NODE 'sudo cat /root/azn-activation/request.json' > approval.json
sha256sum approval.json        # must equal payload_sha256
PYTHONPATH=src uv run --no-project --with 'pynacl>=1.5' python -m tools.operator_sign \
  --purpose activation --payload approval.json \
  --expect-payload-sha256 NODE_PRINTED_SHA256 --expect-public ENROLLED_PUBLIC_HEX \
  --seed /path/outside/any/checkout/rehearsal.seed --out approval.sig
scp approval.sig NODE:azn-approval.sig
```

The signer refuses anything that is not a canonical v2 payload with a window of
at most 72 h. Before copying back, the operator compares its printed summary
(units, generation, epoch, sequence, window) with §6.2's, then deletes
`approval.json`.

### 6.4 Install (assistant)

```sh
ssh NODE 'sudo install -m 0600 -o root -g root "$HOME"/azn-approval.sig /root/azn-activation/approval.sig && rm "$HOME"/azn-approval.sig'
ssh NODE 'cd / && sudo PYTHON -I -m azazel_nexus_runtime.activation_cli install --payload /root/azn-activation/request.json --signature /root/azn-activation/approval.sig --confirm-sha256 NODE_PRINTED_SHA256'
```

Expected: `Verified observe-baseline approval (signature, policy, context,
floors):`, the units, `high water (initialized): epoch E, seq 1, generation
N, ...` and `Approval installed. This is NOT a grant: ...`, exit 0. Then:

```sh
sudo ls -l /etc/azazel/activation/ /var/lib/azazel/state/activation/
sudo grep -oE '"event_type": ?"[^"]*"' /var/lib/azazel/state/activation.jsonl | tail -n 3
```

`policy.json`, `approval.json`, `approval.sig` root `0600`; `high-water.json`
present; the last events include `activation.generation_published` and
`activation.approval_installed`. `request.json` and `approval.sig` stay in
`/root/azn-activation` until §10 (§8 N2 re-installs them). Run `install` and
`generation-publish` only while no pass runs (shared ledger, design §3.5).

## 7. Grant, then start (#206 P6)

### 7.1 Enable the controller (assistant)

```sh
sudo systemctl unmask azazel-activated.service
systemctl is-enabled azazel-activated.service
```

Expected `enabled` (`install.sh` enables it; the lab mask hid it). If it reads
`disabled`, `sudo systemctl enable azazel-activated.service`. Take
**snapshot S1**: every input installed, nothing granted yet. It is the point
to return to if the approval window runs out mid-run or a positive boot has
to be repeated from scratch.

### 7.2 Boot A — grant (units not yet started)

Assistant reboots on the operator's go-ahead; **operator unlocks** as in §3.5.
Assistant:

```sh
findmnt -no SOURCE /etc/azazel/commissioning
systemctl show azazel-activated.service -p Result -p ExecMainStatus
journalctl -b -u azazel-activated.service -o cat
sudo ls -l /run/azazel-activation/granted/
systemctl is-enabled azazel-mio-entryd.service azazel-knowledge-lited.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-edge-probed.service
systemctl is-active  azazel-mio-entryd.service azazel-knowledge-lited.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-edge-probed.service
sudo tail -n 1 /var/lib/azazel/state/activation.jsonl
```

Expected:

- `Result=success`, `ExecMainStatus=0`; the journal line
  `az-activated completed safely: granted=5, withheld=7, reasons=...`
  (Variant B with launchable Edge: `granted=6`), and no
  `readiness notification unavailable`. `reasons` names only refusals of units
  outside the approval (for example `outside_lease_scope`, `wiring_absent`).
- `/run/azazel-activation/granted/` (root `0755`) holds exactly the granted
  units, each an empty root `0644` file.
- The granted units are `enabled` but `inactive`: they were masked when the
  boot began, so no start job was queued, and a grant never starts a unit.
  **要確認** that none started.
- The last ledger entry is `activation.inputs_incomplete` with every
  producer in `observed_inputs.producers` `verified`, `missing_producers`
  only `authoritative_commissioning_admission`, `renderer_measurement` and
  (Variant A) `edge_evidence`, `grant_markers` the granted units and
  `observed_inputs.high_water` `raised`. Earlier entries in this boot:
  `activation.unit_granted` per unit and `activation.high_water_raised`.

### 7.3 Boot B — the granted units start

Reboot again; **operator unlocks**. Assistant repeats §7.2 and adds:

```sh
systemctl show azazel-mio-entryd.service azazel-knowledge-lited.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-edge-probed.service -p Id -p ActiveState -p SubState -p ActiveEnterTimestamp -p ConditionResult
journalctl -b -o short-precise -u azazel-activated.service -u azazel-mio-entryd.service -u azazel-edge-intaked.service | head -n 60
systemctl list-jobs
systemctl is-system-running
```

Expected: the same pass result and markers; each granted unit `active` (the
oneshot probe may be `inactive` with `Result=success` after running),
`ConditionResult=yes`, started **after** the controller's READY; no `unmet
condition` line for a granted unit; no pending jobs. Record the timestamps.
Take **snapshot S2**.

## 8. Negative runs

Each case changes one input, reboots (operator unlocks, except N1), checks,
and restores. The strongest form runs a case on the boot **after a granting
boot**, when the units are enabled and their start jobs are queued: the pass
then remasks them, writes no marker, and systemd skips each with `unmet
condition check`. After a negative boot the units stay masked, so the restore
boot grants again without starting anything; run the next case after that.
Record which form each case used.

Common checks after each negative boot (assistant):

```sh
journalctl -b -u azazel-activated.service -o cat
sudo ls /run/azazel-activation/granted 2>&1
systemctl is-enabled azazel-mio-entryd.service azazel-knowledge-lited.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-edge-probed.service
systemctl is-active  azazel-mio-entryd.service azazel-knowledge-lited.service azazel-edge-intaked.service azazel-incident-explaind.service azazel-edge-probed.service
journalctl -b -o cat | grep -c 'unmet condition'
sudo tail -n 1 /var/lib/azazel/state/activation.jsonl
```

Common expectation, unless the case says otherwise: `granted=0`; `reasons`
`health_not_established` (no lease and no health; or the generation reason
named in the case), possibly with `wiring_absent` as well, which the library
checks first for `azazel-model-fetchd`, `azazel-mio-locald` and
`azazel-mio-remoted` (`_withholding_reason` in `src/azazel_nexus/activation.py`);
no `granted/` directory; every unit `masked` and `inactive`;
`observed_inputs.high_water` `not_attempted` (the floors are not raised).

In `activation.inputs_incomplete`, a producer is `not_attempted` **only when
it depends on the one that failed** (`collect_pass_inputs` in
`runtime/src/azazel_nexus_runtime/activation_pass.py`): `node_identity`,
`activation_policy`, `epoch_high_water`, `trusted_clock` and `node_health`
are evaluated independently and read `verified` unless they fail themselves;
`operational_generation_publisher` is evaluated only with commissioning
evidence and a policy; `activation_approval_loader` only when the six before
it (`authenticated_commissioning`, `node_identity`, `activation_policy`,
`epoch_high_water`, `trusted_clock`, `operational_generation_publisher`) all
verified. For example N1 reads `authenticated_commissioning` and
`inventory_binding` `failed`, `operational_generation_publisher` and
`activation_approval_loader` `not_attempted`, and every other producer
`verified`.

| case | operation (who) | expected beyond the common one | restore |
| --- | --- | --- | --- |
| **N1 locked** (#242 P1) | at the reboot nobody types the passphrase or answers the agent for more than 300 s (operator) | about 300 s in, `Failed to query password: Timer expired`; the mount `Dependency failed`; the controller starts right after (§0 item 3) and completes; `authenticated_commissioning` and `inventory_binding` `failed`, `full_commissioning: unavailable`; `systemctl is-system-running` `degraded` (the cryptsetup unit only) | reboot and unlock |
| **N2 approval removed** | `sudo rm /etc/azazel/activation/approval.json /etc/azazel/activation/approval.sig` (assistant) | `activation_approval_loader` `failed`, all earlier producers `verified` | §6.4's `install` again with the kept, byte-identical files (no `--replace`); `high water (raised)`. If the window ended, a new request and signature with `--seq 2` (a different approval must use a sequence above the floor) |
| **N3 tree altered** | keep a copy, then append one byte to `/var/lib/azazel/generations/N/tree/baseline.json` (assistant: `sudo cp -a … /root/azn-activation/baseline.json.orig`, `printf ' ' \| sudo tee -a … >/dev/null`) | the controller's own check withholds everything (`reasons=generation_unverified`); `operational_generation_publisher` `failed` | `sudo cp -a /root/azn-activation/baseline.json.orig …/baseline.json`, or revert to S2 |
| **N3b drop-in** (design §3.2) | `sudo install -d -m 0755 /etc/systemd/system/azazel-edge-intaked.service.d` and a one-line `[Service]` file `azn-rehearsal.conf` in it; `daemon-reload` (assistant) | `operational_generation_publisher` `failed` (override refused) | remove the directory, `daemon-reload` |
| **N4 clock moved back** | `sudo timedatectl set-ntp false`; `sudo timedatectl set-time '<last pass time − 1 h>'`; reboot (assistant) | `trusted_clock` `failed` (clock below `time_floor − 300 s`); approval `not_attempted`. **要確認:** that the VM's RTC keeps the earlier time across a guest reboot and that nothing advances the clock before the pass (`journalctl -b \| grep -i 'time'`); if it is advanced, record N4 as *not exercisable on this VM* and do not touch systemd's own clock floor | `sudo timedatectl set-ntp true`, wait for `NTPSynchronized=yes` (`timedatectl show`), reboot. A VM that cannot sync by NTP: set the real time back with `sudo timedatectl set-time` from an independent source, or revert to S2 |
| **N5 probe stale** (Variant B only) | `sudo systemctl mask azazel-edge-probe-preflight.service` (assistant); this boot has no probe result, the last one names another boot | **differs from the common one:** the five SUPPORTING units are granted (and start, if enabled); edge-core withheld `edge_not_ready: digest_matches,health_endpoint_healthy`, no marker for it, `masked` and not started; `observed_inputs.edge_evidence: not_launchable` | `sudo systemctl unmask azazel-edge-probe-preflight.service` |
| **N6 locked after a grant** | as N1, run on the boot after a granting boot if N1 was not | queued starts skipped (`unmet condition`) | reboot and unlock |
| **N7 epoch raised** | see below (assistant, operator agrees) | `node_identity` and `epoch_high_water` `verified`, `activation_approval_loader` `failed` (the approval names the old epoch) | revert to S2 |
| **N8 operator revoked** | `sudo PYTHON -I -m azazel_nexus.operator_enrollment revoke LABEL` (interactive: public key, fingerprint, `REVOKE LABEL`; assistant with the operator's go-ahead) | with one rehearsal operator who also signed the proposal, `authenticated_commissioning` fails first (the evidence's signer is revoked); `node_health` `operator_trust` fails if no other active key; record the producer statuses as observed | revert to S2 (or S0 at the end). Only without a revert is the revocation permanent: the label cannot be re-enrolled |

**N7 detail.** The declaration store has no replace path
(`bootstrap_deployment_store.py` initializes only when no `deployment.json`
exists), so raising the declared epoch on the VM means moving the declaration
aside and publishing a new one; the change is undone only by reverting the
snapshot. Assistant, while the current declaration is still in place:

```sh
sudo PYTHON -I -c 'import dataclasses, sys; from azazel_nexus.bootstrap_deployment_store import load_bootstrap_deployment as l; from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment as e; d = l(); sys.stdout.write(e(dataclasses.replace(d, security_epoch=d.security_epoch + 1)).decode() + "\n")'
sudo mv /etc/azazel/bootstrap/deployment.json /root/azn-quarantine/deployment.json.orig
ssh -t NODE 'sudo /opt/azazel-nexus/venv/bin/azazel-nexus bootstrap-deployment-initialize'
```

Paste the printed line, re-enter the printed SHA-256 and type `INITIALIZE`.
The declaration holds digests and a label, no secret. Run N7 and N8 last.

## 9. Observations

**O1. BARRIER window after READY.** On boot B (and every granting boot):

```sh
systemctl show azazel-activated.service -p ActiveEnterTimestamp -p InactiveEnterTimestamp -p Result
journalctl -b -o short-precise -u azazel-activated.service
```

READY is processed at `ActiveEnterTimestamp`; the process exits after the
bounded `BARRIER=1` wait, at about `InactiveEnterTimestamp`. Expected: under
about 5 s apart, `Result=success`. Record the measured gap.

**O2. Residual window for auditd and commissiond** (design §8). Neither
carries the marker condition. To observe what the design names "left unmasked
when the boot began", only with the operator's agreement and after a
granting boot, the assistant creates that state for auditd alone:

```sh
sudo systemctl unmask azazel-auditd.service && sudo systemctl enable azazel-auditd.service
```

Reboot and unlock. Then:

```sh
journalctl -b -o short-precise -u azazel-activated.service -u azazel-auditd.service
systemctl show azazel-auditd.service -p ActiveEnterTimestamp -p InactiveEnterTimestamp -p Result
systemctl is-enabled azazel-auditd.service
```

Expected (design): the queued start is released by READY, auditd runs until
the controller exits and `BindsTo=` stops it, at most about 5 s after READY;
the pass masked it again (`masked`). Record whether it reached `active`, how
long it ran and how it ended. Restore at once:
`sudo systemctl unmask azazel-auditd.service && sudo systemctl disable azazel-auditd.service && sudo systemctl mask azazel-auditd.service && sudo systemctl reset-failed`.
commissiond (`Requires=`/`BindsTo=` auditd) is observed the same way only if
the owner asks.

**O3. Loop units without auditd** (design §6 decision 8). On boot B, after
10 minutes: `systemctl show <granted units> -p ActiveState -p NRestarts -p Result`
and their journals. Record whether each stays up without the bootstrap-only
auditd.

**O4. Timings.** For one locked and one unlocked boot: time from boot to the
prompt, to the unlock or timeout, to the mount, to the controller start
(`systemd-analyze critical-chain azazel-activated.service`).

## 10. Clean up

Preferred: **revert to snapshot S0** (assistant, operator agrees). It undoes
the policy, generation, approval, high water, ledger appends, a raised epoch,
a revocation, the crypttab and fstab lines, the moved selection and the
controller unmask. If the owner wants the VM to keep the boot-time unlock,
re-apply §3.1 and §3.4 only.

Without reverting (only possible when N7 and N8 were not run): stop and
re-mask the loop units (`sudo systemctl stop …`, `sudo systemctl reset-failed`,
`sudo systemctl mask …` for the five or six units); remove
`approval.json`/`approval.sig`; `sudo systemctl mask azazel-activated.service`;
move `selection.json` back from `/root/azn-quarantine`; the quarantined
`commissioning-proposal.sig` belongs to the **old** volume, and moving it back
would overwrite the new one in `/etc/azazel/mio-profile/`, so do that only
together with switching `crypttab` back to the old volume (otherwise keep the
new signature and leave the old one in quarantine); remove the crypttab, fstab and `/data` lines and
`daemon-reload`. The ledger, the generation and the high water stay: they are
append-only or raise-only history, never edited.

Always: the assistant deletes `/root/azn-activation`; the operator deletes
every workstation copy (`approval.json`, `approval.sig`, `draft.json`,
`proposal.json`) and destroys the rehearsal seed. With Option B, the operator
decides whether S0 (which still holds the old key file) is deleted.

## 11. What to record

Comment on [#206](https://github.com/01rabbit/Azazel-Nexus/issues/206) (P6)
and [#242](https://github.com/01rabbit/Azazel-Nexus/issues/242) (P1),
labelled `rehearsal`, then update this runbook's status line in a docs PR:

- main commit installed; VM class facts only (Debian release, kernel, systemd
  version, architecture); storage option (A or B), Edge variant (A or B), the
  substitutions (loop-file LUKS, secrets on root, unencrypted `/data`, moved
  selection and signature);
- §3.4's three outputs and §3.5's loop-device answer;
- boots A and B: the `az-activated completed safely` lines, producer statuses,
  `missing_producers`, marker names, unit states and start order;
- each negative case: operation, form (after a granting boot or not), the
  outcome line, failed producers, unit states, the `unmet condition` count,
  and the restore result; N4 or N5 *not exercised* where applicable;
- O1–O4 values; every deviation and every **要確認** answered.

Never record the passphrase, a seed, a public key, a signature, a payload,
the approval, the generation or commissioning digests, node digests, boot or
machine ids, hostnames, addresses, interface names, MACs or serials
([inventory confidentiality](../inventory-confidentiality.md)). The record is
VM software rehearsal: not HG-08 or any hardware evidence, and not a
production approval.

## 12. Not covered on a VM

- TPM2 unlock with a passphrase fallback and its negative boots (#242 P2,
  HG-08, owner-gated).
- A real dm-crypt device, `/var/lib/azazel/secrets` on the same device
  (design §5 decision 3), and an encrypted mission volume at `/data`.
- Edge Core on its intended x86_64 hardware ([HG-07](hg-07.md)).
- Any production approval: rehearsal keys never leave this VM.
