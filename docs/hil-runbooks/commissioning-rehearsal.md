# Commissioning and M.I.O. ceiling — VM rehearsal (never evidence)

Owner: [#93](https://github.com/01rabbit/Azazel-Nexus/issues/93).
Status: **rehearsed once on a Debian 13 aarch64 VM (2026-10-19, main
`815d3ca`); hardware-unverified**.

This runbook walks the operator flow from an installed node to entryd reading a
verified LITE/FULL ceiling: encrypted commissioning storage, the signed role
draft, the full commissioning proposal with its M.I.O. ceiling, review and
publication, and entryd's credential snapshot. It records the substitutions a
VM needs. Like [§17 of the admission runbook](mio-admission.md#17-vm-rehearsal-never-evidence),
a VM rehearses **mechanics only**: nothing here is HIL evidence, nothing is
attested for a campaign, and every artefact is labelled `rehearsal`.

The ceiling is recorded, never granted. With HG-05 unmeasured, provider
admission stays closed and the capability state stays CORE whatever ceiling
is selected ([M.I.O. runtime](../mio-runtime.md), [operations §0](../operations.md#0-read-only-operator-setup-guide)).

## 1. Keys and who does what

- **Use a rehearsal operator**, as §17 of the admission runbook requires for
  any VM rehearsal: enroll a key generated for the VM only
  (`python -m azazel_nexus.operator_enrollment`, see
  [Debian installation](../debian-live-install.md)), never enroll it on a real
  node, and destroy its seed when the rehearsal ends. The 2026-10-19 run used
  `owner`, the operator already enrolled on that VM; this record does not
  establish that the key was VM-only. If it is enrolled on any real node, that
  run deviated from this rule. Either way, its commissioning signatures stay
  bound to the VM's node identity and must not be reused anywhere.
- **The operator signs on their own workstation.** The node prints a payload
  SHA-256; the operator fetches the payload, signs with
  [`tools/operator_sign.py`](../../tools/operator_sign.py), and copies back only
  the 64-byte signature. The assistant or any remote helper never reads the seed.
  Run the signer from a reviewed checkout with a pinned, hash-verified PyNaCl:
  the seed shares that process with the imported code. This rehearsal uses
  its `commissioning` and `commissioning-proposal` purposes only; its
  `activation` purpose (boot-free v2 approval) is described in
  [observe-baseline activation §3.1](../activation-observe-baseline.md#31-activation-approval-schema-v2-boot-free)
  and is not part of commissioning.
- **Confidentiality.** The draft and proposal contain raw interface identity.
  Keep workstation copies in a private `0700` directory, delete them after
  signing, and never paste them into issues, logs or chat
  ([inventory confidentiality](../inventory-confidentiality.md)).
- Every node-side command below runs as root on the node. `az-nexus-commission`
  is the runtime module `azazel_nexus_runtime.commission_cli`; on an install
  without the console script, run
  `sudo /opt/azazel-nexus/venv/bin/python -I -m azazel_nexus_runtime.commission_cli ...`
  from `/` (every node command below assumes `cd /`). `commission` and
  `proposal-export` require an interactive terminal
  (`ssh -t`).
  Below, `PYTHON` stands for `/opt/azazel-nexus/venv/bin/python`, `NODE` for
  the SSH destination and `LABEL` for the enrolled operator label.

## 2. Preconditions

1. **Snapshot the VM** before starting. Route and audit ledger appends cannot
   be undone; a snapshot is the only complete restore. Also keep a root `0600`
   tarball of `/etc/azazel`, `/var/lib/azazel` and the installed packages.
2. **Current code.** The installed packages must include #183 (credential
   ownership as systemd 257 presents it, non-empty `SetCredential` fallbacks).
   Re-run `packaging/install.sh` after updating; on a lab VM follow the upgrade
   note in [lab demonstration](../lab-demonstration.md) and mask the activation
   controller again afterwards.
3. **Fabric extra** (`azazel-fabric` at the pin in `pyproject.toml`) in the
   node's interpreter. Without it every reader yields CORE and
   `proposal-export` cannot assemble the record. The VM had no `pip`; the
   2026-10-19 run built `azazel-fabric` and its dependencies with
   `pip install --target` in a `debian:trixie` aarch64 container and copied the
   tree into the venv's `site-packages`.
4. **No lab marker.** `/etc/azazel-lab/LAB-HOST` forces CORE and refuses
   `commission`, `commission-review` and `proposal-review`. Only after
   confirming no `azazel-lab-*` unit, no `/var/lib/azazel-lab/<id>` and no
   `azazel_nexus_lab` in the production interpreter, the operator moves it aside
   (do not delete it):
   `sudo install -d -m 0700 /root/azn-quarantine && sudo mv /etc/azazel-lab/LAB-HOST /root/azn-quarantine/`.
   **This applies to a lab VM only.** A real node that carries the marker ran
   lab code and is reinstalled, not cleaned; removing the marker grants nothing
   and its output is still not evidence ([hardware gates](../hardware-gates.md)).
5. **Commissionable interface.** `az-nexus-commission hardware-assess` must
   report `interfaces_observed` greater than `interfaces_refused`.

## 3. Storage the commissioning tools require

**Encrypted commissioning storage.** The tools check that
`/etc/azazel/commissioning` is on a LUKS dm-crypt device
([HIL preflight](../hil-preflight.md)). On a VM without a second disk, a
loop-backed LUKS2 file passes the same check (`cryptsetup-bin` must be
installed). The operator types the passphrase:

```sh
sudo install -d -m 0700 /var/lib/azn-rehearsal-luks
sudo fallocate -l 64M /var/lib/azn-rehearsal-luks/commissioning.img
sudo cryptsetup luksFormat --type luks2 /var/lib/azn-rehearsal-luks/commissioning.img
sudo cryptsetup open /var/lib/azn-rehearsal-luks/commissioning.img azn-commissioning
sudo mkfs.ext4 -q /dev/mapper/azn-commissioning
sudo mount -o nodev,nosuid,noexec /dev/mapper/azn-commissioning /etc/azazel/commissioning
sudo rmdir /etc/azazel/commissioning/lost+found
sudo chown root:azcommission /etc/azazel/commissioning && sudo chmod 0750 /etc/azazel/commissioning
```

Do not add it to `crypttab` or `fstab`; reopen it by hand after a reboot.
The check cannot tell a loop file on an unencrypted disk from a real encrypted
volume. The loop file substitutes for the mechanics only; a real node uses a
real dm-crypt device ([HIL preflight](../hil-preflight.md)).

**Commissioning key.** If `/var/lib/azazel/secrets/commissioning.key` is
absent, create it with the root-only script in
[core reserve measurement](../core-reserve-measurement.md#commissioning-key-initialization-root-only).
The script prints nothing and never replaces a key. On the VM the secrets
directory stayed on the unencrypted root filesystem; a real node keeps it on
commissioned storage.

**Mission storage.** `proposal-export` needs a complete resource observation,
and `mission_available_mib` is read from a `/data` that is a separate,
writable filesystem. It does not test encryption. The VM run mounted an
unencrypted 256 MiB ext4 loop file at `/data`. A real node mounts its encrypted
mission volume there. Confirm with `az-nexus-commission resources`: exit 0 and
`"unavailable": []`.

## 4. Role draft

```sh
ssh -t NODE 'cd / && sudo PYTHON -I -m azazel_nexus_runtime.commission_cli commission \
  --operator LABEL --at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --draft-output /etc/azazel/commissioning/commissioning-draft.json'
```

The operator assigns each interface a role and types `CONFIRM`
([roles](../commissioning.md#4-roles-come-from-the-operator-not-from-inference)).
Nothing is configured. Then:

```sh
sudo sha256sum /etc/azazel/commissioning/commissioning-draft.json   # on the node
```

On the workstation, in a private directory:

```sh
umask 077
ssh NODE 'sudo cat /etc/azazel/commissioning/commissioning-draft.json' > draft.json
PYTHONPATH=src uv run --no-project --with 'pynacl>=1.5' python -m tools.operator_sign \
  --purpose commissioning --payload draft.json \
  --expect-payload-sha256 NODE_PRINTED_SHA256 --expect-public ENROLLED_PUBLIC_HEX \
  --seed /path/outside/any/checkout/operator.seed --out draft.sig
scp draft.sig NODE:azn-draft.sig
```

On the node, install it and review:

```sh
sudo install -m 0600 -o root -g root ~/azn-draft.sig /etc/azazel/commissioning/commissioning-draft.sig && rm ~/azn-draft.sig
sudo PYTHON -I -m azazel_nexus_runtime.commission_cli commission-review --operator LABEL
```

Expected: `Signed draft review: assigned bindings verified.`

## 5. Full proposal with the M.I.O. ceiling

```sh
ssh -t NODE 'cd / && sudo PYTHON -I -m azazel_nexus_runtime.commission_cli proposal-export --operator LABEL'
```

Enter `CORE`, `LITE` or `FULL`, then `EXPORT`. The proposal (`schema`
`azazel-nexus/commissioning-proposal/v2`) is written to the encrypted
directory, and the two copies are published to `/etc/azazel/mio-profile/`.
Print `sha256sum /etc/azazel/commissioning/commissioning-proposal.json` on the
node, then sign that file exactly as in §4 with
`--purpose commissioning-proposal` and the newly printed SHA-256, install it as
`/etc/azazel/commissioning/commissioning-proposal.sig` (root `0600`), then:

```sh
sudo PYTHON -I -m azazel_nexus_runtime.commission_cli proposal-review --operator LABEL --check-current-hardware
```

Expected: `Full proposal signature verified; current hardware fields match
retained evidence.` The signature is then published to
`/etc/azazel/mio-profile/`. Files in both directories are create-only; another
ceiling needs a new proposal.

## 6. entryd reads the ceiling

Start entryd by hand as in [§17](mio-admission.md#17-vm-rehearsal-never-evidence)
(production activation of entryd does not exist yet):

```sh
sudo systemctl unmask azazel-mio-entryd.service && sudo systemctl daemon-reload
sudo systemctl start --job-mode=ignore-requirements azazel-mio-entryd.service
sudo ls -l /run/credentials/azazel-mio-entryd.service/
```

Expect five credentials: `mio-node`, `mio-trust` and three `mio-profile_*`
files, each root:root `0440` with an ACL for `azmioentry` on systemd 257.
`azazel-nexus status` and `setup`, run as root, then show
`recorded ceiling: LITE; capability state: CORE` (or the chosen ceiling)
with the reasons from the last `mio.capability.transition`.

## 7. Clean up and restore

```sh
sudo systemctl stop azazel-mio-entryd.service && sudo systemctl mask azazel-mio-entryd.service
sudo umount /data && sudo losetup -D
sudo umount /etc/azazel/commissioning && sudo cryptsetup close azn-commissioning
```

Delete the workstation copies of the draft and proposal (`draft.json`,
`proposal.json`); only the signatures ever return to the node. Destroy the
rehearsal operator's seed. Revert to the
snapshot to undo everything, including ledger appends. Without a snapshot,
`mv` the lab marker back if the VM returns to lab use, and move the published
proposal files out of `/etc/azazel/mio-profile/` while keeping the directory,
since entryd will not start without it.

## 8. Not covered on a VM

- Bootstrap re-initialization for the current boot: it needs a snapshot taken
  before the first bootstrap ([runtime activation](../runtime-activation-remaining.md)).
- Provider admission and HG-05 (an aarch64 or virtualized host is refused).
- Mission Pack selection: it needs a measured reserve and x86_64.
- Production activation of entryd: it is not implemented on any host.

## 9. Record of the 2026-10-19 run

The run used a Debian 13 aarch64 VM with systemd 257 and main `815d3ca`, with
Fabric `v0.9.0rc2` installed. One interface was assigned `management`. The
draft review and the proposal review both verified. entryd recorded
`profile: LITE` with state CORE, and the route ledger verified. The
substitutions were the loop-file LUKS2, the secrets directory on root, and an
unencrypted `/data`. Details are in issue #93. This is VM software
rehearsal, not hardware evidence.
