# Commissioning storage at boot — design proposal (#242)

Owner: [#242](https://github.com/01rabbit/Azazel-Nexus/issues/242) (blocks P6 of
[#206](https://github.com/01rabbit/Azazel-Nexus/issues/206)).
Status: **proposed; awaiting owner decisions (§5); nothing implemented**.

## 1. Problem

The boot-time activation pass ([observe-baseline activation](activation-observe-baseline.md))
calls `load_commissioning_evidence()`
(`runtime/src/azazel_nexus_runtime/commissioning_input.py`). It reads the
signed full proposal (`commissioning-proposal.expected.json`,
`commissioning-proposal.json`, `commissioning-proposal.sig`) from
`/etc/azazel/commissioning`, and `read_proposal_review_inputs`
(`src/azazel_nexus/commissioning_draft.py`) refuses unless that directory is
on a LUKS dm-crypt device. Nothing opens that volume before the pass: the
[commissioning rehearsal](hil-runbooks/commissioning-rehearsal.md) says not to
add it to `crypttab` or `fstab`. Every real boot pass therefore fails
`authenticated_commissioning` and grants nothing.

The refusal itself is correct and needs no change: a locked volume leaves a
plain directory, `luks_backed` is false, and the pass refuses with
`lease=None`.

## 2. What the check needs

The verifier needs the full signed payload, not a digest of it: the Ed25519
signature is over the whole payload, the payload is rebuilt canonically from
the retained inventory, and the retained inventory is compared field by field
with the current hardware. The payload holds raw identity (board serial,
storage serials, permanent MACs), which
[inventory confidentiality](inventory-confidentiality.md) §3 allows only in the
encrypted commissioning record. The binding key
(`/var/lib/azazel/secrets/commissioning.key`) is also read.

## 3. Options

| option | idea | verdict |
| --- | --- | --- |
| 1 | TPM2-bound unlock (`systemd-cryptenroll --tpm2-device`, crypttab `tpm2-device=auto,nofail`) | sound; needs a hardware gate (proposed HG-08); phase 2 |
| 2a | keep a full copy of the proposal outside LUKS | contradicts inventory confidentiality §3; rejected |
| 2b | keep only digest, signature and an HMAC seal | cannot satisfy the verifier; would be a persistent "verified" record and new local authority; rejected |
| 2c | TPM-sealed systemd credentials (`LoadCredentialEncrypted=`) | a decrypt failure stops the controller before its remask and ledger record; inferior to 1 |
| 3 | operator unlocks, then reruns the controller | dependents already settled this boot; units would need manual starts; never a steady state; rejected |
| 4 | crypttab entry **without a key file**, passphrase typed at boot (console, or `systemd-tty-ask-password-agent` over SSH), `nofail,timeout=` | nothing stored; untyped → boot continues locked and the pass refuses; **recommended phase 1** |

Option 1 is a strict extension of option 4: phase 2 adds `tpm2-device=auto`
and a TPM key slot to the same crypttab line and keeps the passphrase slot as
the fallback.

## 4. Proposed design

- **Ordering.** The controller unit gains `After=etc-azazel-commissioning.mount`
  (and the secrets mount, §5 Q3). Only `After=`: a `Requires=`,
  `BindsTo=` or `RequiresMountsFor=` on storage would stop the controller from
  running when the storage fails, and its preflight remask is what narrows.
  `After=` on a mount that does not exist is a no-op. While a mount job is
  pending the controller waits for it, up to the device timeout below.
- **crypttab / fstab** (documented, installed by the operator, never with a key
  file): `azn-commissioning <device> none nofail,timeout=<T>` and
  `/dev/mapper/azn-commissioning /etc/azazel/commissioning ext4
  nodev,nosuid,noexec,nofail,x-systemd.device-timeout=<T> 0 0`. The device
  timeout matches the crypttab `timeout=`; otherwise the mount job waits for
  the mapped device only for the default start timeout (90 s) and may fail
  before the prompt ends and not be retried after a later unlock. That an
  untyped passphrase leaves the volume locked and the boot continuing after
  `<T>` is to be verified in P1. Key files and `systemd-creds` with the host key
  are forbidden.
- **Diagnostic only.** The pass may record a fixed label
  `commissioning_storage: luks_backed | not_luks_backed` in its observed inputs;
  it never feeds the decision and carries no device or path.

### Phases

| phase | content |
| --- | --- |
| P0 | `hardening.py` `After=` lines + generated unit + tests (no `Requires=`/`Wants=`/`BindsTo=`/`RequiresMountsFor=` on storage); optional diagnostic label; docs (this file, commissioning rehearsal §3, debian-live-install layout) |
| P1 | VM rehearsal (never evidence): locked boot times out → refusal recorded, nothing starts; unlocked boot → grant → reboot → unlock → units start (unblocks #206 P6) |
| P2 | hardware, owner-gated (HG-08): TPM2 enrolment with passphrase fallback; positive boot auto-unlocks; Secure Boot toggled, other boot media and a PCR change each leave it locked and the pass refusing |

## 5. Owner decisions

Recommended defaults in brackets.

1. Production unlock factor? **[passphrase at boot until HG-08 passes, then
   TPM2 with the passphrase as fallback; TPM2 + PIN only where whole-device
   theft is in scope]**
2. PCR policy? **[PCR 7 + 4, re-enrolling after boot-loader updates through the
   fallback]**
3. Does `/var/lib/azazel/secrets` share the commissioning LUKS device?
   **[yes, a second mount on the same device; the controller is ordered after
   both mounts]**
4. Prompt timeout `T`? **[300 s, then continue locked; the controller and its
   dependents wait this long]**
5. LVM on LUKS? **[not supported; the volume must be plain LUKS, as
   `luks_backed` checks the immediate device]**
6. The raw-identity copy in `/etc/azazel/mio-profile/`? **[separate issue
   [#244](https://github.com/01rabbit/Azazel-Nexus/issues/244); never a source
   for the activation pass]**
7. Gate bookkeeping? **[new HG-08 in [hardware gates](hardware-gates.md),
   hardware-unverified]**
8. A vTPM on the VM? **[not needed for P1; a swtpm run is a mechanics
   rehearsal only]**

To verify on the VM: that systemd 257 sets up a loop device for a regular-file
crypttab source, and how a `nofail` entry is ordered; the explicit `After=` on
the mount makes the design independent of the latter.
