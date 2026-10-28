# Real-systemd integration run — one script for the container and the VM (never hardware evidence)

## 概要（日本語）

`tools/vm_integration.py` は、systemd が PID 1 で動く使い捨ての Linux ノードに対して、
本番の `packaging/install.sh`（本番 unit・本番アカウント）で導入し、統合ループを起動し、
障害を注入し、ノードを再起動し、その結果を JSON で記録するところまでを 1 本で行う。
ノード側の処理はどこでも同じで、違うのは接続先だけである。

- `docker:<container>[@<context>]` — systemd を PID 1 にした特権 Debian trixie コンテナ。
  **コンテナ内 systemd リハーサルであり、VM でも実機でもない。**
- `ssh:<destination>` — VM。ノード側のコマンドはすべて `sudo -n` で実行する。

起動はリハーサル専用の手動起動（[統合ループ手順書 §6](integration-loop-rehearsal.md#6-rehearsal-only-start-alternative-to-activation)）
で行う。通常の activation 経路は commissioning（LUKS 上の commissioning 記憶域と、
恒久 MAC を読める NIC）を必要とし、コンテナでは成立しないため、このスクリプトは
承認・lease・generation・Mission Pack を一切作らない。`LOCAL_MODEL_ADMISSION_ENABLED`
などの実機ゲートにも触れない。この試験で使う鍵（Lite の失効署名鍵）はノードの
`/run/azn-vmit`（tmpfs、root 0700）に `azn-vmit-lab` の名で生成し、終了時に上書き消去する。

Status: **container rehearsal run on 2026-10-28** on aarch64 (colima, native) and
x86_64 (colima under Rosetta), recorded in
[`docs/evidence/vm-integration-container-2026-10-28.md`](../evidence/vm-integration-container-2026-10-28.md).
**Not run on a VM**: the Arm VM is not available yet. Nothing here is HIL
evidence, nothing is attested for a campaign, and every artefact is labelled
`rehearsal`. Like the other runbooks in this directory,
`tests/unit/test_runbook_references.py` checks every command and flag named
here against the code.

## 1. What one run does

The controller half runs on the operator's machine; it copies the checkout's
`HEAD` (`git archive`) and the script to the node, then runs the node half as
root, phase by phase. Each phase prints one JSON result; the controller
collects them into one record.

| phase | what happens on the node |
| --- | --- |
| `prepare` | records the OS, kernel, systemd and CPU; refuses unless the operator passed `--disposable-node` and the node has no venv, no `/etc/azazel`, no `/var/lib/azazel` and no kept storage-pressure copies; with `--rosetta`, refuses unless the node is x86_64 user space translated by Rosetta; checks the prerequisites; builds `/opt/azazel-nexus/venv` from the copied source; runs `packaging/install.sh`; checks that every governed unit this run uses is installed masked and that the activation controller is enabled |
| `start` | enrolls Knowledge Lite from the public fixture bundle ([knowledge-lite-consumer §11](../knowledge-lite-consumer.md#11-first-enrollment-from-a-fresh-install-to-available), with the substitutions in §2); installs and verifies the Edge package when one is given; makes this boot's grant markers by hand; starts the auditd rehearsal copy, `azazel-knowledge-lited`, `azazel-mio-referenced`, `azazel-mio-entryd`, `azazel-edge-intaked`, `azazel-incident-explaind` and (with a package) the probe and `azazel-edge-core`, all with `--job-mode=ignore-requirements` |
| `scenarios` | the checks of §4: the model-free reference path, Knowledge citations and status; SIGKILL; broken replies; malformed Edge lines; Lite expiry; storage pressure; Edge Core with the advisory side stopped (H1–H3); a Lite revocation |
| restart | the controller restarts the node: `docker restart` for a container (systemd boots again, the kernel does not), `systemctl reboot` for a VM (a new boot id is required) |
| `after-restart` | the boot's activation pass ran and granted nothing; no marker survived; every hand-unmasked unit is masked again and none is running; a start without a marker is skipped; the Lite revocation still holds; the activation ledger's last entry |
| `cleanup` | overwrites and removes everything under `/run/azn-vmit` (already gone after a restart), removes the Rosetta drop-in, stops the fake peers, and reports (never discards) a storage-pressure mount or kept copy left by an interruption. It runs also when the run is interrupted (a failed restart, a timeout, Ctrl-C) |

A check that raises is recorded as `fail` with its exception, never as a
crash of the run. A blocking failure in `prepare` or `start` stops the run
before the scenarios.

## 2. What it does not do, and the substitutions it records

- **No activation admission.** The units are started by the rehearsal-only
  start: grant markers made by hand under `/run/azazel-activation/granted`
  (tmpfs, gone at the next boot) and `--job-mode=ignore-requirements`. The
  record says `activation admission: not exercised` in effect: the
  `after-restart` phase shows the regular pass granting nothing. The regular
  path on a VM is the [activation rehearsal](activation-rehearsal.md), which
  stays manual (it needs an interactive commissioning and a VM-only operator).
- **auditd** runs as the integration loop runbook's rehearsal copy
  `azn-rehearsal-auditd.service`, a unit file under `/run/systemd/system`
  without the controller dependencies (`BindsTo=azazel-activated.service`
  would stop it at once). `systemd-analyze verify` must print no warning.
- **Knowledge Lite** is enrolled with the **public fixture key** of
  `contract/azazel-knowledge-lite/anchors.toml` (published by Azazel-Knowledge,
  test-only; it must never be pinned on a real node). Two steps of §11 have no
  shipped entrypoint and run as library calls, as §11 says; one more is
  substituted here:
  - step 5 (revocation policy) is the library call the repin path uses,
    `commission_policy`, run as `azcommission`, not through `az-commissiond`
    (only the supporting bootstrap starts it); the written file is given
    `trust.json`'s owner and mode, as the repin does for its own files;
  - the revocation key is this run's lab key, and the revocation statement in
    §4 is accepted with `RevocationStore.accept` as `azcommission` (no shipped
    entrypoint either); its two files are then given `trust.json`'s metadata
    (finding F3 in the evidence record).
  The commissioning digest the pin and the policy carry is a label derived
  from `azn-vmit-lab` and the run id: the node has no commissioning record.
- **Edge** decisions are dry runs (`defense_enforce=false`,
  `defense_dry_run=true`); the stimulus is synthetic eve lines appended to an
  empty `/var/log/suricata/eve.json` (no Suricata), one new source address per
  stimulus so each one opens a new incident. Without `--edge-package` the
  stimulus is Edge's own fixture lines replayed to intake as `azedge`, and the
  Edge Core checks are `skip`.
- **No model.** Model admission stays closed, so every frame is a
  deterministic handoff; `azazel-mio-locald.service` is never started, and
  altering its replies is `skip` (nobody reads them).
- **No Mission Pack.** A pack cannot be ACTIVE without commissioning on LUKS
  storage and a measured Core reserve (HG-05); referenced therefore answers
  with the fixed word `no_pack`, and pack expiry is `skip`.
- **x86_64 under Rosetta** (`--rosetta`): Rosetta translates into executable
  heap pages, so every x86_64 process under `MemoryDenyWriteExecute=yes` dies
  with SIGTRAP -- systemd's own `systemd-journald` and `systemd-logind` too,
  and the activation controller at boot. `prepare` therefore writes one
  runtime top-level drop-in for every service,
  `/run/systemd/system/service.d/azn-vmit-rosetta.conf`
  (`MemoryDenyWriteExecute=no`), restarts journald, and `cleanup` removes it.
  Being under `/run`, it is gone at the restart, so the boot's own pass dies
  before it decides; `after-restart` records that, puts the drop-in back and
  starts the same controller once in that boot (`after-restart.rosetta-pass`).
  Seccomp filters are not enforced under Rosetta either. That run says nothing
  about `MemoryDenyWriteExecute` or `SystemCallFilter` on x86_64
  ([§17 of the admission runbook](mio-admission.md#17-vm-rehearsal-never-evidence)).

## 3. Preparing the node

### 3.1 Container (aarch64, Apple Silicon)

A privileged Debian trixie container with systemd as PID 1, as in
[§17 of the admission runbook](mio-admission.md#17-vm-rehearsal-never-evidence)
(image `az-nexus-systemd:trixie`, which adds systemd to Debian trixie):

```sh
docker --context colima run -d --name azn-vmit --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock az-nexus-systemd:trixie
docker --context colima exec azn-vmit systemctl is-system-running --wait
docker --context colima exec azn-vmit sh -c 'apt-get update -qq && apt-get install -y -qq apparmor iproute2 openssl gcc python3-dev'
```

`is-system-running` reads `degraded` in a container
(`systemd-modules-load.service` fails); that is expected.

### 3.2 Container (x86_64 under Rosetta)

Use the colima profile with Rosetta and an amd64 image whose systemd does not
mount `binfmt_misc` (otherwise the host loses the Rosetta registration):
`proc-sys-fs-binfmt_misc.automount`, `proc-sys-fs-binfmt_misc.mount` and
`systemd-binfmt.service` masked in the image.

```sh
docker --context colima-rosetta run -d --name azn-vmit-amd64 --platform linux/amd64 --dns 1.1.1.1 \
  --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  --entrypoint /sbin/init az-nexus-systemd:trixie-amd64b
```

then the same package installation as §3.1.

### 3.3 VM

- Debian 13 with systemd as PID 1, either CPU. **Take snapshot S0 first**:
  the install, the ledgers and the Lite revocation are not undone otherwise.
- A fresh node: no `/opt/azazel-nexus/venv`, no earlier Azazel-Nexus install
  (`/etc/azazel`, `/var/lib/azazel`), no lab marker. The run refuses otherwise,
  and it never runs without `--disposable-node`: the operator's statement that
  the node is a throwaway lab node, since the run pins the public fixture key
  and injects faults. Never pass it for a node that matters.
- The SSH user can run `sudo -n` (non-interactive). The run never asks for a
  password; a temporary sudo grant is removed after the whole run.
- Packages: `apparmor`, `iproute2`, `openssl`, and for the venv either network
  access with `gcc` and `python3-dev` (the runtime's C extension is built by
  pip) or a wheelhouse on the node passed as `--wheelhouse PATH`.
- The VM is reverted to S0 afterwards; the run's own cleanup only removes the
  lab key and the Rosetta drop-in. Storage-pressure copies live under
  `/var/lib/azn-vmit-capacity/` on the node's disk only while a scenario runs;
  if a run stops part-way they are kept there (and the next run refuses the
  node) so that nothing is lost.

## 4. The Edge package

Build it with Azazel-Edge's `packaging/nexus-core/nexus_core_package.py` as in
[integration loop rehearsal §2](integration-loop-rehearsal.md#2-build-the-edge-package-separate-x86_64-host),
on a host of the **node's** CPU, and check the three contract files against
`contract/azazel-edge-core/`. The packager labels every package `x86_64`; on
an aarch64 node the run records the binary's real architecture as a deviation.
The run verifies the archive and the binary against the manifest before
anything executes it and refuses on a mismatch.

## 5. Running it

From the checkout to be installed (its `HEAD` is what the node gets):

```sh
python3 -m tools.vm_integration run --disposable-node --target docker:azn-vmit@colima \
  --edge-package edge-dist --out RESULT.json --scratch SCRATCH_DIR
python3 -m tools.vm_integration run --disposable-node --target docker:azn-vmit-amd64@colima-rosetta --rosetta \
  --edge-package edge-dist --out RESULT.json --scratch SCRATCH_DIR
python3 -m tools.vm_integration run --disposable-node --target ssh:NODE --edge-package edge-dist --out RESULT.json
python3 -m tools.vm_integration render RESULT.json
```

`edge-dist` is the packager's output directory (manifest and archive side by
side). A run takes about 15 to 25 minutes: the explainer allows six
explanations a minute and waits 60 s after each restart. The exit status is 1
when any check failed. Remove the container afterwards
(`docker --context colima rm -f azn-vmit`), or revert the VM to S0.

## 6. The checks and what they expect

| id | expectation |
| --- | --- |
| `scenarios.knowledge-status` | `knowledge.status` answers `available`, freshness `current` |
| `scenarios.entry-route` | an operator `mio.route` gets `deterministic handoff`, outcome `refused` |
| `scenarios.reference-direct-refused` | referenced refuses an operator (`principal_denied`): only a service may call it |
| `scenarios.reference-display` | every explanation is the deterministic handoff with `content_kind` `deterministic_notice` and referenced's fixed word (`mio_handoff:no_pack`) |
| `scenarios.knowledge-citation` | every explanation cites `T1110` from the fixture through knowledge-lited |
| `scenarios.status` / `status-private` | `azazel-nexus status` shows intake and explainer running, `(observe-only, not executed)` and Lite `available`, and no incident address |
| `scenarios.edge-decisions` | Edge Core decided twice (notify, isolate) on two alerts, dry run |
| `scenarios.kill.*` | SIGKILL of one daemon: it ends `failed` (`Restart=no`), every other unit and Edge Core (same PID) keep running, the loop explains with the fixed failure for the missing service (`knowledge_unavailable`, `mio_handoff:reference_service_unavailable`, `mio_unavailable`), and a hand restart recovers it |
| `scenarios.broken.*` | a fake peer under the real account (`azmioref`, `azknowledge`) answering with an injection text or garbage is refused (`mio_handoff:reference_refused` / `reference_service_unavailable`, `knowledge_reply_refused` / `knowledge_unavailable`); nothing of its text reaches the record; malformed Edge lines are refused and counted (`EDGE_JSON`, `EDGE_SHAPE`, `EDGE_TOO_LARGE`) |
| `scenarios.expiry.lite-replace` | the expired fixture (same `bundle_version`) cannot replace the admitted bundle; the daemon's store stays `current` |
| `scenarios.expiry.lite-reader` | the expired fixture verifies, serves no indicator and still serves static reference (library on the node, not the daemon) |
| `scenarios.capacity.*` | the writer's directory is a tmpfs holding exactly its data (0 bytes free): the failure is visible (unit `failed`, `storage_failed`, `audit_forward_dropped`, `mio_unavailable`), other units and Edge Core keep running, and the writer starts again when space returns |
| `scenarios.isolation` | auditd, Knowledge, referenced, entryd, intake and the explainer stopped: Edge Core keeps running with the same PID and decides on new alerts |
| `scenarios.h2-edge-restart`, `h1`, `h3`, `h-deps` | observations for assessment §5 H1–H3, reported and never changed here |
| `scenarios.revoke.lite` | a lab-signed revocation of the admitted bundle makes both azknowledge and knowledge-lited read `revoked` |
| `after-restart.*` | the pass granted nothing, no marker, every unit masked again and inactive, a start without a marker is skipped (`ConditionResult=no`), the revocation still reads `revoked` |

## 7. The record

`run --out` writes `azazel-nexus/vm-integration-run/v1` JSON. Every string in
it passes the confidentiality filter of the script: IPv4 and IPv6 addresses,
MACs (colon or hyphen), UUIDs (boot ids), incident ids, `0x` values, 32/64-hex
digests and ids and any other run of 12 or more hex digits (container ids,
fingerprints), in upper or lower case, are replaced, and the node's own host
names (and the SSH destination's host or the container name) are replaced by
name. Clock times and version strings written `version 1.2.3.4` or `v1.2.3.4`
stay readable; a bare four-part version is indistinguishable from an IPv4
address and is replaced. Only the source commit stays readable. Never add a
hostname, interface name, the
Edge journal, evidence or ledger contents to it
([inventory confidentiality](../inventory-confidentiality.md)). Commit the JSON
records and a short Markdown summary under `docs/evidence/`, labelled with
what the node was (container or VM, CPU, emulation).

## 8. Not covered

- The regular activation path (commissioning, approval, grant at boot) — the
  [activation rehearsal](activation-rehearsal.md) on a VM.
- A real model, a Mission Pack, the online AI route, the NOC observation.
- Physical NICs, real storage, power loss, TPM, Secure Boot, performance and
  memory headroom: hardware only ([hardware gates](../hardware-gates.md)).
- A kernel reboot in a container: `docker restart` re-runs systemd's boot,
  not the kernel's; the VM run (`systemctl reboot`) is the one that does.
