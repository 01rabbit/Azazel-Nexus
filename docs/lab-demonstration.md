# Lab demonstration / ラボデモ

「LAB — 実機の根拠ではありません／受け入れではありません／本番の起動ではありません」

Debian 13 aarch64 VMware・2 GiB の所有者向けデモです。`ask` は **SERVICE PATH**
（実 entryd の応答）と **LAB-INPROCESS — 受け入れ外・サービス経路外**（lab プロセス内の
実ライブラリ照合）を分けて表示します。Mission Pack の選択は設計どおり拒否します。
実測 reserve・LUKS・x86_64 の本番条件を偽装しません。SERVICE PATH は deterministic
handoff と `reference_status: unavailable`、元の routing reason をそのまま示します。
LAB-INPROCESS は lab 同梱 baseline の template から候補、代替仮説、信頼データの
確認手順・初動対応・不足情報を表示します。サービスがこの baseline を選択したという意味ではありません。

`bench` は「仮想マシン・ソフトウェア性能（実機の根拠ではない）」だけを測定します。
出力は lab root 内の JSON と日本語表です。実機 evidence、admission、activation には使えません。
Live Edge authority と lease は未観測です。relocation では `Type=notify` が `exec` に変わります。
VM での実起動・実モデル性能は VM 上で下記手順を実行して確認してください。

LAB — NOT hardware evidence / NOT admission / NOT production activation.

## VM installation

Use a disposable Debian 13 test VM, a reviewed checkout at `/opt/src/Azazel-Nexus`,
a separately prepared offline wheel directory `/opt/lab-wheels`, and the pinned
architecture-specific b11716 binary at `/opt/lab-assets/llama-server`.
Nothing is downloaded by the lab. The production installer verifies the runtime
against the existing architecture digest pins. The lab does not launch a model server.
The VM must have Python 3.11+ with venv and the production offline staging inputs
prepared as described in [the systemd runbook](evidence/milestone1-real-systemd-smoke-RUNBOOK.md).

On a fresh VM, install the reviewed production files/accounts first. The installer
masks operational services; explicitly stop and mask the activation controller too.
If the reviewed build is already installed, omit the installer command.

```sh
cd /opt/src/Azazel-Nexus
sudo sh packaging/install.sh --llama-runtime /opt/lab-assets/llama-server
sudo systemctl stop azazel-activated.service
sudo systemctl mask azazel-activated.service
sudo python3 -m venv /opt/azazel-lab/venv
sudo /opt/azazel-lab/venv/bin/python -m pip install --no-index --find-links /opt/lab-wheels . ./runtime ./lab
```

`up` checks that **all production units are already masked and stopped**, including
the activation controller. The lab never enables, unmasks or starts production units.
The separate lab distribution is absent from the production bundle and installed-file
manifest. Do not install it into the production interpreter or daemon import path;
the production loaded-module verifier refuses it.

## Owner demo script

Run from `/opt/src/Azazel-Nexus`. Each command starts with the Japanese and English LAB
banner. `up` succeeds when the three isolated services start and Pack inspection
returns the expected refusal. Its result still records that production refusal.

```sh
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo up
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo status
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo knowledge T1110
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo ask lab/src/azazel_nexus_lab/scenarios/ssh-brute-force.json
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo ask lab/src/azazel_nexus_lab/scenarios/port-scan.json
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo ask lab/src/azazel_nexus_lab/scenarios/phishing.json
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo ask lab/src/azazel_nexus_lab/scenarios/ransomware.json
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo ask lab/src/azazel_nexus_lab/scenarios/out-of-scope.json
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo audit
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo bench --requests 20 --duration 300 --interval 5
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo break knowledge-trust
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo knowledge T1110
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo break locald
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo ask lab/src/azazel_nexus_lab/scenarios/ssh-brute-force.json
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo break pack-expire
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo break audit-tamper
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo audit
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo down
```

The final `audit` is expected to refuse after tampering; run commands individually.
Copy any wanted `demo/bench/*.json` and `*.txt` results **before** `down`, which deletes
that lab root. Keep copies labelled as lab software measurements, outside hardware
evidence directories. `pack-expire` reports unavailable: no active Pack was selected.
For a quick bench plumbing check use `--requests 2 --duration 1 --interval 0.1`;
this short run cannot establish sustained stability.

## What each part demonstrates

- `up`: three real installed daemon wrappers under independently named transient
  units, relocated sandbox properties, ephemeral test trust pins and a real LiteImport
  of the unchanged producer Knowledge fixture. Production Pack inspection refuses
  the lab envelope. That expected refusal does not make the lab startup fail.
- `status`: real `azazel-nexus status` and `setup` against relocated state, beginning
  with `LAB HOST`. Unknown prerequisites remain unknown.
- `knowledge T1110`: real trusted local reader of the fixture. This is an operator
  read; Knowledge socket lookup remains restricted to service principals.
- `ask` SERVICE PATH: actual `mio.advise` over entryd's socket, production principal
  checks and route auditing. Its raw reply, reason and reference status are retained.
  No lab playbook loader is added to production entryd or locald.
- `ask` LAB-INPROCESS: the **same validated frame**, `gate_frame`, real keyword
  `match`, `build_options`, `retrieval_decision`, `delivered_document` and the strict
  delivered-document reader. Provenance is `keyword` and model id `deterministic`.
  Baseline procedures remain unreviewed templates. Out-of-scope input shows its gate
  refusal, rather than an invented candidate. The English header is
  `LAB-INPROCESS — NOT admission / OUTSIDE service path`.
- `ask --embedding` and `bench --embedding`: explicitly refuse with a LAB message
  pointing to `tests/e2e_local_inference/harness.py` for test-only inference.
  The shipped lab has no embedding launcher, production serving subclass, admission
  hook override, or injected admission callback. It does not use or bypass production
  serving/admission. Production admission remains closed; this lab path is not an
  admission. Plain `ask` and `bench` use keyword retrieval. The e2e harness is a
  separate test tool, not an installed lab command or hardware evidence.
- `audit`: route/local/Lite-import hash-chain verification. Knowledge daemon events
  are an **unhashed event log**; JSON framing is checked without a cryptographic claim.
- `break`: trust corruption, stopped locald, or route-ledger tampering. Each prints
  production unit state and activation-approval hashes before/after. Live Edge
  authority and live lease are **unobserved**; file hashes cannot certify them.
- `down`: exact lab-unit stop, overwrite/fsync/unlink of both ephemeral private keys,
  lab-root removal, retained `/etc/azazel-lab/LAB-HOST`. Stop failure retains recovery
  state. Overwriting cannot guarantee physical erasure on SSD/COW/snapshots; discard
  the VM as well. The marker blocks HIL/reserve/model admission/model-import-fetched/commission/commission review/
  bootstrap approval publication; removing it grants no admission.

## Bench contract and interpretation

Schema: `azazel-nexus-lab/bench/v1`. JSON and Japanese summary are created exclusively
under `/var/lib/azazel-lab/<id>/bench/<UTC timestamp>.{json,txt}`, with both LAB banners
and **仮想マシン・ソフトウェア性能（実機の根拠ではない）**. No output-directory flag exists. JSON records package/Python/kernel versions,
architecture and baseline/scenario SHA-256.
Production HIL, reserve and Pack validators refuse the lab schema/domain.

Bench restarts the lab stack before measurement and records per-service elapsed time
from launch to active and socket-file readiness (50 ms polling; socket creation is
not a completed application request). It then measures N actual entryd round trips
**at each concurrency 1, 2, 4**, with individual durations/statuses, median p50 and
nearest-rank p95. The fresh client's process startup is outside the timed exchange.
Keyword latency includes reading/parsing the packaged baseline and document construction.
Embedding serving is unavailable in the shipped lab; `--embedding` refuses before measurement.

Each service reports `/proc/<MainPID>/status` VmRSS/VmHWM and cgroup-v2 `memory.peak`.
Missing kernel counters are `unavailable`/null, never zero evidence. The sustained run repeats serial
entryd batches, reference retrieval and service memory sampling for the configured
wall duration (default 300 s), recording first-to-last RSS and p50/reference latency
deltas plus all samples. Startup/polling and final requests can extend the duration.
No model is loaded by the lab.

For each of knowledge-trust, locald and audit-tamper, bench records elapsed time from
break initiation to three identical responses/refusals 100 ms apart, or a 15 s
observation timeout. It probes the affected surface (Knowledge status socket, entryd, audit validator),
retains the responses, and samples service memory. A stable refusal counts as stable
refusal, not successful recovery. Before/after each experiment it stops lab writers,
restores only the affected lab trust/ledger snapshot, and recreates the lab services.
No production file is restored or modified. Results represent this VM, build,
fixture, concurrency and workload; host contention, paging and cache state affect them.

## Boundaries and relocation

Root clients set primary effective GID to `azazel-operator` in a fresh child;
existing PrincipalPolicy classifies this as OPERATOR. Workers run the installed lab
distribution via `python -I -B -m azazel_nexus_lab.worker`, with cwd `/` and only
fixed PATH/LC_ALL plus the lab-root relocation value in their environment; caller
PYTHONPATH, cwd and environment are not inherited. Supplementary membership alone
does not grant root that class. No real keys or production trust enrollment are used.
The fixed lab root is `/var/lib/azazel-lab/<id>` with 1–12 lowercase ASCII letters/digits;
there is no arbitrary root, admission or trust bypass. `AZAZEL_ROOT` is only the
existing relocation mechanism, established before runtime imports in fresh children.

Relocation uses the smoke parser, command builder, effective-property and syscall
checks, shared as non-production helpers in the lab package. The repository smoke
tool loads those helpers directly; daemon runtime contains no relocation executor. Production `[Unit]` activation dependencies are not applied. **Type=notify →
exec** matches existing relocated READY suppression; it does not establish production
notify readiness. The exact locald production model-identity pre-start hook is omitted.
Other sandbox directives remain checked; effective ReadWritePaths must remain under
the lab root. Unknown hooks, drop-ins or executable paths refuse.

Lab envelopes use `azazel-nexus-lab/` and `azazel-nexus-lab/v1\0`. Native Knowledge
input retains its producer format inside the envelope. Deliberate exception:
`resign_fixture` signs the Lite manifest bytes in the production raw signature
format (without the lab domain), so the real Lite importer can read the fixture.
The signing key is ephemeral; its trust anchor is pinned only under the lab root,
never enrolled in operator trust. Both ephemeral private keys are overwritten,
fsynced and unlinked on `down`, subject to the storage-erasure limits above.
Lab envelopes themselves retain the lab signature domain. Baseline library data is loaded only by the lab
process. Production `src` and `runtime` never import the lab package;
`LOCAL_MODEL_ADMISSION_ENABLED` remains `False`, and `LLAMA_RUNTIME_DIGESTS` is unchanged.
See [hardware gates](hardware-gates.md), [Knowledge trust](knowledge-lite-trust.md),
and [model catalog](model-catalog.md). This work does not depend on sibling issue #162.
