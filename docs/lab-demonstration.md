# Lab demonstration / ラボデモ

「LAB — 実機の根拠ではありません／受け入れではありません／本番の起動ではありません」

Debian 13 aarch64 VMware・2 GiB の所有者向けデモです。別配布の `lab/`
だけを導入し、一時鍵・データ・ソケットを `/var/lib/azazel-lab/demo` に隔離します。
本番 unit は masked のままです。ホストには `/etc/azazel-lab/LAB-HOST` が残り、
HIL・reserve 測定・model admission・commission review・bootstrap approval 公開を拒否します。
マーカーを消しても admission、署名、hardware gate の条件は満たされません。

**現在は部分実装です。** `up` は Knowledge fixture と実 daemon の隔離起動を準備しますが、
Mission Pack の本番検証は lab schema/domain、aarch64、実測 reserve 不在、暗号化されていない
ストレージを受け入れません。本番検証を弱めずに baseline を選択する lab 専用 fixture
provisioning の設計判断が未解決です。`up` はその拒否を表示して degraded（終了コード 1）に
なり、baseline reference と `pack-expire` の完全デモはできません。
この状態を issue #164 の完成や VM 動作確認として扱わないでください。

LAB — NOT hardware evidence / NOT admission / NOT production activation.

The current tool exposes the production refusal instead of fabricating a reserve,
compatibility tuple, encrypted-storage assertion or native pack admission receipt.
It starts only independently named transient copies of the installed daemon wrappers.
No activation controller, remote provider or model is started. The existing
`LOCAL_MODEL_ADMISSION_ENABLED` remains `False`.

## Separate installation

Use a disposable test VM with the reviewed production build already installed and
**all production units masked and stopped**. The lab checks this prerequisite.
It does not mask, unmask, enable or start any production unit.

From this checkout, provision a separate Python environment and a separately
prepared offline wheel directory containing setuptools, PyNaCl, PyYAML and
runtime dependencies. These wheels and the lab are deliberately absent from the
production offline bundle and installed-file manifest.

```sh
sudo python3 -m venv /opt/azazel-lab/venv
sudo /opt/azazel-lab/venv/bin/python -m pip install --no-index --find-links /path/to/lab-wheels . ./runtime ./lab
```

The lab distribution declares `az-nexus-lab`; `packaging/install.sh` does not install it.
Do not install the lab into the production interpreter or add its sources to a daemon's
import path. The production loaded-module verifier explicitly refuses its package.

## Owner demo script

Run these commands individually from the checkout; `up` currently returns 1 with
its explicit degraded result. Do not interpret that as a completed baseline demo.
Each invocation prints the Japanese warning followed by the English warning,
then lab-labelled JSON with `lab: true` and `not_hardware_evidence: true`.
Captured production CLI output remains inside this labelled JSON.

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
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo break knowledge-trust
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo knowledge T1110
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo break locald
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo break pack-expire
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo break audit-tamper
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo audit
sudo /opt/azazel-lab/venv/bin/az-nexus-lab --id demo down
```

What the owner can inspect:

- `up`: three real installed wrappers, relocated sandbox properties, an ephemeral
  public trust pin, a re-signed Knowledge fixture, and the real production Pack
  CLI refusing the lab envelope. The refusal is an explicit limitation.
- `status`: real `azazel-nexus status` and `setup` against relocated state. Both
  begin with `LAB HOST` on a marked machine. Unknown prerequisites remain unknown.
- `knowledge T1110`: the producer fixture's Brute Force reference through the real
  trusted reader. This operator command reads locally; Knowledge socket lookup
  remains restricted to service principals.
- `ask`: `mio.advise` sent over the real entryd socket, with production principal
  checks and route auditing. Until baseline fixture selection is resolved, security
  questions retain deterministic fallback without a selected baseline reference.
  Out-of-scope requests retain their bounded refusal.
- `audit`: route/local/Lite-import hash-chain verification. Knowledge daemon events
  are an **unhashed event log**; the command validates JSON framing and labels that
  limitation instead of claiming a cryptographic chain.
- `break`: Knowledge trust becomes unreadable, locald stops, or the route ledger
  is tampered. `pack-expire` currently reports unavailable because no pack was
  selected. Every break prints the unchanged production-unit and activation-approval
  snapshot. Live Edge authority and live lease are explicitly unobserved: this
  build has no live authority-query transport, so file hashes cannot certify them.
- `down`: stop the exact lab units, overwrite/sync/unlink both ephemeral private
  keys, remove the lab root, retain the host marker. Failure to stop a unit retains
  the root and keys for recovery. Overwriting cannot guarantee physical erasure
  on SSD, snapshot or copy-on-write storage; discard the disposable VM as well.

## Boundaries and principal

The root-run client sets its **primary effective GID** to `azazel-operator` in a
fresh child process. Existing `PrincipalPolicy` explicitly classifies this combination
as an operator. Root's supplementary group membership alone does not do so.
No new operator account, operator private key or production trust enrollment is
created. The lab never reads `~/azazel-operator-key`.

The root is fixed under `/var/lib/azazel-lab/<id>`; ids contain at most twelve ASCII
letters/digits. There is no arbitrary root or trust override. `AZAZEL_ROOT` is used
only for the existing relocation mechanism in fresh daemon/client processes. No
production gate gains an environment-variable bypass.

Relocation reuses the smoke tool's parser, command builder, effective-property and
syscall verification. Production `[Unit]` activation dependencies are never applied.
`Type=notify` becomes `exec`, because the existing relocated runtime suppresses READY.
The exact locald production identity pre-start hook is omitted: it provisions a
production model identity, and no model may be admitted here. All remaining sandbox
directives are retained and checked after startup. Effective `ReadWritePaths` must
resolve within the lab root. An unreviewed hook, drop-in or executable refuses.

Exported lab envelopes and scenarios use `azazel-nexus-lab/` schemas and the signature
domain `azazel-nexus-lab/v1\0`. Native Knowledge importer input retains its producer's
signature format *inside* the lab envelope, signed with an ephemeral test key pinned
only under the lab root. The fixture tables come unchanged from the existing producer
fixture builder output pinned in `contract/azazel-knowledge-lite/FIXTURE.json`; the
builder's source is not vendored here. Production Pack/reserve validators refuse lab
schemas, and production Pack signatures refuse the lab domain even with a trusted key.
The lab envelope is never converted into production hardware evidence.

See [hardware gates](hardware-gates.md), [Knowledge trust](knowledge-lite-trust.md),
and [the real systemd smoke runbook](evidence/milestone1-real-systemd-smoke-RUNBOOK.md).
This work is stacked on `work/issue-163`; it does not import or depend on sibling
`work/issue-162` or substitute for that lane's HIL virtualization/refusal corpus.
