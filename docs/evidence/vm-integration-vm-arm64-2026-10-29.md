# 実 systemd 統合検証（V1）— Arm VM（VMware Fusion、aarch64）：2026-10-29

**Arm VM での VM ソフトウェア統合の証拠（ADR-0003 D5）。実機の証拠ではなく、ハードウェアゲートを閉じない。**
HIL の証跡ではなく、キャンペーンに使わず、HG の欄にも載せない
（[実機受入 §1](../hardware-acceptance.md)）。
手順は [real-systemd integration run](../hil-runbooks/vm-integration.md) の §3.3・§5、
記録の原本は [`vm-integration-vm-arm64-2026-10-29/`](vm-integration-vm-arm64-2026-10-29/)
の JSON 1 件（`azazel-nexus/vm-integration-run/v1`、`render` で下の表を生成）。

## 条件

| 項目 | 値 |
| --- | --- |
| 実行場所 | VMware Fusion（macOS ホスト、Apple silicon）上の Debian 13.7 arm64 VM。systemd 257 が PID 1、kernel 6.12 arm64、4 vCPU、RAM 約 2.9 GiB。**エミュレーションなし（ネイティブ aarch64 の仮想化）** |
| 対象の指定 | `--target ssh:<NODE>`（鍵認証、ノード側は `sudo -n`）、`--disposable-node` |
| 開始状態 | 作業前の snapshot S0 から、過去の Azazel 導入の残骸（`/opt/azazel*`・`/etc/azazel*`・`/var/lib/azazel*`・`/usr/libexec/azazel`・azazel の unit と AppArmor profile・az* のアカウントとグループ）を手で除いた状態。**OS を新しく入れた状態ではない**。過去の commissioning リハーサルの `/etc/crypttab` の 1 行は残し、その `systemd-cryptsetup` unit は導入前から毎回の起動で失敗している（起動はその timeout を待つ） |
| 導入した commit | `7ef1702`（worktree clean、`git archive HEAD`） |
| Python と venv | Debian の CPython 3.13.5。VM は外部に出られない（host-only の NIC のみ、既定経路なし）ので `--wheelhouse` を使った：V2 と同じ aarch64 lab の wheelhouse に build backend の `setuptools==84.0.0` の wheel を足したもの。本番 venv `/opt/azazel-nexus/venv` は pip `--no-index` で source から構築 |
| ノードに足したもの | runtime の C 拡張を source から build するための `gcc` と `python3-dev`（Debian 13.7 の公式 deb を Mac で取得して VM に置き、VM の署名済み apt の索引と照合して `apt-get install --no-download` で導入） |
| Edge | Azazel-Edge `cc769e0` を `rust:1-trixie`（aarch64）で build し Edge の packager で包装したもの（[コンテナの記録](vm-integration-container-2026-10-28.md) と同じ package）。契約 3 ファイルは Nexus の `contract/azazel-edge-core/` と一致。**中身は aarch64、名前は packager 固定の x86_64。arm64 の Edge Core pin は無い**（[オーナー判断 H5](../owner-decisions.md#2-優先度の高いもの)）。逸脱として下に記録する |
| 起動経路 | リハーサル専用の手動起動（統合ループ手順書 §6）。**activation admission: not exercised** |
| 再起動 | `systemctl reboot`（**新しい kernel boot**。boot id が変わったことを道具が確認） |

使ったもの：本番の `install.sh`・本番 unit・本番アカウント・実 Unix socket・実 daemon（実プロセス）。
Edge Core は aarch64 の実バイナリ（dry run、advisory）、刺激は合成の eve 行。Knowledge は公開 fixture
（テスト専用鍵）。モデルは使っていない（`LOCAL_MODEL_ADMISSION_ENABLED=False` のまま）。
ラボ鍵は Lite の失効署名鍵 1 本だけで、ノードの `/run/azn-vmit` に生成し、再起動で消えた。
ラボ印 `/etc/azazel-lab/LAB-HOST` は道具が書いて残した。VM は終了後に S0 へ戻した。

## 結果の要約

- **pass 55 / fail 0 / skip 2**（`{"pass": 55, "fail": 0, "skip": 2}`、終了コード 0）。
  skip は「locald の応答改変」（admission が閉じていて locald は誰にも呼ばれない）と
  「Mission Pack の期限」（commissioning と HG-05 がなく、pack を ACTIVE にできない）。
  コンテナの aarch64（54 / 0 / 2）より 1 件多いのは、その後に入った `start.lab-marker`。
- **kernel の再起動を経た `after-restart`**（コンテナではできなかったもの）：起動時の
  activation pass は `granted=0, withheld=16, reasons=no_generation`。手で作った marker は
  0 件、手で unmask した unit はすべて再び masked・inactive、tmpfs 上の auditd の複製と
  ラボ鍵は消え、marker なしの起動は `ConditionResult=no` で skip、再起動前に入れた Lite の
  失効は `revoked` のまま。activation ledger の最後は `activation.inputs_incomplete`。
- モデルなしの参照（`deterministic handoff`、`mio_handoff:no_pack`）、Knowledge Lite の
  `T1110` の引用、SIGKILL・偽の応答・壊れた Edge 行・容量圧迫・advisory 側の全停止の
  いずれでも、他の unit と Edge Core（同じ PID）は動き続けた。

## 逸脱

| # | 内容 |
| --- | --- |
| D1 | Edge Core は aarch64 の実バイナリだが、arm64 の Edge Core pin は無く、package の名前と manifest の `architecture` は packager 固定の `x86_64`（道具の `start.edge-package` も逸脱として記録）。Edge Core を含む検査（`edge-decisions`、`kill.*` の Edge 継続、`isolation`、`h2-edge-restart`、`h-deps`、`start.edge-posture`・`edge-probe`）は **この逸脱の上での pass** であり、arm64 の Edge 配備の証拠ではない。偽の digest や amd64 バイナリは使っていない |
| D2 | VM は S0 の残骸を手で除いた状態で、新しく入れた OS ではない（条件の表） |
| D3 | 本番 venv の依存は lab の wheelhouse から入れ、Nexus の 2 つは source から build（ノードに gcc と python3-dev を足した）。V2 のオフライン bundle による導入とは別の経路 |

## 見つかったこと

| # | 内容 | 扱い |
| --- | --- | --- |
| F1 | `tools/vm_integration.py` の `prepare` は、`--wheelhouse` を渡すと前提の検査から `gcc` と `Python.h` を外す。しかし venv には source のパス（`SRC` と `SRC/runtime`）を `pip install` するので、runtime の C 拡張の build に compiler と header が要る。compiler の無いノードでは、前提の検査を通った後に `prepare.venv` で失敗するはず（この実行では gcc を先に入れたので未再現。コードの読みによる） | 報告のみ（試験用の道具の前提検査の不一致。製品の動作ではない） |
| F2 | H2：`azazel-edge-core.service` は `Restart=no`。SIGKILL 後は `failed` のまま（コンテナの F2 と同じ） | 報告のみ。オーナー判断 |
| F3 | H1：intake を止めると、Edge の判断は Edge の journal にしか残らない（コンテナの F4 と同じ） | 報告のみ |
| F4 | S0 に残る `/etc/crypttab` の 1 行のため、毎回の起動で `systemd-cryptsetup@azn\x2dcommissioning.service` が失敗し、`is-system-running` は `degraded`。この run の検査には影響しなかった | VM 側の残骸。製品の欠陥ではない |

## これが示さないもの

- 実機（Arm・amd64）での挙動、実 NIC、実記憶域、電源断、TPM、Secure Boot、性能、メモリ余力。
- 通常の activation 経路による付与（承認・lease・generation）。この run は付与しないことだけを確かめる。
- arm64 の Edge Core の配備（pin が無い）、x86_64 での `MemoryDenyWriteExecute` と `SystemCallFilter`。
- 実モデル、オンライン AI、Mission Pack、NOC 観測。
- VMware 以外の仮想化基盤での同じ結果。

## 手順（再現）

1. VM の snapshot S0 を取り、過去の導入の残骸があれば除く（runbook §3.3 の fresh node）。
2. aarch64 の build host で lab の wheelhouse を作る（[V2 の記録](offline-install-aarch64-lab-vm-2026-10-29.json) と同じ）。ノードの root 所有の directory に、その wheel と `setuptools==84.0.0` の wheel を置く。ノードに `gcc` と `python3-dev` を入れる。
3. Mac 側の checkout（HEAD が導入される）から：

   ```sh
   python3 -m tools.vm_integration run --disposable-node --target ssh:<NODE> \
     --edge-package <aarch64 Edge package dir> --wheelhouse <node wheelhouse dir> \
     --out RESULT.json --scratch <SCRATCH_DIR>
   python3 -m tools.vm_integration render RESULT.json
   ```

4. VM を S0 に戻す。

## 各チェック

### aarch64（Arm VM、VMware）— aarch64-vmware.json

- 範囲: VM software integration: not hardware evidence
- commit: `7ef170236d9b`（worktree: clean）
- 環境: <host> GNU/Linux 13, kernel 6.12.113+deb13-arm64, systemd 257, virtualization vmware
- 結果: pass 55 / fail 0 / skip 2

| id | 結果 | 内容 |
| --- | --- | --- |
| `prepare.fresh-node` | pass | the node is a fresh, disposable lab node: the operator passed --disposable-node; no venv, /etc/azazel, /var/lib/azazel or kept capacity data |
| `prepare.tools` | pass | installer and run prerequisites present: apparmor_parser, ip, setpriv, runuser, systemd-run, openssl |
| `prepare.venv` | pass | azazel-nexus and the runtime installed into the production venv: pip --no-index (wheelhouse), exit 0 |
| `prepare.install` | pass | packaging/install.sh (production units and accounts): exit 0; Azazel-Nexus installed. Operational units are masked. / The next boot records a fail-closed activation decision; no unit is / admitted until the required admission and health evidence is available. |
| `prepare.masked` | pass | every governed unit this run uses is installed masked: {"azazel-auditd.service": "masked", "azazel-edge-core.service": "masked", "azazel-edge-intaked.service": "masked", "azazel-edge-probed.service": "masked", "azazel-incident-explaind.service": "masked", "azazel-knowledge-lited.service": "masked", "azazel-mio-entryd.service": "masked", "azazel-mio-referenced.service": "masked"} |
| `prepare.controller` | pass | the activation controller is enabled for the next boot:  |
| `prepare.no-lab-marker` | pass | no lab marker (/etc/azazel-lab/LAB-HOST) on the node:  |
| `start.controller-idle` | pass | the activation controller is not running (its boot pass is over): {"Result": "success", "ActiveState": "inactive"} |
| `start.lab-marker` | pass | the node is marked as a lab host before the public fixture key is pinned: /etc/azazel-lab/LAB-HOST written by this run (azazel_nexus.lab_keys) |
| `start.knowledge-enroll` | pass | Knowledge Lite enrolled from the public fixture (knowledge-lite-consumer §11): reasons seen by azknowledge in order: trust_unreadable -> unverified -> no_bundle -> available; fixture anchor key pinned (public, test-only), revocation policy with this run's lab key written by the repin library call as azcommission (not through az-commissiond) |
| `start.edge-package` | pass | Edge package verified against its manifest and installed: binary architecture aarch64 under the packager's fixed x86_64 name (a recorded deviation: the packager labels every package x86_64); eve.json created empty, azedge group read (no Suricata) |
| `start.audit-copy` | pass | auditd rehearsal copy (integration-loop §6.1) passes systemd-analyze verify with no warning:  |
| `start.hand-start` | pass | rehearsal-only start (§6): hand-made grant markers, --job-mode=ignore-requirements: {"azn-rehearsal-auditd.service": "started", "azazel-knowledge-lited.service": "started", "azazel-mio-referenced.service": "started", "azazel-mio-entryd.service": "started", "azazel-edge-intaked.service": "started", "azazel-incident-explaind.service": "started", "azazel-edge-probed.service": "started", "azazel-edge-core.service": "started"} |
| `start.edge-posture` | pass | Edge Core started observe-only (dry run, advisory): {"defense_dry_run": "true", "defense_enforce": "false", "defense_enforce_level": "advisory", "high_impact_auto": "false"} |
| `start.edge-probe` | pass | the four-check probe reads health and running passed after Edge started: {"health": "passed", "running": "passed"} |
| `scenarios.knowledge-status` | pass | knowledge-lited answers knowledge.status: available: {"state": "available", "reason_code": "available", "freshness": "current"} |
| `scenarios.entry-route` | pass | entryd routes an operator request to the deterministic handoff (no model admitted): {"route": "deterministic handoff", "outcome": "refused", "reason": "degraded to the deterministic handoff: no candidate is permitted besides it"} |
| `scenarios.reference-direct-refused` | pass | referenced refuses an operator connecting directly (service principal only): {"ok": false, "refusal": "principal_denied"} |
| `scenarios.reference-display` | pass | explainer records the deterministic handoff with referenced's fixed missing-reference word: [{"transition": "opened", "edge_would": "notify", "route": "deterministic handoff", "outcome": "refused", "reason": "mio_handoff:no_pack", "content_kind": "deterministic_notice", "knowledge_state": "available", "citations": ["T1110"], "failure_codes": ["mio_handoff"]}, {"transition": "updated", "edge_would": "isolate", "route": "deterministic handoff", "outcome": "refused", "reason": "mio_handoff:no_pack", "content_kind": "deterministic_notice", "knowledge_state": "available", "citations": ["T1110"], "failure_codes": ["mio_handoff"]}] |
| `scenarios.knowledge-citation` | pass | explanations cite the fixture bundle (T1110) through knowledge-lited: [["T1110"], ["T1110"]] |
| `scenarios.status` | pass | azazel-nexus status shows intake, explainer, the observe-only incident and Lite available: edge loop section and Knowledge Lite section read |
| `scenarios.status-private` | pass | status carries no address from the incident: 0 address(es) found |
| `scenarios.edge-decisions` | pass | Edge Core decided twice (notify then isolate) on the two alerts, dry run: 2 decision line(s) |
| `scenarios.kill.azazel-knowledge-lited` | pass | SIGKILL azazel-knowledge-lited.service: others keep running, fail-closed degradation, hand restart recovers: the loop still explained, with the fixed failure for the missing service; repaired before: none; state after kill failed/signal, Restart=no, NRestarts=0; others active: True; Edge Core unchanged: True; restarted: active |
| `scenarios.kill.azazel-mio-referenced` | pass | SIGKILL azazel-mio-referenced.service: others keep running, fail-closed degradation, hand restart recovers: the loop still explained, with the fixed failure for the missing service; repaired before: none; state after kill failed/signal, Restart=no, NRestarts=0; others active: True; Edge Core unchanged: True; restarted: active |
| `scenarios.kill.azazel-mio-entryd` | pass | SIGKILL azazel-mio-entryd.service: others keep running, fail-closed degradation, hand restart recovers: the loop still explained, with the fixed failure for the missing service; repaired before: none; state after kill failed/signal, Restart=no, NRestarts=0; others active: True; Edge Core unchanged: True; restarted: active |
| `scenarios.kill.azn-rehearsal-auditd` | pass | SIGKILL azn-rehearsal-auditd.service: others keep running, fail-closed degradation, hand restart recovers: the loop still explained, with the fixed failure for the missing service; repaired before: none; state after kill failed/signal, Restart=no, NRestarts=0; others active: True; Edge Core unchanged: True; restarted: active |
| `scenarios.kill.azazel-incident-explaind` | pass | SIGKILL azazel-incident-explaind.service: others keep running, fail-closed degradation, hand restart recovers: intake kept accepting with the explainer dead; nothing explained; repaired before: none; state after kill failed/signal, Restart=no, NRestarts=0; others active: True; Edge Core unchanged: True; restarted: active |
| `scenarios.kill.azazel-edge-intaked` | pass | SIGKILL azazel-edge-intaked.service: others keep running, fail-closed degradation, hand restart recovers: Edge kept deciding with intake dead (its forward fails, decisions stay in its journal); repaired before: none; state after kill failed/signal, Restart=no, NRestarts=0; others active: True; Edge Core unchanged: True; restarted: active |
| `scenarios.broken.referenced-injection` | pass | referenced-injection: a reference reply under azmioref is refused; the loop explains without it: [{"transition": "opened", "edge_would": "notify", "route": "deterministic handoff", "outcome": "refused", "reason": "mio_handoff:reference_refused", "content_kind": "deterministic_notice", "knowledge_state": "available", "citations": ["T1110"], "failure_codes": ["mio_handoff"]}, {"transition": "updated", "edge_would": "isolate", "route": "deterministic handoff", "outcome": "refused", "reason": "mio_handoff:reference_refused", "content_kind": "deterministic_notice", "knowledge_state": "available", "citations": ["T1110"], "failure_codes": ["mio_handoff"]}, {"transition": "opened", "edge_would":  |
| `scenarios.broken.referenced-garbage` | pass | referenced-garbage: a garbage reply under azmioref is refused; the loop explains without it: [{"transition": "opened", "edge_would": "notify", "route": "deterministic handoff", "outcome": "refused", "reason": "mio_handoff:reference_service_unavailable", "content_kind": "deterministic_notice", "knowledge_state": "available", "citations": ["T1110"], "failure_codes": ["mio_handoff"]}, {"transition": "updated", "edge_would": "isolate", "route": "deterministic handoff", "outcome": "refused", "reason": "mio_handoff:reference_service_unavailable", "content_kind": "deterministic_notice", "knowledge_state": "available", "citations": ["T1110"], "failure_codes": ["mio_handoff"]}] |
| `scenarios.broken.knowledge-injection` | pass | knowledge-injection: a knowledge reply under azknowledge is refused; the loop explains without it: [{"transition": "opened", "edge_would": "notify", "route": "deterministic handoff", "outcome": "refused", "reason": "mio_handoff:no_pack", "content_kind": "deterministic_notice", "knowledge_state": "unavailable", "citations": [], "failure_codes": ["mio_handoff", "knowledge_reply_refused"]}, {"transition": "updated", "edge_would": "isolate", "route": "deterministic handoff", "outcome": "refused", "reason": "mio_handoff:no_pack", "content_kind": "deterministic_notice", "knowledge_state": "unavailable", "citations": [], "failure_codes": ["mio_handoff", "knowledge_reply_refused"]}] |
| `scenarios.broken.knowledge-garbage` | pass | knowledge-garbage: a garbage reply under azknowledge is refused; the loop explains without it: [{"transition": "opened", "edge_would": "notify", "route": "deterministic handoff", "outcome": "refused", "reason": "mio_handoff:no_pack", "content_kind": "deterministic_notice", "knowledge_state": "unavailable", "citations": [], "failure_codes": ["mio_handoff", "knowledge_unavailable"]}, {"transition": "updated", "edge_would": "isolate", "route": "deterministic handoff", "outcome": "refused", "reason": "mio_handoff:no_pack", "content_kind": "deterministic_notice", "knowledge_state": "unavailable", "citations": [], "failure_codes": ["mio_handoff", "knowledge_unavailable"]}] |
| `scenarios.broken.locald` | skip | locald reply alteration: not exercised: model admission is closed (LOCAL_MODEL_ADMISSION_ENABLED=False), so entryd never contacts locald and azazel-mio-locald.service is never granted; altering a reply nobody reads proves nothing |
| `scenarios.broken.edge-lines` | pass | malformed Edge lines are refused by intake, counted, and nothing is accepted: refusals +4; accepted unchanged: True |
| `scenarios.expiry.lite-replace` | pass | an equal-version bundle (the expired fixture) cannot replace the admitted one; the daemon's store keeps serving the current bundle: import admitted=False, transitions ['lite.import.started', 'lite.import.quarantined']; azknowledge reads available/current |
| `scenarios.expiry.lite-reader` | pass | an expired bundle verifies, serves no indicator and still serves static reference (library on the node, not the daemon): admitted=True; time-bound stale, static available; dated rows served 0, reference rows 4 at the node's current time |
| `scenarios.expiry.pack` | skip | Mission Pack expiry: not exercised: no Mission Pack can be ACTIVE here -- pack admission needs commissioning on LUKS storage and a measured Core reserve (HG-05), and this run fabricates neither; referenced therefore answers no_pack, which is the fixed missing-reference word recorded above |
| `scenarios.capacity.route-ledger` | pass | storage pressure on route-ledger: the writer's failure is visible and contained, other units and Edge Core keep running, and it recovers when space returns: {"free_bytes": 0, "precondition_repaired": [], "drives": 1, "restore": "ok", "writers_started": {"azazel-mio-entryd.service": "active"}, "writers_after": {"azazel-mio-entryd.service": "failed"}, "effects": ["azazel-mio-entryd.service failed", "explanation failure codes mio_unavailable"], "edge_decisions": 2, "recovered": {"azazel-mio-entryd.service": "active"}, "explanations": 2, "status_audit_line": "audit: ok -- chain verified at auditd start; chain 5.9 KiB in 1 segment(s); 6.8 GiB free on its filesystem; warns at >= 1.0 GiB chain or < 1.0 GiB free; rate_limited: none (snapshot 54s old)"} |
| `scenarios.capacity.intake-segment` | pass | storage pressure on intake-segment: the writer's failure is visible and contained, other units and Edge Core keep running, and it recovers when space returns: {"free_bytes": 0, "precondition_repaired": [], "drives": 1, "restore": "ok", "writers_started": {"azazel-edge-intaked.service": "active"}, "writers_after": {"azazel-edge-intaked.service": "active"}, "effects": ["intake storage_failed", "intake refused {\"storage_failed\": 2}"], "edge_decisions": 2, "recovered": {"azazel-edge-intaked.service": "active"}, "explanations": 0, "status_audit_line": "audit: ok -- chain verified at auditd start; chain 9.3 KiB in 1 segment(s); 6.8 GiB free on its filesystem; warns at >= 1.0 GiB chain or < 1.0 GiB free; rate_limited: none (snapshot 10s old)"} |
| `scenarios.capacity.incident-ledger` | pass | storage pressure on incident-ledger: the writer's failure is visible and contained, other units and Edge Core keep running, and it recovers when space returns: {"free_bytes": 0, "precondition_repaired": [], "drives": 2, "restore": "ok", "writers_started": {"azazel-edge-intaked.service": "active"}, "writers_after": {"azazel-edge-intaked.service": "active"}, "effects": ["intake storage_failed", "intake refused {\"storage_failed\": 2}"], "edge_decisions": 2, "recovered": {"azazel-edge-intaked.service": "active"}, "explanations": 2, "status_audit_line": "audit: ok -- chain verified at auditd start; chain 9.3 KiB in 1 segment(s); 6.8 GiB free on its filesystem; warns at >= 1.0 GiB chain or < 1.0 GiB free; rate_limited: none (snapshot 46s old)"} |
| `scenarios.capacity.audit` | pass | storage pressure on audit: the writer's failure is visible and contained, other units and Edge Core keep running, and it recovers when space returns: {"free_bytes": 0, "precondition_repaired": [], "drives": 3, "restore": "ok", "writers_started": {"azn-rehearsal-auditd.service": "active"}, "writers_after": {"azn-rehearsal-auditd.service": "failed"}, "effects": ["azn-rehearsal-auditd.service failed", "explainer audit_forward_dropped +1"], "edge_decisions": 2, "recovered": {"azn-rehearsal-auditd.service": "active"}, "explanations": 6, "status_audit_line": "audit: ok -- WARNING: capacity warning (filesystem_free): nothing is deleted (retention policy: never delete, warn only); see docs/operations.md (Audit chain retention); chain verified at auditd start; chain 10.0 KiB in 1 segment(s); 0 B free on its filesystem; warns at >= 1.0 GiB chain or < 1.0 GiB free; capacity warning (filesystem_free); rate_limited: none (snapshot 45s old)"} |
| `scenarios.isolation` | pass | with auditd, Knowledge, referenced, entryd, intake and the explainer stopped, Edge Core keeps running and deciding (dry run): advisory units: {"azn-rehearsal-auditd.service": "inactive", "azazel-knowledge-lited.service": "inactive", "azazel-mio-referenced.service": "inactive", "azazel-mio-entryd.service": "inactive", "azazel-edge-intaked.service": "inactive", "azazel-incident-explaind.service": "inactive"}; Edge Core active, same PID: True; decisions on the new alerts: 2; intake accepted +0 (H1: the decisions exist only in Edge's journal while intake is down; forward-related journal lines seen: 1) |
| `scenarios.h2-edge-restart` | pass | H2 observed: Edge Core after SIGKILL: Edge Core failed/signal after 5 s, Restart=no, NRestarts=0: nothing restarts it in this build (finding reported, unit unchanged) |
| `scenarios.h-deps` | pass | Edge Core's unit names no advisory, Knowledge, explainer, intake or audit unit as Requires/BindsTo/PartOf/Wants: {"Requires": "azazel-activated.service sysinit.target system.slice", "BindsTo": "", "PartOf": "", "Wants": "tmp.mount -.mount"} |
| `scenarios.h1` | pass | H1 observed: Edge's own normalized log: AZAZEL_FORWARD_LOG=false: with intake stopped or full, Edge's decisions persist only in its journal (LogRateLimitBurst applies); finding reported, unit unchanged |
| `scenarios.h3` | pass | H3 observed: auditd and the controller: azazel-auditd BindsTo=; azazel-activated Requires=system.slice BindsTo=-: no unit dependency lets auditd stop the controller or Edge Core; a full audit store is read by the next boot's pass (node health), which is outside a container hand start |
| `scenarios.revoke.lite` | pass | a lab-signed Lite revocation of the admitted bundle stops serving it: modes written by accept {"revocations.signed": "0o640", "revocation-policy.json": "0o640"} (set to trust.json's for the reader); accept exit 0 ; azknowledge reads quarantined/revoked; knowledge-lited answers quarantined/revoked |
| `after-restart.pass` | pass | the activation pass ran and granted nothing: az-activated completed safely: granted=0, withheld=16, reasons=no_generation |
| `after-restart.markers` | pass | no grant marker survived the restart: 0 marker(s) |
| `after-restart.remasked` | pass | every hand-unmasked unit is masked again by the pass: {"azazel-knowledge-lited.service": "masked", "azazel-mio-referenced.service": "masked", "azazel-mio-entryd.service": "masked", "azazel-edge-intaked.service": "masked", "azazel-incident-explaind.service": "masked", "azazel-edge-core.service": "masked", "azazel-edge-probed.service": "masked"} |
| `after-restart.not-running` | pass | no hand-started unit came back: {"azazel-knowledge-lited.service": "inactive", "azazel-mio-referenced.service": "inactive", "azazel-mio-entryd.service": "inactive", "azazel-edge-intaked.service": "inactive", "azazel-incident-explaind.service": "inactive", "azazel-edge-core.service": "inactive", "azazel-edge-probed.service": "inactive", "azn-rehearsal-auditd.service": "inactive"} |
| `after-restart.no-rehearsal-files` | pass | the auditd copy and the lab key (both on tmpfs) are gone:  |
| `after-restart.start-refused` | pass | a start without this boot's grant marker is skipped (ConditionPathExists): exit 0; {"ActiveState": "inactive", "ConditionResult": "no"} |
| `after-restart.revocation-holds` | pass | the Lite revocation made before the restart still holds: quarantined/revoked |
| `after-restart.ledger` | pass | the activation ledger's last entry: activation.inputs_incomplete; missing_producers authoritative_commissioning_admission, renderer_measurement, edge_evidence, authenticated_commissioning, inventory_binding, node_identity, activation_policy, epoch_high_water |
| `cleanup.lab-keys` | pass | lab key material destroyed (overwritten, then removed): 0 file(s) overwritten and removed under /run/azn-vmit; the container or VM itself is discarded (or reverted to its snapshot) after the run |
