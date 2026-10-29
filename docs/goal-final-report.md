# ゴールの最終報告（Arm・共通中核・UI・Knowledge 連携）

Status: **報告（2026-10-29、main `0ed7ab0` 時点）。** 実機がまだ使えない条件で、
Azazel-Nexus を Arm Linux VM で検証できる構成・amd64 と Arm に共通の中核処理・
オフラインの操作 UI・Fabric 契約に基づく Knowledge 連携まで進めたゴール
（#355〜#383）の結果をまとめる。一次資料は main のコードと文書、`git log` の
squash コミット、各 PR の本文とレビュー対応のコメントである。PR 番号は
[01rabbit/Azazel-Nexus](https://github.com/01rabbit/Azazel-Nexus) の pull request。

**この文書が示さないもの**：実機での結果（§3・§5）。ここにある試験の結果は
すべて Linux コンテナでのものである（この報告の後、2026-10-29 に Arm VM で V1〜V3 を実行した。
[記録](evidence/arm-vm-acceptance-vm-arm64-2026-10-29.md)。VM の結果でありハードウェアゲートは閉じない）。有限回のレビューで見つけて直した問題を挙げるが、
それで安全が証明されたとは言えない（§4）。オーナー判断はどれも未決である（§6）。

関連：[契約表](contract-table.md) ·
[実機受入手順](hardware-acceptance.md) ·
[オーナー判断の一覧](owner-decisions.md) ·
[ADR-0003](adr/0003-arm-software-verification-profile.md)

## 1. 目的と 6 つの設計原則

目的は、実機を待たずに進められる範囲（Arm VM で検証できる構成、CPU に依存しない
中核、オフライン UI、Fabric 契約と Knowledge Lite の連携）を、実装・試験・敵対的
レビュー・修正・再検証まで終えることだった。配備基準は amd64（Debian 13）のまま
変えていない（[ADR-0002](adr/0002-debian-13-baseline.md)、
[ADR-0003](adr/0003-arm-software-verification-profile.md)）。

各原則をどこで守っているかを示す。PR はすべて main に squash でマージ済み。

| # | 原則 | PR | コード | 試験 |
| --- | --- | --- | --- | --- |
| 1 | Fabric が契約、Knowledge が根拠、M.I.O. が説明と助言、Edge が判断と執行。Nexus と UI に防御判断の権限を作らない | #355（`azui` を SERVICE から外す）、#358・#363・#364（status の read model と snapshot。Edge の判断は「would」として表示）、#365・#372（操作の無い読取専用 UI） | [`principal.py`](../runtime/src/azazel_nexus_runtime/principal.py)、[`status_view.py`](../src/azazel_nexus/status_view.py)、[`ui_serve.py`](../runtime/src/azazel_nexus_runtime/ui_serve.py)、[`ui_model.py`](../src/azazel_nexus/ui_model.py) | [`test_ui_account_privilege.py`](../tests/unit/test_ui_account_privilege.py)（`azui` はどの daemon のどの verb も拒否される）、[`test_ui_serve.py`](../tests/unit/test_ui_serve.py)、[`test_status_view.py`](../tests/unit/test_status_view.py) |
| 2 | 条件が揃えばオンライン AI、通信不能なら認可済みローカル AI、AI 不能なら決定論の処理と検証済みの参照へ退避 | #356（entryd が locald の認可状態を読んで LOCAL の選択に反映）、#361（送信同意の永続化と、送信直前の撤回世代の照合） | [`mio_entryd.py`](../runtime/src/azazel_nexus_runtime/mio_entryd.py)、[`mio_locald.py`](../runtime/src/azazel_nexus_runtime/mio_locald.py)、[`mio_remote_consent.py`](../runtime/src/azazel_nexus_runtime/mio_remote_consent.py)、[`remote_envelope.py`](../src/azazel_nexus/remote_envelope.py) | [`test_mio_local_admission.py`](../tests/unit/test_mio_local_admission.py)、[`test_mio_remote_consent.py`](../tests/unit/test_mio_remote_consent.py)、[`test_mio_entryd_opt_in.py`](../tests/unit/test_mio_entryd_opt_in.py)。モデルなしの決定論の handoff はコンテナ内 systemd の統合実行で確認（[記録](evidence/vm-integration-container-2026-10-28.md)） |
| 3 | AI・Knowledge・UI が止まっても Edge の検知・判断・証拠・lease 失効を止めない | #366（実 systemd の統合実行と障害注入、容量切れで ledger が壊れる欠陥の修正）、#372（UI を止めても他が止まらないことの確認）、#375（Lite import 中も決定論の経路は止まらない） | [`audit.py`](../src/azazel_nexus/audit.py)、[`vm_integration.py`](../tools/vm_integration.py) | [`test_audit_chain.py`](../tests/unit/test_audit_chain.py)、[`test_vm_integration.py`](../tests/unit/test_vm_integration.py)。SIGKILL・偽の応答・壊れた Edge 行・容量圧迫で Edge Core が同じ PID のまま動き続けたことを[記録](evidence/vm-integration-container-2026-10-28.md)に残した |
| 4 | Arm と amd64 で判断・認可・契約・監査の意味・失敗時の動作・操作を変えない | #360（CPU 名の正規化を platform profile に集約）、#371（共通試験ベクトル 13 件）、#373（導入時の CPU 評価）、#382（tested tuple の CPU を profile から読む） | [`platform_profile.py`](../src/azazel_nexus/platform_profile.py)、[`cross_arch.py`](../tests/vectors/cross_arch.py)、[`cross_arch_vectors.py`](../tools/cross_arch_vectors.py) | [`test_platform_profile.py`](../tests/unit/test_platform_profile.py)、[`test_cross_arch_vectors.py`](../tests/unit/test_cross_arch_vectors.py)（固定値 [`digests.json`](../tests/vectors/digests.json) と比較）。手順と比較条件は [共通試験ベクトル](cross-arch-vectors.md) |
| 5 | バイナリ・ABI・ドライバ・資源・性能の差を明示し、同じ性能やモデル出力を保証しない | #373（OS・CPU・dpkg・Python ABI の観測）、#374（core reserve v4・HIL capture・mission pack が申告値でなく観測値を使う）、#378（aarch64 の lab 用ハッシュ固定 lock） | [`platform_observation.py`](../runtime/src/azazel_nexus_runtime/platform_observation.py)、[`install_platform.py`](../runtime/src/azazel_nexus_runtime/install_platform.py)、[`core_reserve_probe.py`](../runtime/src/azazel_nexus_runtime/core_reserve_probe.py)、[`hil_capture.py`](../runtime/src/azazel_nexus_runtime/hil_capture.py)、[`requirements-aarch64-cp313.lock`](../packaging/offline/requirements-aarch64-cp313.lock) | [`test_platform_observation.py`](../tests/unit/test_platform_observation.py)、[`test_core_reserve_probe.py`](../tests/unit/test_core_reserve_probe.py)、[`test_hil_readiness_capture.py`](../tests/unit/test_hil_readiness_capture.py)、[`test_offline_arm_lab_target.py`](../tests/unit/test_offline_arm_lab_target.py)。既知の差は [ADR-0003 の Known differences](adr/0003-arm-software-verification-profile.md#known-differences-and-follow-up-changes) |
| 6 | ラボの鍵・データ・証拠・認可を本番と分け、本番の読取側が誤受理しない。ラボ設定で本番の認可や実機ゲートを迂回しない | #360・#374（lab profile は core reserve・HIL 記録・preflight・model admission を `LAB_PROFILE_NOT_FOR_PRODUCTION` で拒否）、#375（公開 fixture 鍵を本番の読取側で拒否）、#378（Arm lab の bundle は Edge slot を運べない）、#382（Arm の tuple は lab 専用で admission を通らない） | [`lab_keys.py`](../src/azazel_nexus/lab_keys.py)、[`lab_host.py`](../src/azazel_nexus/lab_host.py)、[`platform_profile.py`](../src/azazel_nexus/platform_profile.py)、[`compatibility.py`](../src/azazel_nexus/compatibility.py) | [`test_knowledge_lite_operator_entry.py`](../tests/unit/test_knowledge_lite_operator_entry.py)（fixture 鍵の pin・repin の拒否）、[`test_fabric_tested_tuple.py`](../tests/unit/test_fabric_tested_tuple.py)、[`test_offline_arm_lab_target.py`](../tests/unit/test_offline_arm_lab_target.py) |

本番の既定値（`LOCAL_MODEL_ADMISSION_ENABLED = False`、amd64 の配備基準など）は
どの PR でも緩めていない。新しい承認 boolean・環境変数による迂回・任意 unit 操作 API
は足していない。

## 2. 成果物の対応表

ゴールが求めた成果物と、その所在。

| 成果物 | 所在 |
| --- | --- |
| 実装と回帰試験 | §1 の表のコードと試験。PR ごとの変更は `git log 19aba95^..0ed7ab0` |
| CPU 共通部分と platform adapter の設計・ADR | [ADR-0003 Arm のソフトウェア検証プロファイル](adr/0003-arm-software-verification-profile.md)（proposed）、[ADR-0004 オフライン wheelhouse の Fabric](adr/0004-fabric-in-offline-wheelhouse.md)（accepted）、[ADR-0005 Arm の lab オフライン target](adr/0005-arm-lab-offline-target.md)（proposed）、[ADR-0006 tested tuple と Arm lab](adr/0006-tested-tuple-fabric-and-arm-lab.md)（proposed）、[共通試験ベクトル](cross-arch-vectors.md) |
| Arm VM の構築・導入・起動・復旧手順 | [VM 統合 runbook](hil-runbooks/vm-integration.md)、[実機受入手順 §4（Arm VM の V1〜V3）](hardware-acceptance.md#4-arm-vm-での受入)、[Debian Live 導入メモの Offline install bundle](debian-live-install.md#offline-install-bundle)、[オフライン導入 runbook](hil-runbooks/offline-install.md)、[activation リハーサル](hil-runbooks/activation-rehearsal.md) |
| Fabric・Knowledge の契約対応表と相互運用結果 | [契約表](contract-table.md)（22 件、未採用の契約、実 Knowledge の `/v1/context` との差）、[契約の所有](contract-ownership.md)、[Knowledge peer](knowledge-peer.md)、[Knowledge Lite 検証器の差分試験](knowledge-lite-differential.md) |
| 動作する UI・操作手順・画面確認記録 | [操作 UI](operator-ui.md)、[UI のブラウザ確認の記録とスクリーンショット](evidence/ui-browser-2026-10-29.md) |
| 検証記録（環境・commit・コマンド・成功・失敗・skip） | [コンテナ内 systemd の統合実行](evidence/vm-integration-container-2026-10-28.md)、[共通試験ベクトルの CPU 間突合せ](evidence/cross-arch-vectors-2026-10-29.md)、[オフライン導入 x86_64](evidence/offline-install-container-2026-10-28.json)、[オフライン導入 aarch64 lab](evidence/offline-install-aarch64-lab-container-2026-10-29.json)、各 PR 本文の試験節、§3 |
| 敵対的レビューの指摘と処置 | §4、各 PR のレビュー対応コメント、[統合実行の「見つかったこと」](evidence/vm-integration-container-2026-10-28.md#見つかったこと)、[差分試験](knowledge-lite-differential.md) |
| 実機でのみ確認できる項目の受入手順 | [実機受入手順](hardware-acceptance.md)（amd64 実機 A1〜A8、Arm VM V1〜V3）、[ハードウェアゲート](hardware-gates.md)、[HIL キャンペーン](hil-campaign.md) |
| オーナー判断 | [オーナー判断の一覧](owner-decisions.md)（69 件） |

## 3. 検証結果

**どれも Linux コンテナでの結果であり、実機・Arm VM での結果ではない**（Arm VM での結果は §5 の
最初の項を参照）。 arm64 は
colima（Apple Silicon 上の VM）のコンテナ、amd64 は colima の Rosetta による x86_64 の
変換で、amd64 ホストでの実行でもない（[ADR-0003](adr/0003-arm-software-verification-profile.md)、
[実機受入手順 §1](hardware-acceptance.md#1-規則vm-の結果を-hardware-evidence-に一般化しない)）。

main `331657a`（#380 のマージ後、#383 の直前。#383 は文書だけの変更）で確かめた全件試験
（tests/unit）：

| 環境 | 依存 | 結果 |
| --- | --- | --- |
| arm64、Python 3.11 | `.[dev]`、`./runtime` | 17532 passed |
| arm64、Python 3.12 | `.[dev]`、`./runtime` | 17532 passed（集計行 `17532 passed, 168 skipped, 2 deselected, 2 warnings`、bench `53 passed`。#383） |
| amd64（Rosetta）、Python 3.12 | `.[dev]`、`./runtime` | 17532 passed |
| arm64、Python 3.12 | `.[dev,fabric]`、`./runtime`（fabric-extra 相当） | 18003 passed（集計行 `18003 passed, 24 skipped, 2 deselected, 2 warnings`。#383） |
| root で実行 | `.[dev]`、`./runtime` | 17519 passed |

- 非 root の実行は uid 1001・`umask 022`、ci.yml と同じ 2 件の `--deselect`。
- 共通試験ベクトル：13 件すべてが aarch64 と amd64（Rosetta）で一致した（13/13）。
  ベクトルの環境には Fabric が入らないため、Fabric の射影（契約表の F2〜F6）は CPU 間で
  比べていない（[契約表 §6](contract-table.md#6-両-cpu-での同一性の確かめ方)）。
  commit `1173852` での Python 3.11〜3.13 の記録は
  [共通試験ベクトルの記録](evidence/cross-arch-vectors-2026-10-29.md) にある。
- 統合ループ（導入・起動・障害注入・再起動後の失効）：コンテナ内 systemd で aarch64 は
  pass 54 / fail 0 / skip 2、x86_64（Rosetta）は pass 58 / fail 0 / skip 2（commit
  `9cd7e9c`。[記録](evidence/vm-integration-container-2026-10-28.md)）。再起動は
  `docker restart` で、カーネルは再起動していない。Edge Core は実バイナリ、Knowledge は
  公開 fixture、モデルは使っていない。
- UI：コンテナ内の headless Chromium で 5 画面の通常・劣化・復旧・狭い画面・XSS の
  fixture を確認し、systemd のコンテナでソケット起動を確認した
  （[記録](evidence/ui-browser-2026-10-29.md)）。実操作・IME・タッチは未確認。

使ったものの区別：試験はモック・fixture と実プロセス（試験内で起動した daemon）、
統合実行はコンテナ内の実 systemd・実 daemon・本番 unit。実モデルの推論はしていない。

## 4. 敵対的レビューで見つかり直した主な問題

各 PR の独立レビューと統合実行で見つかったもののうち、影響の大きいもの。各行の
「回帰試験」は、修正を外すと失敗することを変異試験で確かめたもの（件数は PR 本文の記載）。

| 問題 | 見つけた経緯と影響 | 修正 | 回帰試験 | PR |
| --- | --- | --- | --- | --- |
| 停止した entryd が稼働中と表示される | 独立レビュー M1。entryd の snapshot が古くても、route ledger の記録を補の生存の証拠として数えたため、entryd が止まっても最大 48 時間「生存の証拠あり」と表示された | snapshot が読めるときは ledger の記録を証拠に数えない（`operator_snapshot_present`）。期限内でも数えない snapshot（未記録・別の記録・`record_uncertain`）も stale に倒す | [`test_status_view.py`](../tests/unit/test_status_view.py) の `test_a_recent_record_does_not_keep_a_stopped_writer_alive` ほか。修正を戻す変異で 6 件失敗 | #370 |
| dpkg が読めないと CPU の検査を迂回できる | レビュー F1。dpkg が無い・拒否・解析不能のとき、外国アーキテクチャの検査がすり抜け、`install_profile_fields` が 0 で終わっていた | `DPKG_UNOBSERVED` として拒否する（`select` 経由のすべての経路と `install.sh`、lab も同じ）。HIL capture は `dpkg_architecture` を記録し、検証側が観測した CPU と照合する。dpkg が読めないホストは取得前に止まる | [`test_platform_observation.py`](../tests/unit/test_platform_observation.py)（dpkg-query が無い・ゴミを返す・失敗する）、capture の dpkg 照合を外す変異の検出 | #373、#374 |
| `azaudit-submit` を通じて監査の書き手になりすませる | 独立レビュー M1。書き手の束縛が片方向で、`azaudit-submit` を持つ `azknowledge`・`azcommission` が、自分の型以外（`activation.unit_granted`・`watchdog.fenced` など）を書けた | 束縛を両方向にし、それぞれ自分の型（`knowledge.lite.import_*`／`knowledge.lite.revocation_*`）しか書けない。他は `principal_denied` | [`test_knowledge_lite_operator_entry.py`](../tests/unit/test_knowledge_lite_operator_entry.py) の `test_a_lite_writer_may_record_nothing_but_its_own_events` ほか。片方向に戻す変異で 2 件失敗 | #375 |
| 本番の読取側が公開 fixture 鍵を受理する | #366 の統合実行で「読取側に拒否する仕組みが無い」と記録し、#375 で修正前は本番の読取側が受理していたことを確認した（`TrustStore.pin`、daemon の status・lookup、store-local の anchor）。レビュー M3 で失効鍵の側も同じと分かった | `lab_keys.PUBLIC_FIXTURE_KEYS` を pin・repin・`CommissionedLite.anchors`・daemon の trust 読取・失効 policy で拒否する。例外はラボ印（`/etc/azazel-lab/LAB-HOST`）のあるホストだけで、フラグ・引数・環境変数の例外は無い | `test_pin_refuses_the_fixture_key_off_a_lab_host`、`test_repin_refuses_the_fixture_key_in_either_role`、`test_every_vendored_fixture_key_is_listed` | #375（#366） |
| 署名検証より前の展開爆弾 | レビュー major。gzip の中身を署名検証の前に展開しており、圧縮率の上限が無かった | 展開しながら 100:1 の率（Knowledge の `DEFAULT_MAX_RATIO`）に枠を足した量で `BUNDLE_DECOMPRESSION_BOMB` として打ち切る。宣言された合計にも同じ率を掛ける。`MAX_TOTAL_BYTES` を 1 GiB から最大の Lite profile に合わせて下げた | [`test_lite_bundle_inflation.py`](../tests/unit/test_lite_bundle_inflation.py)（tracemalloc のピーク、展開量の上限）。率の上限を外す変異で 2 件、宣言の検査を外す変異で 1 件失敗 | #379 |
| Fabric の射影が日次 segment を溢れ、説明が残らない | レビュー major。射影付きの記録が `SegmentFull` になると説明そのものが記録されなかった | 射影なしの記録で 1 回だけ再試行する（`SegmentFull` は書込み前に出るので二重に書かれない） | [`test_fabric_explanation_projection.py`](../tests/unit/test_fabric_explanation_projection.py)（射影なしなら入る大きさで説明が残り、`explanation_segment_full` が数えられない） | #380 |
| Fabric extra でだけ出る失敗を `importorskip` が隠していた | `test_commissioning.py` の途中のモジュール単位の `importorskip("azazel_fabric")` が、その前の Fabric 非依存の 11 件ごと skip していた（`test_inventory.py` も 12 件）。Fabric 入りでだけ退役ロール語の試験 2 件が失敗していた | Fabric 依存部分を別ファイルに分け、fabric-extra ジョブの skip 拒否一覧に入れた。2 語はロールの意味でないため理由付きで許可した | [`test_optional_skips_are_scoped.py`](../tests/unit/test_optional_skips_are_scoped.py)（試験定義の後のモジュール単位の `importorskip` を拒否） | #381 |

ほかに、#366 の統合実行で、容量切れで追記が途中で止まると route ledger と監査
チェーンの末尾に壊れた行が残り、以後 entryd と auditd が起動を拒み続ける欠陥を見つけ、
部分行を取り消すように直した（[`audit.py`](../src/azazel_nexus/audit.py)、
[`test_audit_chain.py`](../tests/unit/test_audit_chain.py)）。

これらは有限回のレビューで見つかったものである。ここに無い欠陥が無いことは示して
いない。

## 5. やっていないこと・制約

- **実機では未実行。Arm VM では V1〜V3 を 2026-10-29 に実行した。** このゴールの成果は、
  どれも実機（amd64・Arm）では実行していない。Arm VM（VMware Fusion、Apple silicon、
  Debian 13.7 arm64）では、main `7ef1702` で V1（pass 55 / fail 0 / skip 2、kernel の再起動を含む。
  うち 24 件は arm64 の pin が無いまま aarch64 で build した Edge Core の上での pass という逸脱付き）、
  V2（arm64 lab のオフライン導入を systemd 段まで）、V3（仮想化センサーの観測）を行った
  （[記録](evidence/arm-vm-acceptance-vm-arm64-2026-10-29.md)）。VM の結果であり、ハードウェア
  ゲートは閉じない。手順と合格条件は [実機受入手順](hardware-acceptance.md) の
  A1〜A8（amd64 実機）と V1〜V3（Arm VM）にある。それ以前の Arm VM の記録
  （commissioning・activation のリハーサル、unit の hardening）は
  [実機受入手順 §2](hardware-acceptance.md#2-これまでに確かめた範囲) の表のとおり。
- **Arm の仮想化センサー**：aarch64 では `cpu_hypervisor` が常に `clear` を読む。代わりの
  信号は実 Arm VM で値を確かめてから決める（V3、オーナー判断 H4）。VMware Fusion の Arm VM では
  `dmi_vendor`・`dmi_product` が observed だった（他の基盤は未観測）。
- **arm64 の Edge Core の pin が無い**：aarch64 の bundle は Edge slot を拒否する。Arm VM
  では Edge Core を含む経路を、aarch64 で build した実バイナリを使う逸脱付きでしか通せない
  （2026-10-29 の V1 はその条件で実行、H5）。
- **Knowledge 本体の `/v1/context` の adapter が無い**（調査の項目 P7・P8）：Nexus の peer
  プロトコルは実 Azazel-Knowledge の API と相互運用せず、Nexus のコードが実 API と要求を
  交わしたことは無い（[契約表 §5](contract-table.md#5-実-knowledge-の-v1context-との差)）。
  外部 peer が無くても Lite で説明と参照は動く。Knowledge 送信の監査と送信直前の再確認も
  未実装。
- **`operator_view` の配線（U7）**：[`operator_view.py`](../src/azazel_nexus/operator_view.py)
  は本番のコードから import されておらず、status の read model と UI に接続していない。
- **ローカル AI への退避は通常起動では働かない**：LOCAL の予測の供給が既定で空のため、
  通常起動では LOCAL が選ばれない（M5）。`LOCAL_MODEL_ADMISSION_ENABLED` は False の
  まま。実モデルの推論は行っていない。
- **オンライン AI の transport は未配線**：同意の照合は実装したが、remoted が同意ストアを
  読む権限（M1）と envelope の署名者（M4）が未決。
- **UI**：loopback の HTTP とログインコードの第 1 段階で、TLS と強い認証は未実装（M20）。
  実ノードでは `azui` が読めない節が多く「権限なし」と表示される（H9）。
- **未採用の Fabric 契約**：`SituationFrame`・`SanitizedRemoteFrame`・`AdvisoryResult`・
  `CtiContextRequest` などは使っていない（[契約表 §4](contract-table.md#4-未採用の契約)）。
- **ADR-0003・0005・0006 は proposed**：既定はコードに採用したが、承認されていない。

## 6. オーナー判断

すべて [オーナー判断の一覧](owner-decisions.md) にある（高 10・中 27・低 32、計 69）。
既定値はどれも権限・送信範囲・認可を広げない側に置いた仮の値で、承認ではない。
優先度の高い 10 件の要約：

| # | 事項 | 現在の既定値 |
| --- | --- | --- |
| H1 | ADR-0003（Arm はソフトウェア検証プロファイル）の採用 | proposed。amd64 が配備基準、arm64 は lab |
| H2 | ADR-0005（オフライン導入の Arm lab target）の採用 | proposed。lab 専用で Edge slot を運べない |
| H3 | ADR-0006 の採用と「本番の読み手は lab purpose を受理しない」を契約にするか | proposed。Arm の tuple はどの admission も拒否 |
| H4 | Arm での仮想化センサーの代わりの信号 | aarch64 では `cpu_hypervisor` が常に `clear`。実 Arm VM での確認待ち |
| H5 | arm64 の Edge Core の pin | 無い。Edge リポジトリの作業が要る |
| H6 | Edge Core と advisory 側 unit の再起動方針 | `Restart=no`。異常終了すると次の起動まで止まる |
| H7 | 公開 fixture 鍵とラボ印の例外 | 本番で拒否、ラボ印のあるホストだけ例外。Mission Pack の検証は印を見ない |
| H8 | Fabric の release 署名鍵を trust anchor にするか | 採用していない。commit pin と wheel hash で固定 |
| H9 | `azui` の読取範囲 | 新しい読取グループを作らない。実ノードでは多くの節が「権限なし」 |
| H10 | Knowledge Lite の時計の床の書込み頻度 | 要求中は 1 秒に最大 1 回 fsync。実機での測定待ち（A5） |

## 7. 次の実機・VM 試験

[実機受入手順](hardware-acceptance.md) の順に行う。Arm VM では V1（`tools/vm_integration.py`
をカーネルの再起動まで含めて実行）、V2（arm64 lab のオフライン導入を systemd 段まで）、
V3（仮想化センサーの値の記録）。amd64 実機では A1（配備基準の導入）から A8 まで。
VM・コンテナの結果をハードウェアゲートの証拠にはしない。
