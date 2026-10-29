# 実機受入手順

Status: **手順のみ。どの項目も実機では未実行（2026-10-29、main `331657a` 時点）。**
この文書は、VM やコンテナで確かめた範囲と、実機でしか確かめられない範囲を分け、
実機と Arm VM で行う受入の手順・合格条件・記録の形を 1 か所にまとめたもの。
個々の手順がすでに runbook にあるものは、ここで繰り返さずにリンクする。

関連：[ハードウェアゲート](hardware-gates.md) ·
[HIL キャンペーン](hil-campaign.md) ·
[HIL の記録](hil-evidence-records.md) ·
[ADR-0003](adr/0003-arm-software-verification-profile.md) ·
[契約表](contract-table.md) ·
[オーナー判断の一覧](owner-decisions.md)

## 1. 規則：VM の結果を hardware evidence に一般化しない

- **VM・コンテナ・CI の結果は、ハードウェアゲートの証拠にならない。** Arm VM の結果は
  ADR-0003 D5 の「VM ソフトウェア統合の証拠」であり、ハードウェアゲートとは別の区分で
  ある。Rosetta による x86_64 の実行も、x86_64 の実機の証拠ではない。
- **ある環境の合格を、別の環境の合格として書かない。** aarch64 のコンテナで通った
  ことは Arm VM で通ったことではなく、Arm VM で通ったことは amd64 の実機で通ったことでは
  ない。記録には、どの環境で何を実行したか（実機・VM・コンテナ、CPU、エミュレーション
  の有無）を必ず書く。
- **未実行は未実行と書く。** 推定値・fixture・模擬の測定で埋めない
  （[Core reserve の測定 §10](core-reserve-measurement.md#10-a-synthetic-record-that-is-not-a-measurement)）。
- **ラボの印と鍵を実機に持ち込まない。** `tools/vm_integration.py` は公開 fixture 鍵を
  pin するためにラボ印（`/etc/azazel-lab/LAB-HOST`）を書き、消さない。印のあるホストは
  HIL の preflight・capture・Core reserve の probe・model admission などで拒否される。
  実機の受入は印の無い新しい導入で行い、VM の手順を実機で流用しない。
- **実機で通しても、本番の既定値を緩めない。** `LOCAL_MODEL_ADMISSION_ENABLED` は
  [mio-admission §14](hil-runbooks/mio-admission.md#14-enablement-criteria-for-local_model_admission_enabled)
  の条件を満たしたうえで、レビューを経たコード変更でだけ有効にする。受入の途中で
  動かすために解除しない。

この規則は既存の文書と同じものである（[ハードウェアゲート](hardware-gates.md#what-the-target-hardware-means-here)、
[HIL の記録](hil-evidence-records.md#tools-and-trust)、
[ADR-0003](adr/0003-arm-software-verification-profile.md#what-this-adr-does-not-establish)）。

## 2. これまでに確かめた範囲

| 項目 | 確かめた環境 | 記録 | 実機で残るもの |
| --- | --- | --- | --- |
| 本番 `install.sh` での導入と、導入後に unit が masked であること | aarch64 のコンテナ、Rosetta 上の x86_64 のコンテナ（どちらも systemd が PID 1） | [vm-integration（コンテナ）](evidence/vm-integration-container-2026-10-28.md) | HG-01（A1） |
| オフライン bundle の導入 | x86_64 のコンテナ、aarch64 lab のコンテナ（どちらも `install.sh --without-service-manager`。systemd 段は未実行） | [x86_64](evidence/offline-install-container-2026-10-28.json)、[aarch64 lab](evidence/offline-install-aarch64-lab-container-2026-10-29.json) | systemd 段まで（A1、V2） |
| 統合ループの起動・障害注入・再起動後の失効（A7） | 上の 2 つのコンテナ（リハーサル専用の手動起動。activation ではない） | [vm-integration（コンテナ）](evidence/vm-integration-container-2026-10-28.md) | VM での実行（V1）、kernel の再起動 |
| commissioning と activation の仕組み | Debian 13 arm64 の VM（loop-file の LUKS、VM 専用の鍵） | [activation リハーサル](hil-runbooks/activation-rehearsal.md#01-run-of-2026-10-23-mechanics-only)、[commissioning リハーサル](hil-runbooks/commissioning-rehearsal.md) | 実 dm-crypt、恒久 MAC、TPM（A2） |
| unit の hardening の宣言と systemd の読取りの一致 | Debian 13 arm64 の VM（entryd と knowledge-lited） | [milestone1 の記録](evidence/milestone1-real-systemd-smoke-2026-10-18.md) | x86_64 での MDWE と SystemCallFilter（A8） |
| 読取専用 UI の表示・劣化・XSS・外部通信なし | aarch64 のコンテナの headless Chromium、x86_64（Rosetta）は通常状態 1 回、aarch64 の systemd コンテナでソケット起動 | [UI のブラウザ確認](evidence/ui-browser-2026-10-29.md) | 実操作・IME・タッチ（A6）、IP フィルタの実効（A7） |
| 判断・認可・監査の意味が CPU 間で同じこと | aarch64 のコンテナと amd64（Rosetta）のコンテナ | [共通試験ベクトル](evidence/cross-arch-vectors-2026-10-29.md) | 実機の両 CPU での実行（V1 のあとに任意） |

どれも VM かコンテナの結果であり、§1 のとおり実機の証拠ではない。

## 3. 実機（amd64）の受入

対象は [ハードウェアゲートの「target hardware」](hardware-gates.md#what-the-target-hardware-means-here)
（配備する資源クラスの rugged な x86_64 Linux PC、Debian 13）である。機材・前提・
順序は [HIL キャンペーン](hil-campaign.md) に従う。下の A1〜A8 は、キャンペーンの
ゲートに加えて、今回のゴールの範囲（#355〜#382）で実機に残った項目を足したもの。

### A1 配備基準の導入

- **手順**：[オフライン導入 runbook](hil-runbooks/offline-install.md) の §1〜§4
  （x86_64 の build host で bundle を作り、ネットワークの無い DUT に root で導入し、
  `install.sh` の systemd 段まで通す）。続けて [HG-01](hil-runbooks/hg-01.md) の手順に
  進む。
- **前提**：[HIL preflight](hil-preflight.md) が READY を返すこと。ラボ印が無いこと。
- **合格条件**：導入が systemd 段まで成功し、運用 unit がすべて masked、activation
  controller だけが enabled であること（HG-01）。`install.sh` が host を
  `deployment-baseline` の profile として観測していること（arm64 や lab として
  識別されていないこと）。
- **記録**：[オフライン導入 runbook §6](hil-runbooks/offline-install.md#6-record) と
  HG-01 の記録（`az-hil-capture` の出力を埋め込む）。

### A2 activation

- **手順**：[HG-04](hil-runbooks/hg-04.md)（実機での commissioning）のあと、
  [HIL キャンペーンの順序](hil-campaign.md#order-at-installation-and-on-every-boot) に
  従って activation を通す。仕組みは VM で確かめた
  [activation リハーサル](hil-runbooks/activation-rehearsal.md) と同じだが、実機では
  [§12 で VM では確かめられないとしたもの](hil-runbooks/activation-rehearsal.md#12-not-covered-on-a-vm)
  （実 dm-crypt、恒久 MAC を読める NIC、実機上の Edge Core）を使う。
- **合格条件**：手編集なしで commissioning が完了し（HG-04）、activation の pass が
  起動時に grant を与え、grant の無い起動では unit が skip されること。鍵は VM の
  リハーサル鍵ではなく、本番の運用者の鍵であること。
- **記録**：HG-04 の記録（`az-hil-capture` を埋め込む）と、activation ledger の最後の
  記録の要約（ID・digest は書かない）。

### A3 HIL のゲート

- **手順**：[HIL キャンペーン](hil-campaign.md) の順序で HG-01〜HG-07 を行う。各ゲートの
  手順は [ハードウェアゲート](hardware-gates.md) から辿る runbook
  （[HG-01](hil-runbooks/hg-01.md)・[HG-02](hil-runbooks/hg-02.md)・
  [HG-04](hil-runbooks/hg-04.md)・[HG-06](hil-runbooks/hg-06.md)・
  [HG-07](hil-runbooks/hg-07.md)、HG-03 は
  [service objectives の SO-10](service-objectives.md) に driver reload を足す、
  HG-05 は A4）。マージ済みで実機待ちの機能は
  [M.I.O. 参照](hil-runbooks/mio-reference.md)・[NOC 観測](hil-runbooks/noc-observation.md)・
  [Edge issuer](hil-runbooks/edge-issuer.md) の runbook にある。
- **合格条件**：各ゲートの文書が定める条件。ゲートの状態を変えてよいのは、
  [HIL の記録](hil-evidence-records.md) の検証を通った記録だけである。
- **記録**：[HIL の記録](hil-evidence-records.md#record-lifecycle) の形
  （`python -m tools.hil_evidence bundle|lint|sign|verify`）。実機の記録は Git の外の
  HIL archive に置き、リポジトリには要約だけを置く。

### A4 Core reserve の実測（HG-05）

- **手順**：[Core reserve の測定 §5](core-reserve-measurement.md#5-the-procedure)。
  `az-hil-readiness` で前提を確かめ、Edge Core の subsystem に負荷がかかった状態で
  `az-core-reserve-probe` を実行する。資源クラスごとに、別々の boot で 3 回以上測る。
- **合格条件**：[§6 の受理条件](core-reserve-measurement.md#6-what-makes-a-record-admissible)
  を満たす `core-reserve/4` の記録がそろうこと。probe がラボ印・baseline でない
  profile・仮想化の観測で拒否しないこと（拒否されたら、その場で止めて原因を記録する）。
- **記録**：§8 の置き場所。採るのは観測の最大値で、推定値で埋めない。

### A5 SD カードや eMMC での fsync の遅延と書込み量

Knowledge Lite の時計の床（`clock-floor.json`）は、要求がある間 1 秒に最大 1 回、
ファイルとディレクトリを fsync する（[Knowledge Lite consumer の Wall-clock floor](knowledge-lite-consumer.md#wall-clock-floor)）。
書込みの頻度を変えるかは [オーナー判断 H10](owner-decisions.md#2-優先度の高いもの) で、
この測定の結果を待っている。

- **手順**：配備で使う記憶媒体（SD カード・eMMC・SSD のうち実際に使うもの）の上で、
  activation 済みの `azazel-knowledge-lited` に、運用で見込む頻度の
  `knowledge.lookup`（説明系が incident ごとに呼ぶもの）が届く状態を作る。
  1. 開始時と終了時に、`knowledge-lited` の `/proc/<PID>/io` の `write_bytes` と、
     記憶媒体の `/sys/block/<dev>/stat` を読む。
  2. 一定時間（例：10 分）、fsync の所要時間を採る（例：`strace -T -e trace=fsync -p <PID>`。
     strace の attach 自体が遅延を足すので、その旨を記録する）。
  3. 24 時間あたりの書込み量に換算する。要求の頻度も記録する。
- **合格条件**：測定中に `knowledge.status` が `state_untrusted`・`unavailable` に
  ならないこと。それ以外の閾値（遅延の上限・1 日の書込み量の上限）は未定で、この測定の
  結果をもとにオーナーが決める（H10）。数値が出たことを「合格」と書かない。
- **記録**：記憶媒体の種類と型番（製造番号は書かない）、fsync の遅延の分布（中央値・
  最大）、1 日あたりの書込み量、要求の頻度、測定時間。CI と VM はこの測定の代わりに
  ならない。

### A6 ブラウザ（実操作・IME・タッチ）

コンテナの headless Chromium で確かめたのは表示と DOM の判定だけで、実操作・IME・
タッチ・画面読上げ・Firefox や Safari は未確認である
（[UI のブラウザ確認の「これが示さないもの」](evidence/ui-browser-2026-10-29.md#これが示さないもの)）。

- **手順**：ノードで [UI を有効にし](operator-ui.md#enabling-it-on-a-node)
  （`azazel-ui.socket` を enable し、`azazel-nexus ui-login` でコードを出す）、
  ノード上のブラウザ（キオスクを使う場合はそのブラウザ）で次を行う。
  1. キーボードだけで、ログインから 5 画面（概況・インシデント・NOC・Knowledge・
     セットアップと復旧）を巡回する。
  2. 日本語 IME を有効にしたままログインコードを入力し、何が起きるかを記録する
     （受理されるか、分かる形で拒否されるか）。
  3. タッチ画面がある場合は、タップ・スクロール・拡大と、狭い幅での表示を確かめる。
  4. 日本語のフォントが表示されること（キオスクのフォントは
     [オーナー判断 L7](owner-decisions.md#4-優先度が低いもの)）。
  5. daemon が実際に書いた snapshot で、劣化（daemon を止める・snapshot を古くする）と
     復旧を表示させる。
- **合格条件**：どの画面も操作でき、劣化時に「正常」や緑の表示にならないこと。
  「実行した」と「Edge would」を取り違えた表示が無いこと。ページ起点の通信が
  loopback だけであること。
- **記録**：[UI のブラウザ確認](evidence/ui-browser-2026-10-29.md) と同じ節構成
  （条件・結果・見つかったこと・これが示さないもの）。画面の画像に interface 名・
  アドレス・ID が写らないことを確かめてから保存する。

### A7 socket unit の IP フィルタ

`azazel-ui.socket` は IPv4 loopback の 8443 だけで待ち受け、`IPAddressDeny=any` と
`IPAddressAllow=localhost` を持つ。コンテナでは unit のプロパティと listener を
確かめただけで、loopback 以外から来た接続をフィルタが実際に落とすことは記録されて
いない。

- **手順**（ノードに LAN 側のアドレスがある状態で）：
  1. 別の機器から、ノードの LAN 側アドレスの 8443 に接続を試みる（待ち受けが無いので
     接続できないことを確かめる）。
  2. ノード上で、送信元を LAN 側のアドレスにして loopback へ接続する
     （例：`curl --interface <LAN 側のアドレス> -m 5 http://127.0.0.1:8443/`）。
     宛先は loopback だが送信元が `localhost` の範囲外なので、フィルタが落とす
     （応答が来ない）ことを期待する。
  3. 対照として、送信元を指定せずに `curl -m 5 http://127.0.0.1:8443/` を実行し、
     応答が来ることを確かめる。
  4. `systemctl show azazel-ui.socket -p IPAddressDeny -p IPAddressAllow` の値を、導入した
     unit ファイルと比べる。
- **合格条件**：1 と 2 で接続が成立せず、3 で成立すること。4 で値が unit ファイルと
  一致すること。2 で応答が来た場合は所見として記録し、UI を有効にしたまま運用しない。
- **記録**：各手順の成否と systemd の版。アドレスは書かない。

### A8 x86_64 での MemoryDenyWriteExecute と SystemCallFilter

Rosetta 上の x86_64 は、`MemoryDenyWriteExecute=yes` のプロセスを SIGTRAP で落とすため
drop-in で外しており、seccomp も効かない。そのため x86_64 での両者は一度も確かめて
いない（[VM 統合 runbook §2](hil-runbooks/vm-integration.md#2-what-it-does-not-do-and-the-substitutions-it-records)、
[mio-admission §17](hil-runbooks/mio-admission.md#17-vm-rehearsal-never-evidence)）。

- **手順**：A2 で activation した実機で、起動した各 unit について
  [M.I.O. 参照 runbook §3](hil-runbooks/mio-reference.md#3-sandbox-of-the-running-units) と
  同じ読取りを行う（`/proc/<PID>/status` の `Seccomp`・`NoNewPrivs`・`CapEff`、
  `systemctl show` の `MemoryDenyWriteExecute`・`SystemCallFilter`・
  `SystemCallArchitectures`、`systemd-analyze security`）。あわせて、journal に
  SIGSYS・SIGTRAP による終了が無いこと、カーネルの監査ログに seccomp の拒否が無い
  ことを確かめる。Edge Core と通常の負荷（A4 の負荷、説明系の要求）を一定時間かける。
- **合格条件**：すべての unit が `Seccomp: 2` で動き続け、`MemoryDenyWriteExecute` が
  unit ファイルどおりに有効で、seccomp・W^X による異常終了が 0 件であること。
  ネイティブ拡張（`_bootstrap_deadline`）を使う unit も含む。llama runtime は model
  admission が閉じている間は動かないので、[mio-admission §5.2](hil-runbooks/mio-admission.md#52-embedding-runtime-measurement-root-on-the-dut)
  の計測で扱う。
- **記録**：unit ごとの値と `systemd-analyze security` の exposure、systemd の版、
  負荷をかけた時間。

## 4. Arm VM での受入

Arm VM の結果は ADR-0003 D5 の「VM ソフトウェア統合の証拠」であり、§1 のとおり
ハードウェアゲートを閉じない。VM は使い捨てとし、始める前に snapshot（S0）を取る。

### V1 `tools/vm_integration.py` の実行

- **手順**：[VM 統合 runbook](hil-runbooks/vm-integration.md) の §3.3（VM の準備）と
  §5。`--target ssh:<NODE>` で実行し、Edge package があれば `--edge-package` を渡す。
  arm64 の Edge Core の pin が無い（[オーナー判断 H5](owner-decisions.md#2-優先度の高いもの)）
  ため、Edge Core を含む検査は記録上の逸脱として残る。
- **合格条件**：[§6 の検査](hil-runbooks/vm-integration.md#6-the-checks-and-what-they-expect)
  がすべて pass（skip は理由付き）。コンテナでは行えなかった kernel の再起動
  （`systemctl reboot`、新しい boot）を経た `after-restart` の検査が pass であること。
- **記録**：`azazel-nexus/vm-integration-run/v1` の JSON と Markdown の要約を
  `docs/evidence/vm-integration-vm-arm64-<日付>/` と `.md` に置く
  （[runbook §7](hil-runbooks/vm-integration.md#7-the-record)）。終わったら S0 に戻す。

### V2 arm64 lab のオフライン導入

- **手順**：[Debian Live の導入メモの Offline install bundle](debian-live-install.md#offline-install-bundle)
  の Arm lab target（`--target debian-13-aarch64-cp313`）で wheelhouse と bundle を
  aarch64 の build host で作り、ネットワークの無い Arm VM に root で
  `offline_bundle.py install --run-installer` で導入する。コンテナでは
  `--without-service-manager` だったので、VM では systemd 段まで通す。
- **合格条件**：導入が systemd 段まで成功し、unit が masked であること。導入した
  runtime が host を `debian-13-arm64-cp313-lab` と観測し、本番の用途（core reserve・
  ハードウェアゲートの記録・preflight・model admission・product admission）を
  `LAB_PROFILE_NOT_FOR_PRODUCTION` で拒否すること。Edge slot を含む bundle が拒否される
  こと（[ADR-0005](adr/0005-arm-lab-offline-target.md)）。
- **記録**：[aarch64 lab のコンテナの記録](evidence/offline-install-aarch64-lab-container-2026-10-29.json)
  と同じ形（`azazel-nexus/prototype-offline-install-evidence/v1`）で、`scope` に VM で
  あることを書く。

### V3 仮想化センサー（ADR-0003 R1 の値の確定）

`cpu_hypervisor` は x86 専用の cpuinfo の印に依存し、aarch64 では常に `clear` を読む。
Arm での代わりの信号は、実 Arm VM で値を確かめてから決めることになっている
（[ADR-0003 の既知の差 R1](adr/0003-arm-software-verification-profile.md#known-differences-and-follow-up-changes)、
[オーナー判断 H4](owner-decisions.md#2-優先度の高いもの)）。

- **手順**：Arm VM で、導入した venv の Python から
  `azazel_nexus_runtime.virtualization_observation.observe_virtualization()` を呼び、
  7 つのセンサー（`hypervisor_type`・`cpu_hypervisor`・`systemd_container`・
  `dockerenv`・`dmi_vendor`・`dmi_product`・`init_cgroup`）の値を記録する。比較として
  `systemd-detect-virt` の出力も記録する。可能なら、異なる仮想化基盤（例：VMware と
  Apple Virtualization）で同じことを行う。
- **合格条件**：判定ではなく観測の記録が目的である。どのセンサーが Arm VM で仮想化を
  `observed` と読むか（読まないか）が、基盤ごとに分かること。
- **記録**：基盤の種類、各センサーの値（`observed`・`clear`・`absent`・`unknown`）、
  `systemd-detect-virt` の値。DMI の製品名に個体を識別する文字列が含まれる場合は伏せる。
  この結果をもとに、R1 の対処（arm64 での非適用の扱いと、capture へのゲート）を別の
  PR で決める。

## 5. 記録の形式

[docs/evidence](evidence/) の既存の形に合わせる。

- **ファイル名**：`<対象>-<環境>-<YYYY-MM-DD>.md` と、同じ名前のディレクトリに原本
  （JSON・画像・ハーネス）。環境には実機・VM・コンテナ、CPU、エミュレーションの有無が
  分かる語を入れる（例：`vm-integration-container-2026-10-28`、
  `offline-install-aarch64-lab-container-2026-10-29`）。
- **Markdown の節**：冒頭の太字で何の証拠で何の証拠でないかを書き、続けて
  「条件」「結果」「見つかったこと」（F1… と扱い）「これが示さないもの」「手順（再現）」。
- **JSON**：道具が出す schema のまま（`azazel-nexus/vm-integration-run/v1`、
  `azazel-nexus/prototype-offline-install-evidence/v1` など）。commit は短い sha で書く。
- **ハードウェアゲートの記録**：[HIL の記録](hil-evidence-records.md) の schema
  （`azazel-nexus/hil-gate/v1`、`azazel-nexus/hil-capture/hg-01/2` など）と署名で、
  Git の外の HIL archive に置く。
- **書かないもの**：秘密・鍵、digest、ID、MAC、アドレス、boot id、ホスト名、interface 名、
  製造番号（[inventory confidentiality](inventory-confidentiality.md)）。

## 6. 止める条件

- 本番の既定値（allowlist 空、`NO_OPT_IN`、`LOCAL_MODEL_ADMISSION_ENABLED=False`、
  配備基準 amd64、未署名 bundle の扱い）を変えないと先へ進めない場合は、そこで止めて
  記録し、オーナー判断に回す。
- ラボ印・fixture 鍵・VM のリハーサル鍵が実機に見つかった場合は、受入を止める。
- そのほかは [HIL キャンペーンの停止条件](hil-campaign.md#stop-conditions-and-review) に
  従う。
