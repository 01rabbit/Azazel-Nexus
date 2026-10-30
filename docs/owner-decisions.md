# オーナー判断の一覧

Status: **未決の一覧（2026-10-29、main `331657a` 時点。H4・H5 の現状は 2026-10-29 の
Arm VM での受入（V1〜V3、main `7ef1702`）の結果を反映）。** #355〜#382 の PR 本文に
ある「オーナー判断」の節を集め、重複をまとめたもの。ここに書く「現在の既定値」は、
実装した PR が安全側に置いた値であり、オーナーが承認した値ではない。どの行も、この
文書の記載だけで決定済みにはならない。決めたときは、関係する PR・ADR・文書を直し、
この表から行を消すか「決定済み」に移す。

関連：[契約表](contract-table.md) ·
[実機受入手順](hardware-acceptance.md) ·
[契約の所有](contract-ownership.md) ·
[ハードウェアゲート](hardware-gates.md)

## 1. 読み方

- **現在の既定値**：いま main のコードと文書がとっている扱い。どれも、権限・送信範囲・
  認可を広げない側に置いてある。
- **選択肢**：PR 本文に挙がった案。案が 1 つしかないものは「維持／変更」とした。
- **影響**：決めたときに変わるもの（コード・schema・運用・他リポジトリ）。
- **優先度**
  - **高**：本番採用・配備・【守る設計】（ゴールの設計原則 1〜6）に直接かかわり、
    次の段階（実機受入、transport の配線、ADR の採用）の前提になるもの。
  - **中**：次にその機能を配線・拡張するときに決める必要があるもの。いまの既定で
    運用はできるが、機能が欠ける・運用者の手間が残る。
  - **低**：名前・表示・文言・内部の整理。いまの既定で安全側に倒れており、急がない。
- PR 番号は [01rabbit/Azazel-Nexus](https://github.com/01rabbit/Azazel-Nexus) の
  pull request。行の中では `#番号` と書く。

## 2. 優先度の高いもの

| # | 事項 | 現在の既定値 | 選択肢 | 影響 | PR・ADR |
| --- | --- | --- | --- | --- | --- |
| H1 | ADR-0003（Arm はソフトウェア検証プロファイル）を accepted にするか | proposed。既定（amd64 が配備基準、arm64 は `lab-software-verification`）はコードに採用済み | 採用／修正して採用／差し戻し | 採用しないと、#360〜#382 の Arm 関係の既定がすべて仮のまま残る。配備基準（ADR-0002）は変わらない | #360、[ADR-0003](adr/0003-arm-software-verification-profile.md) |
| H2 | ADR-0005（オフライン導入の Arm lab target）を accepted にするか | proposed。target `debian-13-aarch64-cp313` は lab 専用、Edge slot を運べない | 採用／修正して採用／差し戻し | Arm VM への導入手順の位置づけが決まる。配備用 target は変わらない | #378、[ADR-0005](adr/0005-arm-lab-offline-target.md) |
| H3 | ADR-0006（tested tuple の CPU を platform profile から読み、Arm の tuple は lab 専用）を accepted にし、「本番の読み手は `lab` purpose を受理しない」を契約として定めるか | proposed。`aarch64` の tuple は purpose `lab-software-verification` のときだけ読み、どの admission も拒否する | 採用（Fabric との合意事項にする）／Nexus 内の既定にとどめる | 採用すると Fabric の `TestedCompatibilityTuple` との対応が契約になる。【守る設計】6 の「ラボ認可を本番が誤受理しない」の根拠になる | #382、[ADR-0006](adr/0006-tested-tuple-fabric-and-arm-lab.md) |
| H4 | Arm での仮想化センサー（ADR-0003 R1）の代わりの観測値 | **2026-10-30 委任された技術判断で決定。** `cpu_hypervisor` は x86 の `flags` 行が無い cpuinfo（aarch64）では `unobservable`（観測不能）と読み、否定所見の `clear` と区別する。否定側の判定（`virtualization_not_observed`）は観測した CPU で読み、arm64 では `unobservable` だけを受け、`clear`（以前の観測器の誤読）は拒否する。`dmi_vendor`・`dmi_product`・`init_cgroup` はどの CPU でも `clear`（読めて信号なし）が必須で、DMI の無い Arm 基盤のように観測できなければ「仮想化でないと言えない」側に倒す。VMware Fusion の Arm VM で DMI が observed だったこと（[V3 の記録](evidence/arm-vm-acceptance-vm-arm64-2026-10-29.md#v3-仮想化センサー)）は他の基盤へ一般化しない。非対称は capture 側に揃えた：`az-hil-capture` も core reserve probe と同じく、配備基準でない profile（arm64 lab）を取得前に `LAB_PROFILE_NOT_FOR_PRODUCTION` で拒否し、検証側（`hil_records`）は以前の版の capture のために拒否を続ける。記録の schema の版は上げない（新しい値は旧い読み手では拒否側に倒れ、新しい読み手は arm64 の `clear` を拒否する） | 決定済み。DMI の無い Arm 基盤や VMware 以外の基盤で使える追加の信号（device tree・ACPI など）は、その基盤での実測を待つ（実測待ち） | arm64 の記録の否定所見は観測できたセンサーだけに基づく。arm64 は lab profile なので、いずれにしても実機の証拠・本番の admission には使えない | #360、#374、[ADR-0003](adr/0003-arm-software-verification-profile.md#known-differences-and-follow-up-changes) |
| H5 | arm64 の Edge Core の pin（ADR-0003 R4） | 無い。aarch64 の bundle は Edge slot を拒否し、x86_64 の Edge を運べない | Edge 側で CPU ごとの pin と CPU 不一致の所見を作る／Arm は Edge なしの lab にとどめる | Edge リポジトリの作業が要る。決まるまで、Arm VM では Edge Core を含む経路を、aarch64 で build した実バイナリを使う逸脱付きでしか通せない（2026-10-29 の V1 はその条件で実行。[記録](evidence/vm-integration-vm-arm64-2026-10-29.md)） | #378、[ADR-0003](adr/0003-arm-software-verification-profile.md)、[ADR-0005](adr/0005-arm-lab-offline-target.md) |
| H6 | Edge Core と advisory 側 unit の再起動方針（A7 の F2） | 異常終了すると次の起動まで止まる（`Restart=no`。activation の「付与は起動時の pass だけ」に合わせている） | `Restart=on-failure` にして同じ boot の marker で再起動できるようにする／現状維持 | 【守る設計】3（AI・Knowledge・UI の停止で Edge を止めない）とは別に、Edge 自身のクラッシュからの回復の扱いが決まる。activation の設計と整合させる必要がある | #366 |
| H7 | 公開 fixture 鍵とラボ印の扱い | **2026-10-30 委任された技術判断で決定（Mission Pack の検証にも印の拒否を足す）。** Knowledge Lite の trust の登録と本番の読取りで、`lab_keys.PUBLIC_FIXTURE_KEYS` の鍵を拒否し、ラボ印（`lab_host` の汚染印）がある場合だけリハーサル用の例外になる点は維持。印のあるホストは activation health・bootstrap overlay・commissioning 承認・model admission に加え、Mission Pack の verify・stage・activate・rollback（と CLI）でも、媒体・保存世代・設定を読む前に `LAB_HOST_MARKER` で拒否する。ラボ側の印の作成と、すべての Mission Pack の公開（state root に依らない）は、ホスト共通の lock（`/run/azazel-lab-host.lock`）を取ってから行い（印の作成は最大 60 秒待って取れなければ印を書かずに拒否、Pack は待たずに拒否、順序は常にホスト共通→state root）、Pack は lock の中で公開の直前にも印を確かめるので、検証後に印が作られて公開まで進む競合も無い。このため印のあるホストでは Pack の `knowledge_lite` が fixture 署名の bundle を指せない | 決定済み。VM のリハーサル（`tools/vm_integration.py`）は Mission Pack を使わないので手順は変わらない。単体試験は、Pack の経路を生成した鍵で署名した Lite で試し、印のある場合の拒否を別に試す | 【守る設計】6 の分離が強まる。印のあるホストでは Mission Pack を一切選べない（印は承認ではなく、外しても何も与えない） | #366、#375（`src/azazel_nexus/lab_keys.py`、`src/azazel_nexus/mission_pack.py`） |
| H8 | Fabric の release 署名鍵を Nexus の trust anchor にするか | 採用していない。オフライン wheelhouse の Fabric は commit pin と wheel hash だけで固定 | 採用（鍵を Nexus に固定し、builder で digest の署名と wheel 内ファイルの照合を行う）／現状維持 | 供給網の認証が hash の一致から発行元の署名に強まる。pin を動かすたびに鍵の運用が要る | #357、[ADR-0004](adr/0004-fabric-in-offline-wheelhouse.md) |
| H9 | UI（`azui`）の読取範囲 | **[ADR-0007](adr/0007-ui-read-leaves.md)（proposed）で既定を採用**：各 snapshot の書き手が、同じ内容の写しを自分の UI 用 leaf（`run/ui-read/<leaf>`、`2750 <書き手>:azui`）に書く。`azui` はどの group にも入らず、daemon の socket にも届かない。写しを置かないもの（Edge probe の結果、Lite store・route ledger・model store・同意の記録など直接読む情報源）は従来どおり「権限なし」 | 維持／読取専用グループ（`azstatus-read` 案）／`azui` を `azazel-operator` に入れる（オーナー方針で不採用） | 書き手が 1 ファイル余分に書く。`install.sh` を再実行しないノードでは、UI は写しを「無い」と表示する | #363、#365、#372、ADR-0007 |
| H10 | Knowledge Lite の時計の床の書込み頻度 | 要求が来ている間は 1 秒に最大 1 回、ファイルとディレクトリを fsync する | 案 A：dated 行を返したときか期限の境界を越えたときだけ書く／案 B：同じ boot の中は CLOCK_BOOTTIME で検出し、boot をまたぐ床だけ書く／案 C：1 セクタを O_DSYNC で上書き | SD カード・eMMC の摩耗と遅延。実機での測定（[実機受入手順](hardware-acceptance.md#a5-sd-カードや-emmc-での-fsync-の遅延と書込み量)）の結果を見て決める | #368、#359 |

## 3. 優先度が中のもの

### 3.1 M.I.O. とオンライン AI 送信

| # | 事項 | 現在の既定値 | 選択肢 | 影響 | PR・ADR |
| --- | --- | --- | --- | --- | --- |
| M1 | remoted が送信同意ストアを読む権限 | ストアは entryd の 0700 ディレクトリにあり、azremote は読めない。読めなければ `opt_in_unavailable` で拒否（fail-closed） | (a) 専用ディレクトリを group azremote の読取専用にする／(b) entryd に読取専用の照会動詞を設ける | transport を配線するときに必須。どちらも権限か protocol を増やす | #361 |
| M2 | 撤回の drain で entryd を待たせる上限 | entryd の accept loop は単一スレッド。送信中に撤回すると最大 65 秒ほかの要求を待たせる（transport が無い現在は起きない） | 待つ上限と「drained: false」の運用を決める | transport の配線時に必要 | #361 |
| M3 | 再起動をまたいだ同意ストアの巻き戻し | プロセス内の巻き戻し・削除は検出。再起動をまたぐ root の差替え・削除は検出できない（local trust） | 現状維持／ストアの識別子（作成時の乱数 epoch など）を envelope に束縛する | 世代番号の振り直しによる古い envelope との一致を塞げる | #361 |
| M4 | envelope の署名者が `opt_in_generation` を入れる | この build に sanitizer の署名者は無い | 署名者を作るときに、許可済みのときだけストアの `reading().generation` を入れる | 送信直前の撤回世代照合が端から端まで成立する | #361 |
| M5 | LOCAL 経路の予測の供給 | `predictions_reader` は既定で空。予測の無い候補は `UNPREDICTABLE` で除外されるため、通常起動では LOCAL は選ばれない | 実測の観測から `route_evidence.predict` を供給する配線を作る（実測なしに予測を作らない） | 決まるまで、認可済みローカル AI へ退避する経路（【守る設計】2）は通常起動で働かない | #356 |
| M6 | embedding の配信を「AI advice (local model)」と表示するか | モデルの関与があるものとして表示 | 現状維持／`content_kind` に語彙を足して区別する | 区別すると recent.json・status・UI の検証規則に波及する | #356 |
| M7 | redaction record を外に出すか（Fabric `SanitizedRemoteFrame` の採用） | record はノードに残し、id（digest）だけを送る。`SanitizedRemoteFrame` は不採用 | (a) record を送る／(b) `redactions=()` で送る／(c) Fabric に参照だけの欄を加法的に足してもらう | 採用の可否が決まる。(a) は伏せた欄の存在を相手に知らせ、(b) は「伏せていない」と述べることになる | #380、[契約の所有 §3.3](contract-ownership.md#33-mio-cognition-path) |

### 3.2 Knowledge

| # | 事項 | 現在の既定値 | 選択肢 | 影響 | PR・ADR |
| --- | --- | --- | --- | --- | --- |
| M8 | 時計の未来への飛躍と snapshot 復元への上限 | 上限なし。未来へ飛ぶと床も上がる。保存領域ごと巻き戻すと床も戻る | 署名済み材料の時刻など、保存領域の外の基準で上限を設ける／現状維持 | 管理者や復元に対する防御ではない点（local trust）は変わらない | #359、#368 |
| M9 | 時計を信用できない間に静的参照も止めるか | 静的参照（ATT&CK）も含めて止める（fail-closed） | 現状維持／時刻に依存しない静的参照だけは出し続ける | 逆行中の説明で引用できる範囲が変わる。Edge の判断には影響しない | #359 |
| M10 | Lite の import が daemon 稼働を前提にすること | 2026-10-30 に委任された技術判断で対応（[ADR-0008](adr/0008-lite-trust-operations.md)）：監査付きの daemon import を基本とし、通常経路に監査の書き手 `azazel-auditd-loop.service` を足した。監査が書けなければ変更前に拒否。監査を省く入口は作らない | 現状維持（daemon import のみ） | activation policy に新 unit を含めないと import は従来どおり拒否される | #375、ADR-0008 |
| M11 | trust root の変更の監査先 | 2026-10-30 に委任された技術判断で対応（ADR-0008 D6）：enroll・repin・失効受理を auditd に記録し、repin は commission ledger にも残す。両者は世代番号で照合する（台帳は統合しない） | 現状維持／台帳を統合する | 監査の照合手順（[trust repin](trust-repin.md)） | #375、ADR-0008 |
| M12 | 初回 pin の出荷入口と、Knowledge の `anchors.revoked` と Nexus の失効形式の対応（K7） | 出荷入口は 2026-10-30 に対応（ADR-0008 D4：`az-nexus-commission trust-enroll`、commissioning の束縛・threshold・fixture 鍵を検査）。K7 は未対応（producer/consumer の契約合意が要る）。`azazel-nexus pack` とライブラリ `LiteImport` は store-local の anchor を読む（[§11 step 8](knowledge-lite-consumer.md#11-first-enrollment-from-a-fresh-install-to-available) で写す） | K7：Knowledge 側と形式を合わせる | Knowledge 側の失効の受け渡し | #375、ADR-0008 |
| M13 | 署名の対象を Knowledge の正準形に限るか | Nexus は整形した manifest への署名も受理する（Knowledge の検証器は拒否する） | raw の manifest が正準形と一致することを求める／現状維持 | 求めると、Nexus の試験と共通試験ベクトル（`knowledge_lite.refusals` など）を作り直す必要がある | #379、[差分試験](knowledge-lite-differential.md) |
| M14 | manifest の順序・展開率・禁止欄の和集合・ローカル層の表名を Nexus でも拒否するか | Nexus の検証器はこれらを拒否しない（差分試験で差として記録） | Nexus でも拒否する／現状維持 | Knowledge の検証器との差が縮む | #379 |
| M15 | Knowledge への修正提案（K8 threshold 0 を拒否、K9 `bundle_version` を整数に限る、K10 1 成分の長さ上限、K11 禁止欄に Nexus の 4 欄を足す） | 提案のみ。Knowledge には出していない | Knowledge に提案する／見送る | Knowledge リポジトリの変更と統合順序 | #379 |
| M16 | `knowledge-status` の版上げ | `knowledge-status/v1`。署名鍵 ID・digest 短縮形・期限などは snapshot に無い | 書き手と読取器に同時に足して `knowledge-status/v2` にする | UI の Knowledge 画面に出せる項目が増える | #363 |

### 3.3 Fabric との契約

| # | 事項 | 現在の既定値 | 選択肢 | 影響 | PR・ADR |
| --- | --- | --- | --- | --- | --- |
| M17 | EvidenceRef を説明に載せるか | **決定（方針【5】E、S-18）**：pending と説明 ledger が遷移の first／latest の evidence digest と受信時刻を運ぶ（原文は運ばない。M.I.O. の frame は読まない）。`ClaimSet` の Edge の claim が Fabric の `EvidenceRef` として引用し、参照切れは `evidence_not_stored`・`evidence_retention_elapsed` と書く。`evidence_refs_not_carried` は運ぶ前の記録と pending だけ。説明器は private な証拠 store を読めないので、保持の窓の内側でも存在は保証しない | pending の形を変えて evidence digest を運ぶ（採用）／現状維持 | 説明 ledger の `ClaimSet` が Edge の証拠を引用できるようになる | #380、[契約の所有 §3.1](contract-ownership.md#31-decision-evidence-and-audit-path) |
| M18 | `os_abi` の語彙 | Nexus は `debian-13/linux-6.12`、Fabric の golden は `linux-gnu-x86_64`。対応表は無く、厳密に比較して違いを報告するだけ | Fabric と共通の語彙を決める | Fabric との合意事項 | #382、[ADR-0006](adr/0006-tested-tuple-fabric-and-arm-lab.md) |
| M19 | Fabric の `CompatibilityManifest` を Nexus が受け取る経路 | 未設計。`check_tested_tuple` に本番の呼出し元は無い | 設計する／Fabric の R1 を待つ | tested tuple の適合が本番の admission に入る | #382 |

### 3.4 状態表示と UI

| # | 事項 | 現在の既定値 | 選択肢 | 影響 | PR・ADR |
| --- | --- | --- | --- | --- | --- |
| M20 | UI の TLS と強い認証（WebAuthn／クライアント証明書）の時期 | 第 1 段階は loopback の HTTP とログインコード。`Secure` Cookie は付けられない | 仕様（HTTPS 8443 と強い認証）に寄せる時期を決める | loopback 以外から使う前に必須 | #365、[操作 UI](operator-ui.md) |
| M21 | UI を統治対象（activation の管理下）にするか | 非統治。activation 前のセットアップ・復旧画面を出せるようにするため | 現状維持／統治する | 統治すると activation 前に表示できない | #365 |
| M22 | 端末だけに出す項目の範囲 | interface の記述（bus_path・physical_label）、interface 名、Edge package root のパス、Edge finding の理由文、発行元名・revocation sequence・floor version、`--ledger` 由来の詳細を JSON と UI から外す（inventory-confidentiality の既定）。ADR-0007 の UI 用の写しにも入らない（写す snapshot はどれもこれらを持たず、試験で確認） | 一部を UI に出す／現状維持 | 機微情報の露出範囲。外へ出す範囲を広げる判断は委任外 | #358、#365、ADR-0007 |
| M23 | status-view の schema の版の規則 | **ADR-0007 D6 で既定を採用**：`azazel-nexus/status-view/1` は追加のみ互換（節・欄の追加は互換。読み手は allowlist で写し、無い節は `pending`、未知の語は「未定義の語」）。欄の削除・意味や型の変更・語の意味の変更は `/2` とし、UI は拒否する。独自の schema を持つ節（`operator-view/1`）も同じ規則 | 節を足すたびに版を上げる／追加のみ互換とする | UI と外部の読み手の互換性 | #358、ADR-0007 |
| M24 | observer の timer を有効化する経路（unit 状態・NOC） | installer も preset も有効化しない（SPEC 2.3 のまま）。**ADR-0007 D8**：`azazel-nexus setup` の手順 `operator-observers` が、有効化のコマンド（`sudo systemctl enable --now azazel-noc-observe.timer azazel-units-observe.timer`）を示し、UI は未有効化を「観測なし（未有効化）」と表示して次の操作に同じコマンドを出す | UI 導入時に preset で enable する／運用者の手順とする（既定） | 有効化されないと、UI の該当節は観測なしのまま | #363、#364、ADR-0007 |

### 3.5 プラットフォームと HIL の記録

| # | 事項 | 現在の既定値 | 選択肢 | 影響 | PR・ADR |
| --- | --- | --- | --- | --- | --- |
| M25 | arm64 での `install.sh` の扱い | 拒否せず通し、lab と識別するだけ（拒否するには新しい承認フラグが要り、規則で禁じられている） | 現状維持／別の仕組みで拒否する | 既存の Arm VM リハーサルが `install.sh` を使っている | #373、[ADR-0003](adr/0003-arm-software-verification-profile.md) |
| M26 | capture の範囲を HG-02／06／07 と behaviour・drill の記録に広げるか | これらには capture の道具が無く、申告値のまま。runbook には「運用者の attestation が唯一の防御」と明記 | 道具を作って platform の観測を付ける／現状維持 | 実機記録の platform が申告から観測へ変わる | #374 |
| M27 | Edge の独立した証拠ストア（A7 の F4） | intake 停止中の Edge の判断は journal にだけ残る | Edge 側に証拠ストアを持たせる／現状維持 | Edge リポジトリの責務。intake 停止中の証拠収集（【守る設計】3）の強さ | #366 |

## 4. 優先度が低いもの

| # | 事項 | 現在の既定値 | 選択肢 | 影響 | PR・ADR |
| --- | --- | --- | --- | --- | --- |
| L1 | `IMPLEMENTATION_SPEC.md` §3 の `azui` の扱い | コードでは `azui` を `SERVICE_ACCOUNTS` から外した。仕様は daemon 用アカウントの一覧に `azui` を挙げたまま | 仕様の表現を直す／現状維持 | 将来 UI から arbiter 等を呼ぶときは、その daemon の policy に `azui` を明示的に加える | #355 |
| L2 | NOC のアカウント名 | `aznoc`（仕様の予約名 `azobs` は `SERVICE_ACCOUNTS` に入っており SERVICE に分類されるため） | `aznoc` のまま仕様を直す／`azobs` を SERVICE から外して使う | 仕様との名前の一致 | #364 |
| L3 | unit 状態の観測アカウント | 既存の `azprobe` を再利用（権限は増えない） | 専用アカウントに分ける | アカウントの数 | #363 |
| L4 | NOC の `RestrictAddressFamilies` | `AF_NETLINK AF_UNIX`（NSS などの AF_UNIX 利用に備える） | `AF_NETLINK` だけに絞る | 収集自体は netlink だけで足りる | #364 |
| L5 | UI の unit 名 | `azazel-ui.service`（仕様は `azazel-uid.service`） | 仕様を直す／unit 名を変える | 名前の一致 | #365 |
| L6 | 境界試験の `ADOPTED_LISTENER` | listener の例外を広げず、新しい分類を設けた | 現状維持／別の形 | 試験の構成だけ | #365 |
| L7 | キオスクの日本語フォント（`fonts-noto-cjk` 等） | 同梱しない（配備側の判断） | 配備手順に入れる／入れない | キオスクでの日本語表示 | #365 |
| L8 | 非 root の `status` テキスト画面に新しい 4 節を出すか | **ADR-0007 D9**：テキスト画面にも運用者向け snapshot の 4 節・保存容量・operator view を、`--json` と同じ語と理由コードで出す（golden を更新） | テキストにも出す（既定）／`--json` だけ | 文言と golden の変更 | #363、ADR-0007 |
| L9 | `not-loaded` の表示語 | GetUnit の結果をそのまま snapshot に入れ、UI では「読込なし（停止後に解放された oneshot も含む。未導入とは限らない）」と注記する（ADR-0007 D9） | UI の語で区別する（既定） | 表示の誤読を減らす | #363、ADR-0007 |
| L10 | M.I.O. の「古すぎ」の判定 | #370 で案 1（書き手の生存の証拠で判定）を既定に採用。主の閾値は `MIO_STALE_S`（300 秒）、補は `MIO_OBSERVATION_STALE_S`（2 日）。snapshot を読めない環境では、要求の無いノードは従来どおり 2 日で stale になり得る | 現状維持／entryd に日次の心拍を書かせる／記録が異なる snapshot の扱いを緩める（緑の経路は作らない） | 誤警報の残り方 | #358、#367、#370 |
| L11 | LOCAL の除外理由を区別して記録するか | admission の読取失敗も固定文 `LOCAL_REFUSAL` で記録（可用性の区別は `mio.entry.availability.local` に残る） | ledger の語彙を足して分ける | ledger の語彙が増える | #356 |
| L12 | 撤回理由の語彙 | `operator_request`／`privacy_review`／`provider_change`／`incident_response` の 4 語に固定 | 語を足す／自由文を許す | protocol の変更 | #361 |
| L13 | 送信同意の operator CLI | entryd の socket 動詞だけ。`azazel-nexus` にサブコマンドは無い | サブコマンドを足す | 運用者の手順 | #361 |
| L14 | 先に進みすぎた時計からの復旧 | 時計を直してから root が `clock-floor.json` を削除し、unit を再起動 | 既存の operator 認可の範囲で専用の復旧 verb を作る／現状維持 | 手順の安全性。新しい迂回経路は作らない | #359 |
| L15 | 旧 3 キー形の引用の受理をいつ止めるか | アップグレード直後の checkpoint・recent.json を壊さないため受理 | 次の版で拒否する | 互換性 | #362 |
| L16 | `signer_key_ids` の表示 | 表示する（commissioned anchor の名前で秘密ではないと判断） | 「名前に機微な情報を入れない」前提を文書に明記する／表示をやめる | 表示と運用の前提 | #362 |
| L17 | 出典の伏字規則 | `12:30:45` なども「possible address form」として伏せる。dataset citation は署名済みだが内容は信用せず、平文化・長さ制限・アドレス構文の除去だけで表示 | 規則を狭めて表示を優先する／現状維持 | 誤検知と露出の兼合い | #362、#368 |
| L18 | 失効受理に確認語を求めるか | ROOT だけで受け付ける（署名が権限で、閉じる方向にしか働かない） | repin と同じく TTY の確認語を求める | 手順の儀式 | #375 |
| L19 | fixture 鍵が pin にあるときの status の理由語 | 既存の `trust_unreadable` を使う | 専用の理由語を足す | UI・CLI の語彙 | #375 |
| L20 | Nexus の試験用 seed を `PUBLIC_FIXTURE_KEYS` に入れるか | 入れていない（製品に現れないことは別の試験が固定） | 入れる | 拒否の網羅性 | #375 |
| L21 | Lite import 中に daemon の単一ループが塞がること | 検証中の status・lookup は待たされ、期限を過ぎた lookup は Knowledge unavailable になる（決定論経路は止まらない） | 現状維持／import を別スレッド・別プロセスにする | 説明系の可用性 | #375 |
| L22 | 説明 ledger の 1 件の大きさ | 現状維持。Fabric があると引用と Edge の判断を Fabric の形でも持つ（上限 1 件 32 KiB）。M17 の証拠参照（2 件まで）と L23 の M.I.O. の claim が加わる。日の segment に射影付きが入らないときは射影なしで書く（#380 の挙動のまま、証拠参照と生成方式は記録に残る）。現在の wheelhouse には Fabric が入っていない | 現状維持（採用）／射影を別に保存する | 1 日分の segment に入る件数 | #380 |
| L23 | M.I.O. の助言を `Claim` に射影するか | **決定**：ローカル回答の生成方式（`local_model_inference`／`embedding_matching`／`deterministic_keyword_matching`）とモデル id を `mio.provenance` に記録し（`content_kind` は互換のため `ai_advice` のまま）、`Claim` に射影する（`model_ref` 付き）。応答に世代が無いので `model_generation` は空で、claim に `model_generation_not_delivered` と書く | ledger にそれらを持たせて射影する（採用。世代は M.I.O. の応答に載るまで空） | `ClaimSet` の網羅性 | #380 |
| L24 | Nexus の tuple の CPU 表記 | カーネル表記（`x86_64`／`aarch64`）を維持 | 正準名（`amd64`／`arm64`）へ移す | mission-pack の設定と `as_record` の版上げが要る | #382 |
| L25 | `fabric_version` の先頭の `v` | 先頭の `v` を 1 文字だけ外して比べる | 現状維持／どちらかに揃える | 比較規則 | #382 |
| L26 | `deployment_profile` と Nexus の `profile`（資源 envelope） | 対応づけない（Fabric は tier を共有契約に載せない方針） | 対応づける | Fabric の claim に envelope が載らないまま | #382 |
| L27 | 正規の CPU 名と lab profile の id | `amd64`／`arm64`、lab profile の id は `-lab` で終わる | 変更する（`platform_profile.py` の表と試験だけで済む） | 名前のみ | #360 |
| L28 | Arm の offline target の識別子に `-lab` を付けるか | `debian-13-aarch64-cp313`（profile id は `-lab` で終わり、報告には purpose が必ず載る） | `-lab` を付ける | 名前のみ | #378、[ADR-0005](adr/0005-arm-lab-offline-target.md#open-for-the-owner) |
| L29 | dpkg が読めないときの扱い | `DPKG_UNOBSERVED` として拒否（`select` 経由のすべての経路と `install.sh`、lab も同じ） | 現状維持／緩める | 導入先はすべて Debian なので、緩める理由は今は無い | #373 |
| L30 | `install.sh` で SOABI を照合するか | 照合しない（実導入では AppArmor の wrapper 検査が `/usr/bin/python3.13` を固定している） | 照合する | 二重の確認 | #373 |
| L31 | HG-01／HG-04 での capture の必須化と、core reserve の旧版記録 | capture を必須にした。measurement は v4、v1〜v3 は「読めるが受理しない」 | 現状維持 | 旧版の記録は受理されない | #374 |
| L32 | Fabric の pin を移すときの手順 | pyproject、uv.lock、`FABRIC_PIN`、`SOURCE_BUILDS`、lock の hash を同時に更新する（試験がずれを拒否する） | 判断ではなく手順。rc6／v0.9.0 へ移す時期だけが判断 | pin の移行 | #357、[ADR-0001](adr/0001-fabric-pin.md) |

## 5. 件数

| 優先度 | 件数 |
| --- | --- |
| 高 | 10 |
| 中 | 27 |
| 低 | 32 |
| 計 | 69 |

元の PR 本文の項目は 90 余りある。同じ論点を扱う項目（たとえば #358 と #367 と #370 の
M.I.O. の stale、#363 と #364 の timer、#359 と #368 の時計の上限、#366 と #375 の
fixture 鍵、#363 と #365 の UI の読取範囲）は 1 行にまとめた。#369・#371・#372・
#376・#377・#381 にはオーナー判断の節が無い（#371 は「なし」と明記）。

## 6. この一覧の外にある判断

#355〜#382 より前の作業で、各文書に置かれたオーナー判断の節がある。ここでは
重複させず、所在だけを挙げる（一部は上の行と同じ論点で、そのときは上の行を正とする）。

- [操作 UI：Open questions for the owner](operator-ui.md#open-questions-for-the-owner)（M20〜M22・H9・L5・L7 と同じ論点）
- [NOC 観測 §8](noc-observation.md#8-owner-decisions)
- [Knowledge Lite 差分試験 §4.4](knowledge-lite-differential.md#44-オーナー判断)（M13〜M15 と同じ論点）
- [Edge package 検証 §3c](edge-package-verification.md#3c-what-still-needs-the-owner)
- [起動時の commissioning 保存 §5](commissioning-storage-at-boot.md#5-owner-decisions)
- [activation の observe baseline §6](activation-observe-baseline.md#6-owner-decisions)
- [Deception の露出許可 §10](deception-exposure-grant.md#10-owner-decisions)・[配線 §9](deception-exposure-wiring.md#9-owner-decisions-before-g6)・[redirect の前提 §7](deception-redirect-prerequisites.md#7-owner-decisions)

## 7. この一覧が示さないこと

- 行の既定値が正しいこと。既定値は「安全側に倒した仮の値」であり、承認ではない。
- 網羅。PR 本文に書かれなかった判断事項や、関連リポジトリ（Edge・Fabric・Knowledge）
  の側で未決のものは含まない。
- 実機での結果。H4・H10 などは実機・実 VM の測定を待っており、その手順は
  [実機受入手順](hardware-acceptance.md) にある。
