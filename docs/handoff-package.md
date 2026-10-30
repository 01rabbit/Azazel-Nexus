# 専門家への引継ぎパッケージ（`azazel-nexus handoff export`）

状態: **初版（ローカル CLI のみ）**。UI からの取得は別 PR。goal 2 方針【5】F、Codex 調査 S-19。

臨時の担当者が、1 件のインシデントについてノードが記録したことを、ネットワークを使わずに 1 つのディレクトリへ書き出し、専門家へ渡すための手順と形式。
生成するだけで送信はしない（送信機能は存在しない）。外部へ渡すかどうか・どの経路で渡すかは担当者と組織の判断であり、このコマンドは決めない。

関連: [運用](operations.md) · [ノード情報の機密区分](inventory-confidentiality.md) · [operator view](operator-view.md) · [integration loop](integration-loop.md)

## 1. 操作手順

1. 書き出し先を用意する。既存の実ディレクトリで、**実行する利用者の所有**で、グループ・他者が書けないもの（例: 暗号化した証拠媒体の中に `sudo mkdir -m 700` で作ったディレクトリ。`sudo` で実行するなら root の所有にする）。
   シンボリックリンクを経由する経路、`/var/lib/azazel`・`/etc/azazel`・`/run`・`/proc`・`/sys`・`/dev` の中は拒否される。
2. インシデント ID を確認する（`azazel-nexus status` の recent incidents に出る `inc-…`）。最新でよければ `latest` と書く。
3. 実行する。

   ```sh
   sudo azazel-nexus handoff export --incident latest --output-dir /media/evidence/handoff
   ```

   成功すると、作成したディレクトリ（`azazel-handoff-<インシデントID>-<UTC時刻>`）、`manifest.json` の SHA-256、抑制した件数、読めなかった情報源を表示する。
4. 表示された manifest の SHA-256 を、媒体とは別の紙・連絡手段で専門家に伝える。専門家は `manifest.json` の digest を照合し、manifest に並ぶ 2 ファイルの digest を照合する。
5. 書き出したディレクトリは `0700`、各ファイルは `0600` で、実行した利用者（`sudo` なら root）の所有になる。媒体へ移す・渡すときは、その権限のまま扱う。

終了コードと表示（§4）:

| 終了 | 表示 | 状態 |
| --- | --- | --- |
| 0 | `handoff: written <パス>` | 完成。manifest まで書いて同期した |
| 3 | `handoff: written <パス>` と `WARNING durability_unconfirmed` または `WARNING file_close_failed`／`directory_close_failed` | 全ファイルは書いて同期したが、ディレクトリの同期か、閉じる処理に失敗した。電源断で失われ得る。媒体上で manifest を照合してから使う |
| 1 | `refused (<コード>); nothing was written.` | パッケージのディレクトリを作る前に止まった。何も作っていない |
| 1 | `refused (<コード>); an incomplete directory … was left at <パス>` | ディレクトリを作った後に失敗した。manifest のない未完成のディレクトリが残っている（書いたファイルは空にしてある）。パッケージではない。確認して消す |
| 1 | `refused (output_replaced); the entry at <パス> is not the directory this command made` | 作った直後のディレクトリが別のものに入れ替わっていた。そこには何も書いていない。確認する |
| 2 | `refused (principal_refused)` | 権限がない |

## 2. 誰が実行でき、何を読むか

実行できるのは **root** と **`azazel-operator` グループの利用者**だけ。それ以外は `principal_refused`（終了コード 2）。
このコマンドのために新しい権限・socket・verb は足していない。どちらの権限でも既存のファイルを読むだけで、socket を開かず、プロセスを起動しない。

| 情報源 | パス | 読める権限 | パッケージに使う欄 |
| --- | --- | --- | --- |
| インシデント台帳（hash chain） | `/var/lib/azazel/edge-incidents/*.jsonl` | root | 観測事実・Edge の判断・証拠参照・時刻 |
| 説明台帳 | `/var/lib/azazel/incident-explain/explanations/*.jsonl` | root | AI の見解・Knowledge の出典 |
| 監査記録（hash chain） | `/var/lib/azazel/state/audit/*.jsonl` | root | 担当者の操作 |
| Knowledge の時計の床 | `/var/lib/azazel/state/knowledge/clock-floor.json` | root | 時刻の信頼性 |
| recent incidents・説明器と intake の状態 | `/var/lib/azazel/run/incident-explain-status/`・`/var/lib/azazel/run/edge-intake-status/` | operator | 台帳を読めないときの代替、ループの状態 |
| Knowledge Lite・M.I.O.・NOC の状態 | `/var/lib/azazel/run/{knowledge,mio,noc}-status/status.json` | operator | Knowledge の現在の世代、経路の能力、通信の受動観測 |
| timesyncd の同期記録 | `/run/systemd/timesync/synchronized` | 全員 | 時刻の信頼性 |

`azazel-operator` の利用者が実行すると台帳は読めない。その欄は `unavailable`／`partial` と `not_readable_by_principal` になり、recent incidents の要約（説明は 280 字の要約、bundle digest は短縮形）で代替する。完全なパッケージには `sudo` を使う。
読まないもの: Edge の証拠ストア（生 payload を含む）、デコイの証拠、コミッショニング記録、`/var/lib/azazel/secrets`、インターフェースの識別情報、台帳回復時の隔離データ。

## 3. 形式

ディレクトリに 3 ファイルを置く。

| ファイル | 内容 |
| --- | --- |
| `handoff.json` | schema `azazel-nexus/handoff-package/1` |
| `handoff.ja.md` | 同じ内容の日本語文書 |
| `manifest.json` | schema `azazel-nexus/handoff-manifest/1`。上の 2 ファイルの SHA-256・バイト数・media type |

`handoff.json` の欄。観測事実・Edge の判断・実行結果・AI の推測は別の欄で、各欄に `authority` を持つ。

| 欄 | 内容 | 材料がないとき |
| --- | --- | --- |
| `time` | 発生時刻（初観測）・最終観測と、その出典。`occurrence`: 発生時刻の信頼性。`generation_clock`: 生成時の時計の状態 | 兆候を列挙し、`untrusted` とする |
| `observed_facts` | Edge の観測（`edge_observation`）。集計（件数・最重大度・最新の遷移・証拠を保存できなかった遷移数）は読んだ全遷移から計算し、遷移の履歴は新しい 256 件まで表示（`transitions_display` に全件数・省略件数・省略した範囲）。台帳の検証結果と欠落記録 | `unavailable`、recent snapshot があれば `partial` |
| `edge_decision` | Edge の決定論的規則の判断。すべて `kind: would`・`executed: false` | `unavailable` |
| `execution` | 実行結果。observe-only なので常に `not_executed`（`nexus_accepts_observe_only`）。各 would に期限 `null`、リース・解除は `not_applicable` | — |
| `ai_assessment` | 説明器の記録（`advisory_only_not_fact`）。経路・結果・説明器の区分・生成方式・本文（製品の固定文のときだけ。ほかは `withheld`）・失敗コード、M.I.O. 経路の能力（鮮度付き）。新しい 16 件まで表示 | `unavailable` と理由（`no_explanation_recorded`、`explanation_pending` など） |
| `business_impact` | 評価は `unavailable`（ノードは業務上の重要度を知らない）。NOC の受動観測（インターフェース数・リンク有無・既定経路数、到達性は未測定）と Nexus が実行した制限数（0） | NOC がなければ `unavailable` |
| `evidence_refs` | Edge の証拠記録の digest（EvidenceRef 相当: `source: edge-core`、`digest`、`role`）。中身は含めない。新しい 64 件まで表示、省略件数付き | `unavailable` |
| `knowledge` | 引用ごとの technique id・claim id・bundle digest・世代・参照時の鮮度・参照時刻・生成時の経過秒、現在の Lite の世代と `superseded`。名前・要約・出典文は伏せる（`withheld`。§5）。現在の世代は鮮度内の snapshot のときだけ比べ、そうでなければ `superseded: null` | `unavailable` と理由 |
| `operator_actions` | 監査記録の検証範囲（`anchored`）、インシデントの監査記録、前 1 時間からのノード操作（操作者名は `withheld`） | `unavailable` |
| `unconfirmed` | 未確認事項（コードと日本語） | — |
| `confidentiality` | 抑制の方針・種別ごとの件数・読んでいないもの・`upload: none` | — |
| `sources` | 各情報源の状態と理由・読める権限 | — |

**このインシデントに対する担当者の確認・承認の記録はない。** Nexus にその記録種別がないため `operator_actions.incident_scoped` は `unavailable`（`no_operator_action_record_type_for_incidents`）。並ぶのは期間内のノード操作で、このインシデントへの操作ではない。

**AI の区分について。** 説明器は、ローカル経路が答えた記録をすべて `ai_advice` と区分する。生成方式（`local_model_inference`／`embedding_matching`／`deterministic_keyword_matching`）は、説明器が回答とともに記録したもの（説明 ledger の `mio.provenance`、#392）を書き、`generation_method_basis: recorded` とする。その記録が無い旧い記録だけ、本文が製品の固定文（banner）ならその banner から判定して `fixed_banner` とする。固定文でない本文は伏せ、生成方式は `not_recorded`。recent snapshot の要約（ASCII に縮めた 280 字）は、日本語の banner がどれも同じ語になるなど複数の固定文で一致するものがあり、そのときは生成方式を決めず本文も出さない（`text_state: ambiguous_summary`）。モデルの識別は、説明 ledger には記録されるようになったがパッケージには載せない（`model_identity_not_included_in_package`。モデル id は自由な文字列で、パッケージの漏えい検査にかかりうるため）。生成方式の記録が無い旧い ledger では `model_identity_not_recorded_in_explanation_ledger`。

**表示の上限。** 上限は表示だけにかかる。最終状態・集計・最新の判断は、読んだ全記録から計算する。表示しなかった記録は `*_display` に全件数・省略件数・省略した範囲（古い側）として書き、Markdown にも出す。

**状態記録の鮮度。** 各 snapshot に、既存の `operator_snapshots.freshness()` と各期限（intake・説明器・recent 30 秒、Knowledge 150 秒、M.I.O.・NOC 300 秒）を当てる。期限を過ぎたもの・未来の日付のものは `stale_last_recorded`（最終記録のみ、現在は未確認）と書き、現在の状態として使わない。

### 台帳の検証

インシデント台帳は、intake の `IncidentLedger` と同じ条件で先頭から検証する。`retained-boundary.json` がなければ genesis（sequence 1）から、あればその `(sequence, hash)` から続くことを確かめ、境界の `oldest` が残っている最初の segment であることも確かめる。境界の `deleted` 以前の segment（境界を書いた後・削除の前の中断で残ったもの）は、intake・説明器と同じく無視する。先頭行・先頭 segment の削除、境界の不一致は `chain_broken`／`retention_boundary_mismatch` になる。
監査記録はインシデントの 1 時間前の日から読む。それより前の segment がなければ genesis から検証し（`anchored: true`）、あれば読んだ範囲の連続性だけを確かめて `anchored: false` と書く。

### 時刻の信頼性

発生時刻と生成時の時計は分けて扱う。

**発生時刻**（`time.occurrence`）: 発生当時に時計が同期していた記録はないので、最良でも `unverified`。次のどれかがあれば `untrusted`: 2026-01-01 より前の発生時刻（`occurred_before_plausible_date`）、最終観測が初観測より前（`last_seen_before_first_seen`）、遷移の時刻の逆行（`transitions_out_of_order`）、発生より前の説明（`explained_before_occurrence`）、生成時刻より後の日時の記録（Knowledge の参照時刻を含む）、生成時の時計の不信。

**生成時の時計**（`time.generation_clock`）。次のどれかがあれば `untrusted`:

- 生成時の時計が 2026-01-01 より前（RTC のリセット等）: `wall_clock_implausible`
- 生成時の時計が Knowledge の時計の床より前（時計が戻った）: `wall_clock_behind_knowledge_floor`
- 生成時刻より 5 秒以上後の日時を持つ記録（snapshot・台帳・監査・Knowledge の参照時刻）がある: `records_dated_after_generation`
- intake・説明器が `segment_from_future` を数えている

どれもなく timesyncd の記録があれば `synchronized_this_boot`。これは起動後に一度同期したことを示すだけで、今も正しいこと・時刻源が真正であること・発生より前に同期したことは示さない。記録がなければ `unverified`。

## 4. 書き出しの安全性

- 出力先は `/` から 1 段ずつ `O_NOFOLLOW` で開く。途中のどこかがシンボリックリンクなら `output_path_refused`。
- 出力先がグループ・他者から書込み可能なら `output_dir_shared_writable`、実行する利用者の所有でなければ `output_dir_not_owned`。
- **信頼の前提。** 出力先は実行する利用者専用のディレクトリとする。同じ利用者（同じ UID）の他のプロセスと root は信頼境界の内側として扱い、それらによる妨害は保証の対象外。以下の「入替の検出」は、この前提の範囲で、作成直後のディレクトリが空・私有でないものに替わっていた場合を検出するだけで、同じ利用者が空の `0700` ディレクトリに入れ替えた場合は検出できない。
- 同じ名前が既にあれば（ディレクトリ・ファイル・リンクのどれでも）`output_exists`。上書きしない。
- 書く前に空き容量を確かめ（本体＋1 MiB＋ファイルごとに 64 KiB）、足りなければ `insufficient_space`。
- **どの段階でも既存のものを置き換えない。** パッケージのディレクトリは `mkdir` で作る（同名のファイル・ディレクトリ・リンクがあれば、空のディレクトリでも失敗する）。各ファイルはその中に `O_CREAT|O_EXCL` で作る。`rename` は使わない（Linux の `rename(2)` は空のディレクトリを置き換えるため。`renameat2(RENAME_NOREPLACE)` は標準ライブラリになく、このパッケージは `ctypes` を使わない方針）。
- 各ファイルを書いて fsync し、**`manifest.json` を最後に**書く。manifest があり、その digest が合うディレクトリだけがパッケージである。
- ディレクトリを作った直後に開いたものが、この利用者の・私有の・空のディレクトリでなければ（入れ替えられた）`output_replaced` とし、そこには何も書かない（検出できる範囲は上の信頼の前提のとおり）。
- ファイルやディレクトリを閉じる処理が失敗しても、残りの記述子は閉じ続け、元の結果（成功、または最初の失敗の理由と残存先）を保つ。成功後に閉じる処理が失敗したときは、パッケージの場所と `file_close_failed`／`directory_close_failed` を表示して終了 3、失敗後ならその理由に `also file_close_failed` などを添える。
- **失敗しても名前で消さない。** 名前を確かめてから消す方式は、その間に入れ替えられると相手のものを消すため。ディレクトリを作った後の失敗（容量不足を含む）では、このコマンドが開いたファイルを自分のファイル記述子で空にして容量を返し、manifest のない未完成のディレクトリの場所を表示する。ディレクトリを作る前の失敗だけを `nothing was written` と表示する。
- manifest まで書けた後に、ディレクトリと親の fsync が失敗したときは、パッケージの場所を表示し `durability_unconfirmed`（終了 3）とする。
- 電源断では manifest のない未完成のディレクトリが残り得る。manifest がないので完成品と区別できる。

## 5. 機密の扱い

既定で抑制する。抑制をやめる option はない（機密情報の外部提供は委任外のため、このコマンドに解除の仕組みを置かない）。

| 種別 | 扱い |
| --- | --- |
| 送信元アドレス（`network_address`）、ルール番号（`rule_identifier`）、宛先ポート（`service_port`）、シグネチャ本文などの producer の自由文（`producer_free_text`） | 台帳から写さない。件数を数える |
| 操作者名（`operator_identity`） | `withheld` と書き、件数を数える |
| 説明台帳の本文・通知（`ai_free_text`） | 製品の固定文（advisory の banner、handoff の通知）と一致するときだけ写す。ほかは出さず `text_state: withheld` |
| Knowledge の名前・要約・出典文（`knowledge_free_text`） | 写さない（`withheld`）。文字の形で自然言語と符号化値（英字だけの Base64 など）・内部の識別名（`srv-db-core` など）を区別することはできないため。専門家は technique id・bundle digest・世代で引ける |
| 監査記録の値（`audit_value`） | 小文字の語（`[a-z][a-z0-9_]*`）か整数のときだけ写す |
| 生 payload・証拠の中身 | 読まない。digest だけ |
| インターフェースの識別 | NOC は件数だけ（名前・アドレス・ゲートウェイは出さない） |

最後に、パッケージと manifest の**すべての文字列**と Markdown を検査する。対象: IP アドレス（v4・v6）、MAC、URL、メールアドレス、Windows と Unix のパス、host:port、ドット区切りのホスト名、インターフェース名、percent 符号化、24 桁以上の 16 進、Base64 らしい値、秘密らしい形（鍵の先頭行、`password=` 等）。形の決まった欄（digest・schema・版・ファイル名）と、ドットのないコード・時刻・ID の形の文字列、製品自身のドット付き語彙だけを除き（コードの形でも 16 進・Base64・秘密の形は検査する）、見つかれば `suppression_incomplete:<種別>` で拒否して何も書かない。
形の決まった欄・コード・時刻・ID の扱いは JSON と Markdown で同じ。ドットを含む語は、製品自身の語彙（監査のイベント種別 `bootstrap.ready` 等。auditd の宣言と照合する試験がある）だけを除き、ほかはホスト名として検査する。
規則は [機密区分](inventory-confidentiality.md)（外部の報告に raw identity を入れない）と status view の伏字（自由文・パスは出さず `withheld` と書く）に合わせている。

## 6. 生成例（fixture 由来）

[`examples/handoff/`](examples/handoff/handoff.ja.md) は **試験用 fixture から生成した例**で、実在のノード・インシデントの記録ではない（`provenance: fixture`、文書の冒頭にも明記）。
fixture は `tools/build_handoff_example.py` が作る: intake と同じ形式で書いたインシデント台帳を、実際の説明器（`Explainer`）が固定の応答で説明し、監査記録と状態 snapshot を置いたもの。fixture のアドレスは文書用の範囲（RFC 5737）で、パッケージに出ないことを示すために入れてある。
`tests/unit/test_handoff.py` が同じ fixture から生成し直してバイト単位で比較する。形式を変えたら `python3 tools/build_handoff_example.py` で作り直す（runtime を import できる環境で）。

## 7. 残る制約

- UI からの取得はない（別 PR）。
- 証拠ストアにその digest の記録がまだ残っているかは確かめていない（ストアは私有）。
- 業務影響はノードでは評価しない。担当者が専門家へ直接伝える。
- 説明台帳はモデルの識別と生成方式を記録していない。説明台帳の Fabric `ClaimSet` は証拠参照を運ばない（S-18）ため、このパッケージは証拠参照をインシデント台帳から取る。
- 監査記録は、インシデントの 1 時間前の日より前の segment があるとき、読んだ範囲の連続性だけを確かめる（`anchored: false`）。全体の検証は auditd の起動時検証による。
- Knowledge の名前・要約・出典文は出さない。検証済み bundle の語彙と照合して出す方式は今後の課題。
- 失敗時に残る未完成のディレクトリは自動では消さない（場所を表示する）。
