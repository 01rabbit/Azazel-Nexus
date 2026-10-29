# 専門家への引継ぎパッケージ（`azazel-nexus handoff export`）

状態: **初版（ローカル CLI のみ）**。UI からの取得は別 PR。goal 2 方針【5】F、Codex 調査 S-19。

臨時の担当者が、1 件のインシデントについてノードが記録したことを、ネットワークを使わずに 1 つのディレクトリへ書き出し、専門家へ渡すための手順と形式。
生成するだけで送信はしない（送信機能は存在しない）。外部へ渡すかどうか・どの経路で渡すかは担当者と組織の判断であり、このコマンドは決めない。

関連: [運用](operations.md) · [ノード情報の機密区分](inventory-confidentiality.md) · [operator view](operator-view.md) · [integration loop](integration-loop.md)

## 1. 操作手順

1. 書き出し先を用意する。既存の実ディレクトリで、グループ・他者が書けないもの（例: 暗号化した証拠媒体の中に `mkdir -m 700` で作ったディレクトリ）。
   シンボリックリンクを経由する経路、`/var/lib/azazel`・`/etc/azazel`・`/run`・`/proc`・`/sys`・`/dev` の中は拒否される。
2. インシデント ID を確認する（`azazel-nexus status` の recent incidents に出る `inc-…`）。最新でよければ `latest` と書く。
3. 実行する。

   ```sh
   sudo azazel-nexus handoff export --incident latest --output-dir /media/evidence/handoff
   ```

   成功すると、作成したディレクトリ（`azazel-handoff-<インシデントID>-<UTC時刻>`）、`manifest.json` の SHA-256、抑制した件数、読めなかった情報源を表示する。
4. 表示された manifest の SHA-256 を、媒体とは別の紙・連絡手段で専門家に伝える。専門家は `manifest.json` の digest を照合し、manifest に並ぶ 2 ファイルの digest を照合する。
5. 書き出したディレクトリは `0700`、各ファイルは `0600` で、実行した利用者（`sudo` なら root）の所有になる。媒体へ移す・渡すときは、その権限のまま扱う。

拒否されたときは固定の理由コードだけを表示し、何も残さない（§4）。

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
| `time` | 発生時刻（初観測）・最終観測と、その出典。`clock`: 時計の状態（`synchronized_this_boot`／`unverified`／`untrusted`）と兆候 | 兆候を列挙し、`untrusted` とする |
| `observed_facts` | Edge の観測（`edge_observation`）。遷移ごとの時刻・件数・重大度・ATT&CK・分類・証拠保存の有無、台帳の連続性と欠落記録 | `unavailable`、recent snapshot があれば `partial` |
| `edge_decision` | Edge の決定論的規則の判断。すべて `kind: would`・`executed: false` | `unavailable` |
| `execution` | 実行結果。observe-only なので常に `not_executed`（`nexus_accepts_observe_only`）。各 would に期限 `null`、リース・解除は `not_applicable` | — |
| `ai_assessment` | 説明器の記録（`advisory_only_not_fact`）。経路・結果・説明器の区分・本文（伏字済）・失敗コード、現在の M.I.O. 経路の能力 | `unavailable` と理由（`no_explanation_recorded`、`explanation_pending` など） |
| `business_impact` | 評価は `unavailable`（ノードは業務上の重要度を知らない）。NOC の受動観測（インターフェース数・リンク有無・既定経路数、到達性は未測定）と Nexus が実行した制限数（0） | NOC がなければ `unavailable` |
| `evidence_refs` | Edge の証拠記録の digest（EvidenceRef 相当: `source: edge-core`、`digest`、`role`）。中身は含めない | `unavailable` |
| `knowledge` | 引用ごとの bundle digest・世代・参照時の鮮度・参照時刻・生成時の経過秒、現在の Lite の世代と `superseded` | `unavailable` と理由 |
| `operator_actions` | 監査記録の連続性、インシデントの監査記録、前 1 時間からのノード操作（操作者名は `withheld`） | `unavailable` |
| `unconfirmed` | 未確認事項（コードと日本語） | — |
| `confidentiality` | 抑制の方針・種別ごとの件数・読んでいないもの・`upload: none` | — |
| `sources` | 各情報源の状態と理由・読める権限 | — |

**このインシデントに対する担当者の確認・承認の記録はない。** Nexus にその記録種別がないため `operator_actions.incident_scoped` は `unavailable`（`no_operator_action_record_type_for_incidents`）。並ぶのは期間内のノード操作で、このインシデントへの操作ではない。

**AI の区分について。** 説明器は、ローカル経路が答えた記録をすべて `ai_advice` と区分する。モデルが文章を生成したのか、決定論的な照合で答えたのかは記録されておらず、パッケージは `generation_method: not_recorded` と書く。モデルの識別も記録されていない（`model_identity_not_recorded_in_explanation_ledger`）。

### 時刻の信頼性

時刻はすべてノードの壁時計による。次のどれかがあれば `untrusted`:

- 生成時の時計が 2026-01-01 より前（RTC のリセット等）: `wall_clock_implausible`
- 生成時の時計が Knowledge の時計の床より前（時計が戻った）: `wall_clock_behind_knowledge_floor`
- 生成時刻より 5 秒以上後の日時を持つ記録がある: `records_dated_after_generation`
- intake・説明器が `segment_from_future` を数えている

どれもなく timesyncd の記録があれば `synchronized_this_boot`。これは起動後に一度同期したことを示すだけで、今も正しいこと・時刻源が真正であることは示さない。記録がなければ `unverified`。

## 4. 書き出しの安全性

- 出力先は `/` から 1 段ずつ `O_NOFOLLOW` で開く。途中のどこかがシンボリックリンクなら `output_path_refused`。
- 出力先がグループ・他者から書込み可能なら `output_dir_shared_writable`。
- 同じ名前が既にあれば（ディレクトリ・ファイル・リンクのどれでも）`output_exists`。上書きしない。
- 書く前に空き容量を確かめ（本体＋1 MiB＋ファイルごとに 64 KiB）、足りなければ `insufficient_space`。
- 隣に私有の一時ディレクトリ（`0700`）を作り、各ファイルを `O_EXCL` で作成・fsync し、最後に名前を付け替える。途中で失敗（容量不足を含む）すれば、一時ディレクトリと中身を消して何も残さない。電源断の場合は `.azazel-handoff-…partial-…` という隠しディレクトリが残り得るが、名前の付け替え前なので完成したパッケージとは区別できる。
- 制約: 付け替えの直前に同名の**空**ディレクトリが作られた場合、Linux の `rename(2)` はそれを置き換える（中身のあるものは置き換えない）。出力先を専用にすることで避ける。

## 5. 機密の扱い

既定で抑制する。抑制をやめる option はない（機密情報の外部提供は委任外のため、このコマンドに解除の仕組みを置かない）。

| 種別 | 扱い |
| --- | --- |
| 送信元アドレス（`network_address`）、ルール番号（`rule_identifier`）、宛先ポート（`service_port`）、シグネチャ本文などの producer の自由文（`producer_free_text`） | 台帳から写さない。件数を数える |
| 操作者名（`operator_identity`） | `withheld` と書き、件数を数える |
| AI の本文・Knowledge の名前と要約に含まれる IP・MAC・インターフェース名・パス・URL・メールアドレス・host:port・秘密らしい文字列 | `[伏字:種別]` に置換し、件数を数える |
| Knowledge の出典文でこれらを含むもの（`citation_text`） | 出典文を出さず `citation_state: withheld` |
| 生 payload・証拠の中身 | 読まない。digest だけ |
| インターフェースの識別 | NOC は件数だけ（名前・アドレス・ゲートウェイは出さない） |

最後に、書く前のファイル全体を IP・MAC・URL・メールアドレス・秘密鍵の形で検査し、残っていれば `suppression_incomplete:<種別>` で拒否して何も書かない。
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
- 監査記録の連続性は、読んだ日（インシデントの 1 時間前の日以降）の範囲でだけ確かめる。全体の検証は auditd の起動時検証による。
