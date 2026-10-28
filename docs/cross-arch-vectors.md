# 共通試験ベクトル（CPU 間の意味の一致）

Status: **実装済み。** aarch64（colima のコンテナ）と amd64（colima-rosetta の
Rosetta 変換によるコンテナ）で同じ digest になることを確認した。**実機の x86_64・
実機の Arm では未実行**（[記録](evidence/cross-arch-vectors-2026-10-29.md)）。

## 1. 目的

ゴールの設計原則 4 は「Arm と amd64 で、判断規則、認可、契約、監査の意味、失敗時の
動作、利用者の操作を変えない」ことを求める。
[ADR-0003](adr/0003-arm-software-verification-profile.md#decision) D6 は、それを
「注入した時計と ID で作る共通の試験ベクトルを両 CPU で実行し、バイト単位で比べる」
ことで確かめると決めた。この文書はそのベクトルの仕様である。

- ベクトル本体：[`tests/vectors/cross_arch.py`](../tests/vectors/cross_arch.py)。
  各ベクトルは本番のコードを固定の入力で実行し、判断・認可・監査の出力を JSON 文書に
  まとめる。その正準バイト列の SHA-256 が digest である。
- 固定値：[`tests/vectors/digests.json`](../tests/vectors/digests.json)。digest、
  そのベクトルが何を含むか（`covers`）、変更の履歴（`history`）を持つ。
- 試験：[`tests/unit/test_cross_arch_vectors.py`](../tests/unit/test_cross_arch_vectors.py)。
  どの CPU で実行しても、各ベクトルが固定値と一致することを確かめる。tests/unit は
  aarch64 でも x86_64 でも同じものが走るので、両方で通ることが「同じ意味」の証拠になる。
- 両 CPU の突合せ：[`tools/cross_arch_vectors.py`](../tools/cross_arch_vectors.py)。
  colima（aarch64）と colima-rosetta（amd64）でベクトルを実行し、digest の一覧を
  JSON で出して突き合わせる。

## 2. ベクトルの一覧

| 名前 | 対象 | 分類 |
| --- | --- | --- |
| `edge.intake` | Edge golden 観測 6 件（[`rust_event_engine_v1.jsonl`](../tests/fixtures/edge/README.md)）の `parse_edge_event` による正準化と `EvidenceRecord` の digest。壊れた入力 6 種の拒否コード | 判断（取り込み） |
| `edge.incident` | golden 観測 2 巡を `IncidentTracker` に通した遷移（opened・updated・idle の closed）、incident_id、件数、most_severe | 判断 |
| `edge.explain` | 上の遷移から作る説明要求 frame（`explanation_input`・`build_frame`）と recent incident の行 | 判断の説明 |
| `knowledge_lite.verify` | Knowledge の公開 fixture（valid と negative 5 件）への `verify_bundle` の受理・拒否（gate と code）、member の digest、2 時点の `read_claims` と reading | 認可（署名・完全性）・期限 |
| `knowledge_lite.lookup` | producer の anchor を pin した node での import 結果と `lookup_context_reading`（valid・expired・corrupt-signature × 技術 ID 5 通り × 2 時点） | 根拠の提供 |
| `revocation` | [`tests/fixtures/revocation/`](../tests/fixtures/revocation/generate.py) の 3 件（ドメイン分離、`RevocationStore.accept`、`verify_bundle`）と、署名済み失効リストの受理・再送拒否・再有効化拒否・`reason_for` | 認可（失効） |
| `signature.ed25519` | RFC 8032 §7.1 の 4 ベクトル。検証が通ること、試験用 signer が RFC と同じ署名を作ること、改変 4 種（署名の 1 bit、メッセージの 1 bit、`s + L`、切詰め）が通らないこと、不正な公開鍵の拒否 | 認可（暗号） |
| `audit.chain` | 同じ 4 イベントから同じ監査チェーン（各 link、head、ファイルの sha256）になること。改変 3 種の検出 | 監査 |
| `status.read_model` | `azazel-nexus status --json` の read model。[`test_status_view.py`](../tests/unit/test_status_view.py) の golden 10 場面 | 状態表示 |
| `platform_profile.selection` | `select_profile` の入力 12 通りに対する profile と拒否理由、production use ごとの可否、境界名の対応と読取りの拒否 | 認可（実行基盤） |
| `mio.route` | `remote_admission` の全組合せ、route の `select` 7 場面と `fallback_once`、`outcome_for`、`terminal_for` | M.I.O. の経路判定 |
| `mio.consent` | `ConsentStore` の世代と send gate（未設定 → 前提 4 つ → 撤回 → 再設定。時刻は注入）と、非正準・重複・過大な記録の拒否 | M.I.O. の同意ゲート |

`mio.route` の `remote_faster` と `tie_to_narrower` の 2 場面だけは、remote を
許可された候補として与えている（このビルドの endpoint allowlist は空なので、実際の
入力からは remote が許可されない）。経路の順序付けを固定するためで、許可の判断は
同じベクトルの `admissions` が実際の入力で固定している。

## 3. 比較条件と除外したもの

### 正準形

`json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False)` を UTF-8 にしたもの。`audit.canonical_event_bytes` や
`edge_intake.canonical` と同じ形である。`ensure_ascii=False` なので、非 ASCII の
文字（説明要求の日本語の質問など）は `\uXXXX` に置き換えず UTF-8 のまま比べる。製品が
書くバイト列と同じものを比べるためである。

受け付ける型は object（キーは文字列）、array、string、整数、true・false・null だけ。
**float は拒否する**。tuple や set などほかの型も拒否する。ベクトルを書く側が明示的に
変換するか除外しない限り、何も digest に入らない。この形は `digests.json` の
`canonical_form` にも記録し、試験がコードと一致することを確かめる。

### 除外・注入したものの一覧

| 種類 | 扱い | 該当箇所 |
| --- | --- | --- |
| 時刻 | すべて注入する。壁時計は読まない | `FRESH`・`LATER`・`CLOCK_AT`、`EvidenceRecord.receive` と `IncidentTracker` の clock、status の `--as-of`、`ConsentStore` の clock |
| 単調時計 | 注入した整数列 | `IncidentTracker` の monotonic（開設レートの予算）、`ConsentStore` の monotonic |
| ID | 製品が digest から導く ID（incident_id、inbox の entry_id、bundle_digest）は比較する。乱数の ID を作る経路（uuid4 を使う commissioning_draft・operator_enrollment・proposal_export・model_admission_cli）はベクトルに含めない | — |
| 入力の float | golden 観測の Edge の f64 の時刻は、整数値であることを確かめて整数として入力する。整数値でない float や、ほかの float が現れたらベクトルは止まる | `$.enforcement.metadata.release_due_epoch`、`$.normalized.ingest_epoch`（`GOLDEN_FLOAT_FIELDS`） |
| 出力の float | 文書から取り除き、取り除いた path をその文書の `excluded_floats` に記録する。path の一覧も digest に入るので、新しい float が現れれば digest が変わる | 下の表 |
| 測定値 | 含めない。resource の読取り（usable memory）は status の場面で固定値を注入し、ファイルシステムの空きは固定の statvfs を注入する。route の予測に使う elapsed_ms は固定の整数の入力で、実測ではない | — |
| 埋め込み類似度 | 含めない（ADR-0003 R8。llama.cpp の SIMD 実装によって CPU 間で一致しない可能性がある）。M.I.O. の `gate_frame` の範囲判定はこのベクトルの対象外 | — |
| 時間に依存する M.I.O. の処理 | 含めない。`MioRouter` の期限計算と試行、send gate の drain の待ち時間は実時間に依存する。判定の部分（`select`・`fallback_once`・`outcome_for`・`terminal_for`・`remote_admission`・同意の世代）だけを含める | — |
| 例外の文 | 他の package や標準ライブラリの例外文（tar・JSON の decoder など）は Python の版で変わるので含めない。拒否は型名と固定のコード（`gate`・`code`）で比べる。製品が固定文で書く理由（失効の `reason_for`、`RevocationRefused` の固定文）は比べる | `refused_reading` の `reason`（拒否の detail を含む）は外す |
| パス・uid | 含めない。status の場面では一時ディレクトリの path が出力に無いことを確かめる。実行ユーザー（root か uid 1001 か）で digest は変わらない | — |
| tar の生成 | `revocation` で組み立てる bundle は mtime 0 の PAX 形式で、その `bundle_digest` は判断ではないので外す | — |

出力から取り除いた float の path：

| ベクトル | path |
| --- | --- |
| `knowledge_lite.verify` | `$.sample_served[].agg_raw_confidence`（Knowledge の行の信頼度。製品は値を変えずに渡すだけ） |
| `status.read_model` | `$.sections.edge_loop.evaluated_at`、`$.sections.edge_loop.explainer.snapshot.written_at`、`$.sections.edge_loop.explainer.source.written_at`、`$.sections.edge_loop.intake.snapshot.decoy.last_accepted_at`、`$.sections.edge_loop.intake.snapshot.edge_forward.reported_at`、`$.sections.edge_loop.intake.snapshot.last_accepted_at`、`$.sections.edge_loop.intake.snapshot.last_processed_at`、`$.sections.edge_loop.intake.snapshot.written_at`、`$.sections.edge_loop.intake.source.written_at`、`$.sections.edge_loop.recent.snapshot.incidents[].first_seen`、`$.sections.edge_loop.recent.snapshot.incidents[].last_seen`、`$.sections.edge_loop.recent.snapshot.written_at`、`$.sections.edge_loop.recent.source.written_at`、`$.sections.health[].source.written_at`、`$.sections.storage.source.observed_at`（いずれも注入した時刻を float の epoch 秒で写したもの。鮮度の判定結果は文字列の欄として比較に残る） |

## 4. 実行

単体試験（CI と同じ。どの CPU でも同じ）：

```sh
python -m pytest -q tests/unit/test_cross_arch_vectors.py
```

1 つのベクトルの文書を見る：

```sh
python tests/vectors/cross_arch.py --show edge.incident
```

両 CPU の突合せ（docker の `colima` と `colima-rosetta` の両 context と、コンテナ内の
`pip install` のためのネットワークが要る）：

```sh
python3 tools/cross_arch_vectors.py --python 3.12 --out report.json
```

各コンテナはこの checkout を読取り専用で mount して複製し、uid 1001・umask 022 で
ベクトルを実行する。amd64 側は `--platform linux/amd64` を付けて Rosetta 上で動かす
（付けないと colima-rosetta でも aarch64 のイメージになる）。報告は CPU ごとの
digest、両者の一致、固定値との一致を持ち、終了コードは全件が一致したときだけ 0 である。
片方の CPU で走らなかったベクトルは `null` と記録し、もう一方の値で埋めない。

## 5. 固定値を更新する手順

固定値を変えてよいのは、**製品の意味を意図して変えたとき**（判断規則・拒否コード・
監査イベントの形・説明の文言などを変える PR）と、**ベクトル自体を意図して変えたとき**
（入力や対象を足す）だけである。次の場合は更新しない。

- 片方の CPU、片方の Python の版だけで digest が変わった。これは発見であり、原因を
  調べて報告する。除外を足して通すことはしない。
- 理由が分からないまま digest が変わった。
- ベクトルを通すためだけに製品の出力を変えたくなった。

手順：

1. 変更の理由になる製品の差分（またはベクトルの差分）を先に用意する。
2. 新しい digest を計算する：`python tests/vectors/cross_arch.py`（`digests` に
   全件が出る）。変わったベクトルについて `--show` で文書を出し、変更前の文書と
   比べて、差が意図した変更だけであることを確かめる。
3. `tests/vectors/digests.json` の該当ベクトルの `sha256` を書き換え、`history` の
   末尾に `{"date", "sha256", "commit_note", "reason"}` を 1 件足す。`reason` には
   何を意図して変えたかと、どの PR・issue の変更かを書く。古い履歴は消さない。
4. `python3 tools/cross_arch_vectors.py` で両 CPU が新しい値で一致することを確かめ、
   PR 本文にその結果（一致したかどうか。digest そのものは書かない）を書く。
5. 試験（`test_each_pin_says_what_it_covers_and_why_it_last_changed`）は、履歴の
   最後の値が固定値と一致すること、理由が空でないこと、日付が古い順であることを
   確かめる。

## 6. 既知の差の扱い

このベクトルは「同じ入力に対して、判断・認可・監査の意味が同じこと」だけを比べる。
次のものは CPU によって正当に違い、**このベクトルの対象外**である（原則 5。
[ADR-0003 D7](adr/0003-arm-software-verification-profile.md#decision) と
[既知の差](adr/0003-arm-software-verification-profile.md#known-differences-and-follow-up-changes)）。

- **binary**：llama runtime、native 拡張 `_bootstrap_deadline`、wheel、Edge Core の
  binary の digest。各 module が CPU ごとに固定し、固定値の無い CPU は拒否する。
- **ABI**：LP64、`SO_PEERGROUPS` など。CPU ごとに確認済みとして記録し、未確認の CPU は
  狭い方の挙動になる。
- **性能と資源の測定値**：比べない。比べるのはスキーマと limitations の記述だけ。
- **モデルの出力**（埋め込み類似度を含む）：一致を約束しない。

また、このベクトルは CPU 間で意味が同じことを示すが、**実機で動くことは示さない**。
両 CPU ともコンテナでの実行であり、amd64 は Rosetta による変換である。

## 7. 記録

- [2026-10-29 の両 CPU の実行](evidence/cross-arch-vectors-2026-10-29.md)
