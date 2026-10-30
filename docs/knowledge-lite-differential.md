# Knowledge Lite 検証器の差分試験（Knowledge と Nexus）

Azazel-Knowledge が `build-lite` で作った bundle を、Knowledge 自身の検証器
（`azazel_knowledge.bundle.verify.verify_bundle`）と Nexus の検証器
（[`lite_bundle.verify_bundle`](../src/azazel_nexus/lite_bundle.py)）に並べて判定させ、
受理・拒否と拒否コードを比べる。道具は
[`tools/knowledge_lite_differential.py`](../tools/knowledge_lite_differential.py)、
CI で回る部分は
[`tests/unit/test_knowledge_lite_differential.py`](../tests/unit/test_knowledge_lite_differential.py)。

## 1. 何を確かめるか

[`contract/azazel-knowledge-lite/`](../contract/azazel-knowledge-lite/) の公開 fixture は、
Nexus が Knowledge の生成物を読めることを示す。しかし次の 2 点は示さない。

- 二つの**検証器**が同じ判定をすること。
- 本番相当の anchor で読めること。fixture の `anchors.toml` は鍵と threshold だけで、
  `key_roles`・`required_signer_role`・`minimum_security_epoch`・
  `accepted_export_policy_digests` を持たない。

この試験では、本番相当の anchor（上の 4 つをすべて設定する）を使い、Knowledge が作った
bundle と、それを変えた bundle を両方の検証器で判定する。

## 2. 手順

1. 試験の実行ごとにラボ鍵（Ed25519、6 本）を生成する。seed は権限 0700 の一時ディレクトリ
   の中で権限 0600 のファイルにだけ書き、`build-lite` に `--sign-key` として渡す。終了時に
   上書きしてから削除する。表示もしない。**公開 fixture 鍵は使わない**。
2. Knowledge 自身の `tools/lite_fixture.py` の行生成（`_write_source_db`）で元 DB を作る。
   Knowledge 自身の `tools/bundle_build.py build-lite` で、署名者の組合せごとの bundle、
   security epoch が最小値より低い bundle、指標が期限切れの bundle を作る。export policy は
   Knowledge の既定 `config/lite-export-policy.yaml`。
3. 各ケースを、Knowledge の検証器（別プロセス、`python -I`）と Nexus の検証器で判定する。
   署名より後の gate を試すケースは、manifest を変えてからラボ鍵で署名し直す
   （Knowledge と同じ正準形の bytes に署名する）。
4. 両方の判定を `EXPECTED`（記録値）と比べる。記録と違う判定、または両方が受理した
   bundle で取り出した member が食い違えば、終了コードは 1。記録値を測った Knowledge の
   commit は `KNOWLEDGE_REVISION`（現在 `09d234c`）。別の commit で実行すると、その旨を
   標準エラーに出す（拒否はしない。新しい Knowledge で何が変わるかを見るのが目的のため）。
5. 「記録どおり」は合格条件の半分でしかない。Knowledge が拒否して Nexus が受理するケースは、
   `NEXUS_LOOSER` に owner-decisions の行番号を書いたものだけを許す
   （`test_nexus_accepts_nothing_knowledge_refuses_without_an_open_owner_decision`）。
   新しくそういう差が出たら、Nexus を直すか判断の行を作るまで CI が落ちる。

実行例（Knowledge の clone は読取専用でよい。Knowledge の中核依存
PyYAML・idna・PyNaCl が要る）。子プロセスはすべて `python -I -B` で動かすので、
Knowledge の clone には `__pycache__` も書かない。作業ディレクトリ（ラボ鍵の seed を
一時的に置く、権限 0700）は `--work-dir` の下に作る。指定しなければ Python の
`tempfile` の既定（`$TMPDIR`、無ければ `/tmp`）になる。共有の `/tmp` を避けたいときは
`--work-dir` か `TMPDIR` で、自分だけが使う場所を指定する：

```sh
docker run --rm -v "$PWD":/src:ro -v /path/to/Azazel-Knowledge:/k:ro python:3.12 bash -c '
  cp -r /src /w && cd /w &&
  python -m pip install -q -e ".[dev]" -e ./runtime pyyaml idna &&
  python tools/knowledge_lite_differential.py --knowledge /k'
```

## 3. CI での扱い（決定）

Azazel-Knowledge は private リポジトリで、Nexus の CI から取得できない。生成物を
vendor する案（ラボ鍵で署名した bundle と anchor をリポジトリに置く）は採らない。
秘密鍵を破棄しても、その公開鍵を持つ anchor がリポジトリに残り、本番の読取側が誤って
pin する経路ができるからである（守る設計 6：ラボの鍵を本番と分ける）。

そこで次のように分ける。

| 部分 | どこで | 何を |
|---|---|---|
| Knowledge の列（Knowledge の検証器の判定） | ローカル専用。`--knowledge` を付けて道具を実行 | 実 Knowledge の `build-lite` と `verify.py` を使う。記録値と違えば失敗 |
| Nexus の列（Nexus の検証器の判定） | CI（単体試験）と道具の両方 | CI では、Knowledge が出力した `contract/azazel-knowledge-lite/lite.tar.gz` と `negative/expired.tar.gz` の manifest と中身をそのまま使い、署名だけを試験中に作った鍵で付け直す。同じケース一覧を Nexus だけで判定し、記録された Nexus の列と比べる |

`--nexus-only` を付けると、CI と同じ判定を道具からも実行できる。Knowledge 側の更新
（新しい gate、コードの変更）は CI では検出できない。Knowledge の pin を上げるとき、
または `lite_bundle.py` を変えるときに、ローカルで道具を実行して記録値を更新する。

## 4. 結果（Azazel-Knowledge 09d234c、#110 のマージ）

実行環境：colima 上の Linux コンテナ（python:3.12、uid 1001）。aarch64（colima-rosetta
context の `--platform linux/arm64`、ネイティブ）と x86_64（同 context の
`--platform linux/amd64`、Rosetta による変換）の両方で実行し、表は同じだった。
実機・VM の結果ではない。

52 件のうち、**一致 41 件・不一致 11 件**。全件が記録値どおり（`not_as_recorded=0`）。
両方が受理した 5 件（valid、expired、rollback_advances、threshold2_both_hold_role、
member_eight_components）は、取り出した member の digest も一致した。不一致 11 件のうち
4 件は両方とも拒否してコードだけが違うもの、6 件は Nexus だけが拒否するもの、1 件
（`manifest_pretty_signed_raw`）が Knowledge だけが拒否するもの。

### 4.0 Knowledge #110 で何が変わったか

この試験の道具を、変更前の Nexus（main `2322468`）のまま Knowledge `09d234c` に向けると
`not_as_recorded=8` になる（`2445c1b` では 0）。8 件の内訳と処置：

| ケース | 2445c1b での Knowledge | 09d234c での Knowledge | 原因 | 処置 |
|---|---|---|---|---|
| `threshold0_bad_signature` | **受理** | `BUNDLE_ANCHORS_THRESHOLD_INVALID` | K8：threshold は 1 以上の整数（bool 不可） | 記録値を更新。両方拒否、コードだけが違う |
| `version_string`、`version_boolean` | 受理 | `BUNDLE_VERSION_INVALID` | K9：`bundle_version` は 1 以上の整数 | 記録値を更新。一致 |
| `member_component_296_bytes` | `BUNDLE_ARCHIVE_UNREADABLE` | `BUNDLE_MEMBER_COMPONENT_TOO_LONG` | K10：1 成分 255 UTF-8 バイトまで | Nexus にも同じ上限と同じコードを入れた（§4.2）。一致 |
| `manifest_shadows_key_roles` | 受理 | `BUNDLE_SHADOWS_TRUST_ANCHOR` | K11：禁止欄に Nexus の 4 欄を足した | 記録値を更新。一致 |
| `signer_revoked`、`threshold2_one_signature`、`threshold2_one_holds_role` | 本来の gate で拒否 | `BUNDLE_ANCHORS_THRESHOLD_INVALID` | Knowledge は読込み時に「失効していない、必要な役割を持つ鍵の数 < threshold」の anchor を拒否するようになった。道具の anchor はちょうどその形だった（役割を持つのは A だけ） | 道具の anchor に、役割を持ち何にも署名しない予備の鍵 F を足し、3 件とも本来の gate（失効署名者・署名数不足・役割不足）で拒否されることを両側で確かめた。元の形の anchor は `anchor_revoked_leaves_no_role_holder`・`anchor_role_holders_below_threshold` として残した（§4.3） |

あわせて足したケース：`version_zero`、`base_version_string`（K9 の版の規則）、
`member_component_276_utf8_bytes`（96 文字で Nexus の 200 文字上限には収まるが成分は
276 バイト）、`signature_not_second`、`manifest_shadows_rollback_state`、
`manifest_local_tier_file_only`（`tables` には書かず member の path だけでローカル層の表を
名乗る）。

### 4.1 一致したもの

本番相当の anchor での通常受理（`valid`）、期限切れの指標を含む bundle の受理
（`expired`。期限は読取側の判断で、gate ではない）、署名者の役割違い・役割なし・
未知の鍵・失効した鍵、threshold 2（署名 1 本、役割を持つ署名者 1 本、両方が役割を持つ）、
security epoch（低い・欠落・bool）、export policy（不受理・欠落）、anti-rollback、format、
`bundle_version`（文字列・bool・0）と `base_version`（文字列）、署名の改ざん、中身の改ざん、
切り詰め、member の欠落・未宣言・重複・symlink・`..`・9 階層・成分長（ASCII 296 バイト、
UTF-8 276 バイト）、展開率、member の順序（manifest が先頭でない、署名が 2 番目でない）、
禁止欄（`trust`・`key_roles`・`last_import_at`）、ローカル層の表名（`tables` と member の
path の両方）。

### 4.2 この PR で Nexus を Knowledge に揃えたもの（委任された技術判断）

いずれも「Knowledge の検証器が拒否し、Nexus が受理していた」か「同じものをコードを
変えて拒否していた」差である。Knowledge が形式の持ち主であり（Nexus は形式を発明
しない）、Knowledge の builder が出す bundle はすべてこれらを満たすので、揃えて失う
互換性は無い。

| 規則 | 変更前の Nexus | 変更後（Knowledge と同じ） | 安全性・互換性の判断 |
|---|---|---|---|
| 禁止欄 | `threshold`・`keys`・`revoked`・`key_roles`・`required_signer_role`・`minimum_security_epoch`・`accepted_export_policy_digests`・`last_imported_version` | 和集合。`anchors`・`trust`・`last_import_at`・`last_bundle_sha256`・`needs_full_rebaseline` を足した | 信頼と取込み状態は anchor とノードの状態だけが決める。Nexus はこれらの欄を読まないので受理しても害は無かったが、名乗ろうとした bundle は報告に値する（既存の方針）。Knowledge #110 も Nexus の 4 欄を足して和集合になった |
| `bundle_version` | 整数（bool 不可）。0 以下は巻戻しとして `BUNDLE_VERSION_REGRESSION` | 1 以上の整数。0 以下も `BUNDLE_VERSION_INVALID` | 拒否は変わらず、理由が正しくなる（版が壊れているのであって古いのではない） |
| `base_version` | 読まない（Lite は full のみ） | null か 1 以上の整数。それ以外は `BUNDLE_BASE_VERSION_INVALID` | Nexus は今後も適用しない。Knowledge が壊れた manifest として拒否するものを受理しない |
| path 成分の長さ | 名前全体 200 文字だけ。多バイト文字なら 1 成分 255 バイト超も通った | 1 成分 255 UTF-8 バイトまで、`BUNDLE_MEMBER_COMPONENT_TOO_LONG`。名前全体より先に検査する | Nexus は disk に展開しないので NAME_MAX に当たる害は無いが、Knowledge が拒否する名前を受理しない。先に検査するのでコードも一致する |
| member の順序 | 順序を見ない | `manifest.json`・`manifest.sig` が先頭 2 つでなければ `BUNDLE_MANIFEST_MISSING` | Nexus は全 member を読んでから判定するので順序は安全性に関わらない。形式を一つにするため（M14） |
| ローカル層の表名 | 見ない | `tables` か `tables/<t>.jsonl`・`deltas/<t>.jsonl` がローカル層の表（Knowledge の `LOCAL_TIER_TABLES` の 14 表）を名乗れば `BUNDLE_TOUCHES_LOCAL_TIER` | Nexus にローカル層は無く読む表しか使わないので害は無いが、誤って作られた bundle を見逃さない（M14）。表の一覧は Knowledge の写しで、ずれはこの道具で検出する |

変更前の Nexus でこれらのケースがどう判定されたかは、§4.0 とこの PR の本文に記録した。

以前の PR（#379）で直したもの：`threshold2_one_holds_role`（役割を持つ署名者の数を
threshold と比べる）、`member_nine_components`（成分の数で数える）、`ratio_over_100`
（署名の検証より前に展開しながら打ち切る）、`manifest_bom_signed_raw`（BOM を拒否）。

### 4.3 残る差と判断

「厳しい側」は拒否した側。「判断」はどちらが正しいかと、どちらかを変えるか。

| ケース | Knowledge | Nexus | 厳しい側 | 判断 |
|---|---|---|---|---|
| `anchor_revoked_leaves_no_role_holder`（threshold 1、唯一の役割保持者 A を失効） | `BUNDLE_ANCHORS_THRESHOLD_INVALID` | `BUNDLE_REVOKED_SIGNER` | 両方拒否 | どちらも安全（どの bundle も受理されない）。Knowledge は anchor を読込み時に拒否し、`azctl keys` がそもそも書かせない。Nexus は anchor を読めるままにして bundle ごとに拒否する。**Nexus は揃えない**：Nexus では失効受理や repin が既存の anchor を読んで置き換えるので、満たせない anchor を読込みで拒否すると、復旧の入口（repin）まで塞ぐおそれがある。満たせない anchor を作らせない検査は、書く側（trust-enroll・repin、#390 の範囲）に置くのが筋で、そこで扱う |
| `anchor_role_holders_below_threshold`（threshold 2、役割保持者は A だけ） | `BUNDLE_ANCHORS_THRESHOLD_INVALID` | `BUNDLE_SIGNER_ROLE_NOT_PERMITTED` | 両方拒否 | 上と同じ。Nexus の役割の gate は役割保持者の数を threshold と比べるので、別の目的の鍵で threshold を埋めることはできない |
| `threshold0_bad_signature` | `BUNDLE_ANCHORS_THRESHOLD_INVALID` | `ANCHORS_INVALID` | 両方拒否 | K8 で Knowledge が Nexus と同じ判断になった。コードだけが違う。Nexus の `ANCHORS_INVALID` は anchor の不正すべてに使う既存のコードで、運用手順と監査の語彙なので変えない |
| `kind_differential` | 受理 | `BUNDLE_KIND_UNSUPPORTED` | Nexus | 設計上の差。Lite は full のみ（ADR-0017）。Knowledge の検証器は full ノード用の差分 bundle も扱う。どちらも正しい |
| `member_name_214_bytes` | 受理 | `BUNDLE_MEMBER_NAME_TOO_LONG` | Nexus | 資源の上限の違い（Nexus 200 文字、Knowledge 1024 バイト）。builder が出す名前は 30 バイト前後で、どちらにも届かない。小さな機器で動く読取側が厳しいのは妥当で、互換性の害は無い。変えない |
| `members_over_64` | 受理 | `BUNDLE_TOO_MANY_MEMBERS` | Nexus | 同じく上限の違い（Nexus 64、Knowledge 256）。builder が出すのは最大 14。Knowledge のスキーマが 60 表を超えたら Nexus の上限を見直す（この道具で検出できる） |
| `signature_33_lines` | 受理 | `BUNDLE_SIGNATURE_MALFORMED` | Nexus | 同じく上限（Nexus は manifest.sig を 32 行まで）。Knowledge の anchor が 32 本を超える鍵を持つことは想定されていない。変えない |
| `manifest_pretty_signed_canonical`（manifest は整形、署名は正準形に対して） | 受理 | `BUNDLE_SIGNATURE_THRESHOLD_NOT_MET` | Nexus | 署名の対象の定義が違う（M13）。Knowledge は `canonical(json.loads(raw))` を検証し、Nexus は raw の bytes を検証する。Knowledge の builder は正準形の bytes をそのまま書くので、実際の bundle では差は出ない |
| `manifest_pretty_signed_raw`（manifest は整形、署名も整形した bytes に対して） | `BUNDLE_SIGNATURE_THRESHOLD_NOT_MET` | **受理** | Knowledge | 上と同じ差の逆向き。**安全性**：Nexus は自分が解析した bytes そのものへの署名を確かめるので、署名されていない内容を読むことはない（真正性の穴ではない）。受理するのは、正しい鍵で署名されているが Knowledge の builder が決して書かない形の manifest だけ。**互換性**：Knowledge の検証器はこれを拒否するので、Nexus が受理する集合のほうが広い。揃えるなら Nexus が「raw の bytes が正準形と一致する」ことを求める側で、Nexus の試験と共通試験ベクトル（`indent=2` の manifest に署名している）を作り直す別の PR になる。**M13 として開いたまま**（`NEXUS_LOOSER`） |
| `manifest_bom_signed_raw` | `BUNDLE_SIGNATURE_THRESHOLD_NOT_MET` | `BUNDLE_MANIFEST_INVALID` | 両方拒否 | コードだけが違う。Nexus は manifest を BOM なしの厳密な UTF-8 として読む |
| `manifest_bom_signed_canonical` | 受理 | `BUNDLE_MANIFEST_INVALID` | Nexus | Knowledge は読み直した正準形で署名を確かめるので通す。Knowledge の builder は BOM を書かない。M13 で正準形を要求すれば、両側とも同じ理由で拒否する形になる |

### 4.4 委任された技術判断と残る論点

[owner-decisions](owner-decisions.md) の M13〜M15 は、2026-10-30 に委任された技術判断として
次のとおり扱った（区分 T。オーナーの追加判断は要らない）。

1. **M14（順序・展開率・禁止欄の和集合・ローカル層の表名）**：すべて Nexus でも拒否する
   ようにした（§4.2。展開率は #379 で対応済み）。
2. **M15（Knowledge への修正提案 K8〜K11）**：Knowledge #110（`09d234c`）で 4 件とも
   実装された。この PR で記録値をそれに合わせ、K10 の成分長は Nexus にも入れた。
3. **M13（署名の対象を正準形に限るか）**：残る唯一の「Nexus が緩い」差。真正性の穴では
   ないので急がないが、方向は「Nexus が raw の bytes が正準形と一致することを求める」に
   決める（形式の持ち主は Knowledge で、受理する集合を一つにするため）。試験と共通試験
   ベクトルの作り直しを伴うので、別の PR で行う。それまでは `NEXUS_LOOSER` に残す。
4. 満たせない anchor（§4.3 の上 2 行）の検査は、読込み側ではなく書く側（trust-enroll・
   repin）で行う。#390 の範囲なので、この PR では足していない。

## 5. 記録の更新

`lite_bundle.py` を変えたとき、または Knowledge の新しい commit に合わせるときは、ローカルで
道具を実行し、`EXPECTED`・`DIVERGENCES`・`NEXUS_LOOSER`・`KNOWLEDGE_REVISION` と §4 を
同じ PR で更新する。不一致の各行には、どちらが厳しいかと根拠を書く
（`test_every_divergence_says_which_side_and_why`）。Knowledge が拒否して Nexus が受理する
差は、owner-decisions の行が無ければ CI が通らない。

公開 fixture（`contract/azazel-knowledge-lite/`）の source revision は `2445c1b` のまま。
Knowledge #110 は builder の引数の検査を厳しくしただけで、fixture の生成器
（`tools/lite_fixture.py`）とその出力は変わっていない。
