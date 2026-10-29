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

1. 試験の実行ごとにラボ鍵（Ed25519、5 本）を生成する。seed は権限 0700 の一時ディレクトリ
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
   bundle で取り出した member が食い違えば、終了コードは 1。

実行例（Knowledge の clone は読取専用でよい。Knowledge の中核依存
PyYAML・idna・PyNaCl が要る）：

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

## 4. 結果（Azazel-Knowledge 2445c1b）

実行環境：colima 上の Linux コンテナ（python:3.12）。aarch64（既定 context）と
x86_64（colima-rosetta、`--platform linux/amd64`）の両方で実行し、表はバイト単位で
同じだった。実機・VM の結果ではない。

42 件のうち、**一致 27 件・不一致 15 件**。全件が記録値どおり。両方が受理した 5 件
（valid、expired、rollback_advances、threshold2_both_hold_role、
member_eight_components）は、取り出した member の digest も一致した。

### 4.1 一致したもの

本番相当の anchor での通常受理（`valid`）、期限切れの指標を含む bundle の受理
（`expired`。期限は読取側の判断で、gate ではない）、署名者の役割違い・役割なし・
未知の鍵・失効した鍵、threshold 2、security epoch（低い・欠落・bool）、export policy
（不受理・欠落）、anti-rollback、format、署名の改ざん、中身の改ざん、切り詰め、member の
欠落・未宣言・重複・symlink・`..`・9 階層。

### 4.2 この PR で Nexus を直したもの（Nexus が緩かった）

| ケース | 修正前の Nexus | Knowledge | 根拠と修正 |
|---|---|---|---|
| `threshold2_one_holds_role`（threshold 2、署名 2 本のうち必要な役割を持つのは 1 本） | 受理 | `BUNDLE_SIGNER_ROLE_NOT_PERMITTED` | Knowledge は「役割を持つ署名者の数 ≥ threshold」を求める（`verify.py` `_check_signer_role`）。ADR-0015 D5b は、別の目的の鍵の署名は threshold を満たしても拒否するとしている。Nexus は役割を持つ署名者が 1 人いれば通しており、別の目的の鍵で threshold を埋められた。Nexus を Knowledge と同じ数え方に直した |
| `member_nine_components`（`tables/a/b/c/d/e/f/g/x.jsonl`） | 受理 | `BUNDLE_MEMBER_PATH_TOO_DEEP` | 両者とも上限は 8。Knowledge は成分の数を数え、Nexus は区切りの数を数えていたため、Nexus は 1 階層深くまで通していた。成分の数に直した（8 成分は両方とも受理） |

### 4.3 残る差（直していない）

「厳しい側」は拒否した側。どちらが正しいかの判断と、提案を書く。

| ケース | Knowledge | Nexus | 厳しい側 | 判断 |
|---|---|---|---|---|
| `threshold0_bad_signature`（anchor が threshold = 0、署名は壊れている） | **受理** | `ANCHORS_INVALID` | Nexus | Nexus が正しい。Knowledge は `int(doc.get("threshold", 1))` をそのまま使うため、threshold 0 の anchor では有効な署名が無くても受理する（役割の gate も「0 ≥ 0」で通る）。Knowledge 側の修正候補（K8） |
| `kind_differential` | 受理 | `BUNDLE_KIND_UNSUPPORTED` | Nexus | 設計上の差。Lite は full のみ（ADR-0017）。Knowledge の検証器は full ノード用の差分 bundle も扱う |
| `version_string`（`"2"`）、`version_boolean`（`true`） | 受理 | `BUNDLE_VERSION_INVALID` | Nexus | Nexus が正しい。Knowledge は `int()` で変換する。Knowledge の builder は整数を出し、Knowledge 自身の epoch の gate は整数以外を拒否している。Knowledge 側の修正候補（K9） |
| `member_name_214_bytes` | 受理 | `BUNDLE_MEMBER_NAME_TOO_LONG` | Nexus | 上限の違い（Nexus 200 文字、Knowledge 1024 バイト）。builder が出す名前は 30 バイト前後で、どちらにも届かない。実害なし |
| `member_component_296_bytes`（1 成分が 255 バイト超） | `BUNDLE_ARCHIVE_UNREADABLE` | `BUNDLE_MEMBER_NAME_TOO_LONG` | 両方拒否 | コードだけが違う。Knowledge の 1024 バイトの上限は 1 成分の長さを抑えないので、staging への書込みでファイルシステムの NAME_MAX に当たり、その OSError が `BUNDLE_ARCHIVE_UNREADABLE` として出る。Knowledge の docstring が目指す「自分の語彙で拒否する」に反する（K10） |
| `members_over_64` | 受理 | `BUNDLE_TOO_MANY_MEMBERS` | Nexus | 上限の違い（Nexus 64、Knowledge 256）。builder が出すのは最大 14。Knowledge のスキーマが 60 表を超えるまでは実害なし |
| `ratio_over_100`（4 MiB のゼロ） | `BUNDLE_DECOMPRESSION_BOMB` | 受理 | Knowledge | Knowledge は展開率 100:1 も上限にする。Nexus は絶対量（member 256 MiB、合計 1 GiB）だけ。Nexus はメモリ上で読むので、上限は絶対量の方が効く。採否はオーナー判断 |
| `manifest_not_first` | `BUNDLE_MANIFEST_MISSING` | 受理 | Knowledge | 形式の定義は Knowledge にあり、manifest.json と manifest.sig を先頭 2 つに置く。Nexus は全 member を読んでから判定するので順序に依存しないが、形式に合わない bundle を通している。Nexus 側で拒否するかはオーナー判断 |
| `manifest_pretty_signed_canonical`（manifest は整形、署名は正準形に対して） | 受理 | `BUNDLE_SIGNATURE_THRESHOLD_NOT_MET` | Nexus | 署名の対象の定義が違う。Knowledge は `canonical(json.loads(raw))` を検証し、Nexus は raw の bytes を検証する |
| `manifest_pretty_signed_raw`（manifest は整形、署名も整形した bytes に対して） | `BUNDLE_SIGNATURE_THRESHOLD_NOT_MET` | **受理** | Knowledge | 上と同じ差の逆向き。Knowledge が決して出さない bundle を Nexus が受理する。**オーナー判断（下記）** |
| `manifest_shadows_trust`（manifest に `trust`） | `BUNDLE_SHADOWS_TRUST_ANCHOR` | 受理 | Knowledge | 禁止する manifest の欄の一覧が違う。Knowledge は `anchors`・`trust` と rollback 状態の欄（`last_import_at` ほか）も禁止する |
| `manifest_shadows_key_roles`（manifest に `key_roles`） | 受理 | `BUNDLE_SHADOWS_TRUST_ANCHOR` | Nexus | 上の逆。Nexus は `key_roles`・`required_signer_role`・`minimum_security_epoch`・`accepted_export_policy_digests` も禁止する。両方の和集合にするのが自然（K11 と Nexus の両方） |
| `manifest_local_tier_table`（`tables/reaction.jsonl`） | `BUNDLE_TOUCHES_LOCAL_TIER` | 受理 | Knowledge | Knowledge のローカル層の表（ノード自身の記録）を名乗る bundle。Nexus にはローカル層が無く、読む表だけを使うので害は無いが、誤って作られた bundle を見逃す |
| `signature_33_lines` | 受理 | `BUNDLE_SIGNATURE_MALFORMED` | Nexus | Nexus は manifest.sig を 32 行に制限する |

### 4.4 オーナー判断

1. **署名の対象（正準形）**：Nexus の検証器も「raw の bytes が Knowledge の正準形と一致する
   こと」を求めるべきか。求めれば `manifest_pretty_signed_raw` を拒否し、両方向とも
   厳しい側にそろう。ただし Nexus の既存試験（`test_lite_bundle.py`、共通試験ベクトル
   `knowledge_lite.refusals` など）は `indent=2` の manifest に署名しており、Knowledge の
   検証器ではすべて拒否される形である。直すと試験とベクトルの digest を大きく作り直す
   ことになるため、この PR では直していない。
2. **形式の順序**（`manifest_not_first`）と**展開率**（`ratio_over_100`）、**禁止欄の和集合**、
   **ローカル層の表名**を Nexus でも拒否するか。
3. Knowledge 側への修正提案：K8（threshold 0 の anchor を拒否）、K9（`bundle_version` を
   整数に限る）、K10（1 成分の長さの上限）、K11（禁止欄に Nexus の 4 欄を足す）。
   調査 c の K1〜K7 に続く番号。Knowledge リポジトリはこの作業では変更していない。

## 5. 記録の更新

`lite_bundle.py` を変えたとき、または Knowledge の pin を上げたときは、ローカルで道具を
実行し、`EXPECTED` と `DIVERGENCES` と §4 を同じ PR で更新する。不一致の各行には、
どちらが厳しいかと根拠を書く（`test_every_divergence_says_which_side_and_why`）。
