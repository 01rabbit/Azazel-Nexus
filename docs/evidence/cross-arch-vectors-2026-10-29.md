# 共通試験ベクトルの CPU 間突合せ — 2026-10-29

**コンテナでの実行：実機ではない。** aarch64 は colima の VM（Apple Silicon 上）の
コンテナ、amd64 は colima-rosetta の Rosetta 2 による x86_64 変換のコンテナである。
ADR-0003 D6 のとおり、amd64 側は「エミュレーション」であって amd64 ホストでの実行
ではない。実機の x86_64・実機の Arm ではどのベクトルも**未実行**。HG の証跡には使わない。

手順と比較条件は [共通試験ベクトル](../cross-arch-vectors.md)。記録の原本は
[`cross-arch-vectors-2026-10-29/`](cross-arch-vectors-2026-10-29/) の JSON 3 件
（`azazel-nexus/cross-arch-vectors/v1`、`tools/cross_arch_vectors.py --out` の出力）。

## 条件

| 項目 | aarch64 | amd64 |
| --- | --- | --- |
| 実行場所 | docker context `colima`、`--platform linux/arm64` | docker context `colima-rosetta`、`--platform linux/amd64`（Rosetta 2 による変換） |
| イメージ | 公式 `python:3.11`・`python:3.12`・`python:3.13`（Debian） | 同じタグの linux/amd64 版 |
| 導入 | checkout を `--mount type=bind`（読取り専用）で mount して複製。試験の依存は `uv.lock` から `uv export --frozen` → `pip install --require-hashes --no-deps`（uv 0.9.5）、本体は `pip install --no-deps -e .`、runtime は `pip install -e ./runtime` | 同じ |
| 実行ユーザー | uid 1001（`su ci -c "umask 022; ..."`） | 同じ |
| commit | `1173852`（worktree clean。#371 のレビュー指摘への対応後に再実行） | 同じ |
| 実行時刻 | 2026-10-29T00:24Z〜00:25Z（UTC） | 同じ |

## 結果

| Python | aarch64 | amd64 | 13 ベクトルの CPU 間一致 | 固定値との一致 |
| --- | --- | --- | --- | --- |
| 3.11 | 3.11.18（`cpython-311-aarch64-linux-gnu`） | 3.11.18（`cpython-311-x86_64-linux-gnu`） | 13/13 | 13/13 |
| 3.12 | 3.12.16（`cpython-312-aarch64-linux-gnu`） | 3.12.16（`cpython-312-x86_64-linux-gnu`） | 13/13 | 13/13 |
| 3.13 | 3.13.17（`cpython-313-aarch64-linux-gnu`） | 3.13.18（`cpython-313-x86_64-linux-gnu`） | 13/13 | 13/13 |

- 13 ベクトル（`edge.intake`、`edge.incident`、`edge.explain`、`knowledge_lite.verify`、
  `knowledge_lite.refusals`、`knowledge_lite.lookup`、`revocation`、`signature.ed25519`、`audit.chain`、
  `status.read_model`、`platform_profile.selection`、`mio.route`、`mio.consent`）の
  digest は、6 通りの組合せ（2 CPU × 3 版）ですべて同じだった。不一致は無い。
- 片方の CPU の実行が失敗した組合せは無い（`failed_runs` は 3 件とも空）。
- 最初の実行（commit `2330436`、12 ベクトル）でも全件一致していた。この記録はレビュー指摘
  への対応（`knowledge_lite.refusals` の追加と `audit.chain` の拡張）後の再実行で上書きした。
- 3.13 は、取得したイメージの patch 版が CPU で違った（3.13.17 と 3.13.18）。digest は同じ。
- 実行ユーザーによる差：開発中に root（uid 0）でも実行し、同じ digest になった
  （この記録の JSON は uid 1001 の実行だけ）。

## これが示すこと・示さないこと

- 示すこと：同じ入力に対して、Edge の取り込み・incident・説明要求、Knowledge Lite の
  検証と参照、失効、Ed25519 の検証、監査チェーン、status の read model、platform
  profile の選択、M.I.O. の経路判定と同意ゲートの出力が、aarch64 と x86_64（Rosetta）
  の CPython 3.11〜3.13 でバイト単位で同じであること。
- 示さないこと：実機での動作、性能、binary・ABI の差（[既知の差の扱い](../cross-arch-vectors.md#6-既知の差の扱い)）、
  ベクトルが含まない経路（埋め込み類似度、時間に依存する M.I.O. の処理など。
  [除外一覧](../cross-arch-vectors.md#除外注入したものの一覧)）。
