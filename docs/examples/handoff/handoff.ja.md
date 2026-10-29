# 専門家への引継ぎパッケージ

> **これは試験用 fixture から生成した例です。実在のノード・インシデントの記録ではありません。**

- インシデント: `inc-5eed0000c0ffee01`（状態: open）
- 生成時刻: 2026-10-29T05:14:00Z（ノードの時計。信頼性は §1）
- 生成者の権限区分: root（root 以外では台帳を読めず、その欄は「なし」になる）
- 送信: していない。このパッケージはローカルに保存しただけで、どこにもアップロードしていない。
- 判断と執行の権限は Edge にある。Nexus は観測・説明・助言のみ。AI の見解は事実ではない。

各欄は「観測事実」「Edge の判断」「実行結果」「AI の推測」を分けて書いている。材料がない欄は正常値で埋めず「なし」と理由を書いている。

## 1. 発生時刻と時刻の信頼性

- 発生時刻（初観測）: 2026-10-29T03:14:00Z（出典: `incident_ledger.first_seen`）
- 最終観測: 2026-10-29T03:15:00Z
- 時計の状態: `synchronized_this_boot`
- 起動後の時刻同期の記録: present（同期が一度あったことを示すだけで、今も正しいこと・時刻源の真正性は示さない）
- Knowledge の時計の床: 2026-10-29T05:00:00Z（読取済）

## 2. 観測事実（Edge の観測）

状態: あり

- 観測期間: 2026-10-29T03:14:00Z 〜 2026-10-29T03:15:00Z
- 件数: 14、最も高い重大度: 2（1 が最も重い）
- ATT&CK 技術: T1046
- 分類: Attempted Information Leak、プロトコル: tcp

| 時刻 | 遷移 | 件数 | 重大度 | 証拠保存 |
| --- | --- | --- | --- | --- |
| 2026-10-29T03:14:00Z | opened | 1 | 3 | あり |
| 2026-10-29T03:15:00Z | updated | 14 | 2 | **なし** |

伏せた欄: 送信元アドレス、ルール番号、宛先ポート、シグネチャ本文。

## 3. Edge の判断（決定論的規則による would）

状態: あり
- 最新: Edge なら **redirect** する（規則: `severity_high_redirect_to_decoy`）。**実行されていない**。

## 4. 自動対処・期限・解除（実行結果）

- 実行結果: **実行なし**（`nexus_accepts_observe_only`）。Nexus は observe-only の事象だけを受け付ける。
- throttle: would（未実行）。期限: なし、リース: 該当なし、解除: 該当なし（未実行のため）
- redirect: would（未実行）。期限: なし、リース: 該当なし、解除: 該当なし（未実行のため）

## 5. AI の見解（推測。事実ではない）

状態: あり
- モデルの識別: なし（`model_identity_not_recorded_in_explanation_ledger`）
- 現在の M.I.O. 経路の能力: なし（理由: `snapshot_unavailable`）
- 外部（リモート）AI: インシデント説明では使っていない
- 注意: 説明器はローカル経路の回答をすべて「AI の助言」と区分する。モデルが文章を生成したのか、決定論的な照合で答えたのかは記録されていない（`generation_method: not_recorded`）。

### 2026-10-29T03:14:30Z — 経路 `local`（説明器の区分では AI の助言: AI advice \(local model\)）

> 決定論的な照合による候補の提示です。結論ではありません。重要な判断は担当者が根拠を確認してから行ってください。

### 2026-10-29T03:16:00Z — 経路 `local`（説明器の区分では AI の助言: AI advice \(local model\)）

> 決定論的な照合による候補の提示です。結論ではありません。重要な判断は担当者が根拠を確認してから行ってください。

## 6. 業務影響

- 評価: なし（`business_impact_not_assessed_by_node`）。担当者が専門家へ直接伝える。
- 通信の観測: なし（理由: `noc_snapshot_unavailable`）
- Nexus 経由で実行した通信制限: 0 件

## 7. 証拠参照（digest のみ）

状態: 一部のみ（理由: `evidence_not_stored`）。生データは含めていない。
- first: `sha256:1111111111111111111111111111111111111111111111111111111111111111`（2026-10-29T03:14:00Z）
- latest: `sha256:2222222222222222222222222222222222222222222222222222222222222222`（2026-10-29T03:15:00Z）

## 8. Knowledge の出典・世代・鮮度

状態: あり
- 現在の Knowledge Lite: 読取済 世代 8、鮮度 `current`
- T1046 Network Service Discovery: 世代 7、参照時の鮮度 `current`、参照時刻 2026-10-29T03:14:30Z、bundle `sha256:abababababababababababababababababababababababababababababababab`、**現在の世代と異なる**

## 9. 担当者の操作（監査記録）

状態: あり
- このインシデントに対する担当者の承認・確認の記録: なし（Nexus にその記録種別がない）
- 対象期間 2026-10-29T02:14:00Z 〜 2026-10-29T05:14:00Z のノード操作（操作者名は伏字）:
  - 2026-10-29T02:50:00Z `activation.unit_granted`

## 10. 未確認事項

- Edge の判断（would）が妥当かは人が確認していない（`edge_judgement_unreviewed`）
- 証拠の中身（生データ）は含めていない。必要なら digest で現地に依頼する（`evidence_content_not_included`）
- 業務影響はノードでは評価していない。担当者が直接伝える（`business_impact_not_assessed`）
- 送信元アドレス・ルール番号・宛先ポートは伏せている（`source_address_withheld`）
- AI の見解は推測であり検証されていない（`ai_advice_unverified`）
- 一部の証拠は保存されていない（容量上限）（`evidence_not_stored`）
- 引用した Knowledge の世代は現在の世代と異なる（`knowledge_superseded`）
- インシデントはまだ閉じていない（生成後も続く可能性がある）（`incident_open`）

## 11. 機密の扱い

既定で抑制している。秘密情報・生 payload・内部識別情報（IP・MAC・インターフェース名・経路・操作者名）は含めない。自由文中の該当形式は `[伏字:種別]` に置換した。

抑制した件数（合計 9）:
- `network_address`: 2
- `rule_identifier`: 2
- `service_port`: 2
- `producer_free_text`: 2
- `operator_identity`: 1
- 読んでいないもの: `edge_evidence_payloads`、`decoy_evidence`、`commissioning_record`、`secrets_directory`、`interface_identity`、`torn_tail_quarantine`

## 12. 読んだ情報源

| 情報源 | 状態 | 理由 | 読める権限 |
| --- | --- | --- | --- |
| `recent_incidents_snapshot` | read |  | operator |
| `explainer_status_snapshot` | read |  | operator |
| `intake_status_snapshot` | read |  | operator |
| `knowledge_status_snapshot` | read |  | operator |
| `mio_status_snapshot` | unavailable | absent | operator |
| `noc_status_snapshot` | unavailable | absent | operator |
| `incident_ledger` | read |  | root |
| `explanation_ledger` | read |  | root |
| `audit_chain` | read |  | root |
| `timesyncd_marker` | read |  | everyone |
| `knowledge_clock_floor` | read |  | root |
