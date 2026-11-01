# 契約表

Status: **現状の一覧（2026-10-29、main `331657a` 時点）。** Nexus と、Edge・Fabric・
Knowledge（Lite と本体）・操作 UI・M.I.O. の間にある契約を、コードから拾って並べた
もの。各行の根拠はファイル名で示す。食い違いがあればコードを正とし、この表を直す。

[契約の所有](contract-ownership.md) は「どの記録を誰が定義するか」（Fabric が持つか、
Nexus のローカルか）を決める文書で、この表はそれと重ならないように、**実際に
やり取りしている形**（方向・形式・認証・失敗時の挙動・実装・試験・CPU 間の確認）を
扱う。所有の判断はあちらを正とする。

関連：[契約の所有](contract-ownership.md) ·
[共通試験ベクトル](cross-arch-vectors.md) ·
[統合ループ](integration-loop.md) ·
[オーナー判断の一覧](owner-decisions.md) ·
[実機受入手順](hardware-acceptance.md)

## 1. 読み方

- **方向**：データが流れる向き。「A → B」は A が書き、B が読む。
- **形式**：コード中の schema の文字列と版、運ぶ手段（Unix socket・ファイル・HTTP）。
  socket は `/var/lib/azazel/run/<leaf>/<名前>.sock` に置き、4 バイトの長さと JSON の
  枠（上限 64 KiB、読取りの期限 5 秒）で話す
  （`runtime/src/azazel_nexus_runtime/transport.py`、`runtime/src/azazel_nexus_runtime/runtime_paths.py`）。
- **認証と署名**：socket の相手は `SO_PEERCRED`（必要なら `SO_PEERGROUPS`）で kernel が
  渡す uid・group で判定する（`runtime/src/azazel_nexus_runtime/principal.py`）。署名は
  Ed25519 で、検証器は純 Python の `src/azazel_nexus/signature.py`。製品に署名器は無い。
- **失敗時**：fail-closed（読めない・不正なら拒否し、何も許可しない）かどうかと、
  Edge の検知・判断・証拠収集・lease 失効を止めないか（【守る設計】3）。
- **CPU 間**：[共通試験ベクトル](cross-arch-vectors.md) のどの family が、その契約の
  意味を両 CPU で固定しているか。family の無いものは「無し」と書く。
- **状態**：本番の経路で使っているか。「試験のみ」は射影や検証器があり試験済みだが、
  本番の呼出し元が無いもの。

## 2. 一覧

| # | 契約 | 方向 | 形式 | 状態 |
| --- | --- | --- | --- | --- |
| E1 | Edge の観測の取り込み | Edge Core → Nexus（intake） | Unix socket、1 接続 1 行の JSON（Edge `rust_event_engine_v1` の封筒、`azazel-edge/forward-stats/v1`） | 本番の経路（observe-only のみ受理） |
| E2 | Edge の判断の説明と表示 | intake の台帳 → 説明器 → status・UI | `azazel-nexus/incident-explain-status/v1`、`azazel-nexus/recent-incidents/v1` | 本番の経路（表示は常に「Edge would」） |
| E3 | Edge package の検証・発行元署名・失効・floor | Edge の packager → Nexus | `contract/azazel-edge-core/pin.json`、`azazel-nexus/edge-probe/v2`、署名 domain `azazel-nexus/edge-package-manifest/v1` | 検証は本番の経路。署名は実装済みで、Edge 側が未署名のため未使用 |
| F1 | Fabric の pin | Fabric → Nexus（依存） | `FABRIC_PIN` `v0.9.0rc5`（optional extra） | 採用 |
| F2 | 能力と mode の公開 | Nexus → Fabric の型 | `schema.mode.ModeState`、`view.status.StatusView` | 本番の経路（`azazel-nexus status`） |
| F3 | Edge の証拠の参照 | Nexus → Fabric の型 | `schema.evidence.EvidenceRef` | 試験のみ |
| F4 | 説明の claim | Nexus → Fabric の型 | `mio_contracts.ClaimSet`、`Claim` | 説明 ledger の中だけに保存（送らない・表示しない） |
| F5 | tested tuple | Nexus ↔ Fabric の型 | `provisioning_contracts.TestedCompatibilityTuple` | 試験のみ（記述であり admission ではない） |
| F6 | interface の識別と commissioning の記録 | Nexus → Fabric の型 | `InterfaceIdentity`、`HardwareInventory`、`CommissioningRecord` など | commissioning の経路で使用（[契約の所有 §3.4](contract-ownership.md#34-provisioning-path)） |
| K1 | Knowledge Lite の bundle | Knowledge → Nexus（ファイル） | gzip の tar（`manifest.json`・`manifest.sig`・`tables/*.jsonl`）、format 1 | 本番の経路（運用者が import） |
| K2 | Knowledge Lite の失効 | Knowledge の運用者 → Nexus（ファイル） | `revocations.signed`、domain `azazel-nexus/revocation/v1` | 本番の経路 |
| K3 | Knowledge Lite の照会 | knowledge-lited → M.I.O.・説明器・運用者 | 動詞 `knowledge.status`・`knowledge.lookup`、`KnowledgeRef`（11 欄） | 本番の経路 |
| K4 | Knowledge Lite の状態 snapshot | knowledge-lited → status・UI | `azazel-nexus/knowledge-status/v1` | 本番の経路 |
| K5 | 外部 Knowledge peer | Nexus → Knowledge 本体（HTTPS） | `azazel-nexus/knowledge-peer/1` | 試験用プロトコル。実 Knowledge と相互運用しない（§5） |
| U1 | 操作 UI | Nexus の UI → ブラウザ | `azazel-nexus/ui-model/1`（`azazel-nexus/status-view/1` と `azazel-nexus/setup/1` の allowlist） | 本番の経路（loopback のみ、installer は有効化しない） |
| U2 | 運用者向け snapshot | 各 daemon → status・UI | `azazel-nexus/mio-status/v1`、`azazel-nexus/units-status/v1`、`azazel-nexus/noc-status/v1`、`azazel-nexus/audit-status/v1`、`azazel-nexus/edge-intake-status/v1` | 本番の経路（observer の timer は有効化しない）。UI 用の同じ内容の写しを `run/ui-read/<leaf>`（`2750 <書き手>:azui`）に書く（[ADR-0007](adr/0007-ui-read-leaves.md)） |
| M1 | M.I.O. の経路、速い静的評価と参照 | 説明器・運用者 → entryd → locald・referenced・remoted | `mio.route`・`mio.advise` に加え、locald の SERVICE 専用 `mio.local.assess`。速い評価は共有 M.I.O. core と Knowledge Lite 読取 client を使い、同じ期限内の最大 250 ms を使う。結果 `fast_assistance` は deep/model answer とは別フィールドで、route selection の score/input にしない | 通常の route/handoff は維持。モデル無しの評価も処理可能。`tests/real_process/test_mio_process_integration.py` は Docker で実 UID と socket を確認 |
| M2 | 送信用の封筒 | sanitizer → remoted → 提供者 | `azazel-nexus/sanitized-envelope/2`、domain `azazel-nexus/sanitized-envelope/v1` | 実装済み。署名器と transport が無く、この build では送れない |
| M3 | 助言の応答 | 提供者・ローカルモデル → Nexus | `advisory_response`、`local_advisory` | 実装済み（実モデル・実提供者とは未接続） |
| M4 | 送信同意 | 運用者 → entryd → remoted | `azazel-nexus/mio-remote-opt-in/v1` | 実装済み（remoted は読めず拒否する。[オーナー判断 M1](owner-decisions.md#31-mio-とオンライン-ai-送信)） |
| M5 | ローカルモデルの admission | 運用者 → locald | `azazel-nexus/local-model-admission/v1` | `LOCAL_MODEL_ADMISSION_ENABLED = False` で閉じている |
| A1 | 監査への追記 | 説明器・knowledge-lited・commissiond → auditd | 動詞 `audit.append` | 本番の経路 |

## 3. 各契約の詳細

### E1 Edge の観測の取り込み

| 項目 | 内容 |
| --- | --- |
| 方向 | Edge Core → Nexus の一方向。Nexus から Edge への制御の経路は無く、何も返さない（[統合ループ](integration-loop.md)） |
| 形式 | Unix socket `edge-intake/edge-intake.sock`。1 接続 1 行の JSON（上限 16 KiB、厳密な UTF-8）。Edge の `rust_event_engine_v1` の 6 欄（`normalized`・`defense`・`enforcement`・`enforcement_status`・`source`・`pipeline`）を閉じた形で読む。転送件数の行は `azazel-edge/forward-stats/v1`（キーはちょうど 5 つ）。decoy の観測は別の socket `decoy-intake` で受け、Nexus 自身の観測として分ける |
| 認証と署名 | `SO_PEERCRED` の uid が `azedge`（decoy は `azdecoy`）であること。署名は無い。送られた値は Edge の主張として上限付きで扱い、判断に使わない |
| 失敗時 | observe-only（advisory・enforcement 無効・dry-run）以外の姿勢は `EDGE_NOT_OBSERVE_ONLY` で拒否し、固定コードで数える。過負荷は捨てて数える（`overloaded`・`queue_full`）。intake の unit は Edge に依存せず、Edge Core の unit も intake に依存しない。socket が無くても Edge は検知と判断を続ける。intake が生きたまま受け付けない場合（SIGSTOP など）に Edge の `connect` が詰まる経路は、Edge 側の修正（Azazel-Edge#431）で塞ぐもので、Nexus 側では直せない |
| 実装 | `src/azazel_nexus/edge_intake.py`、`runtime/src/azazel_nexus_runtime/edge_intaked.py` |
| 試験 | `tests/unit/test_edge_intake.py`、`tests/unit/test_edge_intaked.py`、`tests/unit/test_decoy_interaction_p2.py`。golden 入力 `tests/fixtures/edge/rust_event_engine_v1.jsonl`（Edge のソースから作ったもので、実行時の記録ではない） |
| CPU 間 | `edge.intake`（正準化・`EvidenceRecord` の digest・壊れた入力の拒否コード）、`edge.incident`（incident の遷移）、`audit.chain`（incident 台帳は監査と同じチェーン） |

### E2 Edge の判断の説明と表示

| 項目 | 内容 |
| --- | --- |
| 方向 | intake の incident 台帳 → 説明器（`az-incident-explaind`）→ 説明 ledger・`recent.json`・status・UI。説明器は M.I.O.（`mio-advise`）と Knowledge（`knowledge-read`）に問い合わせる |
| 形式 | `azazel-nexus/incident-explain-status/v1`、`azazel-nexus/recent-incidents/v1`（最大 20 行、アドレスを含まない）。Edge の `defense.action` は「Edge would <action>」としてだけ表示し、実行したとは書かない。read model は `status_view.AUTHORITY` で `edge_decisions` を `would_not_executed` と固定する |
| 認証と署名 | 台帳は `azincident-read` グループで読むだけ。M.I.O.・Knowledge へは各 socket の group と `SO_PEERCRED` |
| 失敗時 | M.I.O. や Knowledge が落ちても、固定の不足説明（`knowledge_unavailable`、`mio_handoff:reference_service_unavailable` など）で記録し、intake・検知・Edge には影響しない。frame は `P3-restricted` で外へ出ない |
| 実装 | `src/azazel_nexus/incident_explain.py`、`runtime/src/azazel_nexus_runtime/incident_explaind.py`、`src/azazel_nexus/edge_loop_status.py` |
| 試験 | `tests/unit/test_incident_explain.py`、`tests/unit/test_incident_explaind.py`、`tests/unit/test_edge_loop_status.py` |
| CPU 間 | `edge.explain`（説明要求の frame と recent の行）、`status.read_model` |

### E3 Edge package の検証・発行元署名・失効・floor

| 項目 | 内容 |
| --- | --- |
| 方向 | Edge の packager（Azazel-Edge `packaging/nexus-core/`）→ Nexus。Nexus は読んで検証するだけ |
| 形式 | pin `contract/azazel-edge-core/pin.json`（`azazel-edge-core/nexus-pin/v1`、manifest は `azazel-edge-core/package-manifest/v1`、health は `azazel-edge-core/health/v1`、x86_64 のみ）。probe の結果は `azazel-nexus/edge-probe/v2`。発行元の anchor は `azazel-nexus/edge-issuer-anchor/v1`、失効リストは `azazel-nexus/edge-package-revocation/v1`、floor は `azazel-nexus/edge-issuer-floor/v1` |
| 認証と署名 | `<manifest>.sig` は Ed25519、domain `azazel-nexus/edge-package-manifest/v1`。**Edge の packager は `signed: false` を固定で書き、署名を作らない**ので、どのノードにも anchor は無い（[Edge package 検証](edge-package-verification.md)） |
| 失敗時 | 判定は passed・failed・not-checked の 3 値で、not-checked は何も許可しない。digest の不一致は SECURITY FINDING として報告し、修復しない。anchor が不正なら `trust_refused`、無ければ判定に影響しない（`not_configured`）。floor と失効は狭める方向にだけ働く |
| 実装 | `src/azazel_nexus/edge_package.py`、`src/azazel_nexus/edge_issuer.py`、`runtime/src/azazel_nexus_runtime/edge_probed.py`、`runtime/src/azazel_nexus_runtime/edge_issuer_floor.py` |
| 試験 | `tests/unit/test_edge_package.py`（Edge の schema の写しとの一致も確かめる）、`tests/unit/test_edge_issuer.py`、`tests/unit/test_runtime_edge_issuer_floor.py`、`tests/unit/test_edge_probed.py` |
| CPU 間 | 専用の family は無い。暗号は `signature.ed25519`、表示は `status.read_model` の Edge の場面。Edge Core の binary は CPU ごとに固定し比較しない（[共通試験ベクトル §6](cross-arch-vectors.md#6-既知の差の扱い)）。Edge package は CPU ごとの pin（`azazel-edge-core/nexus-pin/v2`、`edge_package.PINS`）で、host の CPU・manifest の architecture・同梱バイナリの ELF ヘッダが一致しなければ拒否（[ADR-0003 R4](adr/0003-arm-software-verification-profile.md#amendment-2026-10-30-r4-the-edge-package-per-cpu)、Azazel-Edge#522） |

### F1〜F6 Fabric

| 項目 | 内容 |
| --- | --- |
| 方向 | Nexus が Fabric の型へ射影する。Fabric から何かを受け取る経路は無い。Fabric を import してよいのは `src/azazel_nexus/fabric_boundary.py` だけ（`tests/unit/test_boundary_static.py`） |
| 形式（pin） | `FABRIC_PIN = "v0.9.0rc5"`。`pyproject.toml` の optional extra `fabric` と `uv.lock`。CORE は Fabric 無しで動く（[ADR-0001](adr/0001-fabric-pin.md)）。オフライン wheelhouse は tag と commit の対応と wheel の hash で固定（[ADR-0004](adr/0004-fabric-in-offline-wheelhouse.md)） |
| 形式（射影） | F2 `project_capability`（`ModeState`・`StatusView`、本番の `azazel-nexus status` が呼ぶ）。F3 `project_edge_evidence`（`EvidenceRef`、本番の呼出し元なし）。F4 `project_explanation`（`ClaimSet`、Edge の判断は `deterministic_core` で、遷移から運んだ証拠の digest を `EvidenceRef`（`edge-core`、trace は incident id）として引用し、参照切れの理由 `evidence_not_stored`・`evidence_retention_elapsed` を limitations に書く。ローカル回答は、記録した候補・順位と（モデルが書いたときは）モデルの説明文を claim にし、埋め込み照合とモデルは `local_model`（`model_ref` 付き）、キーワード照合は `deterministic_core`（固定 banner は claim にしない）、各 `KnowledgeRef` は `knowledge_advisory`。説明器が ledger に保存するだけ）。F5 `project_tested_tuple`・`check_tested_tuple`（`TestedCompatibilityTuple`、[ADR-0006](adr/0006-tested-tuple-fabric-and-arm-lab.md)）。F6 `InterfaceIdentity`・`resolve_interface_assignment` ほか provisioning の型 |
| 認証と署名 | Fabric の release 署名は Nexus が検証しない（commit と hash の固定のみ。[オーナー判断 H8](owner-decisions.md#2-優先度の高いもの)） |
| 失敗時 | 射影は `available=False` と理由を返すだけで、呼出し元を止めず、能力や権限を変えない。版が pin と違えば unavailable。例外は commissioned activation で、pin どおりの Fabric が無ければ拒否する（ADR-0004） |
| 実装 | `src/azazel_nexus/fabric_boundary.py`、`runtime/src/azazel_nexus_runtime/incident_explaind.py`（F4 の保存） |
| 試験 | `tests/unit/test_fabric_boundary.py`、`tests/unit/test_edge_intake_fabric.py`、`tests/unit/test_fabric_explanation_projection.py`、`tests/unit/test_evidence_refs.py`、`tests/unit/test_fabric_tested_tuple.py`、`tests/unit/test_inventory_fabric.py`、`tests/unit/test_commissioning_fabric.py`。Fabric の extra を入れた全件（ci.yml の fabric-extra 相当）で走る |
| CPU 間 | **無し。** ベクトルの実行環境は `dev` extra だけを入れ、Fabric を入れない。`status.read_model` は `project_capability` を差し替えている。Fabric の射影が両 CPU で同じことは、Fabric 入りの全件を両 CPU で回して確かめるしかない |

### K1・K2 Knowledge Lite の bundle と失効

| 項目 | 内容 |
| --- | --- |
| 方向 | Azazel-Knowledge の `build-lite` が作る → 運用者が Nexus に import する（ファイル）。失効リストも同じ |
| 形式 | gzip の tar。`manifest.json`、`manifest.sig`（manifest の raw bytes への分離署名）、宣言した `tables/*.jsonl`。`SUPPORTED_FORMATS = (1, 1)`。上限は bundle 512 MiB・member 64 個など（`src/azazel_nexus/lite_bundle.py`）。失効は `revocations.signed`（domain `azazel-nexus/revocation/v1`、役割 `revocation-signing`） |
| 認証と署名 | 信頼はノードの `anchors.toml` だけが決める（`threshold`・`keys`・`key_roles`・`required_signer_role`・`minimum_security_epoch`・`accepted_export_policy_digests`）。manifest がこれらを名乗れば `BUNDLE_SHADOWS_TRUST_ANCHOR`（Knowledge の禁止欄 `anchors`・`trust`・取込み状態の欄との和集合。[差分試験 §4.2](knowledge-lite-differential.md#42-この-pr-で-nexus-を-knowledge-に揃えたもの委任された技術判断)）。公開 fixture の鍵は `PUBLIC_FIXTURE_KEY` で拒否し、例外はラボ印のあるホストだけ（`src/azazel_nexus/lab_keys.py`）。import は ROOT の動詞 `knowledge.import`、失効受理は ROOT の経路で、どちらも auditd に記録する |
| 失敗時 | fail-closed。gate（anchors・archive・manifest・format・signature・signer-role・security-epoch・export-policy・rollback・content）のどれかで拒否する。版は watermark で上がるだけで、下回れば `state_untrusted`。期限は gate ではなく、行ごとに読取り時に判断し、期限切れの動的情報を現行の根拠にしない。時計が床より戻れば静的参照も含めて配らない（[Wall-clock floor](knowledge-lite-consumer.md#wall-clock-floor)）。どの状態でも決定論の経路は止まらない |
| 実装 | `src/azazel_nexus/lite_bundle.py`、`src/azazel_nexus/lite_import.py`、`src/azazel_nexus/lite_trust.py`、`src/azazel_nexus/lite_service.py`、`src/azazel_nexus/revocation.py`、`runtime/src/azazel_nexus_runtime/knowledge_lited.py`、`runtime/src/azazel_nexus_runtime/knowledge_clock_floor.py` |
| 試験 | `tests/unit/test_lite_bundle.py`、`tests/unit/test_lite_import.py`、`tests/unit/test_lite_trust.py`、`tests/unit/test_lite_revocation.py`、`tests/unit/test_knowledge_clock_floor.py`、`tests/unit/test_knowledge_lite_enrollment.py`。producer が出した fixture は `contract/azazel-knowledge-lite/`。Knowledge の検証器との差分は `tools/knowledge_lite_differential.py`（[差分試験](knowledge-lite-differential.md)。CI では Nexus の列だけ） |
| CPU 間 | `knowledge_lite.verify`、`knowledge_lite.refusals`、`revocation`、`signature.ed25519`。時計の床は対象外 |

### K3・K4 Knowledge Lite の照会と状態

| 項目 | 内容 |
| --- | --- |
| 方向 | knowledge-lited → M.I.O.（entryd）・説明器・arbiter（照会）、運用者（状態）、status・UI（snapshot） |
| 形式 | 運用者用 `knowledge/knowledge.sock`、サービス用 `knowledge-read/knowledge-read.sock`。`knowledge.status`（応答はちょうど 9 キー）と `knowledge.lookup`（引数 `technique_ids` 最大 8 件、応答 `refs` 最大 16 件と `reason_code`）。`KnowledgeRef` はちょうど 11 欄（`technique_id`・`name`・`summary`・`claim_id`・`bundle_digest`・`freshness`・`source_kind`・`generation`・`trust_check`・`as_of`・`citation`）。snapshot は `azazel-nexus/knowledge-status/v1` |
| 認証と署名 | `knowledge.status` は OPERATOR と SERVICE、`knowledge.lookup` は SERVICE だけ。プロセスの境界ではどこでも `read_knowledge_refs` で形を検査する |
| 失敗時 | クライアントは期限 0.5 秒、再試行なし。失敗は `KnowledgeUnavailable` だけになり、説明は固定の不足説明で続く |
| 実装 | `runtime/src/azazel_nexus_runtime/knowledge_lited.py`、`runtime/src/azazel_nexus_runtime/knowledge_client.py`、`src/azazel_nexus/operator_snapshots.py` |
| 試験 | `tests/unit/test_knowledge_lookup.py`、`tests/unit/test_knowledge_lited.py`、`tests/unit/test_core_lite_integration.py`、`tests/unit/test_operator_snapshots.py` |
| CPU 間 | `knowledge_lite.lookup`（技術 ID 5 通り × 2 時点）。snapshot は `status.read_model` に含まれる範囲だけ |

### K5 外部 Knowledge peer

| 項目 | 内容 |
| --- | --- |
| 方向 | Nexus → Knowledge 本体（ノードの外） |
| 形式 | `azazel-nexus/knowledge-peer/1`。`POST /knowledge/v1/capabilities` のあと `POST /knowledge/v1/query`。署名 domain は registry・capability・response の 3 つに分ける。要求 64 KiB・応答 256 KiB・全体 10 秒・待ち行列 0・再試行 0 |
| 認証と署名 | mTLS 必須（commissioning した CA、署名済みの hostname、SPKI pin、クライアント証明書）。名前解決はしない。応答は peer 鍵の Ed25519 で検証する |
| 失敗時 | ローカル優先。拒否されれば embedded cache、それも無ければ `no-context` を明示する。P2・P3 は外へ出さない |
| 実装 | `src/azazel_nexus/knowledge_peer.py`、`runtime/src/azazel_nexus_runtime/knowledge_egress.py`。本番のコードで peer のクライアントを作るものは無い |
| 試験 | `tests/unit/test_knowledge_peer.py`（loopback のサーバと試験用 TLS fixture）、`tests/unit/test_runtime_boundary.py` |
| CPU 間 | 無し |

### U1 操作 UI

| 項目 | 内容 |
| --- | --- |
| 方向 | Nexus の UI（`az-ui`、アカウント `azui`）→ 同じホストのブラウザ。読取りだけで、操作のボタンは無い |
| 形式 | `azazel-ui.socket` が IPv4 loopback の 8443 で待ち受け、fd を渡す（`az-ui` は bind しない）。TLS は無い。`GET /api/session`・`GET /api/view`・`POST /api/login`・`POST /api/logout` と静的ファイル。ブラウザへ送るのは `azazel-nexus/ui-model/1`（`azazel-nexus/status-view/1` と `azazel-nexus/setup/1` の allowlist）。ラベルは `azazel-nexus/ui-labels/1` |
| 認証と署名 | `azazel-nexus ui-login`（`azazel-operator` のメンバー）が出す 1 回限りのコード（`azazel-nexus/ui-login/1`、60 秒）。cookie `azui_session`（`HttpOnly`・`SameSite=Strict`、`Secure` なし）。`Host` の完全一致、POST の `Origin`・`Content-Type`・CSRF token、query string の拒否、CSP（[操作 UI の Browser boundary](operator-ui.md#browser-boundary)）。socket は `IPAddressDeny=any`・`IPAddressAllow=localhost` |
| 失敗時 | 読めない snapshot は `permission_denied` などと表示し、正常とは表示しない。UI に依存する unit は無く、止めても中核は止まらない |
| 実装 | `runtime/src/azazel_nexus_runtime/ui_serve.py`、`src/azazel_nexus/ui_model.py`、`src/azazel_nexus/ui_login.py`、`src/azazel_nexus/status_view.py` |
| 試験 | `tests/unit/test_ui_serve.py`、`tests/unit/test_ui_model_and_login.py`、`tests/unit/test_ui_account_privilege.py`、`tests/unit/test_status_view.py`。ブラウザでの確認は [UI のブラウザ確認](evidence/ui-browser-2026-10-29.md) |
| CPU 間 | `status.read_model`（status-view/1 の golden 10 場面）。`ui-model/1` の family は無い。ブラウザの表示は aarch64 と x86_64（Rosetta、通常状態 1 回）で一致を記録済み |

### U2 運用者向け snapshot

| 項目 | 内容 |
| --- | --- |
| 方向 | 各 daemon・observer → `azazel-nexus status --json`・UI |
| 形式 | `/var/lib/azazel/run/<leaf>/status.json`。`azazel-nexus/mio-status/v1`（entryd）、`azazel-nexus/units-status/v1`（`az-units-observe`）、`azazel-nexus/noc-status/v1`（`az-noc-observe`、元の観測は `azazel-nexus/noc-observation-local/v1`）、`azazel-nexus/audit-status/v1`（auditd）、`azazel-nexus/edge-intake-status/v1`（intake）、K4 の knowledge-status |
| 認証と署名 | leaf は書き手の所有で、group `azazel-operator` が読む。署名は無い（ローカルの信頼） |
| 失敗時 | 読み手は閉じた形だけを受け付け、外れたものは refused と表示する。書き手は一時ファイルから rename し、失敗しても本業を止めない。版を上げるときは書き手と読み手を同時に変える |
| 実装 | `src/azazel_nexus/operator_snapshots.py`、`runtime/src/azazel_nexus_runtime/status_snapshot.py`、`src/azazel_nexus/noc_status.py`、`runtime/src/azazel_nexus_runtime/noc_snapshot.py` |
| 試験 | `tests/unit/test_operator_snapshots.py`、`tests/unit/test_noc_status.py`、`tests/unit/test_noc_observe.py`、`tests/unit/test_mio_status.py`、`tests/unit/test_audit_status.py` |
| CPU 間 | 個別の family は無い。`status.read_model` が読んだ結果の一部を含む |

### M1 M.I.O. の経路と参照

| 項目 | 内容 |
| --- | --- |
| 方向 | 説明器（`mio-advise`、動詞 `mio.advise`）・運用者（`mio-entry`、動詞 `mio.route`）→ entryd → locald（ローカルモデル）・referenced（モデル不要の参照）・remoted（オンライン AI） |
| 形式 | `mio.route`（`privacy_class`・`deadline_ms`）。期限は 500 ms と呼出し側の余裕。route ledger は日ごとの segment のチェーン |
| 認証と署名 | `SO_PEERCRED` と group。`mio.advise` は説明器だけ、`P3-restricted` だけ。entryd は uid ごとに流量を制限する。referenced は SERVICE だけが呼べる |
| 失敗時 | 認可済みのモデルが無い・予測が無い・期限超過・両 AI 不能のときは決定論の handoff（`mio_handoff:*` の固定語）へ退避する。LOCAL は予測が供給されない間は選ばれない（[オーナー判断 M5](owner-decisions.md#31-mio-とオンライン-ai-送信)） |
| 実装 | `runtime/src/azazel_nexus_runtime/mio_entryd.py`、`runtime/src/azazel_nexus_runtime/mio_locald.py`、`runtime/src/azazel_nexus_runtime/mio_referenced.py`、`runtime/src/azazel_nexus_runtime/mio_remoted.py` |
| 試験 | `tests/unit/test_mio_locald.py`、`tests/unit/test_mio_remoted.py`、`tests/unit/test_route_audit.py` ほか `tests/unit/test_mio_*.py` |
| CPU 間 | `mio.route`（`remote_admission`・`select`・`fallback_once`・`outcome_for`・`terminal_for`）。期限の計算と埋め込みの類似度は対象外 |

### M2〜M5 送信の封筒・応答・同意・ローカル admission

| 項目 | 内容 |
| --- | --- |
| 方向 | M2：sanitizer → remoted → 提供者。M3：提供者・ローカルモデル → Nexus。M4：運用者 → entryd（ストア）→ remoted（送信直前の照合）。M5：運用者 → locald |
| 形式 | M2：payload の schema `azazel-nexus/sanitized-envelope/2`、署名 domain `azazel-nexus/sanitized-envelope/v1`。`content_digest`・`privacy_class`・`policy_revision`・`expires_at`・`nonce` と `provider_id`・`opt_in_generation` を束縛する。M3：`AdvisoryText` と入れ子の無い `AdvisoryData` だけ（`src/azazel_nexus/advisory_response.py`）、ローカルは `src/azazel_nexus/local_advisory.py`。M4：`azazel-nexus/mio-remote-opt-in/v1`、動詞 `mio.remote.opt_in.status`・`.set`・`.withdraw`。M5：`azazel-nexus/local-model-admission/v1` |
| 認証と署名 | M2：Ed25519。remoted の外向き通信は mTLS 必須・SPKI pin・redirect を追わない・再試行なし。M4：OPERATOR だけ。M5：運用者の承認（domain `azazel-nexus/operator-approval/v1`） |
| 失敗時 | M2：署名器と sanitizer の鍵が無く、出荷時の transport は `None` なので送れない（fail-closed）。M3：tool call・URL・コマンド・enforcement の指示は拒否し、部分的な成功は無い。M4：読めなければ `NO_OPT_IN`、remoted は `opt_in_unavailable`・`opt_in_not_granted`・`opt_in_generation_mismatch` で拒否。M5：`LOCAL_MODEL_ADMISSION_ENABLED = False` で常に閉じている（x86_64 のみ） |
| 実装 | `src/azazel_nexus/remote_envelope.py`、`runtime/src/azazel_nexus_runtime/inference_egress.py`、`runtime/src/azazel_nexus_runtime/mio_remote_consent.py`、`src/azazel_nexus/model_admission.py` |
| 試験 | `tests/unit/test_remote_envelope.py`、`tests/unit/test_inference_egress.py`、`tests/unit/test_advisory_response.py`、`tests/unit/test_local_advisory.py`、`tests/unit/test_mio_remote_consent.py`、`tests/unit/test_mio_entryd_opt_in.py`、`tests/unit/test_mio_local_admission.py` |
| CPU 間 | M4 は `mio.consent`。M2・M3・M5 は無し |

### A1 監査への追記

| 項目 | 内容 |
| --- | --- |
| 方向 | 説明器・knowledge-lited・commissiond → auditd |
| 形式 | `audit-submit/audit-submit.sock`（追記専用。登録されている動詞は `audit.append` だけ）。状態は `azazel-nexus/audit-status/v1` |
| 認証と署名 | kernel の uid で書ける event を縛る（`azexplain` は `edge.incident.*`、`azknowledge` は `knowledge.lite.import_*`、`azcommission` は `knowledge.lite.revocation_*`）。違えば `principal_denied` |
| 失敗時 | uid ごとの流量と日ごとの上限（`rate_limited`）。説明器からの送信は best effort で、失敗しても説明と台帳を止めない（`audit_forward_dropped`・`audit_forward_refused`） |
| 実装 | `runtime/src/azazel_nexus_runtime/auditd.py`、`src/azazel_nexus/audit.py` |
| 試験 | `tests/unit/test_runtime_auditd.py`、`tests/unit/test_auditd_submit_listener.py`、`tests/unit/test_audit_chain.py` |
| CPU 間 | `audit.chain` |

## 4. 未採用の契約

| 契約 | 所在 | Nexus での扱い | 採用に要るもの |
| --- | --- | --- | --- |
| `mio_contracts.SituationFrame` | Fabric（pin に存在） | 使わない。frame は Nexus の `incident_explain.build_frame` | 共有 frame への移行の判断 |
| `mio_contracts.SanitizedRemoteFrame` | Fabric | 使わない。封筒は M2 | redaction record の扱い（[オーナー判断 M7](owner-decisions.md#31-mio-とオンライン-ai-送信)） |
| `mio_contracts.AdvisoryResult`・`MergedAdvisory`・`Disagreement` | Fabric | 使わない（M3 は Nexus のローカルの形。Nexus は助言を merge しない） | 助言の provenance（model_ref・generation）を ledger に持つこと（[オーナー判断 L23](owner-decisions.md#4-優先度が低いもの)） |
| `cti_contracts.CtiContextRequest`・`CtiContextResponse` | Fabric | 使わない。`SourceProduct` に Nexus が無く、Nexus は要求者になれない。実 Knowledge の `/v1/context` もこの形ではない | Fabric と Knowledge の合意 |
| `deception_contracts` | Fabric | 本番のコードは import しない（試験が `EnvironmentEvent` で decoy の形を確かめるだけ）。I4 の判断の記録は未実装（[redirect の前提](deception-redirect-prerequisites.md)） | I4 の設計 |
| `effect_contracts` | Fabric | import していない（[ADR-0001](adr/0001-fabric-pin.md)） | — |
| `schema.decision.DecisionExplanation`、`schema.action.ActionIntent`、`schema.audit.AuditEvent`、`notify.model.NotificationEvent`、`schema.state.StateSnapshot`、`schema.trust.TrustCapsule` | Fabric | 射影が無い（[契約の所有 §3.1](contract-ownership.md#31-decision-evidence-and-audit-path) の表に名前があるだけ） | 適合試験 |
| `CompatibilityManifest` ほか provisioning の R1 の記録 | Fabric（目標） | 受け取る経路が未設計（[オーナー判断 M19](owner-decisions.md#33-fabric-との契約)） | Fabric の R1 |
| Edge の lease の配送（integration broker） | Nexus のローカル | `azazel-nexus/edge-lease/1` を組み立てるが、配送は常に `transport unavailable`（[integration broker](integration-broker.md)） | Fabric 側の transport |

## 5. 実 Knowledge の `/v1/context` との差

K5 の peer プロトコルは Nexus が試験用に定めたもので、実際の Azazel-Knowledge の API とは
相互運用しない。比較の詳細は [Knowledge peer の比較表](knowledge-peer.md#the-real-knowledge-api-and-this-protocol)
にあり、要点は次のとおり。どちらも、Nexus のコードが実 API と要求を交わしたことは無い。

| 項目 | Nexus の peer プロトコル | 実 Knowledge の `/v1/context` |
| --- | --- | --- |
| 入口 | `POST /knowledge/v1/capabilities` → `POST /knowledge/v1/query` | `POST /v1/context`（`/knowledge/v1/capabilities` は 404、測定済み） |
| 運ぶ手段 | mTLS 必須（CA・hostname・SPKI pin・クライアント証明書） | 平文の HTTP（文書は「mTLS optional」だが実装は無い） |
| 認証 | クライアント証明書だけ | Bearer token（`query` の scope） |
| 応答の真正性 | Ed25519 の署名を peer 鍵で検証 | 署名なし（Knowledge は自分の監査チェーンに記録する） |
| 要求の形 | `azazel-nexus/knowledge-peer/1`（sanitizer の出力をそのまま） | `ContextApiRequest`。未知の欄は無視され、`CtiContextRequest` の形の本文にも 200 を返す（測定済み） |
| 期限 | 署名した文書ごとに `issued_at`・`expires_at` | 応答に期限は無い（`source_freshness` はデータの鮮度） |
| 要求者の識別 | クライアント証明書の commissioning した識別 | token の key。`edge_id` は自由な文字列 |
| privacy | P2・P3 は出さない、P1 は policy が要る、redaction record は残す | 要求は entity の値をそのまま運ぶ。privacy class の契約は無い |

本番で外部 Knowledge と相互運用するには、プロトコルと署名済み capability の形を
Azazel-Knowledge と合意する必要がある。それまでは Lite（K1〜K4）だけで動き、外部 peer が
無くても説明と参照は止まらない。

## 6. 両 CPU での同一性の確かめ方

1. どの CPU でも、単体試験 `tests/unit/test_cross_arch_vectors.py` が各 family の
   digest を固定値（`tests/vectors/digests.json`）と比べる。tests/unit は aarch64 でも
   x86_64 でも同じものが走る。
2. `tools/cross_arch_vectors.py --python 3.12` が、aarch64（colima）と amd64
   （colima-rosetta、Rosetta）のコンテナで同じベクトルを実行し、digest を突き合わせる
   （[共通試験ベクトル §4](cross-arch-vectors.md#4-実行)）。
3. 比べるのは正準 JSON の SHA-256 で、時刻・ID は注入し、float は拒否するか除外して
   path を記録する（[§3](cross-arch-vectors.md#3-比較条件と除外したもの)）。

| 契約 | family |
| --- | --- |
| E1 | `edge.intake`、`edge.incident` |
| E2 | `edge.explain`、`status.read_model` |
| E3 | `signature.ed25519`、`status.read_model`（表示のみ） |
| K1・K2 | `knowledge_lite.verify`、`knowledge_lite.refusals`、`revocation`、`signature.ed25519` |
| K3 | `knowledge_lite.lookup` |
| U1・U2 | `status.read_model` |
| M1 | `mio.route` |
| M4 | `mio.consent` |
| A1 | `audit.chain` |
| 実行基盤の選択（[ADR-0003](adr/0003-arm-software-verification-profile.md)） | `platform_profile.selection` |

**どの family にも入っていないもの**：Fabric の射影（F2〜F6。ベクトルの環境に Fabric が
入らない）、Knowledge peer（K5）、封筒の検証（M2）、助言の応答（M3）、ローカル
admission（M5）、`ui-model/1`、NOC と mio-status の snapshot、Edge の発行元と floor、
Knowledge の時計の床。これらは各 CPU の単体試験が通ることまでは言えるが、出力が
バイト単位で同じことは確かめていない。

どの確認もコンテナでのもので、amd64 は Rosetta による変換である。実機の両 CPU では
未実行（[実機受入手順](hardware-acceptance.md)）。
