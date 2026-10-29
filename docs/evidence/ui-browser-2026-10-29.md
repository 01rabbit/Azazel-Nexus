# 読取専用 UI の実ブラウザ検証（U6）— コンテナ内 headless Chromium：2026-10-29

**コンテナ内の headless Chromium と、コンテナ内 systemd のリハーサル：VM でも実機でもない。**
HIL の証跡ではなく、HG の欄にも載せない。対象は [読取専用 UI](../operator-ui.md)（`az-ui`、#365）。
撮影と判定は [`ui-browser-2026-10-29/harness.py`](ui-browser-2026-10-29/harness.py) が行い、
判定の原本は同じディレクトリの JSON 3 件（`aarch64-result.json`、`amd64-result.json`、
`systemd-result.json`）。画像は同じディレクトリの PNG。

## 条件

| 項目 | aarch64（主） | x86_64（比較） | systemd リハーサル |
| --- | --- | --- | --- |
| 実行場所 | colima（Apple Silicon、ネイティブ aarch64）のコンテナ 1 個、`--network none`、uid 1001 | colima の Rosetta プロファイル上の linux/amd64 コンテナ（**Rosetta エミュレーション**）、`--network none`、uid 1001 | colima（aarch64）の特権 Debian trixie コンテナ、systemd 257 が PID 1。導入後に外部ネットワークを外した（lo のみ）。Chromium は別コンテナで、このコンテナのネットワーク名前空間を共有 |
| イメージ | `edge-touch-shot:py311`（Debian trixie）に pytest・dbus-next・PyYAML・Pillow を足したもの（作成時のみネットワークあり） | `debian:trixie` に chromium・fonts-noto-cjk・python3（3.13）等を入れたもの | `az-nexus-systemd:trixie`、Python 3.13.5。本番の venv（pip、ネットワークあり）と `packaging/install.sh` で導入 |
| ブラウザ | Chromium 156.0.8078.47（Debian trixie、headless=new、`--no-sandbox`） | 同じ版（x86_64 ビルド） | aarch64 と同じイメージ |
| Python（UI 側） | 3.11.17 | 3.13.5 | 3.13.5（本番 venv） |
| UI の起動 | `tools/ui_socket_activate.py` で 127.0.0.1:8443 を渡し、`python -m azazel_nexus_runtime.ui_serve`（**live**：`AZAZEL_ROOT` の一時ノードを読む）。XSS だけ `--fixture` で 8444 | 同じ（live、通常状態のみ） | `systemctl enable --now azazel-ui.socket`（本番 unit、`azui`、ソケット起動） |
| 対象 commit | このファイルを加えた PR の head（main `b3f7e4f` ＋下記の UI 修正） | 同じ | 同じ |

**入力は何か**（設計上の表示と実データを区別するため）：

- live の UI は、ノード上と同じ読取器で snapshot ファイルを読む。ただしファイルの中身は
  **ハーネスが製品の生成関数で書いた fixture** で、daemon が動いて書いたものではない：
  Edge loop（intake・explainer・recent・audit）は status read model の試験の生成関数、
  Knowledge・M.I.O.・unit 状態は `operator_snapshots.*_snapshot`、NOC だけは
  **実際の受動観測**（`noc_snapshot.observe` が、そのコンテナの netlink と sysfs を読んだもの）。
  Edge loop の snapshot は 30 秒で古くなるので、通常状態の間は 3 秒ごとに書き直した（daemon の代わり）。
- XSS の確認は保存済み fixture（`tests/fixtures/ui/demo-status-view.json` に HTML/JS を埋めたもの）。
  画面には「fixture 表示」の帯が出る。
- systemd リハーサルでは snapshot を書いていない。実際に動いたのは `azazel-noc-observe` と
  `azazel-units-observe`（timer と手動起動）だけで、ほかの daemon は install.sh のとおり masked のまま。

ログインは毎回、UI が書いた実際のログインコードで行った（aarch64・x86_64 はハーネスがファイルから読む。
systemd では `azazel-operator` の利用者が `azazel-nexus ui-login` で得たもの）。コードは
`Input.insertText` で入力し Enter で送信した。コードは記録・画像のどこにも残していない。
Chromium は DevTools Protocol を `--remote-debugging-pipe` で操作し、デバッグ用のポートは開いていない。

## 結果

| # | 確認 | 結果 | 根拠 |
| --- | --- | --- | --- |
| 1 | 5 画面（概況・インシデント・NOC・Knowledge・セットアップ・復旧）がログイン後に表示される | pass | `normal-*.png`、`aarch64-result.json` の `states.normal` |
| 2 | 日本語：`lang="ja"`、見出しの和文は Noto Sans CJK JP で描画（`CSS.getPlatformFontsForNode`）。語には英語の enum を併記 | pass | `fonts_ja_heading`、各画像 |
| 3 | 劣化 6 種（snapshot が無い・壊れている・古い・時刻が未来・symlink・サイズ超過 300 KiB）：snapshot を読む 6 枚のカード（通信、M.I.O. snapshot、Knowledge snapshot、サービス、intake、explainer）のどれも緑（`tone-ok`）にならず、中に緑の badge も「正常」の語も無い | pass（6/6） | `degraded-*-overview.png`、`checks.degraded.*`。下の表 |
| 4 | 復旧：snapshot を新しく書き戻すと、ページの 5 秒ごとの更新で通常と同じ表示（6 枚のカードの tone が通常と一致）に戻る。再ログイン不要 | pass | `recovered-overview.png`、`checks.recovered.same_as_normal` |
| 5 | 狭い画面（幅 360 px、モバイル表示）：横スクロールなし（`scrollWidth` 360 = `clientWidth` 360）。タブは 2 列に折り返し、44 px 以上の押下領域 | pass | `narrow-overview.png`、`narrow-incidents.png` |
| 6 | XSS：status の値（Fabric の `status`・`reason_code`・`version`）、インシデント ID、AI 要約、Knowledge 引用名に `<img src=x onerror=…><script>…</script>` を入れた fixture で、`window.__azxss` は未定義、`document.images` 0、`<script>` は `/static/app.js` の 1 個だけ、ページ文中に文字として 14 箇所。`/x` への要求も無い。未知の語の Fabric カードは「？ 未定義の語」（unknown）で緑にならない | pass | `xss-*.png`、`states.xss.probe` |
| 7 | 外部通信：ページが出した要求は全件 `http://127.0.0.1:<port>/`（aarch64 31 件、x86_64 8 件、systemd 8 件。CDP の `Network.requestWillBeSent`）。NetLog でも、ページを起点とする（`initiator` がページの origin）外部要求は 0 件 | pass | `page_requests_external`、`netlog.page_initiated_external` |
| 8 | Chromium 自身の背景通信（component updater `update.googleapis.com`、x86_64 では DoH の `chrome.cloudflare-dns.com`）は `initiator: not an origin` の要求として NetLog に現れ、すべて `ERR_INTERNET_DISCONNECTED`（-106）で終わった。完了した外部要求は 0 件 | 記録（UI の要求ではない） | `netlog.browser_initiated`、`netlog.external_completed` |
| 9 | systemd：`azui` の UI はソケット起動で動き、`azui` が読めない snapshot の節を **権限なし（`permission_denied` / `access_permission_denied`）** と表示する（概況・インシデント・NOC・Knowledge・セットアップの 15 枚）。「無い」とも「正常」とも表示しない | pass | `systemd-overview.png`、`systemd-result.json` |
| 10 | systemd：UI のプロセスは uid/gid とも `azui`、補助グループ無し、`CapEff` 0、`NoNewPrivs` 1、seccomp 有効、ネットワーク名前空間は `lo`（と `sit0`）だけ。unit は `RestrictAddressFamilies=AF_UNIX`、`PrivateNetwork=yes`、`IPAddressDeny=any`。listener は systemd が持つ `127.0.0.1:8443` だけ | pass | 実行時の `/proc/<pid>/status`、`systemctl show`、`ss -ltn`（下記手順 §3） |
| 11 | systemd：`systemctl stop azazel-ui.socket azazel-ui.service` の後も `azazel-noc-observe.timer`・`azazel-units-observe.timer` は active、両 service は手動起動で `Result=success`、snapshot は書き直された。8443 は閉じて接続できない。逆依存は `azazel-ui.service` 自身のみ | pass | 下記手順 §3 |
| 12 | x86_64（Rosetta）で通常状態を 1 回：43 枚のカードの（画面・題・tone・語・理由）が aarch64 と完全一致。概況・インシデント・Knowledge の文字列も数字を伏せて一致。NOC とセットアップの差は、コンテナの interface の数と経過秒の小数だけ（環境差） | pass | `amd64-normal-overview.png`、`amd64-result.json` |

劣化状態ごとの 6 枚のカード（aarch64、DOM から抽出。全カードで tone は `unknown`＝「？」の破線）：

| 状態 | 語（enum） | 理由コード |
| --- | --- | --- |
| 通常（参考） | intake・explainer は `running`（● 緑）、Knowledge snapshot は `available`（● 緑）、サービスは `degraded`（▲）、NOC・M.I.O. snapshot は `observed`・`recorded`（◆ 情報） | — |
| 無い | `unavailable` | `snapshot_absent_or_refused` |
| 壊れている（`{"schema":`） | `unavailable` | `snapshot_absent_or_refused` |
| 古い（1 時間前） | `stale` | `snapshot_expired` |
| 未来（1 時間先） | `stale` | `snapshot_dated_in_future` |
| symlink（中身は新しい） | `unavailable` | `snapshot_absent_or_refused` |
| サイズ超過 | `unavailable` | `snapshot_absent_or_refused` |

## 画像

| 状態 | 画像（全画面、最大高さ 2600 px、48 色のパレット PNG） |
| --- | --- |
| 通常（1280 px） | [概況](ui-browser-2026-10-29/normal-overview.png)・[インシデント](ui-browser-2026-10-29/normal-incidents.png)・[NOC](ui-browser-2026-10-29/normal-noc.png)・[Knowledge](ui-browser-2026-10-29/normal-knowledge.png)・[セットアップ・復旧](ui-browser-2026-10-29/normal-setup.png) |
| 劣化 | [無い](ui-browser-2026-10-29/degraded-absent-overview.png)・[壊れている](ui-browser-2026-10-29/degraded-broken-overview.png)・[古い](ui-browser-2026-10-29/degraded-stale-overview.png)・[未来](ui-browser-2026-10-29/degraded-future-overview.png)・[symlink](ui-browser-2026-10-29/degraded-symlink-overview.png)・[サイズ超過](ui-browser-2026-10-29/degraded-oversize-overview.png) |
| 復旧 | [概況](ui-browser-2026-10-29/recovered-overview.png) |
| 狭い画面（360 px） | [概況](ui-browser-2026-10-29/narrow-overview.png)・[インシデント](ui-browser-2026-10-29/narrow-incidents.png) |
| XSS（fixture） | [概況](ui-browser-2026-10-29/xss-overview.png)・[インシデント](ui-browser-2026-10-29/xss-incidents.png) |
| systemd（権限なし） | [概況](ui-browser-2026-10-29/systemd-overview.png) |
| x86_64（Rosetta） | [概況](ui-browser-2026-10-29/amd64-normal-overview.png) |

NOC とセットアップの画面は 2600 px より長く、画像は上端から 2600 px まで。全文は各 JSON の
カード一覧と、ハーネスが出す `text/` に残る（`text/` はリポジトリに入れていない）。

## 見つかったこと

| # | 内容 | 扱い |
| --- | --- | --- |
| F1 | NOC 画面：入れ子の表（`dl.kv` の中の `dl.kv`）が深くなるたびに値の列が狭まり、`regular_file` が 1 文字ずつ縦に並び、カードの外にはみ出した。1280 px でもページの高さが 1 万 px を超えた。値の欄に置いた badge も同じく縦に潰れた | **修正済み**（`ui_static/app.css`）。入れ子の表はキーの下に値を置く 1 列にし、値の列に最小幅を与え、grid の子に `min-width: 0`、NOC 画面のカードは全幅、badge は折り返す。修正後の撮影が上の画像。回帰試験 `test_nested_tables_stack_and_times_are_shown_as_times` |
| F2 | `content_freshness_evaluated_at` などの `*_at` の数値（epoch 秒）が `1793227046.818…` のまま表示された | **修正済み**（`ui_static/app.js`）。`tree()` で `*_at` の数値は他の時刻と同じ形式（日時と経過）で表示する。文字列の時刻は従来どおり |
| F3 | Chromium 156 は応答の `Permissions-Policy` の `bluetooth` を知らない語として警告する（コンソール）。他の語は有効 | 報告のみ。Web Bluetooth を持つブラウザでは意味があるので外さない |
| F4 | ブラウザが自動で取りに行く `/favicon.ico` が 404 になり、コンソールに 1 行出る | 報告のみ（UI は 5 つの経路しか持たない設計どおり） |
| F5 | fixture 表示では、保存時の評価（例：intake「● 稼働（snapshot が新しい）」）がそのまま出て、同じカードに「38 日前」と並ぶ。画面上部の「fixture 表示：…このノードの現在の状態ではありません」の帯で区別される | 報告のみ（fixture は保存した read model を写す設計） |
| F6 | live 表示の「AI 経路（M.I.O.）」「Knowledge Lite」「防御状態（Edge）」は、このリハーサルでは route ledger・Lite・Edge package を置いていないので通常状態でも `unknown`／`unavailable`／`absent` | 欠陥ではない（入力が無いことを正しく示している） |

## 手順（再現）

### 1. aarch64（主）

```sh
# 撮影用イメージ（作成時のみネットワークあり）
printf 'FROM edge-touch-shot:py311\nRUN pip install --no-cache-dir -q pytest dbus-next==0.2.3 PyYAML==6.0.3 Pillow==11.3.0\n' \
  | docker --context colima build -q -t u6-shot:py311 -
# 撮影（ネットワークなし、uid 1001）。run.sh は clone を /w/repo に写し、
# AZAZEL_ROOT=/w/node、PYTHONPATH=src:runtime/src:tests/unit で harness.py を実行する
docker --context colima run --rm --network none --user 1001:1001 \
  --tmpfs /w:rw,exec,uid=1001,gid=1001,mode=0755,size=1g --shm-size=512m \
  -v <clone>:/src:ro -v <out>:/out -v <run.sh>:/run.sh:ro u6-shot:py311 bash /run.sh
```

`run.sh` の中身：

```sh
umask 022; mkdir -p /w && cp -r /src /w/repo
export HOME=/w AZAZEL_ROOT=/w/node HARNESS_WORK=/w/harness TZ=Asia/Tokyo
export PYTHONPATH=/w/repo/src:/w/repo/runtime/src:/w/repo/tests/unit
mkdir -p "$AZAZEL_ROOT"
python3 /w/repo/docs/evidence/ui-browser-2026-10-29/harness.py --repo /w/repo --out /out "$@"
```

終了コード 0 と `result.json` の `failures: []` が合格。

### 2. x86_64（Rosetta、通常状態のみ）

`debian:trixie` に `chromium fonts-noto-cjk fonts-dejavu-core python3 python3-pil python3-pytest
python3-yaml python3-pip` と `dbus-next==0.2.3` を入れたイメージを
`docker --context colima-rosetta build --platform linux/amd64` で作り、上と同じ
`docker run` を `--context colima-rosetta --platform linux/amd64` で、引数
`--only normal --prefix amd64-` で実行。

### 3. systemd リハーサル（aarch64）

```sh
docker --context colima run -d --name azn-u6sd --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock -v <clone>:/src:ro az-nexus-systemd:trixie
# コンテナ内：apt で apparmor iproute2 openssl gcc python3-dev python3-venv、
# /opt/azazel-nexus/venv に pip install . ./runtime、
# env PYTHON=/opt/azazel-nexus/venv/bin/python sh packaging/install.sh
systemctl start azazel-noc-observe.service azazel-units-observe.service
systemctl start azazel-noc-observe.timer azazel-units-observe.timer
systemctl enable --now azazel-ui.socket
useradd -m -G azazel-operator u6op
docker --context colima network disconnect bridge azn-u6sd     # 以後 lo のみ
# 最初の接続で azazel-ui.service が起動しコードを書く。u6op で ui-login してコードを得て、
# Chromium を --network container:azn-u6sd で起動し harness.py --attach-code <file>
# （この撮影は、ハーネスが Chromium を /bin/sh 経由で起動していた版で行った。
#   以後の変更はその 1 行を bash にしただけ：dash は 2 桁の記述子を受け付けず x86_64 で失敗したため）
systemctl stop azazel-ui.socket azazel-ui.service              # 他の unit の状態を前後で比較
```

## これが示さないもの

- **実機ではない。VM でもない。** カーネルの再起動、実 NIC、実記憶域、性能、電源断、
  TPM・Secure Boot、物理分離は何も示さない。systemd はコンテナ内のもの（PID 1 は systemd だが
  カーネルはホストの colima VM のもの）。
- **Mac の Google Chrome での実操作はしていない。** キーボードだけの操作（Tab・矢印でのタブ移動、
  フォーカス表示）、実際のタッチ操作、IME での入力、画面読上げ、ダークモードの表示は確かめていない。
  狭い画面はモバイル表示のエミュレーション（`Emulation.setDeviceMetricsOverride`）で、実機の端末ではない。
- headless Chromium 156 だけで、Firefox・Safari・ほかの版は試していない。Chromium はコンテナ内で
  `--no-sandbox` で動かした。
- 通常・劣化の入力は製品の生成関数で書いた fixture で、daemon が実際に動いて書いたものではない
  （NOC だけはコンテナの実観測）。daemon を止めたときに snapshot が古くなる経路は、ここでは
  ファイルを古い時刻で書いて代用した。
- systemd リハーサルの「権限なし」は、snapshot の leaf（`2750 <writer>:azazel-operator`）に
  `azui` が入れないことによる。読取グループを作るかどうか（オーナー判断）はここで決めていない。
- x86_64 は Rosetta エミュレーション。x86_64 の systemd では UI を動かしていない。
- 外部通信 0 件はページの要求について。Chromium 自身の背景通信は止めきれず（上の結果 #8）、
  `--network none` で失敗した。ネットワークがある環境で Chromium が自分で外へ出ることは、UI の性質ではなく
  ブラウザの設定の問題として残る。
