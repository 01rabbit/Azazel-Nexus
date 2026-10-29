# Arm VM での受入（V1〜V3）と VM 上の全件試験：2026-10-29

**Arm VM（VMware Fusion、Apple silicon のホスト）での VM ソフトウェア統合の証拠（ADR-0003 D5）。
実機の証拠ではなく、ハードウェアゲートを閉じない。** [実機受入](../hardware-acceptance.md) §4 の
V1〜V3 をこの VM 1 台で行った記録の索引と、V3・全件試験・共通試験ベクトルの本文。
原本は [`arm-vm-acceptance-vm-arm64-2026-10-29/`](arm-vm-acceptance-vm-arm64-2026-10-29/)。

| 項目 | 結果 | 記録 |
| --- | --- | --- |
| V1 `tools/vm_integration.py`（kernel の再起動を含む） | pass 55 / fail 0 / skip 2。うち 24 件は Edge Core の逸脱（D1）の上での pass（Edge Core は arm64 の pin が無いまま aarch64 の実バイナリで実行） | [vm-integration-vm-arm64-2026-10-29.md](vm-integration-vm-arm64-2026-10-29.md) |
| V2 arm64 lab のオフライン導入（systemd 段まで） | 導入 exit 0、unit は masked、host は `debian-13-arm64-cp313-lab`、本番用途 5 つは `LAB_PROFILE_NOT_FOR_PRODUCTION`、Edge slot は build・verify・install のすべてで拒否 | [offline-install-aarch64-lab-vm-2026-10-29.json](offline-install-aarch64-lab-vm-2026-10-29.json) |
| V3 仮想化センサー | `dmi_vendor`・`dmi_product` が observed、`cpu_hypervisor` は clear。`systemd-detect-virt` は `vmware` | 下の §V3、[JSON](arm-vm-acceptance-vm-arm64-2026-10-29/v3-virtualization-sensors.json) |
| tests/unit 全件（参考） | 最終の実行で 5 failed, 17529 passed, 166 skipped, 2 deselected。5 件はすべて環境由来と判断（下の §全件試験） | [要約](arm-vm-acceptance-vm-arm64-2026-10-29/unit-suite-summary.txt) |
| 共通試験ベクトル（参考） | VM の 13 件の digest が pin と一致し、amd64（Rosetta のコンテナ）とも一致 | [JSON](arm-vm-acceptance-vm-arm64-2026-10-29/cross-arch-vectors-vm-vs-amd64-rosetta.json) |

## 条件（共通）

| 項目 | 値 |
| --- | --- |
| 基盤 | VMware Fusion（macOS、Apple silicon）。ゲストは Debian 13.7 arm64、kernel 6.12、systemd 257、4 vCPU、RAM 約 2.9 GiB、Debian の CPython 3.13.5 |
| 対象 commit | `7ef1702`（main） |
| 開始状態 | 作業前の snapshot S0 から、過去の Azazel 導入の残骸を手で除いたもの（新しく入れた OS ではない）。V1 と V2 はそれぞれこの状態から始め、終了後に S0 へ戻した |
| ネットワーク | VM の NIC は 2 本とも VMware の host-only。VM に IPv4・IPv6 の既定経路は無く、名前解決できず、外部への TCP 接続は `Network is unreachable`。これは S0 の状態そのもので、この作業で変えていない。host-only の側の macOS ホストとだけ通信でき、制御（ssh）と持込みに使った |
| build host（V2・V1 の wheelhouse） | colima の既定 context（aarch64、ネイティブ）上の `debian:trixie` linux/arm64 コンテナ（`--rm`）。uid 1001、umask 022、commit の clean な clone。**VM 自身ではない** |
| 試験・ベクトルの実行 | VM 上の非 root ユーザー（uid 1000）、umask 022。main の checkout を VM 上の user venv に `pip -e` で入れたもの（依存は lab の wheelhouse と pytest・PyNaCl の wheel から `--no-index`） |

使わなかったもの：`~/azn-sign`、本番の鍵、実モデル。`LOCAL_MODEL_ADMISSION_ENABLED` と実機検証ゲートには
触れていない。テスト用の鍵（公開 fixture と V1 のラボ鍵）は VM の中だけで使い、VM は S0 に戻した。

## V2 の要点

記録の本体は [JSON](offline-install-aarch64-lab-vm-2026-10-29.json)（`azazel-nexus/prototype-offline-install-evidence/v1`、
`scope` に VM であることを記載。§5 に従い digest は書いていない）。

- build：`build_wheelhouse.py --target debian-13-aarch64-cp313` と `build_offline_bundle.py` が exit 0
  （346 member、slot はすべて空）。Edge package を渡した build は exit 2 で拒否
  （`carries no Edge package ... no Edge pin exists for this one`）。
- VM（root、compiler なし、上のネットワーク状態）：一部を反転したコピーは展開前に拒否。
  Edge slot を埋めた bundle（builder の拒否 2 つを、使い捨ての harness の中だけで無効にして作った
  **攻撃用の入力**。製品の経路ではない）は `verify` でも `install` でも同じ理由で拒否され、
  展開先も venv も作られなかった。
- 本来の bundle を `offline_bundle.py install --run-installer` で導入：exit 0。lock の照合・
  `pip check`・import・recheck が pass、`install.sh` の systemd 段まで実行（`--without-service-manager`
  は使っていない）。運用 unit 16 個が masked、`azazel-activated` と `azazel-edge-probe-preflight` だけが
  enabled、何も動いていない。
- 導入した runtime は host を `debian-13-arm64-cp313-lab` / `lab-software-verification` と観測し、
  `require_deployment_baseline` は 5 つの本番用途（core-reserve-record・hardware-gate-record・
  hil-preflight・model-admission・product-admission）をすべて `LAB_PROFILE_NOT_FOR_PRODUCTION` で拒否。
- `systemctl reboot` の後（新しい boot id）：起動時の pass は `granted=0, withheld=16, reasons=no_generation`、
  unit はすべて masked・inactive のまま。
- オフライン導入はラボ印を書かない（V1 の道具だけが書く）。

## V3 仮想化センサー

[ADR-0003 R1](../adr/0003-arm-software-verification-profile.md#known-differences-and-follow-up-changes) の値を
決めるための観測であり、判定ではない。`observe_virtualization()` を、main の checkout を入れた user venv と、
V2 で導入した本番 venv（root）の両方から呼び、同じ値を得た。

| センサー | 値 | 読んだもの |
| --- | --- | --- |
| `hypervisor_type` | `absent` | `/sys/hypervisor/type` が無い |
| `cpu_hypervisor` | `clear` | `/proc/cpuinfo` に `hypervisor` の語が無い（x86 の flag は arm64 に無い。R1 の予想どおり） |
| `systemd_container` | `absent` | `/run/systemd/container` が無い |
| `dockerenv` | `absent` | `/.dockerenv` が無い |
| `dmi_vendor` | `observed` | `sys_vendor` が `VMware, Inc.` |
| `dmi_product` | `observed` | `product_name` が VMware の汎用の型名（個体の識別子ではない） |
| `init_cgroup` | `clear` | `0::/init.scope` |

`systemd-detect-virt` は `vmware`（`--vm` も `vmware`、`--container` は `none`）。arm64 でも DMI
（ACPI の OEM id も VMware）から仮想化が読める。`/sys/firmware/devicetree/base/hypervisor` は無い
（ACPI で起動）。CPU の implementer は Apple。

**基盤は VMware Fusion の 1 つだけ。** Apple Virtualization・QEMU/KVM・UTM・Parallels と、
Arm の実機（否定側）は観測していない。R1 の対処は別の PR で決める。

## 全件試験

ci.yml と同じ 2 件の `--deselect`、非 root（uid 1000）、umask 022、Python 3.13.5。VM 上で 1 本ずつ、
`suite-lock.sh` で直列化して 3 回実行した。集計行はそのまま：

| 実行 | 条件 | 集計行 |
| --- | --- | --- |
| 1 | `TMPDIR=/tmp`（tmpfs 1.5 GiB）、interpreter を `../venv/bin/python` で起動 | `186 failed, 17348 passed, 166 skipped, 2 deselected, 2 warnings in 275.88s` |
| 2 | `TMPDIR` をホーム配下の ext4（長いパス）、interpreter は絶対パス | `5 failed, 17529 passed, 166 skipped, 2 deselected, 3 warnings in 292.07s` |
| 3 | `TMPDIR=/var/tmp/azp`（ext4）、interpreter は絶対パス | `5 failed, 17529 passed, 166 skipped, 2 deselected, 3 warnings in 277.75s` |

あわせて実行 3 の後に `bench`（`53 passed in 0.49s`）と `tools/check_docs_links.py`
（`internal links OK (148 Markdown files checked)`）が通った。Fabric の extra を入れた全件は
行っていない（Fabric の wheel は lab の wheelhouse にあるが、`.[fabric]` は git の URL を指すため、
外に出られない VM では入れていない）。

失敗の分類（製品の欠陥は見つかっていない。下はすべて試験の前提と環境の不一致）：

| 失敗 | 実行 | 原因（確認の方法） |
| --- | --- | --- |
| `test_mission_pack`・`test_model_acquire_e2e`・`test_model_import`・`test_playbook_selection` など 177 件 | 1 | `TMPDIR` の tmpfs が 1.5 GiB で、製品の空き容量の床 `MIN_FREE_BYTES`（2 GiB）を下回る（`insufficient disk budget before staging`・`insufficient_disk`）。ext4 の `TMPDIR` では通った |
| `test_stage_runtime_entrypoints` 7 件 | 1 | interpreter を `src/../venv/bin/python` で起動したため、製品の `canonical absolute Python interpreter path required` が正しく拒否した。絶対パスで通った |
| `test_knowledge_lited.py::test_socket_round_trip_and_refusals` | 2・3 | `TMPDIR` のパスが長く、socket のパスが 107 byte を超えた（製品の `SocketMisconfigured` が理由を示して拒否）。`/tmp` の実行 1 では通った |
| `test_exposure_route_dump.py::test_the_dump_equals_ip_j_in_a_fresh_namespace` | 2・3 | `unshare --user --map-root-user --net` の中の `ip rule add ... uidrange 1-2` を kernel が `Invalid uid range` で拒否（この user namespace に写像されているのは uid 0 だけ）。VM 上で同じコマンドを手で実行して再現 |
| `test_so06_edge.py::test_a_library_that_freezes_the_monotonic_clock_is_refused` | 1・2・3 | 試験は `CLOCK_MONOTONIC` を 3600 秒に固定した preload の下で `time.sleep(0.02)` を呼ぶ。CPython の sleep は monotonic の絶対時刻で待つので、起動から 1 時間未満のノードでは固定値が未来になり、60 秒の timeout まで戻らない（`timed out after 60 seconds`）。起動から 1 時間以上たった colima などでは通る |
| `test_runtime_bootstrap_journal_retire.py::test_mask_changed_during_audit_refuses_before_any_mutation`、`test_runtime_bootstrap_journal_reboot_reset.py::test_prior_boot_fence_check_refuses_after_change[mask]` | 2・3 | 試験は mask の symlink を消して同じ `/dev/null` への symlink を作り直し、変更の検出を期待する。ext4 では作り直した symlink が同じ inode 番号と同じ時刻になることが多く（VM 上で 2000 回中 1996 回）、stamp が同じになる。tmpfs では 3 回とも pass、ext4 では 3 回中 1 回失敗。作り直した mask は所有者・種類・指す先（`/dev/null`）が毎回検査されるので、見逃されるのは中身の同じ差替えだけである（製品の検査を弱める経路ではないと判断。仮説ではなく、上の再現で確認） |

## 共通試験ベクトル

VM 上で `python tests/vectors/cross_arch.py`（uid 1000、umask 022）を実行し、同じ commit を
colima-rosetta の `python:3.13` linux/amd64 コンテナ（**Rosetta による変換。amd64 の実機ではない**）で
実行した出力と `tools/cross_arch_vectors.py --compare` で突き合わせた。13 件すべてで
`all_equal: true`、`all_match_pins: true`。`--compare` は 1 つ目の出力を「colima の aarch64
コンテナ」と名付けるので、保存した JSON ではその欄を VM と書き直し、`note` に経緯を書いた。

## これが示さないもの

- 実機（Arm・amd64）での挙動、実 NIC、実記憶域、電源断、TPM、Secure Boot、性能、メモリ余力。
- arm64 の Edge Core の配備（pin が無い）。V1 の Edge Core の検査は逸脱の上での pass。
- 通常の activation 経路（承認・lease・generation）、実モデル、オンライン AI、Mission Pack。
- VMware 以外の仮想化基盤での値。新しく入れた OS からの導入。
- Fabric extra を入れた全件試験、Python 3.11・3.12 での VM 上の全件。

## 手順（再現）

- V1：[vm-integration-vm-arm64-2026-10-29.md の手順](vm-integration-vm-arm64-2026-10-29.md#手順再現)。
- V2：[Debian Live の導入メモの Offline install bundle](../debian-live-install.md#offline-install-bundle) の Arm lab target。
  build は aarch64 のコンテナ、install は VM 上の root 所有の reviewed checkout から
  `python3 -I tools/offline_bundle.py install --bundle B --into /var/lib/azazel-offline/bundle --venv /opt/azazel-nexus/venv --python /usr/bin/python3 --run-installer`。
- V3：導入した venv の Python で
  `python -I -c 'from azazel_nexus_runtime.virtualization_observation import observe_virtualization as o; print(o())'`
  と `systemd-detect-virt`。
- 全件：VM 上の非 root ユーザーで `umask 022; TMPDIR=<ext4 の短いパス> <venv の絶対パス>/python -m pytest tests/unit -q -p no:cacheprovider --deselect ...（ci.yml と同じ 2 件）`。
