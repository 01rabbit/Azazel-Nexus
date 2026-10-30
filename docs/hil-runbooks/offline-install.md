# Offline install bundle — install on target hardware through the systemd stage

## 概要（日本語）

[#346](https://github.com/01rabbit/Azazel-Nexus/pull/346) のオフライン install bundle を、
対象実機（Debian 13 x86_64、ネットワーク無し）で root により導入し、`install.sh` の
systemd 段（daemon-reload、運用 unit の mask、活性化コントローラの enable）まで通す手順。
あわせて、非 root での導入が拒否されること、Edge の pin
（packaging/offline/edge-artifact.sha256）が無い checkout では Edge slot が拒否される
ことを確かめる。

**bundle は署名されていない**（報告は常に `bundle_authenticated: false`）。recheck は
展開後の書き換え（TOCTOU）を防ぐだけで、**root での導入は bundle に入ったコード
（自前の wheel 2 つと install.sh など）を実行する**。媒体の管理だけが攻撃者との間に
ある。VM・コンテナの結果は証跡にならない。ゲートの状態は変えない。

Status: **not run; hardware-unverified**. Owner: [#346](https://github.com/01rabbit/Azazel-Nexus/pull/346)
(merged software); related gate [HG-01](hg-01.md) (#115 pilot, #4 campaign).

Use the [campaign](../hil-campaign.md), the [evidence rules](../hil-evidence-records.md),
the [offline install bundle contract](../debian-live-install.md#offline-install-bundle)
and [HG-01](hg-01.md). Where this runbook and the code disagree, the code wins:
`tests/unit/test_runbook_references.py` and
`tests/unit/test_hil_runbook_merged_features.py` check what is named here.

## 0. Scope and what exists already

| Evidence class | What exists for #346 | What it does not show |
| --- | --- | --- |
| mock | `tests/unit/test_offline_install_bundle.py`: every refusal, the caps, the lock check, recheck, the Edge pin gate | a real interpreter ABI or systemd |
| real process | the same tests build and extract real archives | — |
| Linux service integration | [container evidence](../evidence/offline-install-container-2026-10-28.json): `--network none`, x86_64 under Rosetta emulation, `install.sh` with `--without-service-manager` — the systemd stage did **not** run | the target ABI, systemd, real accounts; it is not hardware evidence |
| target hardware | **none** — this runbook | — |

**Before you start, accept what root runs.** Until bundle signing exists,
installing as root executes bundle-supplied code: the two Nexus wheels
(pinned by version only), `install.sh` and the tools it runs all come from the
bundle. Build the bundle yourself from a reviewed checkout (§1), keep custody
of the medium from build host to DUT, and treat a bundle of unknown custody as
untrusted: do not install it.

## 1. Build the bundle (separate x86_64 build host, online)

The build host is Debian 13, x86_64, Debian's CPython 3.13 with `python3-dev`,
a C compiler and `git` (the pinned Fabric wheel is rebuilt from its tagged
commit and must reproduce the locked hash; ADR-0004), from a clean reviewed
checkout at the commit under test.
It is not the DUT. As an ordinary user with umask 022 and a 0755 output
directory:

```sh
python3 tools/build_wheelhouse.py --output /path/to/wheelhouse
python3 tools/build_offline_bundle.py --output /path/to/azazel-nexus-offline.tar.gz --wheelhouse /path/to/wheelhouse
sha256sum /path/to/azazel-nexus-offline.tar.gz
```

The wheelhouse build refuses any architecture or interpreter other than
x86_64 CPython 3.13 (target `debian-13-x86_64-cp313`, the default). The
aarch64 lab target of [ADR-0005](../adr/0005-arm-lab-offline-target.md) is
never used for this runbook. Keep the bundle's
sha256 in the protected record only; it identifies the bundle you will carry,
it does not authenticate it.

For §3.2 only, build a **second** bundle that carries an Edge slot. The build
itself verifies the slot against the checkout's Edge pin, so this needs a
**throwaway copy** of the checkout with a rehearsal-only pin file added
(packaging/offline/edge-artifact.sha256 holding one `<sha256>  <name>` line
for the real Edge artifact, two spaces). Never commit, push or carry that
pin back into the reviewed checkout: pinning a released Edge artifact is an
owner decision. Delete the throwaway copy afterwards.

```sh
python3 tools/build_offline_bundle.py --output /path/to/azazel-nexus-offline-edge.tar.gz --wheelhouse /path/to/wheelhouse --edge-package /path/to/edge-package --edge-source 'Azazel-Edge packager, commit and build host noted in the record'
```

`/path/to/edge-package` holds exactly `azazel-edge-core-0.1.0-x86_64.manifest.json`
and `azazel-edge-core-0.1.0-x86_64.tar.gz` from Azazel-Edge's packager, as in
[HG-07](hg-07.md) step 1.

## 2. The DUT before installation

1. Start from the approved clean target image (Debian 13, x86_64, systemd as
   PID 1) with Debian's `python3` and `python3-venv` already present (the
   bundle does not carry an interpreter), no network, local console, and the
   [HG-01](hg-01.md) independent capture running on every attached link.
2. Place a reviewed checkout of the same commit on the DUT, root-owned and not
   group/other-writable; the verifier is run from it, never from the bundle.
   Copy the bundle from the custody medium and compare its sha256 with the
   build host's.
3. `install -d -m 0755 /var/lib/azazel-offline /opt/azazel-nexus` as root:
   the parents of `--into` and `--venv` must exist, be root-owned and not
   group/other-writable. `/var/lib/azazel-offline/bundle` and
   `/opt/azazel-nexus/venv` must not exist.

`CHECKOUT` below is the reviewed checkout's absolute path.

## 3. Install refusals

### 3.1 Not as root

As an ordinary account:

```sh
python3 -I CHECKOUT/tools/offline_bundle.py install --bundle /path/to/azazel-nexus-offline.tar.gz --into /var/lib/azazel-offline/bundle --venv /opt/azazel-nexus/venv --python /usr/bin/python3 --run-installer
echo "exit=$?"
```

Expect exit `2`, nothing on standard output, and on standard error a JSON
object with `"bundle_authenticated": false` and the refusal
"install runs as root, so the extracted tree, the venv and everything
install.sh later runs are root-owned and no unprivileged account can change
them in between". Nothing may be created under `/var/lib/azazel-offline` or
`/opt/azazel-nexus`.

### 3.2 Edge slot with no reviewed pin

The reviewed checkout ships no Edge pin. As root, verify the Edge-carrying
bundle of §1 against it:

```sh
sudo python3 -I CHECKOUT/tools/offline_bundle.py verify --bundle /path/to/azazel-nexus-offline-edge.tar.gz --into /var/lib/azazel-offline/edge-check
echo "exit=$?"
```

Expect exit `2` and the refusal "the reviewed checkout pins no Edge artifact
(packaging/offline/edge-artifact.sha256); an Edge slot is refused before it is
parsed", with `"bundle_authenticated": false`, and
`/var/lib/azazel-offline/edge-check` absent afterwards. An Edge slot accepted
by the reviewed checkout is a failure. Do not add a pin to the DUT's checkout
to make it pass.

## 4. Install through the systemd stage

As root, from the reviewed checkout, with the capture of §2 running:

```sh
sudo sh -c 'umask 022; python3 -I CHECKOUT/tools/offline_bundle.py install --bundle /path/to/azazel-nexus-offline.tar.gz --into /var/lib/azazel-offline/bundle --venv /opt/azazel-nexus/venv --python /usr/bin/python3 --run-installer > /root/offline-install-report.json'
echo "exit=$?"
sudo /opt/azazel-nexus/venv/bin/python -I -c 'import json; r = json.load(open("/root/offline-install-report.json")); print(r["schema"], r["bundle_authenticated"], r["signature"]["present"], r["install"]["pip_check"], r["install"]["imports"], r["recheck"]["recheck"], r["installer"]["exit"], [k for k, v in r["slots"].items() if v["state"] != "empty"]); t = r["installer"]["stdout_tail"]; print("installed" if "Azazel-Nexus installed. Operational units are masked." in t else "NOT INSTALLED", "stage-skipped" if any(l.startswith("SERVICE-MANAGER STAGE NOT EXECUTED") for l in t) else "stage-ran", repr(t[-1:]))'
```

Pass for this step needs, all of:

- exit `0`; the report's `schema` `azazel-nexus-offline-bundle-report@1`,
  `bundle_authenticated` false, `signature.present` false, `pip_check`
  `pass`, `imports` `pass`, `recheck` `pass`, installer `exit` 0, no filled
  slot;
- the interpreter probe passed (a mismatch refuses with
  `'x86_64 cpython 3 13'` in the message; that is a failed target ABI, not a
  skipped step);
- the installer's closing output (the report keeps the last lines of its
  standard output as `stdout_tail`): it contains
  `Azazel-Nexus installed. Operational units are masked.`, which `install.sh`
  prints after the systemd stage and follows it with two more lines, the
  last being `admitted until the required admission and health evidence is available.`;
  the script prints `installed`, `stage-ran` and that last line. **No** line
  `SERVICE-MANAGER STAGE NOT EXECUTED: no unit was masked or enabled.` may
  appear (`stage-skipped`): it means the systemd stage did not run, which
  fails this runbook.

Then read the systemd state the stage left:

```sh
systemctl --version | head -n 1
systemctl list-unit-files 'azazel-*'
for u in $(systemctl list-unit-files 'azazel-*' --no-legend | awk '{print $1}'); do printf '%s %s %s\n' "$u" "$(systemctl is-enabled "$u" 2>&1)" "$(systemctl is-active "$u" 2>&1)"; done
stat -c '%U %a' /opt/azazel-nexus/venv
```

Expect every governed operational unit `masked` and inactive — the
installer masks `azazel-commissiond.service`, `azazel-auditd.service`,
`azazel-auditd-loop.service`, `azazel-watchdog.service`, `azazel-edge-core.service`,
`azazel-edge-probed.service`, `azazel-incident-explaind.service`,
`azazel-edge-intaked.service`, `azazel-model-fetchd.service`,
`azazel-mio-locald.service`, `azazel-mio-remoted.service`,
`azazel-mio-entryd.service`, `azazel-mio-referenced.service`,
`azazel-knowledge-lited.service`, `azazel-decoy-nsd.service`,
`azazel-decoy-netd.service` and `azazel-decoyd.service` — and only
`azazel-activated.service` and `azazel-edge-probe-preflight.service`
`enabled`. Cross-check the masked set against the installed
`packaging/install.sh` from the bundle, not against this list alone. The venv
must read `root 755`. Continue with [HG-01](hg-01.md) steps 3–6 (the
`az-hil-capture hg-01` acquisition, a reboot without activation, the capture
correlation); this runbook's install is HG-01's installation step done from
the bundle.

`tools/e2e.py` always reports its "units masked and disabled" stage as not
executed, also on a host with systemd; it is not a substitute for the reads
above.

## 5. Failure handling

If any refusal occurs before `install.sh`, the extracted tree and the venv
are removed: record the refusal and stop. If `install.sh` exits non-zero, the
tree and venv are kept for inspection and the host may be partly changed:
stop, keep the DUT isolated, and recover by re-imaging, not by repairing the
install. An unexpectedly active or unmasked unit fails the run as in
[HG-01](hg-01.md); remediation never turns the original install into a pass.

## 6. Record

Retain in the protected HIL archive, never in Git, an issue or a PR: the
reviewed commit, the build host class (Debian release, Python, architecture),
the bundle's custody chain, the refusals of §3 (exit status and fixed
refusal text), the report fields of §4 named above, the installer's last
line, the systemd version and the per-unit enabled/active states, and the
HG-01 capture results. Keep the bundle sha256 and the full report only inside
the protected record. Never record the rehearsal-only Edge pin, any digest
outside the protected record, boot ids, addresses, MACs or interface names.

The outcome is `passed`, `failed` or `not-run` in the
[vocabulary](../hil-evidence-records.md). A pass is the target-ABI and
systemd-stage confirmation the
[offline bundle table](../debian-live-install.md#offline-install-bundle)
says is missing. It does not sign the bundle, does not pin an Edge artifact,
admits nothing carried in a slot, and closes HG-01 only through HG-01's own
record and validator.
