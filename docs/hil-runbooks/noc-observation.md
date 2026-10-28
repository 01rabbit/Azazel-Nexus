# Read-only NOC observation — no transmission on target hardware

## 概要（日本語）

[#344](https://github.com/01rabbit/Azazel-Nexus/pull/344) の `az-nexus-noc` を対象実機
（Debian 13 x86_64）で確かめる手順。実行中に観測ロールのインターフェイスを
**独立した機器**でキャプチャし、その IF から出たフレームが 0 であることを確認する
（[SO-10](../service-objectives.md#so-10-field-exercise--hardware-only) と
[HG-03](../hardware-gates.md#hg-03--an-observation-interface-transmits-nothing) の
実験に組み込む）。あわせて、使うソケットが AF_NETLINK だけであること、出力に
インターフェイス名・MAC・アドレス類が出ないことを確かめる。DUT 上のカウンタや
DUT 上のキャプチャは証拠にならない。VM・コンテナの結果も証跡にならない。
ゲートの状態は変えない。

Status: **not run; hardware-unverified**. Owner: [#344](https://github.com/01rabbit/Azazel-Nexus/pull/344)
(merged software); SO-10/HG-03 owner [#17](https://github.com/01rabbit/Azazel-Nexus/issues/17),
linked by [#4](https://github.com/01rabbit/Azazel-Nexus/issues/4).

Use the [campaign](../hil-campaign.md), the [evidence rules](../hil-evidence-records.md)
and the [NOC observation contract](../noc-observation.md). Where this runbook
and the code disagree, the code wins:
`tests/unit/test_runbook_references.py` and
`tests/unit/test_hil_runbook_merged_features.py` check what is named here.

## 0. Scope and what exists already

| Evidence class | What exists for #344 | What it does not show |
| --- | --- | --- |
| mock | `tests/unit/test_noc_observe.py`: parsers, unknown reasons, redaction against fixture values, the static socket scan | a kernel |
| real process | the same file runs the command against a real Linux kernel's netlink in the test container | target NICs and drivers; it is container evidence, not hardware |
| Linux service integration | none run: `azazel-noc-observe.service` and its timer exist (U3), generated from their declaration, but have not run under systemd | — |
| target hardware | **none** — this runbook | — |

The command's own output says what it is not evidence for: its
`not_evidence_for` list names SO-10 zero-transmit, and its `tx_packets_delta`
is a counter on the device under test. **Neither the command's output nor any
DUT counter or DUT-local capture is evidence of silence.** Only the
independent capture of §3 is.

## 1. Preconditions

1. The DUT satisfies the [campaign](../hil-campaign.md) prerequisites and has
   a **commissioned observation role** resolved against the physical adapter,
   as SO-10 step 1 requires.
2. An independent physical capture on the observation link — a second host,
   tap or switch mirror feeding an independent recorder — set up exactly as
   SO-10 steps 2–3 describe, with direction attribution verified and capture
   health/drop counters recorded. An incomplete or dropping capture makes the
   run inconclusive, never a pass.
3. Nexus installed from a reviewed checkout containing #344; the command is
   the console script `/opt/azazel-nexus/venv/bin/az-nexus-noc`. It needs no
   root: run it as an unprivileged account (the responsible operator's own),
   and record which. If it only works as root on this image, record that as a
   finding; do not change permissions to make it work.

## 2. The command on the DUT

```sh
/opt/azazel-nexus/venv/bin/az-nexus-noc --interval 1
echo "exit=$?"
```

Expect exit 0 and exactly one line of JSON on standard output, nothing on
standard error. Check its fixed parts (read on the DUT; do not export the
line):

- `schema` is `azazel-nexus/noc-observation-local/v1`;
- `transmission.sockets` is `AF_NETLINK/NETLINK_ROUTE only`,
  `transmission.requests` is `RTM_GETADDR`, `RTM_GETLINK`, `RTM_GETROUTE` and
  `transmission.active_checks` is `none`;
- `uplink.reachability` and `dns.resolution` are `unknown` with reason
  `active_check_not_performed`;
- every interface's `role` is `unknown` with `role_evidence_not_provided`
  (roles are not wired into the command).

A failure prints only `az-nexus-noc: collection_failed` on standard error and
exits 1; that is a classified failure of this step, not a silence result.
`--interval` outside 0.2–10.0 seconds is refused by the argument parser
(exit 2). Record each unknown field's reason word (for example
`speed_not_reported`, `no_lease_file`), which says what this hardware's
drivers and network stack report.

### 2.1 Socket families

If `strace` is approved on the DUT image:

```sh
strace -f -e trace=socket,connect,bind -o /root/noc-strace.txt /opt/azazel-nexus/venv/bin/az-nexus-noc --interval 1 >/dev/null
grep -c 'socket(AF_NETLINK' /root/noc-strace.txt
grep -E 'socket\(AF_(INET|INET6|PACKET|UNIX)|connect\(|bind\(' /root/noc-strace.txt
```

Expect `4` netlink sockets (one to locate interfaces, then one each for the
link, address and route dumps) and no line from the second `grep`. Any other
socket family, `connect` or `bind` is a failure. Without `strace`, this step
is `not-run`; the static scan and runtime check of §0 remain software
evidence only. Delete the trace afterwards: it can hold paths and names.

### 2.2 Nothing identifying is printed

Collect, as root, the DUT's own identifiers into a root-only file and search
the command's output for them. Never print, copy or export the identifier
list:

```sh
sudo install -d -m 0700 /root/noc-check
sudo sh -c 'ip -o link show | awk -F": " "{print \$2}" | cut -d@ -f1; cat /sys/class/net/*/address; ip -o addr show | awk "{print \$4}" | cut -d/ -f1; ip -o route show | awk "\$2 == \"via\" {print \$3}"; awk "/^nameserver/ {print \$2}" /etc/resolv.conf /run/systemd/resolve/resolv.conf 2>/dev/null; awk "/^search|^domain/ {for (i = 2; i <= NF; i++) print \$i}" /etc/resolv.conf' | grep -v '^$' | sort -u | sudo tee /root/noc-check/identifiers >/dev/null
/opt/azazel-nexus/venv/bin/az-nexus-noc --interval 1 | sudo tee /root/noc-check/output.json >/dev/null
sudo grep -cwFf /root/noc-check/identifiers /root/noc-check/output.json
```

Expect `0`. A match on an interface name, MAC, address, gateway or
nameserver is a failure: keep the output in the protected record only, and
report the field name, never the matched value. A search domain that is also
an ordinary word can match the command's fixed text; attribute such a match
from the protected output before classifying it. Remove
`/root/noc-check` after the run.

This search finds the identifiers only in the form the tools above print
them. A MAC or address rendered in another form (upper case, without
separators, an IPv6 address written differently, a reversed or encoded form)
would not match, so a `0` here is evidence against the plain forms only; the
code's guarantee rests on what it parses past (§0), not on this search.

## 3. No frame on the observation link while it runs

Run inside an SO-10 run, so that the stress, timing and attribution rules of
[SO-10](../service-objectives.md#so-10-field-exercise--hardware-only) apply
unchanged:

1. Start the independent capture first (SO-10 step 4).
2. On the DUT, as the account of §1, start the command in a loop **before**
   the recorder marks `independent-capture-stress-start`. It logs each run's
   wall-clock start, end and exit status and runs until a stop file appears;
   its output is discarded:

   ```sh
   rm -f ~/noc-stop; : > ~/noc-runs.log
   while [ ! -e ~/noc-stop ]; do s=$(date +%s.%N); /opt/azazel-nexus/venv/bin/az-nexus-noc --interval 1 >/dev/null 2>&1; rc=$?; echo "$s $(date +%s.%N) $rc" >> ~/noc-runs.log; done
   ```

   Create the stop file (`touch ~/noc-stop`) only **after** the recorder marks
   `independent-capture-stress-stop`. Record both moments, and the loop's
   start and stop, in the stress event log in that order. Then summarise:

   ```sh
   awk '{n++; if ($3 != 0) f++} NR > 1 {g = $1 - e; if (g > m) m = g} {e = $2} END {print "runs", n, "failed", f + 0, "max_gap_s", m + 0}' ~/noc-runs.log
   ```
3. Drive the SO-10 stress operations (link up/down, IPv6 RA, DHCP
   offers/requests, a DUT suspend/resume) as SO-10 step 5 requires; HG-03
   adds a driver reload. The command keeps running across them.
4. On the **independent recorder**, count every frame attributed to the
   observation interface's outgoing link over the interval, including ARP,
   DHCP, IPv6 RS/NS/NA, mDNS, LLDP and 802.1X (SO-10 step 6).

Pass only if, all of:

- the count is exactly `0` with a healthy, non-dropping capture;
- `failed` is `0`: **every** run of the command exited 0. A run that failed
  did not observe anything, so a silence over failed runs says nothing about
  the command;
- the runs **cover the whole stress interval**: the loop started before
  `independent-capture-stress-start` and stopped after
  `independent-capture-stress-stop` (from the event log), and `max_gap_s` is
  below one second except for gaps that the event log matches to the DUT's
  own suspend (the command cannot run while the DUT is suspended).

A loop that did not cover the interval, or a gap that the event log does not
explain, makes the run **inconclusive** for the command (the SO-10 silence
result itself is unaffected). One frame fails, whatever its apparent origin:
attribute it from the capture and keep it. This run is an SO-10 run with the command added, not a separate
claim: its silence result counts for SO-10/HG-03 only through the SO-10
record and validator (`python -m tools.service_objectives`), with all three
runs per class. Add to that record's manifest that `az-nexus-noc` ran during
the interval, the number of runs and the commit; do not add a field the
validator does not define.

The command reads netlink and files and opens no interface, so a zero count
here says that nothing on the node, the command included, transmitted on
that link during the run. It says nothing about the management link or any
other interface; capture those separately if they are in question.

## 4. Record

Retain in the protected HIL archive, never in Git, an issue or a PR: the
installed commit, the account used, the §2 fixed-part checks and the unknown
reason words, the §2.1 socket count, the §2.2 match count, and the SO-10 run's
record, captures and manifest. Do not record the command's full output (its
counts describe the node's topology), interface names, MACs, addresses,
gateway, nameservers, search domains, boot ids or capture contents outside the
protected SO-10 manifest.

The outcome is `passed`, `failed` or `not-run` in the
[vocabulary](../hil-evidence-records.md). A pass here does not wire roles into
the command, does not implement active checks, and is no Edge NOC evaluation;
the owner decisions of [NOC observation §8](../noc-observation.md#8-owner-decisions)
are unchanged.
