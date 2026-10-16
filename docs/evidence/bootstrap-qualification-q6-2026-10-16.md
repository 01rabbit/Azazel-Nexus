# Bootstrap factory qualification: Q6 audit and commission peer proofs on a sandbox fixture (test VM, 2026-10-16)

Scope: Debian 13 test VM, systemd 257.13, build c79291b; not hardware evidence; production factory unchanged.
Definition: Q6 in `docs/evidence/bootstrap-factory-switch-review-2026-10-16.md`. Fixture-scoped: the result below does not qualify the product units.
Method: one transient unit `q6fix-sandbox-<stamp>-<pid>` (PrivateMounts, PrivateTmp, Delegate with a `driver` subgroup, RuntimeMaxSec=180, AF_UNIX/AF_NETLINK only, IPAddressDeny=any) held a private mount namespace.
Inside it, tmpfs was mounted over the five leaf directories and a datagram sink over `/run/systemd/notify`. The INSTALLED `az-auditd` and `az-commissiond` ran as their service users (setpriv, no supplementary groups, no_new_privs, umask 0027, `env -i`).
The real `peer_credentials`, audit and commission peer proofs and the real audit/commission clients ran against them. Identities (MainPID, owner, digest) were synthetic. A fixture root is impossible (the peers refuse `ROOT != "/"`), so real absolute paths were kept and only the leaves were shadowed.
The cgroup string was exercised through a mimic cgroup namespace: the daemons sat in `<unit>/mimic/system.slice/azazel-{auditd,commissiond}.service`, and the proof reader entered a cgroup namespace rooted at `<unit>/mimic`, so the kernel printed the fixed strings.
Harness: `q6-run.sh`, `q6_proof.py`, `README-q6.md` (design, per-check feasibility, Gate A expected outcome). Raw outputs (`inner.log`, before/after snapshots and diffs) are retained in the operator's scratch area.
Cleanup: the fixture unit was collected; no product unit was started, stopped, masked, enabled or reloaded; the real ledger was untouched.

## Run history (orchestrator-observed console output)

| Run | Outcome |
|---|---|
| 1 (build c79291b, Debian 13 test VM, boot 8c3dd0e1-...) | Daemons started, READY=1 x2. PRE-ROOT, N0, P0-fixture-cgroupns, P0-namespaces, P1-peercred-raw and N1 x2 PASS. P0-daemon-cgroup audit/comm, P1-audit-observe and P2-commission FAILED and the proof crashed (FileNotFoundError in `move()`). Root cause was in the HARNESS: `echo $$ > cgroup.procs` in a `( )` subshell moved the driver shell, not the daemon. Fixed by exec'ing via `sh -c` and verifying placement. drift=0. |
| 2 | `systemd-run` rc=203: the script was installed without the exec bit (operator error). Nothing ran. |
| 3 | `Q6 SUMMARY pass=15 fail=0`, drift=0, VERDICT PASS (fixture-scoped). Detailed below. |

One harness edit by the orchestrator: the product-unit precondition tolerates `azazel-activated.service` in `failed` state (left by the prior Q4-R run).

## Run 3 results

| Check | Result |
|---|---|
| PRE-ROOT: `runtime_paths.ROOT` is `/` | PASS |
| N0-host-cgroupns: host cgroup namespace refused ("cgroup namespace root is not host root") | PASS |
| P0-fixture-cgroupns: own cgroup `/system.slice/azazel-activated.service` inside the mimic namespace | PASS |
| P0-namespaces: cgroup namespace identity stable across the exchange | PASS |
| P0-daemon-cgroup-audit / -comm: `0::/system.slice/azazel-auditd.service` and `0::/system.slice/azazel-commissiond.service` | PASS |
| P1-peercred-raw: SO_PEERCRED (11348, 996, 985) equals the expected (pid, uid, gid) | PASS |
| P1-audit-observe-with-proof: real client, proof before and after, head (0, 64 zeros); empty tmpfs ledger accepted as genesis by the installed auditd | PASS |
| P2-commission-inventory-with-proof: real client, digest `sha256:26d9664c...` | PASS |
| N1-audit / N1-comm peercred-pid: wrong pid refused ("socket peer identity differs") | PASS |
| N2-audit-cgroup-string: altered string refused ("audit peer cgroup differs"); N2-restored-passes | PASS |
| P3-leaf-mode: overlay leaf mode 2710 (the review text says 0710; code and layout require 2710) | PASS |
| N3-leaf-mode: wrong mode refused ("audit path ownership or mode refused") | PASS |

Observed chain: `/` 755, `/var` 755, `/var/lib` 755, `/var/lib/azazel` 711 root, `/var/lib/azazel/run` 711 root (all real directories); `run/audit` 2710 uid 996 gid 979 and `run/commission` 2710 uid 997 gid 979 (tmpfs overlay).
Installed binaries: `az-auditd` sha256 `f6610350...`, `az-commissiond` sha256 `9c4b5a68...`. Both sent READY=1 to the private sink.
Host view of the audit daemon: `/system.slice/q6fix-sandbox-.../mimic/system.slice/azazel-auditd.service`, which differs from the product string, as expected. Pre/post snapshots (units, product-unit states, `/var/lib/azazel` and `/etc/azazel` metadata, state hashes, host mounts, `/run` dirs, cgroups, identity files, masks, unix listeners) show drift=0.

## What is qualified (fixture-scoped)

- Peer credential equality (pid, uid, gid) against the installed daemons, with a negative control.
- Exact-byte comparison logic for `0::<group>\n` and cgroup namespace stability, via a mimic cgroup namespace, with positive and negative controls. This proves the comparison, not systemd's placement.
- The 0711 chain on real directories (`/var/lib/azazel`, `/var/lib/azazel/run`), root-owned and not group/other writable.
- The 2710 leaf and 0660 socket declaration, on the tmpfs overlay (setgid group inheritance verified by the daemon before READY).
- Real client exchanges (`observe_head`, `observe_inventory`) with proof before and after.
- An empty ledger accepted as genesis by the installed auditd, in a tmpfs ledger (Q10 evidence for the empty-ledger rule only).

## What is NOT qualified

- B1: real systemd placement and the literal `/proc/<pid>/cgroup` string of the product units (default slice, no override). Only the first real start can show it.
- B2: retained manager identities (`Id`, `ControlGroup`, owner, profile digest, InvocationID) pinned to the product units and real D-Bus observation. Synthetic identities were used.
- B3: product unit hardening (ProtectSystem, seccomp, MDWE, capabilities, dependency edges) was not reproduced; the daemons ran under the driver, not the product sandbox.
- R1: the real `run/audit` and `run/commission` leaf owner and mode are shadowed by the overlay. Verify them separately and read-only.

## Limits

VM only, fixture-scoped, synthetic identities, real ledger untouched, product units never started. Issue #93 remains open. The harness is not part of the product tree; the 15 PASS lines hold for build c79291b and the installed binaries hashed above.
Implication: Q6 narrows the first-start unknowns to B1, B2, B3 and R1; none of them closes without a supervised real start.
