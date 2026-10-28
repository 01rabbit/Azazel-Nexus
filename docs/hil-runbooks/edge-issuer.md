# Edge issuer signature, revocation and rollback floor — target hardware

## 概要（日本語）

[#345](https://github.com/01rabbit/Azazel-Nexus/pull/345) の対象実機（Debian 13 x86_64）
での確認手順。Edge 配布物の発行者署名・失効リスト・ロールバック床について、
次を確かめる。

- issuer anchor の無いノードは従来どおり（`not_configured`、床も ledger も変わらない）。
- **テスト専用の鍵**で anchor を置き、実際の活性化の sandbox（`azazel-activated.service`）
  の下で床 `/var/lib/azazel/state/edge-issuer/floor.json` が書けること。
- 失効（版・digest）、古い失効リスト、壊れた anchor、無効な署名が拒否されること。

テスト用の鍵・署名・床は**本物の承認や発行者に昇格させない**。秘密鍵はオフラインの
作業機の外へ出さず、記録・ログ・Issue・PR に残さない。終わったら anchor・署名・
失効リスト・床をすべて消し、anchor 無しの状態に戻ったことを確かめる。発行者が誰か、
鍵の生成と保管、認証を必須にするかはオーナーの判断のまま変わらない。VM・コンテナの
結果は証跡にならない。ゲートの状態は変えない。

Status: **not run; hardware-unverified**. Owner: [#345](https://github.com/01rabbit/Azazel-Nexus/pull/345)
(merged software); related gate [HG-07](hg-07.md) (#4, explicit child work).

Use the [campaign](../hil-campaign.md), the [evidence rules](../hil-evidence-records.md)
and the [Edge package verification contract](../edge-package-verification.md)
(§3a–§3d). Where this runbook and the code disagree, the code wins:
`tests/unit/test_runbook_references.py` and
`tests/unit/test_hil_runbook_merged_features.py` check what is named here.

## 0. Scope and what exists already

| Evidence class | What exists for #345 | What it does not show |
| --- | --- | --- |
| mock | `tests/unit/test_edge_issuer.py`, `tests/unit/test_runtime_edge_issuer_floor.py`, `tests/unit/test_runtime_activation_pass.py`: every status word, the raise conditions, the floor write, with test-only keys under a temporary directory and the owner check redirected to the test user | root ownership, the systemd sandbox, a real Edge package |
| real process | none beyond the unit tests | — |
| Linux service integration | none: the floor write has never run under `azazel-activated.service` | — |
| target hardware | **none** — this runbook | — |

**What a pass here is not.** No issuer exists, Edge signs nothing, and the
key used below is a throwaway test key. A pass shows that this node's
verifier, its file checks and the activation controller's floor write behave
as specified on this hardware. It does not authenticate any Edge package,
does not name an issuer, does not make issuer authentication required and is
no owner decision ([§3c](../edge-package-verification.md#3c-what-still-needs-the-owner)).

## 1. Preconditions and key custody

1. [HG-07](hg-07.md)'s preconditions hold: the real Edge package installed at
   `/opt/azazel/edge-core` through the approved deployment path, and the
   regular activation path able to grant `azazel-edge-core.service`
   (Variant B of the [activation rehearsal](activation-rehearsal.md)). Without
   an Edge Core grant, §4 is `not-run`.
2. Nexus installed from a reviewed checkout containing #345. `PYTHON` below is
   `/opt/azazel-nexus/venv/bin/python`; commands spell the full path.
3. **The test issuer key.** Generate it on an offline workstation, never on
   the DUT, with OpenSSL 3, inside a directory on a memory-backed file system
   (tmpfs) so that it never reaches a disk:

   ```sh
   KEYDIR=$(mktemp -d -p /dev/shm hil-issuer.XXXXXX) && chmod 0700 "$KEYDIR" && cd "$KEYDIR"
   openssl genpkey -algorithm ed25519 -out test-issuer.pem
   openssl pkey -in test-issuer.pem -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'
   ```

   The second command prints the 64-hex public key. Label the key file
   test-only. It signs only the files of §3 for this run, is never enrolled
   or reused for anything else, and is destroyed in §6. The private key, the
   signatures and the floor's contents never enter Git, an issue, a PR, a
   ticket, a terminal transcript or the HIL record; record only that a
   test-only key was used and destroyed, and its role.
4. Use an issuer name nobody could mistake for a real one, for example
   `hil-test-only` (`[a-z0-9][a-z0-9._-]{0,63}`).

## 2. Baseline: no anchor, behaviour unchanged

Before placing anything, confirm the node has no issuer configuration and no
floor, then read status as root (root reads the real state):

```sh
sudo ls -la /etc/azazel/edge-issuer /var/lib/azazel/state/edge-issuer
sudo /opt/azazel-nexus/venv/bin/azazel-nexus status
sudo /opt/azazel-nexus/venv/bin/python -I -c 'from pathlib import Path; from azazel_nexus.audit import AuditLedger
events = [e.event for e in AuditLedger(Path("/var/lib/azazel/state/activation.jsonl"))][-8:]
print([e["event_type"] for e in events], any("edge_issuer" in (e.get("observed_inputs") or {}) for e in events))'
```

Both directories must be absent (or the node is not at baseline: stop and
find out why). The edge section must print
`issuer_authenticated: no (not_configured)`,
`revocation: not_configured (revoked: not_evaluated)` and
`rollback floor: absent`, with the unsigned caveat, and the five package
checks exactly as in [HG-07](hg-07.md). After a regular-path activation pass
the last activation record must carry no `observed_inputs.edge_issuer` and
there must be no `activation.edge_issuer_floor` event. Anything else on a node
without an anchor is a failure: the anchor is what decides whether anything
changes.

## 3. Place the test anchor, signature and revocation list

On the DUT, compute what the issuer signs, carry it to the workstation, sign
it there, and carry back only the 64-byte signatures. First set two shell
variables on the DUT, used by every later step that names the manifest or its
signature (`<manifest>.sig` beside the installed manifest):

```sh
MANIFEST=/opt/azazel/edge-core/azazel-edge-core-0.1.0-x86_64.manifest.json
SIG="$MANIFEST.sig"
/opt/azazel-nexus/venv/bin/python -I -c 'import sys; from azazel_nexus.edge_issuer import manifest_signature_target; sys.stdout.buffer.write(manifest_signature_target(open(sys.argv[1], "rb").read()))' "$MANIFEST" > manifest-target.bin
printf '%s' '{"issued_at": "2026-10-28T00:00:00Z", "package": "azazel-edge-core", "revoked_digests": [], "revoked_versions": [], "schema": "azazel-nexus/edge-package-revocation/v1", "sequence": 2}' | /opt/azazel-nexus/venv/bin/python -I -c 'import sys; from azazel_nexus.edge_issuer import canonical_json; sys.stdout.buffer.write(canonical_json(sys.stdin.buffer.read()))' > revocations-2.payload
printf 'azazel-nexus/edge-package-revocation/v1\000' | cat - revocations-2.payload > revocations-2.target
```

On the workstation:

```sh
openssl pkeyutl -sign -inkey test-issuer.pem -rawin -in manifest-target.bin -out manifest.sig
openssl pkeyutl -sign -inkey test-issuer.pem -rawin -in revocations-2.target -out revocations-2.sig
```

Each `.sig` must be exactly 64 bytes. Back on the DUT, as root:

```sh
sudo install -d -m 0755 -o root -g root /etc/azazel/edge-issuer
printf '{"issuer": "hil-test-only", "public_key": "%s", "schema": "azazel-nexus/edge-issuer-anchor/v1"}' "$PUBLIC_HEX" > issuer.json
cat revocations-2.sig revocations-2.payload > revocations.signed
sudo install -m 0644 -o root -g root issuer.json revocations.signed /etc/azazel/edge-issuer/
sudo install -m 0644 -o root -g root manifest.sig "$SIG"
sudo /opt/azazel-nexus/venv/bin/azazel-nexus status
```

(The shell variable PUBLIC_HEX holds the key printed in §1.) Expect `digest_verified: yes`,
`issuer_authenticated: yes (authenticated, issuer hil-test-only)`,
`revocation: in_force, sequence 2 (revoked: none)`, `rollback floor: absent`,
the five package checks unchanged and no issuer notes. A sequence-2 list is
placed first so that §5.3 can replay sequence 1.

## 4. The floor is written under the activation sandbox

The floor is written only by `azazel-activated.service` (root,
`ProtectSystem=strict`, `UMask=0027`, `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`,
writable `ReadWritePaths=/var/lib/azazel/state`), and only after it granted
`azazel-edge-core.service`, wrote its marker and appended the pass record.
Reboot so that the regular pass runs with the anchor in place, then:

```sh
sudo journalctl -b -u azazel-activated.service -o cat | grep -F 'edge issuer floor'
sudo stat -c '%U:%G %a %h' /var/lib/azazel/state/edge-issuer /var/lib/azazel/state/edge-issuer/floor.json
sudo /opt/azazel-nexus/venv/bin/python -I -c 'from pathlib import Path; from azazel_nexus.audit import AuditLedger
[print(e.event["event_type"], e.event["edge_issuer_floor"]) for e in list(AuditLedger(Path("/var/lib/azazel/state/activation.jsonl")))[-8:] if e.event["event_type"] == "activation.edge_issuer_floor"]'
sudo /opt/azazel-nexus/venv/bin/python -I -c 'from pathlib import Path; from azazel_nexus.edge_issuer import decode_floor
f = decode_floor(Path("/var/lib/azazel/state/edge-issuer/floor.json").read_bytes()); print(f.version, f.revocation_sequence, bool(f.package_digest), bool(f.revocation_digest))'
sudo /opt/azazel-nexus/venv/bin/azazel-nexus status
```

Pass if: the journal has no `az-activated edge issuer floor` line (it is
printed only for `failed`, `refused` or `uncertain`, or when the record was
not appended); `stat` prints a leaf line beginning `root:root 755` and the
file line `root:root 644 1`; the activation ledger
holds `activation.edge_issuer_floor raised`; the decoded floor is version
`0.1.0`, revocation sequence `2`, both digests present; and status prints
`rollback floor: held, floor 0.1.0`. A further reboot must give
`activation.edge_issuer_floor held` and leave the file unchanged.

If the pass did not grant Edge Core, the floor must stay absent and no floor
event may appear: that is `not-run` for this section, not a pass. A floor
written by anything but this pass, or a floor raised when Edge Core was not
granted, is a failure. Do not print the floor file or its digests into any
record.

## 5. Refusals

Each case is read with `sudo /opt/azazel-nexus/venv/bin/azazel-nexus status`
(`inspect` applies the same checks the activation pass uses). Restore the §3
state between cases. Where a case that fails a package check (5.1, 5.2, 5.3,
5.5, 5.6) is confirmed with a reboot, the pass must withhold Edge Core
(`edge_not_ready`, no grant marker for `azazel-edge-core.service`) and must
not move the floor. Case 5.4 changes no package check: issuer authentication
is not required for acceptance (an owner decision), so it only changes the
issuer line and stops the floor from being raised.

| Case | How | Expected status lines |
| --- | --- | --- |
| 5.1 revoked version | sign a sequence-3 list with `"revoked_versions": ["0.1.0"]` and place it | `revocation: in_force, sequence 3 (revoked: revoked_version)`; `version_matches` fails |
| 5.2 revoked digest | sign a sequence-3 list whose `revoked_digests` holds the installed artifact's `sha256:` digest (from the manifest, on the DUT only) | `revoked: revoked_digest`; `digest_matches` fails although `digest_verified: yes` |
| 5.3 older list replayed | after §4 raised the floor at sequence 2, place a validly signed sequence-1 list; then remove the list entirely | `revocation: rolled_back`; `digest_matches` fails, in both variants |
| 5.4 signature invalid | flip one bit: `sudo /opt/azazel-nexus/venv/bin/python -I -c 'import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[0] ^= 1; open(p, "wb").write(b)' "$SIG"`; restore with the §3 `install` of `manifest.sig` | `issuer_authenticated: no (signature_invalid)` |
| 5.5 anchor unsafe | `sudo chmod 0666 /etc/azazel/edge-issuer/issuer.json` | `issuer_authenticated: no (trust_refused)`; `digest_matches` fails as a `SECURITY FINDING` |
| 5.6 same version, other digest | only if a second, different `0.1.0` artifact is available through the approved deployment path: install it with its own signed manifest | `rollback floor: replayed, floor 0.1.0`; `version_matches` fails |
| 5.7 below the floor | **not-run**: the pin admits exactly `0.1.0`, so no lower version can reach the floor check today | — |

Sign each list exactly as in §3 (canonical payload, the revocation domain,
64-byte signature first). A case whose expected words do not appear, or that
leaves any check passing that should fail, is a failure. Keep every output.
A floor that is corrupted (`floor_status: refused`) is covered by the mock
evidence only; do not hand-edit the floor on a DUT to produce it.

## 6. Restore the node and destroy the key

As root, with nothing being activated, follow the
[floor recovery procedure](../edge-package-verification.md#3d-recovering-from-a-wrongly-raised-floor-root-manual)
and remove every test file (in a shell where `MANIFEST` and `SIG` are set
as in §3):

```sh
sudo rm /var/lib/azazel/state/edge-issuer/floor.json
sudo rm /etc/azazel/edge-issuer/issuer.json /etc/azazel/edge-issuer/revocations.signed
sudo rm "$SIG"
sudo rmdir /etc/azazel/edge-issuer /var/lib/azazel/state/edge-issuer
sudo /opt/azazel-nexus/venv/bin/azazel-nexus status
```

Status must again print `issuer_authenticated: no (not_configured)` and
`rollback floor: absent`. Restore any artifact changed in 5.6 through the
approved deployment path.

**The activation ledger keeps the test.** `/var/lib/azazel/state/activation.jsonl`
is an append-only, hash-chained ledger: the pass records of this run, with
`observed_inputs.edge_issuer` showing `authenticated` under the test anchor,
and the `activation.edge_issuer_floor` events (`raised`, `held`) stay on the
node permanently. Never edit or truncate the ledger to remove them. Instead,
write in the operations log, for anyone who later reads that ledger: that
these records were produced by a test-only issuer key during this runbook
(name the run and the time window), that the key was not a real issuer and
authenticated nothing, and that the floor was raised and removed by whom and
when (no audit event is written for the removal).

On the workstation, destroy the key and every signature and target file, then
the tmpfs directory: `shred -u "$KEYDIR"/*` and `rmdir "$KEYDIR"`, and power
the workstation off so that nothing of the tmpfs remains in memory. Do the
same with the copies of `manifest-target.bin`, the payloads and the
signatures on the DUT and on the transfer medium. A key that touched a
persistent disk cannot be shredded reliably (journaling and flash
remapping); if that happened, record it, and treat the key as exposed even
though it is a test key. A DUT that leaves this runbook with a test anchor, list,
signature or floor in place is not at baseline and must not proceed to any
other exercise.

## 7. Record

Retain in the protected HIL archive, never in Git, an issue or a PR: the
installed Nexus and Edge commits, the §2 baseline lines, the §3–§5 status
lines and floor labels (the words above, not digests), the `stat` output of
§4, the restoration result of §6, and the systemd version and class facts.
Never record the key, a signature, a revocation payload, the floor file,
any digest, boot id or address.

There is no hardware record schema for this exercise yet: its outcome is
`passed`, `failed` or `not-run` in the [vocabulary](../hil-evidence-records.md),
for field review. It changes no gate (HG-07 stays open) and authenticates no
Edge package.
