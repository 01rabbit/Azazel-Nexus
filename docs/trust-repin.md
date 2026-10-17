# Local trust replacement confirmation

The commissioning CLI requires a local interactive TTY and fresh confirmation
words for trust replacement. This guards human intent against accidental or
non-root use, not against a malicious root process. The daemon admits only ROOT
callers, but its challenge reply includes both the nonce and confirmation words.
A root process can complete challenge and confirm directly on the commissioning
socket without the CLI or a TTY. Single-use, short-lived challenges bind the
principal and proposed anchor bytes; they do not attest human presence.

After a completed replacement, snapshot cleanup failure adds the fixed boolean
`cleanup_failed: true` to the outcome. The reported promotion and generation
remain valid; a cleanup error does not turn a committed promotion into a refusal.
The pending challenge map relies on single-threaded daemon dispatch.

`production_repin` adapts the immutable runtime request and confirmation to
`lite_trust.RepinRequest` and `lite_trust.RepinConfirmation`, then invokes the
real `TrustStore.repin`. The audit principal is the fixed string `root`, derived
only after the peer credential has uid 0 and the ROOT class. Caller arguments
cannot set it. The confirmation timestamp supplies the operation's `now`.

Production placement and permissions
------------------------------------

The fixed TrustStore root is `/var/lib/azazel/lite-trust`, provided by
`runtime_paths.lite_trust_root`. Previously the library took a caller-selected
root; the installer declared no production Lite TrustStore directory or owner.
This integration declares that dedicated directory as `azcommission:azknowledge`
mode `2750`. The installer now creates the non-login `azknowledge` consumer
account as well as `azcommission`. The consumer group has read/search access,
with no directory or file write access. No bundle, content cache or operational
generation directory belongs in this trust-only leaf.

Initial commissioning still uses `TrustStore.pin` once. The provisioning root
operator must assign the resulting `trust.json` to `azcommission:azknowledge`
mode `0640` before repin is enabled; pin's API and behavior are unchanged. The
installer creates directories, never a trust root or keys. For an existing
caller-selected store, root must provision its public trust records into this
leaf with that ownership and mode before starting the daemon; there is no
automatic discovery or migration. Consumers must open `TrustStore` at the same
fixed root and supply their commissioned digest to `keys()`. There is currently
no shipped Knowledge Lite daemon unit to reconfigure.

`az-commissiond` runs as non-root `azcommission`, with supplementary group
`azknowledge` so it can preserve that GID on new files. Repin preserves the
initial trust record's uid, gid and mode, including on the generation pointer;
readable generation directories get search permission. Setgid on the trust
root also preserves the reader group for newly created children. The Lite
consumer can read the promoted generation after restart through `trust-current`.
It receives no write permission to the trust directory or ledger.

The commissioning unit's `ReadWritePaths` contains exactly the trust leaf,
`/var/lib/azazel/state/commission`, and its existing socket leaf
`/var/lib/azazel/run/commission`. Broad writes to `/var/lib/azazel/run` and
`/etc/azazel/commissioning` have been removed. The state leaf is daemon-owned
mode `0700`, holding private confirmation snapshots, refusals and its ledger;
no shared state, auditd chain, bundle cache or generation tree becomes writable.
The declarations in [layout.py](../src/azazel_nexus/layout.py),
[install.sh](../packaging/install.sh), and
[hardening.py](../runtime/src/azazel_nexus_runtime/hardening.py) agree.

The repin ledger is the commissioning daemon's own append-only hash chain at
`/var/lib/azazel/state/commission/commission.jsonl`, fixed by
`runtime_paths.commission_ledger_path`. It is separate from `refusals.jsonl`
and auditd's single-writer chain, following watchdog's `watchdog.jsonl` pattern.
The real library appends `trust.repin.authorized` before swapping the pointer,
and `trust.repin.promoted` after the durable swap. Each has exactly the six
provenance fields: generation, old/new fingerprints, principal, `at`, and reason
(plus the event type). Nonces and key bytes are excluded. An authorization audit
failure or failed pointer replacement keeps the old active root. A failure
after pointer replacement (directory fsync or promotion audit) may leave the new
root active and must be investigated using the pointer and ledger; it does not
prove rollback.

The challenge input remains `/etc/azazel/commissioning/repin-anchor.json`.
Its directory is `root:azcommission` mode `0750`; root provisions the file as
`root:azcommission` mode `0640` containing `{"keys": ["<Ed25519 public key hex>"]}`.
Root alone can replace/write it, and the daemon can read it through its primary
group. Keeping it out of daemon-owned state prevents the daemon from replacing
the operator's proposed input. It is read-only inside the service sandbox.
Challenge and confirm reject symlinks and non-regular/oversized input, bind its
bytes to a short-lived nonce, then pass a private immutable snapshot to the
library. The snapshot is removed after success or failure.

Verification
------------

[Runtime integration tests](../tests/unit/test_runtime_repin_integration.py)
exercise challenge → confirm with the production adapter and real library on a
temporary root using generated test keys. They verify promotion, the two audit
records and all six fields, new-key bundle verification and old-key rejection,
and retention of the old root/bundle on injected audit or pointer failure.
[Boundary scans](../tests/unit/test_runtime_repin_boundary.py) continue to pin
local commissioning reachability. Their exact string inventory now includes
the library audit event names introduced in lane B; these are events, not wire
verbs. No library socket/subprocess/runtime import or repin reachability
exception was added.
