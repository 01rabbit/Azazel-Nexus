# Explicit Online Acquisition

Status: **path composed and tested against a loopback TLS fixture; no daemon
starts it and no endpoint is commissioned**
(`src/azazel_nexus/model_acquisition.py`,
`runtime/src/azazel_nexus_runtime/model_fetch.py`, Nexus#96).

The installer may fetch a model. It does not fetch by default, and it never
fetches because something asked nicely.

```
catalog names a SYMBOL → this build resolves it, or refuses
                       → operator confirms, explicitly and separately
                       → capacity checked BEFORE a byte moves
                       → fetch (runtime) → the offline import path verifies
                                        ↘ offline import, always available
```

Related: [the model catalog contract](model-catalog.md) ·
[offline model import](model-import.md) ·
[the source registry](source-registry.md) ·
[the operator screen](operator-view.md) ·
[the route policy](mio-route-policy.md) ·
[runtime boundary](runtime-boundary.md)

## 1. A symbol, never a location

`ModelEntry.source_id` **names** a source. It cannot spell one: the pattern
admits no dot, no slash and no colon — nothing a URL or a path could be built
from.

This is the point of the whole design. **If a catalog could carry an
endpoint, a catalog signature would become a way to point a node at any host
on the internet**, and whoever signs catalogs would hold that power over
every node their catalog reaches. Signing a catalog is meant to be authority
over *which models are offered*, not over *where this node connects*.

So a catalog chooses **among sources this build already knows**, and knows
none it was not built with. An unknown symbol is a refusal, not a lookup.
That is the discipline `remote_trust` holds for endpoints, applied one layer
up.

The library holds the symbols (`KNOWN_SOURCES`). The runtime holds the
addresses (`ENDPOINT_FOR`). Deliberately not together: a library that knew
the address would be a library one import away from using it, and
`route_selection` and `remote_trust` — pure judgement layers with no client —
are reachable from the library.

The two tables are **one fact recorded twice**, and an import-time check is
what keeps them one fact. A symbol in one and not the other stops the runtime
module loading, rather than failing at the moment an operator finally
confirms a fetch.

### A `null` source is an answer, not a gap

An entry whose `source_id` is `null` has **no source usable for online
acquisition**. Terminal: nothing falls back to another entry's source, to a
default, or to anything an operator could type, and no endpoint may be
supplied later to fill it — because there is nothing to fill.

`plan_acquisition` refuses it as `SOURCE_UNAVAILABLE` before capacity,
attempts or anything else a caller could influence, and the function has no
parameter through which a location could arrive.

The artifact is still perfectly importable offline.

### The catalog schema moved to `/2`

`source_id` is required in the document and may be `null`. Required so that
"no online source" is something a catalog author **stated** rather than
forgot; nullable because most entries honestly have none, and absence of a
source means the only route in is an operator's import.

A required field changes what the document is, so `CATALOG_SCHEMA` moved to
`azazel-nexus/model-catalog/2`. `CATALOG_DOMAIN` stayed at `v1`. The full rule
for which number moves when is in [the catalog contract](model-catalog.md)
§2.1; in short, the domain names the **kind** of signing target and the
canonical signing protocol, the schema names the **shape**, and `source_id`
changed the shape alone.

## 2. Not configured off. Absent on every node that has not been commissioned.

"Default off" is a setting, and a setting is a thing that can be set.

The code that opens a connection exists in exactly one module,
`artifact_egress.py`, and §9 composes it with the plan, the Source Registry
and the offline importer. What no node has is anything to point it at:

- `ENDPOINT_FOR` is **empty**, and a test keeps it empty. Endpoints come from a
  signed Source Registry ([source-registry.md](source-registry.md)), which the
  build does not ship.
- `az-model-fetchd` starts only when `load_fetch_commissioning` loads every
  required file. Otherwise it exits with "no transport wired" and fixed
  file/reason labels, without parser diagnostics or keys.
- Activation withholds `azazel-model-fetchd.service` as `wiring_absent` until
  fetch commissioning loads (or the legacy endpoint table is nonempty).
  Validation is cached per process against each commissioning file's path,
  size, nanosecond modification time and inode, including optional client
  identity files. Changes invalidate the result; failed reads or changes during
  validation withhold the capability.
  Commissioning alone does not grant activation or network firewall access.

`drive_fetch` is the older iterator seam. It still takes a `fetcher` and has no
default; the composed path does not go through it.

`tests/unit/test_runtime_boundary.py` refuses `AF_INET`, `AF_INET6`,
`AF_PACKET` and `create_connection` in every runtime module except the two
named egress modules, and that scan passes with the composed path in it.

## 3. The operator confirms, and separately

Acquisition is its own confirmation on [the operator screen](operator-view.md),
its own row, its own reason and its own audit transition
(`mio.model.acquisition.planned`).

An operator who chose `fastest-permitted`, consented to remote advisory
routing, and acknowledged a licence has consented to **none** of this.
Routing a sanitised question to a remote advisor and downloading several
gibibytes onto this disk are different acts with different consequences, and
one "yes" covering both would be a "yes" nobody knowingly gave.

Sources are confirmed **one at a time**. There is no "all".

## 4. What a plan is, and what it is not

`plan_acquisition` produces an `AcquisitionPlan`: a decided, bounded
description of a fetch. **Producing a plan fetches nothing**, and every
refusal happens before one exists — in a fixed order, cheapest and most
absolute first, so a node never checks the disk for something it was never
permitted to fetch:

1. `NO_SOURCE_DECLARED` — the catalog permits no online route for it
2. `UNKNOWN_SOURCE` — the symbol resolves against a fixed table or to nothing
3. `NOT_CONFIRMED` — no operator confirmed a fetch from that source
4. `ALREADY_INSTALLED` — at this digest; fetching again spends disk for nothing
5. `ATTEMPTS_EXHAUSTED` — resume makes a retry cheap, not unbounded
6. `INSUFFICIENT_DISK` — checked before a byte moves

A plan names a symbol, a size, a digest and a deadline. It does **not** name
a host, a URL, a port or a path, and neither does the event it produces —
there is no address at this layer to leak.

## 5. Bounds a fetcher cannot widen

- **Deadline.** A fetch with no deadline is one nobody learns has stopped.
- **Declared size.** A fetcher yielding more is stopped at the byte that
  exceeds it: a file that grew is not the file that was planned for.
- **Resume offset**, counted in a bounded chunk, so a multi-gibibyte transfer
  does not start over — and the digest is still checked afterwards, so
  resuming cannot skip verification.
- **Attempt budget**, finite.

`FetchOutcome` has `COMPLETE`, `TIMED_OUT`, `INTERRUPTED`, `OVERRAN` and
`NO_FETCHER`. It has no `VERIFIED` and no `PROMOTED`, because this layer
decides neither.

## 6. No second verifier

A fetched artifact lands where an imported one lands and goes through the
**same** path: the same enumeration, the same capacity precheck, the same
`verify_artifact`. Neither acquisition module imports `hashlib`, so neither
could verify even if somebody named a function for it.

There is no shortcut for bytes that arrived over a socket. If anything they
deserve the stricter path; they get the identical one.

## 7. Failing to fetch is not failing

When acquisition cannot happen — no source, no consent, no fetcher, a
timeout, a digest that did not match — [the offline import
route](model-import.md) is untouched.

**A node that cannot download is a node that installs from a USB stick**,
not a node that cannot install.

## 8. Fetching is not admitting

Acquisition puts an artifact where one can be verified. Admission is decided
against a measured Core reserve ([`HG-05`](hardware-gates.md)) and every gate
after it; launching is [#97](https://github.com/01rabbit/Azazel-Nexus/issues/97).
Neither module here has a verb that could change that, and the M.I.O. status
expression is unchanged by this work:

> M.I.O. routing and commissioning control plane implemented; provider
> execution unavailable pending hardware evidence and provider integration

## 9. The composed path ([#96](https://github.com/01rabbit/Azazel-Nexus/issues/96))

`model_fetch.acquire` has an import mode for explicitly composed callers and
a fetch-only ready mode used by the daemon. `model_fetch.compose_service` puts it behind `az-model-fetchd`'s
`FetchService.handle`, which is how the tests drive it.

```
verified catalog entry + signed Source Registry (separate keys)
  → plan_acquisition (consent, attempts, already installed, capacity)
  → resolve_candidate, bound to the plan (source, digest, size)
  → resume prefix check on fetch_dir/<digest>.part
  → ONE artifact_egress.fetch_artifact call (pin, mTLS, allowlist, bounds)
  → daemon: os.replace into fetch/ready/<artifact filename> → FETCHED
  → root: azazel-nexus model-import-fetched MODEL_ID [--acknowledge-license]
  → copy and fsync into models/inbox (ready file retained until promotion)
  → ModelImport.import_entry (#95: same digest/signature check, promotion)
  → on promotion, remove ready file
```

**The request names symbols and numbers, and the plan decides.** A request
whose digest, size or source differs from the plan resolved from the catalog
and the registry is refused `plan_mismatch` before anything is dialled, and the
partial's name comes from the plan's digest.

**Each request is one attempt.** There is no loop and no retry. The composed
service counts failed transport attempts per artifact and refuses
`attempts_exhausted` without dialling once the budget is spent; a promotion
or completed ready handoff clears it. The count is in memory and belongs to that service instance: it
starts from the `attempts_used` the composer passes, and a new composition or a
restarted daemon starts it again. A durable budget would have to be persisted
by whoever composes the service; nothing does that yet.

**Capacity and UTC time are read per request**. Import-mode composition also
reads installed state per request. The daemon supplies an empty installed map
because azfetch cannot read the models root; the root importer independently
handles duplicates through #95. If either cannot be read, the request is refused
(`capacity_unavailable`, `installed_state_unavailable`) without dialling.
Capacity is measured on the filesystem that holds the partials. Import mode
also checks the models root filesystem before dialling, requiring room for the
full artifact plus the existing headroom even when resuming a partial. An
unreadable measurement refuses `capacity_unavailable`; inadequate room refuses
`insufficient_disk`. Ready mode checks only the fetch filesystem. The importer
checks its own room again before it stages (#95); these checks reserve no space.

**A complete partial that could not be handed off stays where it is**
(`handoff_failed`, `retained: partial`). This path does not move it again: a
request resuming at the full size is not a fetch, and a request from zero is
refused because the partial is not empty. Its way forward is the offline
import of §7.

The result is a state, a reason from a fixed vocabulary, the bytes still held,
whether the attempt can resume, and what is left where — never a host, path,
pin, client identity or exception text:

| state | what happened | `retained` |
| --- | --- | --- |
| `refused` | consent, source, disk, attempts, plan or resume refused before any connection | `none`, or `partial` when a regular partial of the wrong length is kept |
| `fetch_incomplete` | timed out or interrupted; resumable | `partial` |
| `fetch_refused` | the transport refused (pin, redirect, allowlist, overrun, status) | `none` |
| `fetch_failed` | TLS or network failure | `none` |
| `write_failed` | the partial could not be written or synced | `none` |
| `import_failed` | `handoff_failed`: the complete file could not be moved, and is kept; `import_failed_inbox_retained`: the importer raised, and the complete, unverified file is in the inbox | `partial` / `inbox` |
| `import_refused` | #95 refused the artifact (for example a digest mismatch: #95 quarantines its staged copy) | `inbox` — the received file is still in the inbox |
| `fetched` | all declared bytes arrived, unverified and unpromoted; root must import | `ready` |
| `promoted` | #95 verified and promoted it | `none` |

`fetched` carries the root CLI command; other states except `promoted` carry
the offline-import guidance of §7, and
every result reports `admitted: false`. **Promoted is not admitted** (§8):
nothing on this path calls provider admission or activation, and the tests
fail if anything does.

### Fetch commissioning files

Root writes `/var/lib/azazel/fetch/commission/` as 0750 root:azfetch and its
files as 0640 root:azfetch. No endpoints or credentials ship with the build.
All files are bounded; malformed or missing data refuses the whole composition.

| file | contents |
| --- | --- |
| `trust.json` | `catalog_keys` and `registry_keys` maps of key id to 32-byte public key hex; `commissioning_digest` (`sha256:` plus 64 hex). Shared ids or key material are refused. |
| `sources.signed` | signed Source Registry under the separate registry keys |
| `catalog.signed` | signed model catalog under catalog keys, bound to the same commissioning digest |
| `ca.pem` | required PEM CA trust anchor; no system-store fallback |
| `client.pem`, `client.key` | optional PEM client identity; both or neither, matching and loadable |
| `addresses.json` | `{"allowed_addresses":["127.0.0.1"]}` shape; 1–256 literal IPs, deployment values supplied by root |
| `consent.json` | `sources` list of known symbols, nonempty `operator`, RFC3339 `at`; explicit fetch consent |

Trust, addresses, consent and PEM files are limited to 64 KiB each; signed
files to 4 MiB at the loader and the readers' own format bounds. Trust maps
have at most 64 keys each; consent has at most 256 source items.

`partial/` and `ready/` are 0750 azfetch:azfetch. The parent and commissioning
directory remain root-owned. Fetch refusal records live in
`partial/refusals.jsonl`. The socket follows the runtime's fixed layout at
`/var/lib/azazel/run/fetch/fetch.sock`, in an azfetch-owned setgid leaf.
The models root is `/var/lib/azazel/models`, 0750 root:azmio; azfetch has no
access. Root separately commissions its `trust/trust.json` (catalog keys and
commissioning digest) and `trust/catalog.signed`. The fetch catalog cannot
replace root's independent catalog verification. A fetched artifact is complete,
not verified, promoted, admitted or running.

### What the tests establish, and what they do not

`tests/unit/test_model_acquire_e2e.py` drives the path through the service
against a loopback TLS server with a test-only certificate for
`fetch.azazel.test` (the resolver is replaced so that name means `127.0.0.1`
and nothing else). It covers success and rollback, each refusal before
connection, TLS failures (issuer, name, expiry, client certificate, pin),
redirect, an address outside the allowlist, overrun, deadline, interruption
and resume, a peer that ignores `Range`, a digest mismatch caught by #95,
write, hand-off and promotion failures, and secret sentinels that must not
reach the reply or the recorder.

It establishes nothing about a real endpoint, a real credential, a real
download or a real link: none was configured, and the fixture keys are
test-only.
