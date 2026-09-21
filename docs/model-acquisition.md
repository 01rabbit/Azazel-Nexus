# Explicit Online Acquisition

Status: **path implemented, no fetcher exists**
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

## 2. Not configured off. Absent.

"Default off" is a setting, and a setting is a thing that can be set.

There is **no fetcher in this distribution**. `drive_fetch` takes one and has
no default; nothing here constructs one; and neither module imports `socket`,
`ssl`, `http` or `urllib`. `tests/unit/test_runtime_boundary.py` already
refuses to find `AF_INET`, `AF_INET6`, `AF_PACKET` or `create_connection`
anywhere in the runtime package, and **that scan passes with this module in
it**.

A build shipped today could not fetch anything even if somebody confirmed
it, because the code that would open the connection does not exist.

### The endpoints cannot resolve either

Every entry in `ENDPOINT_FOR` is a host under `.invalid`, which RFC 2606
reserves and guarantees will never resolve. That is not a placeholder to be
tidied up later; it is the second lock. Naming a real host is a deliberate,
reviewable change to that table, and the `Endpoint` constructor refuses any
host that is not under `.invalid` — so it cannot happen by typo.

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
