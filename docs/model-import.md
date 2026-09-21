# Offline Model Import

Status: **implemented** (`src/azazel_nexus/model_import.py`, Nexus#95).
How a signed model artifact gets onto a node with no network, and what
getting on does not buy it.

```
inbox --> capacity precheck --> staging --> atomic promotion
                                     \--> quarantine
                              rollback <--/
```

Related: [the model catalog contract](model-catalog.md) (what may be offered
at all) · [M.I.O. runtime control plane](mio-runtime.md) ·
[the operator screen](operator-view.md) ·
[the source registry](source-registry.md) ·
[Hardware gates](hardware-gates.md) ·
[Core reserve measurement](core-reserve-measurement.md) ·
[the Knowledge Lite consumer](knowledge-lite-consumer.md) ·
[Azazel-Nexus #3](https://github.com/01rabbit/Azazel-Nexus/issues/3)

## 1. This is #3's model slice, not a second route

[#3](https://github.com/01rabbit/Azazel-Nexus/issues/3) describes the Mission
Pack lifecycle: offline removable-media ingestion, staged verification,
explicit operator review, atomic activation, retained rollback, append-only
audit evidence. This module implements that lifecycle **for model artifacts
only**, in #3's vocabulary, so that the rest of a Mission Pack — policy,
runbooks, reasoning-playbook versions, Knowledge Lite references — composes
with it later rather than routing around it.

Where #3's criteria are narrower than what a model needs, #3 governs. Where
a model needs more (the size, the executability, the cost of a failed
verification), this document says so and the code carries it.

## 2. The seven boundaries hold, and are not reimplemented

The discipline established for the [Knowledge Lite import](knowledge-lite-consumer.md)
(#67) applies unchanged:

| principle | here |
| --- | --- |
| the caller picks an entry and nothing else | `import_entry(entry_id, model_id)`. No path, no root, no key, no policy |
| every stage is bounded | inbox entries, artifact size, chunk size, retained generations |
| quarantine holds only | never executed, extracted, served or retried |
| the audit carries digests and reasons | never content, never key material |
| promotion is atomic | one `os.replace` |
| a status read writes nothing | `reading_for`, `current_generation`, `list_inbox` |
| trust material is commissioned, never carried in | `CommissionedModels.trusted_keys` |

What is **not** carried over is the implementation. A Lite bundle is at most
512 MiB of JSON claims; a model artifact is tens of gibibytes of weights.

| | Knowledge Lite | model artifact |
| --- | --- | --- |
| size | bounded by memory | never fits in memory; every read is chunked |
| enumeration | id is the content digest | hashing the inbox to list it would cost as much as importing from it |
| failure | advice goes stale | the disk fills, and a half-written file in the store is a file something may later run |

## 3. Enumeration does not hash

A Lite entry id is the digest of the file's bytes, which is affordable
because the bytes fit. Hashing forty gibibytes to draw a listing would make
*looking* at the inbox as expensive as *importing* from it, and an operator
would stop looking.

So an entry id here is a digest over the entry's **identity** — its name and
its size — not its content. The property that matters is unchanged: a caller
cannot spell a path with one, and an id a fresh enumeration does not produce
is a refusal rather than something to try. The integrity a content id would
have given is given instead by the catalog digest, checked against the
staged copy before anything is promoted.

Including the size has a second effect worth having: **a file swapped
between the listing and the import no longer answers to the id it was listed
under.**

Symlinks are not listed. `lstat` is used rather than `stat`, so a link is
never sized by its target, and following one would read outside the
operator's media entirely.

## 4. The import never consumes the inbox

Nothing is moved out of the inbox and nothing is deleted from it. It is the
operator's media, and an import that failed halfway through would otherwise
have eaten the only copy.

The inbox is the node's **supply directory**, not only the operator's. An
operator places a file there; [acquisition](model-acquisition.md) may place
one there too. Nothing follows differently: bytes that arrived over a socket
take the same enumeration, the same capacity precheck and the same
verification as bytes from a USB stick. **There is no shortcut for downloaded
bytes.**

## 5. Atomic promotion is a property of the filesystem, not of intent

Promotion is one `os.replace` from staging into the store, which is atomic
**only within one filesystem**. Across devices a move is a copy followed by
an unlink, and there is a window in which the store holds a partial file.

So staging and the store sharing a device is checked, and an import refuses
with `PROMOTION_NOT_ATOMIC` when they do not. This is not a budget question:
no amount of free space makes a cross-device move atomic.

## 6. Capacity is checked before staging, never during

A node must not discover the disk is full with half an artifact on it. Before
a byte is copied:

```
free >= declared_size + MIN_FREE_HEADROOM_BYTES
```

The headroom is what the node keeps for itself. A node that imports a model
and can no longer write its own audit chain has not gained anything.

The predecessor is **not** subtracted, because it stays where it is. That is
what rollback is, and retention is what makes rollback cost disk.

## 7. Every interrupt window leaks rather than loses

Ordering is chosen so that a process killed at any point leaves a file nobody
references — which the next import sweeps — and never a generation that
references a file that is not there.

1. Copy into staging under a temporary name, chunked, bounded by the declared
   size. A file that grows while it is read is refused as `SIZE_MISMATCH`.
2. `os.replace` the temporary to its digest-derived staging name.
3. Verify with `model_catalog.verify_artifact` — one verification path, so
   there is exactly one place that decides whether an artifact matches its
   declaration.
4. `os.replace` into the store.
5. Write the new generation file.
6. `os.replace` the current pointer.
7. Sweep: generation files past the retention window, then store artifacts no
   retained generation names.

The sweep runs **after** the pointer moves, never before. Staging is swept at
the start of the next import rather than in a handler, so it survives a
process that was killed outright.

## 8. Rollback

`rollback(reason, actor, now)` restores the generation before the current
one. It refuses when there is none — a rollback that invented a predecessor
would be an install wearing a rollback's name — and refuses when the earlier
generation names an artifact the store no longer holds, because restoring it
would activate a generation that is not complete.

The audit entry records the reason, the actor, both generation numbers, both
generation ids, and the digests restored.

## 9. Importing is not admitting, and neither is installing

An artifact in the store is **present**. It is not admitted, it is not
activated, and nothing here can run it.

- Admission is decided against a measured Core reserve
  ([`HG-05`](hardware-gates.md)) and every gate after it.
- Launching is [#97](https://github.com/01rabbit/Azazel-Nexus/issues/97).
- `ModelReading.admitted` is `False` by construction and this module has no
  verb that could change it. A static scan asserts the absence of
  `subprocess`, `shutil`, `tarfile`, `zipfile`, `gzip`, `lzma`, `bz2`,
  `socket`, `ssl`, `http`, `urllib` and `ctypes`, and of any function whose
  name begins `run`, `exec`, `launch`, `start`, `download`, `fetch`,
  `unpack`, `extract`, `retry`, `serve`, `admit` or `activate`.

`shutil` is on that list above all: importing it would put `unpack_archive`
one attribute access away from a module whose whole contract is that it
unpacks nothing.

## 10. No authority

An import does not move Edge authority, the action lease, enforcement or
activation. Only the Edge-owned deterministic arbiter decides and enforces;
`FULL → LITE → CORE` is a capability state, not an authority state.
`test_no_import_moves_the_edge_answer` holds the Edge answer fixed across a
promotion, a second promotion, a quarantine, a rollback and a status read.

The M.I.O. status expression is unchanged by this work:

> M.I.O. routing and commissioning control plane implemented; provider
> execution unavailable pending hardware evidence and provider integration
