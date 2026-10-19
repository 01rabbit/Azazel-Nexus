# The runtime boundary

Azazel-Nexus is two distributions, and the split is the point.

| Distribution | Package | What it may import |
| --- | --- | --- |
| `azazel-nexus` | `azazel_nexus` | The standard library, minus anything operational |
| `azazel-nexus-runtime` | `azazel_nexus_runtime` | The above, plus sockets, netlink and process control |

`azazel_nexus` holds what the node decides: state, contracts, generations, the
audit model, the capability model, and the refusals that make each of them
checkable. `tests/unit/test_boundary_static.py` scans its source and rejects
`socket`, `ssl`, `http`, `urllib`, `subprocess`, `ctypes`, `multiprocessing`,
`asyncio` and the rest.

That scan is not a restriction the runtime layer was built to get around. It
is the reason the library's decisions can be tested at all: code that cannot
act can be exercised exhaustively, and a privilege decision written in it is a
privilege decision a test can drive into every branch.

**The dependency runs one way.** The runtime imports the library. The library
never imports the runtime, and two checks keep it that way: a static scan in
`tests/unit/test_runtime_boundary.py`, and the CI job that imports the library
in an environment where the runtime is not installed and fails if it turns out
to be importable.

## What the runtime adds, and what it does not

It adds the ability to act: a Unix domain socket, a netlink read, a systemd
operation. It does not add a second place where policy lives. Every decision a
daemon makes is the library's; the daemon carries it out.

So a daemon's tests are about carrying out — did it ask systemd for the right
thing, did it refuse the right frame — and the library's tests are about
deciding. A daemon that started deciding things would be a second copy of the
policy, and the two copies would agree until they did not.

## Nothing listens on a network

Every daemon speaks `AF_UNIX`. `test_the_runtime_opens_no_internet_socket`
scans the runtime for `AF_INET`, `AF_INET6`, `AF_PACKET` and
`create_connection`, and the unit files set `RestrictAddressFamilies` and
`IPAddressDeny=any`.

Two enforcement points, and they are not redundant. The static scan runs in
CI and proves the code contains no such path. The systemd settings run on the
host and would stop one that did. CI cannot check the second — that is
`HG-01` in [hardware gates](hardware-gates.md) — and the host does not run
the first.

## Who is calling

Derived by the server from `SO_PEERCRED` and from the socket's own ownership
and mode. **A request never contributes to it.** A request that could name its
own role would be making an assertion, and an authorization resting on an
assertion is not an authorization.

Keys a caller might use to try — `principal`, `role`, `uid`, `sudo` and the
rest — are refused with their own reason, so that an attempt to supply a
principal appears in the ledger as that rather than as a typo. No verb may
declare an argument with one of those names; the type refuses to be built.

The socket's mode answers *who can connect*. Peer credentials answer *who
did*. Neither substitutes for the other, and a daemon checks both.

## What a caller may say

A verb from a fixed allowlist, and arguments that are ordinals, flags, values
from a set the verb enumerates, or digests. There is no argument kind that
carries free text.

A digest is `sha256:` and sixty-four lowercase hex digits. It is **compared,
never dereferenced**: it names nothing on the filesystem and reaches nothing.

This is what makes "no arbitrary command, unit name, path or argument" a
property of the type system rather than a rule each daemon remembers. A unit
is addressed by a symbolic key the daemon resolves through its own fixed
table; an interface by an ordinal into the daemon's own enumeration. **A
caller cannot name a device or a unit.**

## The frame

Four bytes of big-endian length, then that many bytes of JSON, one request per
connection.

| Refusal | Cause |
| --- | --- |
| `frame_too_large` | The declared length exceeds the fixed 64 KiB ceiling |
| `truncated_frame` | The peer closed before the declared length arrived |
| `trailing_bytes` | Bytes followed the frame |
| `malformed_frame` | Zero length, no header, or bytes that are not JSON |
| `not_an_object` | Valid JSON that is not a request |
| `unknown_verb` | Not in the allowlist |
| `client_asserted_principal` | A reserved key |
| `undeclared_argument` / `missing_argument` | The request and the verb disagree |
| `argument_type` / `argument_range` | The value is not what the argument declares |
| `principal_denied` | The caller holds no class the verb admits |
| `read_deadline` | The peer stopped sending and did not close |
| `verb_unavailable` | The caller was admitted, but this build does not implement the verb yet (`watchdog.probe`, #42); the daemon keeps serving |
| `rate_limited` | The caller is over auditd's per-writer rate or daily budget (detail `rate` or `daily`); final for that request, summarized in the chain rather than recorded per request (`docs/integration-loop.md`, "Audit chain limits") |

`frame_too_large` is refused **before the body is read**. A ceiling enforced
after reading everything has already spent the memory it exists to protect.

`read_deadline` exists because a peer that connects, sends three bytes and
stops is the cheapest denial of service there is.

## What a refusal records

A rejected frame is attacker-supplied by definition, so nothing from it is
written to the ledger verbatim. Recorded: the reason, the byte count, a
16-character fingerprint of the frame, and the caller's credentials — which do
not come from the caller.

Not recorded: the frame's contents, an unknown verb's name, or an undeclared
argument's key. The first two are obvious. The third is the one this
implementation got wrong on the first pass: *declared* argument names are safe
because they are the daemon's own, and an undeclared key is the caller's text
wearing the same shape.

The fingerprint is what an operator uses to see that one unknown verb arrived
four hundred times, without the ledger carrying four hundred copies of
whatever it said.


Local model hosting pins exactly one llama.cpp b11716 runtime with architecture
specific executable digests. Only runtime mio_supervisor executes it; the
library hashes bytes and performs admission/readiness checks without importing
socket, subprocess or runtime. Both optional servers use AF_UNIX under the same
PrivateNetwork and aggregate memory/CPU ceilings. Production admission remains
closed (HG-05 and operator approval); an installed binary does not open it.
See [local runtime](mio-local-runtime.md).
