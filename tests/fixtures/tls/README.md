# Test-only TLS material

Fixed certificates and keys for the artifact fetch service's TLS, mTLS and
pinning tests. They are **committed on purpose**.

## Why fixed, and not generated per run

An earlier version generated a certificate with the `openssl` CLI at test
time and skipped when the CLI was absent. That made the `openssl` binary's
presence, version and command-line behaviour a **precondition of the TLS
tests** — so the tests that matter most were the ones most likely not to run,
and a green pipeline would not have said whether they did.

These files were generated once, here, and committed. The tests use the
standard library's `ssl` and a loopback server, and **run every time**.

## The material

| file | what |
| --- | --- |
| `trusted-ca.crt` / `.key` | the CA a test node is commissioned to trust |
| `untrusted-ca.crt` / `.key` | a CA nothing trusts, for the untrusted-issuer case |
| `server.crt` / `.key` | `SAN=DNS:localhost`, issued by the trusted CA |
| `server-wrong-name.crt` / `.key` | `SAN=DNS:not-localhost.test.invalid`, for hostname mismatch |
| `server-expired.crt` / `.key` | valid 2020-01-01 to 2020-01-02, long expired |
| `server-untrusted-ca.crt` / `.key` | correct name, wrong issuer |
| `client.crt` / `.key` | the node's mTLS identity, issued by the trusted CA |
| `client-untrusted.crt` / `.key` | a client identity the server will not accept |

Every subject is prefixed so that it cannot be mistaken for anything real,
and the CAs are self-signed with no path to any public root.

## These keys are test-only, and that is enforced

`tests/unit/test_tls_fixture_hygiene.py` scans the distribution and refuses to
find this material in production source, packaging, runtime state, catalog or
registry signing, operator credentials, or release signing.

A private key committed to a repository is a compromised key. These are
committed **because** they are worthless: they authenticate a loopback server
that exists for the length of a test, and if one ever appeared somewhere that
mattered, the scan above is what would say so.

## Regenerating

Not required, and not automated: the pins in
`tests/unit/test_artifact_egress.py` are fixed values checked against these
files. Regenerating means recomputing those constants, which is deliberate —
a pin the test derives from the file it is testing is a pin that checks
nothing.
