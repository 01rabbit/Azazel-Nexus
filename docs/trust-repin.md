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

The runtime production operation currently fails closed pending integration with
the library trust store and audit ledger; injected test operations exercise the
confirmation protocol without production keys.
