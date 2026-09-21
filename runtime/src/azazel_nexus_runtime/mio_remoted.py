"""`az-mio-remoted`: the only place an observation could leave this node (#98).

Three services now reach outward or run code, and they share nothing that
carries authority:

| service | account | socket | may | resolves through |
| --- | --- | --- | --- | --- |
| `az-model-fetchd` | `azfetch` | `fetch` | pull public bytes in | Source Registry |
| `az-mio-locald` | `azmio` | `mio` | run one local binary | package allowlist |
| **`az-mio-remoted`** | **`azremote`** | **`remote`** | **push a sanitised frame out** | **Provider Registry** |

None of the three inherits another's account, allowlist, socket, egress
exception or commissioned registry. A node where the credential that pulls a
file also pushes a report is a node where one compromise is two.

## The fourth refusal of P2 / P3

`routing`, `sanitizer` and `remote_trust` each refuse a class that may not
leave. This is the **fourth**, and it is not a replacement for any of them.

The instant before a byte leaves is the last place a mistake is still a
mistake rather than a disclosure. Not checking there is betting that the
other three are correct -- and they are three pieces of code that can each be
edited by somebody who has read only one of them.

So this service refuses on its own evidence, from inside a signed envelope,
with the other three switched off. `tests/unit/test_mio_remoted.py` drives
exactly that.

## A caller supplies two symbols and a sealed envelope

| argument | kind |
| --- | --- |
| `provider_id` | identifier |
| `request_id` | identifier |

The frame and its envelope arrive as the request's payload, and the envelope
is the **only** thing that establishes what class the frame is.
`protocol.ArgumentKind` has no free-text member, so there is no way to
express a URL, a header, a proxy, a certificate path, a model name, a prompt,
an evidence blob or a privacy class in a request.

**A caller cannot say what class its frame is.** It can only present
something a sanitizer boundary signed, and that signature binds the class to
the content, the policy revision, an expiry, a nonce and a provider. A
caller that could assert a class would be a caller that could assert
`P0-public` over anything it liked.

## No retry, one attempt

`route_selection` decides whether a failure falls back, and it decides once.
Nothing here loops around a send.

## What it never says

No frame, no response body, no credential, no private key, no token, no
prompt, no evidence, no assembled URL. The reply carries symbols, counts and
a structured reason; there is no field on it that could hold any of them, and
there is no command line to leak one through.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from azazel_nexus.advisory_response import AdvisoryRefused, read_advisory
from azazel_nexus.provider_registry import ProviderRefused, resolve_provider
from azazel_nexus.remote_envelope import (
    EnvelopeRefused,
    NonceLedger,
    open_envelope,
)
from azazel_nexus.sanitizer import NEVER_REMOTE

from .principal import PrincipalClass
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry

__all__ = [
    "INFER_VERB",
    "MAX_PAYLOAD_BYTES",
    "PayloadRefused",
    "REGISTRY",
    "RemoteInferenceService",
    "PROVIDER_REGISTRY_PATH",
    "SOCKET_NAME",
    "TRANSPORT",
    "read_payload",
    "main",
]

#: Its own socket. Not the operator plane's, not the fetcher's, not the local
#: runtime's. A service that can send what this node observed, answering
#: where everything else answers, would be reachable by everything that can
#: reach anything.
SOCKET_NAME = "remote"

#: Where the commissioned Provider Registry would live. Fixed here: a
#: registry path supplied by a caller is a caller choosing who the providers
#: are.
PROVIDER_REGISTRY_PATH = Path("/var/lib/azazel/remote/providers.signed")

#: The transport this build wires in. **`None`, and that is the shipped
#: state.**
#:
#: Not a disabled feature: this distribution contains no inference transport,
#: so the path is absent rather than switched off and there is no setting
#: that turns it on. `activated.wired_capabilities` reads this, so the unit
#: is withheld rather than granted and the node does not carry a service that
#: would start and exit.
#:
#: Wiring one is a reviewed change to this file. The **commissioned** halves
#: -- a Provider Registry and a key holding the sanitizer role -- are signed
#: data and arrive separately; all three are needed, and each refuses on its
#: own.
TRANSPORT: Optional[Callable[..., tuple]] = None

INFER_VERB = Verb(
    name="remote.infer",
    arguments=(
        Argument("provider_id", ArgumentKind.IDENTIFIER),
        Argument("request_id", ArgumentKind.IDENTIFIER),
    ),
    # Not `OPERATOR`. An operator asks the component that owns the routing
    # decision; they do not reach past it to the thing that opens the socket.
    admits=frozenset({PrincipalClass.ROOT, PrincipalClass.SERVICE}),
    accepts_payload=True,
    payload_contract="mio_remoted.read_payload -> open_envelope",
)

REGISTRY = VerbRegistry([INFER_VERB])


#: The largest payload this verb will decode, before decoding. The envelope
#: is small by construction and the frame is bounded by the sanitizer policy
#: and again by the provider record; this is the bound that applies before
#: either of those has been read.
MAX_PAYLOAD_BYTES = 512 * 1024


class PayloadRefused(Exception):
    """A payload that is not the declared shape. Refused, never repaired."""


def read_payload(payload: Mapping) -> tuple:
    """The `remote.infer` payload contract: exactly two base64 strings.

    The transport layer delivers a JSON object, so bytes travel as base64.
    Decoded **here**, under a ceiling, with `validate=True` -- a lenient
    decoder silently drops characters it does not recognise, which would mean
    the bytes the envelope was checked against are not the bytes that were
    sent.

    Exactly two keys, and an unknown one is refused rather than ignored: a
    key this reader does not consume is a key the sender expected somebody
    to.
    """

    if not isinstance(payload, Mapping):
        raise PayloadRefused("a payload is an object")
    unknown = sorted(set(payload) - {"frame", "envelope"})
    if unknown:
        raise PayloadRefused(f"the payload carries unknown {unknown}")
    missing = sorted({"frame", "envelope"} - set(payload))
    if missing:
        raise PayloadRefused(f"the payload omits {missing}")

    decoded = []
    for key in ("frame", "envelope"):
        value = payload[key]
        if not isinstance(value, str):
            raise PayloadRefused(f"{key} is base64 text")
        if len(value) > MAX_PAYLOAD_BYTES:
            raise PayloadRefused(
                f"{key} is larger than {MAX_PAYLOAD_BYTES} encoded bytes"
            )
        try:
            decoded.append(base64.b64decode(value, validate=True))
        except (ValueError, binascii.Error) as exc:
            raise PayloadRefused(f"{key} is not valid base64: {exc}") from exc
    return decoded[0], decoded[1]


@dataclass(frozen=True)
class InferenceReply:
    """What the service says back. Symbols, counts and a structured reason.

    There is deliberately **no `answered` and no `completed` field**. Whether
    a request was answered is `route_selection`'s word, decided from this
    plus whether the advisory validated. A transport that could report
    "answered" would be a transport whose TLS failure could be reported as a
    reply.
    """

    provider_id: str
    request_id: str
    outcome: str
    refusal: Optional[str]
    reason: str
    response_digest: Optional[str] = None
    advisory_fields: int = 0

    def as_document(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "request_id": self.request_id,
            "outcome": self.outcome,
            "refusal": self.refusal,
            "reason": self.reason,
            "response_digest": self.response_digest,
            "advisory_fields": self.advisory_fields,
        }


class RemoteInferenceService:
    """Open an envelope, resolve a provider, send once, validate the answer.

    Every decision about *where* comes from the signed Provider Registry,
    which the caller does not supply and cannot influence. Every decision
    about *what class* comes from the signed envelope, which the caller can
    present but cannot mint.
    """

    def __init__(
        self,
        *,
        registry: Any = None,
        sanitizer_keys: Optional[dict] = None,
        policy_revision: int = 0,
        nonces: Optional[NonceLedger] = None,
        transport: Optional[Callable[..., tuple]] = None,
        clock: Callable[[], str] = lambda: "",
    ) -> None:
        self._registry = registry
        # Empty by default and empty as shipped. No key holds the sanitizer
        # role on this node, so no envelope verifies and nothing is sent.
        self._sanitizer_keys = dict(sanitizer_keys or {})
        self._policy_revision = policy_revision
        self._nonces = nonces if nonces is not None else NonceLedger()
        # No default. Nothing in this distribution provides one, so the
        # ordinary result of a well-formed request is that there is no
        # transport -- the path is absent rather than disabled.
        self._transport = transport
        self._clock = clock

    def handle(self, request: Any) -> dict:
        arguments = request.arguments
        provider_id = arguments["provider_id"]
        request_id = arguments["request_id"]

        def refuse(refusal: str, reason: str) -> dict:
            return InferenceReply(
                provider_id=provider_id,
                request_id=request_id,
                outcome="not_sent",
                refusal=refusal,
                reason=reason,
            ).as_document()

        try:
            frame, envelope = read_payload(getattr(request, "payload", None) or {})
        except PayloadRefused as exc:
            return refuse("malformed_payload", str(exc))

        # 1. The envelope, first and on its own evidence. Nothing about the
        #    frame is believed until something signed says what it is.
        try:
            opened = open_envelope(
                envelope,
                frame=frame,
                sanitizer_keys=self._sanitizer_keys,
                provider_id=provider_id,
                policy_revision=self._policy_revision,
                now=self._clock(),
                nonces=self._nonces,
            )
        except EnvelopeRefused as exc:
            return refuse(exc.refusal.value, exc.reason)

        # 2. The fourth refusal of P2 / P3, on this service's own reading of
        #    the signed class. `open_envelope` refuses these too; both
        #    statements stand, because one of them being rewritten is the
        #    case this exists for.
        if opened.privacy_class in NEVER_REMOTE:
            return refuse(
                "class_not_remote_eligible",
                f"{opened.privacy_class.value} does not leave this node. The "
                "sanitizer, the router and the trust reading each refuse this; "
                "so does the last component before the byte leaves",
            )

        # 3. The provider, from the signed registry only.
        try:
            record = resolve_provider(
                provider_id, self._registry, privacy_class=opened.privacy_class
            )
        except ProviderRefused as exc:
            return refuse(exc.refusal.value, exc.reason)

        if len(frame) > record.max_request_bytes:
            return refuse(
                "request_too_large",
                f"the frame is {len(frame)} bytes and this provider's ceiling "
                f"is {record.max_request_bytes}; nothing is sent",
            )

        if self._transport is None:
            return refuse(
                "no_transport",
                "this distribution contains no inference transport. The path "
                "is absent rather than disabled, so there is no setting that "
                "turns it on",
            )

        # 4. One attempt. No loop, no retry: the router decides fallback once.
        report, body = self._transport(
            record=record, frame=frame, path=record.path_for()
        )
        if report.outcome.value != "received":
            return InferenceReply(
                provider_id=provider_id,
                request_id=request_id,
                outcome=report.outcome.value,
                refusal=None,
                reason=report.reason,
            ).as_document()

        # 5. The untrusted content boundary.
        try:
            advisory = read_advisory(body, max_bytes=record.max_response_bytes)
        except AdvisoryRefused as exc:
            return InferenceReply(
                provider_id=provider_id,
                request_id=request_id,
                outcome="not_advice",
                refusal=exc.refusal.value,
                reason=exc.reason,
            ).as_document()

        return InferenceReply(
            provider_id=provider_id,
            request_id=request_id,
            outcome="advisory",
            refusal=None,
            reason="a bounded advisory was read; it is context and a "
            "recommendation, and it changes nothing this node decides",
            response_digest=advisory.digest,
            advisory_fields=len(advisory.data.fields) if advisory.data else 0,
        ).as_document()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Optional[Callable[[], None]] = None,
) -> int:
    """Serve. Takes no arguments, by design.

    `argv` is accepted and **refused if it carries anything**. An argument
    vector is readable by every user on the host, so a service that took an
    endpoint, a token, a certificate path or a model name on its command line
    would publish it to all of them.
    """

    if argv:
        raise SystemExit(
            "az-mio-remoted takes no arguments. Which providers exist, who "
            "this node presents as, and what it may send are commissioned "
            "state on this node, not things a command line says"
        )
    raise SystemExit(
        "az-mio-remoted has no provider commissioned in this build. The "
        "Provider Registry ships absent and no key holds the sanitizer role, "
        "so no envelope verifies and no provider symbol resolves; a service "
        "that started anyway would be a service listening for work it could "
        "not do"
    )


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
