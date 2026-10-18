"""`az-model-fetchd`: the service that may reach the network, and only it (#105).

A module with a socket in it is a module boundary. This is the service
boundary: its own unit, its own system account (`azfetch`), its own socket,
one writable directory, and the only `RestrictAddressFamilies` in the
distribution that names an internet family.

Everything else -- `azazel_nexus` and its routing, catalog, registry and
operator-view modules, and every other daemon here -- keeps no network API at
all. `tests/unit/test_runtime_boundary.py` and
`tests/unit/test_runtime_hardening.py` each assert that, each with one named
exemption, and each asserts the exemption set has exactly one member.

## What a caller may ask for

One verb, `model.fetch`, and its arguments are **symbolic**:

| argument | kind |
| --- | --- |
| `model_id` | identifier |
| `source_id` | identifier |
| `digest` | `sha256:` + 64 hex |
| `size_bytes` | ordinal |
| `resume_from` | ordinal |

`protocol.ArgumentKind` has no free-text member, so there is no way to
express a URL, a proxy, a header, a shell command or a file path in a
request. That is not a check this module performs; it is a shape a request
cannot take. A caller sends symbols, and the *service* resolves them --
against the signed Source Registry, on this node, under commissioned trust.

**The caller never names where the bytes come from.** That is the whole
point of the split: a client that could supply an endpoint would make every
guarantee in the registry advisory.

## What it does with them

The explicitly composed service resolves the signed catalog and registry,
binds the request to that plan, and delegates to `model_fetch.acquire`.
That path makes one dedicated TLS transfer into a resumable fetch directory,
then hands complete bytes to the fetch ready directory. Root copies them
through the #95 inbox importer; only that importer verifies and promotes; the reply distinguishes promotion from fetching and
always reports admission as false. Nothing here starts a model.

The daemon starts only with valid fetch commissioning. It cannot read the
models root or promote; root runs model-import-fetched for that step.

## What it never says

No credential, no private key, no token, no request body, no assembled URL.
Not in a reply, not in an audit event, not in the journal -- and there is no
command line to leak one through, because the executable takes no arguments
at all.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from azazel_nexus.model_acquisition import AcquisitionRefused
from azazel_nexus.source_registry import RegistryRefused

from .model_fetch import OFFLINE_IMPORT, AcquisitionResult
from .principal import PrincipalClass
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry

__all__ = [
    "FETCH_VERB",
    "MAX_ARTIFACT_BYTES",
    "REGISTRY",
    "SOCKET_NAME",
    "FetchService",
    "main",
]

#: Its own socket, not the operator plane's. A service with egress that
#: answered on the shared socket would be reachable by everything that can
#: reach anything.
SOCKET_NAME = "fetch"

#: The largest artifact this service will be asked for, as an argument
#: ceiling. `model_acquisition` has its own; this one exists so that a
#: malformed request is refused by the protocol rather than by the code that
#: would otherwise have to hold the number in two places.
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024

FETCH_VERB = Verb(
    name="model.fetch",
    arguments=(
        Argument("model_id", ArgumentKind.IDENTIFIER),
        Argument("source_id", ArgumentKind.IDENTIFIER),
        Argument("digest", ArgumentKind.DIGEST),
        Argument("size_bytes", ArgumentKind.ORDINAL, maximum=MAX_ARTIFACT_BYTES),
        Argument("resume_from", ArgumentKind.ORDINAL, maximum=MAX_ARTIFACT_BYTES),
    ),
    # Only the node's own accounts and root. An operator asks the component
    # that owns the acquisition decision; they do not reach past it to the
    # thing that opens the socket.
    admits=frozenset({PrincipalClass.ROOT, PrincipalClass.SERVICE}),
)

REGISTRY = VerbRegistry([FETCH_VERB])


@dataclass(frozen=True)
class FetchOutcomeReply:
    """What the service says back. Symbols and counts."""

    model_id: str
    source_id: str
    outcome: str
    received: int
    reason: str

    def as_document(self) -> dict:
        return {
            "model_id": self.model_id,
            "source_id": self.source_id,
            "outcome": self.outcome,
            "received": self.received,
            "reason": self.reason,
        }


class FetchService:
    """Resolve a symbolic plan on this node, then move bytes.

    Everything that decides *where* comes from `resolve`, which the caller
    does not supply and cannot influence: it is built once from commissioned
    material when the service starts.
    """

    def __init__(
        self,
        *,
        resolve: Callable[[str, str], Any],
        transfer: Callable[..., Any],
        staging: Path,
    ) -> None:
        self._resolve = resolve
        self._transfer = transfer
        self._staging = staging

    def handle(self, request: Any) -> dict:
        arguments = request.arguments
        model_id = arguments["model_id"]
        source_id = arguments["source_id"]
        try:
            plan = self._resolve(model_id, source_id)
        except Exception as exc:
            # Only enumerated refusal codes may cross the service boundary.
            reason = "source_unavailable"
            if isinstance(exc, (AcquisitionRefused, RegistryRefused)):
                reason = exc.cause.value
            return {
                **FetchOutcomeReply(
                    model_id, source_id,
                    "source_unavailable" if reason == "source_unavailable" else "refused",
                    0, reason,
                ).as_document(),
                "admitted": False, "resumable": False, "retained": "none",
                "offline_import": OFFLINE_IMPORT,
            }

        if (model_id, arguments["digest"], arguments["size_bytes"], source_id) != (
            plan.model_id, plan.expected_digest, plan.expected_size_bytes, plan.source_id,
        ):
            return {
                **FetchOutcomeReply(model_id, source_id, "refused", 0,
                                    "plan_mismatch").as_document(),
                "admitted": False, "resumable": False, "retained": "none",
                "offline_import": OFFLINE_IMPORT,
            }

        # Only the legacy transfer seam uses this sink and destination.
        # The composed acquire path owns its file lifecycle and ignores the sink.
        # The legacy destination also comes from the resolved plan's digest.
        destination = self._staging / (plan.expected_digest.split(":", 1)[1] + ".part")
        received = 0

        def sink(chunk: bytes) -> None:
            nonlocal received
            with destination.open("ab") as handle:
                handle.write(chunk)
            received += len(chunk)

        result = self._transfer(
            plan=plan,
            expected_digest=plan.expected_digest,
            expected_size=plan.expected_size_bytes,
            resume_from=arguments["resume_from"],
            sink=sink,
        )
        if isinstance(result, AcquisitionResult):
            return {
                **FetchOutcomeReply(
                    model_id, source_id, result.state.value, result.received,
                    result.reason,
                ).as_document(),
                "admitted": result.admitted, "resumable": result.resumable,
                "retained": result.retained,
                "offline_import": result.offline_import,
            }
        return FetchOutcomeReply(
            model_id=model_id,
            source_id=source_id,
            outcome=result.outcome.value,
            received=result.received,
            reason=result.reason,
        ).as_document()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Optional[Callable[[], None]] = None,
) -> int:
    """Serve. Takes no arguments, by design.

    `argv` is accepted and **refused if it carries anything**, matching every
    other daemon here: an argument vector is readable by every user on the
    host, so a service that took an endpoint, a token or a path on its
    command line would publish it to all of them.
    """

    if argv:
        raise SystemExit(
            "az-model-fetchd takes no arguments. Where it may connect, who it "
            "presents as, and what it may write are commissioned state on "
            "this node, not things a command line says"
        )
    import shutil

    from .artifact_egress import tls_context
    from .model_fetch import (
        FetchNotCommissioned,
        compose_service,
        load_fetch_commissioning,
    )
    from .principal import PrincipalPolicy
    from .runtime_paths import (
        audit_sink,
        fetch_commission_dir,
        fetch_dir,
        fetch_partial_dir,
        fetch_ready_dir,
        socket_path,
    )
    from .serve import serve_forever
    from .systemd_notify import runtime_ready_callback

    try:
        commissioned = load_fetch_commissioning(fetch_commission_dir())
        context = tls_context(
            ca_certificate=str(commissioned.ca_certificate),
            client_certificate=str(commissioned.client_certificate) if commissioned.client_certificate else None,
            client_key=str(commissioned.client_key) if commissioned.client_key else None,
        )
    except FetchNotCommissioned as exc:
        raise SystemExit("az-model-fetchd has no transport wired: " + ", ".join(exc.missing)) from None
    except Exception:  # noqa: BLE001 - any failure is a closed refusal with no exception text
        raise SystemExit("az-model-fetchd has no transport wired: tls:invalid") from None
    service = compose_service(
        consent=commissioned.consent, registry=commissioned.registry,
        catalog=commissioned.catalog, models=None, context=context,
        allowed_addresses=commissioned.allowed_addresses, handoff="ready",
        fetch_dir=fetch_partial_dir(), ready_dir=fetch_ready_dir(),
        free_bytes=lambda: shutil.disk_usage(fetch_dir()).free, installed=dict,
        license_acknowledged=False, actor="azfetch", deadline_seconds=3600,
    )
    return serve_forever(path=socket_path("fetch"), registry=REGISTRY,
                         policy=PrincipalPolicy.resolve(), audit=audit_sink("fetch"),
                         handler=service.handle, stop=stop,
                         # Type=notify: READY=1 only after the socket is bound.
                         ready=ready if ready is not None else runtime_ready_callback())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
