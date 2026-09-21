"""`az-mio-locald`: the only place a model process could ever be started (#97).

A module with a socket in it is a *module* boundary. This is the **service**
boundary: its own unit, its own system account (`azmio`), its own socket, its
own runtime directory, one writable path, and `PrivateNetwork=yes` on top of
the `IPAddressDeny=any` every unit here carries.

It is not the fetch service and shares nothing with it. `azfetch` may reach
the network and may not run a program; `azmio` may run one program, from a
fixed list, and may reach nothing. Neither account's access is reused for the
other, and no future remote-inference transport (#98) inherits either.

## This build starts nothing, and the reason is structural

`model_runtime.RUNTIMES` is empty, so no `runtime_id` resolves.
`activation.UnitDefinition.wiring` keeps this unit from being granted, so the
node does not carry a unit that would start and exit at the next boot. And
`readiness` refuses first for the unmeasured Core reserve, which is the
answer on every node this build runs on.

Three separate refusals, in three separate places, for three separate
reasons. Not redundancy: each covers a case the others do not. Wire a runtime
and the reserve still refuses. Measure the reserve and the empty allowlist
still refuses. Grant the unit by hand and `main` still exits.

## What a caller may ask for

One verb, `model.activate`, and its arguments are **two identifiers**:

| argument | kind |
| --- | --- |
| `model_id` | identifier |
| `runtime_id` | identifier |

`protocol.ArgumentKind` has no free-text member, so there is no way to
express a command, a path, an environment variable, a socket address or a
model option in a request. That is not a check this service performs; it is a
shape a request cannot take. A control plane that could pass a model option
could pass one that loads a plugin.

The service resolves both symbols itself -- the runtime through the
package's own allowlist, the artifact through the staging directory it owns.
**The caller never names a file and never names a program.**

## What it never says

No path, no argv, no environment, no model output, no prompt. Not in a reply,
not in an audit event, not in the journal -- and there is no command line to
leak one through, because the executable takes no arguments at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from azazel_nexus.model_runtime import (
    ActivationReadiness,
    RuntimeRefused,
    inspect_artifact,
    readiness,
    resolve_runtime,
)

from .principal import PrincipalClass
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry

__all__ = [
    "ACTIVATE_VERB",
    "LocalRuntimeService",
    "REGISTRY",
    "SOCKET_NAME",
    "STAGING",
    "main",
]

#: Its own socket, not the operator plane's and not the fetcher's. A service
#: that could start a process, answering where everything else answers, would
#: be reachable by everything that can reach anything.
SOCKET_NAME = "mio"

#: The one directory this service reads models from and the only path it may
#: write. Fixed here: a staging directory supplied by a caller is a caller
#: choosing which file is the model.
STAGING = Path("/var/lib/azazel/mio")

ACTIVATE_VERB = Verb(
    name="model.activate",
    arguments=(
        Argument("model_id", ArgumentKind.IDENTIFIER),
        Argument("runtime_id", ArgumentKind.IDENTIFIER),
    ),
    # Not `OPERATOR`. An operator asks the component that owns the admission
    # decision; they do not reach past it to the thing that would start a
    # process.
    admits=frozenset({PrincipalClass.ROOT, PrincipalClass.SERVICE}),
)

REGISTRY = VerbRegistry([ACTIVATE_VERB])


@dataclass(frozen=True)
class ActivationReply:
    """What the service says back. Symbols and a reason, never a path."""

    model_id: str
    runtime_id: str
    readiness: str
    reason: str

    def as_document(self) -> dict:
        return {
            "model_id": self.model_id,
            "runtime_id": self.runtime_id,
            "readiness": self.readiness,
            "reason": self.reason,
        }


class LocalRuntimeService:
    """Decide whether a model could be started here. Never start one.

    Deciding and starting are separate on purpose, and this half is the one
    that is testable without a provider. `start` is not a method that is
    disabled -- there is no such method, because a method nothing calls is a
    method the next change calls.
    """

    def __init__(
        self,
        *,
        staging: Path = STAGING,
        reserve: Optional[Any] = None,
        admitted: Callable[[str], bool] = lambda model_id: False,
    ) -> None:
        self._staging = staging
        # Supplied, never discovered. The library reads the record; this
        # service is handed the result, so that a node whose reserve record
        # was removed becomes a node that refuses rather than one that
        # remembers.
        self._reserve = reserve
        self._admitted = admitted

    def handle(self, request: Any) -> dict:
        arguments = request.arguments
        model_id = arguments["model_id"]
        runtime_id = arguments["runtime_id"]

        # The artifact path is derived from the symbol, inside the directory
        # this service owns. `model_id` is an `IDENTIFIER`, whose grammar has
        # no `/` and no `.` run that could climb -- but the join is still done
        # here and nowhere else, and the result is never echoed back.
        artifact = None
        try:
            resolve_runtime(runtime_id)
        except RuntimeRefused:
            pass
        else:
            artifact = inspect_artifact(self._staging / f"{model_id}.model")

        verdict = readiness(
            admitted=self._admitted(model_id),
            runtime_id=runtime_id,
            artifact=artifact,
            reserve=self._reserve,
        )
        return ActivationReply(
            model_id=model_id,
            runtime_id=runtime_id,
            readiness=verdict.readiness.value,
            reason=verdict.reason,
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
    host, so a service that took a model path, a runtime path or an option on
    its command line would publish it to all of them.
    """

    if argv:
        raise SystemExit(
            "az-mio-locald takes no arguments. Which model, which runtime and "
            "what it may consume are decided from commissioned state and this "
            "package's own allowlist, not from a command line"
        )
    raise SystemExit(
        "az-mio-locald has no provider wired in this build. The runtime "
        "allowlist is empty, so no runtime_id resolves to a binary, and a "
        "service that started anyway would be a service listening for work "
        "it could not do"
    )


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
