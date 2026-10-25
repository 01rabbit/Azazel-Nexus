"""Resolving a source symbol, and driving a bounded fetch (#96).

`azazel_nexus.model_acquisition` decides **whether** a model may be fetched
and produces a plan. This module is where the symbol in that plan becomes an
address, and where a transfer would be driven. It lives in the runtime
distribution because that is where privileged, outward-facing work belongs --
`az-edge-probed` and `az-core-reserve-probe` sit in the same place for the
same reason.

`acquire` composes explicit consent, the signed Source Registry, the dedicated
TLS transport and the existing #95 importer. `compose_service` exposes that
path through the symbolic fetch service. Commissioning is supplied by the
caller; the daemon starts only when all fetch commissioning loads.
`drive_fetch` remains the legacy iterator seam.

## The endpoint table ships empty, and going to production does not loosen it

An earlier version filled this table with `.invalid` hosts and had `Endpoint`
refuse anything else. That stops a mistaken fetcher, and it is the wrong
shape: **going to production would then mean relaxing the validator** -- and
a design whose next step is to relax a check is a design that gets relaxed,
probably in a hurry, probably by someone who did not write it.

So the validator now accepts any production-valid FQDN and refuses what is
actually dangerous: address literals, and anything that smuggles a scheme, a
port, a path, a query or userinfo into a host field. And the table is
**empty**. A node that may fetch takes its endpoints from the signed,
commissioned Source Registry -- reviewed, signed, audited data -- not from a
code change. Test fixtures put loopback endpoints in a registry of their own;
they do not put them here.

A symbol with an endpoint here that the library does not know still stops
this module loading: an address nothing can name is an address nobody chose.

## The library holds the symbols, this holds the addresses

Deliberately not together. A library that knew the address would be a
library one import away from using it, and `route_selection` and
`remote_trust` -- pure judgement layers with no client -- are reachable from
the library.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import stat
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from azazel_nexus.model_acquisition import (
    KNOWN_SOURCES,
    MAX_ATTEMPTS,
    MIN_FREE_HEADROOM_BYTES,
    AcquisitionPlan,
    AcquisitionRefused,
    SourceConsent,
    plan_acquisition,
)
from azazel_nexus.model_catalog import (
    CatalogRefused,
    ModelCatalog,
    ModelEntry,
    artifact_filename,
    read_catalog,
)
from azazel_nexus.model_import import CommissionedModels, ModelImport, entry_id_for
from azazel_nexus.source_registry import (
    CommissionedSources,
    RegistryRefused,
    SourceRegistry,
    read_registry,
    resolve_candidate,
)
from azazel_nexus_runtime.artifact_egress import EgressRefused, Outcome, fetch_artifact

if TYPE_CHECKING:
    from .model_fetchd import FetchService

__all__ = [
    "ENDPOINT_FOR",
    "AcquisitionResult",
    "AcquisitionState",
    "Endpoint",
    "FetchCommissioning",
    "FetchNotCommissioned",
    "FetchOutcome",
    "FetchRefused",
    "FetchResult",
    "acquire",
    "compose_service",
    "drive_fetch",
    "endpoint_for",
    "load_fetch_commissioning",
]


@dataclass(frozen=True)
class Endpoint:
    """Where a symbol resolves. Fixed in the build, never supplied."""

    host: str
    port: int
    #: The path component, with `{digest}` the only substitution. A template
    #: with any other hole would be a template something could steer.
    path_template: str

    def __post_init__(self) -> None:
        if not _HOSTNAME.fullmatch(self.host) or _ADDRESS_LITERAL.match(self.host):
            raise ValueError(
                f"{self.host!r} is not a hostname. A scheme, a port, a path, "
                "a query, userinfo or an address literal are separate fields "
                "or they do not exist"
            )
        holes = self.path_template.count("{")
        if holes != 1 or "{digest}" not in self.path_template:
            raise ValueError(
                f"{self.path_template!r} has holes other than {{digest}}. A "
                "template with another hole is a template something can steer"
            )


#: A hostname, and nothing that could carry a scheme, a port, a path, a
#: query or userinfo. Those are separate fields or they do not exist.
_HOSTNAME = re.compile(
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\Z"
)
#: An address literal would let this table both name a source and pick its
#: address, skipping the commissioned address allowlist that exists because a
#: right name is not a right address.
_ADDRESS_LITERAL = re.compile(r"^[0-9.]+$")

#: **Empty, and that is the shipped state.**
#:
#: An earlier version filled this with `.invalid` hosts and had `Endpoint`
#: refuse anything else, on the theory that a build which could not name a
#: real host could not reach one. That is true and it is the wrong shape:
#: going to production would then require *loosening the validator*, and a
#: design whose next step is to relax a check is a design that will be
#: relaxed -- probably in a hurry, probably by someone who did not write it.
#:
#: So the validator accepts any production-valid FQDN and refuses what is
#: actually dangerous (address literals, schemes, userinfo, ports or paths
#: smuggled into a host), and **this table ships empty**. A node that may
#: fetch gets its endpoints from the signed, commissioned Source Registry --
#: reviewed, signed and audited data -- not from a code change.
#:
#: Test fixtures put loopback endpoints in a registry of their own. They do
#: not put them here.
ENDPOINT_FOR: Mapping[str, Endpoint] = {}

# An endpoint here for a symbol the build does not know would be an address
# nothing can name. The other direction is now ordinary: `KNOWN_SOURCES`
# names the symbols a catalog may use, and this table is empty in a shipped
# build, because endpoints are commissioned data rather than code.
_unknown = sorted(set(ENDPOINT_FOR) - set(KNOWN_SOURCES))
if _unknown:
    raise ImportError(
        f"{_unknown} have endpoints and are not symbols this build knows. An "
        "address nothing can name is an address nobody chose"
    )


class FetchOutcome(str, Enum):
    """How a drive ended. `COMPLETE` is not `VERIFIED` and not `PROMOTED`."""

    #: Every declared byte arrived. Whether they are the right bytes is
    #: decided by `model_catalog.verify_artifact`, not here.
    COMPLETE = "complete"
    #: The deadline passed. Whatever arrived is discarded by the caller.
    TIMED_OUT = "timed_out"
    #: The transfer stopped early. Resumable from `received`.
    INTERRUPTED = "interrupted"
    #: More bytes arrived than were declared.
    OVERRAN = "overran"
    #: The legacy drive seam has no default fetcher; acquire is the composed path.
    NO_FETCHER = "no_fetcher"


class FetchRefused(Exception):
    """The drive did not start. Nothing was written."""


@dataclass(frozen=True)
class FetchResult:
    """What a drive did. Never a verdict about the bytes."""

    outcome: FetchOutcome
    received: int
    reason: str

    @property
    def complete(self) -> bool:
        return self.outcome is FetchOutcome.COMPLETE

    def as_event(self) -> dict:
        """The symbol's outcome and a count. No host, no path, no bytes."""

        return {
            "event_type": "mio.model.acquisition.fetched",
            "outcome": self.outcome.value,
            "received": self.received,
            "reason": self.reason,
        }


def endpoint_for(plan: AcquisitionPlan) -> Endpoint:
    """Resolve the plan's symbol. Refuses rather than constructing one."""

    try:
        return ENDPOINT_FOR[plan.source_id]
    except KeyError:
        raise FetchRefused(
            f"{plan.source_id!r} resolves to no endpoint in this build"
        ) from None


def drive_fetch(
    plan: AcquisitionPlan,
    *,
    fetcher: Callable[..., Iterable[bytes]] | None = None,
    sink: Callable[[bytes], None] | None = None,
    elapsed: Callable[[], int] | None = None,
) -> FetchResult:
    """Drive one attempt at `plan`, bounded by everything the plan carries.

    This legacy seam has no default `fetcher`; `acquire` is the composed
    acquisition path. The daemon requires fetch commissioning.

    The bounds are the plan's and cannot be widened from here: the deadline,
    the declared size, and the chunk the resume offset is counted in. A
    fetcher that yields more than was declared is stopped at the byte that
    exceeds it -- a file that grew is not the file that was planned for.
    """

    endpoint = endpoint_for(plan)
    if fetcher is None:
        return FetchResult(
            outcome=FetchOutcome.NO_FETCHER,
            received=plan.resume_from,
            reason=(
                "drive_fetch's legacy seam has no default fetcher; acquire is "
                "the composed path. This seam made no transfer; "
                f"no transfer to {endpoint.host} was attempted"
            ),
        )
    if sink is None:
        raise FetchRefused("a drive writes somewhere or it does not run")

    clock = elapsed or (lambda: 0)
    received = plan.resume_from
    for chunk in fetcher(
        host=endpoint.host,
        port=endpoint.port,
        path=endpoint.path_template.format(digest=plan.expected_digest),
        offset=plan.resume_from,
        chunk_bytes=plan.chunk_bytes,
    ):
        if clock() > plan.timeout_seconds:
            return FetchResult(
                outcome=FetchOutcome.TIMED_OUT,
                received=received,
                reason=(
                    f"the deadline of {plan.timeout_seconds}s passed. A fetch "
                    "with no deadline is one nobody learns has stopped"
                ),
            )
        if received + len(chunk) > plan.expected_size_bytes:
            return FetchResult(
                outcome=FetchOutcome.OVERRAN,
                received=received,
                reason=(
                    f"more than the declared {plan.expected_size_bytes} bytes "
                    "arrived. A file that grew is not the file that was "
                    "planned for"
                ),
            )
        sink(chunk)
        received += len(chunk)

    if received != plan.expected_size_bytes:
        return FetchResult(
            outcome=FetchOutcome.INTERRUPTED,
            received=received,
            reason=(
                f"{received} of {plan.expected_size_bytes} bytes arrived. "
                "Resumable from here; the digest is still checked afterwards, "
                "so resuming cannot skip verification"
            ),
        )
    return FetchResult(
        outcome=FetchOutcome.COMPLETE,
        received=received,
        reason=(
            "every declared byte arrived. Whether they are the right bytes is "
            "decided by the same verification an offline import goes through, "
            "and nothing here has decided it"
        ),
    )


class AcquisitionState(str, Enum):
    """Fetch completion and import promotion never grant admission."""

    REFUSED = "refused"
    FETCH_INCOMPLETE = "fetch_incomplete"
    FETCH_REFUSED = "fetch_refused"
    FETCH_FAILED = "fetch_failed"
    WRITE_FAILED = "write_failed"
    IMPORT_REFUSED = "import_refused"
    IMPORT_FAILED = "import_failed"
    PROMOTED = "promoted"
    FETCHED = "fetched"


OFFLINE_IMPORT = "Use the #95 offline import: place a complete artifact in the commissioned inbox and import its entry id."


@dataclass(frozen=True)
class AcquisitionResult:
    """A bounded public outcome; received counts artifact bytes still on disk.

    retained names the remaining handoff location without exposing a path.
    A promoted artifact lives in the #95 store, with no fetch handoff retained.
    """

    state: AcquisitionState
    reason: str
    received: int
    resumable: bool = False

    retained: Literal["none", "partial", "inbox", "ready"] = "none"
    guidance: str = ""
    admitted: bool = field(default=False, init=False)

    @property
    def offline_import(self) -> str:
        if self.retained == "ready":
            return self.guidance
        if self.state is AcquisitionState.PROMOTED:
            return ""
        if self.retained == "inbox":
            return "The complete artifact is already in the commissioned inbox; use the #95 offline import with its entry id."
        return OFFLINE_IMPORT


class _SinkError(OSError):
    """Distinguish a local write failure from a transport failure."""


def acquire(
    *,
    entry: ModelEntry,
    consent: SourceConsent,
    registry: SourceRegistry,
    models: CommissionedModels | None,
    handoff: Literal["import", "ready"] = "import",
    ready_dir: Path | None = None,
    context,
    allowed_addresses: Sequence[str],
    fetch_dir: Path,
    free_bytes: int,
    resume_from: int = 0,
    attempts_used: int = 0,
    installed: Mapping[str, str],
    license_acknowledged: bool,
    now: str,
    actor: str,
    deadline_seconds: int,
    recorder: Callable[[str, Mapping], None] | None = None,
    clock=None,
    sleeper=None,
    transport=fetch_artifact,
) -> AcquisitionResult:
    """Plan, resolve, then hand complete bytes to root or the #95 importer.

    One transport call per invocation; repeated invocations are separate
    attempts counted by the composed service.
    """

    if handoff not in ("import", "ready") or (handoff == "import" and models is None) or (handoff == "ready" and ready_dir is None):
        raise ValueError("invalid handoff configuration")
    part = fetch_dir / (entry.digest.split(":", 1)[1] + ".part")
    try:
        status = part.lstat()
    except FileNotFoundError:
        status = None
    except OSError:
        return AcquisitionResult(AcquisitionState.WRITE_FAILED, "write_failed", 0)
    received = status.st_size if status is not None and stat.S_ISREG(status.st_mode) else 0
    retained = "partial" if status is not None and stat.S_ISREG(status.st_mode) else "none"

    def event(step, state, reason):
        if recorder is not None:
            recorder(step, {
                "model_id": entry.model_id, "source_id": entry.source_id,
                "digest": entry.digest, "size": entry.size_bytes,
                "received": received, "state": state, "reason": reason,
            })

    def finish(state, reason, resumable=False):
        event("outcome", state.value, reason)
        return AcquisitionResult(state, reason, received, resumable, retained)

    if not 0 <= resume_from <= entry.size_bytes:
        return finish(AcquisitionState.REFUSED, "resume_mismatch")
    try:
        plan = plan_acquisition(
            entry, consent=consent, free_bytes=free_bytes, resume_from=resume_from,
            attempts_used=attempts_used, installed=installed,
        )
    except AcquisitionRefused as exc:
        return finish(AcquisitionState.REFUSED, exc.cause.value)
    event("plan", "planned", "planned")
    try:
        candidate = resolve_candidate(entry, registry)
    except RegistryRefused as exc:
        return finish(AcquisitionState.REFUSED, exc.cause.value)
    if (candidate.source_id, candidate.digest, candidate.size_bytes) != (
        plan.source_id, plan.expected_digest, plan.expected_size_bytes,
    ):
        return finish(AcquisitionState.REFUSED, "plan_mismatch")

    # Partials belong outside every importer-owned handoff and state directory.
    protected = (models.staging, models.inbox, models.store, models.quarantine,
                 models.root / "trust", models.root / "state") if models else ()
    if any(fetch_dir.resolve().is_relative_to(path.resolve()) for path in protected):
        return finish(AcquisitionState.REFUSED, "unsafe_fetch_dir")

    def discard():
        nonlocal received, retained
        try:
            part.unlink(missing_ok=True)
            received = 0
            retained = "none"
        except OSError:
            # Cleanup is best effort if the filesystem itself stops accepting writes.
            retained = "partial"

    try:
        status = part.lstat() if part.exists() or part.is_symlink() else None
        if status is not None and not stat.S_ISREG(status.st_mode):
            discard()
            return finish(AcquisitionState.REFUSED, "resume_mismatch")
        if (status is None and resume_from != 0) or (
            status is not None and status.st_size != resume_from
        ):
            return finish(AcquisitionState.REFUSED, "resume_mismatch")
        fetch_dir.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
        with os.fdopen(os.open(part, flags, 0o600), "ab", buffering=0) as stream:
            retained = "partial"

            def sink(chunk):
                nonlocal received
                try:
                    if stream.write(chunk) != len(chunk):
                        raise _SinkError()
                    received += len(chunk)
                except OSError:
                    raise _SinkError() from None

            try:
                result = transport(
                    host=candidate.record.host, port=candidate.record.port,
                    path=candidate.path, expected_pin=candidate.record.certificate_pin,
                    expected_size=plan.expected_size_bytes, resume_from=resume_from,
                    allowed_addresses=allowed_addresses,
                    deadline_seconds=min(deadline_seconds, plan.timeout_seconds),
                    bandwidth_bytes_per_second=candidate.record.bandwidth_bytes_per_second,
                    sink=sink, context=context, clock=clock, sleeper=sleeper,
                )
            except _SinkError:
                raise
            except EgressRefused:
                discard()
                return finish(AcquisitionState.FETCH_REFUSED, "egress_refused")
            except OSError:
                discard()
                return finish(AcquisitionState.FETCH_FAILED, "transport_failed")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        discard()
        return finish(AcquisitionState.WRITE_FAILED, "write_failed")

    if result.outcome in (Outcome.TIMED_OUT, Outcome.INTERRUPTED):
        return finish(AcquisitionState.FETCH_INCOMPLETE, result.outcome.value, True)
    if result.outcome is not Outcome.COMPLETE or received != plan.expected_size_bytes:
        discard()
        return finish(AcquisitionState.FETCH_REFUSED, "egress_refused")
    event("fetch", "fetched_complete", "complete")

    if handoff == "ready":
        try:
            ready_dir.mkdir(parents=True, exist_ok=True)
            os.replace(part, ready_dir / artifact_filename(entry))
        except OSError:
            return finish(AcquisitionState.WRITE_FAILED, "handoff_failed")
        retained = "ready"
        event("outcome", "fetched", "complete")
        return AcquisitionResult(
            AcquisitionState.FETCHED, "complete", received, retained="ready",
            guidance=f"Root must run azazel-nexus model-import-fetched {entry.model_id}",
        )

    # Importer events include paths and actor data; expose only our bounded schema.
    def import_event(transition, payload):
        event("import", "importing", "importing")

    try:
        name = artifact_filename(entry)
        models.inbox.mkdir(parents=True, exist_ok=True)
        os.replace(part, models.inbox / name)
    except OSError:
        return finish(AcquisitionState.IMPORT_FAILED, "handoff_failed")
    retained = "inbox"
    try:
        outcome = ModelImport(models, recorder=import_event).import_entry(
            entry_id_for(display_name=name, size=entry.size_bytes), entry.model_id,
            now=now, actor=actor, license_acknowledged=license_acknowledged,
        )
    except OSError:
        return finish(AcquisitionState.IMPORT_FAILED, "import_failed_inbox_retained")
    if not outcome.promoted:
        return finish(AcquisitionState.IMPORT_REFUSED, "import_refused")
    retained = "none"
    return finish(AcquisitionState.PROMOTED, "promoted")


def compose_service(
    *,
    consent: SourceConsent,
    registry: SourceRegistry,
    models: CommissionedModels | None,
    handoff: Literal["import", "ready"] = "import",
    ready_dir: Path | None = None,
    context,
    allowed_addresses: Sequence[str],
    fetch_dir: Path,
    free_bytes: Callable[[], int] | None = None,
    installed: Callable[[], Mapping[str, str]] | None = None,
    license_acknowledged: bool,
    now: Callable[[], str] = lambda: datetime.now(timezone.utc).isoformat(),
    actor: str,
    deadline_seconds: int,
    catalog: ModelCatalog | None = None,
    attempts_used: int = 0,
    recorder: Callable[[str, Mapping], None] | None = None,
    clock=None,
    sleeper=None,
    transport=fetch_artifact,
) -> FetchService:
    """Compose a service with live preflight inputs and bounded artifact counters.

    Each explicit request can spend one attempt. Promotion or a ready handoff
    resets that artifact's counter; refusals before transport leave it untouched. This starts no daemon.
    The attempt counter is in-memory, per composed service instance, seeded by
    attempts_used, and reset by recomposition or process restart. A durable budget
    would have to be persisted by whoever composes it.
    """

    from .model_fetchd import FetchService

    if handoff not in ("import", "ready") or (handoff == "import" and models is None) or (handoff == "ready" and ready_dir is None):
        raise ValueError("invalid handoff configuration")
    if models is None and catalog is None:
        raise ValueError("verified catalog required")

    def current_catalog():
        return catalog if catalog is not None else models.catalog()

    attempts: dict[tuple[str, str], int] = {}

    def disk_free(path):
        ancestor = path
        while not ancestor.exists():
            ancestor = ancestor.parent
        return shutil.disk_usage(ancestor).free

    def installed_now():
        if handoff == "ready":
            return {}
        current = ModelImport(models).current_generation()
        return current.installed if current else {}

    def resolve(model_id, source_id):
        entry = current_catalog().entry(model_id)
        if entry is None:
            raise LookupError()
        try:
            resolve_candidate(entry, registry)
        except RegistryRefused as exc:
            if recorder is not None:
                recorder("outcome", {
                    "model_id": entry.model_id, "source_id": entry.source_id,
                    "digest": entry.digest, "size": entry.size_bytes,
                    "received": 0, "state": "refused", "reason": exc.cause.value,
                })
            raise
        # Bind request symbols to the verified catalog and commissioned registry.
        return AcquisitionPlan(
            model_id=entry.model_id, source_id=entry.source_id,
            expected_digest=entry.digest, expected_size_bytes=entry.size_bytes,
            resume_from=0,
        )

    def transfer(*, plan, resume_from, **unused):
        try:
            entry = current_catalog().entry(plan.model_id)
        except (CatalogRefused, OSError):
            return AcquisitionResult(AcquisitionState.REFUSED, "catalog_unavailable", 0)
        if entry is None or (entry.source_id, entry.digest, entry.size_bytes) != (
            plan.source_id, plan.expected_digest, plan.expected_size_bytes,
        ):
            return AcquisitionResult(AcquisitionState.REFUSED, "plan_mismatch", 0)
        try:
            installed_state = (installed or installed_now)()
        except (CatalogRefused, OSError):
            return AcquisitionResult(AcquisitionState.REFUSED, "installed_state_unavailable", 0)
        try:
            available_bytes = free_bytes() if free_bytes is not None else disk_free(fetch_dir)
            if handoff == "import" and disk_free(models.root) < entry.size_bytes + MIN_FREE_HEADROOM_BYTES:
                return AcquisitionResult(AcquisitionState.REFUSED, "insufficient_disk", 0)
        except OSError:
            return AcquisitionResult(AcquisitionState.REFUSED, "capacity_unavailable", 0)
        key = (entry.model_id, entry.digest)
        reached_transport = False

        def counted_transport(**kwargs):
            nonlocal reached_transport
            reached_transport = True
            return transport(**kwargs)

        result = acquire(
            entry=entry, consent=consent, registry=registry, models=models,
            handoff=handoff, ready_dir=ready_dir,
            context=context, allowed_addresses=allowed_addresses, fetch_dir=fetch_dir,
            free_bytes=available_bytes, resume_from=resume_from,
            attempts_used=attempts.get(key, min(MAX_ATTEMPTS, attempts_used)),
            installed=installed_state, license_acknowledged=license_acknowledged,
            now=now(), actor=actor, deadline_seconds=deadline_seconds, recorder=recorder,
            clock=clock, sleeper=sleeper, transport=counted_transport,
        )

        if result.state in (AcquisitionState.PROMOTED, AcquisitionState.FETCHED):
            attempts[key] = 0
        elif reached_transport:
            attempts[key] = min(MAX_ATTEMPTS, attempts.get(key, attempts_used) + 1)
        return result

    return FetchService(resolve=resolve, transfer=transfer, staging=fetch_dir)


class FetchNotCommissioned(Exception):
    """Only fixed file names and reason words cross the startup boundary."""

    def __init__(self, *, missing: tuple[str, ...]):
        self.missing = missing
        super().__init__(", ".join(missing))


@dataclass(frozen=True)
class FetchCommissioning:
    sources: CommissionedSources
    registry: SourceRegistry
    catalog: ModelCatalog
    consent: SourceConsent
    allowed_addresses: tuple[str, ...]
    ca_certificate: Path
    client_certificate: Path | None
    client_key: Path | None


FETCH_COMMISSIONING_REQUIRED = (
    "trust.json", "sources.signed", "catalog.signed", "ca.pem",
    "addresses.json", "consent.json",
)
FETCH_COMMISSIONING_OPTIONAL = ("client.pem", "client.key")
FETCH_COMMISSIONING_FILES = FETCH_COMMISSIONING_REQUIRED + FETCH_COMMISSIONING_OPTIONAL


def load_fetch_commissioning(directory: Path) -> FetchCommissioning:
    """Load all commissioning or refuse. No parser diagnostics or key material escape."""
    from azazel_nexus.model_paths import bounded_read, load_model_trust

    from .artifact_egress import tls_context

    def checked(name, reader):
        try:
            return reader(directory / name)
        except Exception:  # noqa: BLE001 - any failure is a closed refusal with no exception text
            raise FetchNotCommissioned(missing=(name + ":invalid",)) from None

    required = FETCH_COMMISSIONING_REQUIRED
    missing_items = []
    for name in required:
        try:
            if not (directory / name).is_file():
                missing_items.append(name)
        except OSError:
            missing_items.append(name + ":invalid")
    missing = tuple(missing_items)
    if missing:
        raise FetchNotCommissioned(missing=missing)
    keys, digest, registry_keys = checked("trust.json", lambda p: load_model_trust(p, registry=True))
    sources = checked("trust.json", lambda p: CommissionedSources(keys, registry_keys, digest))
    # Give existing readers an immutable, bounded snapshot instead of reopening.
    @dataclass(frozen=True)
    class Document:
        raw: bytes

        def read_bytes(self):
            return self.raw

    def registry(p):
        return read_registry(Document(bounded_read(p, 4 * 1024 * 1024)), commissioned=sources)

    def catalog(p):
        return read_catalog(Document(bounded_read(p, 4 * 1024 * 1024)), trusted_keys=keys, commissioning_digest=digest)
    signed_registry = checked("sources.signed", registry)
    signed_catalog = checked("catalog.signed", catalog)
    def addresses(p):
        doc = json.loads(bounded_read(p, 65536))
        values = doc["allowed_addresses"]
        if type(values) is not list or not 0 < len(values) <= 256 or not all(type(v) is str for v in values):
            raise ValueError()
        return tuple(str(ipaddress.ip_address(value)) for value in values)
    allowed = checked("addresses.json", addresses)
    def consent(p):
        doc = json.loads(bounded_read(p, 65536))
        if type(doc["sources"]) is not list or not 0 < len(doc["sources"]) <= 256:
            raise ValueError()
        if not all(type(v) is str for v in doc["sources"]) or type(doc["operator"]) is not str or type(doc["at"]) is not str:
            raise ValueError()
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", doc["at"]):
            raise ValueError()
        datetime.fromisoformat(doc["at"])
        return SourceConsent(frozenset(doc["sources"]), doc["operator"], doc["at"])
    confirmed = checked("consent.json", consent)
    ca = directory / "ca.pem"
    checked("ca.pem", lambda p: bounded_read(p, 65536))
    checked("ca.pem", lambda p: tls_context(ca_certificate=str(p)))
    cert, key = directory / "client.pem", directory / "client.key"
    cert_present = checked("client.pem", lambda p: p.is_symlink() or p.exists())
    key_present = checked("client.key", lambda p: p.is_symlink() or p.exists())
    if cert_present != key_present:
        raise FetchNotCommissioned(missing=("client.pem:pair", "client.key:pair"))
    if cert_present:
        checked("client.pem", lambda p: bounded_read(p, 65536))
        checked("client.key", lambda p: bounded_read(p, 65536))
        try:
            tls_context(ca_certificate=str(ca), client_certificate=str(cert), client_key=str(key))
        except Exception:  # noqa: BLE001 - any failure is a closed refusal with no exception text
            raise FetchNotCommissioned(missing=("client.pem:invalid", "client.key:invalid")) from None
    return FetchCommissioning(sources, signed_registry, signed_catalog, confirmed, allowed,
                              ca, cert if cert_present else None, key if key_present else None)
