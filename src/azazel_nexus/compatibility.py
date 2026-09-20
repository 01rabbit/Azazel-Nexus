"""Tested compatibility tuples, and why a version range is not one (#5, E2).

`docs/contract-ownership.md` §4.1 is the contract this module implements:

    Field releases use a deny-by-default set of tested tuples. A tuple is
    exact; a version range is a descriptive compatibility claim and MUST NOT
    authorize activation.

Four properties, each a refusal rather than a convention.

**Deny by default.** `TestedTupleSet.admits` returns a refusal unless some
member matches. There is no path through this module that admits a candidate
because nothing objected to it.

**A tuple is exact.** Every digest and version field is compared byte for
byte. A field that *looks* like a range — `>=1.2`, `1.2.*`, `^1.2`, `1.2 - 1.4`
— is refused when the tuple is constructed, not tolerated at match time. A
range is a claim about compatibility; admission needs a statement about what
was tested.

**Feature sets go one way.** `cpu_features`, `fabric_features` and
`schema_features` are *requirements*: what the tuple needs must be a subset of
what the host offers. The reverse — accepting a host that needs more than the
tuple was tested with — is the shape this check exists to prevent, so the
direction is tested in both directions.

**Ordered comparisons go one way too.** The host's security epoch must be at
least the tuple's minimum. An epoch comparison written the other way admits
exactly the artifacts the epoch exists to exclude.

The resource profile is matched **exactly**, not as a floor. A tuple records
the envelope it was tested in; a component tested only in `core` and run in
`lite` is running somewhere nobody tested it. Two envelopes need two tuples.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from .resource_profile import ResourceProfile

__all__ = [
    "ADMITTED_ARCHITECTURE",
    "CompatibilityRefused",
    "HostFacts",
    "TestedTuple",
    "TestedTupleSet",
]

#: `docs/contract-ownership.md` §4.1: "`x86_64` for Nexus; other values are
#: rejected". Not a default and not a preference -- the only admitted value.
ADMITTED_ARCHITECTURE = "x86_64"

#: What a version range looks like. Anything matching is refused as a tuple
#: field, because it describes a set of versions rather than the one that was
#: tested.
_RANGE = re.compile(r"[*^~]|[<>]=?|\s-\s|\|\||,|\bx\b|\.\*")

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class CompatibilityRefused(Exception):
    """The tuple is not a tuple, or the candidate matches none."""


@dataclass(frozen=True)
class HostFacts:
    """What this host is, as measured or configured. Never what it may do."""

    os_abi: str
    architecture: str
    cpu_features: frozenset[str]
    fabric_version: str
    fabric_features: frozenset[str]
    schema_features: frozenset[str]
    profile: ResourceProfile
    overlay_schema: str
    security_epoch: int


@dataclass(frozen=True)
class TestedTuple:
    """One exact combination that was tested, and nothing near it.

    `__test__ = False` because the contract's own name for this starts with
    "Tested", and pytest would otherwise try to collect it. The alternative --
    renaming it -- would cost the traceability to
    `docs/contract-ownership.md` §4.1, which is worth more than the class name.
    """

    __test__ = False

    component_digest: str
    adapter_digest: str
    renderer_digest: str
    toolchain_digest: str
    os_abi: str
    architecture: str
    fabric_version: str
    profile: ResourceProfile
    overlay_schema: str
    security_epoch: int
    max_rollback_version: str
    cpu_features: frozenset[str] = frozenset()
    fabric_features: frozenset[str] = frozenset()
    schema_features: frozenset[str] = frozenset()

    #: Fields whose value must name one version, never a set of them.
    _VERSIONED = (
        "os_abi",
        "fabric_version",
        "overlay_schema",
        "max_rollback_version",
    )
    _DIGESTS = (
        "component_digest",
        "adapter_digest",
        "renderer_digest",
        "toolchain_digest",
    )

    def __post_init__(self) -> None:
        for name in self._DIGESTS:
            value = getattr(self, name)
            if not _DIGEST.match(value or ""):
                raise CompatibilityRefused(
                    f"{name} is an immutable digest as sha256:<64 hex>; got {value!r}"
                )
        if self.architecture != ADMITTED_ARCHITECTURE:
            raise CompatibilityRefused(
                f"Nexus admits {ADMITTED_ARCHITECTURE} only; got {self.architecture!r}"
            )
        if self.security_epoch < 0:
            raise CompatibilityRefused("a security epoch is not negative")
        for name in self._VERSIONED:
            value = getattr(self, name)
            if not str(value).strip():
                raise CompatibilityRefused(f"{name} names one tested version")
            if _RANGE.search(str(value)):
                raise CompatibilityRefused(
                    f"{name}={value!r} describes a set of versions; a tested tuple "
                    "names the one version that was tested, and a range is a "
                    "compatibility claim that must not authorize activation"
                )

    def refusal_for(self, host: HostFacts) -> Optional[str]:
        """Why this tuple does not cover `host`, or `None` if it does.

        Returns text rather than a bool so that a refusal names the dimension
        that produced it. Two dimensions failing for one reason would read as
        one check.
        """

        if host.architecture != self.architecture:
            return (
                f"architecture {host.architecture!r} is not the tested "
                f"{self.architecture!r}"
            )
        if host.os_abi != self.os_abi:
            return f"os_abi {host.os_abi!r} is not the tested {self.os_abi!r}"
        if host.fabric_version != self.fabric_version:
            return (
                f"fabric_version {host.fabric_version!r} is not the tested "
                f"{self.fabric_version!r}"
            )
        if host.overlay_schema != self.overlay_schema:
            return (
                f"overlay_schema {host.overlay_schema!r} is not the tested "
                f"{self.overlay_schema!r}"
            )
        if host.profile is not self.profile:
            return (
                f"the tuple was tested in the {self.profile.value!r} envelope and "
                f"this host is {host.profile.value!r}; an envelope it was not "
                "tested in is an envelope nobody tested it in"
            )
        if host.security_epoch < self.security_epoch:
            return (
                f"security epoch {host.security_epoch} is below the tuple's minimum "
                f"{self.security_epoch}"
            )
        for label, required, offered in (
            ("cpu_features", self.cpu_features, host.cpu_features),
            ("fabric_features", self.fabric_features, host.fabric_features),
            ("schema_features", self.schema_features, host.schema_features),
        ):
            missing = sorted(required - offered)
            if missing:
                return f"the host does not offer required {label}: {missing}"
        return None

    def as_record(self) -> dict:
        """The tuple as it appears in an audit event. Sorted, so it replays."""

        return {
            "component_digest": self.component_digest,
            "adapter_digest": self.adapter_digest,
            "renderer_digest": self.renderer_digest,
            "toolchain_digest": self.toolchain_digest,
            "os_abi": self.os_abi,
            "architecture": self.architecture,
            "cpu_features": sorted(self.cpu_features),
            "fabric_version": self.fabric_version,
            "fabric_features": sorted(self.fabric_features),
            "schema_features": sorted(self.schema_features),
            "profile": self.profile.value,
            "overlay_schema": self.overlay_schema,
            "security_epoch": self.security_epoch,
            "max_rollback_version": self.max_rollback_version,
        }


@dataclass(frozen=True)
class TestedTupleSet:
    """The deny-by-default set. Empty admits nothing, and says so."""

    __test__ = False

    tuples: tuple[TestedTuple, ...] = ()

    @classmethod
    def of(cls, tuples: Iterable[TestedTuple]) -> "TestedTupleSet":
        return cls(tuple(tuples))

    def admits(
        self, component_digest: str, host: HostFacts
    ) -> tuple[Optional[TestedTuple], str]:
        """The matching tuple and why, or `None` and why not.

        Both halves are returned in both cases: an admission that cannot say
        which tuple admitted it is an admission nobody can audit.
        """

        if not self.tuples:
            return None, (
                "no tested tuples are configured; a deny-by-default set that is "
                "empty admits nothing, which is the correct answer and not an error"
            )

        candidates = [t for t in self.tuples if t.component_digest == component_digest]
        if not candidates:
            return None, (
                f"no tested tuple names component {component_digest}; a correctly "
                "signed artifact that matches no tested tuple is rejected"
            )

        refusals: list[str] = []
        for tested in candidates:
            refusal = tested.refusal_for(host)
            if refusal is None:
                return tested, (
                    f"component {component_digest} matches a tested tuple for "
                    f"{tested.os_abi} / {tested.profile.value}"
                )
            refusals.append(refusal)
        return None, (
            f"component {component_digest} is named by {len(candidates)} tested "
            f"tuple(s), none of which covers this host: {'; '.join(refusals)}"
        )
