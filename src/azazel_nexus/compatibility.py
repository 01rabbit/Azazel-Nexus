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

**A lab tuple never admits (ADR-0006).** The admitted CPU is the kernel name
of the one deployment-baseline profile in `platform_profile.REVIEWED_PROFILES`
(``x86_64``), not a constant of this module. A tuple's `purpose` is the
purpose of the reviewed profile for its CPU and nothing else: an ``aarch64``
tuple can be *recorded*, as ``lab-software-verification``, so that a Fabric
`TestedCompatibilityTuple` for ``arm64`` has a faithful Nexus reading, and
`refusal_for` refuses it for every host. There is no flag, field or setting
that lets one admit.

`fabric_shared_fields` renders the fields Nexus and Fabric's
`TestedCompatibilityTuple` both carry, in Fabric's vocabulary; the Fabric
model itself is built and compared in `fabric_boundary` only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from . import platform_profile as _pp
from .resource_profile import ResourceProfile

__all__ = [
    "ADMITTED_ARCHITECTURE",
    "FABRIC_ONLY_FIELDS",
    "FABRIC_SHARED_FIELDS",
    "FABRIC_TUPLE_PRODUCT",
    "NEXUS_ONLY_FIELDS",
    "CompatibilityRefused",
    "HostFacts",
    "TestedTuple",
    "TestedTupleSet",
    "fabric_release_version",
    "fabric_shared_fields",
    "tuple_purpose",
]

#: `docs/contract-ownership.md` §4.1: the CPU of the deployment-baseline
#: profile (ADR-0002, ADR-0003 D3), in the kernel spelling the tuple records,
#: compatibility configuration, HIL records and the Edge pin already use. It
#: is read from `platform_profile.REVIEWED_PROFILES` (ADR-0006) so it cannot
#: drift from the profile the HIL preflight and core reserve check; it is
#: still ``x86_64``, and it is the only CPU a tuple can be admitted for.
ADMITTED_ARCHITECTURE = _pp.kernel_name(_pp.deployment_baseline_profile().architecture)

#: What a version range looks like. Anything matching is refused as a tuple
#: field, because it describes a set of versions rather than the one that was
#: tested.
_RANGE = re.compile(r"[*^~]|[<>]=?|\s-\s|\|\||,|\bx\b|\.\*")

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class CompatibilityRefused(Exception):
    """The tuple is not a tuple, or the candidate matches none."""


def tuple_purpose(architecture: object) -> str:
    """The purpose a tuple for this kernel-spelled CPU has, from the reviewed
    profile table. A CPU no profile lists is refused, not given a purpose."""

    try:
        return _pp.purpose_for_architecture(_pp.from_boundary("kernel", architecture))
    except _pp.PlatformRefused as refused:
        raise CompatibilityRefused(
            f"architecture {architecture!r} is not a reviewed CPU ({refused.reason})"
        ) from None


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

    model_role: str | None = None

    #: What results for this tuple may be used for (ADR-0006): the purpose of
    #: the reviewed platform profile for `architecture`, and only that. The
    #: default is the deployment baseline, so every existing record reads as
    #: before; ``lab-software-verification`` is accepted only together with
    #: the lab profile's CPU, and `refusal_for` refuses such a tuple always.
    purpose: str = _pp.PURPOSE_DEPLOYMENT_BASELINE

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
        if self.model_role not in (None, "embedding", "generative"):
            raise CompatibilityRefused("unknown model role")
        # Fields are read by name from `vars(self)`, not `getattr`: this module
        # is reachable from the broker's content plane (through
        # `fabric_boundary`), whose import scan refuses dynamic attribute reads.
        fields = vars(self)
        for name in self._DIGESTS:
            value = fields[name]
            if not _DIGEST.fullmatch(value or ""):
                raise CompatibilityRefused(
                    f"{name} is an immutable digest as sha256:<64 hex>; got {value!r}"
                )
        if type(self.purpose) is not str or self.purpose not in _pp.PURPOSES:
            raise CompatibilityRefused(f"unknown tuple purpose {self.purpose!r}")
        if self.purpose == _pp.PURPOSE_DEPLOYMENT_BASELINE:
            if self.architecture != ADMITTED_ARCHITECTURE:
                raise CompatibilityRefused(
                    f"Nexus admits {ADMITTED_ARCHITECTURE} only; got {self.architecture!r}"
                )
        elif tuple_purpose(self.architecture) != self.purpose:
            raise CompatibilityRefused(
                f"a {self.purpose} tuple names the CPU of a {self.purpose} profile; "
                f"{self.architecture!r} is not one"
            )
        if self.security_epoch < 0:
            raise CompatibilityRefused("a security epoch is not negative")
        for name in self._VERSIONED:
            value = fields[name]
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

        if self.purpose != _pp.PURPOSE_DEPLOYMENT_BASELINE:
            # First, and for every host: the CPU, OS and fields below may all
            # match, and a lab result is still not deployment evidence.
            return (
                f"the tuple was tested on a {self.purpose} profile "
                f"({self.architecture!r}); it records a lab software run and "
                "cannot back a production admission (ADR-0006)"
            )
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
            **({"model_role": self.model_role} if self.model_role is not None else {}),
            # Omitted for the baseline, so every record that existed before
            # ADR-0006 -- and every mission pack that names one -- is unchanged.
            **({"purpose": self.purpose}
               if self.purpose != _pp.PURPOSE_DEPLOYMENT_BASELINE else {}),
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
        self, component_digest: str, host: HostFacts, *, model_role: str | None = None
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
            if model_role is not None and (tested.model_role or "generative") != model_role:
                refusals.append("tested model role mismatch")
                continue
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


# -- Fabric's `TestedCompatibilityTuple` (ADR-0006) ---------------------------

#: The `product` a Fabric tuple about Nexus names (Fabric's golden fixture).
FABRIC_TUPLE_PRODUCT = "azazel-nexus"

#: (Nexus field, Fabric field) for what both records carry. Every value is
#: compared exactly after the vocabulary step in `fabric_shared_fields`.
FABRIC_SHARED_FIELDS: tuple[tuple[str, str], ...] = (
    ("component_digest", "artifact_digest"),
    ("adapter_digest", "adapter_digest"),
    ("fabric_version", "fabric_version"),
    ("os_abi", "os_abi"),
    ("architecture", "architecture"),
    ("cpu_features", "cpu_features"),
    ("schema_features", "schema_features"),
    ("overlay_schema", "overlay_schema_version"),
)

#: Nexus fields Fabric's tuple has no place for. They stay Nexus-local and are
#: neither exported nor inferred from a Fabric record: `profile` in particular
#: is a Nexus resource envelope, and Fabric's free-text `deployment_profile`
#: is not read as one.
NEXUS_ONLY_FIELDS: tuple[str, ...] = (
    "renderer_digest", "toolchain_digest", "fabric_features", "profile",
    "security_epoch", "max_rollback_version", "model_role", "purpose",
)

#: Fabric fields with no Nexus counterpart: identity and provenance of the
#: claim. The caller supplies them when projecting; a comparison ignores them.
FABRIC_ONLY_FIELDS: tuple[str, ...] = (
    "schema_version", "tuple_id", "product", "product_version",
    "deployment_profile", "evidence_ref",
)


def fabric_release_version(tag: object) -> str:
    """A Nexus tuple's Fabric tag (``v0.9.0rc5``) as Fabric's version string
    (``0.9.0rc5``, its ``__version__``). Exactly one leading ``v``; anything
    else is refused rather than guessed."""

    if type(tag) is not str or not tag.startswith("v") or not tag[1:] or tag[1] == "v":
        raise CompatibilityRefused(
            f"fabric_version {tag!r} is not a Fabric release tag of the form v<version>"
        )
    return tag[1:]


def fabric_shared_fields(tested: TestedTuple) -> dict:
    """The fields `tested` shares with Fabric's `TestedCompatibilityTuple`,
    named and spelled as Fabric spells them.

    Two translations, each one table: the CPU through `platform_profile`
    (kernel ``x86_64``/``aarch64`` to Fabric ``amd64``/``arm64``), and the
    Fabric tag through `fabric_release_version`. Feature sets become sorted
    tuples, so the same tuple renders the same bytes. Everything else is
    copied as is; ``os_abi`` in particular is compared byte for byte, since
    no table relates Nexus's and Fabric's spellings of it.
    """

    if type(tested) is not TestedTuple:
        raise CompatibilityRefused("a Fabric rendering needs a TestedTuple")
    try:
        architecture = _pp.fabric_name(_pp.from_boundary("kernel", tested.architecture))
    except _pp.PlatformRefused as refused:
        raise CompatibilityRefused(
            f"architecture {tested.architecture!r} has no Fabric name ({refused.reason})"
        ) from None
    return {
        "artifact_digest": tested.component_digest,
        "adapter_digest": tested.adapter_digest,
        "fabric_version": fabric_release_version(tested.fabric_version),
        "os_abi": tested.os_abi,
        "architecture": architecture,
        "cpu_features": tuple(sorted(tested.cpu_features)),
        "schema_features": tuple(sorted(tested.schema_features)),
        "overlay_schema_version": tested.overlay_schema,
    }
