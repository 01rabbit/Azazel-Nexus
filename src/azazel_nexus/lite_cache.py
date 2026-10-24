"""The embedded read-only Knowledge Lite cache, and its staged/atomic reader.

Nexus#15. Knowledge ADR-0015 D7 splits the concern: Knowledge produces, selects,
and signs a Lite artifact; **what a consumer does when it cannot read one is the
consumer's decision**, and Knowledge cannot prove it. This module is that
decision.

    A consumer that cannot read it must remain fully operational -- Edge Core
    is never blocked by missing, corrupt, or expired knowledge.

Four things follow, and each is enforced rather than described.

**Absence is not an error.** A missing artifact yields `ABSENT` and a working
node. There is no code path here that raises because knowledge is unavailable.

**Verification is not this module's job, and its absence fails closed.** Nexus
owns the reader, not the verifier. The verifier is injected; the default
(`refuse_everything`) verifies nothing and refuses everything, so a caller that
forgets to supply one gets a node that runs with no Lite data -- never a node
that admits unverified data.

**Any exception from verification is a refusal.** Knowledge's verifier wraps
the tar decoder's error on the truncated fixture as `BUNDLE_ARCHIVE_UNREADABLE`,
and its own `negative.json` still warns not to rely on that: "a reader that
catches only the verifier's own exception type is one decoder change away from
letting a truncated artifact through as an unhandled error". So this reader
catches `Exception`, deliberately and narrowly around the verifier call alone.

**Staging is not admission.** Two of Knowledge's negative fixtures write bytes
into staging *before* failing. Promotion therefore happens only after a verdict
of admitted -- never as a side effect of having written something.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .store_dirs import store_directory

__all__ = [
    "DEGRADED_CAPABILITY",
    "Admission",
    "AdmissionDecision",
    "Freshness",
    "StagedReader",
    "Verdict",
    "classify_freshness",
    "refuse_everything",
    "split_by_freshness",
]

#: Where a node lands when Lite is unavailable for any reason.
#:
#: It is a capability state, not an authority level, and it is not an error
#: state. `docs/capability-model.md` §7: degradation is driven by the loss of
#: an optional component, never by a change in authority.
DEGRADED_CAPABILITY = "CORE"


class Admission(str, Enum):
    """What the cache did with an artifact."""

    #: Verified, promoted, and readable.
    ADMITTED = "admitted"
    #: No artifact at that path. Expected, routine, not a fault.
    ABSENT = "absent"
    #: An artifact was present and the verifier rejected it.
    REFUSED = "refused"
    #: An artifact was present and could not be assessed at all -- no verifier
    #: was supplied, or verification raised something the verifier does not
    #: model. Distinguished from REFUSED because the operator plane must be
    #: able to tell "we checked and said no" from "we could not check".
    UNVERIFIABLE = "unverifiable"


class Freshness(str, Enum):
    """Whether a claim may be served, evaluated against the caller's `as_of`."""

    CURRENT = "current"
    EXPIRED = "expired"
    #: The claim carries no expiry the consumer can evaluate. Static reference
    #: material is this: versioned, not dated.
    NOT_CLOCK_BOUND = "not_clock_bound"
    #: An expiry was declared and could not be parsed. Treated as expired at
    #: the serving boundary; kept distinct so the operator plane can see that
    #: the artifact, not the clock, is the problem.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Verdict:
    """What an injected verifier returns. It never carries an authority."""

    admitted: bool
    reason: str
    #: Knowledge's error code where one exists. `None` is normal: an artifact
    #: that fails to extract here (the truncated fixture does) never reaches
    #: the verifier, so no verifier code exists for it.
    error_code: str | None = None


@dataclass(frozen=True)
class AdmissionDecision:
    """The whole outcome, including what the operator plane must be told."""

    admission: Admission
    capability: str
    reason: str
    error_code: str | None = None
    #: True when bytes reached staging before the outcome was known. Recorded
    #: because "nothing was written" and "something was written and discarded"
    #: are different facts, and an audit record that conflates them is wrong.
    staging_written: bool = False
    #: True only when a promotion actually happened.
    promoted: bool = False
    degradation_visible: bool = True

    def blocks_core(self) -> bool:
        """Always False, and asserted as such by the tests.

        Kept as a method rather than a constant so the claim is stated at the
        place a caller would look for it, and so a future change that made it
        conditional would have to be written deliberately.
        """

        return False


def refuse_everything(artifact: Path) -> Verdict:
    """The default verifier: verifies nothing, admits nothing.

    A caller that forgets to inject a real verifier gets a node running on
    `CORE` with no Lite data. The alternative default -- admitting what it
    cannot check -- is the one failure this module must not be able to have.
    """

    return Verdict(
        admitted=False,
        reason=(
            "no verifier was supplied; this reader does not verify and will not "
            "admit unverified content"
        ),
        error_code=None,
    )


def classify_freshness(expiry: str | None, *, as_of: str) -> Freshness:
    """Classify one claim's expiry against the caller's `as_of`.

    Expiry is per claim. Knowledge's fixture index is explicit that it has no
    manifest field and no filename convention, so a consumer cannot decide an
    artifact is expired -- it decides each claim is, and keeps serving the
    rest. That is why an `expired` fixture is a *valid* artifact.
    """

    if expiry is None:
        return Freshness.NOT_CLOCK_BOUND
    try:
        expires = _parse_instant(expiry)
        now = _parse_instant(as_of)
    except ValueError:
        return Freshness.UNKNOWN
    return Freshness.CURRENT if expires > now else Freshness.EXPIRED


def split_by_freshness(
    claims: Sequence[Mapping], *, as_of: str
) -> tuple[list[dict], list[dict]]:
    """Split claims into what may be served now and what is withheld.

    An expired claim is **unavailable, not merely labelled** -- it does not
    appear in the served list. The artifact around it is not discarded:
    claims that are not clock-bound keep being served, which is how
    withholding the expired entries stays distinguishable from throwing the
    artifact away.

    This is the only implementation of that rule. `StagedReader.serve` and
    `lite_service.KnowledgeLite.read` both call it rather than each deciding
    for itself, because two copies of a serving rule agree only until one of
    them is edited.
    """

    served: list[dict] = []
    withheld: list[dict] = []
    for claim in claims:
        freshness = classify_freshness(claim.get("expiry"), as_of=as_of)
        labelled = {**claim, "freshness": freshness.value}
        if freshness in (Freshness.CURRENT, Freshness.NOT_CLOCK_BOUND):
            served.append(labelled)
        else:
            withheld.append(labelled)
    return served, withheld


def _parse_instant(raw: str) -> datetime:
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError(f"instant must carry an explicit offset: {raw!r}")
    return parsed


@dataclass
class StagedReader:
    """Stage, verify, then promote -- and never in any other order.

    The live directory is only ever replaced by an atomic rename of a fully
    verified staging directory, so a reader looking at the live path during a
    swap sees the old content or the new one, never a partial mixture.
    """

    root: Path
    verifier: Callable[[Path], Verdict] = refuse_everything
    _staging_written: bool = field(default=False, init=False, repr=False)

    @property
    def live(self) -> Path:
        """Where a verified archive is unpacked and served from.

        Deliberately **not** `root/live`. `LiteGenerationStore` keeps its live
        *pointer* -- a file -- at that name, and a node whose staged reader and
        generation store share a root had one of them overwrite the other's
        `live` and the next promotion raise `NotADirectoryError` out of
        `shutil.rmtree`. A module whose docstring says it never raises for the
        node must not have a second module able to make it raise.
        """

        return self.root / "admitted"

    @property
    def staging(self) -> Path:
        return self.root / "staging"

    def admit(self, artifact: Path, *, extract: Callable[[Path, Path], None] | None = None) -> AdmissionDecision:
        """Attempt to make `artifact` the live cache. Never raises for the node."""

        if not artifact.exists():
            return AdmissionDecision(
                admission=Admission.ABSENT,
                capability=DEGRADED_CAPABILITY,
                reason=(
                    f"no Lite artifact at {artifact}; absence of knowledge is not "
                    "an error condition and Core continues"
                ),
            )

        self._reset_staging()
        self._staging_written = False
        if extract is not None:
            # Extraction may write bytes and *then* fail. That is the shape of
            # two of Knowledge's negative fixtures, and it must not become an
            # admission.
            try:
                extract(artifact, self.staging)
            except Exception as exc:  # noqa: BLE001 -- see module docstring
                self._staging_written = self._staging_has_content()
                self._reset_staging()
                return AdmissionDecision(
                    admission=Admission.UNVERIFIABLE,
                    capability=DEGRADED_CAPABILITY,
                    reason=f"extraction failed and nothing was promoted: {exc}",
                    staging_written=self._staging_written,
                )
            self._staging_written = self._staging_has_content()

        try:
            verdict = self.verifier(artifact)
        except Exception as exc:  # noqa: BLE001 -- any exception is a refusal
            self._reset_staging()
            return AdmissionDecision(
                admission=Admission.UNVERIFIABLE,
                capability=DEGRADED_CAPABILITY,
                reason=(
                    "verification raised rather than returning a verdict; treated "
                    f"as a refusal: {exc}"
                ),
                staging_written=self._staging_written,
            )

        if not verdict.admitted:
            self._reset_staging()
            return AdmissionDecision(
                admission=Admission.REFUSED,
                capability=DEGRADED_CAPABILITY,
                reason=verdict.reason,
                error_code=verdict.error_code,
                staging_written=self._staging_written,
            )

        self._promote()
        return AdmissionDecision(
            admission=Admission.ADMITTED,
            capability="LITE",
            reason=verdict.reason,
            error_code=verdict.error_code,
            staging_written=self._staging_written,
            promoted=True,
            degradation_visible=False,
        )

    def serve(
        self, claims: Sequence[dict], *, as_of: str
    ) -> tuple[list[dict], list[dict]]:
        """Split claims into what may be served and what is withheld.

        Delegates to `split_by_freshness`. The rule has one implementation
        because two copies of "which claims may be served" agree only until
        one of them is edited.
        """

        return split_by_freshness(claims, as_of=as_of)

    # -- internals ---------------------------------------------------------

    def _staging_has_content(self) -> bool:
        return self.staging.exists() and any(self.staging.rglob("*"))

    def _reset_staging(self) -> None:
        if self.staging.exists():
            shutil.rmtree(self.staging)
        store_directory(self.staging)

    def _promote(self) -> None:
        """Replace live with staging by rename. No partial state is observable."""

        store_directory(self.root)
        retired = self.root / "retired"
        if retired.exists():
            shutil.rmtree(retired)
        if self.live.exists():
            os.rename(self.live, retired)
        os.rename(self.staging, self.live)
        if retired.exists():
            shutil.rmtree(retired)
        store_directory(self.staging)
