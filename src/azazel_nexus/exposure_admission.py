"""The exposure evidence a pass hands the controller, and its own codes (#196 G6).

`docs/deception-exposure-wiring.md` §4.1 to §4.3. The conditions of the
`DECEPTION_EXPOSURE` tier (grant §5 C1) are judged in two halves. The
runtime half, pass step 10 (`azazel_nexus_runtime.exposure_pass`), reads the
host and asks the G6 parts in a fixed order, stages `P1` to `P11`, and makes
one value of it: `ExposureEvidence`. The library half,
`ActivationController._withholding_reason`, consumes that value at one fixed
position (checks L3 to L5) and decides.

`ExposureEvidence` is a **statement the runtime makes**, as
`EdgeBaselineState` is: nothing here proves it (§10 item 8). The production
caller is the pass, and the pass's tripwire re-checks the value after the
decision, every stage included. Its constructor refuses an inconsistent
value:

* `refusal` None: `scope_digest` is a `sha256:<hex>` digest and `stages` is
  exactly `EXPOSURE_STAGES`;
* `refusal` a `"<code>: <phrase>"` string: `stages` is a strict prefix of
  `EXPOSURE_STAGES` (the stages that held before the one that refused).

**The codes this module owns** are the ones the G6 parts do not already
say: the library's (`exposure_evidence_absent`, `exposure_evidence_mismatch`,
and `exposure_stage_unreadable` for an exception in any stage) and the
pass's new stage codes (P1, P6's first two, P8, P9, P10). Each is
`"<code>: <phrase>"` with a fixed phrase (`EXPOSURE_ADMISSION_PHRASES`);
no name, prefix, address or value. The other stage codes are the parts'
own, carried as the parts say them.

This module reads nothing, grants nothing and imports no runtime module.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Optional

__all__ = [
    "DECEPTION_SCOPE_ABSENT",
    "DECEPTION_SCOPE_REFUSED",
    "DECOY_SCOPE_UNRENDERABLE",
    "EXPOSURE_ADMISSION_CODES",
    "EXPOSURE_ADMISSION_PHRASES",
    "EXPOSURE_APPROVAL_BINDING_DIFFERS",
    "EXPOSURE_APPROVAL_NOT_V3",
    "EXPOSURE_EVIDENCE_ABSENT",
    "EXPOSURE_EVIDENCE_MISMATCH",
    "EXPOSURE_FILES_UNREADABLE",
    "EXPOSURE_GENERATION_ABSENT",
    "EXPOSURE_GENERATION_DIFFERS",
    "EXPOSURE_STAGES",
    "EXPOSURE_STAGE_UNREADABLE",
    "ExposureEvidence",
    "admission_refusal",
]

#: The runtime stages of wiring §4.3, in the order the pass asks them.
EXPOSURE_STAGES: tuple[str, ...] = (
    "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10", "P11")

# The library's checks (§4.2).
EXPOSURE_EVIDENCE_ABSENT = "exposure_evidence_absent"
EXPOSURE_EVIDENCE_MISMATCH = "exposure_evidence_mismatch"
EXPOSURE_STAGE_UNREADABLE = "exposure_stage_unreadable"
# The pass's own stage codes (§4.3).
EXPOSURE_APPROVAL_NOT_V3 = "exposure_approval_not_v3"
DECEPTION_SCOPE_ABSENT = "deception_scope_absent"
DECEPTION_SCOPE_REFUSED = "deception_scope_refused"
DECOY_SCOPE_UNRENDERABLE = "decoy_scope_unrenderable"
EXPOSURE_GENERATION_ABSENT = "exposure_generation_absent"
EXPOSURE_FILES_UNREADABLE = "exposure_files_unreadable"
EXPOSURE_GENERATION_DIFFERS = "exposure_generation_differs"
EXPOSURE_APPROVAL_BINDING_DIFFERS = "exposure_approval_binding_differs"

#: Each code's one fixed phrase: no unit, name, prefix, digest or count.
EXPOSURE_ADMISSION_PHRASES: dict[str, str] = {
    EXPOSURE_EVIDENCE_ABSENT: ("this pass handed no exposure evidence, so nothing "
                               "reachable from outside is admitted"),
    EXPOSURE_EVIDENCE_MISMATCH: ("the exposure evidence was measured against another "
                                 "generation than the verified one"),
    EXPOSURE_STAGE_UNREADABLE: ("a stage of the exposure conditions could not be "
                                "completed, so the tier is withheld"),
    EXPOSURE_APPROVAL_NOT_V3: ("the lease does not come from a verified v3 approval "
                               "naming the whole exposure tier"),
    DECEPTION_SCOPE_ABSENT: ("the commissioning proposal carries no deception scope; "
                             "a v3 proposal is required"),
    DECEPTION_SCOPE_REFUSED: "the commissioning proposal's deception scope is refused",
    DECOY_SCOPE_UNRENDERABLE: ("the scope file could not be rendered from the deception "
                               "scope and this boot's ingress names"),
    EXPOSURE_GENERATION_ABSENT: ("the verified generation has no exposure section, so it "
                                 "does not describe the exposure tier"),
    EXPOSURE_FILES_UNREADABLE: ("the exposure unit, watch unit or profile files could not "
                                "be read in their closed form"),
    EXPOSURE_GENERATION_DIFFERS: ("the generation's exposure section does not describe "
                                  "the files and the scope placed now"),
    EXPOSURE_APPROVAL_BINDING_DIFFERS: ("the approval's exposure fields are not this "
                                        "pass's scope digest and counts"),
}
EXPOSURE_ADMISSION_CODES: tuple[str, ...] = tuple(EXPOSURE_ADMISSION_PHRASES)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
#: `"<code>: <phrase>"`: a snake_case code, one space, a nonempty phrase.
_REFUSAL = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+: [^:\n]{1,512}\Z")


def admission_refusal(code: str) -> str:
    """`"<code>: <phrase>"` for one of `EXPOSURE_ADMISSION_CODES`."""

    return f"{code}: {EXPOSURE_ADMISSION_PHRASES[code]}"


@dataclass(frozen=True)
class ExposureEvidence:
    """What pass step 10 established about the exposure tier for one generation.

    `generation_digest` is the verified generation the stages were measured
    against; `scope_digest` the rendered scope file's digest (None until P8
    rendered one); `refusal` None, or the first failing stage's
    `"<code>: <phrase>"`; `stages` the stages that held, in order.
    """

    generation_digest: str
    scope_digest: Optional[str]
    refusal: Optional[str]
    stages: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.generation_digest) is not str or not _DIGEST.match(self.generation_digest):
            raise ValueError("exposure evidence names no generation digest")
        if (type(self.stages) is not tuple
                or self.stages != EXPOSURE_STAGES[:len(self.stages)]):
            raise ValueError("exposure evidence stages are not a prefix of P1 to P11")
        if self.scope_digest is not None and (
                type(self.scope_digest) is not str or not _DIGEST.match(self.scope_digest)):
            raise ValueError("exposure evidence scope digest is not a digest")
        if self.refusal is None:
            if self.stages != EXPOSURE_STAGES or self.scope_digest is None:
                raise ValueError(
                    "exposure evidence without a refusal holds every stage and a scope digest")
            return
        if type(self.refusal) is not str or not _REFUSAL.match(self.refusal):
            raise ValueError("exposure evidence refusal is not a code and a phrase")
        if len(self.stages) >= len(EXPOSURE_STAGES):
            raise ValueError("exposure evidence with a refusal holds a strict prefix of stages")

    @property
    def established(self) -> bool:
        """Every stage held (the constructor already pinned what that implies)."""

        return self.refusal is None

    @property
    def failed_stage(self) -> Optional[str]:
        """The stage that refused, or None when every stage held."""

        return None if self.refusal is None else EXPOSURE_STAGES[len(self.stages)]

    @property
    def code(self) -> Optional[str]:
        """The refusal's code, without its phrase; None when every stage held."""

        return None if self.refusal is None else self.refusal.split(":", 1)[0]
