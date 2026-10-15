"""Connect administrator-selected context to new generation publication only."""

from dataclasses import asdict
from hashlib import sha256
import json

from azazel_nexus.bootstrap_generation_publish import (
    BootstrapGenerationDurabilityUncertain, publish_bootstrap_generation, publication_digest,
)
from azazel_nexus.generation import GenerationRefused
from azazel_nexus.bootstrap_clock import decode_administrator_anchor
from azazel_nexus.bootstrap_clock_store import (
    TimeDurabilityUncertain, initialize_administrator_time, recover_administrator_time,
)
from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap_declared_context import DeclaredBootstrapContext, load_declared_bootstrap_context


def selected_time_digest(*, raw: bytes, selected: DeclaredBootstrapContext, recovery: bool) -> str:
    """Bind exact administrator time bytes, selected context and operation."""
    if type(selected) is not DeclaredBootstrapContext or type(recovery) is not bool:
        raise ApprovalRefused("independent selection and exact operation required")
    anchor = decode_administrator_anchor(raw)
    context = selected.context
    if (anchor.node_digest, anchor.policy_digest, anchor.boot_id) != (
        context.node_digest, context.policy_digest, context.boot_id,
    ):
        raise ApprovalRefused("administrator time anchor selection differs")
    transcript = json.dumps({
        "schema": "azazel-nexus/selected-time-publication/v1",
        "anchor_sha256": sha256(raw).hexdigest(), "selection": asdict(selected),
        "operation": "recover" if recovery else "initialize",
    }, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + sha256(transcript).hexdigest()


def publish_selected_administrator_time(*, raw: bytes, confirmed_digest: str,
                                        confirmed_operation: bool, recovery: bool):
    """Use protected selection, not caller context, for explicit time publication.

    Does not calibrate UTC, set OS clocks, renew records, reset deadlines or start.
    The existing clock store checks current boot, policy, expiry and drift bounds.
    """
    try:
        selected = load_declared_bootstrap_context()
        if (confirmed_operation is not True or type(confirmed_digest) is not str
                or confirmed_digest != selected_time_digest(raw=raw, selected=selected, recovery=recovery)):
            raise ApprovalRefused("selected time confirmation differs")

        def recheck():
            if load_declared_bootstrap_context() != selected:
                raise ApprovalRefused("administrator selection changed during time publication")

        if recovery:
            recover_administrator_time(raw, expected=selected.context,
                                       confirmed_sha256=sha256(raw).hexdigest(),
                                       confirmed_recovery=True, revalidate_selection=recheck)
        else:
            initialize_administrator_time(raw, expected=selected.context,
                                          confirmed_sha256=sha256(raw).hexdigest(),
                                          confirmed_initialize=True, revalidate_selection=recheck)
    except TimeDurabilityUncertain:
        raise
    except Exception:
        raise ApprovalRefused("selected administrator time publication refused; inspect retained state") from None


def selected_publication_digest(*, metadata: bytes, config: bytes,
                                selected: DeclaredBootstrapContext) -> str:
    """Bind confirmation to exact bytes AND administrator-selected target/context."""
    if type(selected) is not DeclaredBootstrapContext:
        raise GenerationRefused("independent declared selection required")
    payload = publication_digest(metadata=metadata, config=config)
    raw = json.dumps({"schema": "azazel-nexus/selected-bootstrap-publication/v1",
                      "publication_digest": payload, "selection": asdict(selected)},
                     sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + sha256(raw).hexdigest()


def publish_selected_bootstrap_generation(*, metadata: bytes, config: bytes,
                                          confirmed_digest: str, confirmed_publish: bool):
    """No caller-supplied context or number, no runtime widening or approval.

    The payload must match independently protected administrator selections.
    Creating this artifact is not proof that the selected closure is admitted.
    """
    try:
        selected = load_declared_bootstrap_context()
        if (confirmed_publish is not True or type(confirmed_digest) is not str
                or confirmed_digest != selected_publication_digest(
                    metadata=metadata, config=config, selected=selected)):
            raise GenerationRefused("selected target and publication confirmation differ")
        def recheck():
            if load_declared_bootstrap_context() != selected:
                raise GenerationRefused("administrator selection changed during publication")

        return publish_bootstrap_generation(
            metadata=metadata, config=config, expected=selected.context,
            confirmed_digest=publication_digest(metadata=metadata, config=config),
            confirmed_publish=confirmed_publish, revalidate_selection=recheck,
        )
    except BootstrapGenerationDurabilityUncertain:
        raise
    except Exception:
        raise GenerationRefused("selected bootstrap publication refused; inspect retained state") from None
