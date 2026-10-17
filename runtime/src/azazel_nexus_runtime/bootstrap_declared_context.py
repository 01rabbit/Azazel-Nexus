"""Independent administrator expectations for provisioning, NOT live admission."""

from dataclasses import dataclass
import re

from azazel_nexus.bootstrap_approval import BootstrapContext
from azazel_nexus.bootstrap_deployment import bind_bootstrap_deployment, declared_node_digest
from azazel_nexus.bootstrap_deployment_store import load_bootstrap_deployment
from azazel_nexus.bootstrap_prestart_store import load_declared_prestart_policy
from azazel_nexus.bootstrap_selection import bind_bootstrap_selection
from azazel_nexus.bootstrap_selection_store import load_bootstrap_selection
from azazel_nexus.hil_preflight import read_boot_id
from azazel_nexus.operator_trust import ApprovalRefused

from .node_config import DeclaredNode, load_declared_node


@dataclass(frozen=True)
class DeclaredBootstrapContext:
    """Distinct from runtime observations: declarations are not measured closure."""

    context: BootstrapContext
    operator: str
    systemd_profile_digest: str

    def __post_init__(self):
        if (type(self.context) is not BootstrapContext
                or type(self.operator) is not str or not self.operator
                or type(self.systemd_profile_digest) is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", self.systemd_profile_digest) is None):
            raise ApprovalRefused("independent declared bootstrap profile required")


def load_declared_bootstrap_context() -> DeclaredBootstrapContext:
    """Build expected bindings without reading candidate approval/generation bytes.

    Admission still requires actual closure, policy semantics, current revocation,
    trusted time, audit and lifecycle checks. This result is for provisioning;
    it must not be substituted for a fresh runtime observation producer.
    """
    try:
        declaration = load_bootstrap_deployment()
        node = load_declared_node()
        if type(node) is not DeclaredNode or declared_node_digest(node.node_id) != declaration.node_digest:
            raise ApprovalRefused("independent node declaration differs")
        boot = read_boot_id()
        selection = load_bootstrap_selection()
        bind_bootstrap_selection(selection, deployment=declaration, boot_id=boot)
        policy = load_declared_prestart_policy(deployment=declaration)
        context = BootstrapContext(
            approval_id=selection.approval_id, node_digest=declaration.node_digest,
            boot_id=boot, generation=selection.generation,
            generation_digest=selection.generation_digest,
            package_digest=policy.package_digest, unit_closure_digest=policy.unit_closure_digest,
            policy_digest=declaration.policy_digest,
            approval_policy_digest=declaration.approval_policy_digest,
            security_epoch=declaration.security_epoch, revocation_digest=declaration.revocation_digest,
        )
        bind_bootstrap_deployment(declaration, context=context, node_id=node.node_id,
                                  operator=declaration.operator)
        if (load_bootstrap_deployment() != declaration or load_declared_node() != node
                or load_bootstrap_selection() != selection or read_boot_id() != boot
                or load_declared_prestart_policy(deployment=declaration) != policy):
            raise ApprovalRefused("declared bootstrap inputs changed")
        return DeclaredBootstrapContext(
            context, declaration.operator, policy.systemd_profile_digest
        )
    except Exception:
        raise ApprovalRefused("declared bootstrap context refused") from None
