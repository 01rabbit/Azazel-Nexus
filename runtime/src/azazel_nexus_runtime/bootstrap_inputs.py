"""Connect protected bootstrap approval and retained deadline readers.

The independent observation producer is still a required deployment component,
not values loaded from approval.json. No enrollment, genesis, deadline reset,
generation admission or service operation happens here.
"""

from dataclasses import dataclass
from typing import Callable

from azazel_nexus.bootstrap_approval import (
    BootstrapContext, VerifiedBootstrapApproval, parse_bootstrap_time,
)
from azazel_nexus.bootstrap_deadline import (
    BootstrapDeadline, begin_deadline, read_boottime_ns,
)
from azazel_nexus.bootstrap_clock import AdministratorTimeWindow
from azazel_nexus.bootstrap_clock_store import load_administrator_time_window
from azazel_nexus.bootstrap_deadline_store import advance_deadline, retain_initial_deadline
from azazel_nexus.bootstrap_store import (
    load_bootstrap_approval,
    read_bootstrap_installed_manifest,
)
from azazel_nexus.bootstrap_prestart_store import load_bootstrap_prestart_policy
from azazel_nexus.bootstrap_prestart_policy import BootstrapPrestartPolicy
from azazel_nexus.bootstrap_generation import VerifiedBootstrapGeneration
from azazel_nexus.bootstrap_generation_store import load_bootstrap_generation
from azazel_nexus.installed_files import (
    SelectedInstalledFiles, measure_installed_files, read_pinned_installed_files,
)
from azazel_nexus.installed_manifest import (
    decode_installed_manifest,
    decode_scope,
    resolve_installed_link,
)
from azazel_nexus.bootstrap_deployment import bind_bootstrap_deployment
from azazel_nexus.bootstrap_deployment_store import load_bootstrap_deployment
from azazel_nexus.hil_preflight import read_boot_id
from azazel_nexus.operator_trust import ApprovalRefused

from .node_config import DeclaredNode, load_declared_node
from .hardening import ACTIVATION_CONTROLLER_UNIT, PROFILES
from .bootstrap_prestart import check_bootstrap_capacity
from .units import UNIT_NAMES, UnitKey
from .startup_wrapper import parse_wrapper
from .python_profile import (
    BASE_INTERPRETER, MAX_PYVENV_BYTES, pyvenv_config_path, validate_pyvenv_config,
)
from .running_python import observe_running_python, validate_running_python
from .python_startup import (
    StartupAbsence, observe_python_startup_absence, startup_absence_paths,
)
from .import_routing import ImportRouting, observe_import_routing
from .loaded_modules import LoadedModules, observe_loaded_modules
from .bootstrap_systemd_profile import (
    SystemdBootstrapProfile,
    bootstrap_systemd_profile_digest,
    observe_bootstrap_systemd_profile,
)
from .bootstrap_declared_context import (
    DeclaredBootstrapContext,
    load_declared_bootstrap_context,
)
from .debian_packages import (
    observe_installed_packages,
    validate_package_snapshot,
)

def measure_bootstrap_installed_files(context: BootstrapContext) -> SelectedInstalledFiles:
    """Measure the fixed, protected selected-file manifest for this admission.

    The manifest's exact bytes are pinned by ``unit_closure_digest`` in the
    independently selected context. All three fixed bootstrap entrypoints must
    be listed as executable regular files. Their canonical startup paths must
    also be covered by pinned regular files or exact directory membership.
    This checks only explicitly listed paths;
    it does not prove package authenticity, absence outside declared roots, Python
    import closure, or loaded systemd configuration.
    """
    try:
        with decode_scope():
            if type(context) is not BootstrapContext:
                raise ApprovalRefused("independent bootstrap context required")
            raw = read_bootstrap_installed_manifest()
            manifest = decode_installed_manifest(
                raw, expected_digest=context.unit_closure_digest,
            )
            targets = {
                ACTIVATION_CONTROLLER_UNIT: "azazel_nexus_runtime.activated:main",
                UNIT_NAMES[UnitKey.AUDITD]: "azazel_nexus_runtime.auditd:main",
                UNIT_NAMES[UnitKey.COMMISSIOND]: "azazel_nexus_runtime.commissiond:main",
            }
            required = {
                profile.executable.removeprefix("/"): targets[profile.unit]
                for profile in PROFILES if profile.unit in targets
            }
            if len(required) != 3:
                raise ApprovalRefused("fixed bootstrap executable profile differs")
            executable_paths = {entry.path for entry in manifest.files if entry.mode == 0o755}
            if not required.keys() <= executable_paths:
                raise ApprovalRefused("bootstrap entrypoints missing from installed selection")
            paths = tuple(sorted(required))
            contents = read_pinned_installed_files(
                raw, expected_digest=context.unit_closure_digest, paths=paths,
            )
            if type(contents) is not tuple or len(contents) != len(paths):
                raise ApprovalRefused("pinned bootstrap wrapper content required")
            startup = tuple(parse_wrapper(content, target=required[path])
                            for path, content in zip(paths, contents, strict=True))
            if len(set(startup)) != 1:
                raise ApprovalRefused("bootstrap wrapper startup paths differ")
            interpreter, import_paths = startup[0]
            resolved_interpreter = resolve_installed_link(manifest, interpreter.removeprefix("/"))
            if resolved_interpreter not in executable_paths:
                raise ApprovalRefused("bootstrap interpreter is not independently pinned")
            directories = {entry.path for entry in manifest.directories}
            pinned_files = {entry.path for entry in manifest.files}
            for path in import_paths:
                relative = path.removeprefix("/")
                if (relative not in directories
                        and not (path.endswith(".zip") and relative in pinned_files)):
                    raise ApprovalRefused("bootstrap initial import path is not covered")
            if any(path.removeprefix("/") not in directories for path in import_paths):
                raise ApprovalRefused("bootstrap source profile requires unpacked imports")
            # pyvenv.cfg is consulted by CPython before the wrapper body. Never
            # reopen an unpinned pathname or accept creation metadata as executable
            # identity: the base bytes and any copied interpreter must also match.
            entries = {entry.path: entry for entry in manifest.files}
            base = entries.get(BASE_INTERPRETER)
            selected = entries[resolved_interpreter]
            if (base is None or base.mode != 0o755
                    or (selected.size, selected.sha256) != (base.size, base.sha256)):
                raise ApprovalRefused("bootstrap base interpreter selection differs")
            config_path = pyvenv_config_path(interpreter)
            config = entries.get(config_path)
            if (config is None or config.mode != 0o644
                    or not 0 < config.size <= MAX_PYVENV_BYTES):
                raise ApprovalRefused("bootstrap Python venv metadata not pinned")
            config_contents = read_pinned_installed_files(
                raw, expected_digest=context.unit_closure_digest, paths=(config_path,),
            )
            if type(config_contents) is not tuple or len(config_contents) != 1:
                raise ApprovalRefused("pinned Python venv content required")
            version = validate_pyvenv_config(config_contents[0])
            running_before = observe_running_python()
            validate_running_python(
                running_before, interpreter=interpreter, import_paths=import_paths,
                version=version, expected_file=selected,
            )
            startup_before = observe_python_startup_absence(interpreter)
            if (type(startup_before) is not StartupAbsence
                    or startup_before.paths != startup_absence_paths(interpreter)):
                raise ApprovalRefused("fixed Python startup absence required")
            main_path = next("/" + path for path, target in required.items()
                             if target == targets[ACTIVATION_CONTROLLER_UNIT])
            routing_before = observe_import_routing(import_paths, manifest, main_path=main_path)
            if type(routing_before) is not ImportRouting or routing_before.import_paths != import_paths:
                raise ApprovalRefused("fixed Python import routing required")
            modules_before = observe_loaded_modules(manifest, import_paths, main_path)
            if type(modules_before) is not LoadedModules or modules_before.import_paths != import_paths:
                raise ApprovalRefused("fixed loaded module profile required")
            measured = measure_installed_files(
                raw, expected_digest=context.unit_closure_digest
            )
            if (type(measured) is not SelectedInstalledFiles
                    or measured.manifest_digest != context.unit_closure_digest
                    or read_bootstrap_installed_manifest() != raw):
                raise ApprovalRefused("bootstrap installed file measurement differs")
            running_after = observe_running_python()
            validate_running_python(
                running_after, interpreter=interpreter, import_paths=import_paths,
                version=version, expected_file=selected,
            )
            if running_after != running_before:
                raise ApprovalRefused("current Python changed during installed measurement")
            startup_after = observe_python_startup_absence(interpreter)
            if type(startup_after) is not StartupAbsence or startup_after != startup_before:
                raise ApprovalRefused("Python startup absence changed during installed measurement")
            routing_after = observe_import_routing(import_paths, manifest, main_path=main_path)
            if type(routing_after) is not ImportRouting or routing_after != routing_before:
                raise ApprovalRefused("Python import routing changed during installed measurement")
            modules_after = observe_loaded_modules(manifest, import_paths, main_path)
            if type(modules_after) is not LoadedModules or modules_after != modules_before:
                raise ApprovalRefused("loaded module profile changed during installed measurement")
            return measured
    except Exception:
        raise ApprovalRefused("protected bootstrap installed files refused") from None


@dataclass(frozen=True)
class ProtectedBootstrapContextObservation:
    """Build runtime context from fixed declarations plus repeated measurements.

    The injectable readers are a private test seam. Production construction is
    provided by ``protected_bootstrap_context_observation`` and has no
    environment/path/bus selection. This binds declarations to the current
    package snapshot, selected-file manifest and a reviewed systemd profile;
    it does not establish package authenticity, complete import closure,
    audit health, rollback resistance or start authority.
    """

    declared: Callable[[], DeclaredBootstrapContext]
    observe_packages: Callable[[], object]
    measure_files: Callable[[BootstrapContext], SelectedInstalledFiles]
    observe_systemd_profile: Callable[[], SystemdBootstrapProfile]

    def __post_init__(self):
        if not all(callable(value) for value in (
            self.declared, self.observe_packages, self.measure_files,
            self.observe_systemd_profile,
        )):
            raise ValueError("fixed bootstrap context observation readers required")

    @staticmethod
    def _profile(value):
        if type(value) is not SystemdBootstrapProfile:
            raise ApprovalRefused("reviewed systemd bootstrap profile required")
        checked = observe_bootstrap_systemd_profile(
            version=value.version, unit_path=list(value.unit_path)
        )
        if checked != value:
            raise ApprovalRefused("systemd bootstrap profile changed")
        return checked

    def __call__(self) -> BootstrapContext:
        try:
            declaration = self.declared()
            if (type(declaration) is not DeclaredBootstrapContext
                    or type(declaration.context) is not BootstrapContext):
                raise ApprovalRefused("protected bootstrap declaration required")
            context = declaration.context

            packages_before = self.observe_packages()
            validate_package_snapshot(packages_before)
            if packages_before.digest != context.package_digest:
                raise ApprovalRefused("installed package context differs")
            files_before = self.measure_files(context)
            if (type(files_before) is not SelectedInstalledFiles
                    or files_before.manifest_digest != context.unit_closure_digest):
                raise ApprovalRefused("selected installed files differ")
            profile_before = self._profile(self.observe_systemd_profile())
            if (bootstrap_systemd_profile_digest(profile_before)
                    != declaration.systemd_profile_digest):
                raise ApprovalRefused("systemd profile differs from approved policy")

            packages_after = self.observe_packages()
            validate_package_snapshot(packages_after)
            files_after = self.measure_files(context)
            profile_after = self._profile(self.observe_systemd_profile())
            declaration_after = self.declared()
            if (packages_after != packages_before or files_after != files_before
                    or profile_after != profile_before
                    or bootstrap_systemd_profile_digest(profile_after)
                    != declaration_after.systemd_profile_digest
                    or declaration_after != declaration):
                raise ApprovalRefused("protected bootstrap context changed during observation")
            return context
        except Exception:
            raise ApprovalRefused("protected bootstrap context observation refused") from None


def _observe_systemd_profile() -> SystemdBootstrapProfile:
    """Read the current system manager profile over the fixed system bus."""
    from .systemd_bus import SystemdBusSession

    with SystemdBusSession.connect() as session:
        profile = session.bootstrap_profile()
    return ProtectedBootstrapContextObservation._profile(profile)


def protected_bootstrap_context_observation() -> ProtectedBootstrapContextObservation:
    """Return the fixed production context producer; never accepts path/bus input."""
    return ProtectedBootstrapContextObservation(
        declared=load_declared_bootstrap_context,
        observe_packages=observe_installed_packages,
        measure_files=measure_bootstrap_installed_files,
        observe_systemd_profile=_observe_systemd_profile,
    )


@dataclass(frozen=True)
class BootstrapObservation:
    """Trusted producer output, not a signed candidate or public request."""

    context: BootstrapContext
    operator: str
    now: str
    clock_trusted: bool
    earliest: str | None = None
    time_window: AdministratorTimeWindow | None = None

    def __post_init__(self):
        if (
            type(self.context) is not BootstrapContext
            or type(self.operator) is not str
            or not self.operator
        ):
            raise ApprovalRefused("independent bootstrap observation required")
        parse_bootstrap_time(self.now)
        if self.clock_trusted is not True:
            raise ApprovalRefused("independently trusted bootstrap time required")
        if self.earliest is not None and parse_bootstrap_time(self.earliest) > parse_bootstrap_time(self.now):
            raise ApprovalRefused("bootstrap time interval is reversed")
        if self.time_window is not None:
            window = self.time_window
            if (type(window) is not AdministratorTimeWindow
                    or (window.node_digest, window.policy_digest, window.boot_id)
                    != (self.context.node_digest, self.context.policy_digest, self.context.boot_id)
                    or (window.earliest_utc, window.latest_utc) != (self.earliest, self.now)):
                raise ApprovalRefused("bootstrap time window binding differs")

    @property
    def earliest_utc(self) -> str:
        return self.now if self.earliest is None else self.earliest

    def require_current_window(self, boottime_ns):
        if self.time_window is not None and (
            type(boottime_ns) is not int
            or not self.time_window.observed_boottime_ns <= boottime_ns < self.time_window.valid_until_boottime_ns
        ):
            raise ApprovalRefused("bootstrap time window stale or expired")


def _verify_observation(observation):
    """Verify the whole trusted interval, not merely its most convenient end.

    The upper bound is retained as `now` to expire conservatively. An exact-time
    observation retains the existing single verification behavior.
    """
    earlier = load_bootstrap_approval(expected=observation.context,
                                     operator=observation.operator, now=observation.earliest_utc)
    if observation.earliest_utc == observation.now:
        return earlier
    later = load_bootstrap_approval(expected=observation.context,
                                   operator=observation.operator, now=observation.now)
    if earlier != later:
        raise ApprovalRefused("bootstrap approval changed across time bounds")
    return later


@dataclass(frozen=True)
class AdministratorBootstrapObservation:
    """Bind fresh observations to installation-neutral administrator records.

    Pass this producer to ProtectedBootstrapInputs. `observe` must independently
    supply current time/context measurements; reading the declaration must never
    manufacture clock trust or installed-health evidence. Platform adapters may
    vary, not the policy/binding checks. No production entrypoint is enabled here.
    """

    observe: Callable[[], BootstrapObservation]

    def __post_init__(self):
        if not callable(self.observe):
            raise ValueError("fresh bootstrap observation producer required")

    def __call__(self) -> BootstrapObservation:
        try:
            deployment = load_bootstrap_deployment()
            node = load_declared_node()
            if type(node) is not DeclaredNode:
                raise ApprovalRefused("independent node declaration required")
            current = self.observe()
            if type(current) is not BootstrapObservation:
                raise ApprovalRefused("fresh bootstrap observation required")
            bind_bootstrap_deployment(deployment, context=current.context,
                                      node_id=node.node_id, operator=current.operator)
            if load_bootstrap_deployment() != deployment or load_declared_node() != node:
                raise ApprovalRefused("administrator context changed during observation")
            return current
        except Exception:
            raise ApprovalRefused("administrator bootstrap observation refused") from None


@dataclass(frozen=True)
class ProtectedAdministratorClockObservation:
    """Selected administrator time source plus independent current context.

    Context still requires real installed/policy measurements; it cannot come
    from approval.json. `clock_trusted` here means protected explicit local
    administrator confirmation, not OS synchronization or external attestation.
    No production records, context producer or services are created by this class.
    """

    observe_context: Callable[[], BootstrapContext]

    def __post_init__(self):
        if not callable(self.observe_context):
            raise ValueError("independent current context producer required")

    def __call__(self):
        def fresh():
            context = self.observe_context()
            if type(context) is not BootstrapContext:
                raise ApprovalRefused("independent bootstrap context required")
            declaration = load_bootstrap_deployment()
            window = load_administrator_time_window(expected=context)
            if self.observe_context() != context:
                raise ApprovalRefused("context changed during administrator time observation")
            return BootstrapObservation(context, declaration.operator, window.latest_utc, True,
                                        earliest=window.earliest_utc, time_window=window)

        return AdministratorBootstrapObservation(fresh)()


def _verified_observation(observe):
    """Fresh double observation and verification; persists nothing.

    Returns ``(approval, current_observation, elapsed_boottime_ns)``. Shared by
    the refresh adapter and the initial-admission adapter so both apply the
    identical fresh trust/context/time/boot checks.
    """
    before = observe()
    if (
        type(before) is not BootstrapObservation
        or read_boot_id() != before.context.boot_id
    ):
        raise ApprovalRefused("current bootstrap boot observation required")
    approval = _verify_observation(before)
    current = observe()
    if (
        type(current) is not BootstrapObservation
        or (current.context, current.operator)
        != (before.context, before.operator)
        or parse_bootstrap_time(current.now) < parse_bootstrap_time(before.now)
        or parse_bootstrap_time(current.earliest_utc) < parse_bootstrap_time(before.earliest_utc)
        or type(current.time_window) is not type(before.time_window)
    ):
        raise ApprovalRefused("bootstrap context changed during verification")
    # Reverify at the current trusted time, including fresh protected trust.
    fresh = _verify_observation(current)
    if fresh != approval or read_boot_id() != current.context.boot_id:
        raise ApprovalRefused(
            "bootstrap trust or boot changed during verification"
        )
    elapsed = read_boottime_ns()
    current.require_current_window(elapsed)
    return fresh, current, elapsed


def _require_stable_after_retention(current, elapsed):
    if read_boot_id() != current.context.boot_id:
        raise ApprovalRefused("bootstrap boot changed during retention")
    if current.time_window is not None:
        final_elapsed = read_boottime_ns()
        current.require_current_window(final_elapsed)
        if final_elapsed < elapsed:
            raise ApprovalRefused("bootstrap elapsed clock moved backward during retention")


@dataclass(frozen=True)
class ProtectedBootstrapInputs:
    """Supervisor refresh adapter. Missing retained state never initializes it.

    ``observe`` must independently measure protected node/policy/epoch/closure
    context and trusted UTC. It is supplied by reviewed runtime composition,
    never CLI/RPC/environment or the signed candidate itself.
    """

    observe: Callable[[], BootstrapObservation]

    def __call__(self) -> BootstrapDeadline:
        try:
            fresh, current, elapsed = _verified_observation(self.observe)
            retained = advance_deadline(
                approval=fresh,
                boot_id=current.context.boot_id,
                now=current.now,
                boottime_ns=elapsed,
                clock_trusted=current.clock_trusted,
            )
            _require_stable_after_retention(current, elapsed)
            return retained
        except Exception:
            raise ApprovalRefused(
                "protected bootstrap runtime inputs refused"
            ) from None


@dataclass(frozen=True)
class ProtectedBootstrapInitialAdmission:
    """The only initializer of the retained bootstrap deadline.

    Composed by ``protected_bootstrap_initial_admission`` from fixed protected
    observations; it is not a flag, selection, environment or CLI input. The
    supervisor calls ``verify`` (read-only) first and ``retain`` only after
    prestart. ``retain`` re-verifies, requires the same approval, and then
    uses the create-only store; it never advances or overwrites existing
    state, and refusal must never fall back to ``ProtectedBootstrapInputs``.
    """

    observe: Callable[[], BootstrapObservation]

    def verify(self) -> VerifiedBootstrapApproval:
        try:
            return _verified_observation(self.observe)[0]
        except Exception:
            raise ApprovalRefused(
                "protected bootstrap runtime inputs refused"
            ) from None

    def retain(self, expected: VerifiedBootstrapApproval) -> BootstrapDeadline:
        try:
            if type(expected) is not VerifiedBootstrapApproval:
                raise ApprovalRefused("verified bootstrap approval required")
            fresh, current, elapsed = _verified_observation(self.observe)
            if fresh != expected:
                raise ApprovalRefused("bootstrap approval changed before retention")
            state = begin_deadline(
                fresh,
                boot_id=current.context.boot_id,
                now=current.now,
                boottime_ns=elapsed,
                clock_trusted=current.clock_trusted,
            )
            retained = retain_initial_deadline(state)
            _require_stable_after_retention(current, elapsed)
            return retained
        except Exception:
            raise ApprovalRefused(
                "protected bootstrap runtime inputs refused"
            ) from None


def protected_bootstrap_inputs() -> ProtectedBootstrapInputs:
    """Compose fixed protected context and administrator-time observations.

    This is a concrete refresh adapter for the runtime supervisor; it does not
    grant a generation, widen the service set, or make the bootstrap path
    operational by itself. Missing enrollment, records, manifest, supported
    systemd profile, or trusted time continues to refuse. Platform additions
    require explicit reviewed readers/profiles rather than path or environment
    overrides.
    """
    context = protected_bootstrap_context_observation()
    observation = ProtectedAdministratorClockObservation(context)
    return ProtectedBootstrapInputs(observation)


def protected_bootstrap_initial_admission() -> ProtectedBootstrapInitialAdmission:
    """Compose the fixed first-admission initializer (no selection input).

    Uses the same protected context and administrator-time observations as
    ``protected_bootstrap_inputs``. Initialization still requires fresh
    verification, successful prestart and the create-only store.
    """
    context = protected_bootstrap_context_observation()
    observation = ProtectedAdministratorClockObservation(context)
    return ProtectedBootstrapInitialAdmission(observation)


@dataclass(frozen=True)
class ProtectedBootstrapGenerationAdmission:
    """Connect the protected reader to the supervisor's admission dependency.

    `admit` is reviewed trusted composition for additional semantic checks. The
    adapter itself binds the fixed generation, selected files, package snapshot
    and systemd profile to protected policy, including before/after checks. The
    supervisor calls this repeatedly; it must not reuse the initial stopped-
    writer audit-head expectation after records advance. Initial audit
    inspection belongs to supervisor prestart; continuing audit inspection
    belongs to the supervisor's separate extension verifier. It must raise on
    uncertainty and return exactly None after success. It must not start
    services or change the generation. The optional profile reader is set only
    by the fixed production factory; no public request selects it.
    The protected package digest is independently compared with two fresh
    Debian dpkg-query snapshots around semantic admission. This is package
    database identity only: it is not package authenticity, selected file
    measurement, unit closure or health. The injected checker must still
    independently check those remaining policy semantics. Byte verification
    alone never invokes this adapter as a grant.
    """

    admit: Callable[[BootstrapContext, VerifiedBootstrapGeneration], None]
    profile_reader: Callable[[], SystemdBootstrapProfile] | None = None

    def __post_init__(self):
        if (not callable(self.admit)
                or (self.profile_reader is not None and not callable(self.profile_reader))):
            raise ValueError("independent bootstrap semantic admission required")

    def __call__(self, context: BootstrapContext) -> VerifiedBootstrapGeneration:
        try:
            if type(context) is not BootstrapContext:
                raise ApprovalRefused("independent bootstrap context required")
            policy_before = None
            profile_before = None
            if self.profile_reader is not None:
                policy_before = load_bootstrap_prestart_policy(expected=context)
                if type(policy_before) is not BootstrapPrestartPolicy:
                    raise ApprovalRefused("protected bootstrap policy required")
                profile_before = ProtectedBootstrapContextObservation._profile(
                    self.profile_reader()
                )
                if (bootstrap_systemd_profile_digest(profile_before)
                        != policy_before.systemd_profile_digest):
                    raise ApprovalRefused("live systemd profile differs from approved policy")
            packages_before = observe_installed_packages()
            validate_package_snapshot(packages_before)
            if packages_before.digest != context.package_digest:
                raise ApprovalRefused("installed package context differs")
            files_before = measure_bootstrap_installed_files(context)
            before = load_bootstrap_generation(expected=context)
            if type(before) is not VerifiedBootstrapGeneration or (
                before.number, before.digest
            ) != (context.generation, context.generation_digest):
                raise ApprovalRefused("bootstrap generation observation differs")
            if self.admit(context, before) is not None:
                raise ApprovalRefused("bootstrap semantic admission result refused")
            packages_after = observe_installed_packages()
            validate_package_snapshot(packages_after)
            if packages_after != packages_before:
                raise ApprovalRefused("installed package observation changed during admission")
            files_after = measure_bootstrap_installed_files(context)
            if files_after != files_before:
                raise ApprovalRefused("selected installed files changed during admission")
            after = load_bootstrap_generation(expected=context)
            if type(after) is not VerifiedBootstrapGeneration or after != before:
                raise ApprovalRefused("bootstrap generation changed during admission")
            if self.profile_reader is not None:
                profile_after = ProtectedBootstrapContextObservation._profile(
                    self.profile_reader()
                )
                policy_after = load_bootstrap_prestart_policy(expected=context)
                if (type(policy_after) is not BootstrapPrestartPolicy
                        or policy_after != policy_before
                        or profile_after != profile_before
                        or bootstrap_systemd_profile_digest(profile_after)
                        != policy_after.systemd_profile_digest):
                    raise ApprovalRefused(
                        "bootstrap profile or policy changed during admission"
                    )
            return after
        except Exception:
            raise ApprovalRefused("protected bootstrap generation admission refused") from None


def _admit_protected_bootstrap_generation(
    context: BootstrapContext, generation: VerifiedBootstrapGeneration
) -> None:
    """Semantically admit the fixed uncommissioned bootstrap tree only.

    This checks the exact policy pin, supported live systemd profile and
    independently re-read fixed generation. Package and selected-file
    measurements surround it in ProtectedBootstrapGenerationAdmission;
    supervisor prestart/readiness/audit and lifetime gates remain separate.
    It is not a grant, manager operation, host authentication or hostile-root
    defense.
    """
    try:
        if (type(context) is not BootstrapContext
                or type(generation) is not VerifiedBootstrapGeneration):
            raise ApprovalRefused("independent bootstrap generation required")
        policy = load_bootstrap_prestart_policy(expected=context)
        if type(policy) is not BootstrapPrestartPolicy:
            raise ApprovalRefused("protected bootstrap policy required")
        # Capacity is a continuing health prerequisite, not only a one-time
        # prestart check. Reuse the capacity-only reader here: replaying the
        # stopped-writer audit check would reject legitimate audit growth.
        check_bootstrap_capacity(expected=context)
        if load_bootstrap_prestart_policy(expected=context) != policy:
            raise ApprovalRefused("bootstrap policy changed during capacity check")
        current = load_bootstrap_generation(expected=context)
        if current != generation:
            raise ApprovalRefused("bootstrap generation changed during admission")
        if load_bootstrap_prestart_policy(expected=context) != policy:
            raise ApprovalRefused("bootstrap policy changed during admission")
    except Exception:
        raise ApprovalRefused("protected bootstrap semantic admission refused") from None


def protected_bootstrap_generation_admission() -> ProtectedBootstrapGenerationAdmission:
    """Compose the fixed production semantic checker; no permissive callback."""
    return ProtectedBootstrapGenerationAdmission(
        admit=_admit_protected_bootstrap_generation,
        profile_reader=_observe_systemd_profile,
    )
