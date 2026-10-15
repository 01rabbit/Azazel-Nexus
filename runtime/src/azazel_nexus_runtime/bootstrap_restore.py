"""Post-unlink reload, stop and empty-cgroup proof before journal completion.

Trusted composition owns the dedicated bus, admitted cgroup descriptor and
restored-file backend. This does not unlink, remove grants, or open production
paths. Synchronous filesystem IO still requires external lifetime supervision.
"""

from azazel_nexus.bootstrap_overlay_journal import OverlayStopEvidence

from .bootstrap_cgroup import validate_cgroup_root
from .bootstrap_job_drain import BootstrapJobDrain
from .bootstrap_masked import BootstrapMaskedPairInspector, _observe_profile
from .bootstrap_stop import BootstrapStopJobs, _validate_expected_owner
from .bootstrap_stopped import BootstrapStoppedPairInspector
from .units import UNIT_NAMES, UnitKey, UnitOperationFailed


class BootstrapRestoreSequence:
    """Single-use restore transaction on one pinned systemd owner."""

    def __init__(self, *, bus, message_factory, message_type, timeout_seconds,
                 files, expected_owner, cgroup_root_fd, owner_uid, check_mount=None):
        self._owner = _validate_expected_owner(expected_owner)
        if self._owner is None:
            raise ValueError("enclosing restoration owner required")
        if not all(callable(getattr(files, name, None)) for name in ("check", "finalize")):
            raise ValueError("trusted restoration file backend required")
        validate_cgroup_root(cgroup_root_fd, owner_uid)
        if check_mount is not None and not callable(check_mount):
            raise ValueError("trusted mount revalidator required")
        self._check_mount = check_mount
        self._arguments = dict(bus=bus, message_factory=message_factory,
                               message_type=message_type, timeout_seconds=timeout_seconds)
        self._reader = BootstrapStopJobs(**self._arguments, expected_owner=self._owner)
        self._files = files
        self._root = cgroup_root_fd
        self._uid = owner_uid
        self._used = False

    async def restore(self):
        if self._used:
            raise UnitOperationFailed("bootstrap restore requires a fresh transaction")
        self._used = True
        reader, owner = self._reader, self._owner

        def check_mount():
            if self._check_mount is not None and self._check_mount() is not None:
                raise UnitOperationFailed("bootstrap mount revalidation unconfirmed")

        async def operation():
            check_mount()
            if await reader._owner() != owner:
                raise UnitOperationFailed("bootstrap restoration owner changed")
            reader._manager_owner = owner
            profile = await _observe_profile(reader)
            fragments = self._files.check()
            if await reader._owner() != owner:
                raise UnitOperationFailed("bootstrap restoration owner changed")
            if await reader._call("Reload", "", [], "") != []:
                raise UnitOperationFailed("bootstrap restoration reload unconfirmed")

            async def check_closed():
                check_mount()
                if (self._files.check() != fragments or await reader._owner() != owner
                        or await _observe_profile(reader) != profile):
                    raise UnitOperationFailed("bootstrap restored fence changed")
                observed = await BootstrapMaskedPairInspector(
                    **self._arguments, expected_owner=owner,
                ).inspect()
                if (observed.fragments != fragments or self._files.check() != fragments
                        or await _observe_profile(reader) != profile
                        or await reader._owner() != owner):
                    raise UnitOperationFailed("bootstrap restored masks unconfirmed")
                check_mount()

            await check_closed()
            await BootstrapJobDrain(
                **self._arguments, expected_owner=owner, check_closed=check_closed,
            ).drain()
            for unit in (UnitKey.COMMISSIOND, UnitKey.AUDITD):
                await check_closed()
                await BootstrapStopJobs(
                    **self._arguments, expected_owner=owner,
                ).stop_and_wait(unit)
                await check_closed()

            async def stopped():
                return await BootstrapStoppedPairInspector(
                    **self._arguments, expected_owner=owner, check_closed=check_closed,
                    cgroup_root_fd=self._root, owner_uid=self._uid,
                ).inspect()

            result = await stopped()
            await check_closed()
            check_mount()
            pair = tuple(UNIT_NAMES[unit] for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND))
            evidence = OverlayStopEvidence(
                start_fence_closed=True, stopped_pair=pair, inactive_pair=pair,
                withdrawn_pair=pair, persistent_masks_restored=True,
                loaded_masks_confirmed=True,
            )
            if self._files.finalize(evidence) is not None:
                raise UnitOperationFailed("bootstrap restoration journal unconfirmed")
            # A visible closed journal is never a substitute for fresh state.
            if await stopped() != result:
                raise UnitOperationFailed("bootstrap restoration cgroup identity changed")
            await check_closed()
            check_mount()
            return result

        try:
            return await reader._bounded(operation())
        except Exception:
            raise UnitOperationFailed("bootstrap restoration unconfirmed") from None
