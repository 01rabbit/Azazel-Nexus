"""Shared NON-PRODUCTION E2E service composition; fixture reserve is not HG-05."""
import os
import stat
import subprocess
from pathlib import Path

from azazel_nexus_runtime.mio_serve import LocalServer
from azazel_nexus_runtime.mio_supervisor import ServingProcess

from azazel_nexus.runtime_lifecycle import LifecycleState, RestartBudget


class NoRemote:
    """Fail loudly if a local-only scenario dispatches remote content."""

    def observe(self):
        return "remote_unavailable"

    def handle(self, *args, **kwargs):
        raise AssertionError("local-only E2E attempted remote inference")


def compose(root: Path, record, observed, *, model_id="e2e-model", runtime_id="e2e-llama"):
    """Compose the real A/B APIs using only trusted constructor injections."""
    from azazel_nexus_runtime.mio_entryd import MioEntryService
    from azazel_nexus_runtime.mio_locald import LocalRuntimeService
    from azazel_nexus_runtime.mio_router import MioRouter

    from azazel_nexus.core_reserve import CoreReserve
    from azazel_nexus.mio_profile import MioProfile
    from azazel_nexus.resource_profile import ResourceProfile
    from azazel_nexus.route_evidence import Prediction
    from azazel_nexus.routing import Route

    reserve = CoreReserve(
        profile=ResourceProfile.STANDARD, reserve_mib=512,
        host_digest="sha256:" + "0" * 64,
        harness_version="e2e-fixture-not-HG-05", sample_count=64, duration_seconds=3600,
    )

    def runtime(identity):
        assert identity == runtime_id
        return record

    local = LocalRuntimeService(
        staging=root / "var/lib/azazel/mio", reserve=reserve,
        admitted=lambda identity: identity == model_id,
        runtime=runtime, server=observed, model_id=model_id, runtime_id=runtime_id,
    )
    router = MioRouter(local=local, remote=NoRemote())
    entry = MioEntryService(
        router=router, profile_reader=lambda: MioProfile.LOCAL_ONLY,
        local_admitted=lambda: True,
        predictions_reader=lambda: {Route.LOCAL: Prediction(
            Route.LOCAL.value, True, 100, 100, 100, False, "e2e fixture prediction",
        )},
    )
    return entry, router


class LabProcess(ServingProcess):
    def start(self):
        if self.process is not None:
            raise RuntimeError("stop previous lab process")
        binary_fd, model_fd = self.descriptors
        executable = f"/proc/self/fd/{binary_fd}"
        argv = [executable, *self.record.argv[1:]]
        argv[argv.index("-m") + 1] = f"/proc/self/fd/{model_fd}"
        self.process = subprocess.Popen(
            argv, executable=executable, pass_fds=(binary_fd, model_fd),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/nonexistent", "LC_ALL": "C"}, cwd=self.root,
            start_new_session=True, close_fds=True,
        )


class LabServer(LocalServer):
    def __init__(self, record, *, root, socket_path, descriptors):
        self.record, self.socket_path = record, socket_path
        self.descriptors = descriptors
        self._identities = [os.fstat(fd) for fd in descriptors]
        self.start_deadline_s = 120
        self.budget, self.ledger, self.on_budget_spent = RestartBudget(generation=0), None, None
        self._child = LabProcess(record, root=root, descriptors=descriptors)
        self._started, self.state = False, LifecycleState.ABSENT

    def _check_admission(self):
        # Already-held immutable lab copies and digest-verified production binary.
        # No production admission claim, file, flag or reserve is created.
        for descriptor, expected in zip(self.descriptors, self._identities, strict=True):
            observed = os.fstat(descriptor)
            if (not stat.S_ISREG(observed.st_mode)
                    or (observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)
                    != (expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns)):
                raise ValueError("lab descriptor closed")

    def memory(self):
        from .bench import process_memory

        process = self._child.process
        return process_memory(process.pid) if process is not None else None


