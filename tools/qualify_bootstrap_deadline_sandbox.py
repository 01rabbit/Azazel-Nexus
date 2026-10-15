"""Operator-only native timer qualification; never a runtime activation gate.

Default is plan-only. --execute needs an interactive operator's root session.
Only uniquely named transient fixture services are operated. No product unit,
provider, network, persistence, media or firmware operation is performed.
"""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid


NATIVE_SHA256 = "1444d49bcc1f73f9818f93729de79ab1481e9ef3d3cd5571446889489910c3f9"
NATIVE_NAME = "_bootstrap_deadline.cpython-313-aarch64-linux-gnu.so"
# Sandbox subset copied from the controller, not its lifecycle/READY protocol.
PROPERTIES = (
    "Type=exec", "User=root", "Restart=no", "RemainAfterExit=yes",
    "RuntimeMaxSec=10s", "TimeoutStartSec=5s", "TimeoutStopSec=5s",
    "KillMode=control-group", "SendSIGKILL=yes", "NoNewPrivileges=yes",
    "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
    "PrivateDevices=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
    "ProtectControlGroups=yes", "RestrictNamespaces=yes", "RestrictSUIDSGID=yes",
    "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
    "SystemCallArchitectures=native", "SystemCallFilter=@system-service",
    "CapabilityBoundingSet=CAP_DAC_READ_SEARCH", "AmbientCapabilities=",
    "SupplementaryGroups=azazel-operator", "IPAddressDeny=any",
    "RestrictAddressFamilies=AF_UNIX AF_NETLINK", "UMask=0027",
    "SetLoginEnvironment=no", "StandardOutput=journal", "StandardError=journal",
    "SyslogIdentifier=azazel-nexus-qualification-probe",
    "UnsetEnvironment=GCONV_PATH GLIBC_TUNABLES LD_ASSUME_KERNEL LD_AUDIT "
    "LD_BIND_NOT LD_BIND_NOW LD_DEBUG LD_DEBUG_OUTPUT LD_DYNAMIC_WEAK LD_HWCAP_MASK "
    "LD_LIBRARY_PATH LD_ORIGIN_PATH LD_POINTER_GUARD LD_PREFER_MAP_32BIT_EXEC "
    "LD_PRELOAD LD_PROFILE LD_PROFILE_OUTPUT LD_SHOW_AUXV LD_TRACE_LOADED_OBJECTS "
    "LD_TRACE_PRELINKING LD_USE_LOAD_BIAS LD_VERBOSE LD_WARN LOCPATH MALLOC_TRACE "
    "NLSPATH PYTHONEXECUTABLE PYTHONHOME PYTHONPATH TZDIR __PYVENV_LAUNCHER__",
)
PROBE = '''import importlib.util,sys,time
from pathlib import Path
assert sys.version_info[:2] == (3,13)
p=Path(__file__).with_name("_bootstrap_deadline.cpython-313-aarch64-linux-gnu.so")
s=importlib.util.spec_from_file_location("_bootstrap_deadline",p)
n=importlib.util.module_from_spec(s); s.loader.exec_module(n)
h=n.arm(time.clock_gettime_ns(time.CLOCK_BOOTTIME)+2_000_000_000)
n.check(h)
print("ARMED",flush=True)
if sys.argv[1] == "release":
    n.release(h)
    time.sleep(2.5)
    print("RELEASE_SURVIVED",flush=True)
else:
    time.sleep(6)
    raise AssertionError("native deadline failed to kill fixture")
'''


def checked_native(path):
    """Read only an explicit ordinary file; never a device or a symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != 71048:
            raise ValueError("reviewed native ordinary file required")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(71049)
        after = os.fstat(fd)
        def stamp(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if stamp(before) != stamp(after) or sha256(data).hexdigest() != NATIVE_SHA256:
            raise ValueError("native artifact changed or digest differs")
        return data
    finally:
        os.close(fd)


def command(unit, directory, mode):
    if mode not in ("expiry", "release"):
        raise ValueError("fixed fixture mode required")
    if type(unit) is not str or re.fullmatch(
        r"azazel-nexus-qualification-[0-9a-f]{32}\.service", unit,
    ) is None:
        raise ValueError("unique qualification fixture unit required")
    return ["/usr/bin/systemd-run", "--quiet", "--unit=" + unit,
            *["--property=" + value for value in PROPERTIES],
            "--property=ReadWritePaths=" + str(directory),
            "/usr/bin/python3.13", "-IS", str(directory / "probe.py"), mode]


def passed(mode, properties, output):
    markers = [line for line in output.splitlines() if line]
    if mode == "expiry":
        return (properties.get("Result") == "signal"
                and properties.get("ExecMainCode") == "2"
                and properties.get("ExecMainStatus") == "9" and markers == ["ARMED"])
    if mode == "release":
        return (properties.get("Result") == "success"
                and properties.get("ExecMainCode") == "1"
                and properties.get("ExecMainStatus") == "0"
                and markers == ["ARMED", "RELEASE_SURVIVED"])
    return False


def _stage_parent():
    # /run is noexec on the review VM: do not remount it or weaken the sandbox.
    # Native extension mappings need an executable filesystem, like production
    # installed code. Use a unique root-only fixture beneath this fixed parent.
    for path in ("/var", "/var/lib"):
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise ValueError("protected qualification staging parent required")
    if os.statvfs("/var/lib").f_flag & os.ST_NOEXEC:
        raise ValueError("qualification staging filesystem is noexec")
    return "/var/lib"


def _stop_fixture(unit):
    subprocess.run(["/usr/bin/systemctl", "stop", unit], check=True, timeout=10)
    # stop need not clear a failed unit's failure state. Reset only this unique
    # fixture, then observe anew; missing units may already be garbage-collected.
    reset = subprocess.run(["/usr/bin/systemctl", "reset-failed", unit],
                           capture_output=True, timeout=5)
    observation = subprocess.run(
        ["/usr/bin/systemctl", "show", unit,
         "--property=LoadState,ActiveState,SubState,MainPID,ControlPID"],
        check=True, capture_output=True, text=True, timeout=5,
    ).stdout
    state = dict(line.split("=", 1) for line in observation.splitlines() if "=" in line)
    if (state.get("LoadState") not in ("loaded", "not-found")
            or state.get("ActiveState") != "inactive" or state.get("SubState") != "dead"
            or state.get("MainPID") != "0" or state.get("ControlPID") != "0"
            or (reset.returncode != 0 and state.get("LoadState") != "not-found")):
        raise RuntimeError("fixture stop unconfirmed: " + unit)


def run(native):
    if os.geteuid() != 0:
        raise PermissionError("operator root authentication required; no sudo attempted")
    data = checked_native(native)
    directory = Path(tempfile.mkdtemp(
        prefix="azazel-nexus-qualification-", dir=_stage_parent(),
    ))
    results = []
    attempted, stopped = [], []
    error = None
    removed = False
    try:
        (directory / NATIVE_NAME).write_bytes(data)
        (directory / "probe.py").write_text(PROBE)
        for mode in ("expiry", "release"):
            unit = "azazel-nexus-qualification-" + uuid.uuid4().hex + ".service"
            attempted.append(unit)
            try:
                subprocess.run(command(unit, directory, mode), check=True, timeout=10)
                deadline = time.monotonic() + 15
                properties = {}
                while time.monotonic() < deadline:
                    observed = subprocess.run(
                        ["/usr/bin/systemctl", "show", unit,
                         "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus"],
                        check=True, capture_output=True, text=True, timeout=5,
                    ).stdout
                    properties = dict(line.split("=", 1) for line in observed.splitlines()
                                      if "=" in line)
                    if properties.get("SubState") in ("failed", "exited", "dead"):
                        break
                    time.sleep(0.1)
                journal_deadline = time.monotonic() + 3
                while True:
                    output = subprocess.run(
                        ["/usr/bin/journalctl", "--unit=" + unit, "--no-pager", "-o", "cat",
                         "--identifier=azazel-nexus-qualification-probe"],
                        check=True, capture_output=True, text=True, timeout=5,
                    ).stdout
                    if passed(mode, properties, output) or time.monotonic() >= journal_deadline:
                        break
                    time.sleep(0.1)
                results.append({"mode": mode, "properties": properties,
                                "markers": output.splitlines(),
                                "passed": passed(mode, properties, output)})
            finally:
                _stop_fixture(unit)
                stopped.append(unit)
    except Exception as failure:
        error = type(failure).__name__ + ": " + str(failure)
    finally:
        if attempted == stopped:
            try:
                shutil.rmtree(directory)
                removed = True
            except Exception as failure:
                cleanup_error = type(failure).__name__ + ": " + str(failure)
                error = cleanup_error if error is None else error + "; " + cleanup_error
    return {"scope": "native timer sandbox only", "results": results,
            "staging_parent": str(directory.parent), "native_sha256": NATIVE_SHA256,
            "probe_sha256": sha256(PROBE.encode()).hexdigest(), "properties": PROPERTIES,
            "error": error, "cleanup_confirmed": attempted == stopped and removed,
            "unconfirmed_units": [unit for unit in attempted if unit not in stopped],
            "retained_directory": None if removed else str(directory)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({"execute": False, "native_sha256": NATIVE_SHA256,
                          "staging_parent": "/var/lib",
                          "properties": PROPERTIES,
                          "scope": "native timer sandbox only; not READY/lifecycle qualification"}))
        return 0
    report = run(args.native)
    print(json.dumps(report))
    return 0 if (report["error"] is None and report["cleanup_confirmed"]
                 and len(report["results"]) == 2
                 and all(item["passed"] for item in report["results"])) else 1


if __name__ == "__main__":
    raise SystemExit(main())
