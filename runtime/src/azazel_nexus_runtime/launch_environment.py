"""Fixed launch constraints, not environment-derived approval or discovery."""


# Names, not glob patterns: systemd UnsetEnvironment applies exact removals at
# its final environment-composition step. This is the supported Linux loader /
# Python launcher set, not a claim to filter every future environment feature.
BOOTSTRAP_UNSET_ENVIRONMENT = tuple(sorted({
    "GLIBC_TUNABLES", "GCONV_PATH", "LOCPATH", "NLSPATH", "MALLOC_TRACE",
    "LD_ASSUME_KERNEL", "LD_AUDIT", "LD_BIND_NOT", "LD_BIND_NOW", "LD_DEBUG",
    "LD_DEBUG_OUTPUT", "LD_DYNAMIC_WEAK", "LD_HWCAP_MASK", "LD_LIBRARY_PATH",
    "LD_ORIGIN_PATH", "LD_POINTER_GUARD", "LD_PRELOAD", "LD_PROFILE",
    "LD_PROFILE_OUTPUT", "LD_SHOW_AUXV", "LD_TRACE_LOADED_OBJECTS",
    "LD_TRACE_PRELINKING", "LD_USE_LOAD_BIAS", "LD_VERBOSE", "LD_WARN",
    "LD_PREFER_MAP_32BIT_EXEC", "PYTHONEXECUTABLE", "PYTHONHOME", "PYTHONPATH", "TZDIR",
    "__PYVENV_LAUNCHER__",
}))


def staging_environment() -> dict[str, str]:
    """Fresh minimal subprocess environment; never inherit launcher variables."""
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
