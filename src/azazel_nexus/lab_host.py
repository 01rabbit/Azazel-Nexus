"""A persistent host contamination marker, never an authorization input.

Deliberately absolute: AZAZEL_ROOT must not hide a marked host. A dangling
symlink or an unreadable marker also refuses; removing it grants nothing.
"""
from pathlib import Path

LAB_HOST_MARKER = Path("/etc/azazel-lab/LAB-HOST")


def is_lab_host() -> bool:
    try:
        LAB_HOST_MARKER.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def refuse_lab_host(error_type=ValueError) -> None:
    if is_lab_host():
        raise error_type("LAB_HOST_MARKER")
