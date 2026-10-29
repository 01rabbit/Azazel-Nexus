#!/usr/bin/env python3
"""Resolve one declared install-profile field for the host installer.

This helper is intentionally read-only. It evaluates the repository's pure
install plan, then emits one allowlisted scalar/line-list so POSIX shell does
not need to parse profile data with ``eval`` or source generated shell code.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "runtime" / "src"))

from azazel_nexus_runtime.install_platform import (  # noqa: E402
    build_install_plan,
    evaluate_install_architecture,
    parse_os_release,
    parse_preset_declarations,
    select_install_profile,
)


_FIELDS = (
    "profile_id",
    "unit_directory",
    "preset_directory",
    "libexec_directory",
    "service_manager",
    "required_tools",
    "mask_units",
    "enable_units",
    # The observed CPU, evaluated against the reviewed platform profiles
    # (ADR-0003 R6). Refused with a reason code when no profile has it.
    # One line, "<architecture> <purpose>", so the host is observed once.
    "platform",
)


def resolve(
    *,
    field: str,
    os_release_path: Path = Path("/etc/os-release"),
    with_accounts: bool = True,
    with_service_manager: bool = True,
    observe_platform=None,
) -> str:
    if field not in _FIELDS:
        raise ValueError("unknown install profile field")
    values = parse_os_release(os_release_path.read_text(encoding="utf-8"))
    profile = select_install_profile(values)
    if field == "platform":
        if observe_platform is None:
            from azazel_nexus_runtime.platform_observation import observe

            def observe_platform():
                return observe(os_release_path=os_release_path)

        selected = evaluate_install_architecture(profile, observe_platform())
        return f"{selected.architecture} {selected.purpose}"
    preset = (ROOT / "packaging" / "azazel-nexus.preset").read_text(encoding="utf-8")
    plan = build_install_plan(
        profile,
        preset_declarations=parse_preset_declarations(preset),
        with_accounts=with_accounts,
        with_service_manager=with_service_manager,
    )
    if field in {
        "profile_id", "unit_directory", "preset_directory", "libexec_directory",
        "service_manager",
    }:
        return str(getattr(profile, field))
    if field == "required_tools":
        return "\n".join(plan.required_tools)
    units = getattr(plan.service_manager, field)
    return "\n".join(units)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--field", choices=_FIELDS, required=True)
    parser.add_argument("--without-accounts", action="store_true")
    parser.add_argument("--without-service-manager", action="store_true")
    args = parser.parse_args(argv)
    try:
        value = resolve(
            field=args.field,
            with_accounts=not args.without_accounts,
            with_service_manager=not args.without_service_manager,
        )
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(f"installation platform refused: {error}")
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
