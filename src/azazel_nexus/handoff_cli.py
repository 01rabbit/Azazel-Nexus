"""`azazel-nexus handoff export`: write one incident's expert handoff package.

Who may run it: root, or a member of `azazel-operator`. Root reads the
ledgers as well as the operator snapshots; an operator gets the snapshots
only and the package says which sections it could not read. No permission,
socket or verb is added for this command (`azazel_nexus.handoff`).

The output is a new directory under `--output-dir`, which must already exist,
be reached without a symbolic link, not be writable by group or others, and
not be inside the product's own state. Nothing is uploaded.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .handoff import (
    HandoffRefused, build_package, encode_files, find_incident, package_name,
    principal_class, write_package,
)

#: What the terminal may say about a refusal: the fixed code and this text.
_REFUSALS_JA = {
    "principal_refused": "root か azazel-operator グループの利用者だけが実行できます。",
    "incident_id_refused": "インシデント ID は inc- と 16 桁の 16 進数、または latest です。",
    "incident_not_found": "そのインシデントの記録が見つかりません（root で実行すると台帳も読みます）。",
    "output_path_not_absolute": "--output-dir は絶対パスで指定してください。",
    "output_path_refused": "出力先の経路にシンボリックリンク等があります。実ディレクトリを指定してください。",
    "output_dir_unavailable": "出力先ディレクトリを開けません（存在しない・権限がない）。",
    "output_dir_shared_writable": "出力先がグループ・他者から書込み可能です。専用のディレクトリを指定してください。",
    "output_in_product_state": "出力先が製品の状態ディレクトリの中です。別の場所を指定してください。",
    "output_exists": "同じ名前のパッケージが既にあります。上書きはしません。",
    "insufficient_space": "空き容量が足りません。何も残していません。",
    "write_failed": "書込みに失敗しました。何も残していません。",
}


def add_parser(sub):
    parser = sub.add_parser(
        "handoff",
        help="write an offline expert handoff package for one incident (no upload)")
    commands = parser.add_subparsers(dest="handoff_command", required=True)
    export = commands.add_parser(
        "export", help="JSON + Japanese Markdown + digest manifest into a new directory")
    export.add_argument("--incident", required=True,
                        help="incident id (inc-<16 hex>) or `latest`")
    export.add_argument("--output-dir", required=True, type=Path,
                        help="existing private directory to create the package in")


def run(args, *, now: str, out, principal=None, root=None) -> int:
    principal = principal_class() if principal is None else principal
    try:
        if principal not in ("root", "operator"):
            raise HandoffRefused("principal_refused")
        incident = find_incident(args.incident, root=root)
        if incident is None:
            raise HandoffRefused("incident_id_refused" if args.incident != "latest"
                                 else "incident_not_found")
        instant = datetime.fromisoformat(now.replace("Z", "+00:00")).timestamp()
        package = build_package(incident, now=instant, principal=principal, root=root)
        files = encode_files(package)
        path = write_package(args.output_dir, package_name(package), files)
    except HandoffRefused as refused:
        code = refused.code
        base = code.split(":", 1)[0]
        print(f"handoff: refused ({code}); nothing was written. "
              + _REFUSALS_JA.get(base, ""), file=out)
        return 2 if base == "principal_refused" else 1
    except Exception:  # noqa: BLE001 - never print a value from below
        print("handoff: refused (internal_error); nothing was written.", file=out)
        return 1
    import hashlib

    manifest = hashlib.sha256(files["manifest.json"]).hexdigest()
    print(f"handoff: written {path}", file=out)
    print(f"manifest sha256: {manifest}", file=out)
    print(f"principal: {principal}; suppressed items: "
          f"{package['confidentiality']['suppressed_total']}; uploaded: no", file=out)
    unavailable = [s["source"] for s in package["sources"] if s["status"] != "read"]
    if unavailable:
        print("not read: " + ", ".join(unavailable), file=out)
    return 0
