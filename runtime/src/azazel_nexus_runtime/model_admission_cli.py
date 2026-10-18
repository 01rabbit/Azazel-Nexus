"""Read-only operator rehearsal. Signs nothing, authorizes nothing."""
import argparse
import os
import sys
from datetime import UTC
from uuid import uuid4

from azazel_nexus import model_admission as admission
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    approval_message,
)

from .model_admission_evidence import read_admissions, request_context


def run_request(*, stdin, stdout):
    raw = stdin.buffer.readline(65537) if hasattr(stdin, "buffer") else stdin.readline(65537).encode()
    if not raw.endswith(b"\n") or len(raw) > 65536:
        raise ApprovalRefused("MALFORMED")
    doc = admission.decode(raw[:-1])
    if set(doc) != {"operator", "issued_at", "expires_at", "memory_need_mib", "envelope_floor_mib"}:
        raise ApprovalRefused("MALFORMED")
    policy, values = request_context(operator=doc["operator"])
    context, descriptors, entry, _provider, _host, _tested, resources, record = values
    try:
        if (type(doc["memory_need_mib"]) is not int or type(doc["envelope_floor_mib"]) is not int
                or context.bindings["resources"] != {"memory_need_mib": doc["memory_need_mib"],
                                                     "envelope_floor_mib": doc["envelope_floor_mib"]}):
            raise ApprovalRefused("RESOURCE_FIT")
        if (admission.utc(doc["expires_at"]) - admission.utc(doc["issued_at"])).total_seconds() > policy.max_seconds:
            raise ApprovalRefused("VALIDITY_EXCEEDS_POLICY")
        payload = admission.admission_payload(context=context, operator=doc["operator"],
                                               approval_id=str(uuid4()), issued_at=doc["issued_at"],
                                               expires_at=doc["expires_at"])
        print(payload.decode(), file=stdout)
        print("payload SHA-256: " + admission.digest(payload), file=stdout)
        print("message SHA-256: " + admission.digest(approval_message(
            ApprovalPurpose.LOCAL_MODEL_ADMISSION, payload)), file=stdout)
        print("domain/purpose: azazel-nexus/operator-approval/v1\\0local-model-admission\\0", file=stdout)
        print("確認 / Review independently against HIL report:", file=stdout)
        print("モデル / Model: " + entry.model_id + " " + entry.digest, file=stdout)
        print("ライセンス / License: " + context.bindings["model"]["license"], file=stdout)
        print("実行 / Runtime: " + context.bindings["runtime"]["binary_digest"], file=stdout)
        print("引数 / argv: " + admission.canonical(list(record.argv)).decode(), file=stdout)
        print("Core reserve MiB: " + str(resources.reserve.reserve_mib), file=stdout)
        print("Peak RSS MiB: " + str(context.bindings["runtime_evidence"]["peak_rss_mib"]), file=stdout)
        print("virtualization_not_observed: true (仮想化は未観測 / negative filter only)", file=stdout)
        print("期間 / Validity: " + doc["issued_at"] + " .. " + doc["expires_at"], file=stdout)
        print("ノード / Node: " + admission.canonical(dict(context.bindings["node"])).decode(), file=stdout)
        print("signs nothing, authorizes nothing / 署名・認可は行いません", file=stdout)
        print("feature disabled / 機能無効" if admission.LOCAL_MODEL_ADMISSION_ENABLED is not True
              else "feature enabled / 機能有効", file=stdout)
    finally:
        descriptors.close()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="az-nexus-model-admission", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    request = commands.add_parser("request")
    request.add_argument("--role", choices=("embedding",), required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--role", choices=("embedding",))
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("refused: ROOT_REQUIRED", file=sys.stderr)
        return 2
    try:
        if args.command == "request":
            return run_request(stdin=sys.stdin, stdout=sys.stdout)
        from datetime import datetime

        reading = read_admissions(now=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
        try:
            event = reading.as_event()
            print("embedding -> " + event["outcome"] +
                  (":" + event["refusal"] if event["refusal"] else ""))
        finally:
            reading.close()
        return 0
    except Exception as error:  # noqa: BLE001 - CLI reader failures never authorize
        symbol = str(error) if type(error) is ApprovalRefused and str(error).isupper() else "EVIDENCE_REFUSED"
        print("embedding -> refused:" + symbol, file=sys.stderr)
        return 2
