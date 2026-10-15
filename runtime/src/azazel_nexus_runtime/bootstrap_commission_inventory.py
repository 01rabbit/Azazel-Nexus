"""Validate the bounded shape of a commission inventory socket reply.

This validates response syntax only. It does not establish that the inventory
is true, recompute its producer digest, or grant admission based on its rows.
"""

import re

from azazel_nexus.commissioning import OPERATOR_VISIBLE_FIELDS
from azazel_nexus.operator_trust import ApprovalRefused

from .commissiond import MAX_INTERFACES

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RESPONSE_FIELDS = {"ok", "result"}
_RESULT_FIELDS = {"snapshot", "interfaces"}
_ROW_FIELDS = {"ordinal", "description", "permanent_mac_readable"}
_DESCRIPTION_FIELDS = frozenset(OPERATOR_VISIBLE_FIELDS)


def validate_inventory_response(response: object) -> str:
    """Validate one exact successful ``commission.inventory`` reply.

    The returned value is the producer's snapshot pin as text; no truth or
    freshness claim is made about that digest or the displayed inventory.
    """
    try:
        if (type(response) is not dict or set(response) != _RESPONSE_FIELDS
                or response["ok"] is not True):
            raise ApprovalRefused("commission inventory response refused")
        result = response["result"]
        if type(result) is not dict or set(result) != _RESULT_FIELDS:
            raise ApprovalRefused("commission inventory result refused")
        digest = result["snapshot"]
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise ApprovalRefused("commission inventory digest refused")
        rows = result["interfaces"]
        if type(rows) is not list or len(rows) > MAX_INTERFACES:
            raise ApprovalRefused("commission inventory rows refused")
        for ordinal, row in enumerate(rows):
            if type(row) is not dict or set(row) != _ROW_FIELDS:
                raise ApprovalRefused("commission inventory row refused")
            if type(row["ordinal"]) is not int or row["ordinal"] != ordinal:
                raise ApprovalRefused("commission inventory ordinal refused")
            if type(row["permanent_mac_readable"]) is not bool:
                raise ApprovalRefused("commission inventory readability flag refused")
            description = row["description"]
            if (type(description) is not dict
                    or not set(description) <= _DESCRIPTION_FIELDS
                    or any(type(value) is not str or not value
                           for value in description.values())):
                raise ApprovalRefused("commission inventory description refused")
        return digest
    except Exception:
        raise ApprovalRefused("commission inventory response refused") from None
