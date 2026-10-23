"""Scope-local signing-key retirement policy; no authority or freshness claim."""
from .merkle import MAX_SIZE


def valid_policy(active, retired) -> bool:
    if type(active) is not frozenset or type(retired) is not dict:
        return False
    if not active and not retired:
        return False
    if any(type(key) is not str or not key for key in active):
        return False
    for key, record in retired.items():
        if (type(key) is not str or not key or key in active or type(record) is not dict
                or set(record) != {"retired_after_size"}
                or type(record["retired_after_size"]) is not int
                or not 0 <= record["retired_after_size"] <= MAX_SIZE):
            return False
    return True


def copy_retirements(active, retired):
    if not valid_policy(active, retired):
        raise ValueError("invalid active/retired evidence key policy")
    return {key: {"retired_after_size": row["retired_after_size"]}
            for key, row in retired.items()}


def key_allowed(key, size, active, retired=None) -> bool:
    retired = {} if retired is None else retired
    if (type(key) is not str or type(size) is not int or not 0 <= size <= MAX_SIZE
            or not valid_policy(active, retired)):
        return False
    return key in active or (key in retired and size <= retired[key]["retired_after_size"])
