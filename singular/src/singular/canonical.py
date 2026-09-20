"""Canonical encoding and hashing.

Everything that gets signed or hashed goes through :func:`canonical` first, so two
implementations that agree on the data agree on the bytes. Floats are rejected on
purpose: their text form is not stable across languages, and a ledger cannot afford
"almost equal".
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

_DOMAIN_LEAF = b"\x00"
_DOMAIN_NODE = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"singular:empty").hexdigest()


def _check(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise TypeError(f"floats are not canonical ({path})")
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"non-string key at {path}")
            _check(item, f"{path}.{key}")
        return
    raise TypeError(f"{type(value).__name__} is not canonical ({path})")


def canonical(value: Any) -> bytes:
    """Deterministic UTF-8 JSON: sorted keys, no whitespace, no floats."""
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(value: Any) -> str:
    return sha256_hex(canonical(value))


def merkle_root(leaf_hashes: Iterable[str]) -> str:
    """Merkle root over hex leaf hashes, in the order given.

    Leaves and inner nodes are domain-separated so an inner node can never be passed
    off as a leaf. An odd node is promoted unchanged (no Bitcoin-style duplication,
    which allows two different leaf lists to share a root).
    """
    level = [hashlib.sha256(_DOMAIN_LEAF + bytes.fromhex(h)).digest() for h in leaf_hashes]
    if not level:
        return EMPTY_ROOT
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(_DOMAIN_NODE + level[i] + level[i + 1]).digest())
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()
