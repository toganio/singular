"""Transactions: what they look like, how they are signed, how signatures are checked.

A transaction is::

    {"v": 1, "type": "...", "subject": "sng1...", "nonce": 7, "body": {...},
     "sigs": [{"role": "agent", "pub": "<hex>", "sig": "<hex>"}, ...]}

Every signer signs the same bytes: a domain prefix plus the canonical form of the
transaction *without* ``sigs`` but *with* the chain id, so a signature made for one
chain (say a test network) is worthless on another.
"""

from __future__ import annotations

from typing import Iterable

from ..canonical import canonical, sha256_hex
from ..errors import LedgerRejected
from ..keys import SigningKey, verify_signature

TX_VERSION = 1
_DOMAIN = b"singular-tx:v1:"

REGISTER = "REGISTER"
LEASE_ACQUIRE = "LEASE_ACQUIRE"
LEASE_RENEW = "LEASE_RENEW"
LEASE_RELEASE = "LEASE_RELEASE"
LEASE_REVOKE = "LEASE_REVOKE"
SEAL = "SEAL"
ACTIONS = "ACTIONS"
TRANSFER = "TRANSFER"
ROLLBACK = "ROLLBACK"
OWNER_ATTEST = "OWNER_ATTEST"
RETIRE = "RETIRE"

# Memory banks: a memory is its own sealed object with its own single line of history.
# An agent's internal memory is a bank bound to that agent; an external bank stands alone.
BANK_CREATE = "BANK_CREATE"
BANK_GRANT = "BANK_GRANT"
BANK_REVOKE = "BANK_REVOKE"
BANK_REKEY = "BANK_REKEY"
BANK_SEAL = "BANK_SEAL"
BANK_TRANSFER = "BANK_TRANSFER"

AGENT_TYPES = frozenset({REGISTER, LEASE_ACQUIRE, LEASE_RENEW, LEASE_RELEASE, LEASE_REVOKE, SEAL,
                         ACTIONS, TRANSFER, ROLLBACK, OWNER_ATTEST, RETIRE})
BANK_TYPES = frozenset({BANK_CREATE, BANK_GRANT, BANK_REVOKE, BANK_REKEY, BANK_SEAL, BANK_TRANSFER})
ALL_TYPES = AGENT_TYPES | BANK_TYPES

MAX_TX_BYTES = 32 * 1024


def signing_bytes(tx: dict, chain_id: str) -> bytes:
    core = {"v": tx["v"], "type": tx["type"], "subject": tx["subject"], "nonce": tx["nonce"],
            "body": tx["body"], "chain": chain_id}
    return _DOMAIN + canonical(core)


def txid(tx: dict, chain_id: str) -> str:
    return sha256_hex(signing_bytes(tx, chain_id))


def build(tx_type: str, subject_id: str, nonce: int, body: dict) -> dict:
    """``subject_id`` is the agent id, or the bank id for ``BANK_*`` transactions."""
    return {"v": TX_VERSION, "type": tx_type, "subject": subject_id, "nonce": nonce, "body": body, "sigs": []}


def sign(tx: dict, chain_id: str, role: str, key: SigningKey) -> dict:
    """Add (or replace) the signature for ``role``. Returns the same dict for chaining."""
    tx["sigs"] = [s for s in tx["sigs"] if s.get("role") != role]
    tx["sigs"].append({"role": role, "pub": key.public_hex, "sig": key.sign(signing_bytes(tx, chain_id))})
    tx["sigs"].sort(key=lambda s: s["role"])
    return tx


def check_shape(tx: object) -> dict:
    """Structural validation only; rules live in :mod:`singular.ledger.state`."""
    if not isinstance(tx, dict):
        raise LedgerRejected("BAD_TX", "transaction must be an object")
    if set(tx) != {"v", "type", "subject", "nonce", "body", "sigs"}:
        raise LedgerRejected("BAD_TX", "unexpected or missing top-level fields")
    if tx["v"] != TX_VERSION:
        raise LedgerRejected("BAD_TX", "unsupported transaction version")
    if tx["type"] not in ALL_TYPES:
        raise LedgerRejected("BAD_TX", f"unknown type {tx['type']!r}")
    if not isinstance(tx["subject"], str) or not 8 <= len(tx["subject"]) <= 64:
        raise LedgerRejected("BAD_TX", "bad subject id")
    if not isinstance(tx["nonce"], int) or isinstance(tx["nonce"], bool) or tx["nonce"] < 1:
        raise LedgerRejected("BAD_TX", "nonce must be a positive integer")
    if not isinstance(tx["body"], dict):
        raise LedgerRejected("BAD_TX", "body must be an object")
    sigs = tx["sigs"]
    if not isinstance(sigs, list) or not 1 <= len(sigs) <= 4:
        raise LedgerRejected("BAD_TX", "sigs must be a list of 1-4 signatures")
    for sig in sigs:
        if not isinstance(sig, dict) or set(sig) != {"role", "pub", "sig"} or \
                not all(isinstance(sig[k], str) for k in ("role", "pub", "sig")):
            raise LedgerRejected("BAD_TX", "malformed signature entry")
    try:
        size = len(canonical(tx))
    except TypeError as exc:
        raise LedgerRejected("BAD_TX", str(exc)) from None
    if size > MAX_TX_BYTES:
        raise LedgerRejected("BAD_TX", "transaction too large")
    return tx


def require_signers(tx: dict, chain_id: str, required: dict[str, str]) -> None:
    """``required`` maps role -> the public key that must have signed in that role.
    Exactly those roles must be present: no missing signer, no surprise extra."""
    by_role = {s["role"]: s for s in tx["sigs"]}
    if len(by_role) != len(tx["sigs"]):
        raise LedgerRejected("BAD_SIGNATURE", "duplicate signer role")
    if set(by_role) != set(required):
        raise LedgerRejected("BAD_SIGNATURE", f"signer roles must be exactly {sorted(required)}")
    message = signing_bytes(tx, chain_id)
    for role, pub in required.items():
        sig = by_role[role]
        if sig["pub"] != pub:
            raise LedgerRejected("BAD_SIGNATURE", f"{role} signature is from the wrong key")
        if not verify_signature(pub, message, sig["sig"]):
            raise LedgerRejected("BAD_SIGNATURE", f"{role} signature does not verify")


def is_hex(value: object, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return value == value.lower()


def require_fields(body: dict, fields: Iterable[str]) -> None:
    expected = set(fields)
    if set(body) != expected:
        raise LedgerRejected("BAD_BODY", f"body fields must be exactly {sorted(expected)}")
