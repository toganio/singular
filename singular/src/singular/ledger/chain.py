"""Blocks and the chain: hash-linked, validator-signed, replayable by anyone.

Like Bitcoin, every block names the hash of the block before it, commits to its transactions
with a Merkle root, and the whole history can be re-verified from the genesis block by someone
who trusts nothing but the genesis hash. Unlike Bitcoin there is no mining: blocks are signed by
a fixed validator set named in genesis (proof of authority), taking turns by height. v0.1 ships
one block producer; other parties run verifying replicas (``singular ledger verify``).

Each block also commits to the full ledger state after it (``state_root``), so a replica that
disagrees about any rule finds out at the first block where it matters.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable

from ..canonical import canonical, hash_obj, merkle_root
from ..errors import LedgerRejected, SingularError
from ..keys import SigningKey, verify_signature
from . import tx as T
from .state import LedgerState

_BLOCK_DOMAIN = b"singular-block:v1:"
ZERO_HASH = "0" * 64
MAX_TXS_PER_BLOCK = 256


class ChainError(SingularError):
    """The chain data itself is invalid (bad link, bad signature, state mismatch)."""


def now_ms() -> int:
    return int(time.time() * 1000)


def block_hash(header: dict) -> str:
    return hash_obj(header)


def make_genesis(chain_name: str, validators: list[str], ts: int | None = None) -> dict:
    """Genesis has no signature; its hash *is* the chain id everyone pins."""
    if not validators or len(set(validators)) != len(validators) or not all(T.is_hex(v, 64) for v in validators):
        raise ChainError("genesis needs a non-empty list of distinct validator public keys")
    header = {"height": 0, "prev": ZERO_HASH, "ts": ts if ts is not None else now_ms(), "tx_root": merkle_root([]),
              "state_root": merkle_root([]), "validator": "",
              "params": {"name": chain_name, "validators": list(validators), "protocol": 1}}
    return {"header": header, "sig": "", "txs": []}


def expected_validator(validators: list[str], height: int) -> str:
    return validators[height % len(validators)]


def apply_block(state: LedgerState, prev_header: dict, validators: list[str], block: dict) -> None:
    """Verify one block against its parent and apply it. Raises :class:`ChainError`."""
    try:
        header, txs, sig = block["header"], block["txs"], block["sig"]
        height = header["height"]
    except (KeyError, TypeError):
        raise ChainError("malformed block") from None
    if set(header) != {"height", "prev", "ts", "tx_root", "state_root", "validator"}:
        raise ChainError(f"block {height}: unexpected header fields")
    if height != prev_header["height"] + 1 or header["prev"] != block_hash(prev_header):
        raise ChainError(f"block {height}: does not link to its parent")
    if not isinstance(header["ts"], int) or header["ts"] <= prev_header["ts"]:
        raise ChainError(f"block {height}: timestamp must move forward")
    if header["validator"] != expected_validator(validators, height):
        raise ChainError(f"block {height}: signed by the wrong validator")
    if not verify_signature(header["validator"], _BLOCK_DOMAIN + canonical(header), sig):
        raise ChainError(f"block {height}: bad validator signature")
    if not isinstance(txs, list) or not 1 <= len(txs) <= MAX_TXS_PER_BLOCK:
        raise ChainError(f"block {height}: must carry 1..{MAX_TXS_PER_BLOCK} transactions")
    try:
        if header["tx_root"] != merkle_root(T.txid(t, state.chain_id) for t in txs):
            raise ChainError(f"block {height}: tx_root mismatch")
        for t in txs:
            state.apply(t, header["ts"])
    except (LedgerRejected, KeyError, TypeError) as exc:
        raise ChainError(f"block {height}: contains an invalid transaction ({exc})") from None
    if header["state_root"] != state.root():
        raise ChainError(f"block {height}: state_root mismatch")


def verify_chain(blocks: Iterable[dict], expected_chain_id: str | None = None) -> tuple[LedgerState, dict]:
    """Replay a whole chain from genesis. Returns the resulting state and the head header."""
    iterator = iter(blocks)
    try:
        genesis = next(iterator)
    except StopIteration:
        raise ChainError("empty chain") from None
    header = genesis.get("header", {})
    if header.get("height") != 0 or header.get("prev") != ZERO_HASH or genesis.get("txs"):
        raise ChainError("first block is not a genesis block")
    chain_id = block_hash(header)
    if expected_chain_id is not None and chain_id != expected_chain_id:
        raise ChainError("this is a different chain than the one you pinned")
    validators = header["params"]["validators"]
    state = LedgerState(chain_id)
    for block in iterator:
        apply_block(state, header, validators, block)
        header = block["header"]
    return state, header


class Chain:
    """A block-producing (or read-only) node's view of the chain, stored in SQLite."""

    def __init__(self, path: str | Path, validator_key: SigningKey | None = None):
        self._lock = threading.RLock()
        self._key = validator_key
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, hash TEXT NOT NULL, data TEXT NOT NULL)")
        self._db.execute("CREATE TABLE IF NOT EXISTS txs (txid TEXT PRIMARY KEY, height INTEGER NOT NULL, subject TEXT NOT NULL)")
        self._db.execute("CREATE INDEX IF NOT EXISTS txs_subject ON txs (subject, height)")
        rows = self._db.execute("SELECT data FROM blocks ORDER BY height").fetchall()
        if not rows:
            raise ChainError("no genesis block; create the chain with Chain.create()")
        self.state, self.head = verify_chain(json.loads(r[0]) for r in rows)
        self.chain_id = self.state.chain_id
        self.validators = json.loads(rows[0][0])["header"]["params"]["validators"]

    @classmethod
    def create(cls, path: str | Path, chain_name: str, validator_key: SigningKey,
               validators: list[str] | None = None) -> "Chain":
        path = Path(path)
        if path.exists() and path.stat().st_size:
            raise ChainError(f"{path} already exists")
        path.parent.mkdir(parents=True, exist_ok=True)
        genesis = make_genesis(chain_name, validators or [validator_key.public_hex])
        db = sqlite3.connect(str(path))
        db.execute("CREATE TABLE blocks (height INTEGER PRIMARY KEY, hash TEXT NOT NULL, data TEXT NOT NULL)")
        db.execute("INSERT INTO blocks VALUES (0, ?, ?)", (block_hash(genesis["header"]), canonical(genesis).decode()))
        db.commit()
        db.close()
        return cls(path, validator_key)

    # -- reading ---------------------------------------------------------------------------

    def info(self) -> dict:
        with self._lock:
            return {"chain_id": self.chain_id, "height": self.head["height"], "head": block_hash(self.head),
                    "head_ts": self.head["ts"], "validators": list(self.validators),
                    "agents": len(self.state.agents), "banks": len(self.state.banks)}

    def blocks(self, start: int = 0, limit: int = 200) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            rows = self._db.execute("SELECT data FROM blocks WHERE height >= ? ORDER BY height LIMIT ?",
                                    (int(start), limit)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def history(self, subject: str, limit: int = 200) -> list[dict]:
        """Every transaction that touched an agent or bank, oldest first: the audit trail."""
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            rows = self._db.execute("SELECT txid, height FROM txs WHERE subject = ? ORDER BY height LIMIT ?",
                                    (subject, limit)).fetchall()
            out = []
            for wanted, height in rows:
                block = json.loads(self._db.execute("SELECT data FROM blocks WHERE height = ?", (height,)).fetchone()[0])
                for t in block["txs"]:
                    if T.txid(t, self.chain_id) == wanted:
                        out.append({"txid": wanted, "height": height, "ts": block["header"]["ts"], "tx": t})
        return out

    # -- writing ---------------------------------------------------------------------------

    def submit(self, tx: dict) -> dict:
        """Validate a transaction and, if it passes, seal it into a new block right away."""
        if self._key is None:
            raise LedgerRejected("READ_ONLY", "this node does not produce blocks")
        with self._lock:
            height = self.head["height"] + 1
            if expected_validator(self.validators, height) != self._key.public_hex:
                raise LedgerRejected("NOT_MY_TURN", "another validator produces the next block")
            ts = max(now_ms(), self.head["ts"] + 1)
            T.check_shape(tx)
            subject = tx["subject"]
            before = (self.state.agents.get(subject), self.state.banks.get(subject),
                      dict(self.state._hashes), dict(self.state.banks))
            try:
                self.state.apply(tx, ts)
                header = {"height": height, "prev": block_hash(self.head), "ts": ts,
                          "tx_root": merkle_root([T.txid(tx, self.chain_id)]),
                          "state_root": self.state.root(), "validator": self._key.public_hex}
                block = {"header": header, "sig": self._key.sign(_BLOCK_DOMAIN + canonical(header)), "txs": [tx]}
                tid = T.txid(tx, self.chain_id)
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute("INSERT INTO blocks VALUES (?, ?, ?)", (height, block_hash(header), canonical(block).decode()))
                self._db.execute("INSERT INTO txs VALUES (?, ?, ?)", (tid, height, subject))
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                self._restore(subject, before)
                raise
            self.head = header
            return {"txid": tid, "height": height, "block": block_hash(header), "ts": ts}

    def _restore(self, subject: str, before: tuple) -> None:
        agent, bank, hashes, banks = before
        if agent is None:
            self.state.agents.pop(subject, None)
        else:
            self.state.agents[subject] = agent
        self.state.banks = banks
        self.state._hashes = hashes

    def append_verified(self, block: dict) -> None:
        """Replica path: verify a block produced elsewhere and store it. On any failure the
        in-memory state is rebuilt from disk, so a bad block can never half-apply."""
        with self._lock:
            try:
                apply_block(self.state, self.head, self.validators, block)
            except ChainError:
                rows = self._db.execute("SELECT data FROM blocks ORDER BY height").fetchall()
                self.state, self.head = verify_chain(json.loads(r[0]) for r in rows)
                raise
            header = block["header"]
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute("INSERT INTO blocks VALUES (?, ?, ?)",
                             (header["height"], block_hash(header), canonical(block).decode()))
            for t in block["txs"]:
                self._db.execute("INSERT OR IGNORE INTO txs VALUES (?, ?, ?)",
                                 (T.txid(t, self.chain_id), header["height"], t["subject"]))
            self._db.execute("COMMIT")
            self.head = header

    @classmethod
    def replica(cls, path: str | Path, genesis: dict, expected_chain_id: str) -> "Chain":
        """Start (or reopen) a read-only verifying copy pinned to a known chain id."""
        path = Path(path)
        if not path.exists() or not path.stat().st_size:
            if block_hash(genesis["header"]) != expected_chain_id:
                raise ChainError("the offered genesis is not the chain you pinned")
            path.parent.mkdir(parents=True, exist_ok=True)
            db = sqlite3.connect(str(path))
            db.execute("CREATE TABLE blocks (height INTEGER PRIMARY KEY, hash TEXT NOT NULL, data TEXT NOT NULL)")
            db.execute("INSERT INTO blocks VALUES (0, ?, ?)", (expected_chain_id, canonical(genesis).decode()))
            db.commit()
            db.close()
        chain = cls(path, None)
        if chain.chain_id != expected_chain_id:
            raise ChainError("existing replica belongs to a different chain")
        return chain

    def close(self) -> None:
        with self._lock:
            self._db.close()
