"""The liability log: a signed, hash-chained record of everything the agent did.

Each record commits to the previous one, to the agent's identity, ownership epoch and run lease,
and to *hashes* of the action's input and output. The records stay with the agent (they may hold
private material); only the chain head, the count and a Merkle root per batch go to the ledger.

That split is what makes the log usable as evidence without publishing anyone's data: reveal one
record later, and anyone can check it hashes into a batch the ledger timestamped back then, signed
by the key the ledger says was the agent's, during a lease the ledger says was live.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .canonical import canonical, hash_obj, merkle_root, sha256_hex
from .errors import SealError
from .keys import SigningKey, verify_signature

ZERO_HASH = "0" * 64
_DOMAIN = b"singular-action:v1:"
MAX_SUMMARY = 2000


def digest_of(value: object) -> str:
    """Hash arbitrary tool input/output. Non-canonical values (floats, objects) fall back to repr-free JSON."""
    try:
        return sha256_hex(canonical(value))
    except TypeError:
        return sha256_hex(json.dumps(value, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8"))


def record_hash(record: dict) -> str:
    return hash_obj({k: v for k, v in record.items() if k != "sig"})


class ActionLog:
    """Append-only JSONL under ``.singular/actions.jsonl`` plus a pointer to what is anchored."""

    def __init__(self, directory: Path):
        self.path = Path(directory) / "actions.jsonl"
        self._lock = threading.Lock()
        self.count, self.head = 0, ZERO_HASH
        # A bought agent arrives without the seller's private records, only with where their chain ended.
        base = Path(directory) / "actions.base.json"
        if base.exists():
            data = json.loads(base.read_text(encoding="utf-8"))
            self.count, self.head = int(data["count"]), str(data["head"])
        self.base_count = self.count
        if self.path.exists():
            for record in self.read():
                self.count, self.head = record["n"], record_hash(record)

    def read(self, first: int = 1) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    record = json.loads(line)
                    if record["n"] >= first:
                        out.append(record)
        return out

    def append(self, key: SigningKey, *, agent_id: str, epoch: int, lease_no: int, ts_ms: int, kind: str,
               name: str, input_value: object, output_value: object, status: str = "ok",
               summary: str = "", session: str = "") -> dict:
        with self._lock:
            record = {"v": 1, "n": self.count + 1, "prev": self.head, "agent": agent_id, "epoch": epoch,
                      "lease": lease_no, "ts": ts_ms, "kind": kind, "name": name, "status": status,
                      "input": digest_of(input_value), "output": digest_of(output_value),
                      "summary": summary[:MAX_SUMMARY], "session": session}
            record["sig"] = key.sign(_DOMAIN + canonical(record))
            line = json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            self.count, self.head = record["n"], record_hash(record)
            return record

    def batch(self, anchored_count: int) -> dict | None:
        """The ``ACTIONS`` transaction body for everything not yet on the ledger."""
        pending = self.read(max(anchored_count, self.base_count) + 1)
        if not pending:
            return None
        return {"first": pending[0]["n"], "last": pending[-1]["n"], "prev_head": pending[0]["prev"],
                "head": record_hash(pending[-1]), "batch_root": merkle_root(record_hash(r) for r in pending)}


def verify_log(records: list[dict], agent_keys_by_epoch: dict[int, str], *, start_head: str = ZERO_HASH,
               start_count: int = 0) -> str:
    """Check numbering, linkage and every signature. Returns the resulting head hash."""
    head, count = start_head, start_count
    for record in records:
        if record.get("n") != count + 1 or record.get("prev") != head:
            raise SealError(f"action log is broken at record {record.get('n')}")
        pub = agent_keys_by_epoch.get(record.get("epoch"))
        unsigned = {k: v for k, v in record.items() if k != "sig"}
        if not pub or not verify_signature(pub, _DOMAIN + canonical(unsigned), record.get("sig", "")):
            raise SealError(f"action record {record.get('n')} has a bad signature")
        head, count = record_hash(record), count + 1
    return head
