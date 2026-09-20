"""The guard that stands between an agent runtime and the ledger.

Life of a run::

    guard = SingularGuard(home, ledger, passphrase)
    guard.start()            # full verify -> acquire the run lease -> heartbeat thread
    guard.check()            # before every action: raises if the lease is not provably ours
    guard.record_action(...) # liability log (anchored in batches)
    guard.reseal("memory")   # after the agent wrote to itself
    guard.stop()             # anchor actions -> final seal -> release the lease

It fails closed. If the ledger cannot be reached long enough for the lease to lapse, or the ledger
says someone else moved this agent's history forward, the guard marks itself lost and ``check``
raises from then on: an agent that cannot prove it is the one running instance stops acting.
"""

from __future__ import annotations

import threading
import time

from . import tree
from .actions import ActionLog
from .agent import AgentHome, check_chain, require_agent, require_bank, submit, verify
from .errors import LeaseError, LedgerRejected, SealError, SingularError
from .keys import SigningKey
from .ledger import tx as T
from .ledger.client import Ledger, LedgerUnavailable

ANCHOR_EVERY = 20  # actions between automatic ledger anchors


def _now_ms() -> int:
    return int(time.time() * 1000)


class SingularGuard:
    def __init__(self, home: AgentHome | str, ledger: Ledger, passphrase: str, *, heartbeat: bool = True):
        self.home = home if isinstance(home, AgentHome) else AgentHome(home)
        self.ledger = ledger
        self._passphrase = passphrase
        self._heartbeat_enabled = heartbeat
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._agent_key: SigningKey | None = None
        self._host_key: SigningKey | None = None
        self._nonce = 0
        self.lease: dict | None = None
        self.epoch = 0
        self.lost_reason: str | None = None
        self.log = ActionLog(self.home.sdir)
        self._anchored = 0
        self._core_root = self._memory_root = ""
        self._core_seq = self._memory_seq = self._bank_nonce = 0

    # -- properties ------------------------------------------------------------------------

    @property
    def active(self) -> bool:
        return self.lease is not None and self.lost_reason is None

    @property
    def agent_id(self) -> str:
        return self.home.agent_id

    @property
    def chain_id(self) -> str:
        return self.home.identity["chain_id"]

    # -- lifecycle -------------------------------------------------------------------------

    def start(self) -> dict:
        with self._lock:
            if self.lease is not None:
                raise LeaseError("guard already started")
            self._agent_key = self.home.unlock(self._passphrase)
            self._passphrase = ""
            report = verify(self.home, self.ledger)
            record = require_agent(self.ledger, self.agent_id)
            if record["status"] != "active":
                raise LeaseError("this agent has been retired")
            if record["agent_pub"] != self._agent_key.public_hex:
                raise LeaseError("this copy's key is no longer the agent's key (it was transferred); this copy cannot run")
            if not report["core"]["ok"]:
                raise SealError(f"core files were changed outside a sealed run: {report['core'].get('diff', {})}")
            if not report["memory"]["ok"]:
                raise SealError(f"internal memory was changed outside a sealed run: {report['memory'].get('diff', {})}")
            self._host_key = SigningKey.generate()
            try:
                submit(self.ledger, self.chain_id, T.LEASE_ACQUIRE, self.agent_id, record["nonce"] + 1,
                       {"host_pub": self._host_key.public_hex, "root": report["core"]["root"],
                        "memory_root": report["memory"]["root"]},
                       {"agent": self._agent_key, "host": self._host_key})
            except LedgerRejected as exc:
                if exc.code == "LEASE_HELD":
                    raise LeaseError(f"this agent is already running somewhere else ({exc.message})") from None
                raise LeaseError(f"the ledger refused the run lease: {exc}") from None
            record = require_agent(self.ledger, self.agent_id)
            bank = require_bank(self.ledger, record["memory_bank"])
            self._nonce, self.lease, self.epoch = record["nonce"], record["lease"], record["epoch"]
            self._core_root, self._core_seq = record["seal"]["root"], record["seal"]["seq"]
            self._memory_root, self._memory_seq, self._bank_nonce = bank["seal"]["root"], bank["seal"]["seq"], bank["nonce"]
            self._anchored = record["actions"]["count"]
            if self.log.count < self._anchored:
                self._abandon("local action log is behind the ledger; this is a stale copy")
                raise SealError("local action log is behind the ledger; this is a stale copy")
            if self._heartbeat_enabled:
                self._thread = threading.Thread(target=self._heartbeat, name="singular-heartbeat", daemon=True)
                self._thread.start()
            return {"agent_id": self.agent_id, "lease": self.lease, "epoch": self.epoch}

    def _abandon(self, reason: str) -> None:
        try:
            self._submit_agent(T.LEASE_RELEASE, {})
        except SingularError:
            pass
        self.lost_reason, self.lease = reason, None

    def check(self) -> None:
        """Raise unless this process provably still holds the run lease."""
        if self.lost_reason:
            raise LeaseError(f"run lease lost: {self.lost_reason}")
        if self.lease is None:
            raise LeaseError("no run lease (guard not started)")
        # The expiry was stamped by the validator's clock, not ours: stop a little early rather than act
        # on a lease that may already be dead on the ledger.
        margin = self.home.identity["policy"]["lease_ttl_ms"] // 10
        if _now_ms() >= self.lease["expires"] - margin:
            self.lost_reason = "lease expired before it could be renewed"
            raise LeaseError(f"run lease lost: {self.lost_reason}")

    def _submit_agent(self, tx_type: str, body: dict) -> dict:
        try:
            receipt = submit(self.ledger, self.chain_id, tx_type, self.agent_id, self._nonce + 1, body,
                             {"agent": self._agent_key, "host": self._host_key})
        except LedgerRejected as exc:
            if exc.code == "NONCE_CONFLICT":
                # The owner may have legitimately used a slot (that does not touch a live lease unless
                # it was a revoke). Re-read; if the lease is still ours, retry once.
                record = require_agent(self.ledger, self.agent_id)
                lease = record.get("lease")
                if lease and self._host_key and lease["host_pub"] == self._host_key.public_hex:
                    self._nonce = record["nonce"]
                    receipt = submit(self.ledger, self.chain_id, tx_type, self.agent_id, self._nonce + 1, body,
                                     {"agent": self._agent_key, "host": self._host_key})
                    self._nonce += 1
                    return receipt
                self.lost_reason = "the ledger shows this agent's history moved on without us"
            elif exc.code in ("NO_LEASE", "LEASE_EXPIRED", "BAD_SIGNATURE", "AGENT_RETIRED"):
                self.lost_reason = f"ledger says {exc.code}"
            raise
        self._nonce += 1
        return receipt

    def renew(self) -> None:
        with self._lock:
            self.check()
            self._submit_agent(T.LEASE_RENEW, {})
            self.lease = require_agent(self.ledger, self.agent_id)["lease"]

    def _heartbeat(self) -> None:
        ttl = self.home.identity["policy"]["lease_ttl_ms"] / 1000.0
        interval = max(0.2, ttl / 3.0)
        while not self._stop.wait(interval):
            try:
                self.renew()
            except LedgerUnavailable:
                continue  # keep trying until the lease actually lapses; check() enforces the deadline
            except SingularError:
                return

    # -- what the agent does ---------------------------------------------------------------

    def record_action(self, kind: str, name: str, input_value: object, output_value: object, *,
                      status: str = "ok", summary: str = "", session: str = "") -> dict:
        with self._lock:
            self.check()
            record = self.log.append(self._agent_key, agent_id=self.agent_id, epoch=self.epoch,
                                     lease_no=self.lease["no"], ts_ms=_now_ms(), kind=kind, name=name,
                                     input_value=input_value, output_value=output_value, status=status,
                                     summary=summary, session=session)
            if self.log.count - self._anchored >= ANCHOR_EVERY:
                self.anchor_actions()
            return record

    def anchor_actions(self) -> dict | None:
        with self._lock:
            self.check()
            body = self.log.batch(self._anchored)
            if body is None:
                return None
            receipt = self._submit_agent(T.ACTIONS, body)
            self._anchored = body["last"]
            return receipt

    def reseal(self, reason: str = "runtime") -> dict:
        """Seal whatever the agent changed in itself. Core and internal memory seal independently."""
        with self._lock:
            self.check()
            out: dict = {"core": None, "memory": None}
            core_entries = self.home.scan_core(use_cache=True)
            core = tree.summarize(core_entries)
            if core["root"] != self._core_root:
                self.home.snapshot("core", core_entries)
                out["core"] = self._submit_agent(T.SEAL, {
                    "seq": self._core_seq + 1, "prev_root": self._core_root, "root": core["root"],
                    "files": core["files"], "bytes": core["bytes"], "reason": reason[:64]})
                self._core_root, self._core_seq = core["root"], self._core_seq + 1
            memory_entries = self.home.scan_memory(use_cache=True)
            memory = tree.summarize(memory_entries)
            if memory["root"] != self._memory_root:
                self.home.snapshot("memory", memory_entries)
                out["memory"] = submit(self.ledger, self.chain_id, T.BANK_SEAL, self.home.bank_id, self._bank_nonce + 1, {
                    "writer": self.agent_id, "key_gen": 0, "seq": self._memory_seq + 1, "prev_root": self._memory_root,
                    "root": memory["root"], "files": memory["files"], "bytes": memory["bytes"]},
                    {"agent": self._agent_key, "host": self._host_key})
                self._memory_root, self._memory_seq, self._bank_nonce = memory["root"], self._memory_seq + 1, self._bank_nonce + 1
            return out

    def signers(self) -> dict[str, SigningKey]:
        """Agent + live-lease host keys, for writes to external memory banks."""
        self.check()
        return {"agent": self._agent_key, "host": self._host_key}

    @property
    def agent_key(self) -> SigningKey:
        self.check()
        return self._agent_key

    def stop(self) -> None:
        """Anchor, seal, release. Safe to call twice; best effort if the lease is already lost."""
        with self._lock:
            self._stop.set()
            if self.lease is None:
                return
            try:
                if not self.lost_reason:
                    self.anchor_actions()
                    self.reseal("shutdown")
                    self._submit_agent(T.LEASE_RELEASE, {})
            finally:
                self.lease = None
                self._agent_key = self._host_key = None
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)
