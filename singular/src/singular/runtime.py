"""The guard that stands between an agent runtime and the ledger.

Life of a run::

    guard = SingularGuard(home, ledger, passphrase)
    guard.start()                       # pin-check the ledger, full verify, take the run lease, heartbeat
    n = guard.begin_action(name, input) # BEFORE a tool runs: idle-drift check + signed intent record
    guard.end_action(n, name, output)   # after it ran: signed result record; changes it made are sealed to it
    guard.stop()                        # anchor, final seal, release

Four rules make this hold under pressure:

* **Fail closed.** No provable lease, no action. The lease deadline is measured on this machine's boot-time
  clock from the moment the request *left*, never from the wall clock, so setting the clock back or suspending
  the machine cannot stretch a lease.
* **Nothing changes while the agent is idle.** Sealed files may change only inside an action the agent itself
  opened. If they differ from the last sealed state while no action is open, someone else wrote to the agent:
  the guard stops acting and seals nothing. A change made inside an action is sealed right after it, in a
  transaction that names that action.
* **No unrecorded action.** The signed intent record is on disk before the tool runs. If it cannot be written,
  the tool does not run. Pending records are anchored on a timer, so at most a few seconds of history ever
  exist only on this disk.
* **The ledger is not trusted blindly.** The guard remembers the last block it saw and refuses a node that
  shows a shorter or different history.
"""

from __future__ import annotations

import json
import os
import threading
import time

from . import tree
from .actions import ActionLog
from .agent import AgentHome, require_agent, require_bank, submit, verify
from .errors import LeaseError, LedgerRejected, SealError, SingularError
from .keys import SigningKey
from .ledger import tx as T
from .ledger.client import Ledger, LedgerUnavailable

ANCHOR_EVERY = 20          # records between forced anchors
ANCHOR_INTERVAL_S = 15.0   # and never leave records un-anchored longer than this while the ledger is reachable
STALE_ACTION_S = 900.0     # an action that never reported back stops shielding drift checks after this long
LEASE_SAFETY = 0.9         # act only during the first 90 % of a lease


def _now_ms() -> int:
    return int(time.time() * 1000)


def _boot_s() -> float:
    """Seconds since boot, counting suspend. Unlike the wall clock, nobody can set it back."""
    try:
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):  # non-Linux
        return time.monotonic()


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
        self.lost_reason: str | None = None     # the lease is gone: nothing can be submitted any more
        self.tamper_reason: str | None = None   # files were touched from outside: no actions, no seals; still anchor + release
        self.log = ActionLog(self.home.sdir)
        self._anchored = 0
        self._core_root = self._memory_root = ""
        self._core_seq = self._memory_seq = self._bank_nonce = 0
        self._deadline = 0.0
        self._ttl_s = 0.0
        self._open: dict[int, float] = {}

    # -- properties ------------------------------------------------------------------------

    @property
    def active(self) -> bool:
        return self.lease is not None and self.lost_reason is None and self.tamper_reason is None

    @property
    def agent_id(self) -> str:
        return self.home.agent_id

    @property
    def chain_id(self) -> str:
        return self.home.identity["chain_id"]

    # -- the ledger must not rewrite history -------------------------------------------------

    def _pin_path(self):
        return self.home.sdir / "ledger-head.json"

    def check_ledger_history(self) -> None:
        """Refuse a node whose chain no longer contains the last block we saw."""
        info = self.ledger.info()
        if info.get("chain_id") != self.chain_id:
            raise SingularError(f"ledger is chain {str(info.get('chain_id'))[:12]}, but this agent lives on {self.chain_id[:12]}")
        path = self._pin_path()
        if path.exists():
            try:
                pin = json.loads(path.read_text(encoding="utf-8"))
                height, wanted = int(pin["height"]), str(pin["hash"])
            except (ValueError, KeyError, TypeError):
                raise SingularError("the pinned ledger head is unreadable; refusing to trust the ledger") from None
            if info["height"] < height:
                raise SingularError(f"the ledger went backwards (height {info['height']}, we have seen {height}); refusing it")
            if self.ledger.block_hash_at(height) != wanted:
                raise SingularError(f"the ledger rewrote history at or before block {height}; refusing it")
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps({"height": info["height"], "hash": info["head"]}), encoding="utf-8")
        os.replace(tmp, path)

    # -- lifecycle -------------------------------------------------------------------------

    def start(self) -> dict:
        with self._lock:
            if self.lease is not None:
                raise LeaseError("guard already started")
            self._agent_key = self.home.unlock(self._passphrase)
            self._passphrase = ""
            self.check_ledger_history()
            report = verify(self.home, self.ledger)
            record = require_agent(self.ledger, self.agent_id)
            if record["status"] != "active":
                raise LeaseError("this agent has been retired")
            if record["agent_pub"] != self._agent_key.public_hex:
                raise LeaseError("this copy's key is no longer the agent's key (it was transferred or rotated); this copy cannot run")
            if not report["core"]["ok"]:
                raise SealError(f"core files were changed outside a sealed run: {report['core'].get('diff', {})}")
            if not report["memory"]["ok"]:
                raise SealError(f"internal memory was changed outside a sealed run: {report['memory'].get('diff', {})}")
            self._host_key = SigningKey.generate()
            self._ttl_s = record["policy"]["lease_ttl_ms"] / 1000.0
            sent = _boot_s()
            try:
                submit(self.ledger, self.chain_id, T.LEASE_ACQUIRE, self.agent_id, record["nonce"] + 1,
                       {"host_pub": self._host_key.public_hex, "root": report["core"]["root"],
                        "memory_root": report["memory"]["root"]},
                       {"agent": self._agent_key, "host": self._host_key})
            except LedgerRejected as exc:
                if exc.code == "LEASE_HELD":
                    raise LeaseError(f"this agent is already running somewhere else ({exc.message})") from None
                raise LeaseError(f"the ledger refused the run lease: {exc}") from None
            self._deadline = sent + self._ttl_s * LEASE_SAFETY
            record = require_agent(self.ledger, self.agent_id)
            bank = require_bank(self.ledger, record["memory_bank"])
            self._nonce, self.lease, self.epoch = record["nonce"], record["lease"], record["epoch"]
            self._core_root, self._core_seq = record["seal"]["root"], record["seal"]["seq"]
            self._memory_root, self._memory_seq, self._bank_nonce = bank["seal"]["root"], bank["seal"]["seq"], bank["nonce"]
            self._anchored = record["actions"]["count"]
            if self.log.count < self._anchored:
                self._abandon("local action log is behind the ledger; this is a stale copy")
                raise SealError("local action log is behind the ledger; this is a stale copy")
            # warm the hash cache now so the first idle check does not re-read every file
            self.home.scan_core(use_cache=True), self.home.scan_memory(use_cache=True)
            if self.log.count > self._anchored:
                self.anchor_actions()  # records a crashed run left behind
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
        if _boot_s() >= self._deadline:
            self.lost_reason = "lease expired before it could be renewed"
            raise LeaseError(f"run lease lost: {self.lost_reason}")

    def check_untouched(self) -> None:
        self.check()
        if self.tamper_reason:
            raise SealError(self.tamper_reason + ". Stop it and run `singular restore`.")

    def _submit_agent(self, tx_type: str, body: dict) -> dict:
        try:
            receipt = submit(self.ledger, self.chain_id, tx_type, self.agent_id, self._nonce + 1, body,
                             {"agent": self._agent_key, "host": self._host_key})
        except LedgerRejected as exc:
            if exc.code == "NONCE_CONFLICT":
                # The owner may have legitimately used a slot. Re-read; if the lease is still ours, retry once.
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
            sent = _boot_s()
            self._submit_agent(T.LEASE_RENEW, {})
            self._deadline = sent + self._ttl_s * LEASE_SAFETY
            self.lease = require_agent(self.ledger, self.agent_id)["lease"]

    def _heartbeat(self) -> None:
        renew_every = max(0.2, self._ttl_s / 3.0)
        tick = min(renew_every, ANCHOR_INTERVAL_S)
        last_renew = _boot_s()
        while not self._stop.wait(tick):
            try:
                if _boot_s() - last_renew >= renew_every:
                    self.renew()
                    last_renew = _boot_s()
                    with self._lock:
                        self.check_ledger_history()
                self.anchor_actions()
            except LedgerUnavailable:
                continue  # keep trying; check() enforces the deadline
            except LedgerRejected:
                if self.lost_reason:
                    return
            except SingularError as exc:
                with self._lock:
                    self.lost_reason = self.lost_reason or str(exc)
                return

    # -- nothing changes while the agent is idle ----------------------------------------------

    def _current(self) -> tuple[list[dict], dict, list[dict], dict]:
        core_entries = self.home.scan_core(use_cache=True)
        memory_entries = self.home.scan_memory(use_cache=True)
        return core_entries, tree.summarize(core_entries), memory_entries, tree.summarize(memory_entries)

    def _open_actions(self) -> int:
        now = _boot_s()
        for n, since in list(self._open.items()):
            if now - since > STALE_ACTION_S:
                del self._open[n]
        return len(self._open)

    def check_idle(self) -> None:
        """With no action open, the files must be exactly the last sealed state."""
        with self._lock:
            self.check_untouched()
            if self._open_actions():
                return
            _, core, _, memory = self._current()
            if core["root"] != self._core_root or memory["root"] != self._memory_root:
                what = "core files" if core["root"] != self._core_root else "internal memory"
                self.tamper_reason = f"{what} changed while the agent was idle: someone else wrote to this agent"
                self.check_untouched()

    # -- what the agent does ---------------------------------------------------------------

    def begin_action(self, name: str, input_value: object, *, kind: str = "tool", session: str = "") -> int:
        """Call BEFORE the action runs. Raises (and the action must not run) unless the lease is provable, the
        files are untouched, and the signed intent is safely on disk."""
        with self._lock:
            self.check_idle()
            record = self.log.append(self._agent_key, agent_id=self.agent_id, epoch=self.epoch, lease_no=self.lease["no"],
                                     ts_ms=_now_ms(), kind=f"{kind}.intent", name=name, input_value=input_value,
                                     output_value=None, status="started", session=session)
            self._open[record["n"]] = _boot_s()
            return record["n"]

    def end_action(self, intent_no: int | None, name: str, output_value: object, *, kind: str = "tool", status: str = "ok",
                   summary: str = "", session: str = "") -> dict:
        """Call after the action ran. Whatever it changed in the agent is sealed, tied to this record."""
        with self._lock:
            record = self.log.append(self._agent_key, agent_id=self.agent_id, epoch=self.epoch,
                                     lease_no=self.lease["no"] if self.lease else 0, ts_ms=_now_ms(), kind=f"{kind}.result",
                                     name=name, input_value={"intent": intent_no}, output_value=output_value,
                                     status=status, summary=summary, session=session)
            self._open.pop(intent_no, None)
            if self.active and not self._open_actions():
                self.reseal(f"action {record['n']}")
            if self.log.count - self._anchored >= ANCHOR_EVERY and self.active:
                self.anchor_actions()
            return record

    def record_action(self, kind: str, name: str, input_value: object, output_value: object, *,
                      status: str = "ok", summary: str = "", session: str = "") -> dict:
        """One-shot form for callers that cannot wrap the action (intent and result in one call)."""
        intent = self.begin_action(name, input_value, kind=kind, session=session)
        return self.end_action(intent, name, output_value, kind=kind, status=status, summary=summary, session=session)

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
        """Seal what the agent changed in itself. Core and internal memory seal independently."""
        with self._lock:
            self.check_untouched()
            out: dict = {"core": None, "memory": None}
            core_entries, core, memory_entries, memory = self._current()
            if core["root"] != self._core_root:
                self.home.snapshot("core", core_entries)
                out["core"] = self._submit_agent(T.SEAL, {
                    "seq": self._core_seq + 1, "prev_root": self._core_root, "root": core["root"],
                    "files": core["files"], "bytes": core["bytes"], "reason": reason[:64]})
                self._core_root, self._core_seq = core["root"], self._core_seq + 1
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
        self.check_untouched()
        return {"agent": self._agent_key, "host": self._host_key}

    @property
    def agent_key(self) -> SigningKey:
        self.check_untouched()
        return self._agent_key

    def stop(self) -> None:
        """Anchor, release. Safe to call twice; best effort if the lease is already lost. Anything that changed
        while idle is NOT sealed on the way out: the next start will refuse it, which is the point."""
        with self._lock:
            self._stop.set()
            if self.lease is None:
                return
            try:
                if not self.lost_reason:
                    try:
                        self.check_idle()
                    except SealError:
                        pass  # tampered: seal nothing, but still put the honest records on the ledger and let go
                    self.anchor_actions()
                    self._submit_agent(T.LEASE_RELEASE, {})
                    self.check_ledger_history()  # remember the block that holds our release
            finally:
                self.lease = None
                self._agent_key = self._host_key = None
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)
