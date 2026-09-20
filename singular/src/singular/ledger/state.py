"""The rule machine: the only place that decides whether a transaction is allowed.

It is deterministic and has no clock of its own. "Now" is always the timestamp of the
block the transaction lands in, so every node that replays the chain reaches the same
state, including the same answer to "was that lease still alive?".

The rules, in plain words:

* One agent, one line of history. Each agent has a ``nonce``; a transaction must carry
  ``nonce + 1``. Two runtimes racing each other cannot both win the same slot.
* One agent, one running place. ``LEASE_ACQUIRE`` only succeeds when no unexpired lease
  exists, and it binds the lease to a fresh host key. Seals, action anchors, renewals and
  the release must be co-signed by *that* host key.
* No outside edits. A ``SEAL`` must name the previous sealed root. A copy whose files
  drifted (or that is simply old) cannot produce a valid next seal, and cannot even take
  the lease, because acquiring also requires the current sealed root.
* Memory is singular too. Every agent has an internal memory bank that only it can seal and
  that travels with it. External memory banks stand alone: their owner grants agents read or
  read+write access, every write is signed by a *running* agent (agent key + lease host key),
  and the bank has one sequence, so concurrent writers serialise: first wins, second rebases.
  Grants are pinned to the agent's ownership epoch, so selling an agent drops its bank access.
* Ownership moves by three signatures: the old owner lets go, the new owner accepts the
  exact sealed state, and a brand-new agent key proves itself. The old agent key stops
  working in the same instant.
"""

from __future__ import annotations

import copy

from ..canonical import canonical, hash_obj, merkle_root
from ..errors import LedgerRejected
from ..keys import derive_agent_id, derive_bank_id, internal_bank_id
from . import tx as T

ZERO_HASH = "0" * 64
MIN_LEASE_TTL_MS = 1_000
MAX_LEASE_TTL_MS = 3_600_000
MAX_DESCRIPTOR_BYTES = 4096
MAX_REASON_LEN = 64
MAX_GRANTS_PER_BANK = 64
MAX_WRAPPED_KEY_HEX = 512
OWNER_WRITER = "owner"


def _reject(code: str, message: str = "") -> None:
    raise LedgerRejected(code, message)


def _uint(value: object, name: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > 2**53:
        _reject("BAD_BODY", f"{name} must be an integer >= {minimum}")
    return value


def _hash(value: object, name: str) -> str:
    if not T.is_hex(value, 64):
        _reject("BAD_BODY", f"{name} must be 64 lowercase hex characters")
    return value


def _pub(value: object, name: str) -> str:
    if not T.is_hex(value, 64):
        _reject("BAD_BODY", f"{name} must be a 32-byte hex public key")
    return value


def _short(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) > MAX_REASON_LEN:
        _reject("BAD_BODY", f"{name} must be a string of at most {MAX_REASON_LEN} characters")
    return value


def _wrapped(value: object) -> str:
    if not isinstance(value, str) or not 32 <= len(value) <= MAX_WRAPPED_KEY_HEX or len(value) % 2:
        _reject("BAD_BODY", "wrapped_key must be hex")
    try:
        bytes.fromhex(value)
    except ValueError:
        _reject("BAD_BODY", "wrapped_key must be hex")
    return value


def lease_active(agent: dict, now_ms: int) -> bool:
    lease = agent.get("lease")
    return bool(lease) and now_ms < lease["expires"]


class LedgerState:
    """All agents known to the chain, plus the machinery to apply one transaction."""

    def __init__(self, chain_id: str):
        self.chain_id = chain_id
        self.agents: dict[str, dict] = {}
        self.banks: dict[str, dict] = {}
        self._hashes: dict[str, str] = {}

    # -- reading ---------------------------------------------------------------------------

    def get(self, agent_id: str) -> dict | None:
        agent = self.agents.get(agent_id)
        return copy.deepcopy(agent) if agent is not None else None

    def get_bank(self, bank_id: str) -> dict | None:
        bank = self.banks.get(bank_id)
        return copy.deepcopy(bank) if bank is not None else None

    def bank_owner(self, bank: dict) -> str:
        """An internal bank has no owner of its own: it belongs to whoever owns its agent."""
        if bank["mode"] == "internal":
            return self.agents[bank["bound_agent"]]["owner_pub"]
        return bank["owner_pub"]

    def grant_valid(self, bank: dict, agent_id: str, *, write: bool, now_ms: int) -> bool:
        agent = self.agents.get(agent_id)
        if agent is None or agent["status"] != "active":
            return False
        if bank["mode"] == "internal":
            return bank["bound_agent"] == agent_id
        grant = bank["grants"].get(agent_id)
        if not grant or grant["epoch"] != agent["epoch"] or grant["key_gen"] != bank["key_gen"]:
            return False
        if grant["expires"] and now_ms >= grant["expires"]:
            return False  # a rented grant that ran out
        return grant["rights"] == "rw" or not write

    def root(self) -> str:
        """Merkle root over every agent and bank record, ordered by id. Goes into each block header."""
        return merkle_root(self._hashes[k] for k in sorted(self._hashes))

    # -- writing ---------------------------------------------------------------------------

    def apply(self, tx: dict, now_ms: int) -> dict:
        """Validate and apply. Raises :class:`LedgerRejected` and changes nothing on failure."""
        T.check_shape(tx)
        if tx["type"] in T.BANK_TYPES:
            return self._apply_bank(tx, now_ms)
        agent_id = tx["subject"]
        current = self.agents.get(agent_id)
        if tx["type"] == T.REGISTER:
            if current is not None:
                _reject("ALREADY_REGISTERED", agent_id)
            updated, bank = self._register(tx, now_ms)
            self._store_bank(bank)
        else:
            if current is None:
                _reject("UNKNOWN_AGENT", agent_id)
            if current["status"] != "active":
                _reject("AGENT_RETIRED", agent_id)
            if tx["nonce"] != current["nonce"] + 1:
                # The fork detector: someone else already used this slot (or skipped ahead).
                _reject("NONCE_CONFLICT", f"expected {current['nonce'] + 1}, got {tx['nonce']}")
            updated = copy.deepcopy(current)
            getattr(self, "_" + tx["type"].lower())(updated, tx, now_ms)
            updated["nonce"] = tx["nonce"]
        self.agents[agent_id] = updated
        self._hashes[agent_id] = hash_obj(updated)
        return updated

    def _store_bank(self, bank: dict) -> None:
        self.banks[bank["id"]] = bank
        self._hashes[bank["id"]] = hash_obj(bank)

    def _apply_bank(self, tx: dict, now_ms: int) -> dict:
        bank_id = tx["subject"]
        current = self.banks.get(bank_id)
        if tx["type"] == T.BANK_CREATE:
            if current is not None or bank_id in self.agents:
                _reject("ALREADY_REGISTERED", bank_id)
            updated = self._bank_create(tx, now_ms)
        else:
            if current is None:
                _reject("UNKNOWN_BANK", bank_id)
            if tx["nonce"] != current["nonce"] + 1:
                # Two writers raced for the same slot: the loser pulls, merges and retries.
                _reject("NONCE_CONFLICT", f"expected {current['nonce'] + 1}, got {tx['nonce']}")
            updated = copy.deepcopy(current)
            getattr(self, "_" + tx["type"].lower())(updated, tx, now_ms)
            updated["nonce"] = tx["nonce"]
        self._store_bank(updated)
        return updated

    # -- REGISTER --------------------------------------------------------------------------

    def _register(self, tx: dict, now_ms: int) -> tuple[dict, dict]:
        body = tx["body"]
        T.require_fields(body, ["agent_pub", "enc_pub", "owner_pub", "salt", "descriptor", "policy",
                                "root", "files", "bytes", "memory_root", "memory_files", "memory_bytes"])
        enc_pub = _pub(body["enc_pub"], "enc_pub")
        agent_pub, owner_pub = _pub(body["agent_pub"], "agent_pub"), _pub(body["owner_pub"], "owner_pub")
        if agent_pub == owner_pub:
            _reject("BAD_BODY", "agent key and owner key must differ")
        if not T.is_hex(body["salt"], 32):
            _reject("BAD_BODY", "salt must be 16 hex bytes")
        if tx["nonce"] != 1:
            _reject("NONCE_CONFLICT", "REGISTER must use nonce 1")
        if tx["subject"] != derive_agent_id(agent_pub, owner_pub, body["salt"]):
            _reject("BAD_AGENT_ID", "agent id does not match its genesis keys")
        descriptor = body["descriptor"]
        if not isinstance(descriptor, dict) or not isinstance(descriptor.get("name"), str) \
                or not descriptor["name"].strip() or not isinstance(descriptor.get("function"), str):
            _reject("BAD_BODY", "descriptor needs string 'name' and 'function'")
        if len(canonical(descriptor)) > MAX_DESCRIPTOR_BYTES:
            _reject("BAD_BODY", "descriptor too large")
        policy = body["policy"]
        if not isinstance(policy, dict) or set(policy) != {"lease_ttl_ms", "allow_owner_attest"} \
                or not isinstance(policy["allow_owner_attest"], bool):
            _reject("BAD_BODY", "policy must be {lease_ttl_ms, allow_owner_attest}")
        ttl = _uint(policy["lease_ttl_ms"], "lease_ttl_ms")
        if not MIN_LEASE_TTL_MS <= ttl <= MAX_LEASE_TTL_MS:
            _reject("BAD_BODY", f"lease_ttl_ms must be within {MIN_LEASE_TTL_MS}..{MAX_LEASE_TTL_MS}")
        root, memory_root = _hash(body["root"], "root"), _hash(body["memory_root"], "memory_root")
        T.require_signers(tx, self.chain_id, {"owner": owner_pub, "agent": agent_pub})
        bank_id = internal_bank_id(tx["subject"])
        if bank_id in self.banks:
            _reject("ALREADY_REGISTERED", bank_id)
        bank = {
            "id": bank_id, "kind": "bank", "mode": "internal", "status": "active", "created": now_ms,
            "name": "internal", "bound_agent": tx["subject"], "owner_pub": None,
            "policy": {"allow_owner_write": False}, "nonce": 1, "key_gen": 0, "grants": {}, "transfers": 0,
            "seal": {"seq": 0, "root": memory_root, "ts": now_ms, "by": tx["subject"],
                     "files": _uint(body["memory_files"], "memory_files"),
                     "bytes": _uint(body["memory_bytes"], "memory_bytes")},
        }
        return {
            "id": tx["subject"], "kind": "agent", "status": "active", "registered": now_ms,
            "memory_bank": bank_id, "enc_pub": enc_pub,
            "genesis": {"agent_pub": agent_pub, "owner_pub": owner_pub, "salt": body["salt"]},
            "owner_pub": owner_pub, "agent_pub": agent_pub, "epoch": 0, "nonce": 1,
            "descriptor": descriptor, "policy": {"lease_ttl_ms": ttl, "allow_owner_attest": policy["allow_owner_attest"]},
            "seal": {"seq": 0, "root": root, "ts": now_ms, "kind": "genesis",
                     "files": _uint(body["files"], "files"), "bytes": _uint(body["bytes"], "bytes")},
            "roots": {root: 0},
            "lease": None, "lease_count": 0, "revocations": 0, "transfers": 0,
            "actions": {"count": 0, "head": ZERO_HASH, "anchors": 0},
        }, bank

    # -- leases ----------------------------------------------------------------------------

    def _lease_acquire(self, agent: dict, tx: dict, now_ms: int) -> None:
        body = tx["body"]
        T.require_fields(body, ["host_pub", "root", "memory_root"])
        host_pub = _pub(body["host_pub"], "host_pub")
        if host_pub in (agent["agent_pub"], agent["owner_pub"]):
            _reject("BAD_BODY", "host key must be a fresh key")
        T.require_signers(tx, self.chain_id, {"agent": agent["agent_pub"], "host": host_pub})
        if lease_active(agent, now_ms):
            _reject("LEASE_HELD", f"agent is running elsewhere until {agent['lease']['expires']}")
        if _hash(body["root"], "root") != agent["seal"]["root"]:
            _reject("STALE_STATE", "core files do not match the latest sealed state")
        if _hash(body["memory_root"], "memory_root") != self.banks[agent["memory_bank"]]["seal"]["root"]:
            _reject("STALE_STATE", "internal memory does not match its latest sealed state")
        agent["lease_count"] += 1
        agent["lease"] = {"no": agent["lease_count"], "host_pub": host_pub, "acquired": now_ms,
                          "expires": now_ms + agent["policy"]["lease_ttl_ms"]}

    def _require_live_lease(self, agent: dict, tx: dict, now_ms: int) -> None:
        if not agent.get("lease"):
            _reject("NO_LEASE", "no run lease is held")
        T.require_signers(tx, self.chain_id, {"agent": agent["agent_pub"], "host": agent["lease"]["host_pub"]})
        if not lease_active(agent, now_ms):
            _reject("LEASE_EXPIRED", "the run lease has expired")

    def _lease_renew(self, agent: dict, tx: dict, now_ms: int) -> None:
        T.require_fields(tx["body"], [])
        self._require_live_lease(agent, tx, now_ms)
        agent["lease"]["expires"] = now_ms + agent["policy"]["lease_ttl_ms"]

    def _lease_release(self, agent: dict, tx: dict, now_ms: int) -> None:
        T.require_fields(tx["body"], [])
        self._require_live_lease(agent, tx, now_ms)
        agent["lease"] = None

    def _lease_revoke(self, agent: dict, tx: dict, now_ms: int) -> None:
        T.require_fields(tx["body"], [])
        T.require_signers(tx, self.chain_id, {"owner": agent["owner_pub"]})
        if not agent.get("lease"):
            _reject("NO_LEASE", "nothing to revoke")
        agent["lease"] = None
        agent["revocations"] += 1

    # -- seals -----------------------------------------------------------------------------

    def _next_seal(self, agent: dict, body: dict, now_ms: int, kind: str, files: int, size: int) -> None:
        seal = agent["seal"]
        if _uint(body["seq"], "seq", 1) != seal["seq"] + 1:
            _reject("STALE_STATE", f"seal seq must be {seal['seq'] + 1}")
        if _hash(body["prev_root"], "prev_root") != seal["root"]:
            _reject("STALE_STATE", "prev_root is not the latest sealed root")
        root = _hash(body["root"], "root")
        agent["seal"] = {"seq": seal["seq"] + 1, "root": root, "ts": now_ms, "kind": kind,
                         "files": files, "bytes": size}
        agent["roots"].setdefault(root, agent["seal"]["seq"])

    def _seal(self, agent: dict, tx: dict, now_ms: int) -> None:
        body = tx["body"]
        T.require_fields(body, ["seq", "prev_root", "root", "files", "bytes", "reason"])
        self._require_live_lease(agent, tx, now_ms)
        _short(body["reason"], "reason")
        self._next_seal(agent, body, now_ms, "runtime", _uint(body["files"], "files"), _uint(body["bytes"], "bytes"))

    def _require_owner_idle(self, agent: dict, tx: dict, now_ms: int) -> None:
        T.require_signers(tx, self.chain_id, {"owner": agent["owner_pub"]})
        if lease_active(agent, now_ms):
            _reject("LEASE_HELD", "release or revoke the run lease first")

    def _rollback(self, agent: dict, tx: dict, now_ms: int) -> None:
        body = tx["body"]
        T.require_fields(body, ["seq", "prev_root", "root"])
        self._require_owner_idle(agent, tx, now_ms)
        if _hash(body["root"], "root") not in agent["roots"]:
            _reject("UNKNOWN_ROOT", "can only roll back to a state this agent has sealed before")
        self._next_seal(agent, body, now_ms, "rollback", agent["seal"]["files"], agent["seal"]["bytes"])

    def _owner_attest(self, agent: dict, tx: dict, now_ms: int) -> None:
        body = tx["body"]
        T.require_fields(body, ["seq", "prev_root", "root", "files", "bytes", "reason"])
        self._require_owner_idle(agent, tx, now_ms)
        if not agent["policy"]["allow_owner_attest"]:
            _reject("POLICY_FORBIDS", "this agent was registered with owner edits forbidden")
        _short(body["reason"], "reason")
        self._next_seal(agent, body, now_ms, "owner_attest", _uint(body["files"], "files"), _uint(body["bytes"], "bytes"))

    # -- actions ---------------------------------------------------------------------------

    def _actions(self, agent: dict, tx: dict, now_ms: int) -> None:
        body = tx["body"]
        T.require_fields(body, ["first", "last", "prev_head", "head", "batch_root"])
        self._require_live_lease(agent, tx, now_ms)
        log = agent["actions"]
        first, last = _uint(body["first"], "first", 1), _uint(body["last"], "last", 1)
        if first != log["count"] + 1 or last < first:
            _reject("ACTION_GAP", f"next action number must be {log['count'] + 1}")
        if _hash(body["prev_head"], "prev_head") != log["head"]:
            _reject("ACTION_FORK", "prev_head is not the anchored action head")
        agent["actions"] = {"count": last, "head": _hash(body["head"], "head"), "anchors": log["anchors"] + 1}
        _hash(body["batch_root"], "batch_root")

    # -- ownership -------------------------------------------------------------------------

    def _transfer(self, agent: dict, tx: dict, now_ms: int) -> None:
        body = tx["body"]
        T.require_fields(body, ["new_owner_pub", "new_agent_pub", "new_enc_pub", "root", "memory_root"])
        new_owner, new_agent = _pub(body["new_owner_pub"], "new_owner_pub"), _pub(body["new_agent_pub"], "new_agent_pub")
        if new_agent in (agent["agent_pub"], agent["owner_pub"], new_owner):
            _reject("BAD_BODY", "the new agent key must be a fresh key")
        T.require_signers(tx, self.chain_id, {"owner": agent["owner_pub"], "new_owner": new_owner, "new_agent": new_agent})
        if lease_active(agent, now_ms):
            _reject("LEASE_HELD", "stop the agent before transferring it")
        if _hash(body["root"], "root") != agent["seal"]["root"]:
            _reject("STALE_STATE", "buyer must accept exactly the latest sealed state")
        if _hash(body["memory_root"], "memory_root") != self.banks[agent["memory_bank"]]["seal"]["root"]:
            _reject("STALE_STATE", "buyer must accept exactly the latest sealed internal memory")
        # The epoch bump is what silently voids every external bank grant this agent held.
        agent.update(owner_pub=new_owner, agent_pub=new_agent, enc_pub=_pub(body["new_enc_pub"], "new_enc_pub"), lease=None,
                     epoch=agent["epoch"] + 1, transfers=agent["transfers"] + 1)

    def _retire(self, agent: dict, tx: dict, now_ms: int) -> None:
        T.require_fields(tx["body"], [])
        T.require_signers(tx, self.chain_id, {"owner": agent["owner_pub"]})
        agent["lease"] = None
        agent["status"] = "retired"

    # -- memory banks ----------------------------------------------------------------------

    def _bank_create(self, tx: dict, now_ms: int) -> dict:
        body = tx["body"]
        T.require_fields(body, ["owner_pub", "salt", "name", "policy", "root", "files", "bytes"])
        owner_pub = _pub(body["owner_pub"], "owner_pub")
        if not T.is_hex(body["salt"], 32):
            _reject("BAD_BODY", "salt must be 16 hex bytes")
        if tx["nonce"] != 1:
            _reject("NONCE_CONFLICT", "BANK_CREATE must use nonce 1")
        if tx["subject"] != derive_bank_id(owner_pub, body["salt"]):
            _reject("BAD_BANK_ID", "bank id does not match its genesis owner key")
        name = _short(body["name"], "name")
        if not name.strip():
            _reject("BAD_BODY", "bank needs a name")
        policy = body["policy"]
        if not isinstance(policy, dict) or set(policy) != {"allow_owner_write"} \
                or not isinstance(policy["allow_owner_write"], bool):
            _reject("BAD_BODY", "policy must be {allow_owner_write}")
        T.require_signers(tx, self.chain_id, {"owner": owner_pub})
        return {
            "id": tx["subject"], "kind": "bank", "mode": "external", "status": "active", "created": now_ms,
            "name": name, "bound_agent": None, "owner_pub": owner_pub, "policy": dict(policy),
            "nonce": 1, "key_gen": 1, "grants": {}, "transfers": 0,
            "seal": {"seq": 0, "root": _hash(body["root"], "root"), "ts": now_ms, "by": OWNER_WRITER,
                     "files": _uint(body["files"], "files"), "bytes": _uint(body["bytes"], "bytes")},
        }

    def _require_external_owner(self, bank: dict, tx: dict) -> None:
        if bank["mode"] != "external":
            _reject("INTERNAL_BANK", "an agent's internal memory cannot be shared or managed separately")
        T.require_signers(tx, self.chain_id, {"owner": bank["owner_pub"]})

    def _bank_grant(self, bank: dict, tx: dict, now_ms: int) -> None:
        body = tx["body"]
        T.require_fields(body, ["agent", "rights", "key_gen", "wrapped_key", "expires"])
        expires = _uint(body["expires"], "expires")  # 0 = no expiry; otherwise ms since epoch
        if expires and expires <= now_ms:
            _reject("BAD_BODY", "expires is already in the past")
        self._require_external_owner(bank, tx)
        agent = self.agents.get(body["agent"]) if isinstance(body["agent"], str) else None
        if agent is None or agent["status"] != "active":
            _reject("UNKNOWN_AGENT", "grants go to registered, active agents")
        if body["rights"] not in ("r", "rw"):
            _reject("BAD_BODY", "rights must be 'r' or 'rw'")
        if _uint(body["key_gen"], "key_gen", 1) != bank["key_gen"]:
            _reject("STALE_GRANT", f"bank key generation is {bank['key_gen']}")
        if body["agent"] not in bank["grants"] and len(bank["grants"]) >= MAX_GRANTS_PER_BANK:
            _reject("TOO_MANY_GRANTS", f"a bank holds at most {MAX_GRANTS_PER_BANK} grants")
        bank["grants"][body["agent"]] = {"rights": body["rights"], "epoch": agent["epoch"], "key_gen": bank["key_gen"],
                                         "wrapped_key": _wrapped(body["wrapped_key"]), "ts": now_ms,
                                         "expires": expires}

    def _bank_revoke(self, bank: dict, tx: dict, now_ms: int) -> None:
        body = tx["body"]
        T.require_fields(body, ["agent"])
        self._require_external_owner(bank, tx)
        if body["agent"] not in bank["grants"]:
            _reject("NO_GRANT", "that agent holds no grant on this bank")
        del bank["grants"][body["agent"]]

    def _bank_rekey(self, bank: dict, tx: dict, now_ms: int) -> None:
        """New data key for everything written from now on. Every surviving grant must be re-wrapped
        in the same transaction, so nobody is left holding a key that no longer opens new writes."""
        body = tx["body"]
        T.require_fields(body, ["key_gen", "wrapped_keys"])
        self._require_external_owner(bank, tx)
        if _uint(body["key_gen"], "key_gen", 1) != bank["key_gen"] + 1:
            _reject("STALE_GRANT", f"next key generation is {bank['key_gen'] + 1}")
        wrapped = body["wrapped_keys"]
        if not isinstance(wrapped, dict) or set(wrapped) != set(bank["grants"]):
            _reject("BAD_BODY", "wrapped_keys must cover exactly the current grants (revoke first to drop one)")
        bank["key_gen"] += 1
        for agent_id, key in wrapped.items():
            agent = self.agents[agent_id]
            bank["grants"][agent_id].update(wrapped_key=_wrapped(key), key_gen=bank["key_gen"], epoch=agent["epoch"])

    def _bank_seal(self, bank: dict, tx: dict, now_ms: int) -> None:
        body = tx["body"]
        T.require_fields(body, ["writer", "key_gen", "seq", "prev_root", "root", "files", "bytes"])
        writer = body["writer"]
        if _uint(body["key_gen"], "key_gen") != bank["key_gen"]:
            # The bank was re-keyed since this writer last looked: what it encrypted is unreadable to others.
            _reject("STALE_GRANT", f"bank key generation is {bank['key_gen']}")
        if writer == OWNER_WRITER:
            self._require_external_owner(bank, tx)
            if not bank["policy"]["allow_owner_write"]:
                _reject("POLICY_FORBIDS", "this bank was created with owner writes forbidden")
        else:
            agent = self.agents.get(writer) if isinstance(writer, str) else None
            if agent is None:
                _reject("UNKNOWN_AGENT", "writer is not a registered agent")
            # Only a legitimately *running* agent may write: its key plus its live lease's host key.
            self._require_live_lease(agent, tx, now_ms)
            if not self.grant_valid(bank, writer, write=True, now_ms=now_ms):
                _reject("NO_GRANT", "writer holds no valid write grant on this bank")
        seal = bank["seal"]
        if _uint(body["seq"], "seq", 1) != seal["seq"] + 1 or _hash(body["prev_root"], "prev_root") != seal["root"]:
            _reject("STALE_STATE", f"bank is at seq {seal['seq']}; pull, merge and retry")
        bank["seal"] = {"seq": seal["seq"] + 1, "root": _hash(body["root"], "root"), "ts": now_ms, "by": writer,
                        "files": _uint(body["files"], "files"), "bytes": _uint(body["bytes"], "bytes")}

    def _bank_transfer(self, bank: dict, tx: dict, now_ms: int) -> None:
        body = tx["body"]
        T.require_fields(body, ["new_owner_pub"])
        if bank["mode"] != "external":
            _reject("INTERNAL_BANK", "internal memory moves only together with its agent")
        new_owner = _pub(body["new_owner_pub"], "new_owner_pub")
        T.require_signers(tx, self.chain_id, {"owner": bank["owner_pub"], "new_owner": new_owner})
        bank.update(owner_pub=new_owner, transfers=bank["transfers"] + 1)
