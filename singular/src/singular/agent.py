"""An agent home on disk, and the operations its owner performs on it.

Layout inside the agent home (for Hermes: the profile's ``HERMES_HOME``)::

    .singular/identity.json       public facts: agent id, chain id, ledger url, sealed path lists
    .singular/agent.keystore.json the agent key, wrapped by the agent passphrase
    .singular/actions.jsonl       the liability log
    .singular/seals/<root>.json   manifest of each recent sealed state
    .singular/objects/<sha256>    content-addressed copies, so the last sealed state can be restored

The owner key is *not* here. It lives wherever the owner keeps it (default ``~/.singular-owner``)
and never travels inside a capsule.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from . import capsule, tree
from .actions import ActionLog
from .errors import CryptoError, LeaseError, LedgerRejected, SealError, SingularError
from .keys import (SigningKey, derive_agent_id, internal_bank_id, load_keystore, new_salt, save_keystore,
                   unwrap_key, wrap_key)
from .ledger import tx as T
from .ledger.client import Ledger

KEEP_SNAPSHOTS = 5
DEFAULT_LEASE_TTL_MS = 120_000


def default_owner_dir() -> Path:
    return Path(os.environ.get("SINGULAR_OWNER_DIR", str(Path.home() / ".singular-owner")))


def create_owner_key(path: Path, passphrase: str) -> SigningKey:
    path = Path(path)
    if path.exists():
        raise SingularError(f"{path} already exists; refusing to overwrite an owner key")
    key = SigningKey.generate()
    save_keystore(path, wrap_key(key, passphrase, label="owner"))
    os.chmod(path.parent, 0o700)
    return key


def load_key(path: Path, passphrase: str, label: str) -> SigningKey:
    store = load_keystore(path)
    if store.get("label") != label:
        raise CryptoError(f"{path} holds a {store.get('label')!r} key, expected {label!r}")
    return unwrap_key(store, passphrase)


class AgentHome:
    def __init__(self, home: str | Path):
        self.home = Path(home)
        self.sdir = self.home / tree.SINGULAR_DIR
        self.identity_path = self.sdir / "identity.json"
        self.keystore_path = self.sdir / "agent.keystore.json"
        self._identity: dict | None = None

    # -- identity --------------------------------------------------------------------------

    @property
    def is_singular(self) -> bool:
        return self.identity_path.exists()

    @property
    def identity(self) -> dict:
        if self._identity is None:
            try:
                self._identity = json.loads(self.identity_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise SingularError(f"{self.home} is not a Singular agent home: {exc}") from None
        return self._identity

    def save_identity(self, identity: dict) -> None:
        self.sdir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.sdir, 0o700)
        tmp = self.identity_path.with_name("identity.json.tmp")
        tmp.write_text(json.dumps(identity, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.identity_path)
        self._identity = identity

    @property
    def agent_id(self) -> str:
        return self.identity["agent_id"]

    @property
    def bank_id(self) -> str:
        return internal_bank_id(self.agent_id)

    def unlock(self, passphrase: str) -> SigningKey:
        return load_key(self.keystore_path, passphrase, "agent")

    # -- scanning --------------------------------------------------------------------------

    def _cache(self, use_cache: bool) -> tree.HashCache | None:
        return tree.HashCache(self.sdir / "hashcache.json") if use_cache else None

    def scan_core(self, use_cache: bool = False) -> list[dict]:
        ident = self.identity
        return tree.scan(self.home, ident["core"], ident.get("exclude"), self._cache(use_cache))

    def scan_memory(self, use_cache: bool = False) -> list[dict]:
        ident = self.identity
        return tree.scan(self.home, ident["memory"], ident.get("exclude"), self._cache(use_cache))

    # -- snapshots: being able to return to the last sealed state ---------------------------

    def snapshot(self, kind: str, entries: list[dict]) -> None:
        objects, seals = self.sdir / "objects", self.sdir / "seals"
        objects.mkdir(parents=True, exist_ok=True)
        seals.mkdir(parents=True, exist_ok=True)
        for entry in entries:
            if "h" in entry and not (objects / entry["h"]).exists():
                tmp = objects / (entry["h"] + ".tmp")
                shutil.copyfile(self.home / entry["p"], tmp)
                digest, _ = tree.file_sha256(tmp)
                if digest != entry["h"]:
                    tmp.unlink()
                    raise SealError(f"{entry['p']} changed while it was being sealed")
                os.replace(tmp, objects / entry["h"])
        manifest = seals / f"{kind}-{tree.root_of(entries)}.json"
        manifest.write_text(json.dumps({"kind": kind, "entries": entries}), encoding="utf-8")
        os.utime(manifest)
        self._prune(kind)

    def _prune(self, kind: str) -> None:
        seals, objects = self.sdir / "seals", self.sdir / "objects"
        manifests = sorted(seals.glob(f"{kind}-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for stale in manifests[KEEP_SNAPSHOTS:]:
            stale.unlink()
        live = set()
        for manifest in seals.glob("*.json"):
            live.update(e["h"] for e in json.loads(manifest.read_text(encoding="utf-8"))["entries"] if "h" in e)
        for obj in objects.iterdir():
            if obj.name not in live:
                obj.unlink()

    def restore(self, kind: str, root: str) -> dict:
        """Put the core or memory set back exactly as it was at the sealed state ``root``."""
        manifest = self.sdir / "seals" / f"{kind}-{root}.json"
        if not manifest.exists():
            raise SealError(f"no local snapshot of {kind} state {root[:12]}; import a capsule of it instead")
        wanted = json.loads(manifest.read_text(encoding="utf-8"))["entries"]
        current = self.scan_core() if kind == "core" else self.scan_memory()
        change = tree.diff(current, wanted)
        for rel in change["added"] + change["changed"]:
            entry = next(e for e in wanted if e["p"] == rel)
            dest = self.home / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if os.path.lexists(dest):
                dest.unlink()
            if "l" in entry:
                os.symlink(entry["l"], dest)
            else:
                shutil.copyfile(self.sdir / "objects" / entry["h"], dest)
        for rel in change["removed"]:
            (self.home / rel).unlink()
        after = self.scan_core() if kind == "core" else self.scan_memory()
        if tree.root_of(after) != root:
            raise SealError("restore did not reproduce the sealed state")
        return {"restored": len(change["added"]) + len(change["changed"]), "deleted": len(change["removed"])}


# -- ledger helpers ----------------------------------------------------------------------------

def require_agent(ledger: Ledger, agent_id: str) -> dict:
    record = ledger.get_agent(agent_id)
    if record is None:
        raise SingularError(f"agent {agent_id} is not on this ledger")
    return record


def require_bank(ledger: Ledger, bank_id: str) -> dict:
    record = ledger.get_bank(bank_id)
    if record is None:
        raise SingularError(f"memory bank {bank_id} is not on this ledger")
    return record


def submit(ledger: Ledger, chain_id: str, tx_type: str, subject: str, nonce: int, body: dict,
           signers: dict[str, SigningKey]) -> dict:
    transaction = T.build(tx_type, subject, nonce, body)
    for role, key in signers.items():
        T.sign(transaction, chain_id, role, key)
    return ledger.submit(transaction)


def check_chain(ledger: Ledger, chain_id: str) -> None:
    actual = ledger.info().get("chain_id")
    if actual != chain_id:
        raise SingularError(f"ledger is chain {str(actual)[:12]}, but this agent lives on {chain_id[:12]}")


# -- owner operations --------------------------------------------------------------------------

def init_agent(home: str | Path, ledger: Ledger, ledger_url: str, owner_key: SigningKey, passphrase: str, *,
               name: str, function: str, details: dict | None = None,
               lease_ttl_ms: int = DEFAULT_LEASE_TTL_MS, allow_owner_attest: bool = False,
               core: list[str] | None = None, memory: list[str] | None = None,
               exclude: list[str] | None = None) -> AgentHome:
    """Turn an existing agent folder into a Singular agent and register it on the ledger."""
    agent_home = AgentHome(home)
    if agent_home.is_singular:
        raise SingularError(f"{home} is already a Singular agent ({agent_home.agent_id})")
    agent_home.home.mkdir(parents=True, exist_ok=True)
    agent_key = SigningKey.generate()
    salt = new_salt()
    agent_id = derive_agent_id(agent_key.public_hex, owner_key.public_hex, salt)
    chain_id = ledger.info()["chain_id"]
    descriptor = {"name": name, "function": function, **(details or {})}
    policy = {"lease_ttl_ms": lease_ttl_ms, "allow_owner_attest": allow_owner_attest}
    identity = {"v": 1, "agent_id": agent_id, "chain_id": chain_id, "ledger_url": ledger_url,
                "descriptor": descriptor, "policy": policy, "core": core or list(tree.DEFAULT_CORE),
                "memory": memory or list(tree.DEFAULT_MEMORY), "exclude": exclude or [],
                "genesis": {"agent_pub": agent_key.public_hex, "owner_pub": owner_key.public_hex, "salt": salt}}
    for rel in identity["memory"]:
        (agent_home.home / rel).mkdir(parents=True, exist_ok=True)
    agent_home.save_identity(identity)
    try:
        save_keystore(agent_home.keystore_path, wrap_key(agent_key, passphrase, label="agent"))
        core_entries, memory_entries = agent_home.scan_core(), agent_home.scan_memory()
        c, m = tree.summarize(core_entries), tree.summarize(memory_entries)
        submit(ledger, chain_id, T.REGISTER, agent_id, 1, {
            "agent_pub": agent_key.public_hex, "enc_pub": agent_key.enc_public_hex, "owner_pub": owner_key.public_hex,
            "salt": salt, "descriptor": descriptor, "policy": policy, "root": c["root"], "files": c["files"],
            "bytes": c["bytes"], "memory_root": m["root"], "memory_files": m["files"], "memory_bytes": m["bytes"],
        }, {"owner": owner_key, "agent": agent_key})
    except BaseException:
        shutil.rmtree(agent_home.sdir, ignore_errors=True)
        raise
    agent_home.snapshot("core", core_entries)
    agent_home.snapshot("memory", memory_entries)
    return agent_home


def verify(agent_home: AgentHome, ledger: Ledger) -> dict:
    """Full check, no cache: do the files on disk match what the ledger sealed?"""
    check_chain(ledger, agent_home.identity["chain_id"])
    record = require_agent(ledger, agent_home.agent_id)
    bank = require_bank(ledger, record["memory_bank"])
    core_entries, memory_entries = agent_home.scan_core(), agent_home.scan_memory()
    core_ok = tree.root_of(core_entries) == record["seal"]["root"]
    memory_ok = tree.root_of(memory_entries) == bank["seal"]["root"]
    report = {"agent_id": record["id"], "status": record["status"], "name": record["descriptor"]["name"],
              "owner_pub": record["owner_pub"], "epoch": record["epoch"],
              "core": {"ok": core_ok, "seq": record["seal"]["seq"], "root": record["seal"]["root"]},
              "memory": {"ok": memory_ok, "seq": bank["seal"]["seq"], "root": bank["seal"]["root"]},
              "lease": record["lease"], "actions": record["actions"],
              "ok": core_ok and memory_ok and record["status"] == "active"}
    for kind, ok, entries, root in (("core", core_ok, core_entries, record["seal"]["root"]),
                                    ("memory", memory_ok, memory_entries, bank["seal"]["root"])):
        manifest = agent_home.sdir / "seals" / f"{kind}-{root}.json"
        if not ok and manifest.exists():
            report[kind]["diff"] = tree.diff(json.loads(manifest.read_text(encoding="utf-8"))["entries"], entries)
    return report


def revoke_lease(agent_home_or_id, ledger: Ledger, chain_id: str, owner_key: SigningKey) -> dict:
    agent_id = agent_home_or_id.agent_id if isinstance(agent_home_or_id, AgentHome) else agent_home_or_id
    record = require_agent(ledger, agent_id)
    return submit(ledger, chain_id, T.LEASE_REVOKE, agent_id, record["nonce"] + 1, {}, {"owner": owner_key})


def retire(agent_id: str, ledger: Ledger, chain_id: str, owner_key: SigningKey) -> dict:
    record = require_agent(ledger, agent_id)
    return submit(ledger, chain_id, T.RETIRE, agent_id, record["nonce"] + 1, {}, {"owner": owner_key})


def rollback(agent_home: AgentHome, ledger: Ledger, owner_key: SigningKey, root: str) -> dict:
    """Owner decision: make an *earlier sealed* core state the current one. Recorded on the ledger."""
    record = require_agent(ledger, agent_home.agent_id)
    agent_home.restore("core", root)
    seal = record["seal"]
    return submit(ledger, agent_home.identity["chain_id"], T.ROLLBACK, record["id"], record["nonce"] + 1,
                  {"seq": seal["seq"] + 1, "prev_root": seal["root"], "root": root}, {"owner": owner_key})


def owner_attest(agent_home: AgentHome, ledger: Ledger, owner_key: SigningKey, reason: str) -> dict:
    """Owner edits the core by hand and takes responsibility for it, *if* the agent's policy allows."""
    record = require_agent(ledger, agent_home.agent_id)
    entries = agent_home.scan_core()
    s, seal = tree.summarize(entries), record["seal"]
    receipt = submit(ledger, agent_home.identity["chain_id"], T.OWNER_ATTEST, record["id"], record["nonce"] + 1,
                     {"seq": seal["seq"] + 1, "prev_root": seal["root"], "root": s["root"], "files": s["files"],
                      "bytes": s["bytes"], "reason": reason}, {"owner": owner_key})
    agent_home.snapshot("core", entries)
    return receipt


# -- proving ownership to a third party ---------------------------------------------------------

_LINK_DOMAIN = b"singular-link:v1:"


def prove_ownership(owner_key: SigningKey, agent_id: str, challenge: str, site: str) -> dict:
    """Answer a one-time challenge from a service (for example a hosting dashboard) that wants to know you
    own an agent. The owner key signs locally; only the signature leaves this machine. The service checks it
    against the owner key the *ledger* names, so this proves current ownership and nothing else. ``site`` is
    part of the signed message, so a proof made for one service cannot be replayed at another."""
    import re
    if not re.fullmatch(r"sng1[a-z2-7]{20,40}", agent_id) or not re.fullmatch(r"[a-f0-9]{64}", challenge) \
            or not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", site):
        raise SingularError("agent id, challenge or site has an unexpected shape; copy the command exactly")
    from .canonical import canonical
    message = _LINK_DOMAIN + canonical({"agent": agent_id, "challenge": challenge, "site": site})
    return {"agent": agent_id, "challenge": challenge, "site": site, "owner_pub": owner_key.public_hex,
            "sig": owner_key.sign(message)}


# -- moving and selling ------------------------------------------------------------------------

def export_capsule(agent_home: AgentHome, ledger: Ledger, out_path: Path, capsule_passphrase: str, *,
                   for_sale: bool = True) -> dict:
    """``for_sale=True`` (default, the safe one) leaves the agent key and the private action records behind:
    a buyer needs neither, and must not be able to act as the agent before the transfer lands.
    ``for_sale=False`` moves *your own* agent to another machine, key and history included."""
    report = verify(agent_home, ledger)
    if not report["ok"]:
        raise SealError("refusing to export: files do not match the sealed state (run `singular verify`)")
    if report["lease"]:
        raise LeaseError("stop the agent (release its lease) before exporting it")
    paths = [e["p"] for e in agent_home.scan_core() + agent_home.scan_memory()]
    meta = {"agent_id": agent_home.agent_id, "chain_id": agent_home.identity["chain_id"],
            "core_root": report["core"]["root"], "memory_root": report["memory"]["root"],
            "core_seq": report["core"]["seq"], "memory_seq": report["memory"]["seq"]}
    if report["actions"]["count"] != ActionLog(agent_home.sdir).count:
        raise SealError("local action log and ledger disagree; anchor or restore before exporting")
    base = agent_home.sdir / "actions.base.json"
    previous = base.read_text(encoding="utf-8") if base.exists() else None
    if for_sale:
        base.write_text(json.dumps({"count": report["actions"]["count"], "head": report["actions"]["head"]}), encoding="utf-8")
    try:
        return capsule.pack(agent_home.home, paths, out_path, capsule_passphrase, {**meta, "for_sale": for_sale}, for_sale=for_sale)
    finally:
        if for_sale:
            base.write_text(previous, encoding="utf-8") if previous is not None else base.unlink()


def import_capsule(capsule_path: Path, target: Path, capsule_passphrase: str, ledger: Ledger) -> AgentHome:
    """Unpack, then trust nothing: the unpacked files must hash to what the ledger sealed."""
    capsule.unpack(capsule_path, target, capsule_passphrase)
    agent_home = AgentHome(target)
    try:
        report = verify(agent_home, ledger)
        if not (report["core"]["ok"] and report["memory"]["ok"]):
            raise SealError("capsule contents do not match the ledger's sealed state; it is stale or was altered")
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)
        raise
    agent_home.snapshot("core", agent_home.scan_core())
    agent_home.snapshot("memory", agent_home.scan_memory())
    return agent_home


def transfer_request(agent_home: AgentHome, ledger: Ledger, new_owner_key: SigningKey, new_passphrase: str) -> dict:
    """Buyer side. Makes a brand-new agent key (kept beside the old keystore until the transfer lands)
    and signs the two buyer roles. The returned document goes to the seller for the final signature."""
    report = verify(agent_home, ledger)
    if not report["ok"]:
        raise SealError("refusing to buy: the files in hand are not the sealed agent")
    record = require_agent(ledger, agent_home.agent_id)
    new_agent_key = SigningKey.generate()
    save_keystore(agent_home.sdir / "agent.keystore.pending.json", wrap_key(new_agent_key, new_passphrase, label="agent"))
    chain_id = agent_home.identity["chain_id"]
    transaction = T.build(T.TRANSFER, record["id"], record["nonce"] + 1, {
        "new_owner_pub": new_owner_key.public_hex, "new_agent_pub": new_agent_key.public_hex,
        "new_enc_pub": new_agent_key.enc_public_hex, "root": report["core"]["root"], "memory_root": report["memory"]["root"]})
    T.sign(transaction, chain_id, "new_owner", new_owner_key)
    T.sign(transaction, chain_id, "new_agent", new_agent_key)
    return {"kind": "singular-transfer-request", "chain_id": chain_id, "tx": transaction}


def transfer_approve(request: dict, ledger: Ledger, owner_key: SigningKey) -> dict:
    """Seller side: the last signature. After this lands, the seller's copy can never run again."""
    if request.get("kind") != "singular-transfer-request":
        raise SingularError("not a transfer request")
    check_chain(ledger, request["chain_id"])
    transaction = T.check_shape(request["tx"])
    if transaction["type"] != T.TRANSFER:
        raise SingularError("transfer request carries the wrong transaction type")
    T.sign(transaction, request["chain_id"], "owner", owner_key)
    return ledger.submit(transaction)


def transfer_finalize(agent_home: AgentHome, ledger: Ledger) -> None:
    """Buyer side, after approval: swap in the new keystore once the ledger names the new key."""
    pending = agent_home.sdir / "agent.keystore.pending.json"
    if not pending.exists():
        raise SingularError("no pending transfer in this agent home")
    record = require_agent(ledger, agent_home.agent_id)
    if record["agent_pub"] != load_keystore(pending)["pub"]:
        raise SingularError("the ledger does not show this transfer yet")
    os.replace(pending, agent_home.keystore_path)
