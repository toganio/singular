"""External memory banks: shared, encrypted, singular memory that lives outside any one agent.

A bank is three things:

* a **ledger record** - its id, owner, grants, key generation and the root of its latest state;
* a **store** - dumb storage full of ciphertext (a folder today; any blob store tomorrow). Whoever
  hosts it can neither read it nor change it unnoticed, because readers check what they decrypt
  against the ledger's root;
* **mounts** - each granted agent's decrypted working copy.

Keys: the bank has a data key per *key generation*. The owner wraps the current data key to each
granted agent's public encryption key and publishes the wrap in the grant. An agent unlocked with
its own passphrase can therefore open its internal memory *and* every bank it was granted, with no
shared bank password to leak or rotate by hand. Revoking an agent re-keys the bank; older data keys
ride inside the (newly encrypted) manifest so current members can still read history.

Concurrency: a bank has one sequence. Writers race optimistically; the loser pulls, three-way merges
and retries. Banks are meant to be written as append-only entries (``entries/<agent>/<time>.md``), which
never conflict.
"""

from __future__ import annotations

import json
import os
import random
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import tree
from .agent import require_agent, require_bank, submit
from .canonical import canonical, sha256_hex
from .errors import CryptoError, LedgerRejected, SealError, SingularError
from .keys import SigningKey, derive_bank_id, new_salt, seal_to
from .ledger import tx as T
from .ledger.client import Ledger
from .ledger.state import OWNER_WRITER

_RETRYABLE = {"NONCE_CONFLICT", "STALE_STATE", "STALE_GRANT"}
MAX_PUSH_ATTEMPTS = 40


class DirStore:
    """Ciphertext storage in a folder (local disk, NFS, a mounted bucket). Writes are atomic."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _resolve(self, name: str) -> Path:
        parts = name.split("/")
        if not all(part and part not in (".", "..") and "\\" not in part for part in parts):
            raise SingularError(f"bad store object name {name!r}")
        return self.path.joinpath(*parts)

    def get(self, name: str) -> bytes | None:
        try:
            return self._resolve(name).read_bytes()
        except FileNotFoundError:
            return None

    def exists(self, name: str) -> bool:
        return self._resolve(name).exists()

    def put(self, name: str, data: bytes) -> None:
        dest = self._resolve(name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(f"{dest.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
        tmp.write_bytes(data)
        os.replace(tmp, dest)


def _ctx(bank_id: str, recipient: str, key_gen: int) -> bytes:
    return canonical({"bank": bank_id, "to": recipient, "gen": key_gen})


def _encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def _decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag:
        raise CryptoError("bank data failed authentication (wrong key, or the store was tampered with)") from None


def _manifest_name(root: str, key_gen: int) -> str:
    return f"manifests/{root}.g{key_gen}.bin"


def _check_manifest(manifest: object, bank_id: str) -> dict:
    """A manifest is written by *another member* of the bank. Treat it as hostile input: a crafted path
    here would otherwise become a file write on every other member's machine."""
    if not isinstance(manifest, dict) or manifest.get("bank") != bank_id or not isinstance(manifest.get("entries"), list):
        raise SealError("bank manifest is malformed")
    for entry in manifest["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"p", "h", "s", "b", "g"}:
            raise SealError("bank manifest entry is malformed")
        rel = entry["p"]
        parts = rel.split("/") if isinstance(rel, str) else []
        if not parts or rel.startswith("/") or "\\" in rel or "\x00" in rel or len(rel) > 1024 or \
                any(part in ("", ".", "..") or part in tree.SECRET_NAMES or part == tree.SINGULAR_DIR for part in parts):
            raise SealError(f"bank manifest carries an unsafe path: {rel!r}")
        if not (T.is_hex(entry["h"], 64) and T.is_hex(entry["b"], 64)) or not isinstance(entry["s"], int) \
                or isinstance(entry["s"], bool) or entry["s"] < 0 or not isinstance(entry["g"], int):
            raise SealError("bank manifest entry is malformed")
    if not isinstance(manifest.get("old_keys", {}), dict):
        raise SealError("bank manifest is malformed")
    return manifest


def _public_entries(entries: list[dict]) -> list[dict]:
    return [{"p": e["p"], "h": e["h"], "s": e["s"]} for e in entries]


# -- owner side --------------------------------------------------------------------------------

class BankOwner:
    """Administration with the bank's *own* key: create, grant, revoke (re-key), hand over."""

    def __init__(self, store: DirStore, ledger: Ledger, owner_key: SigningKey, bank_id: str | None = None):
        self.store, self.ledger, self.key = store, ledger, owner_key
        self.chain_id = ledger.info()["chain_id"]
        self.bank_id = bank_id or json.loads(store.get("bank.json") or b"{}").get("bank_id")

    @classmethod
    def create(cls, store: DirStore, ledger: Ledger, owner_key: SigningKey, name: str, *,
               allow_owner_write: bool = True) -> "BankOwner":
        if store.exists("bank.json"):
            raise SingularError("this store already holds a bank")
        self = cls(store, ledger, owner_key, bank_id="-")
        salt = new_salt()
        self.bank_id = derive_bank_id(owner_key.public_hex, salt)
        dek = os.urandom(32)
        empty = tree.summarize([])
        self._write_manifest(empty["root"], 1, {1: dek}, [], seq=0)
        self._save_owner_keys({1: dek})
        store.put("bank.json", json.dumps({"bank_id": self.bank_id, "chain_id": self.chain_id, "name": name}).encode())
        submit(ledger, self.chain_id, T.BANK_CREATE, self.bank_id, 1, {
            "owner_pub": owner_key.public_hex, "salt": salt, "name": name,
            "policy": {"allow_owner_write": allow_owner_write}, "root": empty["root"], "files": 0, "bytes": 0},
            {"owner": owner_key})
        return self

    # data keys, wrapped to the owner's own encryption key and kept beside the ciphertext
    def _save_owner_keys(self, keys: dict[int, bytes], recipient: SigningKey | None = None, enc_pub: str | None = None) -> None:
        enc_pub = enc_pub or self.key.enc_public_hex
        wrapped = {str(gen): seal_to(enc_pub, dek, context=_ctx(self.bank_id, "owner", gen)) for gen, dek in keys.items()}
        self.store.put("owner.keys.json", json.dumps(wrapped).encode())

    def _owner_keys(self) -> dict[int, bytes]:
        raw = self.store.get("owner.keys.json")
        if raw is None:
            raise SingularError("store has no owner key file")
        return {int(gen): self.key.open_sealed(box, context=_ctx(self.bank_id, "owner", int(gen)))
                for gen, box in json.loads(raw).items()}

    def _write_manifest(self, root: str, key_gen: int, keys: dict[int, bytes], entries: list[dict], seq: int) -> None:
        manifest = {"v": 1, "bank": self.bank_id, "seq": seq, "key_gen": key_gen, "entries": entries,
                    "old_keys": {str(g): k.hex() for g, k in keys.items() if g != key_gen}}
        self.store.put(_manifest_name(root, key_gen),
                       _encrypt(keys[key_gen], canonical(manifest), b"singular-manifest:" + self.bank_id.encode()))

    def _bank(self) -> dict:
        return require_bank(self.ledger, self.bank_id)

    def grant(self, agent_id: str, rights: str = "r", expires_ms: int = 0) -> dict:
        bank, agent = self._bank(), require_agent(self.ledger, agent_id)
        gen = bank["key_gen"]
        wrapped = seal_to(agent["enc_pub"], self._owner_keys()[gen], context=_ctx(self.bank_id, agent_id, gen))
        return submit(self.ledger, self.chain_id, T.BANK_GRANT, self.bank_id, bank["nonce"] + 1,
                      {"agent": agent_id, "rights": rights, "key_gen": gen, "wrapped_key": wrapped,
                       "expires": expires_ms}, {"owner": self.key})

    def revoke(self, agent_id: str, *, rekey: bool = True) -> dict:
        """Drop the grant and (by default) re-key, so the revoked agent cannot read anything written later."""
        bank = self._bank()
        receipt = submit(self.ledger, self.chain_id, T.BANK_REVOKE, self.bank_id, bank["nonce"] + 1,
                         {"agent": agent_id}, {"owner": self.key})
        if rekey:
            self.rekey()
        return receipt

    def rekey(self) -> dict:
        bank, keys = self._bank(), self._owner_keys()
        old_gen, new_gen = bank["key_gen"], bank["key_gen"] + 1
        raw = self.store.get(_manifest_name(bank["seal"]["root"], old_gen))
        if raw is None:
            raise SealError("store is missing the manifest for the bank's current state")
        manifest = json.loads(_decrypt(keys[old_gen], raw, b"singular-manifest:" + self.bank_id.encode()))
        keys[new_gen] = os.urandom(32)
        self._write_manifest(bank["seal"]["root"], new_gen, keys, manifest["entries"], manifest["seq"])
        self._save_owner_keys(keys)
        wrapped = {}
        for agent_id in bank["grants"]:
            agent = require_agent(self.ledger, agent_id)
            wrapped[agent_id] = seal_to(agent["enc_pub"], keys[new_gen], context=_ctx(self.bank_id, agent_id, new_gen))
        return submit(self.ledger, self.chain_id, T.BANK_REKEY, self.bank_id, bank["nonce"] + 1,
                      {"key_gen": new_gen, "wrapped_keys": wrapped}, {"owner": self.key})

    def mount(self, directory: str | Path) -> "BankMount":
        return BankMount(self.store, self.ledger, self.bank_id, directory, owner_key=self.key)

    def transfer_approve(self, request: dict) -> dict:
        """Hand the bank to a new owner who asked with :func:`bank_transfer_request`. Re-key afterwards
        is the *new* owner's move: the old owner has seen every data key up to now."""
        if request.get("kind") != "singular-bank-transfer-request" or request.get("bank_id") != self.bank_id:
            raise SingularError("not a transfer request for this bank")
        keys = self._owner_keys()
        transaction = T.check_shape(request["tx"])
        T.sign(transaction, self.chain_id, "owner", self.key)
        receipt = self.ledger.submit(transaction)
        self._save_owner_keys(keys, enc_pub=request["enc_pub"])
        return receipt


def bank_transfer_request(ledger: Ledger, bank_id: str, new_owner_key: SigningKey) -> dict:
    bank = require_bank(ledger, bank_id)
    chain_id = ledger.info()["chain_id"]
    transaction = T.build(T.BANK_TRANSFER, bank_id, bank["nonce"] + 1, {"new_owner_pub": new_owner_key.public_hex})
    T.sign(transaction, chain_id, "new_owner", new_owner_key)
    return {"kind": "singular-bank-transfer-request", "bank_id": bank_id, "chain_id": chain_id,
            "enc_pub": new_owner_key.enc_public_hex, "tx": transaction}


# -- which banks an agent home is attached to ---------------------------------------------------
# Local operator configuration (.singular/banks/attached.json). It is not sealed and never travels in
# a capsule: where a bank's ciphertext lives is a fact about this machine, and grants die on sale anyway.

def _attached_path(agent_home) -> Path:
    return agent_home.sdir / "banks" / "attached.json"


def attached_banks(agent_home) -> list[dict]:
    try:
        data = json.loads(_attached_path(agent_home).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [b for b in data if isinstance(b, dict) and {"bank_id", "store", "name"} <= set(b)]


def attach_bank(agent_home, ledger: Ledger, bank_id: str, store: str | Path, name: str | None = None) -> dict:
    record = require_bank(ledger, bank_id)
    if record["mode"] != "external":
        raise SingularError("internal memory is already part of the agent; attach external banks only")
    public = json.loads(DirStore(store).get("bank.json") or b"{}")
    if public.get("bank_id") != bank_id:
        raise SingularError(f"{store} does not hold bank {bank_id}")
    entry = {"bank_id": bank_id, "store": str(Path(store).resolve()), "name": name or record["name"]}
    banks = [b for b in attached_banks(agent_home) if b["bank_id"] != bank_id and b["name"] != entry["name"]] + [entry]
    path = _attached_path(agent_home)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps(banks, indent=2), encoding="utf-8")
    return entry


def detach_bank(agent_home, bank: str) -> bool:
    banks = attached_banks(agent_home)
    kept = [b for b in banks if bank not in (b["bank_id"], b["name"])]
    if len(kept) == len(banks):
        return False
    _attached_path(agent_home).write_text(json.dumps(kept, indent=2), encoding="utf-8")
    return True


# -- member side -------------------------------------------------------------------------------

class BankMount:
    """A decrypted working copy of a bank, for one reader/writer.

    Give it either ``agent_id`` + ``agent_key`` (a granted agent) or ``owner_key`` (the bank owner).
    """

    def __init__(self, store: DirStore, ledger: Ledger, bank_id: str, directory: str | Path, *,
                 agent_id: str | None = None, agent_key: SigningKey | None = None, owner_key: SigningKey | None = None):
        self.store, self.ledger, self.bank_id = store, ledger, bank_id
        self.dir = Path(directory)
        self.files = self.dir / "files"
        self.agent_id, self._agent_key, self._owner_key = agent_id, agent_key, owner_key
        self.chain_id = ledger.info()["chain_id"]
        self._aad = b"singular-manifest:" + bank_id.encode()

    # -- keys ------------------------------------------------------------------------------

    def _current_key(self, bank: dict) -> bytes:
        gen = bank["key_gen"]
        if self._owner_key is not None:
            raw = self.store.get("owner.keys.json")
            boxes = json.loads(raw) if raw else {}
            if str(gen) not in boxes:
                raise CryptoError("owner key file does not hold the bank's current data key")
            return self._owner_key.open_sealed(boxes[str(gen)], context=_ctx(self.bank_id, "owner", gen))
        grant = bank["grants"].get(self.agent_id)
        agent = require_agent(self.ledger, self.agent_id)
        now = int(time.time() * 1000)
        if not grant or grant["epoch"] != agent["epoch"] or grant["key_gen"] != gen or \
                (grant["expires"] and now >= grant["expires"]):
            raise CryptoError(f"agent {self.agent_id} holds no valid grant on bank {self.bank_id}")
        return self._agent_key.open_sealed(grant["wrapped_key"], context=_ctx(self.bank_id, self.agent_id, gen))

    def _load_manifest(self, bank: dict) -> tuple[dict, dict[int, bytes]]:
        gen, root = bank["key_gen"], bank["seal"]["root"]
        raw = self.store.get(_manifest_name(root, gen))
        if raw is None:
            raise SealError("store is missing the manifest for the bank's sealed state")
        key = self._current_key(bank)
        try:
            manifest = _check_manifest(json.loads(_decrypt(key, raw, self._aad)), self.bank_id)
        except ValueError:
            raise SealError("bank manifest is not JSON") from None
        if tree.root_of(_public_entries(manifest["entries"])) != root:
            raise SealError("bank store does not match the ledger's sealed root")
        keys = {int(g): bytes.fromhex(k) for g, k in manifest.get("old_keys", {}).items()}
        keys[gen] = key
        return manifest, keys

    # -- state -----------------------------------------------------------------------------

    def _base(self) -> list[dict]:
        try:
            return json.loads((self.dir / "mount.json").read_text(encoding="utf-8"))["entries"]
        except (OSError, ValueError, KeyError):
            return []

    def _save_base(self, bank: dict, entries: list[dict]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)  # the working copy is plaintext
        tmp = self.dir / "mount.json.tmp"
        tmp.write_text(json.dumps({"bank_id": self.bank_id, "seq": bank["seal"]["seq"], "root": bank["seal"]["root"],
                                   "entries": entries}), encoding="utf-8")
        os.replace(tmp, self.dir / "mount.json")

    def _scan(self) -> list[dict]:
        self.files.mkdir(parents=True, exist_ok=True)
        entries = tree.scan(self.files, ["."])
        if any("l" in e for e in entries):
            raise SealError("memory banks do not hold symlinks")
        return entries

    def _fetch(self, entry: dict, keys: dict[int, bytes]) -> bytes:
        raw = self.store.get("blobs/" + entry["b"])
        if raw is None or sha256_hex(raw) != entry["b"]:
            raise SealError(f"bank store lost or altered the data for {entry['p']}")
        if entry["g"] not in keys:
            raise SealError(f"no data key for generation {entry['g']} ({entry['p']})")
        plain = _decrypt(keys[entry["g"]], raw, b"singular-blob:" + self.bank_id.encode() + bytes.fromhex(entry["h"]))
        if sha256_hex(plain) != entry["h"]:
            raise SealError(f"bank data for {entry['p']} does not match its sealed hash")
        return plain

    def _write_file(self, rel: str, data: bytes) -> None:
        dest = self.files / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, dest)

    # -- operations ------------------------------------------------------------------------

    def pull(self) -> dict:
        """Bring the working copy to the ledger's latest sealed state, keeping local unsealed edits.
        Three-way merge per path; a true both-sides edit keeps the remote version and saves ours
        beside it as ``<path>.conflict-<who>``."""
        return self._pull()[0]

    def _pull(self) -> tuple[dict, dict, dict, dict[int, bytes]]:
        bank = require_bank(self.ledger, self.bank_id)
        manifest, keys = self._load_manifest(bank)
        base = {e["p"]: e["h"] for e in self._base()}
        local = {e["p"]: e["h"] for e in self._scan()}
        remote = {e["p"]: e for e in manifest["entries"]}
        updated = conflicts = removed = 0
        who = (self.agent_id or "owner")[:12]
        for path, entry in remote.items():
            mine, was = local.get(path), base.get(path)
            if mine == entry["h"]:
                continue
            if mine is not None and mine != was and entry["h"] != was:
                self._write_file(f"{path}.conflict-{who}", (self.files / path).read_bytes())
                conflicts += 1
            elif mine != was and entry["h"] == was:
                continue  # only we changed it (or deleted it): our edit stands
            self._write_file(path, self._fetch(entry, keys))
            updated += 1
        for path, was in base.items():
            if path not in remote and local.get(path) == was:
                (self.files / path).unlink()
                removed += 1
        self._save_base(bank, _public_entries(manifest["entries"]))
        return ({"seq": bank["seal"]["seq"], "updated": updated, "removed": removed, "conflicts": conflicts},
                bank, manifest, keys)

    def push(self, signers: dict[str, SigningKey] | None = None) -> dict | None:
        """Seal local changes into the bank. Retries through races with other writers."""
        if signers is None:
            if self._owner_key is None:
                raise SingularError("an agent pushes with its live-lease signers (guard.signers())")
            signers = {"owner": self._owner_key}
        writer = OWNER_WRITER if "owner" in signers else self.agent_id
        last_error: LedgerRejected | None = None
        for attempt in range(MAX_PUSH_ATTEMPTS):
            if attempt:
                # Lost a race. Someone always wins each round, so the bank keeps moving; random backoff
                # keeps any single writer from losing forever.
                time.sleep(random.uniform(0, min(0.5, 0.01 * 2 ** min(attempt, 6))))
            # Merge and seal against ONE snapshot of the bank. Re-reading the ledger here would let a
            # faster writer slip in between the merge and the seal, and our seal would silently drop
            # their entry while still naming their root as prev_root. With one snapshot, that race
            # ends in STALE_STATE and a retry instead.
            _, bank, manifest, keys = self._pull()
            gen = bank["key_gen"]
            known = {e["h"]: e for e in manifest["entries"]}
            entries = []
            for entry in self._scan():
                if entry["h"] in known:
                    entries.append({**entry, "b": known[entry["h"]]["b"], "g": known[entry["h"]]["g"]})
                    continue
                sealed = _encrypt(keys[gen], (self.files / entry["p"]).read_bytes(),
                                  b"singular-blob:" + self.bank_id.encode() + bytes.fromhex(entry["h"]))
                blob_id = sha256_hex(sealed)
                self.store.put("blobs/" + blob_id, sealed)
                entries.append({**entry, "b": blob_id, "g": gen})
            summary = tree.summarize(_public_entries(entries))
            if summary["root"] == bank["seal"]["root"]:
                return None
            seq = bank["seal"]["seq"] + 1
            new_manifest = {"v": 1, "bank": self.bank_id, "seq": seq, "key_gen": gen, "entries": entries,
                            "old_keys": {str(g): k.hex() for g, k in keys.items() if g != gen}}
            self.store.put(_manifest_name(summary["root"], gen), _encrypt(keys[gen], canonical(new_manifest), self._aad))
            try:
                receipt = submit(self.ledger, self.chain_id, T.BANK_SEAL, self.bank_id, bank["nonce"] + 1, {
                    "writer": writer, "key_gen": gen, "seq": seq, "prev_root": bank["seal"]["root"],
                    "root": summary["root"], "files": summary["files"], "bytes": summary["bytes"]}, signers)
            except LedgerRejected as exc:
                if exc.code in _RETRYABLE:
                    last_error = exc
                    continue
                raise
            self._save_base(require_bank(self.ledger, self.bank_id), _public_entries(entries))
            return receipt
        raise SingularError(f"could not push to the bank after {MAX_PUSH_ATTEMPTS} attempts: {last_error}")

    def append_entry(self, text: str, *, title: str = "") -> str:
        """The conflict-free way to write: one new file per entry, namespaced by writer."""
        who = self.agent_id or "owner"
        rel = f"entries/{who}/{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{time.monotonic_ns() % 10**9:09d}.md"
        heading = f"# {title}\n\n" if title else ""
        self._write_file(rel, (heading + text.rstrip() + "\n").encode("utf-8"))
        return rel

    def list(self) -> list[dict]:
        return _public_entries(self._scan())

    def read(self, rel: str) -> str:
        target = (self.files / rel).resolve()
        if self.files.resolve() not in target.parents:
            raise SingularError("path escapes the bank")
        return target.read_text(encoding="utf-8")
