"""``singular unlock``: the owner edits a stopped agent from somewhere else (Singular Cloud's unlocker).

The owner key never comes here. Whoever holds it (a browser, another machine) reads the agent with ``describe``,
decides on edits, computes the roots those edits produce, and signs the seals itself. ``apply`` then writes the
edits, re-scans, and submits the signed seals only if they name exactly the roots the edited files now have.
Anything else, and every file is put back as it was.

Both commands read one JSON object on stdin and print one on stdout, so a runner can call them in a one-shot
container on the agent's volume (``SINGULAR_HOME``, ``SINGULAR_LEDGER``) without any network port.

    describe   {}                                         -> agent id, sealed entries, text of editable files
    apply      {"edits": [...], "txs": [...]}             -> receipts   (stdin, or ``--input FILE``)

An edit is ``{"p": "skills/x/SKILL.md", "text": "..."}`` (create or replace, UTF-8) or ``{"p": ..., "delete": true}``.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path, PurePosixPath

from . import agent as A, tree
from .errors import LedgerRejected, SealError, SingularError
from .ledger import tx as T
from .ledger.client import Ledger

MAX_TEXT = 256 * 1024          # files larger than this are listed but not handed out for editing
MAX_EDITS = 64
MAX_EDIT_BYTES = 1 << 20
MAX_TOTAL_BYTES = 4 << 20


def _sealed_set(agent_home: A.AgentHome, rel: PurePosixPath) -> str | None:
    ident = agent_home.identity
    for kind in ("core", "memory"):
        for top in ident[kind]:
            top_path = PurePosixPath(top)
            if rel == top_path or top_path in rel.parents:
                return kind
    return None


def check_path(agent_home: A.AgentHome, raw: object) -> tuple[PurePosixPath, str]:
    """A path the owner may edit: relative, plain, inside a sealed set, never under ``.singular/``, never a secret."""
    if not isinstance(raw, str) or not raw or len(raw) > 512 or "\\" in raw or "\0" in raw or raw != raw.strip():
        raise SingularError(f"bad path {raw!r}")
    rel = PurePosixPath(raw)
    if rel.is_absolute() or any(part in ("", ".", "..") for part in raw.split("/")):
        raise SingularError(f"path must be relative and plain: {raw!r}")
    if rel.parts[0] == tree.SINGULAR_DIR or any(part in tree.SECRET_NAMES for part in rel.parts):
        raise SingularError(f"{raw} is not agent content")
    kind = _sealed_set(agent_home, rel)
    if kind is None:
        raise SingularError(f"{raw} is not under a sealed path ({', '.join(agent_home.identity['core'] + agent_home.identity['memory'])})")
    return rel, kind


def _walk_no_links(home: Path, rel: PurePosixPath, *, create: bool) -> Path:
    """Every existing component below home must be a real directory, so a planted symlink cannot redirect a write."""
    here = home
    for part in rel.parts[:-1]:
        here = here / part
        try:
            st = os.lstat(here)
        except FileNotFoundError:
            if not create:
                raise SingularError(f"{rel} does not exist") from None
            os.mkdir(here, 0o755)
            continue
        if not stat.S_ISDIR(st.st_mode):
            raise SingularError(f"{rel}: {here.relative_to(home)} is not a plain directory")
    target = here / rel.parts[-1]
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return target
    if not stat.S_ISREG(st.st_mode):
        raise SingularError(f"{rel} is not a regular file (links and directories are not edited here)")
    return target


def _read(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.unlock.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def describe(agent_home: A.AgentHome, ledger: Ledger) -> dict:
    report = A.verify(agent_home, ledger)
    core, memory = agent_home.scan_core(), agent_home.scan_memory()
    texts: dict[str, str] = {}
    for entry in core + memory:
        if "h" not in entry or entry["s"] > MAX_TEXT:
            continue
        data = _read(agent_home.home / entry["p"])
        try:
            texts[entry["p"]] = data.decode("utf-8") if data is not None else None
        except UnicodeDecodeError:
            continue
    return {"agent_id": agent_home.agent_id, "chain_id": agent_home.identity["chain_id"], "bank_id": agent_home.bank_id,
            "sealed_paths": {"core": agent_home.identity["core"], "memory": agent_home.identity["memory"]},
            "ok": report["ok"], "lease": report["lease"],
            "core": {"root": tree.root_of(core), "entries": core},
            "memory": {"root": tree.root_of(memory), "entries": memory},
            "texts": {p: t for p, t in texts.items() if t is not None}}


def _parse_edits(agent_home: A.AgentHome, edits: object) -> list[tuple[PurePosixPath, str, bytes | None]]:
    if not isinstance(edits, list) or not 0 < len(edits) <= MAX_EDITS:
        raise SingularError(f"between 1 and {MAX_EDITS} edits")
    out, seen, total = [], set(), 0
    for edit in edits:
        if not isinstance(edit, dict) or set(edit) not in ({"p", "text"}, {"p", "delete"}):
            raise SingularError("an edit is {p, text} or {p, delete: true}")
        rel, kind = check_path(agent_home, edit["p"])
        if str(rel) in seen:
            raise SingularError(f"{rel} is edited twice")
        seen.add(str(rel))
        if "delete" in edit:
            if edit["delete"] is not True:
                raise SingularError("delete must be true")
            out.append((rel, kind, None))
            continue
        if not isinstance(edit["text"], str):
            raise SingularError("text must be a string")
        data = edit["text"].encode("utf-8")
        total += len(data)
        if len(data) > MAX_EDIT_BYTES or total > MAX_TOTAL_BYTES:
            raise SingularError("edit too large")
        out.append((rel, kind, data))
    return out


def _classify(agent_home: A.AgentHome, txs: object, record: dict, bank: dict) -> dict[str, dict]:
    """Exactly the owner seals this agent can take: at most one OWNER_ATTEST and one owner BANK_SEAL."""
    if not isinstance(txs, list) or not 0 < len(txs) <= 2:
        raise SingularError("one or two signed transactions")
    found: dict[str, dict] = {}
    for raw in txs:
        transaction = T.check_shape(raw)
        if transaction["type"] == T.OWNER_ATTEST and transaction["subject"] == record["id"]:
            kind = "core"
        elif transaction["type"] == T.BANK_SEAL and transaction["subject"] == bank["id"] \
                and transaction["body"].get("writer") == "owner":
            kind = "memory"
        else:
            raise SingularError("only an OWNER_ATTEST for this agent and an owner BANK_SEAL for its memory are applied here")
        if kind in found:
            raise SingularError(f"two {kind} seals")
        found[kind] = transaction
    return found


def apply(agent_home: A.AgentHome, ledger: Ledger, request: dict) -> dict:
    """Write the owner's edits, then submit the owner's signed seals if (and only if) they match the result."""
    record = A.require_agent(ledger, agent_home.agent_id)
    bank = A.require_bank(ledger, record["memory_bank"])
    if record["lease"] and record["lease"]["expires"] > time.time() * 1000:
        # the ledger refuses an owner seal under a live lease anyway; failing here keeps the files untouched
        raise SingularError("the agent is running; stop it first")
    report = A.verify(agent_home, ledger)
    if not (report["core"]["ok"] and report["memory"]["ok"]):
        raise SealError("the files on this host do not match the ledger; refusing to edit on top of them")
    edits = _parse_edits(agent_home, request.get("edits"))
    txs = _classify(agent_home, request.get("txs"), record, bank)

    home = agent_home.home
    backup: list[tuple[Path, bytes | None]] = []

    def put_back(kinds: set[str]) -> None:
        for (path, before), (_, kind, _) in zip(reversed(backup), reversed(edits[:len(backup)])):
            if kind not in kinds:
                continue
            if before is None:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
            else:
                _write(path, before)

    try:
        for rel, _kind, data in edits:
            path = _walk_no_links(home, rel, create=data is not None)
            backup.append((path, _read(path)))
            if data is None:
                if backup[-1][1] is None:
                    raise SingularError(f"{rel} does not exist")
                os.unlink(path)
            else:
                _write(path, data)
        core, memory = agent_home.scan_core(), agent_home.scan_memory()
        present = {e["p"] for e in core + memory}
        for rel, _kind, data in edits:
            if (data is not None) != (str(rel) in present):
                raise SingularError(f"{rel} is not sealed (an excluded name, or byte-identical to a skill Hermes ships)")
        roots = {"core": tree.summarize(core), "memory": tree.summarize(memory)}
        changed = {"core": roots["core"]["root"] != record["seal"]["root"],
                   "memory": roots["memory"]["root"] != bank["seal"]["root"]}
        for kind in ("core", "memory"):
            if changed[kind] != (kind in txs):
                raise SingularError(f"the edits {'change' if changed[kind] else 'do not change'} the {kind}, "
                                    f"but a {kind} seal was {'not ' if changed[kind] else ''}signed")
        expected = {"core": A.owner_attest_body(record["seal"], roots["core"], ""),
                    "memory": A.owner_memory_body(bank["seal"], roots["memory"])}
        for kind, transaction in txs.items():
            body = {k: v for k, v in transaction["body"].items() if k != "reason"}
            want = {k: v for k, v in expected[kind].items() if k != "reason"}
            if body != want:
                raise SingularError(f"the signed {kind} seal does not name what the edited files hash to; nothing was changed")
    except BaseException:
        put_back({"core", "memory"})
        raise

    receipts: dict[str, dict] = {}
    try:
        if "core" in txs:
            receipts["core"] = ledger.submit(txs["core"])
    except BaseException:
        put_back({"core", "memory"})
        raise
    agent_home.snapshot("core", core)
    if "memory" in txs:
        try:
            receipts["memory"] = ledger.submit(txs["memory"])
        except LedgerRejected as exc:
            put_back({"memory"})  # the core seal already landed and stands on its own
            return {"receipts": receipts, "memory_refused": {"error": exc.code, "message": exc.message}}
        agent_home.snapshot("memory", memory)
    return {"receipts": receipts}


def main(command: str, home: str, ledger: Ledger, input_path: str | None = None) -> int:
    agent_home = A.AgentHome(home)
    if not agent_home.is_singular:
        raise SingularError(f"{home} holds no Singular agent")
    raw = "{}"
    if command == "apply":
        source = open(input_path, "rb") if input_path else sys.stdin.buffer  # noqa: SIM115
        with source:
            raw = source.read(8 << 20).decode("utf-8")
    try:
        request = json.loads(raw or "{}")
    except ValueError:
        raise SingularError("stdin is not JSON") from None
    if not isinstance(request, dict):
        raise SingularError("stdin must be a JSON object")
    result = describe(agent_home, ledger) if command == "describe" else apply(agent_home, ledger, request)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


__all__ = ["describe", "apply", "check_path", "main"]
