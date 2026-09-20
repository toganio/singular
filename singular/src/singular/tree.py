"""Turning a folder into one hash: the ``state_root`` that seals are made of.

An agent home is split in two sealed sets:

* **core**   - who the agent is: persona, profile, skills, schedules.
* **memory** - what it has learned: its internal memory bank.

Each set hashes to its own root, so a large memory never slows down sealing the core, and the
memory can be reasoned about (and in the external-bank case, shared) on its own.

Deliberately *not* sealed: secrets (API keys belong to whoever operates the agent, not to the
agent), operator settings (``config.yaml``: a buyer must be able to point the agent at their own
model provider), caches, logs and session databases.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath

from .canonical import hash_obj, merkle_root
from .errors import SealError

SINGULAR_DIR = ".singular"

# (cron/jobs.json is not here: the scheduler rewrites it on every tick, outside any agent action.)
DEFAULT_CORE = ["SOUL.md", "profile.yaml", "skills"]
DEFAULT_MEMORY = ["memories"]

# Never sealed, never exported, whatever the include lists say.
# (Hermes also counts its session database as secret material; tests/test_hermes_contract.py keeps this list honest.)
SECRET_NAMES = frozenset({".env", ".env.local", "auth.json", "auth.lock", "vault.key", "vault.json.enc", "state.db"})
# Files that the *installed agent software* ships and copies into the home are product content, not identity.
# A baseline maps a sealed prefix to the directory the software ships; see ``scan``.
HERMES_SKILLS_BASELINE = {"prefix": "skills", "source": "hermes:bundled_skills"}

DEFAULT_EXCLUDE = [".bundled_manifest", ".bundled_manifest_*", "__pycache__", "*.pyc", ".DS_Store", "*.tmp", "*.lock", "*.db", "*.db-wal", "*.db-shm", "*-journal",
                   ".usage.json", ".usage_*", ".hub", ".git"]


def _excluded(rel: PurePosixPath, patterns: list[str]) -> bool:
    for part in rel.parts:
        if part in SECRET_NAMES or part == SINGULAR_DIR:
            return True
        if any(fnmatch.fnmatchcase(part, pattern) for pattern in patterns):
            return True
    return False


def check_link(rel: PurePosixPath, target: str) -> None:
    """A sealed symlink must stay inside the agent home. A link to ``/etc/...`` or ``../../x`` would let
    content that is *not* under the seal steer the agent, and would read the buyer's own files after a sale."""
    if os.path.isabs(target) or "\\" in target:
        raise SealError(f"symlink {rel} points outside the agent home ({target}); replace it with a real file")
    depth = len(rel.parts) - 1
    for part in PurePosixPath(target).parts:
        depth += -1 if part == ".." else (0 if part == "." else 1)
        if depth < 0:
            raise SealError(f"symlink {rel} points outside the agent home ({target}); replace it with a real file")


def file_sha256(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


class HashCache:
    """Skips re-reading unchanged files during *runtime* reseals of a large memory.

    Keyed on (size, mtime_ns, ctime_ns, inode). ``ctime`` is the part that matters: ``utime()`` can forge
    mtime after an in-place edit, but nothing short of changing the system clock can set ctime back. It is
    still only a performance hint, so every trust decision (startup, import, transfer) hashes in full.
    """

    def __init__(self, path: Path | None):
        self.path = path
        self._data: dict[str, list] = {}
        self._dirty = False
        if path and path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._data = {}

    def lookup(self, key: str, st: os.stat_result) -> str | None:
        hit = self._data.get(key)
        return hit[4] if hit and hit[:4] == [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino] else None

    def store(self, key: str, st: os.stat_result, digest: str) -> None:
        self._data[key] = [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino, digest]
        self._dirty = True

    def save(self) -> None:
        if self.path and self._dirty:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(self._data), encoding="utf-8")
            os.replace(tmp, self.path)
            self._dirty = False


def resolve_baseline(source: str) -> Path | None:
    """Where the installed software keeps the pristine copy. Unknown or unavailable -> no baseline, which is the
    safe direction: everything is sealed."""
    if source == "hermes:bundled_skills":
        override = os.environ.get("HERMES_BUNDLED_SKILLS")
        if override:
            return Path(override) if Path(override).is_dir() else None
        try:
            from tools.skills_sync import _get_bundled_dir  # type: ignore  # pinned by tests/test_hermes_contract.py
            found = Path(_get_bundled_dir())
            return found if found.is_dir() else None
        except Exception:  # noqa: BLE001 - Hermes not importable here
            return None
    return None


def scan(home: Path, include: list[str], exclude: list[str] | None = None,
         cache: HashCache | None = None, baselines: list[dict] | None = None) -> list[dict]:
    """List every sealed entry under ``home`` for the given include paths, sorted by path.

    A regular file becomes ``{"p", "h", "s"}``; a symlink becomes ``{"p", "l"}`` and is *never
    followed*, so a link cannot smuggle outside content under the seal.

    ``baselines``: a file under a baseline prefix that is byte-identical to the file the installed software
    ships at the same relative path is skipped. So the seal covers exactly what is the agent's own: every
    skill it wrote, and every shipped skill that differs by even one byte from what the software ships. A
    software update can refresh shipped files without breaking the seal; nobody can alter one unnoticed,
    because the altered file stops matching the baseline and lands under the seal, where it changes the root.
    """
    home = Path(home)
    patterns = DEFAULT_EXCLUDE + list(exclude or [])
    entries: dict[str, dict] = {}
    shipped: list[tuple[PurePosixPath, Path]] = []
    for baseline in baselines or []:
        source = resolve_baseline(str(baseline.get("source", "")))
        if source is not None:
            shipped.append((PurePosixPath(str(baseline.get("prefix", ""))), source))

    def is_shipped(rel: PurePosixPath, digest: str) -> bool:
        for prefix, source in shipped:
            try:
                inside = rel.relative_to(prefix)
            except ValueError:
                continue
            twin = source.joinpath(*inside.parts)
            try:
                st = os.lstat(twin)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            key = f"baseline:{twin}"
            twin_digest = cache.lookup(key, st) if cache else None
            if twin_digest is None:
                twin_digest, _ = file_sha256(twin)
                if cache:
                    cache.store(key, st, twin_digest)
            if twin_digest == digest:
                return True
        return False

    def add(path: Path) -> None:
        rel = PurePosixPath(path.relative_to(home).as_posix())
        if _excluded(rel, patterns):
            return
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            link = os.readlink(path)
            check_link(rel, link)
            entries[str(rel)] = {"p": str(rel), "l": link}
        elif stat.S_ISDIR(st.st_mode):
            for child in sorted(os.listdir(path)):
                add(path / child)
        elif stat.S_ISREG(st.st_mode):
            digest = cache.lookup(str(rel), st) if cache else None
            if digest is None:
                digest, _ = file_sha256(path)
                if cache:
                    cache.store(str(rel), st, digest)
            if not is_shipped(rel, digest):
                entries[str(rel)] = {"p": str(rel), "h": digest, "s": st.st_size}
        # sockets, devices, fifos: not agent state

    for item in include:
        rel = PurePosixPath(item)
        if rel.is_absolute() or ".." in rel.parts:
            raise SealError(f"include path must stay inside the agent home: {item!r}")
        target = home / rel
        if os.path.lexists(target):
            add(target)
    if cache:
        cache.save()
    return [entries[key] for key in sorted(entries)]


def root_of(entries: list[dict]) -> str:
    return merkle_root(hash_obj(entry) for entry in entries)


def summarize(entries: list[dict]) -> dict:
    return {"root": root_of(entries), "files": len(entries), "bytes": sum(e.get("s", 0) for e in entries)}


def diff(old: list[dict], new: list[dict]) -> dict:
    """Human-readable difference between two scans: what makes a seal fail."""
    before, after = {e["p"]: e for e in old}, {e["p"]: e for e in new}
    return {"added": sorted(set(after) - set(before)), "removed": sorted(set(before) - set(after)),
            "changed": sorted(p for p in set(before) & set(after) if before[p] != after[p])}
