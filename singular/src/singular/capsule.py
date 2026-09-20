"""The transport capsule: an agent packed into one encrypted file, for moving or selling.

Format (all integers big-endian)::

    b"SNGCAP1\\n" | u32 header_len | header JSON | { u32 chunk_len | chunk ciphertext }*

The payload is a gzip'd tar of the sealed core + internal memory + the ``.singular`` identity
folder, encrypted in 1 MiB chunks with ChaCha20-Poly1305 under a key stretched from the capsule
passphrase with scrypt. Each chunk's nonce and associated data carry its index and a "this is the
last chunk" flag, and the associated data also carries the header hash, so chunks cannot be
reordered, dropped, truncated, or spliced between capsules without failing authentication.

A capsule is only a parcel. What makes the unpacked agent *the* agent is that its roots match the
ledger; ``unpack`` is always followed by a full verification.
"""

from __future__ import annotations

import io
import json
import os
import struct
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .canonical import canonical, sha256_hex
from .errors import CapsuleError, CryptoError
from . import keys as _keys
from .keys import check_passphrase, derive_key
from .errors import SealError
from .tree import SECRET_NAMES, SINGULAR_DIR, check_link

MAGIC = b"SNGCAP1\n"
CHUNK = 1 << 20
MAX_HEADER = 64 * 1024
MAX_MEMBERS = 200_000
MAX_UNPACKED_BYTES = 64 << 30
# Runtime-only files inside .singular that must not travel.
_LOCAL_ONLY = {"hashcache.json", "runtime.json", "banks", "objects", "seals", "agent.keystore.pending.json"}
# Left out of a capsule made for a *sale*: the seller's wrapped key (a buyer could grind its passphrase and run
# the agent under the seller's name before the transfer lands) and the seller's private action records.
_SELLER_ONLY = {"agent.keystore.json", "actions.jsonl"}


def _aad(header_hash: bytes, index: int, final: bool) -> bytes:
    return header_hash + struct.pack(">IB", index, 1 if final else 0)


def _nonce(prefix: bytes, index: int, final: bool) -> bytes:
    return prefix + struct.pack(">IB", index, 1 if final else 0)


def pack(home: Path, paths: list[str], out_path: Path, passphrase: str, meta: dict, *, for_sale: bool = False) -> dict:
    """Write an encrypted capsule containing ``paths`` (relative to ``home``) plus ``.singular``."""
    check_passphrase(passphrase)
    home = Path(home)
    salt, prefix = os.urandom(16), os.urandom(7)
    header = {"v": 1, "kind": "singular-capsule", "meta": meta, "chunk": CHUNK,
              "kdf": {"name": "scrypt", "n": _keys._SCRYPT_N, "salt": salt.hex()}, "nonce_prefix": prefix.hex()}
    header_bytes = canonical(header)
    header_hash = bytes.fromhex(sha256_hex(header_bytes))
    aead = ChaCha20Poly1305(derive_key(passphrase, salt, _keys._SCRYPT_N))

    with tempfile.TemporaryFile() as plain:
        with tarfile.open(fileobj=plain, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
            for rel in paths:
                tar.add(home / rel, arcname=rel, recursive=False)
            sdir = home / SINGULAR_DIR
            for path in sorted(sdir.rglob("*")):
                rel = path.relative_to(home)
                if rel.parts[1] in _LOCAL_ONLY or path.is_dir() or path.is_symlink():
                    continue
                if for_sale and rel.parts[1] in _SELLER_ONLY:
                    continue
                tar.add(path, arcname=rel.as_posix(), recursive=False)
        total = plain.tell()
        plain.seek(0)
        out_path = Path(out_path)
        tmp = out_path.with_name(out_path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes)
            index, remaining = 0, total
            while True:
                chunk = plain.read(CHUNK)
                remaining -= len(chunk)
                final = remaining <= 0
                sealed = aead.encrypt(_nonce(prefix, index, final), chunk, _aad(header_hash, index, final))
                out.write(struct.pack(">I", len(sealed)) + sealed)
                index += 1
                if final:
                    break
        os.replace(tmp, out_path)
    return header


def read_header(capsule_path: Path) -> dict:
    with open(capsule_path, "rb") as handle:
        return _read_header(handle)[0]


def _read_header(handle) -> tuple[dict, bytes]:
    if handle.read(len(MAGIC)) != MAGIC:
        raise CapsuleError("not a Singular capsule")
    (length,) = struct.unpack(">I", handle.read(4))
    if not 0 < length <= MAX_HEADER:
        raise CapsuleError("capsule header has an impossible size")
    raw = handle.read(length)
    try:
        header = json.loads(raw)
    except ValueError:
        raise CapsuleError("capsule header is not JSON") from None
    if not isinstance(header, dict) or header.get("kind") != "singular-capsule" or header.get("v") != 1 \
            or canonical(header) != raw:
        raise CapsuleError("capsule header is malformed")
    return header, raw


def _decrypt_to(handle, header: dict, raw_header: bytes, passphrase: str, sink) -> None:
    try:
        kdf = header["kdf"]
        n = int(kdf["n"])
        if kdf.get("name") != "scrypt" or not 2**14 <= n <= 2**20:
            raise CapsuleError("unsupported capsule KDF parameters")
        key = derive_key(passphrase, bytes.fromhex(kdf["salt"]), n)
        prefix = bytes.fromhex(header["nonce_prefix"])
        if len(prefix) != 7:
            raise CapsuleError("bad nonce prefix")
    except (KeyError, ValueError, TypeError):
        raise CapsuleError("capsule header is malformed") from None
    aead, header_hash = ChaCha20Poly1305(key), bytes.fromhex(sha256_hex(raw_header))
    index, final = 0, False
    while not final:
        size_raw = handle.read(4)
        if len(size_raw) != 4:
            raise CapsuleError("capsule is truncated")
        (size,) = struct.unpack(">I", size_raw)
        if not 16 <= size <= CHUNK + 16:
            raise CapsuleError("capsule chunk has an impossible size")
        sealed = handle.read(size)
        if len(sealed) != size:
            raise CapsuleError("capsule is truncated")
        # We do not know in advance which chunk is last; the flag is authenticated, so try both.
        for final in (False, True):
            try:
                sink.write(aead.decrypt(_nonce(prefix, index, final), sealed, _aad(header_hash, index, final)))
                break
            except InvalidTag:
                continue
        else:
            raise CryptoError("wrong capsule passphrase, or the capsule was tampered with")
        index += 1
    if handle.read(1):
        raise CapsuleError("unexpected data after the final chunk")


def _safe_member(member: tarfile.TarInfo) -> PurePosixPath:
    rel = PurePosixPath(member.name)
    if rel.is_absolute() or ".." in rel.parts or not rel.parts:
        raise CapsuleError(f"capsule member escapes the target folder: {member.name!r}")
    if any(part in SECRET_NAMES for part in rel.parts):
        raise CapsuleError(f"capsule carries a secrets file, refusing: {member.name!r}")
    if not (member.isreg() or member.issym()):
        raise CapsuleError(f"capsule member has a forbidden type: {member.name!r}")
    return rel


def unpack(capsule_path: Path, target: Path, passphrase: str) -> dict:
    """Decrypt into ``target`` (which must be empty or absent). Returns the capsule header.

    Members are written by hand instead of ``tarfile.extractall``: only regular files and symlinks,
    never through an existing symlink, never outside ``target``, never setuid, never a secrets file.
    Symlinks are recreated as links (they are part of the sealed state) but nothing is ever written
    *through* one.
    """
    target = Path(target)
    if target.exists() and any(target.iterdir()):
        raise CapsuleError(f"{target} is not empty; import into a fresh folder")
    with open(capsule_path, "rb") as handle, tempfile.TemporaryFile() as plain:
        header, raw = _read_header(handle)
        _decrypt_to(handle, header, raw, passphrase, plain)
        plain.seek(0)
        target.mkdir(parents=True, exist_ok=True)
        os.chmod(target, 0o700)
        root = target.resolve()
        count = written = 0
        try:
            with tarfile.open(fileobj=plain, mode="r:gz") as tar:
                for member in tar:
                    count += 1
                    if count > MAX_MEMBERS:
                        raise CapsuleError("capsule has too many members")
                    rel = _safe_member(member)
                    dest = root.joinpath(*rel.parts)
                    parent = dest.parent
                    parent.mkdir(parents=True, exist_ok=True)
                    if parent.resolve() != parent or root not in (parent, *parent.parents):
                        raise CapsuleError(f"capsule member would be written through a link: {member.name!r}")
                    if os.path.lexists(dest):
                        raise CapsuleError(f"capsule lists the same path twice: {member.name!r}")
                    if member.issym():
                        try:
                            check_link(rel, member.linkname)
                        except SealError as exc:
                            raise CapsuleError(str(exc)) from None
                        os.symlink(member.linkname, dest)
                        continue
                    source = tar.extractfile(member)
                    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    with os.fdopen(fd, "wb") as out:
                        while block := source.read(1 << 20):
                            written += len(block)
                            if written > MAX_UNPACKED_BYTES:
                                raise CapsuleError("capsule unpacks to an unreasonable size")
                            out.write(block)
                    if member.mode & 0o100:
                        os.chmod(dest, 0o700)
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise CapsuleError(f"capsule payload is corrupt: {exc}") from None
    return header
