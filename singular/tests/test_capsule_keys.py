import io
import os
import struct
import tarfile

import pytest

from singular import capsule, keys, tree
from singular.canonical import canonical, sha256_hex
from singular.errors import CapsuleError, CryptoError, SealError
from singular.keys import SigningKey, seal_to, unwrap_key, wrap_key

PASSWORD = "a long enough passphrase"


def test_keystore_roundtrip_at_full_cost(monkeypatch):
    monkeypatch.setattr(keys, "_SCRYPT_N", 2**15)
    key = SigningKey.generate()
    store = wrap_key(key, PASSWORD, label="agent")
    assert key.seed.hex() not in str(store)
    assert unwrap_key(store, PASSWORD).public_hex == key.public_hex
    with pytest.raises(CryptoError):
        unwrap_key(store, PASSWORD + "x")
    relabelled = {**store, "label": "owner"}
    with pytest.raises(CryptoError):
        unwrap_key(relabelled, PASSWORD)
    with pytest.raises(CryptoError):
        wrap_key(key, "short", label="agent")
    weak = {**store, "kdf": {**store["kdf"], "n": 2}}
    with pytest.raises(CryptoError):
        unwrap_key(weak, PASSWORD)


def test_sealed_box_is_bound_to_recipient_and_context():
    alice, bob = SigningKey.generate(), SigningKey.generate()
    box = seal_to(alice.enc_public_hex, b"data key", context=b"bank1")
    assert alice.open_sealed(box, context=b"bank1") == b"data key"
    for key, ctx in ((bob, b"bank1"), (alice, b"bank2")):
        with pytest.raises(CryptoError):
            key.open_sealed(box, context=ctx)


def test_scan_never_follows_symlinks_or_seals_secrets(tmp_path):
    (tmp_path / "skills").mkdir()
    (tmp_path / "SOUL.md").write_text("soul")
    os.symlink("../SOUL.md", tmp_path / "skills" / "link")   # in-home link: recorded, never followed
    (tmp_path / "skills" / ".env").write_text("KEY=1")
    (tmp_path / "skills" / "a.md").write_text("a")
    entries = tree.scan(tmp_path, ["skills"])
    assert [e["p"] for e in entries] == ["skills/a.md", "skills/link"] and "l" in entries[1]
    with pytest.raises(SealError):
        tree.scan(tmp_path, ["../etc"])
    root = tree.root_of(entries)
    (tmp_path / "skills" / "a.md").write_text("b")
    assert tree.root_of(tree.scan(tmp_path, ["skills"])) != root


def _evil_capsule(path, members):
    """Build a validly *encrypted* capsule whose tar payload is hostile."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    payload = buf.getvalue()
    salt, prefix = os.urandom(16), os.urandom(7)
    header = {"v": 1, "kind": "singular-capsule", "meta": {}, "chunk": capsule.CHUNK,
              "kdf": {"name": "scrypt", "n": 2**14, "salt": salt.hex()}, "nonce_prefix": prefix.hex()}
    raw = canonical(header)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    aead = ChaCha20Poly1305(keys.derive_key(PASSWORD, salt, 2**14))
    sealed = aead.encrypt(capsule._nonce(prefix, 0, True), payload, capsule._aad(bytes.fromhex(sha256_hex(raw)), 0, True))
    path.write_bytes(capsule.MAGIC + struct.pack(">I", len(raw)) + raw + struct.pack(">I", len(sealed)) + sealed)


def _file(name, data=b"x"):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def _link(name, target):
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    return info, None


@pytest.mark.parametrize("members", [
    [_file("../escape.txt")],
    [_file("/abs/escape.txt")],
    [_link("skills", "/tmp"), _file("skills/pwned.txt")],
    [_file(".env", b"STOLEN=1")],
    [_file("a.txt"), _file("a.txt")],
])
def test_hostile_capsules_are_refused(tmp_path, members):
    path = tmp_path / "evil.capsule"
    _evil_capsule(path, members)
    with pytest.raises(CapsuleError):
        capsule.unpack(path, tmp_path / "out", PASSWORD)
    assert not (tmp_path / "escape.txt").exists()


def test_capsule_refuses_non_empty_target_and_garbage(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "x").write_text("x")
    junk = tmp_path / "junk"
    junk.write_bytes(b"not a capsule")
    with pytest.raises(CapsuleError):
        capsule.unpack(junk, tmp_path / "out", PASSWORD)
    with pytest.raises(CapsuleError):
        capsule.unpack(junk, tmp_path / "fresh", PASSWORD)


def test_large_payload_spans_chunks(tmp_path):
    home = tmp_path / "home"
    (home / ".singular").mkdir(parents=True)
    (home / "big.bin").write_bytes(os.urandom(capsule.CHUNK * 2 + 123))
    capsule.pack(home, ["big.bin"], tmp_path / "c.capsule", PASSWORD, {})
    capsule.unpack(tmp_path / "c.capsule", tmp_path / "out", PASSWORD)
    assert (tmp_path / "out" / "big.bin").read_bytes() == (home / "big.bin").read_bytes()


def test_symlink_out_of_home_cannot_be_sealed_or_imported(tmp_path):
    (tmp_path / "skills").mkdir()
    os.symlink("/etc/passwd", tmp_path / "skills" / "abs")
    with pytest.raises(SealError, match="outside the agent home"):
        tree.scan(tmp_path, ["skills"])
    (tmp_path / "skills" / "abs").unlink()
    os.symlink("../../up", tmp_path / "skills" / "rel")
    with pytest.raises(SealError):
        tree.scan(tmp_path, ["skills"])
    (tmp_path / "skills" / "rel").unlink()
    os.symlink("../SOUL.md", tmp_path / "skills" / "ok")
    assert tree.scan(tmp_path, ["skills"])[0]["l"] == "../SOUL.md"
    evil = tmp_path / "evil.capsule"
    _evil_capsule(evil, [_link("skills/leak", "/etc/passwd")])
    with pytest.raises(CapsuleError):
        capsule.unpack(evil, tmp_path / "out", PASSWORD)
