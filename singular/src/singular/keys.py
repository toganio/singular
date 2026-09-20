"""Keys, agent ids, and the passphrase-wrapped keystore.

Three kinds of Ed25519 key exist in Singular:

* **owner key**  - the legally responsible person or company. Never travels with the agent.
* **agent key**  - the agent's own signing key. Lives inside the agent home, wrapped by a
  passphrase. Replaced on every transfer, which is what kills the seller's leftover copy.
* **host key**   - made fresh in memory each time a runtime starts. The ledger binds the run
  lease to it, so a second process holding the same agent key still cannot act.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from .canonical import canonical, sha256_hex
from .errors import CryptoError

AGENT_ID_PREFIX = "sng1"
BANK_ID_PREFIX = "snb1"
KEYSTORE_KIND = "singular-keystore"
MIN_PASSPHRASE_LEN = 10

# scrypt cost. n=2**15 is ~100 ms and 32 MiB: painful for bulk guessing, fine at startup.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


class SigningKey:
    """An Ed25519 private key with hex helpers."""

    def __init__(self, private: Ed25519PrivateKey):
        self._private = private

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "SigningKey":
        if len(seed) != 32:
            raise CryptoError("an Ed25519 seed is 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def seed(self) -> bytes:
        return self._private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    @property
    def public_hex(self) -> str:
        return self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def sign(self, message: bytes) -> str:
        return self._private.sign(message).hex()

    # -- encryption half -------------------------------------------------------------------
    # One passphrase must open the agent *and* every memory bank it was granted. So the agent's
    # X25519 decryption key is derived from the same seed: unlock the agent, and the bank keys
    # wrapped to ``enc_public_hex`` open with it.

    def _enc_private(self) -> X25519PrivateKey:
        material = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"singular-enc-v1").derive(self.seed)
        return X25519PrivateKey.from_private_bytes(material)

    @property
    def enc_public_hex(self) -> str:
        return self._enc_private().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def open_sealed(self, sealed_hex: str, *, context: bytes) -> bytes:
        """Open a box made by :func:`seal_to` for this key."""
        try:
            raw = bytes.fromhex(sealed_hex)
            ephemeral, nonce, ciphertext = raw[:32], raw[32:44], raw[44:]
            private = self._enc_private()
            shared = private.exchange(X25519PublicKey.from_public_bytes(ephemeral))
            recipient = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            return ChaCha20Poly1305(_box_key(shared, ephemeral, recipient)).decrypt(nonce, ciphertext, context)
        except (ValueError, InvalidTag):
            raise CryptoError("this key cannot open that sealed box") from None


def _box_key(shared: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ephemeral_pub + recipient_pub,
                info=b"singular-box-v1").derive(shared)


def seal_to(enc_public_hex: str, plaintext: bytes, *, context: bytes) -> str:
    """Anonymous public-key box (ephemeral X25519 + ChaCha20-Poly1305). ``context`` is bound as
    associated data, so a bank key wrapped for one bank/agent/generation cannot be replayed as another."""
    try:
        recipient = bytes.fromhex(enc_public_hex)
        recipient_key = X25519PublicKey.from_public_bytes(recipient)
    except ValueError:
        raise CryptoError("bad encryption public key") from None
    ephemeral = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce = os.urandom(12)
    key = _box_key(ephemeral.exchange(recipient_key), ephemeral_pub, recipient)
    return (ephemeral_pub + nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, context)).hex()


def verify_signature(public_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        raw_pub = bytes.fromhex(public_hex)
        raw_sig = bytes.fromhex(signature_hex)
        if len(raw_pub) != 32 or len(raw_sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(raw_sig, message)
        return True
    except (ValueError, InvalidSignature):
        return False


def derive_agent_id(genesis_agent_pub: str, genesis_owner_pub: str, salt: str) -> str:
    """The permanent id. It commits to the *genesis* keys, so it survives key rotation on
    transfer while still being impossible to claim for anyone who did not create it."""
    return _b32id(AGENT_ID_PREFIX, {"a": genesis_agent_pub, "o": genesis_owner_pub, "s": salt})


def _b32id(prefix: str, payload: dict) -> str:
    digest = bytes.fromhex(sha256_hex(canonical(payload)))[:20]
    return prefix + base64.b32encode(digest).decode("ascii").lower().rstrip("=")


def derive_bank_id(genesis_owner_pub: str, salt: str) -> str:
    return _b32id(BANK_ID_PREFIX, {"bank": "external", "o": genesis_owner_pub, "s": salt})


def internal_bank_id(agent_id: str) -> str:
    """Every agent has exactly one internal memory bank; its id follows from the agent id."""
    return _b32id(BANK_ID_PREFIX, {"bank": "internal", "agent": agent_id})


def new_salt() -> str:
    return secrets.token_hex(16)


def check_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise CryptoError(f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters")


def derive_key(passphrase: str, salt: bytes, n: int | None = None) -> bytes:
    return Scrypt(salt=salt, length=32, n=n or _SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P).derive(passphrase.encode("utf-8"))


def wrap_key(key: SigningKey, passphrase: str, *, label: str) -> dict:
    """Encrypt a private key under a passphrase. The label and public key are bound as AAD,
    so a keystore cannot be relabelled or swapped under a different identity."""
    check_passphrase(passphrase)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    header = {"kind": KEYSTORE_KIND, "v": 1, "label": label, "pub": key.public_hex,
              "kdf": {"name": "scrypt", "n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P, "salt": salt.hex()},
              "nonce": nonce.hex()}
    ciphertext = ChaCha20Poly1305(derive_key(passphrase, salt, _SCRYPT_N)).encrypt(nonce, key.seed, canonical(header))
    return {**header, "ct": ciphertext.hex()}


def unwrap_key(store: dict, passphrase: str) -> SigningKey:
    try:
        header = {k: v for k, v in store.items() if k != "ct"}
        if header.get("kind") != KEYSTORE_KIND or header.get("v") != 1:
            raise CryptoError("not a Singular keystore")
        kdf = header["kdf"]
        if kdf.get("name") != "scrypt" or not (2**14 <= int(kdf["n"]) <= 2**20):
            raise CryptoError("unsupported keystore KDF parameters")
        wrapping = derive_key(passphrase, bytes.fromhex(kdf["salt"]), int(kdf["n"]))
        seed = ChaCha20Poly1305(wrapping).decrypt(bytes.fromhex(header["nonce"]), bytes.fromhex(store["ct"]),
                                                  canonical(header))
    except InvalidTag:
        raise CryptoError("wrong passphrase or corrupted keystore") from None
    except (KeyError, ValueError, TypeError) as exc:
        raise CryptoError(f"malformed keystore: {exc}") from None
    key = SigningKey.from_seed(seed)
    if key.public_hex != header.get("pub"):
        raise CryptoError("keystore public key does not match its private key")
    return key


def save_keystore(path: Path, store: dict) -> None:
    """Write a keystore with owner-only permissions, atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(store, handle, indent=2, sort_keys=True)
    os.replace(tmp, path)


def load_keystore(path: Path) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CryptoError(f"cannot read keystore {path}: {exc}") from None
