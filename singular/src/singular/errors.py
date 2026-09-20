"""Exception types shared across Singular."""


class SingularError(Exception):
    """Base class for every Singular failure."""


class CryptoError(SingularError):
    """Bad key, bad passphrase, or a ciphertext that failed authentication."""


class SealError(SingularError):
    """The agent's files do not match what the ledger says they should be."""


class LeaseError(SingularError):
    """The run lease could not be acquired, was lost, or belongs to someone else."""


class CapsuleError(SingularError):
    """A transport capsule is malformed or unsafe to unpack."""


class LedgerRejected(SingularError):
    """The ledger refused a transaction. ``code`` is a stable machine-readable reason."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message
