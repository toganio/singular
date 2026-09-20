"""How the rest of Singular talks to a ledger.

:class:`Ledger` is the pluggable seam. v0.1 ships two backends: :class:`LocalLedger` (a chain in
this process; tests, single-machine use) and :class:`HttpLedger` (a remote node). A future backend
that anchors to a public chain implements the same five methods.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Protocol

from ..errors import LedgerRejected, SingularError
from .chain import Chain, ChainError, block_hash, verify_chain


class LedgerUnavailable(SingularError):
    """The ledger could not be reached. Runtimes treat this as "cannot prove my lease"."""


class Ledger(Protocol):
    def info(self) -> dict: ...
    def get_agent(self, agent_id: str) -> dict | None: ...
    def get_bank(self, bank_id: str) -> dict | None: ...
    def history(self, subject: str) -> list[dict]: ...
    def submit(self, tx: dict) -> dict: ...


class LocalLedger:
    def __init__(self, chain: Chain):
        self.chain = chain

    def info(self) -> dict:
        return self.chain.info()

    def get_agent(self, agent_id: str) -> dict | None:
        return self.chain.state.get(agent_id)

    def get_bank(self, bank_id: str) -> dict | None:
        return self.chain.state.get_bank(bank_id)

    def history(self, subject: str) -> list[dict]:
        return self.chain.history(subject)

    def submit(self, tx: dict) -> dict:
        return self.chain.submit(tx)


class HttpLedger:
    def __init__(self, url: str, timeout: float = 10.0, register_token: str | None = None):
        self._token = register_token or os.environ.get("SINGULAR_REGISTER_TOKEN")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise SingularError(f"ledger url must be http(s)://host[:port], got {url!r}")
        if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1") \
                and os.environ.get("SINGULAR_ALLOW_INSECURE_LEDGER") != "1":
            raise SingularError("refusing a plain-http ledger on the network: anyone in between could lie about "
                                "leases and seals. Use https, or set SINGULAR_ALLOW_INSECURE_LEDGER=1 on a trusted LAN")
        self.url = url.rstrip("/")
        self.timeout = timeout

    def _call(self, path: str, payload: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(self.url + path, data=data, method="POST" if data else "GET",
                                         headers={"Content-Type": "application/json"} if data else {})
        if data and self._token and payload.get("type") in ("REGISTER", "BANK_CREATE"):
            request.add_header("Authorization", f"Bearer {self._token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - scheme checked
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            except ValueError:
                raise LedgerUnavailable(f"ledger answered {exc.code} without JSON") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise LedgerUnavailable(f"cannot reach ledger at {self.url}: {exc}") from None

    def info(self) -> dict:
        return self._call("/info")[1]

    def _record(self, kind: str, subject: str) -> dict | None:
        status, body = self._call(f"/{kind}/{urllib.parse.quote(subject, safe='')}")
        if status == 404:
            return None
        if status != 200:
            raise LedgerUnavailable(f"ledger answered {status}")
        return body[kind]

    def get_agent(self, agent_id: str) -> dict | None:
        return self._record("agent", agent_id)

    def get_bank(self, bank_id: str) -> dict | None:
        return self._record("bank", bank_id)

    def history(self, subject: str) -> list[dict]:
        return self._call(f"/history/{urllib.parse.quote(subject, safe='')}")[1].get("history", [])

    def submit(self, tx: dict) -> dict:
        status, body = self._call("/tx", tx)
        if status == 200:
            return body["receipt"]
        if status == 429:
            raise LedgerUnavailable("ledger is rate-limiting this address; slow down")
        if "error" in body:
            raise LedgerRejected(str(body["error"]), str(body.get("message", "")))
        raise LedgerUnavailable(f"ledger answered {status}")

    def fetch_blocks(self, start: int = 0):
        while True:
            batch = self._call(f"/blocks?from={start}&limit=200")[1].get("blocks", [])
            if not batch:
                return
            yield from batch
            start = batch[-1]["header"]["height"] + 1

    def audit(self, expected_chain_id: str) -> dict:
        """Download the whole chain and replay every rule. Trusts nothing but the pinned chain id."""
        state, head = verify_chain(self.fetch_blocks(0), expected_chain_id)
        return {"chain_id": state.chain_id, "height": head["height"], "head": block_hash(head),
                "agents": len(state.agents), "banks": len(state.banks), "state": state}


def open_ledger(url: str) -> "Ledger":
    """``http(s)://...`` for a remote node, or ``file:<path>`` for a local read-only chain file."""
    if url.startswith("file:"):
        return LocalLedger(Chain(url[5:], None))
    return HttpLedger(url)


__all__ = ["Ledger", "LocalLedger", "HttpLedger", "LedgerUnavailable", "ChainError", "open_ledger"]
