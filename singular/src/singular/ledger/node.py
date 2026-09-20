"""HTTP front for a chain. Standard library only, so a ledger node has no web-framework attack
surface to keep patched.

    GET  /info                     chain id, height, validators
    GET  /agent/<id>               current agent record
    GET  /bank/<id>                current memory-bank record
    GET  /history/<id>             every transaction that touched an agent or bank
    GET  /blocks?from=N&limit=M    raw blocks, for replicas and auditors
    POST /tx                       submit a signed transaction

Nothing here needs authentication: every write is authorised by the signatures inside the
transaction, and every read is public by design (the ledger holds hashes, never agent content).
"""

from __future__ import annotations

import hmac
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ..errors import LedgerRejected
from .chain import Chain
from .tx import MAX_TX_BYTES

_ID = re.compile(r"^[a-z0-9]{8,64}$")


class RateLimiter:
    """Token bucket per client address for ``POST /tx``. Every accepted transaction is permanent chain
    growth, so an open node must not let one address write without bound. (Put a real proxy / WAF in
    front of a public node as well; this is the floor, not the ceiling.)"""

    def __init__(self, per_minute: int, burst: int):
        self.rate, self.burst = per_minute / 60.0, float(burst)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._buckets) > 50_000:  # bound memory under address churn
                self._buckets.clear()
            tokens, last = self._buckets.get(client, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self._buckets[client] = (tokens, now)
                return False
            self._buckets[client] = (tokens - 1.0, now)
            return True


def _handler_for(chain: Chain, limiter: "RateLimiter | None" = None, read_limiter: "RateLimiter | None" = None,
                 register_tokens: frozenset = frozenset(), trust_proxy: bool = False):
    class Handler(BaseHTTPRequestHandler):
        server_version = "singular-ledger"
        protocol_version = "HTTP/1.1"
        timeout = 15  # a stalled client cannot pin a worker thread forever

        def log_message(self, fmt, *args):  # noqa: D401 - quiet by default
            return

        def _send(self, status: int, payload: dict) -> None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _client(self) -> str:
            if trust_proxy:  # only meaningful when *our own* proxy appends the hop
                hops = [h.strip() for h in self.headers.get("X-Forwarded-For", "").split(",") if h.strip()]
                if hops:
                    return hops[-1][:64]
            return self.client_address[0]

        def do_GET(self):  # noqa: N802
            if read_limiter is not None and not read_limiter.allow(self._client()):
                self.close_connection = True
                return self._send(429, {"error": "RATE_LIMITED"})
            url = urlparse(self.path)
            parts = [p for p in url.path.split("/") if p]
            try:
                if parts == ["info"]:
                    return self._send(200, chain.info())
                if len(parts) == 2 and parts[0] in ("agent", "bank", "history") and _ID.match(parts[1]):
                    if parts[0] == "history":
                        return self._send(200, {"history": chain.history(parts[1])})
                    with chain._lock:
                        record = chain.state.get(parts[1]) if parts[0] == "agent" else chain.state.get_bank(parts[1])
                        head = chain.head["height"]
                        head_ts = chain.head["ts"]
                    if record is None:
                        return self._send(404, {"error": "NOT_FOUND"})
                    return self._send(200, {parts[0]: record, "height": head, "head_ts": head_ts})
                if parts == ["blocks"]:
                    query = parse_qs(url.query)
                    start = int(query.get("from", ["0"])[0])
                    limit = int(query.get("limit", ["200"])[0])
                    if start < 0:
                        raise ValueError
                    return self._send(200, {"blocks": chain.blocks(start, limit)})
            except ValueError:
                return self._send(400, {"error": "BAD_REQUEST"})
            self._send(404, {"error": "NOT_FOUND"})

        def do_POST(self):  # noqa: N802
            if urlparse(self.path).path != "/tx":
                return self._send(404, {"error": "NOT_FOUND"})
            if limiter is not None and not limiter.allow(self._client()):
                self.close_connection = True
                return self._send(429, {"error": "RATE_LIMITED", "message": "too many transactions from this address"})
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if not 0 < length <= MAX_TX_BYTES * 2:
                self.close_connection = True
                return self._send(413, {"error": "BAD_REQUEST", "message": "missing or oversized body"})
            try:
                tx = json.loads(self.rfile.read(length))
            except ValueError:
                return self._send(400, {"error": "BAD_REQUEST", "message": "body is not JSON"})
            if register_tokens and isinstance(tx, dict) and tx.get("type") in ("REGISTER", "BANK_CREATE"):
                # Node policy, not consensus: an operator may require an API token to *create* things, so an
                # open node cannot be bloated with junk agents. Everything else stays permissionless.
                offered = self.headers.get("Authorization", "").removeprefix("Bearer ").strip().encode()
                if not any(hmac.compare_digest(offered, t.encode()) for t in register_tokens):
                    return self._send(401, {"error": "REGISTER_TOKEN_REQUIRED", "message": "this node requires a token to register"})
            try:
                return self._send(200, {"receipt": chain.submit(tx)})
            except LedgerRejected as exc:
                return self._send(409, {"error": exc.code, "message": exc.message})
            except RecursionError:
                return self._send(400, {"error": "BAD_REQUEST", "message": "nesting too deep"})

    return Handler


class LedgerNode:
    """Run a chain behind HTTP. ``port=0`` picks a free port (used by tests and the demo)."""

    def __init__(self, chain: Chain, host: str = "127.0.0.1", port: int = 0, *,
                 writes_per_minute: int = 120, burst: int = 60, reads_per_minute: int = 1200,
                 register_tokens: list[str] | None = None, trust_proxy: bool = False):
        self.chain = chain
        limiter = RateLimiter(writes_per_minute, burst) if writes_per_minute > 0 else None
        read_limiter = RateLimiter(reads_per_minute, reads_per_minute // 4) if reads_per_minute > 0 else None
        self._server = ThreadingHTTPServer((host, port), _handler_for(
            chain, limiter, read_limiter, frozenset(register_tokens or ()), trust_proxy))
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "LedgerNode":
        self._thread = threading.Thread(target=self._server.serve_forever, name="singular-ledger", daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)
