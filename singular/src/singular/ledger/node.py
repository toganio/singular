"""HTTP front for a chain. Standard library only, so a ledger node has no web-framework attack
surface to keep patched.

    GET  /info                     chain id, height, validators
    GET  /agent/<id>               current agent record
    GET  /bank/<id>                current memory-bank record
    GET  /history/<id>?limit=N     the latest N (<= 1000) transactions that touched an agent or bank, oldest first
    GET  /blocks?from=N&limit=M    raw blocks, for replicas and auditors
    POST /tx                       submit a signed transaction

Nothing here needs authentication: every write is authorised by the signatures inside the
transaction, and every read is public by design (the ledger holds hashes, never agent content).

This server speaks plain HTTP. A node reachable from the network MUST sit behind a TLS-terminating proxy
(clients refuse plain-http ledgers off-machine for good reason: whoever is in between could lie about leases
and seals). The proxy is also where per-client limits beyond the floor below belong.
"""

from __future__ import annotations

import hmac
import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ..errors import LedgerRejected
from .chain import Chain
from .tx import MAX_TX_BYTES

_ID = re.compile(r"^[a-z0-9]{8,64}$")
REQUEST_DEADLINE_S = 20.0   # a whole request (headers + body), however slowly it trickles in
_BAD_INPUT = (ValueError, TypeError, KeyError, OverflowError, RecursionError)


class RateLimiter:
    """Token bucket per client address for ``POST /tx``. Every accepted transaction is permanent chain
    growth, so an open node must not let one address write without bound. (Put a real proxy / WAF in
    front of a public node as well; this is the floor, not the ceiling.)"""

    def __init__(self, per_minute: int, burst: int, max_clients: int = 50_000):
        self.rate, self.burst, self.max_clients = per_minute / 60.0, float(burst), max_clients
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._pruned = 0.0

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if client not in self._buckets and len(self._buckets) >= self.max_clients:
                # Bound memory under address churn without ever forgetting a throttled client (forgetting is a reset):
                # drop only buckets that have refilled, which say nothing a fresh one would not; newcomers that still
                # find no room share one bucket.
                if now - self._pruned >= 1.0:
                    self._pruned = now
                    self._buckets = {k: (t, last) for k, (t, last) in self._buckets.items()
                                     if t + (now - last) * self.rate < self.burst}
                if len(self._buckets) >= self.max_clients:
                    client = "\0overflow"
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
        timeout = 15  # per read; REQUEST_DEADLINE_S bounds the whole request
        error_content_type = "application/json"
        error_message_format = '{"error":"HTTP_%(code)d"}'

        def version_string(self) -> str:  # no Python version in the Server header
            return self.server_version

        def log_message(self, fmt, *args):  # noqa: D401 - quiet by default
            return

        def handle_one_request(self):
            self.server.watch(self.connection)
            try:
                super().handle_one_request()
            finally:
                self.server.unwatch(self.connection)

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
            try:
                url = urlparse(self.path)
                parts = [p for p in url.path.split("/") if p]
                if parts == ["info"]:
                    return self._send(200, chain.info())
                if len(parts) == 2 and parts[0] in ("agent", "bank", "history") and _ID.match(parts[1]):
                    if parts[0] == "history":
                        items, truncated = chain.history_page(parts[1], int(parse_qs(url.query).get("limit", ["200"])[0]))
                        return self._send(200, {"history": items, "truncated": truncated})
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
                    if not 0 <= start < 2**63:
                        raise ValueError
                    return self._send(200, {"blocks": chain.blocks(start, limit)})
            except _BAD_INPUT:
                return self._send(400, {"error": "BAD_REQUEST"})
            except Exception:  # noqa: BLE001 - answer, never drop the connection with a traceback
                return self._send(500, {"error": "INTERNAL"})
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
            except (ValueError, RecursionError):
                return self._send(400, {"error": "BAD_REQUEST", "message": "body is not JSON (or nests too deep)"})
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
            except _BAD_INPUT:
                return self._send(400, {"error": "BAD_REQUEST", "message": "malformed transaction"})
            except Exception:  # noqa: BLE001
                return self._send(500, {"error": "INTERNAL"})

    return Handler


class _Server(ThreadingHTTPServer):
    """At most ``max_workers`` connections at once (beyond that, new ones are closed at once instead of each
    costing a thread), and a watchdog that cuts any request not complete within ``REQUEST_DEADLINE_S``: the
    per-read timeout alone lets a client trickle one byte every few seconds forever (slowloris)."""

    daemon_threads = True

    def __init__(self, address, handler, max_workers: int):
        super().__init__(address, handler)
        self._slots = threading.BoundedSemaphore(max_workers)
        self._deadlines: dict[socket.socket, float] = {}
        self._watch_lock = threading.Lock()
        self._closed = threading.Event()
        threading.Thread(target=self._watchdog, name="singular-ledger-watchdog", daemon=True).start()

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def watch(self, conn: socket.socket) -> None:
        with self._watch_lock:
            self._deadlines[conn] = time.monotonic() + REQUEST_DEADLINE_S

    def unwatch(self, conn: socket.socket) -> None:
        with self._watch_lock:
            self._deadlines.pop(conn, None)

    def _watchdog(self) -> None:
        while not self._closed.wait(0.5):
            now = time.monotonic()
            with self._watch_lock:
                late = [conn for conn, deadline in self._deadlines.items() if deadline <= now]
            for conn in late:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def server_close(self) -> None:
        self._closed.set()
        super().server_close()


class LedgerNode:
    """Run a chain behind HTTP. ``port=0`` picks a free port (used by tests and the demo)."""

    def __init__(self, chain: Chain, host: str = "127.0.0.1", port: int = 0, *,
                 writes_per_minute: int = 120, burst: int = 60, reads_per_minute: int = 1200,
                 register_tokens: list[str] | None = None, trust_proxy: bool = False, max_workers: int = 64):
        self.chain = chain
        limiter = RateLimiter(writes_per_minute, burst) if writes_per_minute > 0 else None
        read_limiter = RateLimiter(reads_per_minute, reads_per_minute // 4) if reads_per_minute > 0 else None
        self._server = _Server((host, port), _handler_for(
            chain, limiter, read_limiter, frozenset(register_tokens or ()), trust_proxy), max_workers)
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
