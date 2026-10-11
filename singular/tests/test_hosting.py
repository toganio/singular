"""Hosting: a capsule on an OCI registry, and the container supervisor (``singular host``) that pulls it,
runs it under the lease, reports to a control plane, and lets go on SIGTERM."""
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import PASS, make_home
from singular import agent as A, hosting, oci
from singular.errors import CapsuleError, SingularError
from singular.keys import SigningKey
from singular.ledger.chain import Chain
from singular.ledger.client import HttpLedger
from singular.ledger.node import LedgerNode

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
HOST = [sys.executable, "-c", "import sys; from singular import keys\nkeys._SCRYPT_N = 2**14\n"
        "from singular.hosting import main; sys.exit(main())"]
CAPSULE_PASS = "a long capsule passphrase"


class FakeRegistry:
    """Just enough of the OCI distribution API: blobs, monolithic uploads, manifests by tag or digest,
    and optionally the bearer-token dance."""

    def __init__(self, token: str | None = None):
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, bytes] = {}
        self.mounts: list[str] = []
        self.token = token
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body=b"", headers=None):
                self.send_response(code)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _authorized(self):
                if registry.token is None or self.path.startswith("/token"):
                    return True
                if self.headers.get("Authorization") == f"Bearer {registry.token}":
                    return True
                realm = f"http://127.0.0.1:{self.server.server_address[1]}/token"
                self._send(401, b"{}", {"WWW-Authenticate": f'Bearer realm="{realm}",service="fake",scope="repository:x:pull"'})
                return False

            def do_GET(self):
                if self.path.startswith("/token"):
                    return self._send(200, json.dumps({"token": registry.token}).encode())
                if not self._authorized():
                    return
                m = re.match(r"^/v2/(.+)/(blobs|manifests)/([^/?]+)$", self.path)
                if not m:
                    return self._send(404)
                _, kind, ref = m.groups()
                if kind == "blobs":
                    data = registry.blobs.get(ref)
                    return self._send(200, data) if data is not None else self._send(404)
                data = registry.manifests.get(ref)
                if data is None:
                    return self._send(404)
                return self._send(200, data, {"Content-Type": oci.MANIFEST_TYPE})

            do_HEAD = do_GET

            def do_POST(self):
                if not self._authorized():
                    return
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                path, _, query = self.path.partition("?")
                repo = re.match(r"^/v2/(.+)/blobs/uploads/$", path).group(1)
                mount = re.search(r"mount=([^&]+)", query)
                if mount and mount.group(1).replace("%3A", ":") in registry.blobs:
                    registry.mounts.append(mount.group(1).replace("%3A", ":"))
                    return self._send(201)
                self._send(202, b"", {"Location": f"/v2/{repo}/blobs/uploads/u1"})

            def do_PUT(self):
                if not self._authorized():
                    return
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if "/blobs/uploads/" in self.path:
                    digest = re.search(r"digest=([^&]+)", self.path).group(1).replace("%3A", ":")
                    assert digest == "sha256:" + hashlib.sha256(body).hexdigest()
                    registry.blobs[digest] = body
                    return self._send(201)
                tag = self.path.rsplit("/", 1)[1]
                registry.manifests[tag] = body
                registry.manifests["sha256:" + hashlib.sha256(body).hexdigest()] = body
                self._send(201)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.host = f"127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


class Collector:
    """A stand-in control plane: records what the supervisor reports."""

    def __init__(self):
        self.events: list[dict] = []
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                body["_auth"] = self.headers.get("Authorization")
                collector.events.append(body)
                self.send_response(204)
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/report"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def states(self):
        return [e["state"] for e in self.events]


@pytest.fixture
def world(tmp_path):
    chain = Chain.create(tmp_path / "chain.db", "host", SigningKey.generate())
    node = LedgerNode(chain, writes_per_minute=0, reads_per_minute=0).start()
    ledger, owner = HttpLedger(node.url), SigningKey.generate()
    agent = A.init_agent(make_home(tmp_path / "owner-home"), ledger, node.url, owner, PASS, name="Ada",
                         function="x", lease_ttl_ms=60_000)
    registry = FakeRegistry()
    yield tmp_path, node, ledger, agent, registry
    registry.close()
    node.stop()
    chain.close()


def export(agent, ledger, path, *, move=True):
    A.export_capsule(agent, ledger, path, CAPSULE_PASS, for_sale=not move)
    return path


# -- OCI ---------------------------------------------------------------------------------------

def test_reference_parsing_requires_an_explicit_registry():
    ref = oci.parse_reference("oci://ghcr.io/togan/ada:v3")
    assert (ref.registry, ref.repository, ref.tag) == ("ghcr.io", "togan/ada", "v3")
    pinned = oci.parse_reference("localhost:5000/ada@sha256:" + "a" * 64)
    assert pinned.digest and pinned.target == pinned.digest
    for bad in ("togan/ada:v3", "ghcr.io/Togan/ada", "ghcr.io/x@sha256:short"):
        with pytest.raises(CapsuleError):
            oci.parse_reference(bad)


def test_push_then_pull_by_digest_gives_back_the_same_capsule(world):
    tmp_path, _, ledger, agent, registry = world
    capsule = export(agent, ledger, tmp_path / "ada.capsule")
    pushed = oci.push(capsule, f"{registry.host}/togan/ada:v1")
    manifest = json.loads(registry.manifests["v1"])
    assert manifest["artifactType"] == oci.ARTIFACT_TYPE
    assert manifest["layers"][0]["mediaType"] == oci.LAYER_TYPE
    assert manifest["annotations"]["dev.singular.agent_id"] == agent.agent_id
    assert manifest["annotations"]["dev.singular.for_sale"] == "false"

    pulled = oci.pull("oci://" + pushed["reference"], tmp_path / "pulled.capsule")
    assert (tmp_path / "pulled.capsule").read_bytes() == capsule.read_bytes()
    assert pulled["manifest_digest"] == pushed["manifest_digest"]


def test_a_tampered_layer_or_a_swapped_manifest_is_refused(world):
    tmp_path, _, ledger, agent, registry = world
    pushed = oci.push(export(agent, ledger, tmp_path / "ada.capsule"), f"{registry.host}/togan/ada:v1")
    layer = pushed["layer_digest"]
    registry.blobs[layer] = registry.blobs[layer][:-1] + bytes([registry.blobs[layer][-1] ^ 1])
    with pytest.raises(CapsuleError, match="digest"):
        oci.pull(f"{registry.host}/togan/ada:v1", tmp_path / "x.capsule")
    assert not (tmp_path / "x.capsule").exists()

    # the tag now points somewhere else; a pinned reference notices
    registry.manifests[pushed["manifest_digest"]] = registry.manifests["v1"] + b" "
    with pytest.raises(CapsuleError, match="pinned"):
        oci.pull(pushed["reference"], tmp_path / "y.capsule")


def test_an_ordinary_image_is_not_taken_for_a_capsule(world):
    tmp_path, _, _, _, registry = world
    registry.manifests["latest"] = json.dumps({"schemaVersion": 2, "mediaType": oci.MANIFEST_TYPE,
                                               "config": {}, "layers": []}).encode()
    with pytest.raises(CapsuleError, match="not a Singular capsule"):
        oci.pull(f"{registry.host}/library/busybox", tmp_path / "z.capsule")


def test_bearer_token_auth(world, monkeypatch):
    tmp_path, _, ledger, agent, _ = world
    registry = FakeRegistry(token="t0k3n")
    try:
        pushed = oci.push(export(agent, ledger, tmp_path / "ada.capsule"), f"{registry.host}/togan/ada:v1")
        oci.pull(pushed["reference"], tmp_path / "pulled.capsule")
    finally:
        registry.close()


# -- supervisor --------------------------------------------------------------------------------

def test_secrets_file_splits_and_refuses_the_owner_key(tmp_path):
    secrets = tmp_path / "s.env"
    secrets.write_text('# hosted agent\nSINGULAR_PASSPHRASE="p w"\nexport OPENROUTER_API_KEY=sk-1\nTELEGRAM_BOT_TOKEN=\'12:ab\'\n')
    own, dotenv = hosting.load_secrets(secrets)
    assert own == {"SINGULAR_PASSPHRASE": "p w"}
    assert dotenv == {"OPENROUTER_API_KEY": "sk-1", "TELEGRAM_BOT_TOKEN": "12:ab"}
    secrets.write_text("SINGULAR_OWNER_PASSPHRASE=x\n")
    with pytest.raises(SingularError, match="owner"):
        hosting.load_secrets(secrets)
    secrets.write_text("not a line\n")
    with pytest.raises(SingularError, match="line 1"):
        hosting.load_secrets(secrets)


def test_a_capsule_made_for_sale_cannot_be_hosted(world):
    tmp_path, node, ledger, agent, registry = world
    pushed = oci.push(export(agent, ledger, tmp_path / "sale.capsule", move=False), f"{registry.host}/togan/ada:sale")
    with pytest.raises(SingularError, match="--move"):
        hosting.prepare_home(tmp_path / "vol" / "home", node.url,
                             {"SINGULAR_CAPSULE": "oci://" + pushed["reference"], "SINGULAR_CAPSULE_PASSPHRASE": CAPSULE_PASS})


def _start_host(tmp_path, node, collector, capsule, command, home, extra=None):
    secrets = tmp_path / "secrets.env"
    secrets.write_text(f"SINGULAR_PASSPHRASE={PASS}\nSINGULAR_CAPSULE_PASSPHRASE={CAPSULE_PASS}\n"
                       "SINGULAR_REPORT_TOKEN=report-token\nOPENROUTER_API_KEY=sk-customer\n")
    env = {**os.environ, "PYTHONPATH": SRC, "SINGULAR_LEDGER": node.url, "SINGULAR_HOME": str(home),
           "SINGULAR_SECRETS_FILE": str(secrets), "SINGULAR_CAPSULE": capsule, "SINGULAR_COMMAND": command,
           "SINGULAR_REPORT_URL": collector.url, **(extra or {})}
    env.pop("SINGULAR_PASSPHRASE", None)
    return subprocess.Popen(HOST, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _wait(predicate, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_host_pulls_runs_under_the_lease_reports_and_releases_on_sigterm(world):
    tmp_path, node, ledger, agent, registry = world
    pushed = oci.push(export(agent, ledger, tmp_path / "ada.capsule"), f"{registry.host}/togan/ada:v1")
    home = tmp_path / "volume" / "home"
    (tmp_path / "volume").mkdir()
    collector = Collector()

    proc = _start_host(tmp_path, node, collector, "oci://" + pushed["reference"], "sleep 600", home)
    assert _wait(lambda: "running" in collector.states()), proc.stderr.read() if proc.poll() is not None else ""
    running = collector.events[-1]
    assert running["agent_id"] == agent.agent_id and running["imported"] is True
    assert running["manifest_digest"] == pushed["manifest_digest"]
    assert running["_auth"] == "Bearer report-token"
    assert ledger.get_agent(agent.agent_id)["lease"] is not None
    # the customer's own key went to the agent's .env, private, and Singular's secrets did not
    dotenv = (home / ".env").read_text()
    assert "OPENROUTER_API_KEY" in dotenv and "SINGULAR" not in dotenv
    assert oct((home / ".env").stat().st_mode & 0o777) == "0o600"

    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=20) == 0
    assert collector.states()[-1] == "stopped"
    assert ledger.get_agent(agent.agent_id)["lease"] is None

    # second start: the volume already holds the agent; no capsule is fetched again
    proc = _start_host(tmp_path, node, collector, "oci://nowhere.invalid/x:y", "true", home)
    assert proc.wait(timeout=30) == 0, proc.stderr.read()
    starts = [e for e in collector.events if e["state"] == "running"]
    assert starts[-1]["imported"] is False
    assert ledger.get_agent(agent.agent_id)["lease"] is None


def test_host_reports_failure_and_takes_no_lease_when_the_agent_runs_elsewhere(world):
    tmp_path, node, ledger, agent, registry = world
    pushed = oci.push(export(agent, ledger, tmp_path / "ada.capsule"), f"{registry.host}/togan/ada:v1")
    from singular.runtime import SingularGuard
    elsewhere = SingularGuard(agent, ledger, PASS)
    elsewhere.start()
    try:
        collector = Collector()
        proc = _start_host(tmp_path, node, collector, "oci://" + pushed["reference"], "true", tmp_path / "vol2")
        assert proc.wait(timeout=30) == 1
        assert collector.states()[-1] == "failed"
        assert "already running" in collector.events[-1]["detail"]
    finally:
        elsewhere.stop()


def test_hermes_hard_exit_still_seals_and_releases(world):
    """Hermes leaves a gateway run through os._exit; the lease must not be left to lapse by TTL."""
    tmp_path, node, ledger, agent, _ = world
    code = ("import os, sys\nfrom singular import keys\nkeys._SCRYPT_N = 2**14\n"
            "from singular.agent import AgentHome\nfrom singular.ledger.client import open_ledger\n"
            "from singular.runtime import SingularGuard\nfrom singular import cli\n"
            f"home = AgentHome({str(agent.home)!r})\nguard = SingularGuard(home, open_ledger({node.url!r}), {PASS!r})\n"
            "guard.start()\nwith cli._stop_before_hard_exit(guard, lambda c: print('after', c)):\n    os._exit(7)\n")
    out = subprocess.run([sys.executable, "-c", code], env={**os.environ, "PYTHONPATH": SRC},
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 7, out.stderr
    assert "after 7" in out.stdout and "sealed and released" in out.stderr
    assert ledger.get_agent(agent.agent_id)["lease"] is None


def test_reports_stay_small_whatever_the_error_says():
    collector = Collector()
    hosting.Reporter(collector.url, "t")("failed", detail="x" * 50_000)
    assert len(collector.events[-1]["detail"]) <= 1501
