"""``singular host``: the supervisor inside the hosted-agent container (``singular/hosting/Dockerfile``).

One container runs one agent. Everything comes from the environment, so any runner (``docker run``, a Cloud
Run worker pool, a customer's own machine) can start the same image the same way:

==============================  =====================================================================
``SINGULAR_LEDGER``             ledger URL (required)
``SINGULAR_HOME``               agent home, a persistent volume (default ``/agent/home``)
``SINGULAR_CAPSULE``            where to get the agent the first time: ``oci://registry/repo@sha256:…``,
                                an ``https://`` URL, or a file path. Ignored once the home holds an agent.
``SINGULAR_CAPSULE_DIGEST``     ``sha256:…`` the capsule file must hash to (for URL / file sources)
``SINGULAR_SECRETS_FILE``       ``KEY=value`` lines (default ``/run/secrets/singular.env``). ``SINGULAR_*``
                                keys stay in this process; every other line becomes the agent's ``.env``
                                (the customer's model key and the like).
``SINGULAR_CONFIG``             a ``config.yaml`` to install (the agent's model / platform settings)
``SINGULAR_COMMAND``            what to run under the lease (default ``hermes gateway run``)
``SINGULAR_REPORT_URL``         optional control plane endpoint; state changes are POSTed there
``SINGULAR_REPORT_TOKEN``       bearer token for it (put it in the secrets file)
==============================  =====================================================================

The agent needs ``SINGULAR_PASSPHRASE`` (its own key) and, for the first start, ``SINGULAR_CAPSULE_PASSPHRASE``.
The *owner* key never belongs on a host: a secrets file that carries an owner passphrase is refused.

Reports are a courtesy for the control plane's panel. The ledger stays the source of truth for "running":
the lease is there, and nobody can fake it from outside this container.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import signal
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import agent as A
from .cli import _enable_hermes_plugin, run_guarded
from .errors import CapsuleError, SingularError
from .ledger.client import open_ledger
from .runtime import SingularGuard

DEFAULT_HOME = "/agent/home"
DEFAULT_SECRETS = "/run/secrets/singular.env"
DEFAULT_COMMAND = "hermes gateway run"
MAX_DOWNLOAD = 8 << 30
# Never accepted on a host: the owner key is what can sell, retire or re-key the agent.
_FORBIDDEN = ("SINGULAR_OWNER_PASSPHRASE",)


class _Stop(KeyboardInterrupt):
    """SIGTERM before the agent command took over its own signal handling."""


def parse_env_file(text: str) -> dict[str, str]:
    """A small, strict dotenv: ``KEY=value``, optional ``export``, optional matching quotes, ``#`` comments."""
    values: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").strip()
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not key.replace("_", "").isalnum() or key[0].isdigit():
            raise SingularError(f"secrets file line {number} is not KEY=value")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key] = value
    return values


def load_secrets(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Split the secrets file into (Singular's own, the agent's ``.env``)."""
    if not path.exists():
        return {}, {}
    values = parse_env_file(path.read_text(encoding="utf-8"))
    for key in _FORBIDDEN:
        if key in values:
            raise SingularError(f"{key} must never be given to a host; the owner key stays with the owner")
    own = {k: v for k, v in values.items() if k.startswith("SINGULAR_")}
    rest = {k: v for k, v in values.items() if not k.startswith("SINGULAR_")}
    return own, rest


def write_dotenv(home: Path, values: dict[str, str]) -> None:
    """The agent's ``.env`` is operator secrets, never sealed and never in a capsule; it is rewritten each start."""
    if not values:
        return
    lines = [f"{key}={json.dumps(value)}" for key, value in sorted(values.items())]
    path = home / ".env"
    tmp = home / ".env.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    os.replace(tmp, path)


class Reporter:
    def __init__(self, url: str | None, token: str | None):
        self.url, self.token = url, token

    def __call__(self, state: str, **fields) -> None:
        print(f"singular-host: {state} " + json.dumps(fields, sort_keys=True, default=str), file=sys.stderr)
        if not self.url:
            return
        fields = {k: (v[:1500] + "…" if isinstance(v, str) and len(v) > 1500 else v) for k, v in fields.items()}
        body = json.dumps({"state": state, "ts": int(time.time() * 1000), **fields}, default=str).encode()
        request = urllib.request.Request(self.url, data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
        if self.token:
            request.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(request, timeout=10):  # noqa: S310 - operator-configured endpoint
                pass
        except (urllib.error.URLError, OSError) as exc:  # the panel is a courtesy; the agent keeps running
            print(f"singular-host: report to control plane failed: {exc}", file=sys.stderr)


def fetch_capsule(source: str, out: Path, expect_digest: str | None = None) -> dict:
    """Bring the capsule to ``out``. Returns where it came from and what it hashes to."""
    if source.startswith("oci://"):
        from . import oci
        pulled = oci.pull(source, out)
        file_digest = pulled["layer_digest"]
        info = {"source": source, "manifest_digest": pulled["manifest_digest"]}
    elif source.startswith(("https://", "http://")):
        if source.startswith("http://") and os.environ.get("SINGULAR_ALLOW_HTTP") != "1":
            raise CapsuleError("refusing a capsule over plain http (set SINGULAR_ALLOW_HTTP=1 for local tests)")
        hasher, written = hashlib.sha256(), 0
        with urllib.request.urlopen(source, timeout=60) as response, open(out, "wb") as handle:  # noqa: S310
            while block := response.read(1 << 20):
                written += len(block)
                if written > MAX_DOWNLOAD:
                    raise CapsuleError("capsule download is unreasonably large")
                hasher.update(block)
                handle.write(block)
        file_digest = "sha256:" + hasher.hexdigest()
        info = {"source": source}
    else:
        shutil.copyfile(source, out)
        file_digest = "sha256:" + hashlib.sha256(Path(out).read_bytes()).hexdigest()
        info = {"source": "file"}
    if expect_digest and file_digest != expect_digest:
        raise CapsuleError(f"capsule hashes to {file_digest}, expected {expect_digest}")
    return {**info, "capsule_digest": file_digest}


def prepare_home(home_path: Path, ledger_url: str, env: dict[str, str]) -> tuple[A.AgentHome, dict]:
    """Import the agent into an empty home on first start; on later starts, use what the volume holds."""
    home = A.AgentHome(home_path)
    if home.is_singular:
        return home, {"imported": False}
    source = env.get("SINGULAR_CAPSULE")
    if not source:
        raise SingularError(f"{home_path} holds no agent yet and SINGULAR_CAPSULE is not set")
    passphrase = env.get("SINGULAR_CAPSULE_PASSPHRASE")
    if not passphrase:
        raise SingularError("SINGULAR_CAPSULE_PASSPHRASE is needed to open the capsule on first start")
    home_path.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(home_path / ".singular-import", ignore_errors=True)  # a first start that died half way
    # Hermes or a stray mount may have left files; a capsule only unpacks into an empty folder.
    if any(home_path.iterdir()):
        raise SingularError(f"{home_path} is not empty but holds no Singular agent; refusing to mix the two")
    with tempfile.TemporaryDirectory(prefix="capsule-") as tmp:
        capsule_path = Path(tmp) / "agent.capsule"
        fetched = fetch_capsule(source, capsule_path, env.get("SINGULAR_CAPSULE_DIGEST"))
        from .capsule import read_header
        if read_header(capsule_path)["meta"].get("for_sale", True):
            raise SingularError("this capsule was made for a sale (it carries no agent key) and cannot run; "
                                "the owner exports a hosted agent with `singular export --move`")
        # unpack inside the volume (same filesystem), then move the verified files up: the volume root itself
        # cannot be renamed, and import_capsule wants a fresh folder
        staging = home_path / ".singular-import"
        A.import_capsule(capsule_path, staging, passphrase, open_ledger(ledger_url))
    for child in list(staging.iterdir()):
        os.replace(child, home_path / child.name)
    staging.rmdir()
    return A.AgentHome(home_path), {"imported": True, **fetched}


def main(argv: list[str] | None = None) -> int:  # noqa: ARG001 - configured by environment only
    env = dict(os.environ)
    secrets_own, dotenv = load_secrets(Path(env.get("SINGULAR_SECRETS_FILE", DEFAULT_SECRETS)))
    env.update(secrets_own)
    report = Reporter(env.get("SINGULAR_REPORT_URL"), env.get("SINGULAR_REPORT_TOKEN"))

    def _sigterm(signum, _frame):
        raise _Stop()

    signal.signal(signal.SIGTERM, _sigterm)
    guard = None
    try:
        ledger_url = env.get("SINGULAR_LEDGER")
        if not ledger_url:
            raise SingularError("SINGULAR_LEDGER is not set")
        report("starting")
        home, how = prepare_home(Path(env.get("SINGULAR_HOME", DEFAULT_HOME)), ledger_url, env)
        if home.identity.get("ledger_url") != ledger_url:  # the agent follows the ledger this host was told to use
            home.save_identity({**home.identity, "ledger_url": ledger_url})
        write_dotenv(home.home, dotenv)
        if config := env.get("SINGULAR_CONFIG"):
            shutil.copyfile(config, home.home / "config.yaml")
        _enable_hermes_plugin(home.home)
        passphrase = env.get("SINGULAR_PASSPHRASE")
        if not passphrase:
            raise SingularError("SINGULAR_PASSPHRASE (the agent's own key) is not set")
        guard = SingularGuard(home, open_ledger(ledger_url), passphrase)
        started = guard.start()
        for key in ("SINGULAR_PASSPHRASE", "SINGULAR_CAPSULE_PASSPHRASE", "SINGULAR_REGISTRY_PASSWORD",
                    "SINGULAR_REPORT_TOKEN"):
            os.environ.pop(key, None)
        report("running", agent_id=started["agent_id"], lease=started["lease"]["no"], epoch=started["epoch"], **how)
        agent_id = guard.agent_id
        code = run_guarded(guard, shlex.split(env.get("SINGULAR_COMMAND", DEFAULT_COMMAND)),
                           on_hard_exit=lambda c: report("stopped", agent_id=agent_id, exit_code=c))
        guard.stop()
        report("stopped", agent_id=guard.agent_id, exit_code=code)
        return code
    except _Stop:
        if guard is not None:
            guard.stop()
        report("stopped", agent_id=guard.agent_id if guard else None, exit_code=0, detail="SIGTERM")
        return 0
    except Exception as exc:  # noqa: BLE001 - whatever went wrong, let go of the lease and say so
        if guard is not None:
            try:
                guard.stop()
            except Exception:  # noqa: BLE001
                pass
        detail = str(exc) if isinstance(exc, SingularError) else f"{type(exc).__name__}: {exc}"
        report("failed", detail=detail)
        return 1


if __name__ == "__main__":
    sys.exit(main())
