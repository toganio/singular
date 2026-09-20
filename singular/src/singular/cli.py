"""``singular`` command line. Passphrases are never taken as arguments (they would land in shell
history and ``ps``): they come from environment variables or an interactive prompt."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__, agent as A
from .bank import BankOwner, DirStore, attach_bank, attached_banks, bank_transfer_request, detach_bank
from .errors import SingularError
from .keys import SigningKey, load_keystore, save_keystore, unwrap_key, wrap_key
from .ledger.chain import Chain
from .ledger.client import HttpLedger, open_ledger
from .ledger.node import LedgerNode
from .runtime import SingularGuard


def _secret(env: str, prompt: str, confirm: bool = False) -> str:
    value = os.environ.get(env)
    if value:
        return value
    if not sys.stdin.isatty():
        raise SingularError(f"set {env} (no terminal to prompt on)")
    value = getpass.getpass(prompt + ": ")
    if confirm and getpass.getpass(prompt + " (again): ") != value:
        raise SingularError("passphrases do not match")
    return value


def _owner_key(args, confirm: bool = False) -> SigningKey:
    path = Path(args.owner_key) if getattr(args, "owner_key", None) else A.default_owner_dir() / "owner.keystore.json"
    return A.load_key(path, _secret("SINGULAR_OWNER_PASSPHRASE", "Owner passphrase", confirm), "owner")


def _home(args) -> A.AgentHome:
    home = A.AgentHome(args.home or os.environ.get("HERMES_HOME") or Path.home() / ".hermes")
    if not home.is_singular:
        raise SingularError(f"{home.home} is not a Singular agent (run `singular init`)")
    return home


def _ledger_for(home: A.AgentHome, args):
    return open_ledger(getattr(args, "ledger", None) or home.identity["ledger_url"])


def _print(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str))


# -- commands ----------------------------------------------------------------------------------

def cmd_owner_new(args) -> int:
    path = Path(args.out) if args.out else A.default_owner_dir() / "owner.keystore.json"
    key = A.create_owner_key(path, _secret("SINGULAR_OWNER_PASSPHRASE", "New owner passphrase", confirm=True))
    _print({"owner_pub": key.public_hex, "keystore": str(path),
            "warning": "Back this file up. Whoever holds it and its passphrase owns your agents."})
    return 0


def cmd_init(args) -> int:
    ledger = open_ledger(args.ledger)
    home = A.init_agent(args.home, ledger, args.ledger, _owner_key(args),
                        _secret("SINGULAR_PASSPHRASE", "New agent passphrase", confirm=True),
                        name=args.name, function=args.function, lease_ttl_ms=args.lease_ttl * 1000,
                        allow_owner_attest=args.allow_owner_edits)
    _enable_hermes_plugin(home.home)
    _print({"agent_id": home.agent_id, "memory_bank": home.bank_id, "home": str(home.home), "chain_id": home.identity["chain_id"]})
    return 0


def _enable_hermes_plugin(home: Path) -> None:
    """Hermes plugins are opt-in per profile: add ``singular`` to ``plugins.enabled``."""
    config = home / "config.yaml"
    try:
        import yaml  # Hermes depends on PyYAML; absent means this is not a Hermes install
    except ImportError:
        return
    data = {}
    if config.exists():
        data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return
    plugins = data.setdefault("plugins", {})
    enabled = plugins.get("enabled") if isinstance(plugins.get("enabled"), list) else []
    if "singular" not in enabled:
        plugins["enabled"] = [*enabled, "singular"]
        config.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def cmd_status(args) -> int:
    home = _home(args)
    report = A.verify(home, _ledger_for(home, args))
    _print(report)
    return 0 if report["ok"] else 2


def cmd_restore(args) -> int:
    home = _home(args)
    ledger = _ledger_for(home, args)
    record = A.require_agent(ledger, home.agent_id)
    bank = A.require_bank(ledger, record["memory_bank"])
    _print({"core": home.restore("core", record["seal"]["root"]), "memory": home.restore("memory", bank["seal"]["root"])})
    return 0


def cmd_run(args) -> int:
    home = _home(args)
    command = [c for c in args.command if c != "--"]
    if not command:
        raise SingularError("usage: singular run --home H -- <command ...>")
    guard = SingularGuard(home, _ledger_for(home, args), _secret("SINGULAR_PASSPHRASE", "Agent passphrase"))
    started = guard.start()
    print(f"singular: {started['agent_id']} holds the run lease #{started['lease']['no']}", file=sys.stderr)
    os.environ["HERMES_HOME"] = str(home.home)
    os.environ.pop("SINGULAR_PASSPHRASE", None)
    try:
        if command[0] == "hermes":
            try:
                from hermes_cli.main import main as hermes_main  # same process: the plugin logs every tool call
            except ImportError:
                hermes_main = None
            if hermes_main is not None:
                from . import hermes_plugin
                hermes_plugin.adopt_guard(guard)
                sys.argv = command
                try:
                    return int(hermes_main() or 0)
                except SystemExit as exc:
                    return int(exc.code or 0) if not isinstance(exc.code, str) else 1
        return subprocess.call(command)  # noqa: S603 - the operator's own command
    finally:
        guard.stop()
        print("singular: sealed and released", file=sys.stderr)


def cmd_export(args) -> int:
    home = _home(args)
    header = A.export_capsule(home, _ledger_for(home, args), Path(args.out),
                              _secret("SINGULAR_CAPSULE_PASSPHRASE", "Capsule passphrase", confirm=True),
                              for_sale=not args.move)
    _print({"capsule": args.out, **header["meta"]})
    return 0


def cmd_import(args) -> int:
    ledger = open_ledger(args.ledger)
    home = A.import_capsule(Path(args.capsule), Path(args.home), _secret("SINGULAR_CAPSULE_PASSPHRASE", "Capsule passphrase"), ledger)
    _print({"agent_id": home.agent_id, "home": str(home.home), "verified": True})
    return 0


def cmd_transfer(args) -> int:
    if args.step == "request":
        home = _home(args)
        request = A.transfer_request(home, _ledger_for(home, args), _owner_key(args),
                                     _secret("SINGULAR_NEW_PASSPHRASE", "New agent passphrase", confirm=True))
        Path(args.file).write_text(json.dumps(request, indent=2), encoding="utf-8")
        _print({"request": args.file, "next": "send this file to the current owner"})
    elif args.step == "approve":
        request = json.loads(Path(args.file).read_text(encoding="utf-8"))
        _print(A.transfer_approve(request, open_ledger(args.ledger), _owner_key(args)))
    else:
        home = _home(args)
        A.transfer_finalize(home, _ledger_for(home, args))
        _print({"agent_id": home.agent_id, "transferred": True})
    return 0


def cmd_owner_action(args) -> int:
    home = _home(args)
    ledger, key, chain_id = _ledger_for(home, args), _owner_key(args), home.identity["chain_id"]
    if args.action == "revoke-lease":
        _print(A.revoke_lease(home, ledger, chain_id, key))
    elif args.action == "retire":
        _print(A.retire(home.agent_id, ledger, chain_id, key))
    elif args.action == "rollback":
        _print(A.rollback(home, ledger, key, args.root))
    else:
        _print(A.owner_attest(home, ledger, key, args.reason))
    return 0


def cmd_prove(args) -> int:
    _print(A.prove_ownership(_owner_key(args), args.agent, args.challenge, args.site))
    return 0


def cmd_history(args) -> int:
    ledger = open_ledger(args.ledger)
    _print([{"height": h["height"], "ts": h["ts"], "type": h["tx"]["type"], "txid": h["txid"],
             "signers": [s["role"] for s in h["tx"]["sigs"]]} for h in ledger.history(args.id)])
    return 0


def cmd_ledger(args) -> int:
    if args.ledger_cmd == "init":
        key = SigningKey.generate()
        save_keystore(Path(args.validator_key), wrap_key(key, _secret("SINGULAR_VALIDATOR_PASSPHRASE", "New validator passphrase", True), label="validator"))
        chain = Chain.create(args.db, args.name, key)
        _print({"chain_id": chain.chain_id, "validator": key.public_hex})
    elif args.ledger_cmd == "serve":
        key = unwrap_key(load_keystore(Path(args.validator_key)), _secret("SINGULAR_VALIDATOR_PASSPHRASE", "Validator passphrase"))
        tokens = [t for t in os.environ.get("SINGULAR_REGISTER_TOKENS", "").split(",") if t]
        node = LedgerNode(Chain(args.db, key), args.host, args.port, register_tokens=tokens, trust_proxy=args.trust_proxy)
        print(f"singular ledger {node.chain.chain_id[:16]} listening on {node.url}", file=sys.stderr)
        try:
            node.serve_forever()
        except KeyboardInterrupt:
            pass
    else:
        audit = HttpLedger(args.url).audit(args.chain_id)
        audit.pop("state")
        _print({"verified": True, **audit})
    return 0


def cmd_bank(args) -> int:
    if args.bank_cmd in ("attach", "detach", "attached"):
        home = _home(args)
        if args.bank_cmd == "attach":
            _print(attach_bank(home, _ledger_for(home, args), args.bank, args.store, args.name))
        elif args.bank_cmd == "detach":
            _print({"detached": detach_bank(home, args.bank)})
        else:
            _print(attached_banks(home))
        return 0
    ledger = open_ledger(args.ledger)
    store = DirStore(args.store)
    if args.bank_cmd == "create":
        owner = BankOwner.create(store, ledger, _owner_key(args), args.name, allow_owner_write=not args.agents_only)
        _print({"bank_id": owner.bank_id, "store": args.store})
    elif args.bank_cmd in ("grant", "revoke", "rekey"):
        owner = BankOwner(store, ledger, _owner_key(args))
        if args.bank_cmd == "grant":
            import time
            expires = int(time.time() * 1000) + args.days * 86_400_000 if args.days else 0
            _print(owner.grant(args.agent, "rw" if args.write else "r", expires))
        elif args.bank_cmd == "revoke":
            _print(owner.revoke(args.agent))
        else:
            _print(owner.rekey())
    elif args.bank_cmd == "transfer-request":
        request = bank_transfer_request(ledger, args.bank, _owner_key(args))
        Path(args.file).write_text(json.dumps(request, indent=2), encoding="utf-8")
        _print({"request": args.file})
    elif args.bank_cmd == "transfer-approve":
        _print(BankOwner(store, ledger, _owner_key(args)).transfer_approve(json.loads(Path(args.file).read_text(encoding="utf-8"))))
    else:  # owner-side pull / push of a working copy
        mount = BankOwner(store, ledger, _owner_key(args)).mount(args.dir)
        _print(mount.pull() if args.bank_cmd == "pull" else (mount.push() or {"unchanged": True}))
    return 0


# -- parser ------------------------------------------------------------------------------------

def build_parser(parser: argparse.ArgumentParser | None = None) -> argparse.ArgumentParser:
    parser = parser or argparse.ArgumentParser(prog="singular", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=f"singular {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add(name, func, help_text, home=False, owner=False, ledger=False):
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(singular_func=func)
        if home:
            p.add_argument("--home", help="agent home (default: $HERMES_HOME or ~/.hermes)")
            p.add_argument("--ledger", help="override the ledger url stored in the agent")
        if ledger:
            p.add_argument("--ledger", required=True, help="ledger url, e.g. https://ledger.example")
        if owner:
            p.add_argument("--owner-key", help="owner keystore (default: ~/.singular-owner/owner.keystore.json)")
        return p

    p = add("owner-new", cmd_owner_new, "create an owner key")
    p.add_argument("--out")
    p = add("init", cmd_init, "register an agent folder on the ledger", owner=True, ledger=True)
    p.add_argument("--home", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--function", required=True, help="what this agent is for (public, permanent)")
    p.add_argument("--lease-ttl", type=int, default=120, help="seconds a run lease lives without a heartbeat")
    p.add_argument("--allow-owner-edits", action="store_true", help="permit owner-attested manual edits (recorded on the ledger)")
    add("status", cmd_status, "verify files against the ledger", home=True)
    add("verify", cmd_status, "alias of status", home=True)
    add("restore", cmd_restore, "put files back to the last sealed state", home=True)
    p = add("run", cmd_run, "verify, take the run lease, run a command, seal and release", home=True)
    p.add_argument("command", nargs=argparse.REMAINDER)
    p = add("export", cmd_export, "pack the agent into an encrypted capsule", home=True)
    p.add_argument("--out", required=True)
    p.add_argument("--move", action="store_true", help="moving your OWN agent: include its key and action records (never use for a sale)")
    p = add("import", cmd_import, "unpack and verify a capsule", ledger=True)
    p.add_argument("capsule")
    p.add_argument("--home", required=True)
    p = add("transfer", cmd_transfer, "sell / hand over an agent", home=True, owner=True)
    p.add_argument("step", choices=["request", "approve", "finalize"])
    p.add_argument("--file", default="transfer-request.json")
    p = add("owner", cmd_owner_action, "owner-only actions", home=True, owner=True)
    p.add_argument("action", choices=["revoke-lease", "retire", "rollback", "attest"])
    p.add_argument("--root")
    p.add_argument("--reason", default="owner edit")
    p = add("prove", cmd_prove, "prove to a service that you own an agent (signs a one-time challenge locally)", owner=True)
    p.add_argument("--agent", required=True)
    p.add_argument("--challenge", required=True)
    p.add_argument("--site", required=True, help="the service asking, exactly as it printed it")
    p = add("history", cmd_history, "audit trail of an agent or bank", ledger=True)
    p.add_argument("id")

    p = sub.add_parser("ledger", help="run or audit a ledger node")
    p.set_defaults(singular_func=cmd_ledger)
    lsub = p.add_subparsers(dest="ledger_cmd", required=True)
    for name in ("init", "serve"):
        q = lsub.add_parser(name)
        q.add_argument("--db", required=True)
        q.add_argument("--validator-key", required=True)
        if name == "init":
            q.add_argument("--name", default="singular")
        else:
            q.add_argument("--host", default="127.0.0.1")
            q.add_argument("--port", type=int, default=8765)
            q.add_argument("--trust-proxy", action="store_true", help="rate-limit by the last X-Forwarded-For hop (only behind your own proxy)")
    q = lsub.add_parser("audit", help="download the whole chain and re-verify every rule")
    q.add_argument("--url", required=True)
    q.add_argument("--chain-id", required=True)

    p = sub.add_parser("bank", help="external memory banks")
    p.set_defaults(singular_func=cmd_bank)
    bsub = p.add_subparsers(dest="bank_cmd", required=True)
    for name in ("create", "grant", "revoke", "rekey", "pull", "push", "transfer-request", "transfer-approve"):
        q = bsub.add_parser(name)
        q.add_argument("--ledger", required=True)
        q.add_argument("--store", required=True, help="folder holding the bank's ciphertext")
        q.add_argument("--owner-key")
        if name == "create":
            q.add_argument("--name", required=True)
            q.add_argument("--agents-only", action="store_true", help="forbid the owner from writing content")
        if name in ("grant", "revoke"):
            q.add_argument("--agent", required=True)
        if name == "grant":
            q.add_argument("--write", action="store_true")
            q.add_argument("--days", type=int, default=0, help="rent: grant expires after N days")
        if name in ("pull", "push"):
            q.add_argument("--dir", required=True)
        if name.startswith("transfer"):
            q.add_argument("--file", default="bank-transfer-request.json")
        if name == "transfer-request":
            q.add_argument("--bank", required=True)
    for name in ("attach", "detach", "attached"):   # tell an agent home which banks it may use, and where they live
        q = bsub.add_parser(name)
        q.add_argument("--home")
        q.add_argument("--ledger")
        if name != "attached":
            q.add_argument("--bank", required=True, help="bank id" + (" or name" if name == "detach" else ""))
        if name == "attach":
            q.add_argument("--store", required=True)
            q.add_argument("--name")
    return parser


def dispatch(args) -> int:
    try:
        return int(args.singular_func(args) or 0)
    except SingularError as exc:
        print(f"singular: {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    return dispatch(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
