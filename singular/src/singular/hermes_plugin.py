"""Hermes Agent plugin: makes a Hermes profile run as a Singular agent.

Singular never patches Hermes. It plugs into the official plugin entry point
(``hermes_agent.plugins``) and uses only public hooks, so a new Hermes release is adopted by
merging it and running ``tests/test_hermes_contract.py``:

* ``on_session_start``   - first session in this process: verify seals, take the run lease.
* ``pre_tool_call``      - the one hook that can veto. No provable lease -> every tool is blocked.
* ``post_tool_call``     - liability log; re-seal right after memory / skill writes.
* ``on_skill_lifecycle`` - re-seal when a skill is created, edited or removed.
* ``on_session_end`` / ``on_session_finalize`` - anchor actions and re-seal.
* process exit           - final seal, release the lease.

The plugin is inert for ordinary Hermes homes: everything keys off ``<HERMES_HOME>/.singular/``.
The agent passphrase comes from ``SINGULAR_PASSPHRASE`` (or a prompt when there is a terminal).
"""

from __future__ import annotations

import atexit
import getpass
import logging
import os
import sys
import threading
from pathlib import Path

from .agent import AgentHome
from .errors import SingularError
from .ledger.client import open_ledger
from .runtime import SingularGuard

logger = logging.getLogger("singular.hermes")

# Hooks this plugin relies on. tests/test_hermes_contract.py asserts Hermes still offers them.
HOOKS_USED = ("on_session_start", "pre_tool_call", "post_tool_call", "on_skill_lifecycle",
              "on_session_end", "on_session_finalize")
# Tools after which the agent has (probably) written to itself.
SELF_WRITE_TOOLS = ("memory", "skill_manage", "skill_manager", "skills", "cron")

_lock = threading.RLock()
_guard: SingularGuard | None = None
_failure: str | None = None


def _hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home  # type: ignore
        return Path(get_hermes_home())
    except Exception:  # noqa: BLE001 - running outside Hermes (tests)
        return Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))


def _passphrase() -> str:
    value = os.environ.pop("SINGULAR_PASSPHRASE", "")
    if value:
        return value
    if sys.stdin is not None and sys.stdin.isatty():
        return getpass.getpass("Singular agent passphrase: ")
    raise SingularError("SINGULAR_PASSPHRASE is not set and there is no terminal to ask on")


def adopt_guard(guard: SingularGuard) -> None:
    """Used by ``singular run``: the launcher already verified and leased; the plugin takes it from there."""
    global _guard, _failure
    with _lock:
        _guard, _failure = guard, None


def current_guard() -> SingularGuard | None:
    return _guard


def _ensure_guard() -> SingularGuard | None:
    """Start the guard once per process. Returns None for non-Singular homes."""
    global _guard, _failure
    with _lock:
        if _guard is not None or _failure is not None:
            return _guard
        home = AgentHome(_hermes_home())
        if not home.is_singular:
            return None
        try:
            guard = SingularGuard(home, open_ledger(home.identity["ledger_url"]), _passphrase())
            guard.start()
        except Exception as exc:  # noqa: BLE001 - any failure means "do not act"
            _failure = str(exc)
            logger.error("Singular refused to start this agent: %s", exc)
            return None
        _guard = guard
        atexit.register(_shutdown)
        logger.info("Singular: %s holds the run lease (lease #%s)", guard.agent_id, guard.lease["no"])
        return guard


def _shutdown() -> None:
    guard = _guard
    if guard is not None:
        try:
            guard.stop()
        except Exception as exc:  # noqa: BLE001
            logger.error("Singular shutdown was not clean: %s", exc)


def _is_singular_home() -> bool:
    return AgentHome(_hermes_home()).is_singular


# -- hooks -------------------------------------------------------------------------------------

def on_session_start(**_kwargs):
    _ensure_guard()


def pre_tool_call(tool_name: str = "", **_kwargs):
    if _guard is None and _failure is None and not _is_singular_home():
        return None
    guard = _ensure_guard()
    try:
        if guard is None:
            raise SingularError(_failure or "guard not running")
        guard.check()
    except SingularError as exc:
        return {"action": "block",
                "message": f"BLOCKED by Singular: this agent cannot prove it is the one running instance ({exc}). "
                           f"Tool '{tool_name}' was not executed."}
    return None


def post_tool_call(tool_name: str = "", args=None, result=None, status=None, session_id: str = "",
                   error_message=None, **_kwargs):
    guard = _guard
    if guard is None:
        return None
    try:
        guard.record_action("tool", tool_name, args or {}, result, status=str(status or "ok"),
                            summary=str(error_message or "")[:200], session=str(session_id or ""))
        if any(tool_name == name or tool_name.startswith(name + "_") for name in SELF_WRITE_TOOLS):
            guard.reseal(f"after {tool_name}")
    except SingularError as exc:
        logger.error("Singular could not record '%s': %s", tool_name, exc)
    return None


def on_skill_lifecycle(**_kwargs):
    _reseal("skill lifecycle")


def on_session_end(**_kwargs):
    _reseal("session end", anchor=True)


def on_session_finalize(**_kwargs):
    _reseal("session finalize", anchor=True)


def _reseal(reason: str, anchor: bool = False) -> None:
    guard = _guard
    if guard is None:
        return
    try:
        if anchor:
            guard.anchor_actions()
        guard.reseal(reason)
    except SingularError as exc:
        logger.error("Singular reseal (%s) failed: %s", reason, exc)


def _setup_cli(parser) -> None:
    from .cli import build_parser
    build_parser(parser)


def _handle_cli(args) -> int:
    from .cli import dispatch
    return dispatch(args)


def register(ctx) -> None:
    for name in HOOKS_USED:
        ctx.register_hook(name, globals()[name])
    try:
        ctx.register_cli_command("singular", "Sealed, single-instance, transferable agent identity (Singular)",
                                 _setup_cli, _handle_cli)
    except Exception as exc:  # noqa: BLE001 - CLI sugar must never stop the hooks from loading
        logger.debug("singular CLI command not registered: %s", exc)
