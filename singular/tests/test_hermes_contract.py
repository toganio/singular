"""The compatibility contract with Hermes Agent.

Singular touches Hermes only through the surface asserted here. When a new Hermes release breaks
something, this file is where it shows first, and ``singular/hermes_plugin.py`` is the only file
that should need adapting. Skipped when Hermes is not importable (the package also runs standalone).
"""
import inspect
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if (REPO_ROOT / "hermes_cli").is_dir() and str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import os  # noqa: E402

if os.environ.get("SINGULAR_REQUIRE_HERMES"):
    import hermes_cli.plugins as plugins  # CI: a silent skip here would be a fake green
else:
    plugins = pytest.importorskip("hermes_cli.plugins", reason="Hermes Agent is not importable here")

from singular import hermes_plugin, tree  # noqa: E402


def test_every_hook_we_use_still_exists():
    missing = [h for h in hermes_plugin.HOOKS_USED if h not in plugins.VALID_HOOKS]
    assert not missing, f"Hermes dropped hooks Singular depends on: {missing}"


def test_plugin_entry_point_group_is_unchanged():
    assert plugins.ENTRY_POINTS_GROUP == "hermes_agent.plugins"


def test_context_still_offers_what_register_calls():
    ctx = plugins.PluginContext
    for method in ("register_hook", "register_cli_command"):
        assert callable(getattr(ctx, method, None)), f"PluginContext.{method} is gone"
    params = inspect.signature(ctx.register_cli_command).parameters
    assert list(params)[1:5] == ["name", "help", "setup_fn", "handler_fn"]


def test_pre_tool_call_block_directive_still_vetoes(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(plugins, "invoke_hook", lambda name, **kw: [{"action": "block", "message": "no"}] if name == "pre_tool_call" else [])
    message, _ = plugins._dispatch_pre_tool_call_hooks("terminal", {"command": "ls"}, session_id="s")
    assert message == "no"


def test_post_tool_call_payload_names():
    import model_tools
    source = inspect.getsource(model_tools._emit_post_tool_call_hook)
    for field in ("tool_name=", "args=", "result=", "status="):
        assert field in source, f"post_tool_call no longer passes {field}"


def test_home_resolution_and_secret_lists():
    from hermes_constants import get_hermes_home
    assert callable(get_hermes_home)
    from hermes_cli import backup
    hermes_secrets = set(getattr(backup, "_SECRET_FILE_NAMES", ()))
    assert hermes_secrets, "Hermes no longer exposes its secret-file list"
    unsealed = {name for name in hermes_secrets if "/" not in name} - tree.SECRET_NAMES
    assert not unsealed, f"Hermes treats these as secrets but Singular would seal/export them: {unsealed}"


def test_memory_and_skills_still_live_where_we_seal_them():
    from hermes_cli.config import _HERMES_HOME_SUBDIRS
    assert {"memories", "skills", "cron"} <= set(_HERMES_HOME_SUBDIRS)
