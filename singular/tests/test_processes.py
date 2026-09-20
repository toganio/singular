"""The same promises, but with real operating-system processes talking to a real HTTP ledger node.
Threads inside one test process prove the rules; these prove the *deployment shape*."""
import os
import shutil
import signal
import subprocess
import sys
import time

import pytest

from conftest import PASS, make_home
from singular import agent as A
from singular.keys import SigningKey
from singular.ledger.chain import Chain
from singular.ledger.client import HttpLedger
from singular.ledger.node import LedgerNode

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
ENV = {**os.environ, "SINGULAR_PASSPHRASE": PASS, "PYTHONPATH": SRC, "SINGULAR_FAST_KDF_FOR_TESTS": "1"}
CLI = [sys.executable, "-c", "import sys; from singular import keys\nkeys._SCRYPT_N = 2**14\nfrom singular.cli import main; sys.exit(main(sys.argv[1:]))"]


@pytest.fixture
def world(tmp_path):
    chain = Chain.create(tmp_path / "chain.db", "proc", SigningKey.generate())
    node = LedgerNode(chain, writes_per_minute=0, reads_per_minute=0).start()
    ledger, owner = HttpLedger(node.url), SigningKey.generate()
    yield tmp_path, node, chain, ledger, owner
    try:
        node.stop()
    except Exception:  # noqa: BLE001 - some tests stop it themselves
        pass
    chain.close()


def new_agent(tmp_path, ledger, url, owner, ttl_ms):
    return A.init_agent(make_home(tmp_path / "home"), ledger, url, owner, PASS, name="Ada", function="x", lease_ttl_ms=ttl_ms)


def run(home, *command, **kw):
    return subprocess.Popen([*CLI, "run", "--home", str(home), "--", *command], env=ENV, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True, **kw)


def wait_for(predicate, seconds=15):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_eight_processes_start_the_same_agent_at_once_and_exactly_one_runs(world):
    tmp_path, node, _, ledger, owner = world
    agent = new_agent(tmp_path, ledger, node.url, owner, 60_000)
    homes = [agent.home] + [tmp_path / f"copy{i}" for i in range(7)]
    for copy in homes[1:]:
        shutil.copytree(agent.home, copy)
    procs = [run(home, sys.executable, "-c", "import time; time.sleep(2.5)") for home in homes]
    results = [(p.wait(timeout=60), p.stderr.read()) for p in procs]
    winners = [err for code, err in results if code == 0]
    losers = [err for code, err in results if code != 0]
    assert len(winners) == 1 and len(losers) == 7, [(c, e[-200:]) for c, e in results]
    assert all("already running somewhere else" in err or "refused the run lease" in err for err in losers), losers
    record = ledger.get_agent(agent.agent_id)
    assert record["lease"] is None and record["lease_count"] == 1      # one lease was ever granted, and it was released
    assert A.verify(agent, ledger)["ok"]


def test_kill_dash_nine_keeps_the_lease_until_it_expires_or_the_owner_revokes(world):
    tmp_path, node, _, ledger, owner = world
    agent = new_agent(tmp_path, ledger, node.url, owner, 3_000)
    victim = run(agent.home, sys.executable, "-c", "import time; time.sleep(60)")
    assert wait_for(lambda: ledger.get_agent(agent.agent_id)["lease"] is not None)
    os.killpg(victim.pid, signal.SIGKILL)                           # no goodbye: nothing sealed, nothing released
    victim.wait(timeout=10)
    retry = run(agent.home, sys.executable, "-c", "pass")
    assert retry.wait(timeout=30) != 0 and "already running somewhere else" in retry.stderr.read()
    # path 1: the owner frees it at once
    A.revoke_lease(agent, ledger, agent.identity["chain_id"], owner)
    freed = run(agent.home, sys.executable, "-c", "pass")
    assert freed.wait(timeout=30) == 0, freed.stderr.read()
    # path 2: nobody does anything; the lease simply runs out
    victim2 = run(agent.home, sys.executable, "-c", "import time; time.sleep(60)")
    assert wait_for(lambda: ledger.get_agent(agent.agent_id)["lease"] is not None)
    os.killpg(victim2.pid, signal.SIGKILL)
    victim2.wait(timeout=10)
    time.sleep(3.3)
    later = run(agent.home, sys.executable, "-c", "pass")
    assert later.wait(timeout=30) == 0, later.stderr.read()


DRIVER = """
import sys, time
from singular import keys; keys._SCRYPT_N = 2**14
from singular.agent import AgentHome
from singular.errors import SingularError
from singular.ledger.client import HttpLedger
from singular.runtime import SingularGuard
home = AgentHome(sys.argv[1])
guard = SingularGuard(home, HttpLedger(home.identity["ledger_url"], timeout=1.0), sys.argv[2])
guard.start(); print("STARTED", flush=True)
while True:
    try:
        n = guard.begin_action("tick", {}); guard.end_action(n, "tick", {}); print("ACTED", flush=True)
    except SingularError as exc:
        print("BLOCKED", exc, flush=True); sys.exit(3)
    time.sleep(0.2)
"""


def test_when_the_ledger_disappears_the_agent_stops_acting_within_one_lease(world):
    tmp_path, node, _, ledger, owner = world
    agent = new_agent(tmp_path, ledger, node.url, owner, 2_000)
    proc = subprocess.Popen([sys.executable, "-c", DRIVER, str(agent.home), PASS], env=ENV, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "STARTED"
    assert proc.stdout.readline().strip() == "ACTED"
    node.stop()                                                       # network partition / ledger outage
    cut = time.time()
    assert proc.wait(timeout=20) == 3, proc.stderr.read()
    out = proc.stdout.read()
    assert "BLOCKED" in out
    assert time.time() - cut < 2.0 * 0.9 + 3.0                        # it did not keep acting past its provable window
