"""Selling on a host, one-file form: `transfer handover --package` hands the bought agent over as its own package
file, recorded on the ledger with the buyer's new agent key, and the host then runs it from that file."""
import json
import subprocess
import sys

import pytest

from conftest import PASS, make_home
from singular import agent as A, hosting, pack
from singular.errors import SingularError
from singular.errors import CryptoError
from singular.keys import SigningKey
from singular.ledger.chain import Chain
from singular.ledger.client import HttpLedger
from singular.ledger.node import LedgerNode
from singular.runtime import SingularGuard
from test_handover import BUYER_PASS, browser_request
from test_hosting import SRC, FakeRegistry
from test_pack import fake_runtime

CAPSULE_PASS = "the buyer's capsule passphrase"


@pytest.fixture
def sold(tmp_path):
    """An agent on an HTTP ledger, sold to a buyer whose browser made the new keys; the transfer has landed."""
    chain = Chain.create(tmp_path / "chain.db", "host", SigningKey.generate())
    node = LedgerNode(chain, writes_per_minute=0, reads_per_minute=0).start()
    ledger, owner = HttpLedger(node.url), SigningKey.generate()
    agent = A.init_agent(make_home(tmp_path / "seller"), ledger, node.url, owner, PASS, name="Ada", function="x",
                         lease_ttl_ms=60_000)
    request, buyer_owner, keystore = browser_request(ledger, agent.agent_id, agent.identity["chain_id"])
    A.transfer_approve(request, ledger, owner, agent.agent_id)
    registry = FakeRegistry()
    yield tmp_path, node, ledger, agent, keystore, fake_runtime(registry)
    registry.close()
    node.stop()
    chain.close()


ENV = {"SINGULAR_PASSPHRASE": BUYER_PASS, "SINGULAR_CAPSULE_PASSPHRASE": CAPSULE_PASS}


def test_the_bought_agent_leaves_the_handover_as_its_own_package(sold):
    tmp_path, node, ledger, agent, keystore, base = sold
    bought = A.handover(agent, tmp_path / "buyer", ledger, keystore)
    out = tmp_path / "package" / "agent.tar"
    info = hosting.package_bought(bought, node.url, out, base, ENV)

    record = ledger.get_agent(agent.agent_id)
    assert info["no"] == 1 and record["package"]["image"] == pack.package_info(out)["image"].removeprefix("sha256:")
    assert record["package"]["capsule"] == info["capsule_digest"].removeprefix("sha256:")
    assert not list(out.parent.glob(".singular-*"))

    # a fresh machine with nothing but the file: the buyer's agent starts from it and runs under the lease
    env = {**ENV, "SINGULAR_PACKAGE": str(out), "SINGULAR_CAPSULE": pack.CAPSULE_IN_IMAGE}
    home, how = hosting.prepare_home(tmp_path / "vol", node.url, env)
    assert how["source"] == "package" and home.agent_id == agent.agent_id
    guard = SingularGuard(home, ledger, BUYER_PASS, heartbeat=False)
    guard.start()
    guard.record_action("tool", "first_under_new_owner", {}, {})
    guard.stop()
    assert hosting.repack_package(home, node.url, env, lambda *a, **f: None)["no"] == 2


def test_a_wrong_agent_passphrase_stops_before_anything_is_built(sold):
    tmp_path, node, ledger, agent, keystore, base = sold
    bought = A.handover(agent, tmp_path / "buyer", ledger, keystore)
    out = tmp_path / "package" / "agent.tar"
    with pytest.raises(CryptoError, match="wrong passphrase"):
        hosting.package_bought(bought, node.url, out, base, {**ENV, "SINGULAR_PASSPHRASE": "not the buyer's"})
    with pytest.raises(SingularError, match="SINGULAR_CAPSULE_PASSPHRASE"):
        hosting.package_bought(bought, node.url, out, base, {"SINGULAR_PASSPHRASE": BUYER_PASS})
    assert not out.exists() and not ledger.get_agent(agent.agent_id).get("package")


def test_cli_handover_with_package(sold):
    tmp_path, node, ledger, agent, keystore, base = sold
    (tmp_path / "agent.keystore.json").write_text(json.dumps(keystore))
    secrets = tmp_path / "singular.env"
    secrets.write_text(f"SINGULAR_PASSPHRASE={BUYER_PASS}\nSINGULAR_CAPSULE_PASSPHRASE={CAPSULE_PASS}\n")
    run = subprocess.run(
        [sys.executable, "-c", "import sys; from singular.cli import main; sys.exit(main())", "transfer", "handover",
         "--from", str(agent.home), "--keystore", str(tmp_path / "agent.keystore.json"), "--home", str(tmp_path / "buyer"),
         "--ledger", node.url, "--package", str(tmp_path / "package" / "agent.tar"), "--base", base],
        capture_output=True, text=True, env={"PYTHONPATH": SRC, "SINGULAR_SECRETS_FILE": str(secrets),
                                             "SINGULAR_ALLOW_INSECURE_LEDGER": "1", "PATH": "/usr/bin:/bin"})
    assert run.returncode == 0, run.stderr
    said = json.loads(run.stdout)
    assert said["handed_over"] and said["package"]["no"] == 1
    assert said["package"]["capsule_digest"] == pack.package_info(tmp_path / "package" / "agent.tar")["capsule_digest"]
