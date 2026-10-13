"""Selling on the site: the buyer's browser makes the new agent key and both buyer signatures from public ledger
facts alone, the seller signs last, and `singular transfer handover` moves the files to the buyer's home."""
import json

import pytest

from conftest import PASS
from singular import agent as A
from singular.errors import LeaseError, SingularError
from singular.keys import SigningKey, wrap_key
from singular.ledger import tx as T
from singular.runtime import SingularGuard

BUYER_PASS = "buyer agent passphrase"


def browser_request(ledger, agent_id, chain_id):
    """What the buyer's tab does: no capsule, no files, only the agent's public record."""
    record, buyer_owner, new_agent = ledger.get_agent(agent_id), SigningKey.generate(), SigningKey.generate()
    bank = ledger.get_bank(record["memory_bank"])
    tx = T.build(T.TRANSFER, agent_id, record["nonce"] + 1, {
        "new_owner_pub": buyer_owner.public_hex, "new_agent_pub": new_agent.public_hex,
        "new_enc_pub": new_agent.enc_public_hex, "root": record["seal"]["root"], "memory_root": bank["seal"]["root"]})
    T.sign(tx, chain_id, "new_owner", buyer_owner)
    T.sign(tx, chain_id, "new_agent", new_agent)
    return {"kind": "singular-transfer-request", "chain_id": chain_id, "tx": tx}, buyer_owner, wrap_key(new_agent, BUYER_PASS, label="agent")


def sold_with_history(agent, ledger, owner):
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    guard.record_action("tool", "secret_deal", {"x": 1}, {"y": 2}, summary="SELLER-PRIVATE-NOTE")
    guard.stop()
    request, buyer_owner, keystore = browser_request(ledger, agent.agent_id, agent.identity["chain_id"])
    A.transfer_approve(request, ledger, owner, agent.agent_id)
    return buyer_owner, keystore


def test_handover_moves_the_sold_agent_without_the_sellers_key_or_history(agent, ledger, owner, tmp_path):
    buyer_owner, keystore = sold_with_history(agent, ledger, owner)
    bought = A.handover(agent, tmp_path / "buyer", ledger, keystore)

    names = {p.name for p in bought.sdir.iterdir()}
    assert "actions.jsonl" not in names and "actions.base.json" in names
    assert not (bought.home / ".env").exists()  # the seller's model key stays with the seller
    assert b"SELLER-PRIVATE-NOTE" not in b"".join(p.read_bytes() for p in bought.home.rglob("*") if p.is_file())
    assert (agent.sdir / "agent.keystore.json").exists() and not (agent.sdir / "actions.base.json").exists()

    guard = SingularGuard(bought, ledger, BUYER_PASS, heartbeat=False)
    guard.start()
    guard.record_action("tool", "first_under_new_owner", {}, {})
    guard.stop()
    record = ledger.get_agent(agent.agent_id)
    assert record["owner_pub"] == buyer_owner.public_hex and record["epoch"] == 1
    with pytest.raises(LeaseError, match="transferred"):
        SingularGuard(agent, ledger, PASS, heartbeat=False).start()


def test_handover_refuses_before_the_transfer_lands(agent, ledger, tmp_path):
    _, _, keystore = browser_request(ledger, agent.agent_id, agent.identity["chain_id"])
    with pytest.raises(SingularError, match="has the transfer landed"):
        A.handover(agent, tmp_path / "buyer", ledger, keystore)
    assert not (tmp_path / "buyer").exists()


def test_handover_refuses_an_owner_keystore(agent, ledger, owner, tmp_path):
    sold_with_history(agent, ledger, owner)
    with pytest.raises(SingularError, match="not an agent keystore"):
        A.handover(agent, tmp_path / "buyer", ledger, wrap_key(owner, PASS, label="owner"))


def test_handover_refuses_the_sellers_own_live_key(agent, ledger, tmp_path):
    from singular.keys import load_keystore
    with pytest.raises(SingularError, match="still names the seller"):
        A.handover(agent, tmp_path / "buyer", ledger, json.loads(agent.keystore_path.read_text()))
    assert load_keystore(agent.keystore_path)["pub"] == ledger.get_agent(agent.agent_id)["agent_pub"]
    assert not (tmp_path / "buyer").exists()


def test_handover_refuses_a_target_inside_the_sellers_home(agent, ledger, owner):
    _, keystore = sold_with_history(agent, ledger, owner)
    with pytest.raises(SingularError, match="outside the seller"):
        A.handover(agent, agent.home / "staging" / "buyer", ledger, keystore)
    assert not (agent.home / "staging").exists()


def test_handover_cli(agent, ledger, owner, tmp_path, monkeypatch):
    from singular import cli
    _, keystore = sold_with_history(agent, ledger, owner)
    (tmp_path / "ks.json").write_text(json.dumps(keystore))
    monkeypatch.setattr(cli, "open_ledger", lambda url: ledger)
    code = cli.main(["transfer", "handover", "--from", str(agent.home), "--keystore", str(tmp_path / "ks.json"),
                     "--home", str(tmp_path / "buyer"), "--ledger", "http://ledger.invalid"])
    assert code == 0 and A.AgentHome(tmp_path / "buyer").is_singular
