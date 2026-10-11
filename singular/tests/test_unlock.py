"""Owner edits: the OWNER_POLICY switch, owner-sealed internal memory, and `singular unlock` (edits sealed elsewhere)."""
import hashlib
import io
import json
import os

import pytest

from conftest import PASS
from singular import agent as A, tree, unlock
from singular.errors import LedgerRejected, SingularError
from singular.keys import SigningKey
from singular.ledger import tx as T
from singular.runtime import SingularGuard


def allow(agent, ledger, owner, value=True):
    return A.set_owner_edits(agent.agent_id, ledger, agent.identity["chain_id"], owner, value)


def files(agent):
    return {p: (agent.home / p).read_bytes() for p in ("SOUL.md", "skills/review/SKILL.md", "memories/MEMORY.md")}


def signed_seals(agent, ledger, owner, edits, *, reason="owner edit", tamper=None):
    """What the browser does: apply the edits to the described entries, compute the roots, sign."""
    described = unlock.describe(agent, ledger)
    sets = {"core": {e["p"]: e for e in described["core"]["entries"]}, "memory": {e["p"]: e for e in described["memory"]["entries"]}}
    for edit in edits:
        kind = "memory" if edit["p"].startswith("memories/") else "core"
        if edit.get("delete"):
            sets[kind].pop(edit["p"])
        else:
            data = edit["text"].encode()
            sets[kind][edit["p"]] = {"p": edit["p"], "h": hashlib.sha256(data).hexdigest(), "s": len(data)}
    record = ledger.get_agent(agent.agent_id)
    bank = ledger.get_bank(agent.bank_id)
    chain_id, txs = agent.identity["chain_id"], []
    core = tree.summarize([sets["core"][p] for p in sorted(sets["core"])])
    memory = tree.summarize([sets["memory"][p] for p in sorted(sets["memory"])])
    if tamper:
        core = {**core, "root": "0" * 64}
    if core["root"] != record["seal"]["root"]:
        t = T.build(T.OWNER_ATTEST, record["id"], record["nonce"] + 1, A.owner_attest_body(record["seal"], core, reason))
        txs.append(T.sign(t, chain_id, "owner", owner) or t)
    if memory["root"] != bank["seal"]["root"]:
        t = T.build(T.BANK_SEAL, bank["id"], bank["nonce"] + 1, A.owner_memory_body(bank["seal"], memory))
        txs.append(T.sign(t, chain_id, "owner", owner) or t)
    return txs


def test_owner_policy_switch(agent, ledger, owner):
    assert ledger.get_agent(agent.agent_id)["policy"]["allow_owner_attest"] is False
    with pytest.raises(LedgerRejected, match="BAD_SIGNATURE|SIGNERS"):
        allow(agent, ledger, SigningKey.generate())
    allow(agent, ledger, owner)
    assert ledger.get_agent(agent.agent_id)["policy"]["allow_owner_attest"] is True
    allow(agent, ledger, owner, False)
    assert ledger.get_agent(agent.agent_id)["policy"]["allow_owner_attest"] is False


def test_owner_policy_needs_a_stopped_agent(agent, ledger, owner):
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    with pytest.raises(LedgerRejected, match="LEASE_HELD"):
        allow(agent, ledger, owner)
    guard.stop()


def test_owner_edits_core_and_memory_then_agent_starts(agent, ledger, owner):
    allow(agent, ledger, owner)
    (agent.home / "SOUL.md").write_text("You are Ada, now terser.\n")
    (agent.home / "memories" / "MEMORY.md").write_text("- client prefers bullet points\n")
    out = A.owner_attest(agent, ledger, owner, "owner tidy-up")
    assert set(out) == {"core", "memory"}
    bank = ledger.get_bank(agent.bank_id)
    assert bank["seal"]["by"] == "owner" and bank["seal"]["seq"] == 1
    assert ledger.get_agent(agent.agent_id)["seal"]["kind"] == "owner_attest"
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    guard.stop()


def test_owner_memory_seal_follows_the_agent_policy(agent, ledger, owner):
    (agent.home / "memories" / "MEMORY.md").write_text("- planted by the owner\n")
    bank = ledger.get_bank(agent.bank_id)
    with pytest.raises(LedgerRejected, match="POLICY_FORBIDS"):
        A.submit(ledger, agent.identity["chain_id"], T.BANK_SEAL, bank["id"], bank["nonce"] + 1,
                 A.owner_memory_body(bank["seal"], tree.summarize(agent.scan_memory())), {"owner": owner})
    allow(agent, ledger, owner)
    bank = ledger.get_bank(agent.bank_id)
    with pytest.raises(LedgerRejected):  # someone else's key, even calling itself the owner
        A.submit(ledger, agent.identity["chain_id"], T.BANK_SEAL, bank["id"], bank["nonce"] + 1,
                 A.owner_memory_body(bank["seal"], tree.summarize(agent.scan_memory())), {"owner": SigningKey.generate()})


def test_owner_memory_seal_refused_while_running(agent, ledger, owner):
    allow(agent, ledger, owner)
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    bank = ledger.get_bank(agent.bank_id)
    with pytest.raises(LedgerRejected, match="LEASE_HELD"):
        A.submit(ledger, agent.identity["chain_id"], T.BANK_SEAL, bank["id"], bank["nonce"] + 1,
                 A.owner_memory_body(bank["seal"], {"root": "1" * 64, "files": 1, "bytes": 1}), {"owner": owner})
    guard.stop()


def test_unlock_describe(agent, ledger):
    described = unlock.describe(agent, ledger)
    assert described["ok"] and described["agent_id"] == agent.agent_id
    assert described["core"]["root"] == ledger.get_agent(agent.agent_id)["seal"]["root"]
    assert described["texts"]["memories/MEMORY.md"] == "- client prefers short answers\n"
    assert ".env" not in described["texts"] and "config.yaml" not in described["texts"]


def test_unlock_apply_edits_creates_and_deletes(agent, ledger, owner):
    allow(agent, ledger, owner)
    edits = [{"p": "SOUL.md", "text": "You are Ada.\n"}, {"p": "skills/brief/SKILL.md", "text": "# brief\nOne page.\n"},
             {"p": "memories/MEMORY.md", "delete": True}, {"p": "memories/people.md", "text": "- Togan: owner\n"}]
    result = unlock.apply(agent, ledger, {"edits": edits, "txs": signed_seals(agent, ledger, owner, edits)})
    assert set(result["receipts"]) == {"core", "memory"}
    assert (agent.home / "skills/brief/SKILL.md").read_text() == "# brief\nOne page.\n"
    assert not (agent.home / "memories/MEMORY.md").exists()
    assert A.verify(agent, ledger)["ok"]
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    guard.stop()


def test_unlock_refuses_a_seal_that_does_not_match_and_changes_nothing(agent, ledger, owner):
    allow(agent, ledger, owner)
    before, nonce = files(agent), ledger.get_agent(agent.agent_id)["nonce"]
    edits = [{"p": "SOUL.md", "text": "something else\n"}]
    with pytest.raises(SingularError, match="does not name"):
        unlock.apply(agent, ledger, {"edits": edits, "txs": signed_seals(agent, ledger, owner, edits, tamper=True)})
    assert files(agent) == before and ledger.get_agent(agent.agent_id)["nonce"] == nonce
    # a seal signed for other edits than the ones sent is refused just the same
    txs = signed_seals(agent, ledger, owner, [{"p": "SOUL.md", "text": "what the owner saw\n"}])
    with pytest.raises(SingularError, match="does not name"):
        unlock.apply(agent, ledger, {"edits": [{"p": "SOUL.md", "text": "what the server wrote\n"}], "txs": txs})
    assert files(agent) == before


def test_unlock_puts_files_back_when_the_ledger_refuses(agent, ledger, owner):
    before = files(agent)  # policy still forbids owner edits
    edits = [{"p": "SOUL.md", "text": "hi\n"}]
    with pytest.raises(LedgerRejected, match="POLICY_FORBIDS"):
        unlock.apply(agent, ledger, {"edits": edits, "txs": signed_seals(agent, ledger, owner, edits)})
    assert files(agent) == before and A.verify(agent, ledger)["ok"]


@pytest.mark.parametrize("path", ["../escape", "/etc/passwd", ".singular/identity.json", ".env", "config.yaml",
                                  "skills/../.env", "memories/./x", "skills\\x", ""])
def test_unlock_refuses_paths_outside_the_sealed_content(agent, ledger, owner, path):
    allow(agent, ledger, owner)
    with pytest.raises(SingularError):
        unlock.apply(agent, ledger, {"edits": [{"p": path, "text": "x"}], "txs": []})


def test_unlock_never_writes_through_a_symlink(agent, ledger, owner, tmp_path):
    allow(agent, ledger, owner)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, agent.home / "skills" / "linked")
    edits = [{"p": "skills/linked/SKILL.md", "text": "x"}]
    with pytest.raises(SingularError):
        unlock.apply(agent, ledger, {"edits": edits, "txs": [{"v": 1}]})
    assert not (outside / "SKILL.md").exists()


def test_unlock_refuses_an_excluded_name(agent, ledger, owner):
    allow(agent, ledger, owner)
    edits = [{"p": "memories/scratch.tmp", "text": "x"}]
    t = T.build(T.BANK_SEAL, agent.bank_id, 2, {"writer": "owner"})
    with pytest.raises(SingularError, match="not sealed"):
        unlock.apply(agent, ledger, {"edits": edits, "txs": [T.sign(t, agent.identity["chain_id"], "owner", owner) or t]})
    assert not (agent.home / "memories/scratch.tmp").exists()


def test_unlock_refuses_while_running(agent, ledger, owner):
    allow(agent, ledger, owner)
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    with pytest.raises(SingularError, match="running"):
        unlock.apply(agent, ledger, {"edits": [{"p": "SOUL.md", "text": "x"}], "txs": []})
    guard.stop()


def test_unlock_only_takes_owner_seals(agent, ledger, owner):
    allow(agent, ledger, owner)
    t = T.build(T.RETIRE, agent.agent_id, ledger.get_agent(agent.agent_id)["nonce"] + 1, {})
    T.sign(t, agent.identity["chain_id"], "owner", owner)
    with pytest.raises(SingularError, match="only an OWNER_ATTEST"):
        unlock.apply(agent, ledger, {"edits": [{"p": "SOUL.md", "text": "x"}], "txs": [t]})
    assert ledger.get_agent(agent.agent_id)["status"] == "active"


def test_unlock_cli_roundtrip(agent, ledger, owner, monkeypatch, capsys):
    from singular import unlock as U
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"")))
    assert U.main("describe", str(agent.home), ledger) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["agent_id"] == agent.agent_id


def test_unlock_apply_from_a_file(agent, ledger, owner, tmp_path, capsys):
    allow(agent, ledger, owner)
    edits = [{"p": "memories/MEMORY.md", "text": "- from a file\n"}]
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"edits": edits, "txs": signed_seals(agent, ledger, owner, edits)}))
    assert unlock.main("apply", str(agent.home), ledger, str(request)) == 0
    assert set(json.loads(capsys.readouterr().out)["receipts"]) == {"memory"}
    assert (agent.home / "memories/MEMORY.md").read_text() == "- from a file\n"
