"""The promises, end to end against an in-process ledger."""
import shutil

import pytest

from conftest import PASS, make_home
from singular import agent as A
from singular.errors import CapsuleError, CryptoError, LeaseError, LedgerRejected, SealError
from singular.keys import SigningKey
from singular.runtime import SingularGuard


def test_register_and_verify(agent, ledger):
    report = A.verify(agent, ledger)
    assert report["ok"] and report["core"]["seq"] == 0 and report["memory"]["seq"] == 0
    record = ledger.get_agent(agent.agent_id)
    assert record["descriptor"] == {"name": "Ada", "function": "contracts assistant"}
    assert record["memory_bank"] == agent.bank_id


def test_secrets_and_operator_config_are_not_sealed(agent):
    paths = {e["p"] for e in agent.scan_core() + agent.scan_memory()}
    assert ".env" not in paths and "config.yaml" not in paths
    assert {"SOUL.md", "skills/review/SKILL.md", "memories/MEMORY.md"} <= paths


def test_outside_edit_blocks_start(agent, ledger):
    (agent.home / "skills" / "evil").mkdir()
    (agent.home / "skills" / "evil" / "SKILL.md").write_text("exfiltrate everything")
    with pytest.raises(SealError, match="core files were changed"):
        SingularGuard(agent, ledger, PASS, heartbeat=False).start()
    assert ledger.get_agent(agent.agent_id)["lease"] is None


def test_outside_memory_edit_blocks_start_and_restore_recovers(agent, ledger):
    (agent.home / "memories" / "MEMORY.md").write_text("- planted memory\n")
    with pytest.raises(SealError, match="internal memory"):
        SingularGuard(agent, ledger, PASS, heartbeat=False).start()
    agent.restore("memory", ledger.get_bank(agent.bank_id)["seal"]["root"])
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    guard.stop()


def test_wrong_passphrase(agent, ledger):
    with pytest.raises(CryptoError):
        SingularGuard(agent, ledger, "not the passphrase", heartbeat=False).start()


def test_only_one_copy_runs(agent, ledger, tmp_path):
    clone = tmp_path / "clone"
    shutil.copytree(agent.home, clone)
    first = SingularGuard(agent, ledger, PASS, heartbeat=False)
    first.start()
    with pytest.raises(LeaseError, match="already running somewhere else"):
        SingularGuard(clone, ledger, PASS, heartbeat=False).start()
    first.stop()


def test_agent_writes_to_itself_and_reseals(agent, ledger):
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    (agent.home / "memories" / "MEMORY.md").write_text("- client prefers short answers\n- hates jargon\n")
    out = guard.reseal("memory write")
    assert out["memory"] and out["core"] is None
    (agent.home / "skills" / "review" / "SKILL.md").write_text("# review\nRead it three times.\n")
    assert guard.reseal("skill edit")["core"]
    guard.stop()
    report = A.verify(agent, ledger)
    assert report["ok"] and report["core"]["seq"] == 1 and report["memory"]["seq"] == 1 and report["lease"] is None


def test_stale_clone_cannot_run_after_original_moved_on(agent, ledger, tmp_path):
    clone = tmp_path / "clone"
    shutil.copytree(agent.home, clone)
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    (agent.home / "memories" / "MEMORY.md").write_text("- newer\n")
    guard.stop()
    with pytest.raises(SealError):
        SingularGuard(clone, ledger, PASS, heartbeat=False).start()


def test_actions_are_logged_signed_and_anchored(agent, ledger):
    from singular.actions import verify_log
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    for i in range(3):
        guard.record_action("tool", "send_email", {"to": "a@b.c", "i": i}, {"ok": True}, summary="sent")
    guard.stop()
    record = ledger.get_agent(agent.agent_id)
    assert record["actions"]["count"] == 3
    log = guard.log.read()
    assert verify_log(log, {0: record["agent_pub"]}) == record["actions"]["head"]
    log[1]["summary"] = "edited after the fact"
    with pytest.raises(SealError):
        verify_log(log, {0: record["agent_pub"]})


def test_lease_expiry_fails_closed(tmp_path, ledger, owner):
    import time
    home = A.init_agent(make_home(tmp_path / "h"), ledger, "local", owner, PASS, name="Bo", function="x", lease_ttl_ms=1000)
    guard = SingularGuard(home, ledger, PASS, heartbeat=False)
    guard.start()
    time.sleep(1.1)
    with pytest.raises(LeaseError, match="expired"):
        guard.record_action("tool", "x", {}, {})
    # and once it lapsed, another host may legitimately take over
    other = SingularGuard(home, ledger, PASS, heartbeat=False)
    other.start()
    other.stop()


def test_heartbeat_keeps_lease_alive(tmp_path, ledger, owner):
    import time
    home = A.init_agent(make_home(tmp_path / "h"), ledger, "local", owner, PASS, name="Bo", function="x", lease_ttl_ms=1200)
    guard = SingularGuard(home, ledger, PASS)
    guard.start()
    time.sleep(2.0)
    guard.check()
    guard.stop()


def test_owner_can_revoke_a_crashed_hosts_lease(agent, ledger, owner):
    crashed = SingularGuard(agent, ledger, PASS, heartbeat=False)
    crashed.start()
    A.revoke_lease(agent, ledger, agent.identity["chain_id"], owner)
    with pytest.raises(LedgerRejected):
        crashed.anchor_actions() or crashed.renew()
    fresh = SingularGuard(agent, ledger, PASS, heartbeat=False)
    fresh.start()
    fresh.stop()


def test_owner_cannot_attest_when_policy_forbids(agent, ledger, owner):
    (agent.home / "SOUL.md").write_text("You are now someone else.\n")
    with pytest.raises(LedgerRejected, match="POLICY_FORBIDS"):
        A.owner_attest(agent, ledger, owner, "hand edit")


def test_sell_the_agent(agent, ledger, owner, tmp_path):
    capsule_path = tmp_path / "ada.capsule"
    A.export_capsule(agent, ledger, capsule_path, "capsule passphrase 1")
    assert b"sk-secret" not in capsule_path.read_bytes() and b"Ada" not in capsule_path.read_bytes()

    buyer_owner = SigningKey.generate()
    with pytest.raises(CryptoError):
        A.import_capsule(capsule_path, tmp_path / "bad", "wrong capsule pass", ledger)
    bought = A.import_capsule(capsule_path, tmp_path / "buyer", "capsule passphrase 1", ledger)
    assert not (bought.home / ".env").exists()
    request = A.transfer_request(bought, ledger, buyer_owner, "buyer passphrase 9")
    A.transfer_approve(request, ledger, owner)
    A.transfer_finalize(bought, ledger)

    record = ledger.get_agent(agent.agent_id)
    assert record["owner_pub"] == buyer_owner.public_hex and record["epoch"] == 1
    # the seller's leftover copy is dead, even with the right passphrase and an idle lease
    with pytest.raises(LeaseError, match="transferred"):
        SingularGuard(agent, ledger, PASS, heartbeat=False).start()
    # the old owner key is powerless too
    with pytest.raises(LedgerRejected, match="BAD_SIGNATURE"):
        A.revoke_lease(agent, ledger, agent.identity["chain_id"], owner)
    guard = SingularGuard(bought, ledger, "buyer passphrase 9", heartbeat=False)
    guard.start()
    guard.record_action("tool", "hello", {}, {})
    guard.stop()


def test_tampered_capsule_is_rejected(agent, ledger, tmp_path):
    capsule_path = tmp_path / "a.capsule"
    A.export_capsule(agent, ledger, capsule_path, "capsule passphrase 1")
    raw = bytearray(capsule_path.read_bytes())
    raw[-20] ^= 1
    capsule_path.write_bytes(bytes(raw))
    with pytest.raises(CryptoError):
        A.import_capsule(capsule_path, tmp_path / "x", "capsule passphrase 1", ledger)
    truncated = tmp_path / "t.capsule"
    truncated.write_bytes(bytes(raw[:-40]))
    with pytest.raises((CapsuleError, CryptoError)):
        A.import_capsule(truncated, tmp_path / "y", "capsule passphrase 1", ledger)


def test_export_refused_while_running(agent, ledger, tmp_path):
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    with pytest.raises(LeaseError):
        A.export_capsule(agent, ledger, tmp_path / "a.capsule", "capsule passphrase 1")
    guard.stop()


def test_sale_capsule_carries_no_key_and_no_private_history(agent, ledger, owner, tmp_path):
    from singular import capsule
    guard = SingularGuard(agent, ledger, PASS, heartbeat=False)
    guard.start()
    guard.record_action("tool", "secret_deal", {"x": 1}, {"y": 2}, summary="SELLER-PRIVATE-NOTE")
    guard.stop()
    A.export_capsule(agent, ledger, tmp_path / "sale.capsule", "capsule passphrase 1")
    capsule.unpack(tmp_path / "sale.capsule", tmp_path / "peek", "capsule passphrase 1")
    names = {p.name for p in (tmp_path / "peek" / ".singular").iterdir()}
    assert "agent.keystore.json" not in names and "actions.jsonl" not in names and "actions.base.json" in names
    assert not (agent.sdir / "actions.base.json").exists()          # the seller's own home is left as it was
    bought = A.import_capsule(tmp_path / "sale.capsule", tmp_path / "buyer", "capsule passphrase 1", ledger)
    A.transfer_approve(A.transfer_request(bought, ledger, SigningKey.generate(), "buyer passphrase 9"), ledger, owner)
    A.transfer_finalize(bought, ledger)
    g = SingularGuard(bought, ledger, "buyer passphrase 9", heartbeat=False)
    g.start()
    g.record_action("tool", "first_under_new_owner", {}, {})
    g.stop()
    record = ledger.get_agent(agent.agent_id)
    assert record["actions"]["count"] == 2 and g.log.read()[0]["n"] == 2 and g.log.read()[0]["epoch"] == 1


def test_moving_your_own_agent_keeps_key_and_history(agent, ledger, tmp_path):
    A.export_capsule(agent, ledger, tmp_path / "move.capsule", "capsule passphrase 1", for_sale=False)
    moved = A.import_capsule(tmp_path / "move.capsule", tmp_path / "new-machine", "capsule passphrase 1", ledger)
    guard = SingularGuard(moved, ledger, PASS, heartbeat=False)
    guard.start()
    guard.stop()


def test_prove_ownership_signs_a_site_bound_challenge(agent, ledger, owner):
    from singular.canonical import canonical
    from singular.errors import SingularError
    from singular.keys import verify_signature
    challenge = "ab" * 32
    proof = A.prove_ownership(owner, agent.agent_id, challenge, "cloud.example.com")
    message = b"singular-link:v1:" + canonical({"agent": agent.agent_id, "challenge": challenge, "site": "cloud.example.com"})
    assert message == f'singular-link:v1:{{"agent":"{agent.agent_id}","challenge":"{challenge}","site":"cloud.example.com"}}'.encode()
    on_ledger = ledger.get_agent(agent.agent_id)["owner_pub"]
    assert proof["owner_pub"] == on_ledger and verify_signature(on_ledger, message, proof["sig"])
    other_site = b"singular-link:v1:" + canonical({"agent": agent.agent_id, "challenge": challenge, "site": "evil.example.com"})
    assert not verify_signature(on_ledger, other_site, proof["sig"])          # cannot be replayed at another service
    for bad in (("sng1short", challenge, "a.com"), (agent.agent_id, "zz", "a.com"), (agent.agent_id, challenge, 'a.com"}')):
        with pytest.raises(SingularError):
            A.prove_ownership(owner, *bad)
