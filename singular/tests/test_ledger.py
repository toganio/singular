"""Rule machine, signatures, and the chain as an auditable object."""
import copy
import json
import sqlite3

import pytest

from singular.canonical import canonical, merkle_root
from singular.errors import LedgerRejected
from singular.keys import SigningKey, derive_agent_id, new_salt
from singular.ledger import tx as T
from singular.ledger.chain import Chain, ChainError, verify_chain
from singular.ledger.client import HttpLedger, LedgerUnavailable
from singular.ledger.node import LedgerNode

R, M = "ab" * 32, "cd" * 32


def register(chain, owner=None, agent=None, ttl=60_000, **over):
    owner, agent = owner or SigningKey.generate(), agent or SigningKey.generate()
    salt = new_salt()
    aid = derive_agent_id(agent.public_hex, owner.public_hex, salt)
    body = {"agent_pub": agent.public_hex, "enc_pub": agent.enc_public_hex, "owner_pub": owner.public_hex, "salt": salt,
            "descriptor": {"name": "Ada", "function": "x"}, "policy": {"lease_ttl_ms": ttl, "allow_owner_attest": False},
            "root": R, "files": 1, "bytes": 1, "memory_root": M, "memory_files": 0, "memory_bytes": 0, **over}
    t = T.build(T.REGISTER, aid, 1, body)
    T.sign(t, chain.chain_id, "owner", owner), T.sign(t, chain.chain_id, "agent", agent)
    chain.submit(t)
    return aid, owner, agent


def send(chain, tx_type, aid, body, **signers):
    t = T.build(tx_type, aid, chain.state.agents[aid]["nonce"] + 1, body)
    for role, key in signers.items():
        T.sign(t, chain.chain_id, role, key)
    return chain.submit(t)


def lease(chain, aid, agent):
    host = SigningKey.generate()
    send(chain, T.LEASE_ACQUIRE, aid, {"host_pub": host.public_hex, "root": R, "memory_root": M}, agent=agent, host=host)
    return host


def code(excinfo):
    return excinfo.value.code


def test_agent_id_cannot_be_squatted(chain):
    owner, agent, thief = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    salt = new_salt()
    aid = derive_agent_id(agent.public_hex, owner.public_hex, salt)
    body = {"agent_pub": agent.public_hex, "enc_pub": agent.enc_public_hex, "owner_pub": thief.public_hex, "salt": salt,
            "descriptor": {"name": "x", "function": "x"}, "policy": {"lease_ttl_ms": 5000, "allow_owner_attest": False},
            "root": R, "files": 0, "bytes": 0, "memory_root": M, "memory_files": 0, "memory_bytes": 0}
    t = T.build(T.REGISTER, aid, 1, body)
    T.sign(t, chain.chain_id, "owner", thief), T.sign(t, chain.chain_id, "agent", agent)
    with pytest.raises(LedgerRejected) as e:
        chain.submit(t)
    assert code(e) == "BAD_AGENT_ID"


def test_register_twice_rejected(chain):
    aid, owner, agent = register(chain)
    with pytest.raises(LedgerRejected):
        register(chain, owner, agent)  # new salt -> new id is fine, so force the same id instead
        t = T.build(T.REGISTER, aid, 1, {})
        chain.submit(t)


def test_lease_needs_agent_key_and_fresh_host(chain):
    aid, owner, agent = register(chain)
    impostor, host = SigningKey.generate(), SigningKey.generate()
    with pytest.raises(LedgerRejected) as e:
        send(chain, T.LEASE_ACQUIRE, aid, {"host_pub": host.public_hex, "root": R, "memory_root": M}, agent=impostor, host=host)
    assert code(e) == "BAD_SIGNATURE"
    with pytest.raises(LedgerRejected) as e:  # owner key alone cannot run the agent either
        send(chain, T.LEASE_ACQUIRE, aid, {"host_pub": host.public_hex, "root": R, "memory_root": M}, agent=owner, host=host)
    assert code(e) == "BAD_SIGNATURE"
    with pytest.raises(LedgerRejected) as e:  # host proof-of-possession is required
        send(chain, T.LEASE_ACQUIRE, aid, {"host_pub": host.public_hex, "root": R, "memory_root": M}, agent=agent)
    assert code(e) == "BAD_SIGNATURE"


def test_stale_roots_cannot_take_the_lease(chain):
    aid, _, agent = register(chain)
    host = SigningKey.generate()
    for body in ({"host_pub": host.public_hex, "root": "00" * 32, "memory_root": M},
                 {"host_pub": host.public_hex, "root": R, "memory_root": "00" * 32}):
        with pytest.raises(LedgerRejected) as e:
            send(chain, T.LEASE_ACQUIRE, aid, body, agent=agent, host=host)
        assert code(e) == "STALE_STATE"


def test_second_holder_of_the_agent_key_cannot_seal_or_anchor(chain):
    aid, _, agent = register(chain)
    lease(chain, aid, agent)
    rogue_host = SigningKey.generate()
    seal = {"seq": 1, "prev_root": R, "root": "11" * 32, "files": 1, "bytes": 1, "reason": "x"}
    with pytest.raises(LedgerRejected) as e:
        send(chain, T.SEAL, aid, seal, agent=agent, host=rogue_host)
    assert code(e) == "BAD_SIGNATURE"
    with pytest.raises(LedgerRejected) as e:
        send(chain, T.LEASE_RELEASE, aid, {}, agent=agent, host=rogue_host)
    assert code(e) == "BAD_SIGNATURE"


def test_seal_chain_is_strict(chain):
    aid, _, agent = register(chain)
    host = lease(chain, aid, agent)
    good = {"seq": 1, "prev_root": R, "root": "11" * 32, "files": 1, "bytes": 1, "reason": "x"}
    for bad in ({**good, "seq": 2}, {**good, "prev_root": "22" * 32}):
        with pytest.raises(LedgerRejected) as e:
            send(chain, T.SEAL, aid, bad, agent=agent, host=host)
        assert code(e) == "STALE_STATE"
    send(chain, T.SEAL, aid, good, agent=agent, host=host)
    with pytest.raises(LedgerRejected):  # replay of the very same seal
        send(chain, T.SEAL, aid, good, agent=agent, host=host)


def test_nonce_replay_and_cross_chain_replay(chain, tmp_path):
    aid, _, agent = register(chain)
    host = SigningKey.generate()
    t = T.build(T.LEASE_ACQUIRE, aid, 2, {"host_pub": host.public_hex, "root": R, "memory_root": M})
    T.sign(t, chain.chain_id, "agent", agent), T.sign(t, chain.chain_id, "host", host)
    chain.submit(copy.deepcopy(t))
    with pytest.raises(LedgerRejected) as e:
        chain.submit(copy.deepcopy(t))
    assert code(e) == "NONCE_CONFLICT"
    other = Chain.create(tmp_path / "other.db", "other", SigningKey.generate())
    oid, _, oagent = register(other)
    with pytest.raises(LedgerRejected):  # a signature made for one chain means nothing on another
        other.submit(copy.deepcopy(t))
    other.close()


def test_action_anchors_must_continue_the_chain(chain):
    aid, _, agent = register(chain)
    host = lease(chain, aid, agent)
    zero = "0" * 64
    send(chain, T.ACTIONS, aid, {"first": 1, "last": 3, "prev_head": zero, "head": "aa" * 32, "batch_root": "bb" * 32}, agent=agent, host=host)
    with pytest.raises(LedgerRejected) as e:
        send(chain, T.ACTIONS, aid, {"first": 3, "last": 5, "prev_head": "aa" * 32, "head": "cc" * 32, "batch_root": "bb" * 32}, agent=agent, host=host)
    assert code(e) == "ACTION_GAP"
    with pytest.raises(LedgerRejected) as e:
        send(chain, T.ACTIONS, aid, {"first": 4, "last": 5, "prev_head": zero, "head": "cc" * 32, "batch_root": "bb" * 32}, agent=agent, host=host)
    assert code(e) == "ACTION_FORK"


def test_transfer_needs_all_three_and_an_idle_agent(chain):
    aid, owner, agent = register(chain)
    new_owner, new_agent = SigningKey.generate(), SigningKey.generate()
    body = {"new_owner_pub": new_owner.public_hex, "new_agent_pub": new_agent.public_hex,
            "new_enc_pub": new_agent.enc_public_hex, "root": R, "memory_root": M}
    with pytest.raises(LedgerRejected) as e:   # buyer cannot take it without the seller
        send(chain, T.TRANSFER, aid, body, new_owner=new_owner, new_agent=new_agent)
    assert code(e) == "BAD_SIGNATURE"
    with pytest.raises(LedgerRejected) as e:   # seller cannot dump it on someone who did not accept
        send(chain, T.TRANSFER, aid, body, owner=owner, new_agent=new_agent)
    assert code(e) == "BAD_SIGNATURE"
    host = lease(chain, aid, agent)
    with pytest.raises(LedgerRejected) as e:
        send(chain, T.TRANSFER, aid, body, owner=owner, new_owner=new_owner, new_agent=new_agent)
    assert code(e) == "LEASE_HELD"
    send(chain, T.LEASE_RELEASE, aid, {}, agent=agent, host=host)
    send(chain, T.TRANSFER, aid, body, owner=owner, new_owner=new_owner, new_agent=new_agent)
    with pytest.raises(LedgerRejected) as e:   # the old agent key died with the transfer
        lease(chain, aid, agent)
    assert code(e) == "BAD_SIGNATURE"
    lease(chain, aid, new_agent)


def test_retired_agent_is_frozen(chain):
    aid, owner, agent = register(chain)
    send(chain, T.RETIRE, aid, {}, owner=owner)
    with pytest.raises(LedgerRejected) as e:
        lease(chain, aid, agent)
    assert code(e) == "AGENT_RETIRED"


def test_rollback_only_to_a_previously_sealed_root(chain):
    aid, owner, agent = register(chain)
    host = lease(chain, aid, agent)
    send(chain, T.SEAL, aid, {"seq": 1, "prev_root": R, "root": "11" * 32, "files": 1, "bytes": 1, "reason": "x"}, agent=agent, host=host)
    send(chain, T.LEASE_RELEASE, aid, {}, agent=agent, host=host)
    with pytest.raises(LedgerRejected) as e:
        send(chain, T.ROLLBACK, aid, {"seq": 2, "prev_root": "11" * 32, "root": "99" * 32}, owner=owner)
    assert code(e) == "UNKNOWN_ROOT"
    send(chain, T.ROLLBACK, aid, {"seq": 2, "prev_root": "11" * 32, "root": R}, owner=owner)
    assert chain.state.agents[aid]["seal"]["kind"] == "rollback"


def test_rejected_tx_changes_nothing(chain):
    aid, _, agent = register(chain)
    before, height = chain.state.root(), chain.head["height"]
    with pytest.raises(LedgerRejected):
        send(chain, T.LEASE_RENEW, aid, {}, agent=agent, host=SigningKey.generate())
    assert chain.state.root() == before and chain.head["height"] == height


@pytest.mark.parametrize("junk", [None, [], "x", {"v": 1}, {"v": 1, "type": "SEAL", "subject": "a" * 10, "nonce": 1.5, "body": {}, "sigs": []},
                                  {"v": 1, "type": "SEAL", "subject": "a" * 10, "nonce": True, "body": {}, "sigs": [{}]}])
def test_malformed_transactions_are_rejected_cleanly(chain, junk):
    with pytest.raises(LedgerRejected):
        chain.submit(junk)


def test_chain_reopens_and_replays_to_the_same_state(chain, tmp_path):
    aid, _, agent = register(chain)
    lease(chain, aid, agent)
    root, head = chain.state.root(), chain.head
    chain.close()
    reopened = Chain(tmp_path / "chain.db", None)
    assert reopened.state.root() == root and reopened.head == head
    with pytest.raises(LedgerRejected):
        reopened.submit({})  # read-only node
    reopened.close()


def _rewrite_block(path, height, mutate):
    db = sqlite3.connect(path)
    block = json.loads(db.execute("SELECT data FROM blocks WHERE height=?", (height,)).fetchone()[0])
    mutate(block)
    db.execute("UPDATE blocks SET data=? WHERE height=?", (canonical(block).decode(), height))
    db.commit()
    db.close()


def test_history_cannot_be_rewritten(chain, tmp_path):
    aid, _, agent = register(chain)
    lease(chain, aid, agent)
    chain.close()
    _rewrite_block(tmp_path / "chain.db", 1, lambda b: b["txs"][0]["body"]["descriptor"].update(name="Mallory"))
    with pytest.raises(ChainError):
        Chain(tmp_path / "chain.db", None)


def test_block_by_non_validator_is_refused(chain, tmp_path):
    register(chain)
    blocks = chain.blocks()
    forged = copy.deepcopy(blocks)
    mallory = SigningKey.generate()
    forged[1]["header"]["validator"] = mallory.public_hex
    forged[1]["sig"] = mallory.sign(b"singular-block:v1:" + canonical(forged[1]["header"]))
    with pytest.raises(ChainError, match="wrong validator"):
        verify_chain(forged)
    verify_chain(blocks, chain.chain_id)
    with pytest.raises(ChainError, match="different chain"):
        verify_chain(blocks, "00" * 32)


def test_http_node_audit_and_replica(chain, tmp_path):
    node = LedgerNode(chain).start()
    try:
        remote = HttpLedger(node.url)
        aid, _, agent = register(chain)
        assert remote.get_agent(aid)["id"] == aid and remote.get_agent("sng1" + "z" * 30) is None
        with pytest.raises(LedgerRejected) as e:
            remote.submit({"nope": 1})
        assert code(e) == "BAD_TX"
        audit = remote.audit(chain.chain_id)
        assert audit["height"] == chain.head["height"] and audit["agents"] == 1
        replica = Chain.replica(tmp_path / "replica.db", chain.blocks(0, 1)[0], chain.chain_id)
        for block in remote.fetch_blocks(1):
            replica.append_verified(block)
        assert replica.state.root() == chain.state.root()
        bad = copy.deepcopy(chain.blocks(1, 1)[0])
        bad["header"]["height"] = 99
        with pytest.raises(ChainError):
            replica.append_verified(bad)
        assert replica.state.root() == chain.state.root()
        replica.close()
        assert remote.history(aid)[0]["tx"]["type"] == "REGISTER"
    finally:
        node.stop()
    with pytest.raises(LedgerUnavailable):
        HttpLedger(node.url, timeout=1).info()


def test_merkle_root_is_not_malleable():
    a, b, c = "aa" * 32, "bb" * 32, "cc" * 32
    assert merkle_root([a, b, c]) != merkle_root([a, b, c, c])
    assert merkle_root([a, b]) != merkle_root([b, a])
    with pytest.raises(TypeError):
        canonical({"x": 1.5})


def test_node_rate_limits_writes_and_client_refuses_plain_http_on_the_network(chain, monkeypatch):
    from singular.errors import SingularError
    node = LedgerNode(chain, writes_per_minute=60, burst=3).start()
    try:
        remote = HttpLedger(node.url)
        outcomes = []
        for _ in range(6):
            try:
                remote.submit({"junk": 1})
            except LedgerRejected:
                outcomes.append("rejected")
            except LedgerUnavailable:
                outcomes.append("limited")
        assert outcomes[:3] == ["rejected"] * 3 and "limited" in outcomes[3:]
    finally:
        node.stop()
    with pytest.raises(SingularError, match="plain-http"):
        HttpLedger("http://ledger.example.com")
    monkeypatch.setenv("SINGULAR_ALLOW_INSECURE_LEDGER", "1")
    HttpLedger("http://ledger.example.com")
    HttpLedger("https://ledger.example.com")


def test_node_can_require_a_token_to_register(chain):
    node = LedgerNode(chain, register_tokens=["tok-123"]).start()
    try:
        owner, agent = SigningKey.generate(), SigningKey.generate()
        salt = new_salt()
        aid = derive_agent_id(agent.public_hex, owner.public_hex, salt)
        t = T.build(T.REGISTER, aid, 1, {"agent_pub": agent.public_hex, "enc_pub": agent.enc_public_hex, "owner_pub": owner.public_hex,
            "salt": salt, "descriptor": {"name": "A", "function": "x"}, "policy": {"lease_ttl_ms": 5000, "allow_owner_attest": False},
            "root": R, "files": 0, "bytes": 0, "memory_root": M, "memory_files": 0, "memory_bytes": 0})
        T.sign(t, chain.chain_id, "owner", owner), T.sign(t, chain.chain_id, "agent", agent)
        for bad in (None, "wrong"):
            with pytest.raises(LedgerRejected) as e:
                HttpLedger(node.url, register_token=bad).submit(t)
            assert code(e) == "REGISTER_TOKEN_REQUIRED"
        HttpLedger(node.url, register_token="tok-123").submit(t)
        lease_tx = T.build(T.LEASE_ACQUIRE, aid, 2, {"host_pub": SigningKey.generate().public_hex, "root": R, "memory_root": M})
        with pytest.raises(LedgerRejected) as e:      # non-creating txs need no token (and fail only on their merits)
            HttpLedger(node.url).submit(lease_tx)
        assert code(e) == "BAD_TX"
    finally:
        node.stop()
