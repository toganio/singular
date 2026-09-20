"""External memory banks: many agents, many banks, one history per bank."""
import threading
import time

import pytest

from conftest import PASS, make_home
from singular import agent as A
from singular.bank import BankMount, BankOwner, DirStore, bank_transfer_request
from singular.errors import CryptoError, LedgerRejected, SealError
from singular.keys import SigningKey
from singular.runtime import SingularGuard


def new_agent(tmp_path, ledger, owner, name):
    return A.init_agent(make_home(tmp_path / name), ledger, "local", owner, PASS, name=name, function="x", lease_ttl_ms=60_000)


def running(home, ledger):
    guard = SingularGuard(home, ledger, PASS, heartbeat=False)
    guard.start()
    return guard


def mount_for(store, ledger, bank_id, guard, tmp_path):
    return BankMount(store, ledger, bank_id, tmp_path / f"mnt-{guard.agent_id[:10]}", agent_id=guard.agent_id,
                     agent_key=guard.agent_key)


@pytest.fixture
def bank(tmp_path, ledger):
    bank_owner_key = SigningKey.generate()
    return BankOwner.create(DirStore(tmp_path / "store"), ledger, bank_owner_key, "case-law")


def test_owner_seeds_and_granted_agent_reads(bank, ledger, owner, tmp_path):
    seed = bank.mount(tmp_path / "owner-mnt")
    seed.append_entry("Statute of limitations is 10 years.", title="limits")
    assert seed.push()
    ada = new_agent(tmp_path, ledger, owner, "ada")
    guard = running(ada, ledger)
    mount = mount_for(bank.store, ledger, bank.bank_id, guard, tmp_path)
    with pytest.raises(CryptoError, match="no valid grant"):
        mount.pull()
    bank.grant(ada.agent_id, "r")
    assert mount.pull()["updated"] == 1
    assert "10 years" in mount.read(mount.list()[0]["p"])
    # read-only: the ledger refuses the write even though the agent can encrypt
    mount.append_entry("my note")
    with pytest.raises(LedgerRejected, match="NO_GRANT"):
        mount.push(guard.signers())
    guard.stop()


def test_store_holds_only_ciphertext(bank, tmp_path):
    seed = bank.mount(tmp_path / "owner-mnt")
    seed.append_entry("TOP-SECRET-MARKER")
    seed.push()
    blob = b"".join(p.read_bytes() for p in (tmp_path / "store").rglob("*") if p.is_file())
    assert b"TOP-SECRET-MARKER" not in blob


def test_one_agent_many_banks_one_passphrase(ledger, owner, tmp_path):
    ada = new_agent(tmp_path, ledger, owner, "ada")
    banks = [BankOwner.create(DirStore(tmp_path / f"s{i}"), ledger, SigningKey.generate(), f"bank{i}") for i in range(3)]
    for b in banks:
        b.grant(ada.agent_id, "rw")
    guard = running(ada, ledger)  # one passphrase unlocked the agent...
    for i, b in enumerate(banks):  # ...and with it every bank it was granted
        mount = mount_for(b.store, ledger, b.bank_id, guard, tmp_path / f"m{i}")
        mount.append_entry(f"note for bank {i}")
        assert mount.push(guard.signers())
        assert ledger.get_bank(b.bank_id)["seal"]["by"] == ada.agent_id
    guard.stop()


def test_many_agents_race_on_one_bank_history_stays_single(bank, ledger, owner, tmp_path):
    guards, mounts = [], []
    for name in ("a1", "a2", "a3", "a4"):
        home = new_agent(tmp_path, ledger, owner, name)
        bank.grant(home.agent_id, "rw")
        guard = running(home, ledger)
        guards.append(guard)
        mounts.append(mount_for(bank.store, ledger, bank.bank_id, guard, tmp_path / name))
    errors = []

    def work(guard, mount, n):
        try:
            for i in range(3):
                mount.append_entry(f"{n} entry {i}")
                mount.push(guard.signers())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(g, m, i)) for i, (g, m) in enumerate(zip(guards, mounts))]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors, errors
    record = ledger.get_bank(bank.bank_id)
    assert record["seal"]["seq"] == 12 and record["seal"]["files"] == 12   # 4 writers x 3, nothing lost, no fork
    final = mounts[0]
    final.pull()
    assert len(final.list()) == 12
    writers = {h["tx"]["body"]["writer"] for h in ledger.history(bank.bank_id) if h["tx"]["type"] == "BANK_SEAL"}
    assert writers == {g.agent_id for g in guards}                        # every write is attributed
    [g.stop() for g in guards]


def test_a_stopped_or_cloned_agent_cannot_write(bank, ledger, owner, tmp_path):
    ada = new_agent(tmp_path, ledger, owner, "ada")
    bank.grant(ada.agent_id, "rw")
    guard = running(ada, ledger)
    mount = mount_for(bank.store, ledger, bank.bank_id, guard, tmp_path)
    signers = guard.signers()
    guard.stop()
    mount.append_entry("written after my lease ended")
    with pytest.raises(LedgerRejected, match="NO_LEASE"):
        mount.push(signers)


def test_revoke_rekeys_and_locks_out_future_reads(bank, ledger, owner, tmp_path):
    ada, bob = new_agent(tmp_path, ledger, owner, "ada"), new_agent(tmp_path, ledger, owner, "bob")
    bank.grant(ada.agent_id, "rw")
    bank.grant(bob.agent_id, "rw")
    ga, gb = running(ada, ledger), running(bob, ledger)
    ma, mb = (mount_for(bank.store, ledger, bank.bank_id, g, tmp_path) for g in (ga, gb))
    ma.append_entry("before revoke")
    ma.push(ga.signers())
    bank.revoke(bob.agent_id)
    assert ledger.get_bank(bank.bank_id)["key_gen"] == 2
    ma.append_entry("after revoke")
    ma.push(ga.signers())                    # survivor was re-wrapped, keeps writing, still reads history
    assert len(ma.list()) == 2
    with pytest.raises(CryptoError):
        mb.pull()
    ga.stop(), gb.stop()


def test_selling_an_agent_drops_its_bank_access(bank, ledger, owner, tmp_path):
    ada = new_agent(tmp_path, ledger, owner, "ada")
    bank.grant(ada.agent_id, "rw")
    A.export_capsule(ada, ledger, tmp_path / "a.capsule", "capsule passphrase 1")
    bought = A.import_capsule(tmp_path / "a.capsule", tmp_path / "buyer", "capsule passphrase 1", ledger)
    A.transfer_approve(A.transfer_request(bought, ledger, SigningKey.generate(), "buyer passphrase 9"), ledger, owner)
    A.transfer_finalize(bought, ledger)
    guard = SingularGuard(bought, ledger, "buyer passphrase 9", heartbeat=False)
    guard.start()
    mount = mount_for(bank.store, ledger, bank.bank_id, guard, tmp_path)
    with pytest.raises(CryptoError, match="no valid grant"):
        mount.pull()
    guard.stop()


def test_rented_grant_expires(bank, ledger, owner, tmp_path):
    ada = new_agent(tmp_path, ledger, owner, "ada")
    bank.grant(ada.agent_id, "rw", expires_ms=int(time.time() * 1000) + 1200)
    guard = running(ada, ledger)
    mount = mount_for(bank.store, ledger, bank.bank_id, guard, tmp_path)
    mount.append_entry("while rented")
    assert mount.push(guard.signers())
    time.sleep(1.3)
    mount.append_entry("after the rent ran out")
    with pytest.raises((CryptoError, LedgerRejected)):
        mount.push(guard.signers())
    guard.stop()


def test_tampered_store_is_detected(bank, ledger, owner, tmp_path):
    seed = bank.mount(tmp_path / "owner-mnt")
    seed.append_entry("genuine")
    seed.push()
    blob = next((tmp_path / "store" / "blobs").iterdir())
    blob.write_bytes(blob.read_bytes()[:-1] + b"\x00")
    ada = new_agent(tmp_path, ledger, owner, "ada")
    bank.grant(ada.agent_id, "r")
    guard = running(ada, ledger)
    with pytest.raises(SealError):
        mount_for(bank.store, ledger, bank.bank_id, guard, tmp_path).pull()
    guard.stop()


def test_bank_can_be_sold(bank, ledger, tmp_path):
    seed = bank.mount(tmp_path / "owner-mnt")
    seed.append_entry("knowledge worth buying")
    seed.push()
    buyer = SigningKey.generate()
    bank.transfer_approve(bank_transfer_request(ledger, bank.bank_id, buyer))
    assert ledger.get_bank(bank.bank_id)["owner_pub"] == buyer.public_hex
    new_owner = BankOwner(bank.store, ledger, buyer)
    new_owner.rekey()
    mount = new_owner.mount(tmp_path / "buyer-mnt")
    mount.pull()
    assert len(mount.list()) == 1
    with pytest.raises(CryptoError):      # the seller can no longer even open the bank's key file...
        bank.rekey()
    from singular.agent import submit
    from singular.ledger import tx as T
    with pytest.raises(LedgerRejected, match="BAD_SIGNATURE"):   # ...and the ledger ignores their signature
        submit(ledger, bank.chain_id, T.BANK_REVOKE, bank.bank_id, ledger.get_bank(bank.bank_id)["nonce"] + 1,
               {"agent": "sng1" + "a" * 32}, {"owner": bank.key})


def test_internal_memory_cannot_be_shared(agent, ledger, owner):
    from singular.agent import submit
    from singular.ledger import tx as T
    record = ledger.get_bank(agent.bank_id)
    with pytest.raises(LedgerRejected, match="INTERNAL_BANK"):
        submit(ledger, agent.identity["chain_id"], T.BANK_GRANT, agent.bank_id, record["nonce"] + 1,
               {"agent": agent.agent_id, "rights": "r", "key_gen": 0, "wrapped_key": "00" * 40, "expires": 0},
               {"owner": owner})


def test_malicious_member_cannot_write_outside_other_members_mounts(bank, ledger, owner, tmp_path):
    """A granted agent controls the manifest it uploads. It must not become a file write elsewhere."""
    from singular import bank as B, tree
    from singular.canonical import canonical
    mallory, victim = new_agent(tmp_path, ledger, owner, "mallory"), new_agent(tmp_path, ledger, owner, "victim")
    bank.grant(mallory.agent_id, "rw"), bank.grant(victim.agent_id, "r")
    gm, gv = running(mallory, ledger), running(victim, ledger)
    mm = mount_for(bank.store, ledger, bank.bank_id, gm, tmp_path)
    record = ledger.get_bank(bank.bank_id)
    _, keys = mm._load_manifest(record)
    payload = b"pwned"
    from singular.canonical import sha256_hex
    h = sha256_hex(payload)
    sealed = B._encrypt(keys[1], payload, b"singular-blob:" + bank.bank_id.encode() + bytes.fromhex(h))
    bank.store.put("blobs/" + sha256_hex(sealed), sealed)
    entries = [{"p": "../../escaped.txt", "h": h, "s": len(payload), "b": sha256_hex(sealed), "g": 1}]
    root = tree.root_of(B._public_entries(entries))
    manifest = {"v": 1, "bank": bank.bank_id, "seq": 1, "key_gen": 1, "entries": entries, "old_keys": {}}
    bank.store.put(B._manifest_name(root, 1), B._encrypt(keys[1], canonical(manifest), mm._aad))
    from singular.agent import submit
    from singular.ledger import tx as T
    submit(ledger, bank.chain_id, T.BANK_SEAL, bank.bank_id, record["nonce"] + 1,
           {"writer": mallory.agent_id, "key_gen": 1, "seq": 1, "prev_root": record["seal"]["root"], "root": root,
            "files": 1, "bytes": len(payload)}, gm.signers())
    with pytest.raises(SealError, match="unsafe path"):
        mount_for(bank.store, ledger, bank.bank_id, gv, tmp_path).pull()
    assert not list(tmp_path.rglob("escaped.txt"))
    gm.stop(), gv.stop()
