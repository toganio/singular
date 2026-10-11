"""``singular pack``: one agent baked into one standalone image, pushed to a registry or written as one file,
and the image's capsule still obeys the ledger (a copy cannot run once the agent has moved on)."""
import gzip
import hashlib
import io
import json
import tarfile

import pytest

from singular import hosting, oci, pack
from singular.errors import CapsuleError, SingularError
from test_hosting import CAPSULE_PASS, export, world  # noqa: F401 - the fixture is used by name


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _layer(files: dict[str, bytes]) -> tuple[bytes, bytes]:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue(), gzip.compress(raw.getvalue(), mtime=0)


def fake_runtime(registry, repo="toganio/singular-runtime", tag="0.1.0", *, label=True, index=False):
    """A tiny image shaped like the runtime: Docker media types, one gzip layer, the runtime label."""
    plain, gz = _layer({"opt/hermes/README": b"hermes\n"})
    config = {"architecture": "amd64", "os": "linux",
              "config": {"Env": ["PATH=/usr/bin", "SINGULAR_LEDGER=https://stale.example"],
                         "Entrypoint": ["/usr/bin/tini", "--", "singular", "host"],
                         "Labels": {"dev.singular.runtime": "1"} if label else {}},
              "rootfs": {"type": "layers", "diff_ids": [_sha(plain)]}, "history": [{"created_by": "base"}]}
    config_raw = json.dumps(config).encode()
    registry.blobs[_sha(config_raw)] = config_raw
    registry.blobs[_sha(gz)] = gz
    manifest = json.dumps({"schemaVersion": 2, "mediaType": pack.DOCKER_MANIFEST,
                           "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                                      "digest": _sha(config_raw), "size": len(config_raw)},
                           "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                                       "digest": _sha(gz), "size": len(gz)}]}).encode()
    registry.manifests[_sha(manifest)] = manifest
    top = manifest
    if index:
        top = json.dumps({"schemaVersion": 2, "mediaType": pack.OCI_INDEX, "manifests": [
            {"mediaType": pack.DOCKER_MANIFEST, "digest": "sha256:" + "0" * 64, "size": 1,
             "platform": {"os": "linux", "architecture": "arm64"}},
            {"mediaType": pack.DOCKER_MANIFEST, "digest": _sha(manifest), "size": len(manifest),
             "platform": {"os": "linux", "architecture": "amd64"}}]}).encode()
        registry.manifests[_sha(top)] = top
    registry.manifests[tag] = top
    return f"{registry.host}/{repo}:{tag}"


def _config(registry, manifest):
    return json.loads(registry.blobs[manifest["config"]["digest"]])


def test_pack_pushes_a_standalone_agent_image(world):
    tmp_path, node, ledger, agent, registry = world
    base = fake_runtime(registry, index=True)
    capsule_path = export(agent, ledger, tmp_path / "ada.capsule")
    result = pack.pack(capsule_path, node.url, base=base, push_to=f"{registry.host}/togan/ada:v1")

    assert result["image"] == f"{registry.host}/togan/ada@{result['manifest_digest']}"
    manifest = json.loads(registry.manifests["v1"])
    assert manifest["mediaType"] == pack.OCI_MANIFEST and len(manifest["layers"]) == 2
    assert manifest["layers"][0]["mediaType"] == "application/vnd.oci.image.layer.v1.tar+gzip"
    assert manifest["annotations"]["dev.singular.agent_id"] == agent.agent_id
    config = _config(registry, manifest)
    env = dict(e.split("=", 1) for e in config["config"]["Env"])
    capsule_bytes = capsule_path.read_bytes()
    assert env["SINGULAR_CAPSULE"] == pack.CAPSULE_IN_IMAGE
    assert env["SINGULAR_CAPSULE_DIGEST"] == _sha(capsule_bytes)
    assert env["SINGULAR_LEDGER"] == node.url                       # the stale base value is replaced
    assert config["config"]["Entrypoint"][-2:] == ["singular", "host"]
    assert len(config["rootfs"]["diff_ids"]) == 2
    # the new layer is a plain tar holding the capsule byte for byte, read-only
    layer = registry.blobs[manifest["layers"][1]["digest"]]
    assert config["rootfs"]["diff_ids"][1] == _sha(layer)
    with tarfile.open(fileobj=io.BytesIO(layer)) as tar:
        member = tar.getmember("opt/singular/agent.sngcap")
        assert member.mode == 0o444 and tar.extractfile(member).read() == capsule_bytes


def test_pack_writes_one_file(world, tmp_path):
    _, node, ledger, agent, registry = world
    base = fake_runtime(registry)
    out = tmp_path / "ada.tar"
    result = pack.pack(export(agent, ledger, tmp_path / "ada.capsule"), node.url, base=base, out=out, tag="ada:latest")
    assert result["tag"] == "ada:latest"
    with tarfile.open(out) as tar:
        names = set(tar.getnames())
        index = json.load(tar.extractfile("index.json"))
        legacy = json.load(tar.extractfile("manifest.json"))
    assert {"oci-layout", "index.json", "manifest.json"} <= names
    assert index["manifests"][0]["annotations"]["io.containerd.image.name"] == "docker.io/library/ada:latest"
    assert legacy[0]["RepoTags"] == ["ada:latest"] and all(path in names for path in legacy[0]["Layers"])
    # the archive reads back as an image (so a `docker save` of the runtime works as --base too)
    with pytest.raises(CapsuleError, match="already holds an agent"):   # an agent image is no base for another
        pack.open_archive_base(out)


def test_pack_refuses_a_sale_capsule_and_a_foreign_base(world):
    tmp_path, node, ledger, agent, registry = world
    with pytest.raises(CapsuleError, match="--move"):
        pack.pack(export(agent, ledger, tmp_path / "sale.capsule", move=False), node.url,
                  base=fake_runtime(registry), push_to=f"{registry.host}/togan/ada:v1")
    with pytest.raises(CapsuleError, match="not a Singular runtime"):
        pack.pack(export(agent, ledger, tmp_path / "ada.capsule"), node.url,
                  base=fake_runtime(registry, repo="library/busybox", label=False), push_to=f"{registry.host}/togan/ada:v1")
    with pytest.raises(CapsuleError, match="--push"):
        pack.pack(tmp_path / "ada.capsule", node.url, base=fake_runtime(registry))


def test_a_corrupted_base_layer_is_refused(world, tmp_path):
    _, node, ledger, agent, registry = world
    base = fake_runtime(registry)
    manifest = json.loads(registry.manifests["0.1.0"])
    registry.blobs[manifest["layers"][0]["digest"]] = b"\x1f\x8b not the layer"
    with pytest.raises(CapsuleError, match="intact"):
        pack.pack(export(agent, ledger, tmp_path / "ada.capsule"), node.url, base=base, out=tmp_path / "x.tar")
    assert not (tmp_path / "x.tar").exists() and not (tmp_path / "x.tar.part").exists()


def test_the_baked_capsule_starts_once_and_copies_go_stale(world, tmp_path):
    """What the image's entrypoint does with the baked capsule: import into an empty volume, verified by the
    ledger. After the agent seals new memories, the same image cannot seed a second volume."""
    _, node, ledger, agent, registry = world
    capsule_path = export(agent, ledger, tmp_path / "ada.capsule")
    env = {"SINGULAR_CAPSULE": str(capsule_path), "SINGULAR_CAPSULE_DIGEST": _sha(capsule_path.read_bytes()),
           "SINGULAR_CAPSULE_PASSPHRASE": CAPSULE_PASS}
    home, how = hosting.prepare_home(tmp_path / "vol1", node.url, env)
    assert how["imported"] and home.agent_id == agent.agent_id

    from singular.runtime import SingularGuard
    from conftest import PASS, agent_writes
    guard = SingularGuard(home, ledger, PASS)
    guard.start()
    agent_writes(guard, "memories/MEMORY.md", "- learned something new\n")   # sealed: the baked capsule is now behind
    guard.stop()

    with pytest.raises(SingularError, match="stale"):
        hosting.prepare_home(tmp_path / "vol2", node.url, env)
    with pytest.raises(CapsuleError, match="expected"):
        hosting.prepare_home(tmp_path / "vol3", node.url, {**env, "SINGULAR_CAPSULE_DIGEST": "sha256:" + "0" * 64})


def test_platform_selection_names_what_is_missing(world):
    _, _, _, _, registry = world
    base = fake_runtime(registry, index=True)
    with pytest.raises(CapsuleError, match="linux/riscv64"):
        pack.open_base(base, "linux/riscv64")
    assert oci.parse_reference(base).tag == "0.1.0"


# -- the package: one file that holds the living agent and is rewritten after each run ----------------

def _package(world, tmp_path, name="ada.tar"):
    _, node, ledger, agent, registry = world
    out = tmp_path / "pkg" / name
    out.parent.mkdir(exist_ok=True)
    pack.pack(export(agent, ledger, tmp_path / "ada.capsule"), node.url, base=fake_runtime(registry), out=out, tag="ada:v1")
    return out


def _run_once(home, ledger, text):
    from singular.runtime import SingularGuard
    from conftest import PASS, agent_writes
    guard = SingularGuard(home, ledger, PASS)
    guard.start()
    agent_writes(guard, "memories/MEMORY.md", text)
    guard.stop()


def test_package_round_trip_and_repack_in_place(world, tmp_path):
    _, node, _, agent, _ = world
    out = _package(world, tmp_path)
    info = pack.package_info(out)
    assert info["agent_id"] == agent.agent_id and info["tag"] == "ada:v1"
    opened = pack.open_package(out)
    config = opened.config
    opened.close()
    assert f"SINGULAR_PACKAGE={pack.PACKAGE_DIR}/ada.tar" in config["config"]["Env"]
    extracted = pack.extract_capsule(out, tmp_path / "x.capsule")
    assert extracted["capsule_digest"] == _sha((tmp_path / "ada.capsule").read_bytes())

    (tmp_path / "other.capsule").write_bytes((tmp_path / "ada.capsule").read_bytes())
    result = pack.repack(out, tmp_path / "other.capsule", node.url)
    after = pack.open_package(out)
    try:
        assert after.tag == "ada:v1" and len(after.layers) == 2       # runtime layers kept, capsule replaced
        assert after.config["config"]["Labels"]["org.opencontainers.image.base.name"].endswith("singular-runtime:0.1.0")
        assert after.config["rootfs"]["diff_ids"][-1] == after.layers[-1]["digest"]
        assert len(after.config["history"]) == 2
    finally:
        after.close()
    assert result["manifest_digest"] == pack.package_info(out)["image"]
    assert not list(out.parent.glob(".singular-*")) and not list(out.parent.glob("*.part"))
    with pytest.raises(CapsuleError, match="no agent in it"):   # a plain runtime image is not a package
        pack._check_runtime({"config": {"Labels": {"dev.singular.runtime": "1"}}, "rootfs": {"type": "layers"}}, "x", agent=True)


def test_the_package_file_carries_the_living_agent(world, tmp_path):
    """Start from the file, run, rewrite the file, record it; the old copy of the file is now refused."""
    _, node, ledger, agent, _ = world
    out = _package(world, tmp_path)
    old_copy = tmp_path / "old-ada.tar"
    old_copy.write_bytes(out.read_bytes())
    from conftest import PASS
    env = {"SINGULAR_PACKAGE": str(out), "SINGULAR_CAPSULE": pack.CAPSULE_IN_IMAGE,
           "SINGULAR_CAPSULE_PASSPHRASE": CAPSULE_PASS, "SINGULAR_PASSPHRASE": PASS}
    home, how = hosting.prepare_home(tmp_path / "vol1", node.url, env)
    assert how["source"] == "package" and home.agent_id == agent.agent_id

    _run_once(home, ledger, "- learned that the client is in Ankara\n")
    reports = []
    info = hosting.repack_package(home, node.url, env, lambda state, **f: reports.append((state, f)))
    assert info["no"] == 1 and reports[-1][0] == "packaged"
    record = ledger.get_agent(agent.agent_id)
    assert record["package"]["capsule"] == info["capsule_digest"].removeprefix("sha256:")
    assert record["package"]["image"] == pack.package_info(out)["image"].removeprefix("sha256:")

    # a second machine, nothing but the new file: the agent comes back with what it learned
    home2, how2 = hosting.prepare_home(tmp_path / "vol2", node.url, env)
    assert "Ankara" in (home2.home / "memories" / "MEMORY.md").read_text()
    # the old copy of the file is refused by name, before anything is unpacked
    with pytest.raises(SingularError, match="old copy"):
        hosting.prepare_home(tmp_path / "vol3", node.url, {**env, "SINGULAR_PACKAGE": str(old_copy)})


def test_a_new_package_of_the_current_state_starts(world, tmp_path):
    """Exporting and packing the agent again (a re-move, or after a sale) makes a file with a new digest but
    the current state: it starts. A copy whose state the ledger has moved past is still refused."""
    _, node, ledger, agent, registry = world
    out = _package(world, tmp_path)
    old_copy = tmp_path / "old-ada.tar"
    old_copy.write_bytes(out.read_bytes())
    from conftest import PASS
    env = {"SINGULAR_PACKAGE": str(out), "SINGULAR_CAPSULE": pack.CAPSULE_IN_IMAGE,
           "SINGULAR_CAPSULE_PASSPHRASE": CAPSULE_PASS, "SINGULAR_PASSPHRASE": PASS}
    home, _ = hosting.prepare_home(tmp_path / "vol1", node.url, env)
    _run_once(home, ledger, "- learned that the client is in Ankara\n")
    assert hosting.repack_package(home, node.url, env, lambda *a, **f: None)["no"] == 1

    again = tmp_path / "pkg2" / "ada.tar"
    again.parent.mkdir()
    pack.pack(export(home, ledger, tmp_path / "again.capsule"), node.url, base=fake_runtime(registry), out=again, tag="ada:v2")
    assert pack.package_info(again)["capsule_digest"].removeprefix("sha256:") != \
        ledger.get_agent(agent.agent_id)["package"]["capsule"]
    home2, how = hosting.prepare_home(tmp_path / "vol2", node.url, {**env, "SINGULAR_PACKAGE": str(again)})
    assert how["source"] == "package" and "Ankara" in (home2.home / "memories" / "MEMORY.md").read_text()
    with pytest.raises(SingularError, match="old copy"):
        hosting.prepare_home(tmp_path / "vol3", node.url, {**env, "SINGULAR_PACKAGE": str(old_copy)})


def test_a_sale_clears_the_package_record(agent, ledger, chain, owner):
    from singular import agent as A
    from singular.keys import SigningKey
    from singular.ledger import tx as T
    from conftest import PASS
    A.record_package(agent, ledger, agent.unlock(PASS), "sha256:" + "1" * 64, "sha256:" + "2" * 64)
    record = ledger.get_agent(agent.agent_id)
    assert record["package"]["no"] == 1
    buyer, new_agent = SigningKey.generate(), SigningKey.generate()
    txn = T.build(T.TRANSFER, agent.agent_id, record["nonce"] + 1, {
        "new_owner_pub": buyer.public_hex, "new_agent_pub": new_agent.public_hex, "new_enc_pub": new_agent.enc_public_hex,
        "root": record["seal"]["root"], "memory_root": ledger.get_bank(record["memory_bank"])["seal"]["root"]})
    for role, key in (("owner", owner), ("new_owner", buyer), ("new_agent", new_agent)):
        T.sign(txn, chain.chain_id, role, key)
    ledger.submit(txn)
    assert ledger.get_agent(agent.agent_id)["package"] is None     # the seller's file is not the buyer's


def test_package_records_follow_the_ledger_rules(world, tmp_path):
    from singular.keys import SigningKey
    from singular.ledger import tx as T
    from singular.errors import LedgerRejected
    from singular.runtime import SingularGuard
    from conftest import PASS
    from singular import agent as A
    _, node, ledger, agent, _ = world
    key = agent.unlock(PASS)
    A.record_package(agent, ledger, key, "sha256:" + "1" * 64, "sha256:" + "2" * 64)
    assert ledger.get_agent(agent.agent_id)["package"]["no"] == 1
    guard = SingularGuard(agent, ledger, PASS)
    guard.start()
    try:
        with pytest.raises(LedgerRejected, match="LEASE_HELD"):   # never while a copy is running
            A.record_package(agent, ledger, key, "sha256:" + "3" * 64, "sha256:" + "4" * 64)
    finally:
        guard.stop()
    record = ledger.get_agent(agent.agent_id)
    body = {"capsule": "5" * 64, "image": "6" * 64, "root": "7" * 64,
            "memory_root": "8" * 64, "actions_head": record["actions"]["head"]}
    with pytest.raises(LedgerRejected, match="STALE_STATE"):       # only for the current state
        A.submit(ledger, agent.identity["chain_id"], T.PACKAGE, agent.agent_id, record["nonce"] + 1, body, {"agent": key})
    report = A.verify(agent, ledger)
    body.update(root=report["core"]["root"], memory_root=report["memory"]["root"])
    with pytest.raises(LedgerRejected, match="BAD_SIGNATURE"):     # only the agent's own key
        A.submit(ledger, agent.identity["chain_id"], T.PACKAGE, agent.agent_id, record["nonce"] + 1, body,
                 {"agent": SigningKey.generate()})
    A.submit(ledger, agent.identity["chain_id"], T.PACKAGE, agent.agent_id, record["nonce"] + 1, body, {"agent": key})
    assert ledger.get_agent(agent.agent_id)["package"]["no"] == 2
