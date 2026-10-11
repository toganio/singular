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
