"""``singular pack``: bake one agent into one standalone image.

The runtime image (``singular/hosting/Dockerfile``) holds Hermes and Singular but no agent. ``pack`` adds one
layer to it that holds the agent's capsule, and points the image's environment at it::

    base runtime image layers (Python, Hermes, Singular)     unchanged, shared by every agent image
    + one layer: /opt/singular/agent.sngcap                  the ``export --move`` capsule, byte for byte
    config: SINGULAR_CAPSULE / SINGULAR_CAPSULE_DIGEST / SINGULAR_LEDGER, dev.singular.* labels

The result runs with one ``docker run`` (or any OCI runtime: Podman, Kubernetes, Cloud Run) and needs nothing
installed beside it. It travels as a registry reference pinned by digest (``--push``) or as a single file
(``--out agent.tar``, an OCI image layout archive that ``docker load`` and ``podman load`` read).

Copying the box does not copy the agent. The capsule in it opens only while its roots are the ledger's
current ones, and the run lease lets one copy run at a time; once the agent has run and sealed new memories,
the baked capsule is stale and every other copy of the image refuses to start. The living agent is the
``/agent/home`` volume; to move it again, ``export --move`` and ``pack`` again.

No Docker is needed to pack: the base is read from a registry (or a ``docker save`` archive) and the new
image is written with the plain registry HTTP API, like ``crane append``.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, capsule, oci
from .errors import CapsuleError

CAPSULE_IN_IMAGE = "/opt/singular/agent.sngcap"
DEFAULT_BASE = f"ghcr.io/toganio/singular-runtime:{__version__}"
DEFAULT_PLATFORM = "linux/amd64"
RUNTIME_LABEL = "dev.singular.runtime"   # set by singular/hosting/Dockerfile; pack refuses any other base

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = oci.MANIFEST_TYPE
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_TAR = "application/vnd.oci.image.layer.v1.tar"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
ACCEPT = (OCI_INDEX, OCI_MANIFEST, DOCKER_LIST, DOCKER_MANIFEST)
# Docker's layer types are OCI's under another name (same bytes); the agent image is always written as OCI.
_LAYER_TYPES = {
    "application/vnd.docker.image.rootfs.diff.tar.gzip": "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+gzip": "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd": "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.oci.image.layer.v1.tar": OCI_LAYER_TAR,
    "application/vnd.docker.image.rootfs.diff.tar": OCI_LAYER_TAR,
}
_OURS = ("SINGULAR_CAPSULE", "SINGULAR_CAPSULE_DIGEST", "SINGULAR_LEDGER")
_MAX_CONFIG = 1 << 20
_NAME = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _platform(text: str) -> dict:
    parts = text.split("/")
    if len(parts) not in (2, 3) or not all(parts):
        raise CapsuleError(f"platform looks like linux/amd64 or linux/arm64/v8, not {text!r}")
    return {"os": parts[0], "architecture": parts[1], **({"variant": parts[2]} if len(parts) == 3 else {})}


def _pick(index: dict, platform: dict, have: Callable[[str], bool] = lambda _d: True) -> dict:
    for desc in index.get("manifests") or []:
        p = desc.get("platform") or {}
        if p.get("os") == platform["os"] and p.get("architecture") == platform["architecture"] \
                and platform.get("variant") in (None, p.get("variant")) and have(desc.get("digest", "")):
            return desc
    wanted = "/".join(platform.values())
    raise CapsuleError(f"the base image has no {wanted} variant (choose another with --platform)")


@dataclass
class Base:
    """A runtime image to build on: its manifest digest, its config and layers, and a way to read its blobs."""
    name: str
    digest: str
    config: dict
    layers: list[dict]
    open_blob: Callable[[str], contextlib.AbstractContextManager]
    registry: str | None = None      # set when it lives in a registry, so a push there can mount its layers
    repository: str | None = None
    _close: list = field(default_factory=list)

    def close(self) -> None:
        for closer in self._close:
            closer()


def _check_runtime(config: dict, name: str) -> None:
    labels = (config.get("config") or {}).get("Labels") or {}
    if labels.get(RUNTIME_LABEL) != "1":
        raise CapsuleError(f"{name} is not a Singular runtime image (no {RUNTIME_LABEL} label); "
                           "build singular/hosting/Dockerfile or use the published runtime")
    if f"{oci.ANNOTATION_PREFIX}agent_id" in labels:
        raise CapsuleError(f"{name} already holds an agent ({labels[oci.ANNOTATION_PREFIX + 'agent_id']}); "
                           "pack on the plain runtime image")
    if config.get("rootfs", {}).get("type") != "layers":
        raise CapsuleError("the base image config has no layer list")


def _layers(manifest: dict, config: dict) -> list[dict]:
    layers = []
    for desc in manifest.get("layers") or []:
        media = _LAYER_TYPES.get(desc.get("mediaType", ""))
        if not media or not re.match(r"^sha256:[0-9a-f]{64}$", str(desc.get("digest", ""))) or int(desc.get("size", -1)) < 0:
            raise CapsuleError(f"the base image has a layer pack cannot carry ({desc.get('mediaType')})")
        layers.append({**{k: v for k, v in desc.items() if k in ("digest", "size", "annotations")}, "mediaType": media})
    if len(layers) != len(config["rootfs"].get("diff_ids") or []):
        raise CapsuleError("the base image's manifest and config disagree on its layers")
    return layers


def open_registry_base(ref_text: str, platform: str = DEFAULT_PLATFORM, *, credentials: bool = True) -> Base:
    ref = oci.parse_reference(ref_text)
    reg = oci.Registry(ref.registry, **({} if credentials else {"user": "", "password": ""}))
    raw, media = reg.get_manifest(ref.repository, ref.target, ACCEPT)
    doc = json.loads(raw)
    media = doc.get("mediaType") or media
    digest = _sha(raw)
    if media in (OCI_INDEX, DOCKER_LIST):
        desc = _pick(doc, _platform(platform))
        raw, media = reg.get_manifest(ref.repository, desc["digest"], ACCEPT)
        doc, digest = json.loads(raw), desc["digest"]
        media = doc.get("mediaType") or media
    if media not in (OCI_MANIFEST, DOCKER_MANIFEST):
        raise CapsuleError(f"{ref} is not an image (manifest type {media!r})")
    cfg_desc = doc.get("config") or {}
    if not 0 < int(cfg_desc.get("size", 0)) <= _MAX_CONFIG:
        raise CapsuleError("the base image config has an impossible size")
    with reg.open_blob(ref.repository, cfg_desc["digest"]) as response:
        cfg_raw = response.read(_MAX_CONFIG + 1)
    if _sha(cfg_raw) != cfg_desc["digest"]:
        raise CapsuleError("the base image config does not match its digest")
    config = json.loads(cfg_raw)
    _check_runtime(config, str(ref))
    return Base(name=str(ref), digest=digest, config=config, layers=_layers(doc, config),
                open_blob=lambda d: reg.open_blob(ref.repository, d), registry=ref.registry, repository=ref.repository)


def open_archive_base(path: Path, platform: str = DEFAULT_PLATFORM) -> Base:
    """A ``docker save`` / ``podman save`` archive: an OCI image layout (``index.json``), or Docker's older
    ``manifest.json`` format."""
    tar = tarfile.open(path, "r:")
    try:
        names = {m.name.removeprefix("./"): m for m in tar.getmembers() if m.isfile()}

        def read(name: str, limit: int = _MAX_CONFIG) -> bytes:
            member = names.get(name)
            if member is None or member.size > limit:
                raise CapsuleError(f"{path} has no usable {name}")
            return tar.extractfile(member).read()

        def blob_name(digest: str) -> str:
            return "blobs/" + digest.replace(":", "/", 1)

        def open_blob(digest: str):
            member = names.get(by_digest.get(digest, blob_name(digest)))
            if member is None:
                raise CapsuleError(f"{path} lacks blob {digest}")
            return contextlib.closing(tar.extractfile(member))

        by_digest: dict[str, str] = {}
        if "index.json" in names:
            doc = json.loads(read("index.json"))
            want = _platform(platform)
            while True:
                descs = doc.get("manifests") or []
                if len(descs) == 1 and "platform" not in descs[0]:
                    desc = descs[0]
                else:
                    desc = _pick(doc, want, lambda d: blob_name(d) in names)
                raw = read(blob_name(desc["digest"]), oci.MAX_MANIFEST)
                if _sha(raw) != desc["digest"]:
                    raise CapsuleError(f"{path}: a manifest does not match its digest")
                doc = json.loads(raw)
                if (doc.get("mediaType") or desc.get("mediaType")) not in (OCI_INDEX, DOCKER_LIST):
                    break
            digest, manifest = desc["digest"], doc
            config_raw = read(blob_name(manifest["config"]["digest"]))
        else:  # docker's legacy archive: paths, no digests, layers possibly uncompressed
            entries = json.loads(read("manifest.json"))
            if not isinstance(entries, list) or len(entries) != 1:
                raise CapsuleError(f"{path} must hold exactly one image")
            config_raw = read(entries[0]["Config"])
            layers = []
            for name in entries[0]["Layers"]:
                hasher, member = hashlib.sha256(), names[name]
                with contextlib.closing(tar.extractfile(member)) as handle:
                    head = handle.read(2)
                    hasher.update(head)
                    while block := handle.read(1 << 20):
                        hasher.update(block)
                d = "sha256:" + hasher.hexdigest()
                by_digest[d] = name
                layers.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip" if head == b"\x1f\x8b"
                               else OCI_LAYER_TAR, "digest": d, "size": member.size})
            manifest = {"layers": layers, "config": {"digest": _sha(config_raw)}}
            digest = None
        config = json.loads(config_raw)
        if _sha(config_raw) != manifest["config"]["digest"]:
            raise CapsuleError(f"{path}: the image config does not match its digest")
        _check_runtime(config, str(path))
        if digest is None:  # what the base manifest would have been, so the label still names it exactly
            digest = _sha(json.dumps(manifest, sort_keys=True).encode())
        return Base(name=Path(path).name, digest=digest, config=config, layers=_layers(manifest, config),
                    open_blob=open_blob, _close=[tar.close])
    except BaseException:
        tar.close()
        raise


def open_base(base: str, platform: str = DEFAULT_PLATFORM, *, credentials: bool = True) -> Base:
    if base.startswith("oci://") or not Path(base).exists():
        return open_registry_base(base, platform, credentials=credentials)
    return open_archive_base(Path(base), platform)


# -- the agent image ------------------------------------------------------------------------------

@dataclass
class AgentImage:
    manifest: bytes
    config: bytes
    layer_path: Path          # the capsule layer (uncompressed tar, so its digest is also its diff id)
    layer: dict               # its descriptor
    meta: dict                # the capsule header's meta

    @property
    def digest(self) -> str:
        return _sha(self.manifest)


def _epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH")
    return int(value) if value and value.isdigit() else int(time.time())


def _capsule_layer(capsule_path: Path, out: Path, mtime: int) -> dict:
    """``/opt/singular/agent.sngcap``, read-only, owned by root; deterministic bytes for one capsule."""
    with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tar:
        for name in ("opt", "opt/singular"):
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, mtime
            tar.addfile(info)
        info = tarfile.TarInfo(CAPSULE_IN_IMAGE.lstrip("/"))
        info.size, info.mode, info.mtime = capsule_path.stat().st_size, 0o444, mtime
        with open(capsule_path, "rb") as handle:
            tar.addfile(info, handle)
    data_digest = "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest()
    return {"mediaType": OCI_LAYER_TAR, "digest": data_digest, "size": out.stat().st_size,
            "annotations": {"org.opencontainers.image.title": "agent.sngcap"}}


def build(base: Base, capsule_path: Path, ledger_url: str, workdir: Path) -> AgentImage:
    header = capsule.read_header(capsule_path)
    meta = header.get("meta") or {}
    if meta.get("for_sale", True):
        raise CapsuleError("this capsule was made for a sale (it carries no agent key) and cannot run; "
                           "pack a capsule from `singular export --move`")
    if not ledger_url.startswith(("https://", "http://")):
        raise CapsuleError("--ledger must be the ledger's URL")
    capsule_digest = "sha256:" + hashlib.sha256(Path(capsule_path).read_bytes()).hexdigest()
    mtime = _epoch()
    layer_path = workdir / "capsule-layer.tar"
    layer = _capsule_layer(Path(capsule_path), layer_path, mtime)

    labels = {f"{oci.ANNOTATION_PREFIX}{k}": str(v).lower() if isinstance(v, bool) else str(v) for k, v in sorted(meta.items())}
    labels.update({"org.opencontainers.image.base.name": base.name, "org.opencontainers.image.base.digest": base.digest,
                   f"{oci.ANNOTATION_PREFIX}capsule_digest": capsule_digest, f"{oci.ANNOTATION_PREFIX}ledger": ledger_url})
    config = copy.deepcopy(base.config)
    inner = config.setdefault("config", {})
    env = [e for e in inner.get("Env") or [] if e.split("=", 1)[0] not in _OURS]
    inner["Env"] = env + [f"SINGULAR_CAPSULE={CAPSULE_IN_IMAGE}", f"SINGULAR_CAPSULE_DIGEST={capsule_digest}",
                          f"SINGULAR_LEDGER={ledger_url}"]
    inner["Labels"] = {**(inner.get("Labels") or {}), **labels}
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
    config["created"] = created
    config["rootfs"]["diff_ids"] = [*config["rootfs"]["diff_ids"], layer["digest"]]
    config["history"] = [*(config.get("history") or []),
                         {"created": created, "created_by": f"singular pack {__version__}", "comment": "the agent's capsule"}]
    config_raw = json.dumps(config, separators=(",", ":"), sort_keys=True).encode()
    manifest = {
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": _sha(config_raw), "size": len(config_raw)},
        "layers": [*base.layers, layer],
        "annotations": {k: v for k, v in labels.items()},
    }
    raw = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
    return AgentImage(manifest=raw, config=config_raw, layer_path=layer_path, layer=layer, meta=meta)


class _Hashing:
    """Reads through to ``inner`` and hashes what passed, so copied blobs are checked on the way."""

    def __init__(self, inner):
        self.inner, self.hasher, self.count = inner, hashlib.sha256(), 0

    def read(self, size: int = -1) -> bytes:
        block = self.inner.read(size)
        self.hasher.update(block)
        self.count += len(block)
        return block

    def check(self, desc: dict) -> None:
        if self.count != int(desc["size"]) or "sha256:" + self.hasher.hexdigest() != desc["digest"]:
            raise CapsuleError(f"base layer {desc['digest']} did not arrive intact")


def push(image: AgentImage, base: Base, target: str) -> dict:
    ref = oci.parse_reference(target)
    if ref.digest:
        raise CapsuleError("push to a tag, not a digest")
    reg = oci.Registry(ref.registry)
    mount_from = base.repository if base.registry == ref.registry else None
    for desc in base.layers:
        if reg._blob_exists(ref.repository, desc["digest"]):
            continue
        if mount_from and reg.mount(ref.repository, desc["digest"], mount_from):
            continue
        with tempfile.TemporaryFile() as spool:
            with base.open_blob(desc["digest"]) as source:
                reader = _Hashing(source)
                shutil.copyfileobj(reader, spool, 1 << 20)
            reader.check(desc)
            spool.seek(0)
            reg._upload(ref.repository, spool, desc["digest"], int(desc["size"]))
    with open(image.layer_path, "rb") as handle:
        reg._upload(ref.repository, handle, image.layer["digest"], image.layer["size"])
    reg._upload(ref.repository, image.config, _sha(image.config))
    reg.put_manifest(ref.repository, ref.target, image.manifest, OCI_MANIFEST)
    return {"image": f"{ref.registry}/{ref.repository}@{image.digest}", "manifest_digest": image.digest}


def _qualified(name: str) -> str:
    """containerd (and so Docker's own image store) looks images up by their full name: ``ada:v1`` is
    ``docker.io/library/ada:v1``, ``you/ada:v1`` is ``docker.io/you/ada:v1``."""
    first = name.split("/", 1)[0]
    if "/" in name and ("." in first or ":" in first or first == "localhost"):
        return name
    return "docker.io/" + (name if "/" in name else "library/" + name)


def write_archive(image: AgentImage, base: Base, out: Path, name: str) -> dict:
    """One file: an OCI image layout in a tar, with Docker's ``manifest.json`` too so every ``docker load``
    (and ``podman load``) takes it and tags it ``name``."""
    if not _NAME.match(name):
        raise CapsuleError(f"--tag must look like name:tag, e.g. ada:latest (got {name!r})")
    repo, _, tag = name.rpartition(":")
    blob = lambda d: "blobs/" + d.replace(":", "/", 1)  # noqa: E731
    index = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [{
        "mediaType": OCI_MANIFEST, "digest": image.digest, "size": len(image.manifest),
        "annotations": {"org.opencontainers.image.ref.name": tag, "io.containerd.image.name": _qualified(name)}}]}
    layers = [*base.layers, image.layer]
    legacy = [{"Config": blob(_sha(image.config)), "RepoTags": [name], "Layers": [blob(d["digest"]) for d in layers]}]
    tmp = out.with_name(out.name + ".part")
    mtime = _epoch()

    def add_bytes(tar, path, data):
        info = tarfile.TarInfo(path)
        info.size, info.mtime, info.mode = len(data), mtime, 0o644
        tar.addfile(info, io.BytesIO(data))

    try:
        with tarfile.open(tmp, "w", format=tarfile.PAX_FORMAT) as tar:
            add_bytes(tar, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
            add_bytes(tar, "index.json", json.dumps(index, sort_keys=True).encode())
            add_bytes(tar, "manifest.json", json.dumps(legacy).encode())
            add_bytes(tar, blob(image.digest), image.manifest)
            add_bytes(tar, blob(_sha(image.config)), image.config)
            for desc in base.layers:
                info = tarfile.TarInfo(blob(desc["digest"]))
                info.size, info.mtime, info.mode = int(desc["size"]), mtime, 0o644
                with base.open_blob(desc["digest"]) as source:
                    reader = _Hashing(source)
                    try:
                        tar.addfile(info, reader)
                    except OSError:  # shorter than its manifest says
                        raise CapsuleError(f"base layer {desc['digest']} did not arrive intact") from None
                reader.check(desc)
            info = tarfile.TarInfo(blob(image.layer["digest"]))
            info.size, info.mtime, info.mode = image.layer["size"], mtime, 0o644
            with open(image.layer_path, "rb") as handle:
                tar.addfile(info, handle)
        os.replace(tmp, out)
    finally:
        if tmp.exists():
            tmp.unlink()
    return {"image": str(out), "tag": name, "manifest_digest": image.digest, "size": out.stat().st_size}


def pack(capsule_path: Path, ledger_url: str, *, base: str | None = None, push_to: str | None = None,
         out: Path | None = None, tag: str | None = None, platform: str = DEFAULT_PLATFORM) -> dict:
    if (push_to is None) == (out is None):
        raise CapsuleError("say where the image goes: --push registry/repo:tag or --out agent.tar")
    base = base or DEFAULT_BASE
    same_registry = push_to is not None and oci.parse_reference(push_to).registry == base.removeprefix("oci://").split("/")[0]
    # registry credentials belong to the registry they were given for; a base elsewhere is read anonymously
    opened = open_base(base, platform, credentials=same_registry)
    try:
        with tempfile.TemporaryDirectory(prefix="singular-pack-") as work:
            image = build(opened, Path(capsule_path), ledger_url, Path(work))
            if push_to:
                result = push(image, opened, push_to)
                where = result["image"]
            else:
                agent = str(image.meta.get("agent_id", "agent")).lower()
                result = write_archive(image, opened, Path(out), tag or f"singular/{re.sub(r'[^a-z0-9]', '', agent)[:16] or 'agent'}:latest")
                where = result["tag"]
    finally:
        opened.close()
    run = ("docker run -d --name agent --read-only --tmpfs /tmp -v agent-home:/agent/home "
           f"-e SINGULAR_PASSPHRASE -e SINGULAR_CAPSULE_PASSPHRASE -e OPENROUTER_API_KEY {where}")
    return {**result, "agent_id": image.meta.get("agent_id"), "base": opened.name, "base_digest": opened.digest,
            "ledger": ledger_url, "run": run}
