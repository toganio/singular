"""Capsules in an OCI registry: push and pull a ``singular export`` file like an image.

A capsule travels as an OCI artifact (image manifest v1 with an ``artifactType``)::

    manifest   application/vnd.oci.image.manifest.v1+json, artifactType application/vnd.singular.capsule.v1
    config     the OCI empty descriptor
    layer[0]   application/vnd.singular.capsule.v1+sngcap   the capsule file, byte for byte
    annotations dev.singular.agent_id / chain_id / core_root / memory_root / for_sale   (copied from its header)

The registry is only a shelf. The capsule stays encrypted, and what makes the unpacked agent *the* agent is
still that its roots match the ledger (``import_capsule`` re-verifies). Pinning a reference by digest
(``repo@sha256:…``) makes the shelf unable to hand over a different parcel; a layer whose bytes do not hash to
the manifest's digest is refused either way.

Only the plain registry HTTP API is used (no extra dependency): anonymous access, HTTP basic, and the bearer
token dance (``WWW-Authenticate: Bearer realm=…``). Credentials come from ``SINGULAR_REGISTRY_USER`` and
``SINGULAR_REGISTRY_PASSWORD``, never from arguments.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import capsule
from .errors import CapsuleError

ARTIFACT_TYPE = "application/vnd.singular.capsule.v1"
LAYER_TYPE = "application/vnd.singular.capsule.v1+sngcap"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
EMPTY_TYPE = "application/vnd.oci.empty.v1+json"
EMPTY_BLOB = b"{}"
EMPTY_DIGEST = "sha256:" + hashlib.sha256(EMPTY_BLOB).hexdigest()
ANNOTATION_PREFIX = "dev.singular."
MAX_MANIFEST = 4 * 1024 * 1024

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPO = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class Reference:
    registry: str      # host[:port]
    repository: str
    tag: str | None = None
    digest: str | None = None

    @property
    def target(self) -> str:
        return self.digest or self.tag or "latest"

    def __str__(self) -> str:
        return f"{self.registry}/{self.repository}" + (f"@{self.digest}" if self.digest else f":{self.tag or 'latest'}")


def parse_reference(ref: str) -> Reference:
    """``registry/repo[:tag][@sha256:…]``, optionally prefixed with ``oci://``. The registry part is mandatory
    (no implicit Docker Hub): a capsule should never be fetched from somewhere the operator did not name."""
    ref = ref.removeprefix("oci://")
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        if not _DIGEST.match(digest):
            raise CapsuleError(f"not a sha256 digest: {digest!r}")
    registry, _, rest = ref.partition("/")
    if not rest or not ("." in registry or ":" in registry or registry == "localhost"):
        raise CapsuleError(f"name the registry explicitly, e.g. ghcr.io/you/agent:tag (got {ref!r})")
    tag = None
    if ":" in rest.rsplit("/", 1)[-1]:
        rest, tag = rest.rsplit(":", 1)
        if not _TAG.match(tag):
            raise CapsuleError(f"bad tag: {tag!r}")
    if not _REPO.match(rest):
        raise CapsuleError(f"bad repository name: {rest!r}")
    return Reference(registry, rest, tag, digest)


def _scheme(registry: str) -> str:
    # Plain HTTP only for a registry on this machine (tests, a local `registry:2`); everything else is TLS.
    host = registry.rsplit(":", 1)[0] if registry.count(":") == 1 else registry
    if os.environ.get("SINGULAR_REGISTRY_INSECURE") == "1" or host in ("localhost", "127.0.0.1", "[::1]"):
        return "http"
    return "https"


class Registry:
    def __init__(self, registry: str, *, user: str | None = None, password: str | None = None, timeout: float = 60):
        self.base = f"{_scheme(registry)}://{registry}/v2/"
        self.user = user if user is not None else os.environ.get("SINGULAR_REGISTRY_USER")
        self.password = password if password is not None else os.environ.get("SINGULAR_REGISTRY_PASSWORD")
        self.timeout = timeout
        self._auth: str | None = None

    # -- auth ------------------------------------------------------------------------------

    def _basic(self) -> str | None:
        if not self.user:
            return None
        return "Basic " + base64.b64encode(f"{self.user}:{self.password or ''}".encode()).decode()

    def _login(self, challenge: str) -> None:
        scheme, _, params = challenge.partition(" ")
        if scheme.lower() == "basic":
            self._auth = self._basic()
            if not self._auth:
                raise CapsuleError("the registry wants a login: set SINGULAR_REGISTRY_USER and SINGULAR_REGISTRY_PASSWORD")
            return
        if scheme.lower() != "bearer":
            raise CapsuleError(f"unsupported registry auth scheme: {scheme}")
        fields = dict(re.findall(r'(\w+)="([^"]*)"', params))
        realm = fields.pop("realm", "")
        if not realm.startswith(("https://", "http://")):
            raise CapsuleError("registry sent a token realm that is not a URL")
        url = realm + "?" + urllib.parse.urlencode({k: v for k, v in fields.items() if k in ("service", "scope")})
        request = urllib.request.Request(url)
        if basic := self._basic():
            request.add_header("Authorization", basic)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - registry's own realm
                body = json.loads(response.read(1 << 20))
        except (urllib.error.URLError, ValueError) as exc:
            raise CapsuleError(f"registry login failed: {exc}") from None
        token = body.get("token") or body.get("access_token")
        if not isinstance(token, str) or not token:
            raise CapsuleError("registry login returned no token")
        self._auth = "Bearer " + token

    def _open(self, method: str, url: str, *, data: bytes | None = None, headers: dict | None = None):
        for attempt in (0, 1):
            request = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}))
            if self._auth:  # unredirected: a blob redirect to a CDN must not carry the registry login along
                request.add_unredirected_header("Authorization", self._auth)
            try:
                return urllib.request.urlopen(request, timeout=self.timeout)  # noqa: S310 - operator-named registry
            except urllib.error.HTTPError as exc:
                challenge = exc.headers.get("WWW-Authenticate", "")
                if exc.code == 401 and attempt == 0 and challenge:
                    self._login(challenge)
                    continue
                detail = exc.read(2048).decode("utf-8", "replace")
                raise CapsuleError(f"registry said {exc.code} for {method} {url}: {detail.strip()[:300]}") from None
            except urllib.error.URLError as exc:
                raise CapsuleError(f"registry unreachable: {exc.reason}") from None
        raise CapsuleError("registry refused the login")  # pragma: no cover

    # -- pull ------------------------------------------------------------------------------

    def manifest(self, ref: Reference) -> tuple[dict, str]:
        url = f"{self.base}{ref.repository}/manifests/{ref.target}"
        with self._open("GET", url, headers={"Accept": MANIFEST_TYPE}) as response:
            raw = response.read(MAX_MANIFEST + 1)
        if len(raw) > MAX_MANIFEST:
            raise CapsuleError("manifest is unreasonably large")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if ref.digest and digest != ref.digest:
            raise CapsuleError(f"registry served a manifest with digest {digest}, not the pinned {ref.digest}")
        try:
            manifest = json.loads(raw)
        except ValueError:
            raise CapsuleError("manifest is not JSON") from None
        if not isinstance(manifest, dict) or manifest.get("artifactType") != ARTIFACT_TYPE:
            raise CapsuleError(f"{ref} is not a Singular capsule (artifactType {manifest.get('artifactType')!r})")
        layers = manifest.get("layers")
        if not isinstance(layers, list) or len(layers) != 1 or layers[0].get("mediaType") != LAYER_TYPE \
                or not _DIGEST.match(str(layers[0].get("digest", ""))):
            raise CapsuleError("a capsule artifact must have exactly one capsule layer")
        return manifest, digest

    def pull(self, ref: Reference, out_path: Path) -> dict:
        """Download the capsule to ``out_path``. Returns ``{"manifest_digest", "layer_digest", "annotations"}``."""
        manifest, manifest_digest = self.manifest(ref)
        layer = manifest["layers"][0]
        size = int(layer.get("size", -1))
        if not 0 < size <= capsule.MAX_UNPACKED_BYTES:
            raise CapsuleError("capsule layer has an impossible size")
        out_path = Path(out_path)
        tmp = out_path.with_name(out_path.name + ".part")
        hasher, written = hashlib.sha256(), 0
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as out, self._open("GET", f"{self.base}{ref.repository}/blobs/{layer['digest']}") as response:
                while block := response.read(1 << 20):
                    written += len(block)
                    if written > size:
                        raise CapsuleError("capsule layer is longer than its manifest says")
                    hasher.update(block)
                    out.write(block)
            if written != size or "sha256:" + hasher.hexdigest() != layer["digest"]:
                raise CapsuleError("capsule layer does not match its digest; refusing it")
            capsule.read_header(tmp)  # a parcel that is not a capsule fails here, before anyone types a passphrase
            os.replace(tmp, out_path)
        finally:
            if tmp.exists():
                tmp.unlink()
        return {"manifest_digest": manifest_digest, "layer_digest": layer["digest"],
                "annotations": manifest.get("annotations") or {}}

    # -- push ------------------------------------------------------------------------------

    def _blob_exists(self, repository: str, digest: str) -> bool:
        try:
            with self._open("HEAD", f"{self.base}{repository}/blobs/{digest}"):
                return True
        except CapsuleError as exc:
            if " 404 " in str(exc):
                return False
            raise

    def mount(self, repository: str, digest: str, from_repository: str) -> bool:
        """Borrow a blob another repository on this registry holds, without copying it. False if refused."""
        url = f"{self.base}{repository}/blobs/uploads/?" + urllib.parse.urlencode({"mount": digest, "from": from_repository})
        try:
            with self._open("POST", url, data=b"") as response:
                return response.status == 201   # 202 means the registry opened a plain upload instead
        except CapsuleError:
            return False

    def _upload(self, repository: str, data, digest: str, size: int | None = None) -> None:
        """Upload a blob (bytes, or an open binary file of ``size`` bytes) unless the repository has it."""
        if self._blob_exists(repository, digest):
            return
        with self._open("POST", f"{self.base}{repository}/blobs/uploads/", data=b"") as response:
            location = response.headers.get("Location")
        if not location:
            raise CapsuleError("registry gave no upload location")
        location = urllib.parse.urljoin(self.base, location)
        location += ("&" if "?" in location else "?") + urllib.parse.urlencode({"digest": digest})
        headers = {"Content-Type": "application/octet-stream"}
        if not isinstance(data, bytes | bytearray):
            headers["Content-Length"] = str(size)
        with self._open("PUT", location, data=data, headers=headers):
            pass

    # -- plain images (``singular pack`` reads a base image and writes an agent image) ----------

    def get_manifest(self, repository: str, target: str, accept: tuple[str, ...]) -> tuple[bytes, str]:
        """Any manifest or index, checked against the digest when ``target`` is one. Returns (raw, mediaType)."""
        with self._open("GET", f"{self.base}{repository}/manifests/{target}", headers={"Accept": ", ".join(accept)}) as response:
            raw = response.read(MAX_MANIFEST + 1)
            content_type = (response.headers.get("Content-Type") or "").split(";")[0].strip()
        if len(raw) > MAX_MANIFEST:
            raise CapsuleError("manifest is unreasonably large")
        if _DIGEST.match(target) and "sha256:" + hashlib.sha256(raw).hexdigest() != target:
            raise CapsuleError(f"registry served a manifest that does not hash to {target}")
        return raw, content_type

    def open_blob(self, repository: str, digest: str):
        return self._open("GET", f"{self.base}{repository}/blobs/{digest}")

    def put_manifest(self, repository: str, tag: str, raw: bytes, media_type: str) -> None:
        with self._open("PUT", f"{self.base}{repository}/manifests/{tag}", data=raw, headers={"Content-Type": media_type}):
            pass

    def push(self, capsule_path: Path, ref: Reference) -> dict:
        """Upload a capsule file and tag it. Returns ``{"manifest_digest", "layer_digest", "reference"}``."""
        if ref.digest:
            raise CapsuleError("push to a tag, not a digest")
        header = capsule.read_header(capsule_path)
        data = Path(capsule_path).read_bytes()
        layer_digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self._upload(ref.repository, EMPTY_BLOB, EMPTY_DIGEST)
        self._upload(ref.repository, data, layer_digest)
        annotations = {ANNOTATION_PREFIX + k: str(v).lower() if isinstance(v, bool) else str(v)
                       for k, v in sorted(header.get("meta", {}).items())}
        manifest = {
            "schemaVersion": 2, "mediaType": MANIFEST_TYPE, "artifactType": ARTIFACT_TYPE,
            "config": {"mediaType": EMPTY_TYPE, "digest": EMPTY_DIGEST, "size": len(EMPTY_BLOB)},
            "layers": [{"mediaType": LAYER_TYPE, "digest": layer_digest, "size": len(data),
                        "annotations": {"org.opencontainers.image.title": Path(capsule_path).name}}],
            "annotations": annotations,
        }
        raw = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
        with self._open("PUT", f"{self.base}{ref.repository}/manifests/{ref.target}", data=raw,
                        headers={"Content-Type": MANIFEST_TYPE}):
            pass
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        return {"manifest_digest": digest, "layer_digest": layer_digest,
                "reference": f"{ref.registry}/{ref.repository}@{digest}"}


def pull(ref: str, out_path: Path) -> dict:
    parsed = parse_reference(ref)
    return Registry(parsed.registry).pull(parsed, out_path)


def push(capsule_path: Path, ref: str) -> dict:
    parsed = parse_reference(ref)
    return Registry(parsed.registry).push(capsule_path, parsed)
