# Singular runtime image

One container runs one Singular agent: Hermes Agent with the Singular plugin, under the agent's run lease.
Singular Cloud runs this image; you can run the same image on your own machine.

```bash
docker build -f singular/hosting/Dockerfile -t singular-runtime .          # from the repository root
```

## What happens when it starts

1. **First start only:** the `/agent/home` volume is empty, so `singular host` fetches the capsule named by
   `SINGULAR_CAPSULE`, opens it with `SINGULAR_CAPSULE_PASSPHRASE`, and checks every file against the ledger.
   A stale or altered capsule is refused here.
2. It writes the agent's `.env` from the secrets file (your model key, bot tokens) and installs `SINGULAR_CONFIG`.
3. It takes the run lease on the ledger and runs Hermes (`hermes gateway run`) inside it.
4. On `docker stop` (SIGTERM) Hermes shuts down, Singular seals what the agent learned and releases the lease.
5. Later starts skip step 1: the agent lives in the volume, with everything it learned.

## Running it

```bash
cat > secrets.env <<'SECRETS'
SINGULAR_PASSPHRASE=…            # the agent's own key
SINGULAR_CAPSULE_PASSPHRASE=…    # only needed for the first start
OPENROUTER_API_KEY=…             # anything not SINGULAR_* becomes the agent's .env
TELEGRAM_BOT_TOKEN=…
SECRETS

docker run -d --name ada \
  -v ada-home:/agent/home \
  -v "$PWD/secrets.env:/run/secrets/singular.env:ro" \
  -v "$PWD/config.yaml:/run/config.yaml:ro" -e SINGULAR_CONFIG=/run/config.yaml \
  -e SINGULAR_LEDGER=https://ledger.example \
  -e SINGULAR_CAPSULE=oci://ghcr.io/you/ada@sha256:… \
  singular-runtime
```

The capsule must be made for hosting: `singular export --move` (a capsule made for a sale carries no agent key
and cannot run). Never put the **owner** passphrase in the secrets file; the image refuses it.

All settings are listed at the top of [`hosting.py`](../src/singular/hosting.py). `SINGULAR_REPORT_URL` and
`SINGULAR_REPORT_TOKEN` let a control plane follow state changes (`starting`, `running`, `stopped`, `failed`);
the ledger stays the source of truth for whether the agent is running.

## One agent, one image (`singular pack`)

The runtime image above holds no agent and pulls one on first start. `singular pack` makes the other kind: an
image with the agent inside, which runs with nothing else installed and no capsule to fetch.

```bash
singular export --move --out ada.capsule                       # stop the agent first
singular pack ada.capsule --ledger https://ledger.example --push ghcr.io/you/ada:v1   # prints ghcr.io/you/ada@sha256:…
singular pack ada.capsule --ledger https://ledger.example --out ada.tar --tag ada:v1  # or: one file
```

Then, on any machine with Docker or Podman:

```bash
docker load -i ada.tar                                         # only for the one-file form
docker run -d --name ada --read-only --tmpfs /tmp -v ada-home:/agent/home \
  -e SINGULAR_PASSPHRASE -e SINGULAR_CAPSULE_PASSPHRASE -e OPENROUTER_API_KEY ada:v1
docker run -it --read-only --tmpfs /tmp -v ada-home:/agent/home -e SINGULAR_PASSPHRASE -e OPENROUTER_API_KEY ada:v1 hermes   # a chat
```

`pack` adds one layer to the runtime image holding the capsule at `/opt/singular/agent.sngcap`, and sets
`SINGULAR_CAPSULE`, `SINGULAR_CAPSULE_DIGEST` and `SINGULAR_LEDGER` in the image. It needs no Docker: it reads
the base from a registry (default `ghcr.io/toganio/singular-runtime:<version>`, or a `docker save` archive
with `--base`) and writes the new image with the registry API. The base digest is recorded in the image labels.

What the box does and does not guarantee:

- **Portable and tamper-evident.** The image is one artifact, pinned by digest; the capsule inside is encrypted,
  and every file it unpacks must hash to what the ledger sealed.
- **Nothing else writes into it.** Hermes, Singular and the capsule are image layers, fixed by the image digest
  and owned by root; the agent runs as an unprivileged user. Run it with `--read-only` (as above) and the only
  writable place is the agent's own home. Inside that home, every core file and the internal memory are sealed:
  at each start the files are checked against the ledger before the agent runs, and a change that did not come
  from a sealed run (another app, a person, a stray mount) stops the start.
- **Never two at once** comes from the ledger, not the box. Any number of copies of the image can exist; the
  run lease lets one run at a time, and a second copy started beside it is refused.
- **Copies go stale.** Once the agent has run and sealed what it learned, the capsule baked in the image is
  behind the ledger and no copy of the image can start a new agent from it. The living agent is the
  `/agent/home` volume: always give it a named volume (`docker run --rm` would delete an anonymous one, and
  with it what the agent learned). To move it again, `export --move` from that volume and `pack` again.
- **Accountable.** The actions the agent takes are anchored on the ledger under its own key, wherever the
  image runs.

## Capsules in a registry

A capsule is pushed as an OCI artifact (`artifactType application/vnd.singular.capsule.v1`, one layer
`application/vnd.singular.capsule.v1+sngcap` holding the capsule file unchanged, header metadata as
`dev.singular.*` annotations). See [`oci.py`](../src/singular/oci.py). Pin references by digest.

## Test

`singular/hosting/e2e.sh [image]` starts a real ledger node and a `registry:2`, creates an agent, pushes it,
runs the image, and checks the lease on the ledger through start, `docker stop` and restart. CI runs it in
`.github/workflows/singular-hosting.yml`.
