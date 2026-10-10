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

## Capsules in a registry

A capsule is pushed as an OCI artifact (`artifactType application/vnd.singular.capsule.v1`, one layer
`application/vnd.singular.capsule.v1+sngcap` holding the capsule file unchanged, header metadata as
`dev.singular.*` annotations). See [`oci.py`](../src/singular/oci.py). Pin references by digest.

## Test

`singular/hosting/e2e.sh [image]` starts a real ledger node and a `registry:2`, creates an agent, pushes it,
runs the image, and checks the lease on the ledger through start, `docker stop` and restart. CI runs it in
`.github/workflows/singular-hosting.yml`.
