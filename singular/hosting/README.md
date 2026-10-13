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

## One agent, one file (`singular pack`)

The runtime image above holds no agent and pulls one on first start. `singular pack` makes the other kind: one
file that holds everything, like a VM disk. Hermes, Singular and the agent (identity, memory, skills, history)
are all inside, and the file is rewritten after every run, so it always holds the agent as it is now.

```bash
singular export --move --out ada.capsule                       # stop the agent first
singular pack ada.capsule --ledger https://ledger.example --out ada.tar --tag ada:v1
```

Then, on any machine with Docker or Podman, from the folder holding `ada.tar`:

```bash
docker load -i ada.tar
docker run -d --name ada --read-only --tmpfs /tmp --user "$(id -u):0" -v "$PWD:/package" \
  -e SINGULAR_PASSPHRASE -e SINGULAR_CAPSULE_PASSPHRASE -e OPENROUTER_API_KEY ada:v1
docker stop -t 120 ada                                          # seals, lets go, rewrites ada.tar
```

What happens:

1. **Start.** The agent comes out of `ada.tar` itself (the folder is mounted at `/package`), is opened with the
   capsule passphrase and checked file by file against the ledger. Only a package holding the current state
   starts: once the agent has moved on, an older copy of the file is refused by name. Exporting and packing the
   agent again (or a sale) makes a new file of the same state, and that one starts.
2. **Run.** It takes the run lease; a second copy started anywhere is refused while it runs.
3. **Stop.** It seals what it learned and lets go of the lease. Then it writes a new `ada.tar` around its new
   state (the runtime layers are taken from the old file, nothing is downloaded), swaps it in atomically, and
   records the new package on the ledger (`PACKAGE`: which capsule and image, signed with the agent's key).
4. **Next start**, here or on any other machine with that file: back to step 1, from the new file. No volume
   is needed and no `docker load` again: the image is only the engine, the agent comes from the file.

Give `docker stop` time to rewrite the file (`-t 120`). If a run is cut off before the rewrite, nothing is lost
as long as the container still exists: `docker start ada` and stop it again.

The same image can also be pushed to a registry (`--push ghcr.io/you/ada:v1`, pinned by the printed digest) and
run with a named volume (`-v ada-home:/agent/home`) instead of a file; then the volume is the living agent.

`pack` needs no Docker: it reads the runtime from a registry (default `ghcr.io/toganio/singular-runtime:<version>`,
or a `docker save` archive with `--base`), adds one layer holding the capsule at `/opt/singular/agent.sngcap`, and
records the runtime's digest in the image labels.

What the file does and does not guarantee:

- **One closed box.** Everything is in the file; the capsule inside is encrypted, and every file it unpacks must
  hash to what the ledger sealed.
- **Nothing else writes into it.** Hermes, Singular and the capsule are image layers owned by root; the agent runs
  unprivileged with `--read-only`, so it can write only its own scratch home and its package folder. Every core
  file and the internal memory are sealed: a change that did not come from a sealed run stops the next start.
- **Never two at once** comes from the ledger, not the box: any number of copies of the file can exist, the run
  lease lets one run at a time, and every copy the agent has moved past is refused.
- **Accountable.** The actions the agent takes are anchored on the ledger under its own key, and each package
  records the action history it carries.

## Capsules in a registry

A capsule is pushed as an OCI artifact (`artifactType application/vnd.singular.capsule.v1`, one layer
`application/vnd.singular.capsule.v1+sngcap` holding the capsule file unchanged, header metadata as
`dev.singular.*` annotations). See [`oci.py`](../src/singular/oci.py). Pin references by digest.

## Test

`singular/hosting/e2e.sh [image]` starts a real ledger node and a `registry:2`, creates an agent, pushes it,
runs the image, and checks the lease on the ledger through start, `docker stop` and restart. CI runs it in
`.github/workflows/singular-hosting.yml`.
