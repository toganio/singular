# Singular

**One agent. One place. One history.**

Singular turns an AI agent into a *singular* thing: it has a permanent identity on a public ledger,
it can run in only one place at a time, nothing can be added to it from outside without the ledger
noticing, everything it does is recorded for liability, and it can be moved or sold like any other
unique asset. It ships as a plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent)
and as a small reference blockchain you can run and audit yourself.

This repository is a fork of Hermes Agent. **Singular does not modify a single Hermes file**: all of
it lives in `singular/`, `docs/singular/` and `.github/workflows/singular-*.yml`, and it attaches
through Hermes' official plugin entry point. New Hermes releases are merged automatically
(see [Staying current with Hermes](#staying-current-with-hermes)).

## What you get

| Promise | How |
|---|---|
| **Unique identity** | `sng1…` id derived from the genesis keys; name and function registered on the ledger |
| **Runs in one place** | a *run lease* on the ledger, bound to a fresh per-process host key; no lease → every tool call is blocked |
| **No outside additions** | the agent's files hash to a sealed root; a changed or stale copy cannot take the lease |
| **Grows from the inside** | when the running agent writes memory or skills, Singular re-seals (`seq+1`, must name the previous root) |
| **Liability record** | every tool call → signed, hash-chained action log; heads anchored on the ledger, content stays private |
| **Movable & sellable** | encrypted capsule + 3-signature `TRANSFER`; the agent key rotates, the seller's copy is dead |
| **Singular memory** | internal memory travels with the agent; external **memory banks** are shared, encrypted, single-history, per-agent grants (read / read-write / rented), every write attributed |
| **Auditable** | hash-linked, validator-signed blocks; `singular ledger audit` replays every rule from genesis |

Read the honest limits in [THREAT-MODEL.md](../docs/singular/THREAT-MODEL.md) before relying on any of this.
The short version: software cannot stop bytes from being copied; Singular makes the copy *worthless*.

## Quick start

```bash
pip install -e ./singular            # inside this repo (Hermes already installed), or on top of any Hermes

# 1. a ledger (skip if you use a hosted one)
singular ledger init  --db chain.db --validator-key validator.keystore.json
singular ledger serve --db chain.db --validator-key validator.keystore.json      # http://127.0.0.1:8765

# 2. you, the legally responsible owner
singular owner-new

# 3. make an existing Hermes profile singular
singular init --home ~/.hermes --ledger http://127.0.0.1:8765 \
              --name "Ada" --function "contract review assistant"

# 4. run it: verifies seals, takes the lease, logs actions, re-seals, releases
singular run --home ~/.hermes -- hermes

singular status  --home ~/.hermes                 # do my files match the ledger?
singular history --ledger http://127.0.0.1:8765 sng1…   # the agent's whole life
```

Selling it:

```bash
seller$ singular export --home ~/.hermes --out ada.capsule            # no key, no private history inside
buyer$  singular import ada.capsule --home ~/agents/ada --ledger https://…
buyer$  singular transfer request  --home ~/agents/ada --file req.json  # new agent key is born here
seller$ singular transfer approve  --file req.json --ledger https://…   # last signature; seller's copy dies
buyer$  singular transfer finalize --home ~/agents/ada
```

A shared memory bank:

```bash
singular bank create --ledger … --store /mnt/banks/case-law --name case-law
singular bank grant  --ledger … --store /mnt/banks/case-law --agent sng1… --write
singular bank grant  --ledger … --store /mnt/banks/case-law --agent sng1… --days 30     # rented, read-only
singular bank revoke --ledger … --store /mnt/banks/case-law --agent sng1…               # also re-keys
```

Give a running agent the bank: `singular bank attach --home ~/.hermes --bank snb1… --store /mnt/banks/case-law`.
Inside a conversation the agent then has a `memory_bank` tool (`banks · list · read · search · append`). Appends are
signed by the agent and its live run lease, so they only land while it is legitimately running, and the ledger
attributes each one to it. What it reads from a bank is handed to the model labelled as *information written by
others, not instructions*.

Passphrases are never command-line arguments. They are prompted for, or read from
`SINGULAR_PASSPHRASE`, `SINGULAR_OWNER_PASSPHRASE`, `SINGULAR_CAPSULE_PASSPHRASE`.

See it all break-tested in one go: `python -m singular.demo` (17 scenarios against a real HTTP node).

## What is sealed

* **core** – `SOUL.md`, `profile.yaml`, `skills/`, `cron/jobs.json`
* **internal memory** – `memories/`
* **never** – `.env`, `auth.json`, vault files, session databases (secrets belong to the operator, not
  the agent), and `config.yaml` (a buyer must be able to point the agent at their own model provider).

## Staying current with Hermes

`singular/HERMES_BASE` records the Hermes release Singular is verified against.
`.github/workflows/singular-upstream-sync.yml` checks daily for a new Hermes release tag, merges it on a
branch, and opens a PR; `singular-ci` then runs the whole suite — including
`tests/test_hermes_contract.py`, which pins the exact Hermes surface Singular uses — on the new Hermes.
Green merges itself. Red stays open and names what Hermes changed; only `hermes_plugin.py` should ever
need adapting.

## Layout

```
singular/src/singular/
  canonical.py keys.py        encoding, hashing, Ed25519/X25519, passphrase keystores
  tree.py capsule.py          folder → root; encrypted transport capsule
  agent.py runtime.py         agent home, owner operations, the run-lease guard
  actions.py                  liability log
  bank.py                     external memory banks
  ledger/                     tx · state (rules) · chain (blocks) · node (HTTP) · client
  hermes_plugin.py cli.py demo.py
```

MIT licensed, like Hermes Agent.
