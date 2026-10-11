# Singular threat model and honest limits (v0.1)

## What Singular cannot do

* It **cannot stop files from being copied.** No software can. What it guarantees is that a copy is
  worthless: only one copy at a time can hold the run lease, and a copy without the lease cannot
  produce a seal, an action anchor or a bank write that anyone will accept as the agent's.
* It **cannot stop someone from running the copied files with Singular switched off** (plain Hermes,
  plugin disabled). That run is simply *not the agent*: it has no lease, leaves no valid record, and the
  next legitimate start will refuse files it changed. If you need "cannot even execute elsewhere", you
  need hardware attestation (TEE); the lease transaction has room for an attestation field, but v0.1
  does not implement it.
* It **cannot make an agent forget.** An agent that was granted read access to a memory bank may have
  copied what it read into its own memory. Revoking re-keys the bank, which protects everything written
  *afterwards*. The read itself is on the agent's action log; the rest is a contract matter.
* It **cannot tell an honest crash from an outside edit.** Both leave files that do not match the last
  seal. Recovery is `singular restore` (back to the last sealed state; Singular re-seals right after
  every memory/skill write, so little is lost) — or, only while the agent's policy allows owner edits
  (`--allow-owner-edits` at registration, or `singular owner allow-edits` later, itself a public `OWNER_POLICY`
  transaction), an owner-attested seal of the core and/or memory that the ledger permanently marks as human
  intervention. A buyer reads the policy and every such seal in the history before buying. With `singular unlock`
  the host applying the edits never holds the owner key: it can refuse an edit, but it cannot make the owner's
  signature cover content other than what the owner's client hashed. It can, however, show that client a wrong
  starting state; a client that cares checks the entries' root against the ledger it trusts.
* It **cannot bind a key to a legal person.** The ledger proves *which key* owned and ran the agent
  when. Tying that key to a company or a human is an off-chain (KYC / contract) step.
* v0.1 has **one block producer** (proof of authority). A malicious validator cannot forge agent or
  owner signatures and cannot rewrite history without breaking every replica's pinned hashes — but it
  *can* censor transactions or stop. Multi-validator consensus is roadmap; anyone can already run a
  verifying replica (`singular ledger audit`, `Chain.replica`).
* The **descriptor (name, function) is public and permanent.** Do not put personal data in it.

## What the running agent enforces on itself (v0.2 hardening)

* **Nothing changes while it is idle.** Sealed files may change only inside an action the agent itself opened. Before every
  action the guard compares the files to the last sealed state; if they differ and no action is open, someone else wrote to the
  agent: it stops acting, seals nothing, anchors its honest records, releases the lease, and refuses to start again until
  `singular restore`. A change made inside an action is sealed right after it, in a transaction that names that action's record.
* **No unrecorded action.** A signed *intent* record is on disk before a tool runs; if it cannot be written the tool is blocked.
  A signed *result* record follows. Pending records are anchored every few seconds, on shutdown, and by the next run after a crash.
  A local log shorter than what the ledger anchored marks a stale or truncated copy, which cannot start.
* **The lease clock cannot be forged.** The guard acts only during the first 90 % of a lease, measured on the machine's
  boot-time clock (which counts suspend and cannot be set back) from the moment the request *left*, never from the wall clock.
* **The ledger is not trusted blindly.** The guard pins the last block it saw (`.singular/ledger-head.json`) and refuses a node
  that shows a shorter history ("went backwards") or a different block at the pinned height ("rewrote history").
* **A leaked agent key can be replaced without a sale.** `singular owner rotate-key` (`ROTATE_KEY`): the old key is dead from that
  block on, even if the thief is running the agent at that moment; bank grants wrapped to the old key are void.
* **Shipped software is not identity.** Under `skills/`, the seal covers every file that is not byte-identical to the file the
  installed Hermes ships at the same path. Hermes updates can refresh shipped skills without breaking the seal; altering one by
  a single byte puts it under the seal and is caught like any other outside edit.

What remains true after all that:

* An attacker who can write to the disk *during* one of the agent's own tool calls can hide a change inside that window; it will
  be sealed, attributed to that action's signed record. Closing this needs OS-level isolation (one user / container per agent),
  which hosting provides and a shared workstation does not.
* Deleting a *pristine shipped* skill file is not noticed (it was never under the seal; Hermes restores it on next sync).
* The ledger pin defends against the ledger, not against someone with write access to the agent's own disk, who can delete it.
* Hermes' optional "staged memory writes" (`/memory approve`) apply changes outside any tool call. Under Singular that is an
  outside edit by design: keep that Hermes option off for Singular agents.
* `singular run -- <command>` records tool calls only when the command is Hermes running **in-process** (Hermes importable in
  Singular's Python). Any other command merely holds the lease; what it writes to sealed files is an outside edit by design.
* `identity.json` stays unsealed apart from the path lists: its `ledger_url` is operator configuration. Pointing it at a hostile
  node is defeated by the chain id every signature binds and by the pinned head, not by the seal; use https.
* The trust boundary is the installed software. Someone who can replace Hermes or Singular on the machine owns that run; the
  ledger still prevents them from running a second instance or rewriting what was already recorded.

## Who we defend against, and how

| Attacker | Wants | Stopped by |
|---|---|---|
| Thief with a copy of the agent folder | run the agent / read it | agent key is scrypt+ChaCha20-Poly1305 wrapped; capsules are encrypted; no key → no lease |
| Owner (or ex-employee) with the passphrase, running a second copy | two instances | `LEASE_ACQUIRE` fails while a lease is live; lease is bound to a per-process host key, so holding the agent key is not enough to seal, anchor, renew or release |
| Same, using an old backup after the agent moved on | roll the agent back quietly | acquiring the lease requires the *current* sealed core and memory roots; stale copy → `STALE_STATE` |
| Anyone with disk access while the agent is stopped | plant a skill / memory | full re-hash at every start; mismatch → refuses to start, every tool blocked. The sealed path lists in `identity.json` are bound into the core root (editing them to hide a file fails verification); the skills baseline ignores `HERMES_BUNDLED_SKILLS` from `.env`; symlinks must land on sealed files without passing through another link |
| Anyone with disk access while the agent is **running** | slip a change in and let the agent seal it as its own | idle-drift check before every action (in-memory, ctime-keyed cache: neither a forged mtime nor an edited cache file hides an in-place edit); drift → no actions, no seals |
| Thief who has the files **and** the passphrase | impersonate the agent | owner rotates the key (`ROTATE_KEY`); the thief's running instance loses the lease in the same block |
| Ledger operator / host | rewrite or truncate history | pinned head continuity check at start, on every renewal and at shutdown |
| Seller after a sale | keep using the agent | `TRANSFER` replaces the agent key; old key and old owner key are rejected from that block on |
| Buyer of one agent | get the seller to sign away another | `transfer approve` signs only a request for the agent id the seller names (`--agent` / `--home`) |
| Buyer, via a bank the sold agent was in | read the bank after the sale | the epoch bump voids the grant, and a later re-key keeps it void (clients revoke such grants instead of re-wrapping) |
| Buyer before paying / before transfer | act as the agent under the seller's name | sale capsules carry **no agent key** and no private action records |
| Malicious capsule | write outside the target, plant secrets, smuggle links | hand-rolled extraction: regular files + in-home symlinks only, no traversal, no writes through links, no secret filenames, size/member caps; then a full verify against the ledger |
| Malicious *member* of a shared bank | write outside their mounts on other members' machines; race honest writers | manifests are treated as hostile input (path/shape validation); store content is checked against the ledger root; writes are merged against a single bank snapshot so a race ends in a retry, never a silent drop |
| Malicious `rw` member of a shared bank | overwrite or erase other members' entries | **not prevented, only made visible.** The ledger holds one root per bank and cannot see paths, so a hostile client can seal a state without others' entries. Honest clients refuse to touch anything outside `entries/<their agent id>/`; the erased entries survive in the earlier manifest and blobs (the store never deletes), and the ledger names the writer of every seal (`seal.by`). Grant `rw` only to agents you would trust with the bank's contents; revoke is immediate |
| Whoever hosts a bank's storage | read or alter memory | storage holds only ciphertext; readers verify manifest and blobs against the ledger root |
| Network attacker | lie about leases/seals | client refuses plain-http ledgers off-machine; signatures bind the chain id (no cross-chain replay); per-subject nonces (no replay) |
| Spammer against a public node | bloat the chain, exhaust the node | per-address token buckets for writes and reads (address churn cannot reset a throttled client), body caps, a cap on concurrent connections, a 20 s deadline per request (slowloris), optional operator token for `REGISTER`/`BANK_CREATE`. A public node **must** sit behind a TLS-terminating proxy, which is also where real per-client limits belong |
| Clock skew | act on a dead lease | runtime stops acting at 90% of the lease lifetime as stamped by the validator |

## Fail-closed behaviour

If the ledger is unreachable the heartbeat keeps trying, but `check()` starts refusing actions once the
lease deadline (minus the skew margin) passes. A lost answer (the transaction landed, the reply did not) is not fatal: the guard
re-reads its record before the next submission and adopts what landed; a seal that did not land is retried before the next action. If the ledger reports that the agent's history moved on
without this process (`NONCE_CONFLICT` with someone else's lease, `NO_LEASE`, `LEASE_EXPIRED`), the guard
marks itself lost and never recovers within that process.

## Operating notes

Default run-lease lifetime is 10 minutes (renewed every ~3). A crashed host therefore frees its agent within 10 minutes on its
own; the owner can free it immediately with `singular owner revoke-lease`. Shorter lifetimes are a per-agent choice at
registration (`--lease-ttl`), paid for in ledger traffic.

## Known gaps (tracked for v0.2)

1. Per-agent `roots` history grows without bound in ledger state.
2. No light-client proofs: a client either trusts its node over TLS or replays the chain.
3. Snapshots (`.singular/objects`) double the disk footprint of sealed files.
4. Session databases are outside the seal; the action log is the record of what happened in sessions.
5. No payment/escrow in `TRANSFER`; atomic sale needs an escrow service or a public-chain anchor.
