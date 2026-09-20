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
  every memory/skill write, so little is lost) — or, only if the agent was registered with
  `--allow-owner-edits`, an owner-attested seal that the ledger permanently marks as human intervention.
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
* The trust boundary is the installed software. Someone who can replace Hermes or Singular on the machine owns that run; the
  ledger still prevents them from running a second instance or rewriting what was already recorded.

## Who we defend against, and how

| Attacker | Wants | Stopped by |
|---|---|---|
| Thief with a copy of the agent folder | run the agent / read it | agent key is scrypt+ChaCha20-Poly1305 wrapped; capsules are encrypted; no key → no lease |
| Owner (or ex-employee) with the passphrase, running a second copy | two instances | `LEASE_ACQUIRE` fails while a lease is live; lease is bound to a per-process host key, so holding the agent key is not enough to seal, anchor, renew or release |
| Same, using an old backup after the agent moved on | roll the agent back quietly | acquiring the lease requires the *current* sealed core and memory roots; stale copy → `STALE_STATE` |
| Anyone with disk access while the agent is stopped | plant a skill / memory | full re-hash at every start; mismatch → refuses to start, every tool blocked |
| Anyone with disk access while the agent is **running** | slip a change in and let the agent seal it as its own | idle-drift check before every action (ctime-keyed cache: a forged mtime does not hide an in-place edit); drift → no actions, no seals |
| Thief who has the files **and** the passphrase | impersonate the agent | owner rotates the key (`ROTATE_KEY`); the thief's running instance loses the lease in the same block |
| Ledger operator / host | rewrite or truncate history | pinned head continuity check at start, on every renewal and at shutdown |
| Seller after a sale | keep using the agent | `TRANSFER` replaces the agent key; old key and old owner key are rejected from that block on |
| Buyer before paying / before transfer | act as the agent under the seller's name | sale capsules carry **no agent key** and no private action records |
| Malicious capsule | write outside the target, plant secrets, smuggle links | hand-rolled extraction: regular files + in-home symlinks only, no traversal, no writes through links, no secret filenames, size/member caps; then a full verify against the ledger |
| Malicious *member* of a shared bank | overwrite others' files, write outside their mounts, erase entries | manifests are treated as hostile input (path/shape validation); store content is checked against the ledger root; writes are merged against a single bank snapshot so a race ends in a retry, never a silent drop |
| Whoever hosts a bank's storage | read or alter memory | storage holds only ciphertext; readers verify manifest and blobs against the ledger root |
| Network attacker | lie about leases/seals | client refuses plain-http ledgers off-machine; signatures bind the chain id (no cross-chain replay); per-subject nonces (no replay) |
| Spammer against a public node | bloat the chain | per-address token buckets for writes and reads, body caps, optional operator token for `REGISTER`/`BANK_CREATE`; run a real proxy in front as well |
| Clock skew | act on a dead lease | runtime stops acting at 90% of the lease lifetime as stamped by the validator |

## Fail-closed behaviour

If the ledger is unreachable the heartbeat keeps trying, but `check()` starts refusing actions once the
lease deadline (minus the skew margin) passes. If the ledger reports that the agent's history moved on
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
