# Singular protocol v1

Normative for the reference implementation in `singular/src/singular`. Rule code: `ledger/state.py`.

## 1. Encoding and hashing

* **Canonical JSON**: UTF-8, keys sorted, separators `,` `:`, no insignificant whitespace, **no floats**, integers within ±2⁵³, no lone surrogates.
* **Hash**: SHA-256, lowercase hex.
* **Merkle root**: leaves `H(0x00‖leaf)`, nodes `H(0x01‖l‖r)`, odd node promoted unchanged, empty = `H("singular:empty")`.
* **Signatures**: Ed25519. **Boxes** (bank keys to agents): ephemeral X25519 → HKDF-SHA256(salt = eph‖recipient, info `singular-box-v1`) → ChaCha20-Poly1305 with context as AAD. An agent's X25519 key is HKDF(seed, `singular-enc-v1`), so one passphrase opens the agent and its banks.
* **Keystores / capsules**: scrypt (n=2¹⁵, r=8, p=1) → ChaCha20-Poly1305; header bound as AAD.

## 2. Identities

* `agent_id  = "sng1" + base32(SHA256(canonical{a: genesis agent pub, o: genesis owner pub, s: salt})[:20])`
* `bank_id   = "snb1" + …{bank:"external", o, s}`; an agent's internal bank: `…{bank:"internal", agent}`
* Keys: **owner** (liable party; never inside the agent), **agent** (inside the agent, passphrase-wrapped, rotated on transfer), **host** (fresh per process; binds the lease).

## 3. Sealed state

**Baselines.** An identity may list `baselines: [{prefix, source, dir?}]`. A regular file under `prefix` that is byte-identical to the
file the installed software ships at the same relative path under `source` is not an entry. v1 defines one source,
`hermes:bundled_skills`: Hermes' own shipped-skills directory, *not* `HERMES_BUNDLED_SKILLS` (Hermes loads that from the unsealed
`.env`). A packaged install that relocates it gets the directory pinned as `dir` at registration. Shipped-but-modified files and
everything the agent authored are entries like any other.

`entry = {p, h, s}` for files, `{p, l}` for symlinks (never followed). A link is refused unless its target, walked one component at
a time against the real tree, stays inside the home, passes through no other symlink (and is not one), and lands inside the same
sealed set on a path that is not excluded. Default excludes (caches, locks, databases) apply everywhere except that under `skills/`
code-like files (`__pycache__`, `*.pyc`, `.git`, `*.db*`, `*-journal`) are entries.

**Sealing config.** `config = {core, memory, exclude, baselines}` from `identity.json`. Unless it is one of the two configs
`singular init` writes by default (default lists, no excludes, and either no baseline or the plain `hermes:bundled_skills` one), the
core set gains the synthetic entry `{p: ".singular/identity.json", c: hash(config)}`, so editing the unsealed lists changes the
core root. (`.singular/` is never scanned, so the path cannot collide.)

`root = merkle(hash(entry) for entries sorted by p)`. An agent has two roots: **core** and **internal memory**. `files` counts
entries without `c`.

## 4. Transactions

```
{"v":1,"type":T,"subject":<agent or bank id>,"nonce":n,"body":{…},"sigs":[{"role","pub","sig"}…]}
signed bytes = "singular-tx:v1:" ‖ canonical{v,type,subject,nonce,body,chain:<chain id>}
```
`nonce` must equal the subject's `nonce + 1` (total order per subject; replay- and fork-proof). The exact set
of signer roles below must be present, no more, no fewer. "now" is the enclosing block's timestamp.

| Type | Signers | Preconditions | Effect |
|---|---|---|---|
| `REGISTER` | owner, agent | id matches genesis keys; nonce 1 | agent + its internal bank created, seal seq 0 |
| `LEASE_ACQUIRE` | agent, host(new) | no live lease; `root` and `memory_root` equal the sealed ones | lease `{no, host_pub, expires = now + ttl}` |
| `LEASE_RENEW` / `LEASE_RELEASE` | agent, host(lease) | lease live | extend / clear |
| `LEASE_REVOKE` | owner | a lease exists | clear (crashed host) |
| `SEAL` | agent, host(lease) | lease live; `seq = seq+1`; `prev_root` = sealed root | new core root |
| `ACTIONS` | agent, host(lease) | lease live; `first = count+1`; `prev_head` = anchored head | new action head, count |
| `TRANSFER` | owner, new_owner, new_agent (the seller's client signs only for the agent id the seller names) | no live lease; buyer names current `root` + `memory_root` | owner/agent/enc keys replaced, `epoch+1` (voids bank grants) |
| `ROLLBACK` | owner | no live lease; target root was sealed before; body `{seq, prev_root, root, files, bytes}` (files/bytes of the target; bodies without them, from before v0.3, keep the current counts) | new seal, kind `rollback` |
| `OWNER_ATTEST` | owner | no live lease; policy `allow_owner_attest` | new seal, kind `owner_attest` |
| `OWNER_POLICY` | owner | no live lease; body exactly `{allow_owner_attest: bool}` | policy's `allow_owner_attest` set (since v0.4; earlier agents could only choose it at `REGISTER`) |
| `ROTATE_KEY` | owner, new_agent | new key is fresh (works even while a lease is held: the holder may be the thief) | agent/enc keys replaced, lease dropped, `epoch+1`, `rotations+1` |
| `RETIRE` | owner | — | agent frozen forever |
| `BANK_CREATE` | owner | id matches; nonce 1 | external bank, key_gen 1 |
| `BANK_GRANT` | bank owner | external; agent active; `key_gen` current | grant `{rights r\|rw, epoch, key_gen, wrapped_key, expires}` |
| `BANK_REVOKE` | bank owner | grant exists | grant removed |
| `BANK_REKEY` | bank owner | `key_gen+1`; wraps cover exactly the current grants | new key generation; each grant keeps its epoch (a grant voided by a sale stays void; clients revoke such grants first) |
| `BANK_SEAL` | agent+host(lease) of `writer`, or bank owner if `writer="owner"` and policy allows (internal bank: the agent's owner, agent not leased, agent policy `allow_owner_attest`) | writer's lease live and grant valid (rights rw, epoch current, key_gen current, not expired) — internal bank: writer is the bound agent; `key_gen` current; `seq+1`; `prev_root` matches | new bank root, attributed to `writer` |
| `BANK_TRANSFER` | owner, new_owner | external | owner replaced |

Rejection codes are stable strings (`LEASE_HELD`, `STALE_STATE`, `NONCE_CONFLICT`, `BAD_SIGNATURE`, `NO_GRANT`, …).

## 5. Blocks

`header = {height, prev, ts, tx_root, state_root, validator}`; block hash = `H(canonical header)`;
signature over `"singular-block:v1:" ‖ canonical(header)` by `validators[height mod n]` from genesis.
`ts` strictly increases. A block carries 1 to 256 transactions; the reference node group-commits (whatever queued while the
previous block was being written goes into the next one), and each transaction is accepted or refused on its own. `state_root` = Merkle root over every agent and bank record by id.
Genesis (`height 0`, `prev = 0…0`, unsigned) carries `params = {name, validators, protocol}`; **its hash is the chain id**,
which agents pin in `identity.json` and which every transaction signature binds.

## 5a. What a client must check about its node

A client keeps a pinned head `{height, hash}` of the last block it saw and, at start, on every lease renewal and at shutdown,
requires `info.height >= pinned.height` and `block_hash_at(pinned.height) == pinned.hash` before updating the pin.

## 6. Action records (off-chain, anchored)

Each action is two records: `kind = "<k>.intent"` (status `started`, written and fsynced **before** the action runs) and
`kind = "<k>.result"` (its `input` hashes `{"intent": n}`). A `SEAL`/`BANK_SEAL` caused by an action carries
`reason = "action <n>"` naming the result record. Runtime rule (not consensus): with no intent open, the files must equal the last
sealed roots (or the roots of a seal it sent whose answer was lost, which it retries first), or the runtime stops acting. The lease
window is `0.9 × ttl` on a boot-time clock, counted from request send. After a lost answer or a `NONCE_CONFLICT`/`ACTION_GAP`/
`STALE_STATE` refusal the runtime re-reads its record: while its lease is live only it can move the core seal, internal bank or
action head, so it adopts what landed (and declares the lease lost if anything else did). The hash cache is in memory only.

Records are written only for tool calls the runtime sees. `singular run -- hermes …` runs Hermes **in-process** (the plugin then
records every tool call); any other command, or Hermes that is not importable there, runs as a plain subprocess that merely holds
the lease: its writes to sealed files are outside any action, and the next start refuses them.


`{v,n,prev,agent,epoch,lease,ts,kind,name,status,input:H,output:H,summary,session,sig}` — `prev` is the hash of the
previous record (without `sig`), signature domain `singular-action:v1:`. `ACTIONS` anchors `(first,last,prev_head,head,batch_root)`.
A sold agent continues the numbering from `actions.base.json` without receiving the seller's records.

## 7. Memory bank store

`bank.json` (public ids) · `owner.keys.json` (data keys boxed to the owner) · `manifests/<root>.g<key_gen>.bin`
(encrypted `{bank, seq, key_gen, entries[{p,h,s,b,g}], old_keys}`) · `blobs/<sha256 of ciphertext>`.
Readers must check `merkle(entries{p,h,s}) == ledger root`, validate every path, and check each blob's
ciphertext hash and plaintext hash. Writers merge and seal against **one** ledger snapshot and retry on
`NONCE_CONFLICT | STALE_STATE | STALE_GRANT`. Reference clients write as an agent only under `entries/<agent id>/`; the
ledger cannot enforce paths (it sees one root), so this is client policy, and an erased entry survives in the earlier manifest.

## 8. Capsule

`"SNGCAP1\n" ‖ u32 len ‖ header ‖ {u32 len ‖ chunk}*`; 1 MiB chunks; nonce = prefix(7) ‖ index(4) ‖ final(1);
AAD = `H(header) ‖ index ‖ final`. Payload: tar.gz of sealed files + `.singular/identity.json` (+ key and action
records only when moving your own agent). Import always ends with a full verification against the ledger, requires the action
history in the capsule (records or `actions.base.json`) to end at the ledger's anchored count and head, and rewrites `ledger_url` to
the importer's ledger. Unpack limits: 100 000 members, 16 GiB, 64 KiB per pax / GNU long-name header; links are validated with every
link in place.

## 8a. Owner edits from elsewhere (`singular unlock`)

A host that keeps a *stopped* agent can apply edits the owner sealed somewhere else, without the owner key ever
reaching it. `describe` prints the sealed entries (and the text of files up to 256 KiB). The owner's client applies
its edits to those entries, computes the core and memory roots per §3, and signs an `OWNER_ATTEST` and/or an owner
`BANK_SEAL`. `apply` writes the edits (never through a symlink, never outside the sealed sets or under `.singular/`),
re-scans, and submits the signed seals only if their bodies equal the seals the edited files produce; otherwise, or if
the ledger refuses the core seal, every file is put back. A refused memory seal puts back the memory edits only.

## 9. Node (reference HTTP front)

`GET /history/<id>?limit=N` returns `{"history": [{txid, height, ts, tx}…], "truncated": bool}`: the newest N (default 200, max 1000)
in ascending order. The node is plain HTTP: anything reachable from the network **must** sit behind a TLS-terminating proxy.
