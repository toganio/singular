# Singular protocol v1

Normative for the reference implementation in `singular/src/singular`. Rule code: `ledger/state.py`.

## 1. Encoding and hashing

* **Canonical JSON**: UTF-8, keys sorted, separators `,` `:`, no insignificant whitespace, **no floats**.
* **Hash**: SHA-256, lowercase hex.
* **Merkle root**: leaves `H(0x00‖leaf)`, nodes `H(0x01‖l‖r)`, odd node promoted unchanged, empty = `H("singular:empty")`.
* **Signatures**: Ed25519. **Boxes** (bank keys to agents): ephemeral X25519 → HKDF-SHA256(salt = eph‖recipient, info `singular-box-v1`) → ChaCha20-Poly1305 with context as AAD. An agent's X25519 key is HKDF(seed, `singular-enc-v1`), so one passphrase opens the agent and its banks.
* **Keystores / capsules**: scrypt (n=2¹⁵, r=8, p=1) → ChaCha20-Poly1305; header bound as AAD.

## 2. Identities

* `agent_id  = "sng1" + base32(SHA256(canonical{a: genesis agent pub, o: genesis owner pub, s: salt})[:20])`
* `bank_id   = "snb1" + …{bank:"external", o, s}`; an agent's internal bank: `…{bank:"internal", agent}`
* Keys: **owner** (liable party; never inside the agent), **agent** (inside the agent, passphrase-wrapped, rotated on transfer), **host** (fresh per process; binds the lease).

## 3. Sealed state

`entry = {p, h, s}` for files, `{p, l}` for in-home symlinks (never followed; out-of-home links are refused).
`root = merkle(hash(entry) for entries sorted by p)`. An agent has two roots: **core** and **internal memory**.

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
| `TRANSFER` | owner, new_owner, new_agent | no live lease; buyer names current `root` + `memory_root` | owner/agent/enc keys replaced, `epoch+1` (voids bank grants) |
| `ROLLBACK` | owner | no live lease; target root was sealed before | new seal, kind `rollback` |
| `OWNER_ATTEST` | owner | no live lease; policy `allow_owner_attest` | new seal, kind `owner_attest` |
| `RETIRE` | owner | — | agent frozen forever |
| `BANK_CREATE` | owner | id matches; nonce 1 | external bank, key_gen 1 |
| `BANK_GRANT` | bank owner | external; agent active; `key_gen` current | grant `{rights r\|rw, epoch, key_gen, wrapped_key, expires}` |
| `BANK_REVOKE` | bank owner | grant exists | grant removed |
| `BANK_REKEY` | bank owner | `key_gen+1`; wraps cover exactly the current grants | new key generation |
| `BANK_SEAL` | agent+host(lease) of `writer`, or bank owner if `writer="owner"` and policy allows | writer's lease live and grant valid (rights rw, epoch current, key_gen current, not expired) — internal bank: writer is the bound agent; `key_gen` current; `seq+1`; `prev_root` matches | new bank root, attributed to `writer` |
| `BANK_TRANSFER` | owner, new_owner | external | owner replaced |

Rejection codes are stable strings (`LEASE_HELD`, `STALE_STATE`, `NONCE_CONFLICT`, `BAD_SIGNATURE`, `NO_GRANT`, …).

## 5. Blocks

`header = {height, prev, ts, tx_root, state_root, validator}`; block hash = `H(canonical header)`;
signature over `"singular-block:v1:" ‖ canonical(header)` by `validators[height mod n]` from genesis.
`ts` strictly increases. `state_root` = Merkle root over every agent and bank record by id.
Genesis (`height 0`, `prev = 0…0`, unsigned) carries `params = {name, validators, protocol}`; **its hash is the chain id**,
which agents pin in `identity.json` and which every transaction signature binds.

## 6. Action records (off-chain, anchored)

`{v,n,prev,agent,epoch,lease,ts,kind,name,status,input:H,output:H,summary,session,sig}` — `prev` is the hash of the
previous record (without `sig`), signature domain `singular-action:v1:`. `ACTIONS` anchors `(first,last,prev_head,head,batch_root)`.
A sold agent continues the numbering from `actions.base.json` without receiving the seller's records.

## 7. Memory bank store

`bank.json` (public ids) · `owner.keys.json` (data keys boxed to the owner) · `manifests/<root>.g<key_gen>.bin`
(encrypted `{bank, seq, key_gen, entries[{p,h,s,b,g}], old_keys}`) · `blobs/<sha256 of ciphertext>`.
Readers must check `merkle(entries{p,h,s}) == ledger root`, validate every path, and check each blob's
ciphertext hash and plaintext hash. Writers merge and seal against **one** ledger snapshot and retry on
`NONCE_CONFLICT | STALE_STATE | STALE_GRANT`.

## 8. Capsule

`"SNGCAP1\n" ‖ u32 len ‖ header ‖ {u32 len ‖ chunk}*`; 1 MiB chunks; nonce = prefix(7) ‖ index(4) ‖ final(1);
AAD = `H(header) ‖ index ‖ final`. Payload: tar.gz of sealed files + `.singular/identity.json` (+ key and action
records only when moving your own agent). Import always ends with a full verification against the ledger.
