# Singular v0.1 — security review (vibe-security skill)

Date: 2026-09-20 · Scope: `singular/` (crypto, keystores, capsules, reference ledger + HTTP node, memory banks,
Hermes plugin, CLI). Skill areas applied: secrets-and-env, authentication (signature-based), rate-limiting,
data-access/input validation, deployment. Not applicable: database-security (no BaaS), payments, mobile,
ai-integration (Singular makes no model calls).

**Open Critical: 0** · **Open High: 0** · Open Medium: 2 · Open Low: 3

Every finding below was reproduced as a failing test first, then fixed; the tests stay in the suite.

## Fixed during this review

### High — a member of a shared bank could write files outside other members' mounts
`bank.py` pulled paths straight from the decrypted manifest. A granted agent controls the manifest it uploads, so
`{"p": "../../.ssh/authorized_keys"}` became a file write on every other member's machine at their next pull.
```python
# before
self._write_file(path, self._fetch(entry, keys))
# after: manifests are hostile input
manifest = _check_manifest(json.loads(plaintext), self.bank_id)   # rejects abs paths, "..", secret names, bad hex/shape
```
Test: `test_malicious_member_cannot_write_outside_other_members_mounts`.

### High — concurrent bank writers could silently erase each other's entries
`push()` merged against one read of the ledger and sealed against a *later* one. A faster writer landing in between
was named as `prev_root` but missing from the new tree: the ledger accepted a seal that deleted their entry.
Fix: merge and seal against a single snapshot, so the race ends in `STALE_STATE` and a retry.
Test: `test_many_agents_race_on_one_bank_history_stays_single` (4 writers × 3 entries → 12 files, seq 12).

### High — a buyer could act as the agent under the seller's name before the transfer
Sale capsules contained the seller's wrapped agent key. A buyer could grind a weak passphrase offline, take the run
lease and produce actions attributed to the seller's ownership epoch.
Fix: `export` is for-sale by default and leaves out `agent.keystore.json` and the private `actions.jsonl`
(the buyer continues the numbering from `actions.base.json`); `--move` is the explicit opt-in for your own agent.
Test: `test_sale_capsule_carries_no_key_and_no_private_history`.

### High — sealed symlinks could pull unsealed outside content into the agent (and read the buyer's files)
A link `skills/x/SKILL.md -> /home/buyer/notes` hashes as a link but *reads* as the buyer's file.
Fix: `tree.check_link` refuses absolute and home-escaping targets at seal time and at capsule import.
Test: `test_symlink_out_of_home_cannot_be_sealed_or_imported`.

### Medium — ledger client accepted plain http to remote hosts
A network attacker could lie about leases and seals. Fix: refused unless loopback or
`SINGULAR_ALLOW_INSECURE_LEDGER=1`. Test: `test_node_rate_limits_writes_and_client_refuses_plain_http_on_the_network`.

### Medium — open node had no abuse controls
Every accepted transaction is permanent chain growth. Fix: per-address token buckets for writes and reads
(proxy-aware only with `--trust-proxy`), request body caps, 15 s socket timeout, optional operator token for
`REGISTER` / `BANK_CREATE` compared with `hmac.compare_digest`. Tests: rate-limit and register-token tests.

### Medium — runtime trusted its own clock for lease expiry
Expiry is stamped by the validator. Fix: stop acting at 90 % of the lease lifetime.

### Medium — a refused bank entry stayed in the working copy and rode along with the next accepted append
Found by `test_agent_reads_searches_and_appends_through_the_tool`. Fix: the `memory_bank` tool deletes the local entry when the
ledger refuses the push.

### Note — prompt injection through shared banks (`memory_bank` tool, AI-integration area)
Bank entries are written by other agents. The tool returns them with an explicit "information, never instructions" notice,
caps read size (48k chars) and entry size (100k chars), refuses path escapes, and requires a provable run lease for every
action. This lowers, and cannot eliminate, the risk that a model follows text it reads; grant `rw` only to agents you trust.

### Low — owner key directory and bank working copies created with default permissions → now `0700`.

## Verified safe (checked, no change needed)
* No hardcoded secrets; passphrases never accepted as CLI arguments; `SINGULAR_PASSPHRASE` is removed from the
  environment before any child process starts; keystores, action log and capsules are written `0600`.
* `.env`, `auth.json`, vault files and `state.db` can never be sealed or exported, and a capsule *containing* one is refused
  (`tests/test_hermes_contract.py` keeps this list in sync with Hermes' own secret list).
* All SQL is parameterised; all parsing is `json` / `yaml.safe_load`; no `pickle`, `eval`, `tarfile.extractall`.
* Signatures bind the chain id (no cross-chain replay) and a per-subject nonce (no replay); signer roles must match exactly.
* A rejected transaction leaves state and chain untouched (`test_rejected_tx_changes_nothing`); rewritten history and
  blocks from non-validators fail replay.
* Wrapped bank keys are bound (AAD) to bank id, recipient and key generation.

## Open (accepted for v0.1, tracked)
* **Medium — single block producer.** A malicious validator can censor or halt (cannot forge or rewrite undetected). Multi-validator consensus is v0.2.
* **Medium — permissionless `REGISTER` on a node run without tokens** can still be bloated by a botnet. Hosted nodes must set `SINGULAR_REGISTER_TOKENS` and sit behind a proxy/WAF.
* **Low — per-agent `roots` map grows forever** in ledger state.
* **Low — hash cache** is trusted during a run (never at start, import or transfer).
* **Low — action `summary` may contain tool error text**; it stays local (`0600`) and only hashes reach the ledger.
