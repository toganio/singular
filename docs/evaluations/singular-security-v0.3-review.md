# Singular security review v0.3 — findings and fixes (2026-10-10)

Method: a read-only review of `singular/` against the three promises (one running place · no outside edits · no unrecorded
action) plus the ledger node and the fork's CI, with a proof script for each finding. Every fix below has a regression test in
`singular/tests/test_review_v03.py` that fails on the code before the fix; every proof script was re-run after the fixes and no
longer exploits.

**Open Critical: 0** · **Open High: 0** · Open Medium: 0 new (v0.2's two remain) · Open Low: see the end

## Found and fixed
| # | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| H1 | High | **The sealed path lists were not sealed.** `core` / `memory` / `exclude` / `baselines` live in the unsealed `.singular/identity.json` yet decide what is sealed: adding `"exclude": ["evil"]` hid a planted skill from `verify` and from the guard. | A non-default sealing config adds a synthetic core entry `{p: ".singular/identity.json", c: hash(config)}`; editing the lists changes the core root. The two configs `singular init` writes by default add nothing, so every existing root stays valid (no ledger change). | `test_editing_the_sealed_path_lists_*`, `test_a_non_default_sealing_config_*` |
| H2 | High | **Symlink chains escaped the home.** `check_link` was lexical: `x -> ../..` plus `SKILL.md -> x/../../etc/passwd` each looked in-home, in `scan` and in capsule unpack. | `tree.link_target` walks the target against the real tree and refuses any target that passes through (or is) another link; unpack validates every link once all are in place. | `test_a_chain_of_*` |
| H3 | High | **A bank re-key revived grants a sale had voided.** `BANK_REKEY` reset each grant's epoch to the agent's current one and `BankOwner.rekey` wrapped the new key to the agent's current (buyer's) key, so revoking any unrelated member gave the buyer the bank. | Ledger: a re-key keeps each grant's epoch. Client: stale grants (epoch moved, agent retired) are revoked before re-keying. | `test_rekey_after_a_sale_*`, `test_ledger_rekey_keeps_*` |
| H4 | High | **`transfer approve` signed any TRANSFER.** A buyer can build a request for any agent of the same owner from public ledger data; the seller's client signed it unseen. Without `--ledger` it crashed (`open_ledger(None)`). | `transfer_approve(request, ledger, owner_key, agent_id)` refuses a request for another agent or an agent the key does not own. CLI: `--agent` (or the agent in `--home`), falls back to the home's ledger url, prints the agent name and the new owner. | `test_transfer_approve_refuses_*`, `test_cli_transfer_approve_*` |
| M1 | Medium | A sealed link could point at an **unsealed** in-home file (`.env`, `config.yaml`, `logs/`), so skill content changed under an unchanged seal. | A link must land inside the same sealed set, on a path that is not excluded. | `test_a_sealed_link_to_an_unsealed_file_*` |
| M2 | Medium | `HERMES_BUNDLED_SKILLS` (loaded by Hermes from the unsealed `.env`) **redirected the skills baseline** to a look-alike tree holding a planted skill. | The variable is ignored at scan time; a packaged install's directory is pinned into the (now sealed) baseline entry at `init`. | `test_baseline_env_var_*` |
| M3 | Medium | The runtime hash cache was **re-read from disk** on every check, so editing a sealed file and its cached digest while the agent idled passed the idle-drift check. | Cache in memory only, for the life of the process; a full scan fills but never trusts it. | `test_a_forged_on_disk_hash_cache_*` |
| M4 | Medium | **One lost ledger answer wedged the guard** (nonce, action count, seal roots fell behind; every later submission failed; `stop()` never released the lease). A seal that failed transiently turned a legitimate write into "tampering". | Resync from the ledger after a lost answer or a stale refusal (while our lease is live, any move there is ours); unconfirmed seals kept pending and retried before the next action; `stop()` releases even when anchoring fails. | `test_a_lost_actions_answer_*`, `test_a_seal_that_did_not_land_*`, `test_stop_releases_*` |
| M5 | Medium | THREAT-MODEL claimed a malicious bank member cannot erase others' entries; the ledger (one root per bank) accepts it. | Threat model corrected (not prevented, only visible: old manifests and blobs survive, `seal.by` names the writer). Honest clients refuse changes outside `entries/<agent id>/`. | `test_a_bank_member_cannot_erase_*` |
| M6 | Medium | Ledger node: rate limiter cleared every bucket at 50k addresses (churn = reset); deep JSON / lone surrogates / `/blocks?from=1e20` dropped the connection with a traceback; unbounded threads; per-read timeout only (slowloris); `Server` header named the Python version. | Refilled-only eviction plus a shared overflow bucket; all handler errors answer 400 (500 if unexpected), `check_shape` rejects unencodable strings; `max_workers` cap; 20 s per-request deadline watchdog; plain `Server` header, JSON error pages. Docs: a public node must sit behind a TLS proxy. | `test_node_*`, `test_rate_limiter_*`, `test_a_slowloris_*` |
| M7 | Medium | `/history/<id>` returned the **oldest** 200 transactions, hiding what an agent did last. | Newest N (`?limit=`, max 1000), ascending, with `truncated`; `{"history": [...]}` shape unchanged. | `test_history_returns_the_newest_*` |
| M8 | Medium | `singular-upstream-sync` auto-merged releases that change `.github/workflows/*` (pushed with a workflow-capable token). | Such a sync PR is left for a human, with a comment listing the workflow files. | workflow |
| L1 | Low | `owner-new` chmodded an existing parent directory. | Only a directory it created. | `test_owner_new_*` |
| L2 | Low | Capsule caps generous; pax / GNU long headers unbounded in memory. | 100k members, 16 GiB, 64 KiB per extended header. | `test_capsule_refuses_an_oversized_pax_header` |
| L3 | Low | Import kept the seller's `ledger_url`; a capsule whose action history no longer matched the ledger imported fine and failed later. | `ledger_url` rewritten to the importer's ledger; action count/head must match the ledger. | `test_import_takes_*` |
| L4 | Low | Default excludes (`__pycache__`, `*.pyc`, `.git`, `*.db`) applied under `skills/`, where they are code or content. | Sealed under `skills/`; only Hermes' bookkeeping stays excluded there. | `test_a_planted_pycache_*` |
| L5 | Low | `ROLLBACK` recorded the current files/bytes; `rollback()` restored files before the ledger accepted. | Body carries the target's files/bytes (old bodies still replay); snapshot checked, ledger first, then restore. | `test_rollback_records_*` |
| L6 | Low | `canonical()` accepted integers other languages round. | ±2⁵³. | `test_canonical_refuses_*` |
| L7 | Low | `singular-ci` skipped the "touches no Hermes file" check for any `upstream-sync/*` head branch, fork PRs included. | Skip requires the head repo to be this repo. | workflow |
| L8 | Low | Docs did not say that `singular run` records tool calls only for Hermes in-process. | PROTOCOL §6, THREAT-MODEL. | — |

## Compatibility
* Existing chains replay unchanged: `BANK_REKEY` differs only where a grant was stale (the case being fixed); old-shape `ROLLBACK`
  bodies are accepted.
* Existing agents with a default sealing config keep their roots. An agent registered with a non-default config (custom
  `--core`/`exclude`, or a pinned baseline) gains the config entry; such a home must be re-sealed (owner attest, if allowed) or
  re-registered.
* Symlinks from one sealed set into another, or into excluded files, are now refused at scan; `__pycache__`, `*.pyc`, `.git` and
  `*.db` files already under `skills/` now count as sealed content (an existing home that has them fails verification until
  restored or re-sealed).
* `transfer_approve` takes the agent id; `singular transfer approve` takes `--agent` or uses the agent in `--home`.

## Still open
* (v0.2) A write racing inside one of the agent's own tool-call windows is sealed (attributed to that action). Needs OS isolation.
* (v0.2) Deleting a pristine shipped skill file is not noticed.
* A hostile `rw` bank member can still seal a state without other members' entries; it is attributable and recoverable, not
  prevented (the ledger sees one root per bank).
* The ledger pin and `ledger_url` are local files; they defend against the ledger, not against a local attacker.
