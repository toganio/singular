# Singular core hardening — adversarial review (2026-09-20)

Method: re-read v0.1 as an attacker against the three promises (one running place · no outside edits · no unrecorded action),
then run the design against a **real Hermes agent loop** and **real OS processes**. Every finding has a test that failed first.

**Open Critical: 0** · **Open High: 0** · Open Medium: 1 · Open Low: 2

## Found and fixed
| # | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| 1 | High | **Outside writes during a run were sealed as the agent's own.** Files were verified only at start; the next re-seal laundered anything on disk. | Idle-drift rule: before every action the files must equal the last seal unless one of the agent's own actions is open. Drift → no actions, no seals, no bank writes; honest records anchored; lease released; restart refused until restore. Seals name the action record that caused them. | `test_idle_drift_*`, real loop |
| 2 | High | **Real Hermes was unusable under Singular.** Hermes syncs its shipped skills into `skills/` at startup (outside any action) and on every update → every tool blocked on first run. Invisible to hook-level tests. | Baseline rule: seal everything under `skills/` that is not byte-identical to what the installed Hermes ships. Tampering with a shipped skill makes it differ → it lands under the seal → caught. | `test_hermes_real_loop.py`, contract test |
| 3 | High | **Actions could happen unrecorded** (record written after the tool; a failed write lost it; up to 19 records lived only on local disk until shutdown and could be truncated). | Signed intent fsynced before the tool runs, tool blocked if that fails; signed result after; anchoring every ≤15 s, at shutdown, and by the next run after a crash; shorter-than-ledger local log = stale copy. | `test_intent_*`, `test_anchor_*` |
| 4 | Medium | **Lease window trusted the wall clock.** Clock set back / NTP step / VM suspend could let a process act on a dead lease. | 90 % window on the boot-time clock, counted from request send. | `test_clock_*` |
| 5 | Medium | **A ledger operator could rewrite or truncate history** unnoticed by a running agent. | Pinned head continuity at start, every renewal, shutdown. | `test_history_rewrite_*`, `test_pinned_*` |
| 6 | Medium | **No remedy for a leaked agent key** short of selling the agent to yourself. | `ROTATE_KEY` (owner + new key); works while the thief holds the lease; epoch bump voids bank grants. | `test_rotate_key_*` |
| 7 | Medium | **Forged mtime hid in-place edits from the hash cache** during a run. | Cache key includes ctime. | `test_ctime_*` |
| 8 | Low | A tampered agent kept its lease until expiry (nobody else could start it after a restore). | "Tampered" is separate from "lease lost": it still anchors and releases. | `test_idle_drift_outside_write…` |
| 9 | Low | One guard per process; a gateway serving several Hermes profiles would share it. | Guard registry keyed by agent home. | integration tests |
| 10 | Low | `cron/jobs.json` was sealed although the scheduler rewrites it outside any action. | Removed from the default core. | real loop |

## Proven with real processes (`tests/test_processes.py`)
* 8 OS processes start the same agent simultaneously over HTTP → exactly 1 runs, 7 refused, 1 lease ever granted.
* `kill -9`: lease stays held; owner revoke frees it at once; otherwise it frees itself at expiry.
* Ledger outage mid-run: the agent stops acting within one lease window and exits.

## Open
* **Medium — a write racing inside one of the agent's own tool-call windows is sealed (attributed to that action).** Needs OS isolation per agent; hosting provides it.
* **Low — deletion of a pristine shipped skill file is not noticed** (never under the seal; Hermes re-syncs it).
* **Low — the ledger pin is a local file**; it defends against the ledger, not against a local attacker.
