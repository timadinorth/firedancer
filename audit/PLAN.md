# Firedancer Audit Plan

Reference scope: [audit/SCOPE.md](./SCOPE.md)

## Purpose

This file is the ranked audit queue.

Use it for:
- what to investigate next
- what order to investigate it in
- what proof target each task is aiming for

Do not use it for:
- subsystem background that is still useful months later
- dead-end notes or why a path already failed
- long evidence chains

Those belong in [audit/NOTES.md](./NOTES.md).

## How To Maintain This File

- Keep tasks ordered from highest current audit value to lowest.
- Start new work from the highest active item unless there is a clear reason not to.
- When a task becomes weaker, move it down instead of leaving it near the top.
- When a task is proved false, remove it from the active queue and record the reason in `audit/NOTES.md`.
- Keep each item short and action-oriented. The point is prioritization, not archival detail.

## Severity Lens

Use `audit/SCOPE.md` for the exact contest rules. In practice, prioritize tasks that can plausibly lead to:
- deterministic all-Firedancer consensus or bank-hash divergence
- sandbox escape
- accounts database corruption with delayed financial impact
- arbitrary write in `execle` or `execrp`
- deterministic cluster-wide liveness failure

## Ranked Queue

### 1. Replay LUT Dependency And Stale-ALT Pre-Resolution

Status:
- `active`

Why this is first:
- strongest current consensus-drift lane that does not require memory corruption
- replay resolves LUTs before execution using root-oriented context
- the scheduler graph visibly tracks resolved ALT addresses, but not obviously the LUT account itself

Target files:
- `src/discof/replay/fd_sched.c`
- `src/discof/replay/fd_rdisp.c`
- `src/discof/replay/fd_replay_tile.c`
- `src/flamenco/runtime/fd_runtime.c`

Proof goal:
- prove or falsify that `Tx0` can mutate a LUT and `Tx1` in the same block can still be resolved or scheduled using stale LUT state

First checks:
- `fd_sched_parse_txn`
- `fd_rdisp_add_txn`
- `sched_fec->alut_ctx->{xid, els}`
- interaction between `published_root_slot` and executing bank horizon

### 2. Leader Bank-ABI Stale-ALT Freeze And ALUT Split Semantics

Status:
- `active`

Why this is second:
- bank ABI bakes loaded ALT addresses into sidecar state before Rust executes the transaction
- unlike runtime bundle execution, this path has no `prev_txn_outs`-style forwarded-state hook
- bank ABI and runtime do not use the same ALUT deactivation rule

Target files:
- `src/discoh/bank/fd_bank_abi.c`
- `src/discoh/bank/fd_bank_abi.h`
- `src/discoh/bank/fd_bank_tile.c`
- `src/flamenco/runtime/fd_alut.h`

Proof goal:
- prove or falsify that leader-side bank execution can use stale LUT contents or stale LUT activation state for same-block or same-bundle traffic

First checks:
- `fd_bank_abi_resolve_address_lookup_tables`
- `fd_bank_abi_txn_init`
- `fd_bank_tile` sanitize path before execution
- `deactivation_slot+512 < slot` heuristic versus `SlotHashes`-based runtime logic

### 3. Accdb Stale-Lineage Reachability In Production Flows

Status:
- `active`

Why this is third:
- strongest current concrete local bug
- already has one-off repro evidence
- still needs a validator-reachable production path to become a strong contest submission

Target files:
- `src/flamenco/accdb/`
- `src/funk/`
- `src/vinyl/`
- long-lived accdb users in replay, resolv, tower, rpc, execle, and execrp

Proof goal:
- show that a real production flow can reuse a canceled XID on the same long-lived accdb user handle and convert the stale-lineage bug into accounts-state corruption

First checks:
- post-cancel accdb-user reuse
- bank lifetime transitions around `cancel`
- v1 versus v2 tombstone and release paths

### 4. Replay Prune, Minority-Fork, And Bank-Lifetime Edge Cases

Status:
- `active`

Why this is fourth:
- recent fixes cluster here
- good bridge between local lifetime bugs and validator-level impact
- can plausibly become either liveness or consensus drift

Target files:
- `src/discof/replay/fd_sched.c`
- `src/discof/replay/fd_replay_tile.c`
- `src/discof/replay/fd_sched.h`
- `src/flamenco/runtime/fd_bank.c`

Proof goal:
- prove or falsify that prune or root-advance edge cases can leave one subsystem using stale bank state after another considers it dead

First checks:
- `fd_sched_root_notify`
- `subtree_abandon`
- `subtree_prune`
- bank refcount release timing versus `fd_accdb_cancel`

### 5. Tower / Ghost Consensus Edge Cases

Status:
- `active`

Why this is fifth:
- directly maps to consensus Highs
- recent fixes indicate unfinished edge conditions are plausible
- lower immediate ROI than the top replay and ALUT lanes, but still strong

Target files:
- `src/choreo/tower/fd_tower.c`
- `src/choreo/tower/fd_tower.h`
- `src/discof/tower/fd_tower_tile.c`
- `src/choreo/ghost/`

Proof goal:
- prove or falsify a deterministic tower or fork-choice divergence under the same network state

First checks:
- `fd_tower_reconcile`
- `fd_tower_vote_and_reset`
- initialization paths
- invalid-ancestor and switch-support assumptions

### 6. VM / CPI Pointer Translation And Direct-Mapping Mismatches

Status:
- `active`

Why this is sixth:
- recent fixes touched real safety boundaries
- can still produce strong execution or liveness findings
- lower priority than current consensus and accdb lanes

Target files:
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi.c`
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c`
- `src/flamenco/vm/syscall/fd_vm_syscall_runtime.c`
- `src/flamenco/runtime/fd_executor.c`

Proof goal:
- prove or falsify a caller/callee update, resize, aliasing, or pointer-validation bug that survives current fixes

First checks:
- direct-mapped versus non-direct-mapped equivalence
- account-info pointer restrictions
- partial-failure rollback behavior

### 7. Sandbox On Broader-I/O Tiles

Status:
- `deprioritized but live`

Why this is below the top lanes:
- first pass on `execle` and `execrp` was weak
- sandbox is still High, but current finding rate is lower than replay and ALUT work

Target files:
- `src/util/sandbox/`
- wider-I/O tile policies under `src/disco/` and `src/discof/`
- topo run descriptors

Proof goal:
- find a real privilege-boundary escape, not tile-to-tile influence

### 8. Execle / Execrp As Secondary Sinks

Status:
- `deprioritized until a producer bug is found`

Why this is low for now:
- current local pass found sink-side fragility but no convincing remote source
- this lane becomes interesting again if pack, replay, or bank metadata can be corrupted first

Target files:
- `src/discof/execle/fd_execle_tile.c`
- `src/discof/execrp/fd_execrp_tile.c`

Proof goal:
- only revisit if a producer-side bug can feed malformed `sz`, `bundle count`, `bank_idx`, or trailer metadata into the consumer

## Current Deprioritized Or Conditional Lanes

- ingress trusted-after-verify fail-stops in `dedup` / `verify` / `resolh` / `tpu_reasm` are mostly exhausted for the `firedancer` binary:
  - `gossip_dedup` is dead in `src/app/firedancer/topology.c`
  - downstream `payload_sz` / `txn_t_sz` fail-stops are redundant after verify parse success
  - `tpu_reasm` fatal sites are internal dcache or chunk-mapping sentinels
  - only revisit this lane if a new producer-contract mismatch or topology-specific path appears
- static `pack` unwritable-table drift without a concrete acceptance or rejection mismatch
- stateless/core-BPF migration drift until the relevant feature path is shown active and in-scope
- restore or repair unless tied to consensus or cluster-wide impact
- PoH or store pressure paths that look node-local rather than population-wide

## Current Best Concrete Candidate

The strongest already-demonstrated local bug remains the accdb stale-lineage issue. The highest-priority non-memory-corruption search lane is replay and bank-side stale ALT handling.
