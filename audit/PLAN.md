# Firedancer High-Severity Audit Plan

Scope reference: [audit/SCOPE.md](./SCOPE.md)

This plan follows the `code-audit` method: start from dangerous sinks, trace the controlling operand backward to an attacker-controlled source, and keep only findings with a defensible High-severity impact chain.

Commit-history focus for this revision:
- upstream commit window reviewed: 2026-04-14 through 2026-05-04
- most recent upstream code changes in that window landed on 2026-04-29
- this revision turns those recent fixes into a ranked audit queue

## High Targets

From `audit/SCOPE.md`, the High targets are:
- bank hash mismatch or consensus bug causing all Firedancer validators to fork from the network
- sandbox escape, excluding tile-to-tile attacks
- accounts database corruption enabling delayed loss of funds
- arbitrary write primitives in execution (`execle` and `execrp`) tiles
- remotely triggerable cluster-wide liveness failure affecting all Firedancer validators

## High Filters

Every candidate should be framed against the actual contest Highs, not just local bug severity.

- consensus: can identical external input drive all Firedancer validators into the same wrong state transition or bank-hash result?
- sandbox: can attacker-controlled input cross the last real trust boundary and make a more privileged component act outside its intended role?
- accounts DB: can trusted fork-aware state become internally inconsistent and still be treated as truth later?
- execution write: can guest-controlled or protocol-controlled execution context become a host-memory write primitive or equivalent state-corruption primitive?
- cluster liveness: can one remote input deterministically drive the whole Firedancer population into the same halt, abort, or unrecoverable dead state?

By default, do not treat these as High without more evidence:
- a single invalid block or one-validator divergence
- skipped leader slots
- leader-only crash paths
- GUI or RPC-only liveness issues in narrow configurations
- tile-to-tile attacks that assume a compromised tile

## Practical High Entry Points

These file groups are worth keeping in rotation because they map directly to the High categories.

### Consensus / Bank-Hash Conformance

Primary files:
- `src/discoh/bank/fd_bank_abi.c`
- `src/disco/pack/fd_pack.c`
- `src/flamenco/runtime/`
- `src/discof/replay/`
- `src/choreo/tower/`
- `src/choreo/ghost/`

Primary question:
- where does Firedancer locally mirror Solana or Agave semantics, and can that mirrored logic deterministically disagree under the same network input?

### Sandbox Boundary

Primary files:
- `src/util/sandbox/`
- `src/app/shared/commands/run/*.seccomppolicy`
- `src/disco/*/*.seccomppolicy`
- `src/discof/*/*.seccomppolicy`
- `src/disco/topo/fd_topo_run.c`

Primary question:
- where is the last real privilege boundary, and can an untrusted input or tile coerce a more privileged side across it?

### Trusted-State Corruption

Primary files:
- `src/flamenco/accdb/`
- `src/funk/`
- `src/vinyl/`
- `src/flamenco/progcache/`

Primary question:
- can fork-aware durable state become wrong in a way that survives long enough to influence replay, runtime, or validator decisions?

### Execution Write Primitives

Primary files:
- `src/discof/execle/`
- `src/discof/execrp/`
- `src/flamenco/vm/`
- `src/flamenco/runtime/`
- `src/flamenco/runtime/program/`
- `src/flamenco/vm/syscall/`

Primary question:
- can guest-controlled sizes, offsets, borrowing state, or VM-to-host transitions turn execution into a host-memory write primitive?

### Deterministic Remote Liveness

Primary files:
- `src/disco/quic/fd_tpu_reasm.c`
- `src/disco/verify/fd_verify_tile.c`
- `src/disco/dedup/fd_dedup_tile.c`
- `src/discoh/resolh/fd_resolh_tile.c`
- `src/discoh/pohh/fd_pohh_tile.c`
- `src/disco/shred/fd_shred_tile.c`
- `src/disco/store/fd_store.c`
- `src/discof/replay/`

Primary question:
- can one remote-looking but protocol-reachable input flow through ingress and hit the same fail-stop path on all Firedancer validators?

## Easy-First Bootstrap Queue

This queue is for the first 2 audit days. It is different from the strongest current evidence queue below. It optimizes for shortest path to a realistic High PoC.

### 1. Ingress Trusted-After-Verify Fail-Stops

Why first:
- the impact target is cluster-wide liveness, not theft
- these paths contain many fail-stop assumptions about what an earlier stage already guaranteed
- they require less total Solana-runtime context than consensus or accdb exploitation

Primary files:
- `src/disco/dedup/fd_dedup_tile.c`
- `src/disco/verify/fd_verify_tile.c`
- `src/discoh/resolh/fd_resolh_tile.c`
- `src/disco/quic/fd_tpu_reasm.c`

Current confidence:
- strongest concrete local anchor in this lane is dedup gossip-vote parse-after-sigverify at `fd_dedup_tile.c:188`
- some obvious sentinels in this group are weaker than they look because they currently appear to guard internal link metadata or allocator state rather than direct remote input

Primary question:
- can a valid-looking remote input survive one ingress stage and then deterministically hit a later fail-stop because the next stage assumes prior validation already happened?

### 2. Semantic Drift in Pack / Bank ABI / ALUT

Why second:
- this is the shortest path from local semantic mismatch to deterministic all-Firedancer divergence
- the code explicitly mirrors Agave and Solana rules in several places
- a bank-hash or replay-conformance High does not require proving direct fund theft

Primary files:
- `src/disco/pack/fd_pack.c`
- `src/disco/pack/fd_pack_unwritable.h`
- `src/discoh/bank/fd_bank_abi.c`
- `src/flamenco/runtime/fd_alut.h`
- `src/flamenco/runtime/`
- `src/discof/replay/`

Current concrete hypotheses:
- ALT temporal semantics in `fd_alut_status` and `fd_alut_active_addresses_len`
- replay-scheduler dependency handling for lookup table accounts
- builtin or migration classification drift, but only if the relevant feature path is active in-scope

Primary question:
- can Firedancer deterministically accept, reject, resolve, or schedule a transaction differently from the contest Agave target under the same input?

### 3. PoH / Shred / Store Deterministic Halt Chains

Why third:
- these paths contain explicit halt or impossible-state logic
- the impact is still cluster-wide liveness rather than a local semantic bug
- proving reachability is usually easier than proving durable state corruption

Primary files:
- `src/discoh/pohh/fd_pohh_tile.c`
- `src/disco/shred/fd_shred_tile.c`
- `src/disco/store/fd_store.c`
- replay-side consumers of those outputs

Primary question:
- can protocol-reachable traffic or replay state drive these fail-stop assumptions in a way that affects the whole Firedancer population rather than one leader or one misconfigured node?

### 4. Keep the Accdb High Candidate Alive in Parallel

Why not first in the bootstrap queue:
- it is already the strongest concrete candidate
- but it is more stateful and the PoC-to-validator-impact bridge is heavier than ingress or semantic-drift work

Working rule:
- keep the stale-lineage candidate open in parallel, but spend the first short passes on ingress and semantic drift first

## Search Order

### 1. Arbitrary Write in `execle` / `execrp`

Why first:
- the impact is explicitly named in scope
- the target set is small
- the sinks are concrete and easy to falsify or prove

Primary files:
- `src/discof/execle/fd_execle_tile.c`
- `src/discof/execrp/fd_execrp_tile.c`
- nearby runtime and accdb commit paths they call

Primary sinks:
- `fd_chunk_to_laddr*`
- `fd_memcpy` or direct structure writes
- scratch / workspace buffer writes
- output publication buffers
- runtime commit paths that materialize account writes

Primary question:
- can remote or protocol-derived data control a destination pointer, offset, count, or index strongly enough to produce a write primitive inside these tiles?

### 2. Sandbox Escape

Why second:
- the file set is narrow
- the impact is direct
- a real sandbox break is easier to define than broad consensus logic

Primary files:
- `src/util/sandbox/fd_sandbox.c`
- `src/util/sandbox/fd_sandbox.h`
- `src/discof/execle/fd_execle_tile.seccomppolicy`
- `src/discof/execrp/fd_execrp_tile.seccomppolicy`
- generated seccomp headers

Primary sinks:
- unexpected allowed syscalls
- inherited file descriptors
- writable executable mappings
- namespace or privilege setup gaps
- host-visible filesystem or socket escape paths

Primary question:
- can untrusted input inside an in-scope tile cross the process sandbox boundary and reach host resources, excluding mere tile-to-tile influence?

### 3. Accounts DB Corruption with Delayed Loss-of-Funds Impact

Why third:
- large surface, but directly mapped to High
- shared memory and async publication are common corruption points

Primary files:
- `src/flamenco/accdb/`
- `src/discof/accdb/fd_accdb_tile.c`
- `src/funk/`
- `src/vinyl/`

Primary sinks:
- publication of account writes
- lineage / root transitions
- refcount and handle lifetime mistakes
- stale pointers into shared memory
- multi-account batch write paths

Primary question:
- can attacker-driven transaction patterns or replay ordering create persistent state corruption that later manifests as balance or ownership divergence?

### 4. Bank-Hash Mismatch / Consensus Fork

Why fourth:
- highest-value logic target
- broader state machine, so more expensive to audit well

Primary files:
- `src/discof/replay/`
- `src/discof/tower/`
- `src/choreo/`
- `src/flamenco/runtime/`
- `src/flamenco/features/`

Primary sinks:
- bank-hash computation and publication
- root advancement
- vote lockout transitions
- fork-choice state
- feature-gated runtime behavior

Primary question:
- can identical network inputs drive all Firedancer validators to a deterministic state transition that diverges from the network?

### 5. Cluster-Wide Liveness Failure

Why fifth:
- many such bugs appear as by-products of the first four audits
- easier to prove once a fatal remote path is already found

Primary files:
- `src/discof/replay/`
- `src/discof/repair/`
- `src/discof/restore/`
- `src/flamenco/runtime/`
- `src/flamenco/vm/`
- `src/ballet/shred/`

Primary sinks:
- remote-input-triggered `FD_LOG_ERR`
- fatal assertions
- oversized allocations
- parser underflow / overflow
- unrecoverable state transitions

Primary question:
- can a protocol-reachable attacker force all Firedancer validators into the same crash or dead state?

## Current Status

Known first-pass results:
- `execle` / `execrp` tile-local arbitrary-write hunt: narrowed, no convincing direct High yet
- sandbox first pass: no convincing `execle` / `execrp` escape yet
- accdb: active High candidate

Active strongest candidate:
- stale accdb lineage cache allows post-cancel writes on an invalid XID
- this is not limited to missing-key `CREATE`
- it also reaches frozen-record copy-on-write on inherited parent or root state
- detailed evidence and one-off repro notes live in `share/codex.md`

Immediate implication:
- the commit-driven queue should start with accdb / vinyl lifetime and then move to replay / tower / VM paths that plausibly convert that primitive or a similar lifetime bug into a validator-level High

## Commit-Driven Queue

This queue is ranked by:
- direct match to High categories in `audit/SCOPE.md`
- density of recent fixes in the same logic
- likelihood that remaining edge cases are still reachable from `firedancer`

### 1. Accdb / Vinyl Lifetime and Stale-Handle Reuse

Why first:
- already has a concrete High candidate
- recent fix history points to the same class of bug
- affects both pure `funk` and vinyl-backed accdb paths

Recent signal:
- 2026-04-22 `b83843ca`: `accdb: stale vinyl release from tombstone`

Primary files:
- `src/flamenco/accdb/fd_accdb_lineage.h`
- `src/flamenco/accdb/fd_accdb_lineage.c`
- `src/flamenco/accdb/fd_accdb_impl_v1.c`
- `src/flamenco/accdb/fd_accdb_impl_v2.c`
- `src/flamenco/accdb/fd_accdb_funk.c`
- `src/flamenco/accdb/fd_accdb_admin_v1.c`
- `src/discof/fd_accdb_topo.c`
- long-lived accdb users in `src/discof/replay/`, `src/discof/resolv/`, `src/discof/tower/`, `src/discof/rpc/`, `src/discof/execle/`, `src/discof/execrp/`

Primary hypotheses:
- a canceled bank XID can be reused on the same tile-local accdb user object after replay-side cancel
- v2 tombstone or vinyl release logic still has a stale-release, double-release, or stale-promotion corner case
- stale lineage plus ancestor promotion can publish records through a freed or recycled txn slot
- production tiles can synthesize `(slot, bank_idx)` again after bank lifetime has already transitioned

Primary sinks:
- `fd_accdb_lineage_write_check`
- `fd_accdb_funk_prep_create`
- v1 `close_rw`
- v2 `funk_close_rw`
- v2 ACQUIRE to RELEASE compaction logic

First tasks:
- trace replay, resolv, tower, and rpc bank-handle release timing against accdb user reuse
- compare v1 and v2 write paths for missing state or membership validation
- stress tombstone and ancestor-promotion cases in v2 around `release_cnt`, `req_cnt`, and `req_val_gaddr0`

Why this can still be High:
- accounts DB corruption enabling delayed loss of funds is explicitly in scope
- the current candidate already proves unsafe post-cancel writes locally

### 2. Replay Scheduler Minority-Fork Pruning and Bank Lifetime

Why second:
- two fixes in two days in the same root-notify / prune path
- replay pruning mistakes can become either consensus divergence or cluster-wide liveness
- this is the most likely place to turn a stale bank handle into a validator-level exploit chain

Recent signal:
- 2026-04-28 `7eaab383`: `sched: fix minority fork prune check on root_notify`
- 2026-04-29 `50f96503`: `sched: fix elevated levels of live slots`

Primary files:
- `src/discof/replay/fd_sched.c`
- `src/discof/replay/fd_replay_tile.c`
- `src/discof/replay/fd_sched.h`

Primary hypotheses:
- subtree pruning still has a reachable edge case where a minority fork is pruned or retained incorrectly under in-flight work
- refcount release timing can leave a bank visible to one subsystem after replay believes it is safe to cancel
- root advancement plus minority-fork abandonment can desynchronize `sched`, `banks`, and `block_id_arr`

Primary sinks:
- `fd_sched_root_notify`
- `subtree_abandon`
- `subtree_is_prunable`
- `subtree_prune`
- replay-side `fd_banks_prune_one_dead_bank` and `fd_accdb_cancel`

First tasks:
- audit every place that walks `child_idx` / `sibling_idx`
- compare scheduler liveness state with replay bank refcounting and dead-bank transitions
- build a hostile scenario around in-flight work on a minority fork during root change

Why this can still be High:
- wrong fork pruning can cause bank-hash mismatch or cluster-wide liveness failure
- stale bank lifetime is the strongest route from the current accdb candidate to validator-level reachability

### 3. Tower Reconcile, Switch Threshold, and Invalid-Ancestor Logic

Why third:
- multiple consensus-facing fixes in the same two-week window
- tower logic maps directly to the High fork category
- this is the cleanest route to a deterministic all-Firedancer divergence

Recent signal:
- 2026-04-14 `f08d97aa`: `fix(tower): switch threshold`
- 2026-04-15 `f0b7de39`: `fix(tower): missing invalid ancestor case in vote_and_reset`
- 2026-04-28 `fcc669f2`: `fix(tower): fd_tower_reconcile bug in initialization`

Primary files:
- `src/choreo/tower/fd_tower.c`
- `src/choreo/tower/fd_tower.h`
- `src/discof/tower/fd_tower_tile.c`
- `src/choreo/ghost/`

Primary hypotheses:
- `fd_tower_reconcile` still mishandles local-root versus on-chain-root interactions in a partially initialized tower
- `vote_and_reset` can still accept a bad ancestor or bad switch-support set in a corner case
- backfilled `voted_block_id` can disagree with Agave under equivocation or repair-driven convergence

Primary sinks:
- `fd_tower_reconcile`
- `fd_tower_vote_and_reset`
- `fd_tower_from_vote_acc`
- `query_vote_accs` reconcile path in `fd_tower_tile.c`

First tasks:
- replay the initialization and wait-for-supermajority paths carefully
- audit root overwrites, dropped on-chain votes, and ancestor assumptions
- compare tower decision inputs with ghost and vote-account-derived state

Why this can still be High:
- consensus bugs causing all Firedancer validators to fork from the network are explicitly High

### 4. VM / CPI / Syscall Pointer Translation and Direct Mapping

Why fourth:
- recent fixes are pointer-validation and alignment fixes, not just semantics
- this is where execution-reachable memory safety and validator-wide crash paths are most likely
- even if not an arbitrary write, a universal abort or deterministic runtime divergence would be valuable

Recent signal:
- 2026-04-22 `87ef4c31`: `fix VM_SYSCALL_CPI_ACC_INFO_DATA_VADDR check`
- 2026-04-22 `9ea4e56a`: `check alignment before performing stores for sysvar syscalls`
- 2026-04-24 `4ad0b1bb`: `restructure cpi to match agave control flow`

Primary files:
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi.c`
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c`
- `src/flamenco/vm/syscall/fd_vm_syscall_runtime.c`
- nearby runtime account-borrowing helpers

Primary hypotheses:
- deprecated versus direct-mapped syscall modes still differ from Agave in a safety-relevant way
- caller-to-callee and callee-to-caller account updates still have a resize or aliasing corner case
- account-info pointer restriction checks can still be bypassed through refcell indirection or stale region metadata

Primary sinks:
- CPI account translation macros
- caller-account update path after resize
- sysvar writes into guest-visible output buffers
- region metadata updates after data-length changes

First tasks:
- audit every use of `vm_syscall_cpi_acc_info_rc_refcell_as_ptr`
- compare direct-mapping and non-direct-mapping branches for ownership and resize equivalence
- inspect whether failed CPI or partial update paths leave caller-visible account state inconsistent

Why this can still be High:
- execution-reachable pointer bugs can become `execle` or `execrp`-adjacent arbitrary writes, or remotely triggerable all-validator crashes

### 5. `execle` Fee-Only / Nonce / CU Accounting and `rdisp` 128-Writable-Account Edge Cases

Why fifth:
- these are narrower than the first four, but still recent and potentially High-relevant
- both touch invariants that can produce divergence or remote liveness effects if still incomplete

Recent signal:
- 2026-04-23 `c1094768`: `bank, execle: fix FeesOnly nonce rebates`
- 2026-04-17 `37a3b81e`: `rdisp: fix handling of transactions with 128 writable accounts`

Primary files:
- `src/discof/execle/fd_execle_tile.c`
- `src/discoh/bank/fd_bank_tile.c`
- `src/discof/replay/fd_rdisp.c`

Primary hypotheses:
- fee-only durable-nonce corner cases can still desynchronize cost, rebate, or landing behavior from the network
- `rdisp` edge encoding around `w_cnt_1` still has an off-by-one, stale-edge, or DAG corruption corner case
- high-account-count transactions can still perturb scheduling order, causing deterministic liveness or execution divergence

Primary sinks:
- fee-only commit / cancel split in `execle`
- rebate arithmetic and `FD_TXN_P_FLAGS_EXECUTE_SUCCESS`
- `FOLLOW_EDGE` and `edge_cnt_etc` encoding in `fd_rdisp.c`

First tasks:
- audit fee-only transactions that fail before VM execution but still touch account-data cost accounting
- inspect `rdisp` transitions for `w_cnt==128` and for `w_cnt==1` sentinel behavior

Why this can still be High:
- `execle` is directly named in scope for arbitrary-write review
- scheduler corruption can cascade into cluster-wide liveness or consensus issues

### 6. Stakes / New Votes / Slot-History Conformance

Why sixth:
- lower immediate signal than the first five
- still a strong consensus and bank-hash candidate due to broad late-April churn in vote and stake accounting

Recent signal:
- 2026-04-16 `55d24ec2`: `zero stake account handling`
- 2026-04-28 `0a47b31b`: `new votes: support for removing old votes`
- 2026-04-28 `c6799e4c`: `runtime: seed new votes on boot`
- 2026-04-23 `835b5019`: `sysvar: simplify slot history code`

Primary files:
- `src/flamenco/stakes/fd_new_votes.c`
- `src/flamenco/stakes/fd_stakes.c`
- `src/flamenco/runtime/fd_executor.c`
- `src/flamenco/runtime/program/fd_vote_program.c`
- `src/flamenco/runtime/sysvar/fd_sysvar_slot_history.c`

Primary hypotheses:
- vote-cache migration across bundle reuse, boot seeding, or removal of old votes still diverges from Agave
- slot-history or slot-hashes availability checks still differ across replay and vote-program paths
- zero-stake or tip-account special handling still perturbs capitalization or hash inputs unexpectedly

Primary sinks:
- vote-update propagation in bundle reuse
- slot-hashes joins and absence handling
- new-vote insertion, removal, and delta application

First tasks:
- compare bundle account-carry logic with vote-update propagation
- inspect boot-time seeding and root-reset paths for `fd_new_votes`
- compare slot-history based vote acceptance with Agave’s rejection cases

Why this can still be High:
- these paths feed bank state and consensus decisions, so remaining edge cases can still produce deterministic bank-hash mismatch

## Lower-Priority From Recent Commits Only

These are not ruled out. They are simply not where the last 20 days of fixes point most strongly.

- sandbox escape: little recent change signal in `src/util/sandbox/`
- `execrp` tile-local arbitrary write: recent changes were mostly metrics, not logic fixes
- generic restore / snapshot parsing: more likely Medium or startup-only unless it can be tied to validator-wide remote impact

## Future High Escalation Tracks

These are not the current top queue, but they are worth preserving because they can become High quickly if an upstream reachability link is found.

### 1. Accdb Stale-Lineage Plus Recycled `(slot, bank_idx)`

Why keep it warm:
- the local accdb stale-lineage defect is already proven
- replay and sched explicitly allow `bank_idx` recycling after prune
- runtime account commits key writes by `{ bank->f.slot, bank->idx }`

Primary files:
- `src/flamenco/accdb/fd_accdb_lineage.h`
- `src/flamenco/accdb/fd_accdb_lineage.c`
- `src/flamenco/accdb/fd_accdb_impl_v1.c`
- `src/flamenco/accdb/fd_accdb_impl_v2.c`
- `src/flamenco/accdb/fd_accdb_admin_v1.c`
- `src/discof/replay/fd_sched.h`
- `src/discof/replay/fd_replay_tile.c`
- `src/flamenco/runtime/fd_bank.c`
- `src/flamenco/runtime/fd_runtime.c`

Primary hypothesis:
- a long-lived tile-local accdb user can keep stale lineage state for `(slot, bank_idx)`
- replay later recycles that `bank_idx` for the same slot or for a reachable conflicting bank-lifetime transition
- runtime then commits writes under the wrong fork ancestry or wrong bank identity

Why this could become High:
- it is the cleanest route from the proven local accdb bug to either delayed loss-of-funds corruption or deterministic bank-hash divergence

Next checks:
- trace every production path that can observe a canceled bank and later reopen with the same logical `(slot, bank_idx)` pair
- compare bank-prune timing with accdb-user lifetime in replay, resolv, tower, rpc, execle, and execrp

### 2. Unchecked `bank_idx` as a Shared Sink

Why keep it warm:
- `execle`, `execrp`, and replay all consume incoming `bank_idx`
- `fd_banks_bank_query` performs raw pool indexing and only rejects `INACTIVE` state afterward
- a stale or corrupted `bank_idx` would taint both account commits and consensus state

Primary files:
- `src/flamenco/runtime/fd_bank.c`
- `src/flamenco/runtime/fd_bank.h`
- `src/discof/execle/fd_execle_tile.c`
- `src/discof/execrp/fd_execrp_tile.c`
- `src/discof/replay/fd_replay_tile.c`
- `src/discof/replay/fd_sched.c`

Primary hypothesis:
- a replay, sched, or pack-side edge case can publish a stale, recycled, or inconsistent `bank_idx`
- the consumer then either crashes all validators through `FD_TEST` / bad state, or commits against the wrong bank object

Why this could become High:
- the sink already exists in scope-reachable code
- the missing piece is only the attacker-reachable producer-side inconsistency

Next checks:
- audit every producer of `bank_idx` carried across links or task structs
- compare `bank_idx` lifetime rules against dead-bank pruning, refcount drops, and root advancement

### 3. Pack-to-`execle` Invariant Mismatch

Why keep it warm:
- `execle` still lacks local checks that equivalent reader paths already carry
- the current falsification depends on the pack producer preserving its serialization contract
- if pack gains a remote-reachable count or size bug, `execle` is the likely detonation point

Primary files:
- `src/disco/pack/fd_pack_tile.c`
- `src/disco/pack/fd_pack.c`
- `src/discof/execle/fd_execle_tile.c`
- `src/disco/gui/fd_gui_tile.c`

Primary hypothesis:
- a pack-side edge case can miscompute fragment `sz`, bundle count, or trailer-derived metadata
- `execle` then amplifies it through unchecked `txn_cnt`, fixed-size bundle staging, or bank selection

Why this could become High:
- arbitrary write in `execle` is explicitly in scope
- the dangerous sink is already identified; only the remote producer chain is missing

Next checks:
- compare pack-side scheduling and publish invariants with every consumer assumption in `execle`
- look for remote-reachable pack states where `schedule_cnt`, bundle flags, or trailer metadata can desynchronize

## Next Concrete Pass

The next code pass should be:
1. map ingress trusted-after-verify fail-stops in `dedup`, `verify`, `resolh`, and `quic/reasm`, with emphasis on remotely reachable parse or metadata assumptions
2. then audit semantic drift in `pack`, `fd_bank_abi`, and `fd_alut.h`, starting with ALT temporal semantics and lookup-table scheduling dependencies
3. then test PoH / shred / store halt chains for deterministic cluster-wide reachability
4. if those lanes do not produce a stronger result quickly, return to the accdb production-reachability trace from `share/codex.md`, then replay scheduler bank lifetime, then tower

Stop conditions:
- if ingress or semantic-drift work produces a credible cluster-wide High first, stay on it until the PoC and impact chain are complete
- if a validator-level reachability chain is found for the accdb stale-XID write, stay on accdb until the impact is fully characterized
- if replay / tower reveals a stronger deterministic fork path first, switch focus immediately to the consensus chain

## Working Rules

- stay inside code reachable from `firedancer`
- prefer GCC-reproducible issues over Clang-only behavior
- ignore `TODO` / `FIXME` as evidence
- ignore tile-to-tile-only attacks
- compare severity against `audit/SCOPE.md`, not gut feeling

## Triage Standard

A candidate advances only if it has all of:
- a named sink
- the exact dangerous operand
- a backward path to a realistic attacker source
- a missing or bypassed invariant
- a High-severity impact story that matches `audit/SCOPE.md`

If any of those are missing, drop the lead quickly and move to the next sink.
