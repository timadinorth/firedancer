# Firedancer Audit Notes

This file is the durable audit memory.

Use it for:
- subsystem facts that help future reviewers build context faster
- results that should not be rediscovered from scratch
- dead ends and why they failed
- constraints, trust boundaries, or invariants that change how a path should be audited
- partial findings that are not strong enough yet for `audit/PLAN.md`, but are still worth preserving

Do not use it for:
- the ranked next-task queue
- temporary assignment text
- broad prioritization debates

The rule of thumb is simple:
- if another agent would waste time without knowing it, record it here
- if the information only matters for deciding what to do next, it belongs in `audit/PLAN.md`

Use these status tags:
- `finding`: evidence-backed bug, or a bug class with a strong enough local proof that it should shape future work
- `hypothesis`: plausible lead that still needs a reachability chain, semantic comparison, or PoC
- `falsified`: investigated path that currently does not look contest-grade; record the reason so nobody repeats the same work blindly
- `todo`: narrow follow-up work that should be resumed later
- `note`: durable context, invariants, or architectural facts that influence audit reasoning

When recording a `falsified` item, prefer the form:
- what was suspected
- what was checked
- why it currently looks weak or blocked

When recording a `hypothesis`, prefer the form:
- exact target path
- what state transition or trust assumption might fail
- what proof would upgrade it

## High Rubric

Notes:
- `note`: classify candidates by systemic effect, not by how scary the local code looks.
- `note`: for consensus Highs, ask whether identical external input yields identical wrong state transitions across all Firedancer validators.
- `note`: for sandbox Highs, ask where the last actual privilege boundary sits and whether a less privileged side can make a more privileged side act for it.
- `note`: for accounts DB Highs, ask whether trusted fork-aware state can become false but still be reused as truth later.
- `note`: for execution Highs, ask whether guest-controlled execution context can become a host-memory write primitive or close equivalent.
- `note`: for liveness Highs, ask whether a protocol-reachable input can deterministically hit the same abort or dead-state path across the whole Firedancer population.
- `note`: by default, do not treat single invalid blocks, skipped slots, leader-only crashes, GUI/RPC-only issues, or tile-to-tile attacker assumptions as High.

## Execle / Execrp

Files:
- `src/discof/execle/fd_execle_tile.c`
- `src/discof/execrp/fd_execrp_tile.c`
- `src/flamenco/runtime/fd_runtime.c`
- `src/flamenco/runtime/fd_bank.c`

Notes:
- `falsified`: no direct remote arbitrary-write chain is proven in the current `execle` / `execrp` pass.
- `note`: `execle` `during_frag` derives `txn_cnt = (sz-sizeof(fd_microblock_execle_trailer_t))/sizeof(fd_txn_e_t)` without a local `sz >= trailer` or exact-divisibility check.
- `note`: `execle` `handle_bundle` stages bundle output into `fd_txn_p_t bundle_txn_temp[5]`; safety currently depends on the pack-side `FD_PACK_MAX_TXN_PER_BUNDLE` contract.
- `note`: `execrp` does not use `sz` as a loop bound or copy length the way `execle` does.
- `note`: both exec tiles call `fd_banks_bank_query` on incoming `bank_idx` without local bounds checks.
- `hypothesis`: if any replay- or pack-side remote bug can corrupt `bank_idx`, the consumer-side sink is already present.
- `hypothesis`: if any pack-side remote-reachable serialization bug breaks `sz` or bundle-count invariants, `execle` becomes the write amplification point.
- `todo`: revisit `execle` only when a producer-side path is found for malformed `sz`, bundle count, or trailer metadata.

## Sandbox

Files:
- `src/util/sandbox/fd_sandbox.c`
- `src/util/sandbox/fd_sandbox.h`
- `src/discof/execle/fd_execle_tile.seccomppolicy`
- `src/discof/execrp/fd_execrp_tile.seccomppolicy`

Notes:
- `falsified`: no convincing `execle` / `execrp` sandbox-escape chain from the first pass.
- `note`: these tiles do not request host networking, connect, or rename privileges in the topo run descriptors.
- `note`: the current seccomp policies only leave narrow write-style syscalls to `stderr` and optional logfile FDs plus sleep/timing support.
- `note`: inherited startup pipe FDs do not look useful under the current seccomp allowlists.
- `todo`: if sandbox comes back into focus, inspect broader-I/O tiles first rather than `execle` / `execrp`.

## Accdb / Funk / Vinyl

Files:
- `src/flamenco/accdb/fd_accdb_lineage.h`
- `src/flamenco/accdb/fd_accdb_lineage.c`
- `src/flamenco/accdb/fd_accdb_impl_v1.c`
- `src/flamenco/accdb/fd_accdb_impl_v2.c`
- `src/flamenco/accdb/fd_accdb_funk.c`
- `src/flamenco/accdb/fd_accdb_admin_v1.c`
- `src/flamenco/accdb/fd_accdb_admin_v2.c`
- `src/funk/`
- `src/vinyl/`

Notes:
- `finding`: stale lineage cache after cancel affects both accdb v1 and v2 user handles.
- `finding`: one-off local repros showed post-cancel acceptance of `fd_accdb_open_rw(... CREATE ...)` on the same accdb user handle.
- `finding`: one-off local repros also showed post-cancel reopening of an inherited parent/root account for copy-on-write on the same handle.
- `note`: `fd_accdb_lineage_set_fork` fast-paths on matching tip XID and skips rebuilding lineage state.
- `note`: `fd_accdb_lineage_write_check` validates range, XID equality, and frozen state, but not live `ACTIVE` state or `txn_map` membership.
- `note`: create paths cache the raw `txn` pointer in `rw->ref->user_data2` and publish through that cached pointer later.
- `hypothesis`: validator-level reachability depends on finding a production path that reuses the same long-lived accdb user after cancel on the same logical XID.
- `hypothesis`: v2 tombstone and vinyl release paths may still hide stale-release or stale-promotion lifetime bugs adjacent to the proven lineage issue.
- `todo`: trace replay, resolv, tower, rpc, execle, and execrp for post-cancel accdb-user reuse.
- `todo`: compare v1 and v2 handling of tombstones, ancestor promotion, and delayed publish against the stale-lineage defect.

## Replay / Scheduler / Banks

Files:
- `src/discof/replay/fd_replay_tile.c`
- `src/discof/replay/fd_sched.c`
- `src/discof/replay/fd_sched.h`
- `src/flamenco/runtime/fd_bank.c`
- `src/flamenco/runtime/fd_bank.h`

Notes:
- `note`: scheduler docs explicitly say a `bank_idx` may be recycled after prune.
- `note`: banks are keyed by bank index rather than slot to support equivocation; the same slot can legitimately exist with different bank identities.
- `note`: `fd_banks_bank_query` performs raw pool indexing before checking `bank->state`.
- `note`: `FD_TEST` is not debug-only in this tree; a failed bank lookup is a hard error, so stale `bank_idx` can also be a liveness sink.
- `hypothesis`: stale or recycled `bank_idx` is the most plausible bridge from local accdb lifetime bugs to validator-level corruption or crash.
- `hypothesis`: minority-fork prune, root notify, and in-flight work accounting may still have an edge case around stale bank visibility.
- `hypothesis`: replay scheduling may still need an explicit dependency on the lookup-table account itself, not just the resolved ALT addresses, when an earlier transaction mutates the LUT and a later transaction reads through it.
- `hypothesis`: replay scheduler currently resolves V0 LUTs against `alut_ctx->{xid=root, els=published_root_slot}` before execution, while runtime execution resolves against `{ bank->slot, bank->idx }`. A later transaction in the same block may therefore see stale LUT contents or stale activation state if an earlier transaction mutates the LUT or if root publication lags the executing bank horizon.
- `note`: this remains unproven. The current code clearly adds edges for immediate accounts and resolved ALT addresses, but the lookup-table account dependency itself still needs an explicit end-to-end check.
- `note`: the replay fast path only marks a transaction `serializing` when ALT resolution fails; successful ALT resolution still feeds resolved addresses into the scheduler graph without an obvious dependency on the LUT account itself.
- `todo`: audit `fd_sched_root_notify`, `subtree_abandon`, `subtree_is_prunable`, and `subtree_prune` against replay refcount drops and accdb cancel timing.
- `todo`: trace every producer and consumer of `bank_idx` that crosses tile or task boundaries.

## Pack / Bank ABI / Runtime Conformance

Files:
- `src/discoh/bank/fd_bank_abi.c`
- `src/disco/pack/fd_pack.c`
- `src/flamenco/runtime/`
- `src/discof/replay/`
- `src/flamenco/features/`

Notes:
- `note`: this is the cleanest place to look for deterministic all-Firedancer divergence from Agave without needing memory corruption.
- `hypothesis`: locally mirrored protocol semantics around feature gates, legacy versus v0 handling, ALT semantics, writability, or replay ordering may still disagree with Agave under the same input.
- `hypothesis`: pack, bank, and runtime may each believe an earlier stage already enforced an invariant, leaving a conformance gap only visible end-to-end.
- `hypothesis`: ALT temporal semantics in `fd_alut_status` and `fd_alut_active_addresses_len` are one of the best concrete semantic-drift targets.
- `note`: the highest-value ALT edge cases are `deactivation_slot == current_slot`, deactivation-slot presence in `SlotHashes`, `current_slot == last_extended_slot`, and `last_extended_slot_start_index` boundaries.
- `hypothesis`: `fd_bank_abi_resolve_address_lookup_tables` and runtime ALUT loading do not implement the same deactivation rule. Bank ABI uses the coarse `deactivation_slot+512 < slot` heuristic, while runtime checks actual `SlotHashes` membership. This is an explicit split-semantics surface near skipped-slot boundaries.
- `hypothesis`: leader-side bank execution may still have the stale-ALT class that runtime bundle execution already regressed on. `fd_bank_abi_txn_init` bakes loaded ALT addresses into sidecar memory before Rust execution sees the transaction, but it resolves from the current bank state only and has no `prev_txn_outs`-style forwarded-state hook for earlier same-block or same-bundle LUT mutations.
- `hypothesis`: stateless-to-core-BPF migration drift is still live but conditional on the relevant migration feature path being active and in scope.
- `note`: local `fd_builtin_programs.c` currently carries both Feature and Slashing stateless-to-core-BPF configs, so any claimed Agave mismatch needs explicit target-version verification before escalation.
- `note`: no bank-ABI-side regression test was found for same-block or same-bundle LUT mutation followed by later LUT use, even though runtime has a bundle ALT stale-read regression test.
- `note`: pack unwritable and builtin-classification differentials are currently deprioritized until a real acceptance or rejection mismatch is shown.
- `todo`: audit places that locally encode Solana semantics instead of simply consuming already-finalized state.
- `todo`: compare legacy and v0 transaction handling around packing, runtime checks, and bank application.
- `todo`: build a same-block and same-bundle ALT-mutation PoC against the bank ABI / bank tile path, not just the runtime bundle path.

## Tower / Ghost / Consensus

Files:
- `src/choreo/tower/fd_tower.c`
- `src/choreo/tower/fd_tower.h`
- `src/choreo/ghost/`
- `src/discof/tower/fd_tower_tile.c`

Notes:
- `note`: recent fixes cluster around switch-threshold, invalid-ancestor handling, and reconcile initialization.
- `hypothesis`: `fd_tower_reconcile` may still have a partial-initialization corner case around local root versus on-chain vote state.
- `hypothesis`: `vote_and_reset` may still mishandle ancestor validity or switch-support accounting in a network-reachable edge case.
- `todo`: compare tower decision inputs from ghost, vote account reads, and replay root updates under equivocation-style scenarios.

## VM / Runtime / CPI

Files:
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi.c`
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c`
- `src/flamenco/vm/syscall/fd_vm_syscall_runtime.c`
- `src/flamenco/runtime/fd_runtime.c`
- `src/flamenco/runtime/fd_executor.c`

Notes:
- `note`: recent fixes were pointer restriction and alignment fixes, not just semantic conformance changes.
- `note`: runtime commit keys accdb writes by `xid = { bank->f.slot, bank->idx }`, so any wrong bank object directly taints account-state publication.
- `hypothesis`: CPI caller/callee account updates may still have aliasing or resize corner cases between direct-mapped and non-direct-mapped paths.
- `hypothesis`: guest-visible pointer or region metadata mismatches may still produce a remotely triggerable all-validator crash even if they do not become an arbitrary write.
- `todo`: audit direct-mapping and non-direct-mapping branches for identical ownership, resize, and rollback behavior.

## Ingress / Cluster-Wide Liveness

Files:
- `src/disco/quic/fd_tpu_reasm.c`
- `src/disco/verify/fd_verify_tile.c`
- `src/disco/dedup/fd_dedup_tile.c`
- `src/discoh/resolh/fd_resolh_tile.c`
- `src/discoh/pohh/fd_pohh_tile.c`
- `src/disco/shred/fd_shred_tile.c`
- `src/disco/store/fd_store.c`
- `src/discof/replay/`

Notes:
- `note`: for this class, the right target is not “any crash” but a remote input that drives the whole Firedancer population into the same fail-stop path.
- `note`: do not treat the whole lane as leader-only. In `firedancer`, `verify` consumes `gossip_out`, so gossip-driven ingress checks run on all validators.
- `note`: `fd_verify_tile.c:49-51` does not reject all gossip votes. It only skips non-vote tags or vote fragments assigned to a different round-robin index. Assigned vote-tag fragments are processed.
- `falsified`: the strongest original anchor, `fd_dedup_tile.c:188`, is dead in the `firedancer` binary. `src/app/firedancer/topology.c` has no `gossip_dedup` link, so dedup never receives `IN_KIND_GOSSIP`. The live path is `gossip_out -> verify -> verify_dedup -> dedup`, and gossip votes reach dedup as `IN_KIND_VERIFY`.
- `note`: verify soft-drops both parse failure and signature failure before publish. On the live `verify_dedup` path, dedup and resolh only see transactions that already passed `fd_txn_parse` and `fd_txn_verify`.
- `note`: `fd_txn_parse_core` enforces `payload_sz <= FD_TXN_MTU`, and the `fd_txn_parse` wrapper with `payload_sz_opt == NULL` enforces full-payload consumption. This makes downstream `payload_sz` and `txn_t_sz` fail-stops in dedup and resolh producer-contract sentinels on the verify path.
- `falsified`: resolh `unknown in kind`, `unknown sig`, and chunk-range fail-stops are internal link-kind, bank-signal, or producer-metadata sentinels, not remotely reachable protocol fail-stops under the contest attacker model.
- `falsified`: `fd_tpu_reasm.c:248` and `:343` are dcache-base or chunk-mapping sentinels. Reaching them requires internal corruption or misconfiguration, not hostile QUIC fragmentation alone.
- `note`: there is a latent `FD_TPU_REASM_MTU > FD_TPU_MTU` mismatch, but the current remote path is blocked by UDP size drops and QUIC flow control (`initial_rx_max_stream_data = FD_TXN_MTU`).
- `note`: the `dedup` bundle crash on `bundle_idx > 4` is currently guarded by the bundle-client `<= 5` transaction cap, QUIC zeroing of `bundle_id`, and the fact that bundles are optional.
- `todo`: if this lane is revisited, pivot to new producer-contract mismatches or follower-wide `shred` / `store` / replay paths instead of repeating the same `dedup` / `verify` / `resolh` / `tpu_reasm` anchors.

## Stakes / Votes / Slot History

Files:
- `src/flamenco/stakes/fd_new_votes.c`
- `src/flamenco/stakes/fd_stakes.c`
- `src/flamenco/runtime/program/fd_vote_program.c`
- `src/flamenco/runtime/sysvar/fd_sysvar_slot_history.c`
- `src/flamenco/runtime/fd_executor.c`

Notes:
- `note`: late-April churn here makes this a realistic bank-hash or consensus-drift candidate even without a memory-safety angle.
- `hypothesis`: new-vote insertion/removal and boot-time seeding may still diverge from Agave under replay edge cases.
- `hypothesis`: slot-history or slot-hashes absence handling may still differ across runtime and vote-program call sites.
- `todo`: compare vote-account update propagation in bundles and root transitions against Agave behavior.

## Restore / Snapshot / Repair

Files:
- `src/discof/restore/fd_snapin_tile.c`
- `src/discof/restore/`
- `src/discof/repair/`
- `src/ballet/shred/`

Notes:
- `note`: `snapin` resets back toward rooted state after cancel, so it weakens the simplest stale-lineage reuse path.
- `hypothesis`: this area is more likely Medium unless a crafted restore or repair path can be shown to force validator-wide divergence or crash.
- `todo`: keep restore and repair in the background when tracing delayed-state corruption paths into replay.

## PoH / Shred / Store

Files:
- `src/discoh/pohh/fd_pohh_tile.c`
- `src/disco/shred/fd_shred_tile.c`
- `src/disco/store/fd_store.c`
- replay-side consumers

Notes:
- `note`: this lane is attractive because the code already contains explicit halt-path language such as `chain must halt` and hard `store full` assumptions.
- `hypothesis`: skipped-tick or leader-state assumptions in `pohh` may still be reachable through hostile-but-valid replay timing or state transitions.
- `hypothesis`: `store full` and related resource assumptions can only become High if network or replay input can force them deterministically across the validator population, not merely on one saturated node.
- `todo`: treat these as deterministic-halt targets, not generic crash targets, and prove whether the reachability is protocol-wide or just local pressure.

## Cross-Subsystem Chains

Notes:
- `hypothesis`: stale accdb lineage + recycled `bank_idx` is the best current route to a future High.
- `hypothesis`: a remote pack-side count or size bug would likely detonate in `execle` because local consumer checks are weaker than equivalent GUI-reader checks.
- `hypothesis`: a stale `bank_idx` bug can present as either liveness failure through `FD_TEST` or silent corruption through wrong-bank account commits.
- `hypothesis`: ALT temporal semantics in `fd_alut_status` and `fd_alut_active_addresses_len` are now one of the highest-value semantic-drift targets.
- `hypothesis`: replay scheduling may still need an explicit dependency on the lookup-table account itself, not just the resolved ALT addresses, when a prior transaction mutates the LUT and a later transaction reads through it.
- `hypothesis`: there are now two distinct stale-ALT surfaces to compare against the known runtime bundle fix: replay pre-resolution at root horizon, and leader bank-ABI pre-resolution into sidecar state.
- `note`: the existing bundle ALT regression in `test_bundle_exec.c` is a same-bundle forwarded-state problem; it does not by itself prove the replay-scheduler LUT-account dependency issue.
- `hypothesis`: stateless-to-core-BPF migration drift is still live but conditional. It only matters if the relevant migration feature path is active and in scope for the contest target.
