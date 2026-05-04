---
name: code-audit
description: Audit Firedancer v1 with Immunefi contest constraints. Use when reviewing in-scope `firedancer`-reachable code for memory-safety, consensus, runtime-conformance, sandbox, and liveness bugs that need a defensible impact chain and runnable PoC.
---

# Firedancer V1 Code Audit

Use this skill for the Firedancer v1 Immunefi audit competition.

If present, read these first:
- `audit/SCOPE.md`
- `audit/ARCHITECTURE.md

## Scope Gates

Audit only code reachable from the `firedancer` binary.

In scope:
- `src/app/firedancer/`
- linked and reachable code under `src/`
- compiler-dependent issues reproducible with GCC 8.5, 13, or 14

Out of scope unless it proves a production issue:
- `src/app/firedancer-dev/`
- code only reachable from `fdctl` or `fddev`
- development scripts, CI, and test-only bugs
- tile-to-tile attacks that assume a compromised tile
- Solana protocol bugs that are not Firedancer implementation bugs
- `TODO` / `FIXME`-only findings without exploitability
- Clang-only behavior

Before treating a bug as new, check whether it is already listed in contest known-issues trackers or public mid-contest fixes.

## Threat Model

Assume remote or protocol-adjacent attackers first:
- gossip peer
- QUIC or TPU packet sender
- malicious leader or validator
- crafted snapshot or repair data provider
- transaction sender
- RPC or GUI client where exposure is intended

Do not rely on:
- privileged operator access
- leaked keys
- social engineering
- destructive testing on mainnet or public testnet

## What Wins

Prioritize bugs that map cleanly to contest impacts:
- Critical: loss of funds, forged or invalid signatures, runtime conformance leading to loss of funds, infinite mint, key exfiltration
- High: cluster-wide consensus fork, sandbox escape, accounts DB corruption enabling delayed loss of funds, arbitrary write in `execle` or `execrp`, cluster-wide liveness failure
- Medium: invalid block production, skipped leader slot, remotely triggerable leader crash or liveness loss
- Low: narrower liveness issues such as exposed RPC or snapshot-boot windows

## Audit Order

Start with the largest attack surfaces called out by the contest:

1. Runtime and VM
   Look in `src/flamenco/runtime/`, `src/flamenco/vm/`, `src/flamenco/progcache/`, `src/flamenco/features/`.
   Hunt for Agave conformance mismatches, integer overflow in cost or size accounting, loader bugs, syscall boundary errors, stale feature-gate assumptions, and arbitrary read/write primitives.

2. Replay and bank lifetime
   Look in `src/discof/replay/`, `src/discoh/bank/`, `src/flamenco/runtime/fd_bank*`.
   Focus on shared-memory ownership, refcounts, fork transitions, delayed frees, stale bank pointers, and state transitions that can desync consensus or bank hash.

3. Accounts DB and storage
   Look in `src/funk/`, `src/vinyl/`, `src/flamenco/accdb/`, `src/discof/accdb/`.
   Hunt for race conditions, corruption across shared memory boundaries, workspace misuse, attacker-reachable `io_uring` misuse, and persistence bugs that become delayed loss-of-funds or replay divergence.

4. Repair, restore, and shred handling
   Look in `src/discof/repair/`, `src/discof/restore/`, `src/discof/forest/`, `src/discof/reasm/`, `src/disco/shred/`, `src/ballet/shred/`.
   Focus on parser trust boundaries, reassembly invariants, oversized allocation math, malformed Merkle or FEC handling, and corrupt data staged for later exploitation.

5. Consensus, tower, gossip
   Look in `src/choreo/`, `src/discof/tower/`, `src/discof/gossip/`, `src/flamenco/gossip/`.
   Hunt for fork-choice mistakes, equivocation logic bugs, false confirmations, stale vote handling, CRDS invariant failures, and amplification or liveness failures.

6. RPC, GUI, networking, sandbox, signing
   Look in `src/discof/rpc/`, `src/disco/gui/`, `src/waltz/`, `src/util/sandbox/`, `src/disco/sign/`.
   Focus on parser bugs, request-state explosions, HTTP/2 or QUIC state machines, shared-memory isolation mistakes, seccomp boundary slips, and private key exposure.

## Method

Work backward from dangerous sinks instead of reading the whole subsystem first.

Good sinks:
- length-controlled copy or parse
- pointer arithmetic and indexing
- allocation sizing
- shared-memory attach, publish, or free
- refcount decrement or ownership transfer
- syscall or VM memory access
- signature acceptance
- consensus vote, fork-choice, or bank-hash commit

For each candidate, recover:
1. the exact operand that makes the sink dangerous
2. where it came from
3. which invariants or guards are supposed to constrain it
4. whether attacker control survives the transforms
5. the concrete validator impact

Prefer evidence chains over suspicion lists.

## Firedancer-Specific Heuristics

- Shared memory is a first-class attack surface. Trace ownership, lifetimes, and publication order across tiles and client-server boundaries.
- Treat workspace allocators, scratch regions, and ring buffers as corruption hotspots.
- For conformance bugs, compare behavior against Agave semantics, not just local assertions.
- Feature-gated code is only bounty-relevant when the gate is active on mainnet or present in `src/flamenco/features/feature_map.json`.
- Snapshot, repair, gossip, and shred paths can stage bad state that detonates later in replay or runtime. Follow the delayed path.
- Sandbox findings need a real isolation break, not mere tile-to-tile reachability.
- If a bug depends on compiler behavior, reproduce with GCC, not Clang.

## Proof Expectations

Valid reports need a runnable PoC. The PoC should:
- build and run against the in-scope branch
- show the actual impact, not just reachability
- be self-contained with reproducible steps
- state the attacker model and controlled inputs

Useful local anchors:
- `contrib/test/run_test_vectors.sh`
- fuzzers and tests near the target subsystem
- local cluster docs under `doc/`
- `audit/SCOPE.md`
- `audit/PLAN.md`

Accepted contest harness targets mentioned by Immunefi:
- `instr_execute`
- `txn_execute`
- `elf_loader`
- `vm_interp`
- `vm_syscall_execute`
- `shred_parse`
- `pack_compute_budget`

## Report Template

Write findings as:
1. sink and vulnerable operation
2. attacker-controlled source
3. missing or bypassed invariant
4. exact path from source to impact
5. why the impact matches Immunefi severity
6. reproduction steps and PoC artifact

If you cannot show exploitability or contest impact, downgrade it to an insight or keep digging.
