# Firedancer High-Severity Audit Plan

Scope reference: [audit/SCOPE.md](./SCOPE.md)

This plan follows the `code-audit` method: start from dangerous sinks, trace the controlling operand backward to an attacker-controlled source, and keep only findings with a defensible High-severity impact chain.

## High Targets

From `audit/SCOPE.md`, the High targets are:
- bank hash mismatch or consensus bug causing all Firedancer validators to fork from the network
- sandbox escape, excluding tile-to-tile attacks
- accounts database corruption enabling delayed loss of funds
- arbitrary write primitives in execution (`execle` and `execrp`) tiles
- remotely triggerable cluster-wide liveness failure affecting all Firedancer validators

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
