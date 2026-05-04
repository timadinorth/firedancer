# Firedancer Architecture

This note describes the architecture of the in-scope `firedancer` validator as it is assembled by `src/app/firedancer/`. It is written for auditing, so it focuses on execution boundaries, shared state, and consensus-critical dataflow rather than operator usage.

## Scope

- This document is about the full Firedancer validator reachable from the `firedancer` binary.
- It does not describe Frankendancer-only behavior except where the repo layout makes that distinction necessary.
- Audit scope and severity mapping are in `audit/SCOPE.md`.

## Top-Level Model

Firedancer is assembled as a topology of isolated worker units called tiles.

- `src/app/firedancer/main.c` is the binary entrypoint.
- `src/app/firedancer/topology.c` builds the validator graph with `fd_topob_*` helpers.
- `src/disco/topo/fd_topo.h` defines the topology objects: workspaces, links, tiles, and shared objects.

The core runtime model is:

1. Create named shared-memory workspaces.
2. Create links inside those workspaces for tile-to-tile message passing.
3. Create tiles and pin them to configured CPUs.
4. Attach shared objects to tiles in read-only or read-write mode.
5. Run tiles under restrictive sandbox and seccomp policies.

## Execution and Memory Model

### Workspaces

A workspace is a Firedancer shared-memory arena backed by hugetlbfs pages. Workspaces are used for both message links and long-lived shared state. Important workspaces include:

- per-tile or per-pipeline workspaces like `quic`, `verify`, `replay`, `execle`, `execrp`, `tower`
- link workspaces like `quic_verify`, `verify_dedup`, `replay_execrp`, `pack_execle`
- state workspaces like `funk`, `banks`, `progcache`, `txncache`, `store`, `rnonce`

### Links

A link is a single-producer, one-or-more-consumer channel built around:

- an `mcache` for metadata and sequencing
- optionally a `dcache` for fragment payloads
- `fseq` credit tracking for reliable flow-controlled consumers

`src/disco/stem/fd_stem.h` shows the common publish path. Internal state/control links are usually reliable. Some high-rate ingress links are intentionally unreliable so the system can drop load instead of backpressuring the network edge.

### Tiles

A tile is the unit of execution in the topology. Each tile has:

- zero or more input links
- zero or more output links
- a metrics object
- optional access to shared objects in RO or RW mode
- a tile-specific seccomp policy in many subsystems

In practice, tiles are the main isolation boundary inside the validator.

## Major Shared State

These shared objects matter most for audit work:

- `funk` in `src/funk/`: in-memory fork-aware database that tracks records and fork transactions
- `banks` in `src/flamenco/runtime/`: slot/fork-specific bank state for execution and replay
- `accdb` in `src/flamenco/accdb/`: accounts database API and cache layer
- `vinyl` in `src/vinyl/`: persistent storage backing for account data when not running in-memory-only
- `progcache` in `src/flamenco/progcache/`: fork-aware concurrent cache of loaded and validated programs
- `txncache`: transaction/status cache shared by replay and execution tiles
- `store` in `src/disco/store/`: shred/FEC-related storage used by replay and shredding paths
- `fec_sets` and `reasm` in `src/discof/reasm/`: reconstruction of slot/FEC order before replay
- signing and nonce-related objects such as `rnonce_ss`

Topology attachments in `src/app/firedancer/topology.c` make the ownership pattern clear:

- replay has RW access to most consensus state
- `execrp` and `execle` have RW access to execution state
- tower and resolv are often RO readers of shared state
- RPC and GUI are observational readers where enabled

## Core Pipelines

### 1. Network Ingress and Egress

Main networking code lives under:

- `src/disco/net/`
- `src/disco/quic/`
- `src/waltz/`
- `src/discof/gossip/`
- `src/discof/repair/`
- `src/discof/txsend/`

The topology creates ingress links such as:

- `net_gossvf`
- `net_shred`
- `net_repair`
- `net_txsend`
- `net_quic`

High-level role split:

- `gossvf` and `gossip` handle cluster gossip and peer/state propagation
- `repair` requests and serves missing data
- `quic` accepts TPU traffic for leader-side transaction intake
- `txsend` sends outgoing transactions and votes
- `sign` services multiple tiles that need signatures

### 2. Follower / Replay Pipeline

This is the path that turns incoming shreds and repaired data into executed slots and consensus updates.

Main tiles:

- `gossip`
- `repair`
- `replay`
- `execrp`
- `tower`
- `txsend`

Main dataflow:

```text
network/gossip/repair/genesis/snapshots
  -> replay
  -> execrp
  -> replay
  -> tower / txsend / rpc / gui
```

More precisely:

- replay consumes repaired data, genesis output, gossip output, tower output, txsend output, snapshot manifests, and leader feedback
- replay publishes `replay_out`, `replay_epoch`, and `replay_execrp`
- `execrp` executes replay-scheduled transactions against runtime/banks/accdb and returns completion messages to replay through `execrp_replay`
- `tower` consumes replay, gossip, and shred outputs to maintain consensus state and vote decisions
- `txsend` consumes replay epoch and tower outputs to send transactions/votes outward

`src/discof/replay/fd_replay_tile.h` is especially important. Replay is tightly coupled to reassembly and bank provisioning:

- it assigns banks to FEC chains
- advances roots
- prunes dead branches
- feeds repair when data must be retried
- mediates execution scheduling and finalized slot publication

### 3. Leader / Block Production Pipeline

This path is enabled when block production is enabled in config.

Main tiles:

- `quic`
- `verify`
- `dedup`
- `resolv`
- `pack`
- `execle`
- `poh`
- `shred`
- `sign`

Main dataflow:

```text
QUIC ingress
  -> verify
  -> dedup
  -> resolv
  -> pack
  -> execle
  -> poh
  -> shred
  -> sign
  -> network
```

Important details:

- `verify` validates and parses incoming transactions
- `dedup` removes duplicates
- `resolv` resolves account-related execution context and fans out to both `pack` and `replay`
- `pack` schedules transactions into microblocks and manages account locking / packing decisions
- `execle` executes leader microblocks against runtime, accdb, banks, progcache, and txncache
- `poh` serializes committed execution into Proof of History order
- `shred` converts leader output into shreds for network broadcast
- `sign` provides signatures for shreds and other signed outputs

There is a feedback loop here:

- `pack` publishes to both `execle` and `poh`
- `execle` can publish consumed-CU feedback back to `pack`
- `poh` publishes back into `replay`
- `tower` also consumes shred output

This is one of the most consensus-critical parts of the system because it couples scheduling, execution, PoH ordering, and shred emission.

### 4. Snapshot and Genesis Restore Pipeline

These tiles bootstrap state before normal replay:

- `genesi`
- `snapct`
- `snapld`
- `snapdc`
- `snapin`
- optional vinyl/lthash helpers such as `snapwm`, `snapwh`, `snapwr`, `snaplh`, `snaplv`, `snapla`, `snapls`

High-level role split:

- `genesi` builds initial state from genesis
- snapshot tiles load, decode, verify, and import snapshot state
- `snapin` produces the manifest/state handoff that replay consumes

This path is security-relevant because snapshot data is large, externally sourced, and capable of seeding long-lived validator state before normal replay begins.

## Runtime, VM, and Storage Roles

### Runtime and VM

`src/flamenco/runtime/fd_runtime.h` describes execution as a deterministic state machine:

- input: parsed transaction plus execution context
- state: bank, accounts database, status cache, program cache, account pool
- output: `fd_txn_out_t`, which is later committed or canceled

Execution is split into:

- prepare and execute
- commit if committable
- cancel otherwise

The sBPF VM and syscall surface live under `src/flamenco/vm/`.

### Accounts and Fork State

The runtime depends heavily on:

- `funk` for fork-aware record/version management
- `accdb` for account reads/writes and cache behavior
- `banks` for slot-scoped runtime state

`src/flamenco/accdb/fd_accdb_sync.h` is a useful audit clue: `fd_accdb_close_rw` publishes writes before propagation is necessarily visible to other threads, so synchronization and publication order are first-class concerns.

### Program Cache

`src/flamenco/progcache/README.md` describes progcache as:

- fork-aware
- thread-concurrent
- fixed-size
- shared by execution tiles and replay
- protected by locking and reclamation rules

That makes it a high-value target for correctness, deadlock, and lifetime bugs.

### Reassembly and Store

`src/discof/reasm/fd_reasm.h` shows that replayed block data is reconstructed as a forest of FEC sets:

- parent-before-child delivery within a fork
- partial ordering across forks
- explicit handling of skips and equivocation
- close coupling with replay’s bank assignment and eviction logic

This is the bridge between raw network shred data and consensus/runtime state.

## Supporting Services

These are not the main consensus engine, but they are part of the reachable system:

- `metric` and `diag`: telemetry and diagnostics
- `gui`: live visualization and inspection
- `rpc`: external query surface
- `plugin`: extension hook tile
- `ipecho`: networking helper
- `solcap` / `shredcap`: capture and observability helpers
- optional `bundle` path for block-engine / bundle traffic

These tiles often observe many internal links and can widen the external attack surface even when they do not own consensus state.

## Trust Boundaries and Audit Implications

### External Untrusted Inputs

The main external trust boundaries are:

- gossip traffic
- repair traffic
- QUIC/TPU transaction traffic
- snapshot and genesis files
- RPC and GUI input parsing
- bundle / block-engine input if enabled

### Internal High-Value Boundaries

The highest-value internal boundaries are:

- shared-memory links between tiles
- shared RO/RW objects such as `funk`, `banks`, `accdb`, `progcache`, `txncache`, `store`
- the sign tile and identity/authority key material paths
- the sandbox boundary around tile runtimes

### Reliability Model

The topology deliberately mixes:

- unreliable links at the packet-ingress edge, where dropping is acceptable
- reliable flow-controlled links for internal control and state propagation

Audits should not treat packet loss at unreliable links as a bug by itself. The interesting bugs are state divergence, unsafe memory access, invariant breakage, bad publication ordering, or incorrect handling of dropped/duplicated work.

## Audit Hotspots by Layer

- `src/app/firedancer/`: topology, config, binary assembly
- `src/disco/` and `src/discof/`: tile orchestration and validator pipeline glue
- `src/flamenco/runtime/`, `src/flamenco/vm/`, `src/flamenco/progcache/`: execution and conformance
- `src/flamenco/accdb/`, `src/funk/`, `src/vinyl/`: persistent and fork-aware state
- `src/discof/replay/`, `src/discof/reasm/`, `src/choreo/`, `src/discof/tower/`: replay and consensus
- `src/disco/quic/`, `src/waltz/`, `src/discof/gossip/`, `src/discof/repair/`: network-facing parsers and state machines
- `src/util/sandbox/`: isolation boundary

## Files Used For This Note

- `src/app/firedancer/main.c`
- `src/app/firedancer/topology.h`
- `src/app/firedancer/topology.c`
- `src/disco/topo/fd_topo.h`
- `src/disco/stem/fd_stem.h`
- `src/disco/tiles.h`
- `src/discof/fd_startup.c`
- `src/discof/replay/fd_replay_tile.h`
- `src/discof/reasm/fd_reasm.h`
- `src/flamenco/runtime/fd_runtime.h`
- `src/flamenco/accdb/fd_accdb_sync.h`
- `src/flamenco/progcache/README.md`
- `src/funk/fd_funk.h`
