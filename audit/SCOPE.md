# Firedancer V1 Audit Competition Scope

Fetched on 2026-05-04 from:
- https://immunefi.com/audit-competition/firedancer-v1-audit-comp/information/
- https://immunefi.com/audit-competition/firedancer-v1-audit-comp/scope/

## In Scope

Primary in-scope asset:
- `Firedancer v1.0 branch (firedancer binary and all reachable code)`

Deployment target:
- Solana mainnet

Directory reference called out by Immunefi:
- `src/app/firedancer/` - binary entry point, topology, CLI
- `src/ballet/` - cryptography
- `src/choreo/` - consensus
- `src/disco/` - shared tiles
- `src/discof/` - full Firedancer tiles
- `src/flamenco/` - runtime, accounts DB API, sBPF VM, bank, program cache
- `src/funk/` - in-memory fork-aware database
- `src/vinyl/` - persistent storage database
- `src/tango/` - IPC, shared memory messaging
- `src/util/` - core utilities, sandbox, tile runtime
- `src/waltz/` - networking

## Out of Scope Notes

Immunefi explicitly calls out these areas as out of scope:
- `firedancer-dev` development binary and tool
- Frankendancer code reachable only from `fdctl` or `fddev`
- development scripts, tools, and CI environment
- Solana protocol bugs
- social engineering or phishing attacks
- test files and test-only code unless they reveal a production vulnerability
- tile-to-tile attacks using a compromised-tile attacker model
- issues based only on `TODO` or `FIXME` comments

## Proof of Concept Requirement

A runnable PoC is required for all severities. The PoC must:
- build and run against the in-scope branch
- demonstrate real impact such as crash, corruption, or bank hash mismatch
- be self-contained with reproducible steps
- state the attacker model and controlled inputs

Accepted harness targets mentioned by Immunefi:
- `instr_execute`
- `txn_execute`
- `elf_loader`
- `vm_interp`
- `vm_syscall_execute`
- `shred_parse`
- `pack_compute_budget`

## Critical

- Any bug leading to loss of funds or acceptance of forged/invalid signatures
- Key compromise or exfiltration exploit chain
- Runtime conformance bugs leading to loss of funds
- Infinite mint: any bug allowing unauthorized token creation

## High

- Bank hash mismatch or consensus bug causing all Firedancer validators to fork from the network
- Any sandbox escape, excluding tile-to-tile attacks
- Accounts database corruption enabling delayed loss of funds
- Arbitrary write primitives in execution (`execle` and `execrp`) tiles
- Remotely triggerable liveness failure affecting the entire cluster at once, where all Firedancer validators crash simultaneously

## Medium

- Any bug leading Firedancer v1.0 to produce an invalid block or skip its leader slot
- Remotely triggerable crash or liveness failure for leader validators
