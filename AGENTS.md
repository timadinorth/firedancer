# Audit File Map

## `audit/SCOPE.md`

This is the canonical local summary of the Immunefi contest scope for this repository.

Use it for:
- in-scope versus out-of-scope boundaries
- severity classes
- attacker-model limits
- PoC expectations

Read this before claiming severity. If a finding depends on a contested assumption, compare it against this file first.

## `audit/NOTES.md`

This is the durable audit memory.

Use it to preserve information that another agent should not have to rediscover, especially:
- subsystem facts that affect reasoning
- trust boundaries and invariants
- partial results that are not yet submission-ready
- dead ends and why they failed
- “do not retry this exact path” explanations
- code-level observations that change the likely exploit path

Important properties:
- this file is not ranked
- sections are organized by subsystem, not by urgency
- it is acceptable for the file to contain mixed certainty levels, as long as they are labeled clearly

Status tags in this file matter:
- `finding`: strong local bug or evidence-backed candidate
- `hypothesis`: plausible lead that still needs proof
- `falsified`: investigated and currently weak, blocked, or non-viable
- `todo`: narrow follow-up work worth resuming later
- `note`: durable context or invariant

Good `audit/NOTES.md` entries explain not only what was checked, but why the result matters. This is especially important for failed paths, because the main value is preventing duplicate work.

## `audit/ARCHITECTURE.md`

This is the subsystem and dataflow map for the Firedancer validator.

Use it for:
- understanding tile roles
- locating shared state objects
- following major runtime and replay flows
- orienting before diving into a new subsystem

This file is background context, not a task queue and not a results log.

## `share/codex.md`

This is the current task handoff file for external agents.

Use it for:
- the presently assigned narrow audit task
- concrete starting points for delegated work

This file is intentionally narrower and more temporary than `audit/PLAN.md`. It should not be treated as the long-term knowledge base for the audit.
