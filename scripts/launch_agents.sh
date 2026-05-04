#!/usr/bin/env bash

set -euo pipefail

AGENTS=(kimi glm mimo deepseek minimax)
SOURCE_BRANCH="${SOURCE_BRANCH:-audit}"
COMMIT_MESSAGE="${COMMIT_MESSAGE:-chore(audit): sync shared audit files before agent launch}"
WAIT_FOR_AGENTS=1

usage() {
  cat <<'EOF'
Usage: scripts/launch_agents.sh [--prompt-file PATH] [--agents a,b,c] [--commit-message MSG] [--no-wait]

Behavior:
- commits all current changes in the source firedancer repo once
- deletes previous top-level markdown reports from share/, except codex.md and prompt.md
- merges the source branch (default: audit) into each agent worktree
- launches each run-<agent> wrapper with the prompt from share/prompt.md
- prepends "Your name is <agent>." to the user prompt

Environment overrides:
- SOURCE_BRANCH
- COMMIT_MESSAGE

Defaults:
- prompt file: share/prompt.md
- agents: kimi,glm,mimo,deepseek,minimax
EOF
}

ROOT_DIR="$(git rev-parse --show-toplevel)"
BASE_DIR="$(dirname "$ROOT_DIR")"
PROMPT_FILE="$ROOT_DIR/share/prompt.md"
LOG_DIR="$ROOT_DIR/share/logs"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prompt-file)
      PROMPT_FILE="$2"
      shift 2
      ;;
    --agents)
      IFS=',' read -r -a AGENTS <<<"$2"
      shift 2
      ;;
    --commit-message)
      COMMIT_MESSAGE="$2"
      shift 2
      ;;
    --no-wait)
      WAIT_FOR_AGENTS=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

info() {
  printf '[launch_agents] %s\n' "$*"
}

die() {
  printf '[launch_agents] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$PROMPT_FILE" ]] || die "Prompt file not found: $PROMPT_FILE"

current_branch="$(git -C "$ROOT_DIR" branch --show-current)"
[[ "$current_branch" == "$SOURCE_BRANCH" ]] || die "Source repo must be on '$SOURCE_BRANCH' (currently '$current_branch')"
git -C "$ROOT_DIR" rev-parse --verify "$SOURCE_BRANCH" >/dev/null 2>&1 || die "Branch '$SOURCE_BRANCH' does not exist"

mkdir -p "$LOG_DIR"

prompt_template="$(<"$PROMPT_FILE")"

info "Source repo: $ROOT_DIR"
info "Prompt file: $PROMPT_FILE"
info "Agents: ${AGENTS[*]}"

git -C "$ROOT_DIR" add -A
if ! git -C "$ROOT_DIR" diff --cached --quiet; then
  info "Committing current source-repo changes on '$SOURCE_BRANCH'"
  git -C "$ROOT_DIR" commit -m "$COMMIT_MESSAGE"
else
  info "Source repo is already clean; no commit created"
fi

info "Removing previous top-level share markdown reports (preserving codex.md and prompt.md)"
find "$ROOT_DIR/share" -maxdepth 1 -type f -name '*.md' \
  ! -name 'codex.md' \
  ! -name 'prompt.md' \
  -delete

declare -A PIDS=()
declare -A LOGS=()
declare -A REPORTS=()

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

for agent in "${AGENTS[@]}"; do
  worktree="$BASE_DIR/firedancer-$agent"
  runner="$worktree/run-$agent"
  report="/home/ubuntu/share/$agent.md"
  log="$LOG_DIR/${agent}-${timestamp}.log"

  [[ -d "$worktree" ]] || die "Missing worktree: $worktree"
  [[ -x "$runner" ]] || die "Missing executable runner: $runner"

  if [[ -n "$(git -C "$worktree" status --porcelain)" ]]; then
    die "Worktree '$worktree' is dirty; commit or clean it before merge"
  fi

  info "Merging '$SOURCE_BRANCH' into '$agent' worktree"
  git -C "$worktree" merge --no-edit "$SOURCE_BRANCH"

  agent_prompt="${prompt_template//<agent_name>/$agent}"
  printf -v full_prompt 'Your name is %s.\n\n%s' "$agent" "$agent_prompt"

  info "Launching $agent (log: $log)"
  (
    cd "$worktree"
    "./run-$agent" -p -n "$agent" "$full_prompt"
  ) >"$log" 2>&1 &

  PIDS["$agent"]=$!
  LOGS["$agent"]="$log"
  REPORTS["$agent"]="$report"
done

if [[ "$WAIT_FOR_AGENTS" -eq 0 ]]; then
  info "Launched all agents in background:"
  for agent in "${AGENTS[@]}"; do
    printf '  %-8s pid=%s log=%s\n' "$agent" "${PIDS[$agent]}" "${LOGS[$agent]}"
  done
  exit 0
fi

failures=0
for agent in "${AGENTS[@]}"; do
  pid="${PIDS[$agent]}"
  log="${LOGS[$agent]}"
  report="${REPORTS[$agent]}"

  if wait "$pid"; then
    if [[ -f "$report" ]]; then
      info "$agent completed successfully (report: $report)"
    else
      info "$agent exited successfully but report is missing: $report"
      failures=$((failures+1))
    fi
  else
    info "$agent failed (see log: $log)"
    failures=$((failures+1))
  fi
done

if [[ "$failures" -gt 0 ]]; then
  die "$failures agent run(s) failed"
fi

missing_reports=0
for agent in "${AGENTS[@]}"; do
  report="${REPORTS[$agent]}"
  if [[ ! -f "$report" ]]; then
    info "Missing expected report for $agent: $report"
    missing_reports=$((missing_reports+1))
  fi
done

if [[ "$missing_reports" -gt 0 ]]; then
  die "$missing_reports expected report file(s) were not created"
fi

info "All agent runs completed"
