#!/usr/bin/env python3

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import glob
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SHARE_ROOT = Path("/home/ubuntu/share")
DEFAULT_PLAN = REPO_ROOT / "audit" / "PLAN.md"
DEFAULT_SCOPE = REPO_ROOT / "audit" / "SCOPE.md"
DEFAULT_NOTES = REPO_ROOT / "audit" / "NOTES.md"
DEFAULT_ARCH = REPO_ROOT / "audit" / "ARCHITECTURE.md"
SYNC_RELATIVE_PATHS = [
    Path("AGENTS.md"),
    Path("audit/SCOPE.md"),
    Path("audit/PLAN.md"),
    Path("audit/NOTES.md"),
    Path("audit/ARCHITECTURE.md"),
    Path(".agents/skills/code-audit/SKILL.md"),
    Path(".claude/skills/code-audit/SKILL.md"),
]


@dataclasses.dataclass
class Agent:
    name: str
    worktree: Path
    runner: Path


@dataclasses.dataclass
class Task:
    ordinal: int
    title: str
    body: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one or more parallel Firedancer audit iterations across worker worktrees."
    )
    parser.add_argument("--share-root", type=Path, default=DEFAULT_SHARE_ROOT)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--cycles", type=int, default=1)
    parser.add_argument("--workers", default="all", help="Comma-separated worker names or 'all'")
    parser.add_argument("--task-index", type=int, help="1-based task index from audit/PLAN.md")
    parser.add_argument(
        "--advance",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Advance to the next ranked task after a successful iteration",
    )
    parser.add_argument("--timeout-minutes", type=int, default=90)
    parser.add_argument(
        "--skip-self-research",
        action="store_true",
        help="Do not run a local codex self-research pass while workers run",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Prepare prompts and manifests but do not launch worker or judge processes",
    )
    parser.add_argument(
        "--agent-glob",
        default="/home/ubuntu/firedancer-*/run-*",
        help="Glob used to discover worker launcher scripts",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        help="Optional state file path. Defaults to <share-root>/.audit-cycle-state.json",
    )
    return parser.parse_args()


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"last_iteration": 0, "next_task_index": 1}
    return json.loads(path.read_text())


def save_state(path: Path, state: dict) -> None:
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def discover_agents(pattern: str) -> list[Agent]:
    agents: list[Agent] = []
    for runner_str in sorted(glob.glob(pattern)):
        runner = Path(runner_str)
        if not runner.is_file():
            continue
        name = runner.name
        if not name.startswith("run-"):
            continue
        agent_name = name[4:]
        agents.append(Agent(name=agent_name, worktree=runner.parent, runner=runner))
    return agents


def select_agents(agents: Iterable[Agent], worker_spec: str) -> list[Agent]:
    agents = list(agents)
    if worker_spec == "all":
        return agents
    wanted = {item.strip() for item in worker_spec.split(",") if item.strip()}
    selected = [agent for agent in agents if agent.name in wanted]
    missing = sorted(wanted - {agent.name for agent in selected})
    if missing:
        raise SystemExit(f"Unknown worker(s): {', '.join(missing)}")
    return selected


def parse_ranked_tasks(plan_path: Path) -> list[Task]:
    text = plan_path.read_text()
    lines = text.splitlines()
    tasks: list[Task] = []
    in_ranked = False
    cur_ordinal: int | None = None
    cur_title: str | None = None
    cur_lines: list[str] = []

    for line in lines:
        if line.strip() == "## Ranked Queue":
            in_ranked = True
            continue
        if not in_ranked:
            continue
        if line.startswith("## "):
            break
        match = re.match(r"^###\s+(\d+)\.\s+(.+)$", line)
        if match:
            if cur_ordinal is not None and cur_title is not None:
                tasks.append(Task(cur_ordinal, cur_title, "\n".join(cur_lines).strip()))
            cur_ordinal = int(match.group(1))
            cur_title = match.group(2).strip()
            cur_lines = []
            continue
        if cur_ordinal is not None:
            cur_lines.append(line)

    if cur_ordinal is not None and cur_title is not None:
        tasks.append(Task(cur_ordinal, cur_title, "\n".join(cur_lines).strip()))

    if not tasks:
        raise SystemExit(f"No ranked tasks found in {plan_path}")
    return tasks


def build_task_snapshot(task: Task, share_root: Path) -> str:
    return f"""# Iteration Task

Generated: {now_utc()}
Source: {DEFAULT_PLAN}
Task index: {task.ordinal}
Task title: {task.title}

## Task Block

{task.body}

## Required Reading

- {DEFAULT_SCOPE}
- {DEFAULT_PLAN}
- {DEFAULT_NOTES}
- {DEFAULT_ARCH}

## Share-Folder Rule

- Read this task file.
- Do not read any other worker report under `{share_root}` unless you are the final judge.
- Write only your assigned output file.
"""


def build_worker_prompt(task_file: Path, output_file: Path, share_root: Path, agent: Agent) -> str:
    return f"""You are an audit worker running inside {agent.worktree}.

Task:
- Read {task_file}
- Execute the assigned audit task
- Save your final report to {output_file}

Hard rules:
- Do not overwrite the task file
- Do not read any other worker report under {share_root}
- You may read audit docs in the repository
- Use firedancer-stateq MCP when helpful, then confirm important claims in source
- Stay within production Firedancer-reachable code
- Revert temporary PoC edits before finishing

Read first:
- {task_file}
- {DEFAULT_SCOPE}
- {DEFAULT_PLAN}
- {DEFAULT_NOTES}
- {DEFAULT_ARCH}

Required report structure:
1. Scope and attacker model
2. Files and functions reviewed
3. Hypotheses tested
4. Evidence chains
5. Findings ranked by severity
6. Falsified leads
7. Best next hypothesis

Report rules:
- Be concrete
- Include file:line references
- Separate proven findings from hypotheses
- If nothing reaches High, say so explicitly
- If the best result is Medium, explain exactly why
- Save the report to {output_file}
- Exit after writing the report
"""


def build_self_research_prompt(task_file: Path, output_file: Path, share_root: Path) -> str:
    return f"""Investigate the current audit task independently in /home/ubuntu/firedancer.

Read:
- {task_file}
- {DEFAULT_SCOPE}
- {DEFAULT_PLAN}
- {DEFAULT_NOTES}
- {DEFAULT_ARCH}

Hard rules:
- Do not read any worker report under {share_root}
- Do not update audit docs in this pass
- Save your notes to {output_file}

Required sections:
1. Main angle investigated
2. Source evidence
3. New hypotheses
4. Dead ends
5. What the judge should look for in worker reports
"""


def build_judge_prompt(
    task_file: Path,
    workers_dir: Path,
    research_file: Path | None,
    output_file: Path,
    iteration_report_copy: Path,
) -> str:
    research_line = f"- {research_file}" if research_file else "- no local research file"
    return f"""You are the iteration judge in /home/ubuntu/firedancer.

Read:
- {task_file}
- every worker report in {workers_dir}
- {DEFAULT_SCOPE}
- {DEFAULT_PLAN}
- {DEFAULT_NOTES}
- {DEFAULT_ARCH}
{research_line}

Task:
- review all worker outputs
- rank them by signal quality and audit value
- identify the strongest new ideas
- identify weak or duplicate ideas
- produce the iteration report

Write the same markdown report to both:
- {output_file}
- {iteration_report_copy}

Required report structure:
1. Iteration summary
2. Worker ranking
3. Strongest new hypotheses or findings
4. Weak, duplicate, or falsified paths
5. Recommended next action
6. Suggested updates for PLAN or NOTES

Requirements:
- include concrete file references where possible
- distinguish High-capable ideas from Medium-only ideas
- be explicit if the iteration produced no credible escalation path
"""


def run_process(command: list[str], cwd: Path, log_path: Path) -> subprocess.Popen[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("w", encoding="utf-8")
    return subprocess.Popen(
        command,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
    )


def terminate_process(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def wait_all(processes: dict[str, subprocess.Popen[str]], timeout_seconds: int) -> dict[str, int | None]:
    deadline = time.time() + timeout_seconds
    still_running = set(processes)
    while still_running:
        for name in list(still_running):
            if processes[name].poll() is not None:
                still_running.remove(name)
        if not still_running:
            break
        if time.time() >= deadline:
            for name in still_running:
                processes[name].terminate()
            time.sleep(3)
            for name in still_running:
                if processes[name].poll() is None:
                    processes[name].kill()
            break
        time.sleep(2)
    return {name: proc.poll() for name, proc in processes.items()}


def wait_for_worker_reports(
    processes: dict[str, subprocess.Popen[str]],
    report_paths: dict[str, Path],
    timeout_seconds: int,
) -> dict[str, int | None]:
    deadline = time.time() + timeout_seconds
    completed: set[str] = set()

    while True:
        for name, report_path in report_paths.items():
            if report_path.exists() and report_path.stat().st_size > 0:
                completed.add(name)

        if completed == set(report_paths):
            break

        dead_without_report = [
            name for name, proc in processes.items()
            if proc.poll() is not None and name not in completed
        ]
        if dead_without_report:
            break

        if time.time() >= deadline:
            break
        time.sleep(2)

    for proc in processes.values():
        terminate_process(proc)

    return {name: proc.poll() for name, proc in processes.items()}


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def pick_task(tasks: list[Task], state: dict, override_index: int | None) -> Task:
    if override_index is not None:
        for task in tasks:
            if task.ordinal == override_index:
                return task
        raise SystemExit(f"Task index {override_index} not found in audit/PLAN.md")
    wanted = state.get("next_task_index", 1)
    for task in tasks:
        if task.ordinal == wanted:
            return task
    raise SystemExit(f"State points to task index {wanted}, but it was not found in audit/PLAN.md")


def next_iteration_number(state: dict) -> int:
    return int(state.get("last_iteration", 0)) + 1


def next_task_after(tasks: list[Task], current: Task) -> int:
    ordinals = [task.ordinal for task in tasks]
    try:
        idx = ordinals.index(current.ordinal)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if idx + 1 < len(tasks):
        return tasks[idx + 1].ordinal
    return current.ordinal


def sync_control_files(agent_worktree: Path) -> None:
    for relative_path in SYNC_RELATIVE_PATHS:
        source = REPO_ROOT / relative_path
        if not source.exists():
            continue
        target = agent_worktree / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def main() -> int:
    args = parse_args()
    share_root = args.share_root
    state_file = args.state_file or (share_root / ".audit-cycle-state.json")
    timeout_seconds = args.timeout_minutes * 60

    share_root.mkdir(parents=True, exist_ok=True)
    state = load_state(state_file)
    tasks = parse_ranked_tasks(args.plan)
    agents = select_agents(discover_agents(args.agent_glob), args.workers)

    if not agents:
        raise SystemExit("No worker launchers found")

    for cycle in range(args.cycles):
        task = pick_task(tasks, state, args.task_index)
        iteration = next_iteration_number(state)
        iter_dir = share_root / "iterations" / f"{iteration:03d}"
        if iter_dir.exists():
            raise SystemExit(f"Iteration directory already exists: {iter_dir}")

        workers_dir = iter_dir / "workers"
        logs_dir = iter_dir / "logs"
        task_file = iter_dir / "task.md"
        self_file = iter_dir / "self-research.md"
        report_copy = iter_dir / "report.md"
        final_report = share_root / f"report-{iteration:03d}.md"
        manifest = {
            "generated_at": now_utc(),
            "iteration": iteration,
            "task_index": task.ordinal,
            "task_title": task.title,
            "workers": [agent.name for agent in agents],
        }

        workers_dir.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(parents=True, exist_ok=True)
        task_file.write_text(build_task_snapshot(task, share_root), encoding="utf-8")
        (iter_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        print(f"[cycle {cycle+1}/{args.cycles}] iteration {iteration:03d}: task {task.ordinal}. {task.title}")
        print(f"[cycle {cycle+1}/{args.cycles}] workers: {', '.join(agent.name for agent in agents)}")

        if args.dry_run:
            for agent in agents:
                report_path = workers_dir / f"{agent.name}.md"
                prompt_path = iter_dir / f"prompt-{agent.name}.txt"
                prompt_path.write_text(
                    build_worker_prompt(task_file, report_path, share_root, agent),
                    encoding="utf-8",
                )
            if not args.skip_self_research:
                (iter_dir / "prompt-self.txt").write_text(
                    build_self_research_prompt(task_file, self_file, share_root),
                    encoding="utf-8",
                )
            (iter_dir / "prompt-judge.txt").write_text(
                build_judge_prompt(task_file, workers_dir, None if args.skip_self_research else self_file, final_report, report_copy),
                encoding="utf-8",
            )
            print(f"[cycle {cycle+1}/{args.cycles}] dry-run only, prompts written to {iter_dir}")
        else:
            processes: dict[str, subprocess.Popen[str]] = {}
            expected_reports: dict[str, Path] = {}

            for agent in agents:
                sync_control_files(agent.worktree)
                report_path = workers_dir / f"{agent.name}.md"
                expected_reports[agent.name] = report_path
                prompt = build_worker_prompt(task_file, report_path, share_root, agent)
                command = [str(agent.runner), "--print", prompt]
                processes[f"worker:{agent.name}"] = run_process(command, agent.worktree, logs_dir / f"{agent.name}.log")

            if not args.skip_self_research:
                command = [
                    "codex",
                    "exec",
                    "--dangerously-bypass-approvals-and-sandbox",
                    "-C",
                    str(REPO_ROOT),
                    build_self_research_prompt(task_file, self_file, share_root),
                ]
                processes["self-research"] = run_process(command, REPO_ROOT, logs_dir / "self-research.log")

            worker_processes = {name: proc for name, proc in processes.items() if name.startswith("worker:")}
            worker_reports = {
                f"worker:{agent_name}": report_path
                for agent_name, report_path in expected_reports.items()
            }
            exit_codes = wait_for_worker_reports(worker_processes, worker_reports, timeout_seconds)

            if "self-research" in processes:
                if self_file.exists():
                    research_exit = wait_for_worker_reports(
                        {"self-research": processes["self-research"]},
                        {"self-research": self_file},
                        max(timeout_seconds // 3, 1),
                    )
                else:
                    research_exit = wait_all({"self-research": processes["self-research"]}, max(timeout_seconds // 3, 1))
                exit_codes.update(research_exit)

            missing = [str(path) for path in expected_reports.values() if not path.exists()]
            if missing:
                print(f"[cycle {cycle+1}/{args.cycles}] missing worker reports:", file=sys.stderr)
                for path in missing:
                    print(f"  - {path}", file=sys.stderr)

            judge_prompt = build_judge_prompt(
                task_file=task_file,
                workers_dir=workers_dir,
                research_file=self_file if self_file.exists() else None,
                output_file=final_report,
                iteration_report_copy=report_copy,
            )
            judge_command = [
                "codex",
                "exec",
                "--dangerously-bypass-approvals-and-sandbox",
                "-C",
                str(REPO_ROOT),
                judge_prompt,
            ]
            judge_proc = run_process(judge_command, REPO_ROOT, logs_dir / "judge.log")
            judge_exit = wait_for_worker_reports(
                {"judge": judge_proc},
                {"judge": final_report},
                timeout_seconds,
            )["judge"]
            exit_codes["judge"] = judge_exit

            summary = {
                "finished_at": now_utc(),
                "iteration": iteration,
                "task_index": task.ordinal,
                "task_title": task.title,
                "exit_codes": exit_codes,
                "expected_reports": {name: str(path) for name, path in expected_reports.items()},
                "self_research": str(self_file) if self_file.exists() else None,
                "final_report": str(final_report) if final_report.exists() else None,
            }
            (iter_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            print(f"[cycle {cycle+1}/{args.cycles}] final report: {final_report}")

        state["last_iteration"] = iteration
        if args.advance:
            state["next_task_index"] = next_task_after(tasks, task)
        save_state(state_file, state)

        if args.task_index is not None:
            break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
