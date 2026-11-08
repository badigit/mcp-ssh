import { homedir } from 'node:os';
import { join } from 'node:path';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import type { BackgroundTask, TaskStatus } from './types.js';

export function shQuote(value: unknown) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

const TASK_ROOT = '$HOME/.mcp-ssh/tasks';

// How long a finished task is kept without anyone asking for it — on the host
// and in the local registry alike, so neither side outlives the other and
// leaves orphans behind. Explicit remove/prune is the normal path; this is the
// floor under it, for the caller who never comes back.
const TASK_RETENTION_DAYS = 7;
const TASK_RETENTION_MS = TASK_RETENTION_DAYS * 24 * 3600 * 1000;
// A burst of tasks can outrun the age limit, so cap the finished ones too.
const TASK_MAX_FINISHED = 200;

// A task whose timestamp is missing or unparseable counts as infinitely old:
// left as NaN it would compare as older than nothing and outlive every real
// task. Finished entries we cannot date are exactly the ones worth dropping.
export function taskStartedAt(task: Partial<BackgroundTask> | undefined) {
  return Date.parse(task?.startedAt ?? '') || 0;
}

export function taskPaths(taskId: string, root = TASK_ROOT) {
  return {
    logPath: `${root}/${taskId}.log`,
    exitPath: `${root}/${taskId}.exit`,
    pgidPath: `${root}/${taskId}.pgid`
  };
}

export function buildTaskStartScript({ taskId, command, root = TASK_ROOT }: { taskId: string; command: string; root?: string }) {
  const { logPath, exitPath, pgidPath } = taskPaths(taskId, root);
  return [
    'set +e',
    `__mcp_root=${root}`,
    'mkdir -p "$__mcp_root" 2>/dev/null',
    // Sweep task files nobody came back for. Keyed on the exit file, so a task
    // that is still running is never touched, however long it runs.
    `find "$__mcp_root" -maxdepth 1 -name '*.exit' -mtime +${TASK_RETENTION_DAYS} 2>/dev/null | ` +
      'while read -r __mcp_old; do rm -f "${__mcp_old%.exit}".log "${__mcp_old%.exit}".exit "${__mcp_old%.exit}".pgid; done 2>/dev/null',
    // The command travels as a positional argument, never spliced into this
    // script's text, so it cannot break out of the wrapper that records the
    // exit code. `eval` is what makes it a shell command rather than an argv.
    `__mcp_cmd=${shQuote(command)}`,
    // `eval` runs in a subshell: a command ending in `exit N` must terminate
    // the command, not the wrapper that still has to record the exit code.
    `setsid "\${SHELL:-/bin/sh}" -c 'ps -o pgid= -p $$ | tr -d " " > "$2"; ( eval "$1" ); printf "%s\\n" "$?" > "$3"' _ "$__mcp_cmd" "${pgidPath}" "${exitPath}" > "${logPath}" 2>&1 < /dev/null &`,
    // Printed synchronously — no sleep, nothing to race against.
    `printf '%s\\n' '__MCP_TASK_STARTED=${taskId}'`
  ].join('\n');
}

export function parseTaskHandshake(stdout: string, taskId: string) {
  return (stdout || '').includes(`__MCP_TASK_STARTED=${taskId}`);
}

export function buildTaskStatusScript({ exitPath, pgidPath }: Pick<BackgroundTask, "exitPath" | "pgidPath">) {
  return [
    'set +e',
    // The exit file is the source of truth: if it exists the task finished,
    // regardless of what any process table says.
    `if [ -r "${exitPath}" ]; then printf '__MCP_TASK_EXIT=%s\\n' "$(cat "${exitPath}" | tr -d ' \\n')"`,
    `elif [ -r "${pgidPath}" ] && kill -0 -- -"$(cat "${pgidPath}" | tr -d ' \\n')" 2>/dev/null; then printf '%s\\n' '__MCP_TASK_RUNNING=true'`,
    `else printf '%s\\n' '__MCP_TASK_RUNNING=false'; fi`
  ].join('\n');
}

export function parseTaskStatus(stdout: string): TaskStatus {
  const text = stdout || '';
  // A stop writes its marker where the wrapper would have written an exit code,
  // so a task we killed stays distinguishable from one that chose to exit.
  const stopped = /__MCP_TASK_EXIT=stopped:(\d+)/.exec(text);
  if (stopped) return { state: 'stopped', exitCode: Number(stopped[1]) };
  const exit = /__MCP_TASK_EXIT=(-?\d+)/.exec(text);
  if (exit) return { state: 'exited', exitCode: Number(exit[1]) };
  if (text.includes('__MCP_TASK_RUNNING=true')) return { state: 'running' };
  return { state: 'unknown' };
}

export function buildTaskStopScript({ pgidPath, exitPath }: Pick<BackgroundTask, "exitPath" | "pgidPath">) {
  return [
    'set +e',
    `__mcp_pgid=$(cat "${pgidPath}" 2>/dev/null | tr -d ' \\n')`,
    // Never signal an empty group: `kill -- -` would hit an unintended target.
    `if [ -z "$__mcp_pgid" ]; then printf '%s\\n' '__MCP_TASK_STOPPED=unknown'; exit 0; fi`,
    // Shell convention: 128 + signal number. Which one we ended up needing says
    // whether the task went down cleanly.
    '__mcp_sig=143',
    'kill -TERM -- -"$__mcp_pgid" 2>/dev/null',
    'sleep 1',
    'if kill -0 -- -"$__mcp_pgid" 2>/dev/null; then kill -KILL -- -"$__mcp_pgid" 2>/dev/null; __mcp_sig=137; sleep 1; fi',
    `if kill -0 -- -"$__mcp_pgid" 2>/dev/null; then printf '%s\\n' '__MCP_TASK_STOPPED=false'; else`,
    // A killed task never reaches the wrapper that records its exit code, so
    // nothing would mark it as finished: status would read `unknown` forever and
    // the retention sweep, which keys on this file, would never reclaim it.
    // Skipped if the task finished on its own first — that code is the real one.
    `if [ ! -r "${exitPath}" ]; then printf 'stopped:%s\\n' "$__mcp_sig" > "${exitPath}"; fi`,
    `printf '%s\\n' '__MCP_TASK_STOPPED=true'; fi`
  ].join('\n');
}

export function buildTaskLogsScript(logPath: string, offset: unknown = 0, limit: unknown = 128 * 1024) {
  const skip = Math.max(0, Number(offset) || 0);
  const count = Math.min(2 * 1024 * 1024, Math.max(1, Number(limit) || 1));
  return [
    'set +e',
    `[ -r "${logPath}" ] || exit 0`,
    `printf '__MCP_TASK_SIZE=%s\\n' "$(wc -c < "${logPath}" | tr -d ' ')"`,
    // base64 so arbitrary bytes survive the ssh round trip intact.
    `dd if="${logPath}" bs=1 skip=${skip} count=${count} 2>/dev/null | base64 | tr -d '\\n' | sed 's/^/__MCP_TASK_LOG=/'`
  ].join('\n');
}

// Deleting the files of a task that is still running would orphan the process
// and destroy the only record of its output. The liveness check and the removal
// therefore live in one script: nothing can start between them, so a task the
// host reports as purged was provably not running at that moment.
export function buildTaskPurgeScript(taskIds: string[], root = TASK_ROOT) {
  const lines = ['set +e'];
  for (const taskId of taskIds) {
    const { logPath, exitPath, pgidPath } = taskPaths(taskId, root);
    lines.push(
      // No exit file plus a live process group means the task is still working.
      `if [ ! -r "${exitPath}" ] && [ -r "${pgidPath}" ] && kill -0 -- -"$(cat "${pgidPath}" 2>/dev/null | tr -d ' \\n')" 2>/dev/null; then`,
      `printf '%s\\n' '__MCP_TASK_BUSY=${taskId}'`,
      `else rm -f "${logPath}" "${exitPath}" "${pgidPath}"; printf '%s\\n' '__MCP_TASK_PURGED=${taskId}'; fi`
    );
  }
  return lines.join('\n');
}

export function parseTaskPurge(stdout: string) {
  const text = stdout || '';
  const collect = (re: RegExp) => [...text.matchAll(re)].map(m => m[1]!);
  return {
    purged: collect(/__MCP_TASK_PURGED=(\S+)/g),
    busy: collect(/__MCP_TASK_BUSY=(\S+)/g)
  };
}

export function parseTaskLogs(stdout: string) {
  const text = stdout || '';
  const size = Number((/__MCP_TASK_SIZE=(\d+)/.exec(text) ?? [])[1] || 0);
  const encoded = (/__MCP_TASK_LOG=([A-Za-z0-9+/=]*)/.exec(text) ?? [])[1] || '';
  return { size, content: encoded ? Buffer.from(encoded, 'base64').toString('utf8') : '' };
}

// Local registry of remote tasks. Holds only pointers (host + remote paths);
// the authoritative state always lives on the remote host.
export class TaskStore {
  path: string;
  constructor(path = join(homedir(), '.mcp-ssh', 'tasks.json')) {
    this.path = path;
  }

  async _load(): Promise<Record<string, BackgroundTask>> {
    try {
      return (JSON.parse(await readFile(this.path, 'utf-8')) as Record<string, BackgroundTask> | null) ?? {};
    } catch {
      // Missing or half-written registry must not brick every later call.
      return {};
    }
  }

  async _save(all: Record<string, BackgroundTask>) {
    try { await mkdir(join(this.path, '..'), { recursive: true }); } catch { /* already there */ }
    await writeFile(this.path, JSON.stringify(all, null, 2), 'utf-8');
  }

  async list() {
    return Object.values(await this._load());
  }

  async get(taskId: string) {
    return (await this._load())[taskId] ?? null;
  }

  // Drops finished tasks nobody pruned: those past the retention window, and
  // the oldest beyond the cap. A task that still claims to be running is never
  // dropped on age alone — its entry is the only handle left on it.
  _gc(all: Record<string, BackgroundTask>) {
    const finished = Object.values(all)
      .filter(task => task.state && task.state !== 'running')
      .sort((a, b) => taskStartedAt(b) - taskStartedAt(a));

    const cutoff = Date.now() - TASK_RETENTION_MS;
    const doomed = finished.filter(
      (task, index) => index >= TASK_MAX_FINISHED || taskStartedAt(task) < cutoff
    );
    for (const task of doomed) Reflect.deleteProperty(all, task.taskId);
    return all;
  }

  async add(task: BackgroundTask) {
    const all = this._gc(await this._load());
    all[task.taskId] = task;
    await this._save(all);
    return task;
  }

  async update(taskId: string, patch: Partial<BackgroundTask>) {
    const all = await this._load();
    const merged = { ...(all[taskId] ?? { taskId } as BackgroundTask), ...patch };
    all[taskId] = merged;
    await this._save(all);
    return merged;
  }

  // Returns the ids that were present, so callers can tell the difference
  // between "deleted" and "was never here".
  async remove(taskIds: string | string[]) {
    const ids = Array.isArray(taskIds) ? taskIds : [taskIds];
    const all = await this._load();
    const removed = ids.filter(id => Object.hasOwn(all, id));
    if (!removed.length) return [];
    for (const id of removed) Reflect.deleteProperty(all, id);
    await this._save(all);
    return removed;
  }
}
