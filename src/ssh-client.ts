/**
 * All SSH operations. Uses the system's native `ssh`/`scp` binaries rather than
 * a JavaScript SSH library, so every option in the user's ~/.ssh/config applies.
 *
 * Security invariants (see CLAUDE.md → Threat Model):
 * - No shell, ever. spawn/execFile run with shell:false and an argv array, so
 *   nothing in a tool argument can reach a local shell.
 * - Every hostAlias passes _assertSafeHostAlias() (strict whitelist) and
 *   _assertKnownHostAlias() (must exist in the user's config or known_hosts).
 * - Every invocation carries `--` to terminate option parsing.
 */
import { spawn as nodeSpawn, execFile } from 'node:child_process';
import type { ChildProcess, SpawnOptions } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { TaskStore, taskPaths, taskStartedAt, buildTaskStartScript, parseTaskHandshake, buildTaskStatusScript, parseTaskStatus, buildTaskStopScript, buildTaskLogsScript, parseTaskLogs, buildTaskPurgeScript, parseTaskPurge } from './tasks.js';
import type { AdhocSpec, AdhocHostInfo, SafeHostInfo, ConnectionOptions, BackgroundTask, BackgroundTaskOptions, PurgeResult, TransferFailure } from './types.js';
import { promisify } from 'node:util';
import { realpathSync, readlinkSync, mkdtempSync, rmSync } from 'node:fs';
import { writeFile, chmod } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join, resolve, sep, dirname, basename } from 'node:path';

import { SSHConfigParser } from './ssh-config-parser.js';
import { hostMatchesAlias } from './config-values.js';
import { debugLog, isWindows, isCaseSensitiveFs, SSH_BIN, SCP_BIN } from './platform.js';
import type {
  BatchResult,
  CommandResult,
  ConnectivityResult,
  HostInfo,
  SpawnEnv,
} from './types.js';

const execFileAsync = promisify(execFile);

const MAX_OUTPUT_SIZE = 10 * 1024 * 1024; // 10MB limit
const DEFAULT_TIMEOUT = 30000;
/** Upper bound when following a symlink chain, so a link loop cannot hang the check. */
const STRICT_HOST_KEY_CHECKING = ['-o', 'StrictHostKeyChecking=accept-new'];

type SpawnFn = (command: string, args: readonly string[], options: SpawnOptions) => ChildProcess;
type ExecFileAsyncFn = (
  file: string,
  args: readonly string[],
  options: Record<string, unknown>,
) => Promise<{ stdout: string; stderr: string }>;

export class SSHClient {
  configParser: SSHConfigParser;
  taskStore = new TaskStore();
  /** Injection points for tests — production always uses the real ones. */
  _spawn: SpawnFn;
  _execFileAsync: ExecFileAsyncFn;
  private _askpassScript: string | null = null;

  constructor() {
    this.configParser = new SSHConfigParser();
    this._spawn = nodeSpawn;
    this._execFileAsync = execFileAsync;
  }

  async listKnownHosts(): Promise<HostInfo[]> {
    return this.configParser.getAllKnownHosts();
  }

  /**
   * Strict whitelist. Two threats this defends against:
   *   1. ssh/scp option injection via leading '-' (e.g. -oProxyCommand=…),
   *      which would execute arbitrary commands LOCALLY on this machine.
   *   2. Shell-metacharacter injection, as defence in depth behind shell:false.
   * Allowed: alphanumerics, '.', '_', '-', ':', '@'. Must not start with '-'.
   *
   * Do not weaken this without understanding the implications — see the
   * CHANGELOG entry for 1.3.5.
   */
  _assertSafeHostAlias(hostAlias: unknown): asserts hostAlias is string {
    if (typeof hostAlias !== 'string' || hostAlias.length === 0) {
      throw new Error('hostAlias must be a non-empty string');
    }
    if (!/^[A-Za-z0-9_.@:][A-Za-z0-9._@:-]*$/.test(hostAlias)) {
      throw new Error(
        `Invalid hostAlias: must match [A-Za-z0-9._@:-] and not start with '-'`
      );
    }
  }

  /**
   * Reject a `localPath` that scp would treat as a *second remote endpoint*.
   *
   * scp decides "remote or local" by looking for a colon that is not preceded by
   * a path separator: `host:/path` and `scp://user@host:port//path` are remote,
   * `/tmp/a:b` is local. A `localPath` of `scp://attacker/…` therefore makes scp
   * open a second SSH connection and copy the file to a host that was never in
   * the user's config — bypassing _assertKnownHostAlias entirely, which is the
   * product's primary trust boundary. `--` does not help: it stops option
   * parsing, not remote-spec interpretation.
   *
   * Reported as GHSA-gpr2-2wqr-7rgp.
   */
  _assertLocalPath(localPath: unknown): asserts localPath is string {
    if (typeof localPath !== 'string' || localPath.length === 0) {
      throw new Error('localPath must be a non-empty string');
    }

    const colon = localPath.indexOf(':');
    if (colon === -1) return;

    // On Windows a leading drive letter is a local path, and scp there treats it
    // as one. Everywhere else `C:\…` really would be parsed as host `C`.
    if (isWindows && /^[A-Za-z]:[\\/]/.test(localPath)) return;

    // A separator before the colon makes it a path, exactly as scp decides it.
    // Backslash only counts as a separator on Windows.
    const separator = localPath.search(isWindows ? /[/\\]/ : /\//);
    if (separator !== -1 && separator < colon) return;

    throw new Error(
      'Invalid localPath: must be a local filesystem path, not an scp remote spec ' +
      '(a colon before the first path separator makes scp copy to another host)'
    );
  }

  /**
   * Reject a download destination inside the user's SSH directory.
   *
   * `~/.ssh/config` is the trust base of this whole product: it *is* the host
   * allowlist `_assertKnownHostAlias()` checks against, and ssh executes any
   * `ProxyCommand` it finds there **locally, through /bin/sh**. So a write into
   * that directory turns the by-design remote RCE of `runRemoteCommand` into
   * local RCE:
   *
   *   1. runRemoteCommand(anyConfiguredHost, 'cat > /tmp/x …ProxyCommand…')
   *   2. downloadFile(thatHost, '/tmp/x', '~/.ssh/config')
   *   3. runRemoteCommand('evil', 'true')   → ProxyCommand runs on this machine
   *
   * Step 3 is not theoretical — it was verified against the real ssh binary.
   * That contradicts the "local RCE must stay impossible" invariant, so the
   * write is refused even though path arguments are otherwise unsandboxed.
   *
   * This guards **integrity, not confidentiality**: `uploadFile` merely *reads*
   * localPath and is deliberately not covered. Blocking reads would be theatre
   * (every other secret on the disk stays readable by design) and would break
   * backing up one's own config to a configured host.
   */
  _assertNotSshDirectory(localPath: string): void {
    const sshDir = join(homedir(), '.ssh');
    // resolve() makes it absolute and collapses '..'; realpath resolves symlinks
    // on whatever part of the path already exists, so a link into ~/.ssh cannot
    // launder the destination.
    // Expand a leading '~' for the check only. We spawn without a shell, so scp
    // would take it literally — but a caller writing '~/.ssh/config' clearly
    // means the SSH directory, and treating it as a plain directory name would
    // let the guard be sidestepped by spelling.
    const expanded = /^~(?=$|[\\/])/.test(localPath)
      ? join(homedir(), localPath.slice(1))
      : localPath;
    const target = realpathish(resolve(expanded));
    const dir = realpathish(sshDir);

    // macOS and Windows are case-insensitive and realpath does not canonicalise
    // case there, so compare case-insensitively on those platforms.
    const norm = (p: string): string => (isCaseSensitiveFs ? p : p.toLowerCase());
    const t = norm(target);
    const d = norm(dir);

    if (t === d || t.startsWith(d + sep)) {
      throw new Error(
        `Invalid localPath: refusing to write inside SSH directory ${sshDir}. That directory defines ` +
        `which hosts may be reached and can make ssh execute commands locally.`
      );
    }
  }

  /** The LLM may only reach hosts the user has actually configured. */
  async _assertKnownHostAlias(hostAlias: string): Promise<void> {
    const cleanAlias = stripUserPrefix(hostAlias);
    const knownHosts = await this.configParser.getAllKnownHosts();
    const isKnown = knownHosts.some(
      host => hostMatchesAlias(host, hostAlias) || hostMatchesAlias(host, cleanAlias)
    );
    if (!isKnown) {
      throw new Error(
        `Unknown hostAlias: ${hostAlias} is not defined in ~/.ssh/config or ~/.ssh/known_hosts`
      );
    }
  }

  async getPasswordForHost(hostAlias: string): Promise<string | null> {
    const cleanAlias = stripUserPrefix(hostAlias);
    const hosts = await this.configParser.processIncludeDirectives(this.configParser.configPath);
    const host = hosts.find(h => hostMatchesAlias(h, cleanAlias));
    return host?._password ?? null;
  }

  /**
   * Write the SSH_ASKPASS helper that echoes the password from the environment.
   * A batch file on Windows, a mode-700 shell script on POSIX.
   */
  async getAskpassScript(): Promise<string> {
    if (this._askpassScript) return this._askpassScript;

    // A predictable path in a shared temp dir is a hijack target: ssh executes
    // this helper with MCP_SSH_PASS in its environment, so whoever controls the
    // file controls what runs and can capture the password. mkdtemp gives an
    // unpredictable, 0700 directory; `flag: 'wx'` makes the create exclusive so
    // an existing file or symlink is never followed.
    const dir = mkdtempSync(join(tmpdir(), 'mcp-ssh-'));
    let scriptPath: string;
    try {
      if (isWindows) {
        scriptPath = join(dir, `mcp-ssh-askpass-${process.pid}.cmd`);
        await writeFile(scriptPath, '@echo off\r\necho %MCP_SSH_PASS%\r\n', { flag: 'wx' });
      } else {
        scriptPath = join(dir, `mcp-ssh-askpass-${process.pid}.sh`);
        await writeFile(scriptPath, '#!/bin/sh\necho "$MCP_SSH_PASS"\n', { flag: 'wx', mode: 0o700 });
        await chmod(scriptPath, 0o700);
      }
    } catch (error) {
      rmSync(dir, { recursive: true, force: true });
      throw error;
    }
    this._askpassScript = scriptPath;

    const cleanup = (): void => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // Already gone, or never written — nothing to clean up.
      }
    };
    process.on('exit', cleanup);
    process.on('SIGINT', () => {
      cleanup();
      process.exit(130);
    });
    process.on('SIGTERM', () => {
      cleanup();
      process.exit(143);
    });

    return scriptPath;
  }

  async _askpassEnvForPassword(password: string): Promise<SpawnEnv | null> {
    if (!password) return null;
    const askpassScript = await this.getAskpassScript();
    return {
      ...process.env,
      MCP_SSH_PASS: password,
      SSH_ASKPASS: askpassScript,
      // `force` tells OpenSSH to use the askpass helper even without a GUI/TTY.
      // Avoid injecting a fake DISPLAY value here; that's a POSIX/X11 assumption
      // and can break platform-specific behavior, especially on Windows.
      SSH_ASKPASS_REQUIRE: 'force'
    };
  }

  /** Environment carrying the password, or null when the host uses key auth. */
  async buildSpawnEnv(hostAlias: string): Promise<SpawnEnv | null> {
    const password = await this.getPasswordForHost(hostAlias);
    if (!password) return null;

    // Refuse to use a password out of a world-readable config
    if (this.configParser._configsWithPasswords) {
      for (const configPath of this.configParser._configsWithPasswords) {
        await this.configParser.checkFilePermissions(configPath);
      }
    }

    const askpassScript = await this.getAskpassScript();
    return {
      ...process.env,
      MCP_SSH_PASS: password,
      SSH_ASKPASS: askpassScript,
      // `force` tells OpenSSH to use the askpass helper even without a GUI/TTY.
      // Avoid injecting a fake DISPLAY value here; that's a POSIX/X11 assumption
      // and can break platform-specific behavior, especially on Windows.
      SSH_ASKPASS_REQUIRE: 'force',
    };
  }

  _resolveAdhoc(spec: Partial<Record<keyof AdhocSpec, unknown>> | undefined) {
    if (spec?.host == null || spec.host === '') return null;
    const { host, user, port, identityFile, proxyJump, password } = spec;

    // Reuse the strict alias whitelist: it also fits IPv4/IPv6 literals and
    // hostnames, blocks a leading '-' (ssh option injection) and cmd.exe
    // metacharacters. This is the one field spliced next to the '--' target.
    this._assertSafeHostAlias(host);

    let target = host;
    if (user != null && user !== '') {
      if (typeof user !== 'string') throw new Error('Invalid ad-hoc user: must be a string');
      const u = user;
      if (!/^[A-Za-z0-9_.@-]+$/.test(u) || u.startsWith('-')) {
        throw new Error(`Invalid ad-hoc user: must match [A-Za-z0-9_.@-] and not start with '-'`);
      }
      target = `${u}@${host}`;
    }

    const sshArgs: string[] = [];
    const scpArgs: string[] = [];
    if (port != null && port !== '') {
      const p = Number(port);
      if (!Number.isInteger(p) || p < 1 || p > 65535) {
        throw new Error('Invalid ad-hoc port: expected an integer 1-65535');
      }
      sshArgs.push('-p', String(p));
      scpArgs.push('-P', String(p)); // scp spells the port flag with a capital P
    }
    // identityFile and proxyJump are passed as the argv token right after their
    // flag, so ssh consumes them as option-arguments regardless of content — a
    // leading '-' there is a value, not a new option, and there is no local shell.
    if (identityFile != null && identityFile !== '') {
      if (typeof identityFile !== 'string') throw new Error('ad-hoc identityFile must be a string');
      sshArgs.push('-i', identityFile);
      scpArgs.push('-i', identityFile);
    }
    if (proxyJump != null && proxyJump !== '') {
      if (typeof proxyJump !== 'string') throw new Error('ad-hoc proxyJump must be a string');
      // Same hardening as host/user, and not optional: unlike -i, ssh folds -J
      // into an internally generated ProxyCommand that it runs through the shell
      // (/bin/sh -c), interpolating each hop into that string. Shell
      // metacharacters here can therefore mean LOCAL command execution on the
      // machine running ssh (cf. CVE-2023-51385), which our threat model forbids.
      // A jump spec is a comma-separated list of [user@]host[:port]; whitelist
      // each hop with the same charset as an alias and forbid a leading '-'.
      for (const hop of proxyJump.split(',')) {
        if (!/^[A-Za-z0-9_.@:][A-Za-z0-9._@:-]*$/.test(hop)) {
          throw new Error(
            `Invalid ad-hoc proxyJump hop '${hop}': must match [A-Za-z0-9._@:-] and not start with '-'`
          );
        }
      }
      sshArgs.push('-J', proxyJump);
      scpArgs.push('-J', proxyJump);
    }

    if (password != null && typeof password !== 'string') throw new Error('Invalid ad-hoc password: must be a string');
    return {
      target,
      sshArgs,
      scpArgs,
      password: typeof password === 'string' ? password || null : null
    };
  }

  // Resolve a target for ssh/scp. Ad-hoc hosts (options.adhoc.host set) skip the
  // known-host gate by design — the caller supplied explicit connection details.
  // The alias path keeps both the safety whitelist and the known-host gate.
  async _prepareConnection(hostAlias: string | null | undefined, options: ConnectionOptions = {}) {
    const adhoc = this._resolveAdhoc(options.adhoc);
    if (adhoc) {
      const env = adhoc.password ? await this._askpassEnvForPassword(adhoc.password) : null;
      return { target: adhoc.target, sshArgs: adhoc.sshArgs, scpArgs: adhoc.scpArgs, env, isAdhoc: true };
    }
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);
    const env = await this.buildSpawnEnv(hostAlias);
    return { target: hostAlias, sshArgs: [], scpArgs: [], env, isAdhoc: false };
  }

  // The connection options a stored task must replay to reach its host again.
  // Alias tasks have no `connection`, so this yields the plain alias path.
  _taskConnOptions(task: BackgroundTask) {
    return { adhoc: task.connection };
  }

  async startBackgroundTask(hostAlias: string | undefined, command: string, options: ConnectionOptions = {}) {
    const adhoc = this._resolveAdhoc(options.adhoc);
    if (adhoc) {
      // A detached task is polled later, after this connection is gone. That
      // reconnect needs the credential — and persisting a password to
      // ~/.mcp-ssh/tasks.json (which `backgroundTask list` hands back to the
      // LLM) would leak it. Key/agent/config auth carries no such secret, so
      // require it for ad-hoc detach.
      if (adhoc.password) {
        throw new Error(
          'Detached background tasks are not supported over ad-hoc password auth. ' +
          'Use identityFile (or a configured host alias) so the task can be polled ' +
          'later without persisting a secret.'
        );
      }
    } else {
      this._assertSafeHostAlias(hostAlias);
      await this._assertKnownHostAlias(hostAlias);
    }

    const taskId = randomBytes(6).toString('hex');
    const paths = taskPaths(taskId);
    const script = buildTaskStartScript({ taskId, command });

    const result = await this.runRemoteCommand(hostAlias, script, { timeout: options.timeout || 30000, adhoc: options.adhoc });
    if (!parseTaskHandshake(result.stdout, taskId)) {
      // Nothing is registered in this case: a task we cannot address is worse
      // than no task, since it would linger in the registry forever.
      throw new Error(
        `Host did not confirm task start (handshake missing). exit=${result.code}. ` +
        `stderr: ${(result.stderr || '').trim().slice(0, 500)}`
      );
    }

    const task: BackgroundTask = {
      taskId,
      // Alias tasks reconnect by alias; ad-hoc tasks replay `connection`. The
      // stored connection carries no password (ad-hoc password + detach is
      // refused above), so it is safe to expose via `backgroundTask list`.
      hostAlias: adhoc ? null : hostAlias,
      connection: adhoc
        ? {
            host: options.adhoc!.host,
            user: options.adhoc!.user ?? undefined,
            port: options.adhoc!.port ?? undefined,
            identityFile: options.adhoc!.identityFile ?? undefined,
            proxyJump: options.adhoc!.proxyJump ?? undefined
          }
        : undefined,
      command,
      ...paths,
      state: 'running',
      startedAt: new Date().toISOString()
    };
    await this.taskStore.add(task);
    return task;
  }

  // A task id is spliced into the purge script, so it must not be able to carry
  // shell syntax. Ours are hex, but the registry is a file on disk that another
  // process could have mangled.
  _assertSafeTaskId(taskId: string) {
    if (!/^[A-Za-z0-9_-]+$/.test(taskId || '')) {
      throw new Error(`Refusing to use unsafe task id '${taskId}'.`);
    }
  }

  // Deletes remote files and registry entries for tasks the host confirms are
  // no longer running. The host is the source of truth: an entry may say
  // 'running' long after the command finished, and only the host can tell.
  async _purgeTasks(tasks: BackgroundTask[], { keepRemote = false } = {}): Promise<PurgeResult> {
    const removed: string[] = [];
    const kept: PurgeResult["kept"] = [];

    const valid: BackgroundTask[] = [];
    for (const task of tasks) {
      // One corrupt entry must not block the cleanup of everything else.
      try {
        this._assertSafeTaskId(task.taskId);
        valid.push(task);
      } catch {
        kept.push({ taskId: task.taskId, reason: 'invalid-id' });
      }
    }

    if (keepRemote) {
      const stale = valid.filter(t => t.state !== 'running');
      valid.filter(t => t.state === 'running').forEach(t => kept.push({ taskId: t.taskId, reason: 'running' }));
      if (stale.length) removed.push(...await this.taskStore.remove(stale.map(t => t.taskId)));
      return { removed, kept };
    }

    // Group by the connection, not just the alias: ad-hoc tasks have no alias
    // but still share a host, and each group is purged in one ssh call.
    const byHost = new Map<string, BackgroundTask[]>();
    for (const task of valid) {
      const key = task.connection ? JSON.stringify(task.connection) : `alias:${task.hostAlias}`;
      if (!byHost.has(key)) byHost.set(key, []);
      byHost.get(key)!.push(task);
    }

    for (const [, hostTasks] of byHost) {
      const ids = hostTasks.map(t => t.taskId);
      const result = await this.runRemoteCommand(hostTasks[0]!.hostAlias, buildTaskPurgeScript(ids), this._taskConnOptions(hostTasks[0]!));
      const { purged, busy } = parseTaskPurge(result.stdout);

      if (purged.length) removed.push(...await this.taskStore.remove(purged));
      for (const id of ids) {
        if (purged.includes(id)) continue;
        // Silence is not consent: if the host never answered for a task, its
        // files are still there and the entry is the only handle left on them.
        kept.push({ taskId: id, reason: busy.includes(id) ? 'running' : 'host-unreachable' });
      }
    }

    return { removed, kept };
  }

  async backgroundTask({
    action = 'list', taskId, offset = 0, limit = 128 * 1024,
    keepRemote = false, olderThanHours
  }: BackgroundTaskOptions = {}) {
    if (action === 'list') return { tasks: await this.taskStore.list() };

    if (action === 'prune') {
      let tasks = await this.taskStore.list();
      if (olderThanHours != null && olderThanHours > 0) {
        const cutoff = Date.now() - olderThanHours * 3600 * 1000;
        tasks = tasks.filter(t => taskStartedAt(t) < cutoff);
      }
      if (!tasks.length) return { removed: [], kept: [] };
      return this._purgeTasks(tasks, { keepRemote });
    }

    if (!['status', 'logs', 'stop', 'remove'].includes(action)) {
      throw new Error(`Unsupported task action '${action}'. Use list, status, logs, stop, remove or prune.`);
    }

    const task = taskId ? await this.taskStore.get(taskId) : null;
    if (!task) throw new Error(`Task '${taskId}' not found in the local registry.`);

    if (action === 'remove') {
      this._assertSafeTaskId(task.taskId);
      if (keepRemote && task.state === 'running') {
        throw new Error(
          `Task '${taskId}' is still running. Stop it first, or drop keepRemote so the host can be asked.`
        );
      }
      return this._purgeTasks([task], { keepRemote });
    }

    if (action === 'status') {
      const result = await this.runRemoteCommand(task.hostAlias, buildTaskStatusScript(task), this._taskConnOptions(task));
      const status = parseTaskStatus(result.stdout);
      return { task: await this.taskStore.update(task.taskId, status) };
    }

    if (action === 'logs') {
      const result = await this.runRemoteCommand(task.hostAlias, buildTaskLogsScript(task.logPath, offset, limit), this._taskConnOptions(task));
      const { size, content } = parseTaskLogs(result.stdout);
      return { taskId, offset, size, content, truncated: offset + Buffer.byteLength(content) < size };
    }

    const result = await this.runRemoteCommand(task.hostAlias, buildTaskStopScript(task), this._taskConnOptions(task));
    const stopped = /__MCP_TASK_STOPPED=(true|unknown)/.test(result.stdout);
    return { task: await this.taskStore.update(task.taskId, { state: stopped ? 'stopped' : 'running' }) };
  }

  async runRemoteCommand(
    hostAlias: string | null | undefined,
    command: string,
    options: ConnectionOptions = {},
  ): Promise<CommandResult> {
    const conn = await this._prepareConnection(hostAlias, options);
    // `||`, not `??`: a zero timeout means "not specified" here, as it does in
    // the tool dispatcher. With `??` a caller passing 0 would get an immediate
    // SIGTERM instead of the default.
    const timeout = options.timeout || DEFAULT_TIMEOUT;

    debugLog(`Executing: ssh ${hostAlias} ${command}\n`);

    const passwordEnv = conn.env;

    return new Promise<CommandResult>((resolve) => {
      const spawnOptions: SpawnOptions = {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        // shell:false is critical: with a shell the args would be re-parsed and
        // metacharacters in `command` could lead to local command injection. We
        // rely on resolveExecutable() to find ssh.exe on Windows, so PATH lookup
        // is not needed here.
        shell: false,
      };
      if (passwordEnv) {
        spawnOptions.env = passwordEnv;
        if (!isWindows) {
          // setsid needed on some systems so SSH uses SSH_ASKPASS instead of tty
          spawnOptions.detached = true;
        }
      }

      const child = this._spawn(
        SSH_BIN,
        [...STRICT_HOST_KEY_CHECKING, ...conn.sshArgs, '--', conn.target, command],
        spawnOptions,
      );

      let stdout = '';
      let stderr = '';
      let killed = false;
      let stdoutTruncated = false;
      let stderrTruncated = false;

      const timer = setTimeout(() => {
        killed = true;
        child.kill('SIGTERM');
      }, timeout);

      child.stdout?.on('data', (data: Buffer) => {
        if (stdout.length < MAX_OUTPUT_SIZE) {
          stdout += data.toString();
        } else if (!stdoutTruncated) {
          stdoutTruncated = true;
          stdout += '\n[Output truncated - exceeded 10MB limit]';
        }
      });

      child.stderr?.on('data', (data: Buffer) => {
        if (stderr.length < MAX_OUTPUT_SIZE) {
          stderr += data.toString();
        } else if (!stderrTruncated) {
          stderrTruncated = true;
          stderr += '\n[Stderr truncated - exceeded 10MB limit]';
        }
      });

      child.on('close', (code: number | null) => {
        clearTimeout(timer);
        resolve({
          stdout,
          stderr: killed ? `${stderr}\n[Command timed out]` : stderr,
          code: killed ? 124 : (code ?? 0),
        });
      });

      child.on('error', (error: Error) => {
        clearTimeout(timer);
        debugLog(`Error executing command on ${hostAlias}: ${error.message}\n`);
        resolve({ stdout, stderr: error.message, code: 1 });
      });
    });
  }

  async getHostInfo(hostAlias: string | undefined, options: ConnectionOptions = {}): Promise<SafeHostInfo | AdhocHostInfo | null> {
    // For an ad-hoc host there is no config entry to read; echo back the
    // supplied connection shape (never the password — only passwordAuth: true).
    const adhoc = this._resolveAdhoc(options.adhoc);
    if (adhoc) {
      const a = options.adhoc!;
      return {
        host: a.host,
        user: a.user ?? null,
        port: a.port ?? null,
        identityFile: a.identityFile ?? null,
        proxyJump: a.proxyJump ?? null,
        ...(adhoc.password ? { passwordAuth: true } : {}),
        source: 'ad-hoc'
      };
    }
    const hosts = await this.configParser.processIncludeDirectives(this.configParser.configPath);
    const host = hosts.find(host => hostMatchesAlias(host, hostAlias)) ?? null;
    if (host) {
      // Never expose password to the LLM
      const { _password, ...safeHost } = host;
      if (_password) safeHost['passwordAuth'] = true;
      return safeHost;
    }
    return null;
  }


  async checkConnectivity(hostAlias: string | undefined, options: ConnectionOptions = {}): Promise<ConnectivityResult> {
    try {
      const result = await this.runRemoteCommand(hostAlias, 'echo connected', options);
      const connected = result.code === 0 && result.stdout.trim() === 'connected';

      return {
        connected,
        message: connected ? 'Connection successful' : 'Connection failed',
      };
    } catch (error) {
      const message = errorMessage(error);
      debugLog(`Connectivity error with ${hostAlias}: ${message}\n`);
      return { connected: false, message };
    }
  }

  async uploadFile(hostAlias: string | undefined, localPath: string, remotePath: string, options: ConnectionOptions = {}) {
    try {
      this._assertLocalPath(localPath);
      const conn = await this._prepareConnection(hostAlias, options);
      debugLog(`Executing: scp ${localPath} ${conn.target}:${remotePath}\n`);

      const spawnOptions: Record<string, unknown> = { timeout: 60000, windowsHide: true, shell: false };
      if (conn.env) spawnOptions['env'] = conn.env;

      await this._execFileAsync(SCP_BIN, ['-o', 'StrictHostKeyChecking=accept-new', ...conn.scpArgs, '--', localPath, `${scpHost(conn.target)}:${remotePath}`], spawnOptions);
      return true;
    } catch (error) {
      const failure = fileTransferFailure(error);
      debugLog(`File upload failed: ${failure.code}\n`);
      options.onError?.(failure);
      return false;
    }
  }

  async downloadFile(hostAlias: string | undefined, remotePath: string, localPath: string, options: ConnectionOptions = {}) {
    try {
      this._assertLocalPath(localPath);
      this._assertNotSshDirectory(localPath);
      const conn = await this._prepareConnection(hostAlias, options);
      debugLog(`Executing: scp ${conn.target}:${remotePath} ${localPath}\n`);

      const spawnOptions: Record<string, unknown> = { timeout: 60000, windowsHide: true, shell: false };
      if (conn.env) spawnOptions['env'] = conn.env;

      await this._execFileAsync(SCP_BIN, ['-o', 'StrictHostKeyChecking=accept-new', ...conn.scpArgs, '--', `${scpHost(conn.target)}:${remotePath}`, localPath], spawnOptions);
      return true;
    } catch (error) {
      const failure = fileTransferFailure(error);
      debugLog(`File download failed: ${failure.code}\n`);
      options.onError?.(failure);
      return false;
    }
  }

  async runCommandBatch(hostAlias: string | undefined, commands: string[], options: ConnectionOptions = {}): Promise<BatchResult> {
    try {
      const results: CommandResult[] = [];
      let success = true;

      for (const command of commands) {
        const result = await this.runRemoteCommand(hostAlias, command, options);
        results.push(result);

        // Keep going on failure — the caller sees every result
        if (result.code !== 0) success = false;
      }

      return { results, success };
    } catch (error) {
      const message = errorMessage(error);
      debugLog(`Error during batch execution on ${hostAlias}: ${message}\n`);
      return {
        results: [{ stdout: '', stderr: message, code: 1 }],
        success: false,
      };
    }
  }
}

/**
 * Resolve a path as far as it exists, so a symlink cannot hide the real target.
 * The final component of a download destination usually does not exist yet, so
 * walk up to the nearest existing ancestor and resolve that.
 */
function realpathish(path: string, symlinkHops = 0): string {
  const absolute = resolve(path);
  if (symlinkHops >= 16) throw new Error('Invalid localPath: too many symbolic links');
  try {
    return realpathSync(absolute);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  try {
    const target = readlinkSync(absolute);
    return realpathish(resolve(dirname(absolute), target), symlinkHops + 1);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT' && (error as NodeJS.ErrnoException).code !== 'EINVAL') throw error;
  }
  const parent = dirname(absolute);
  if (parent === absolute) return absolute;
  return join(realpathish(parent, symlinkHops), basename(absolute));
}

function scpHost(hostAlias: string): string {
  const at = hostAlias.lastIndexOf('@');
  return at === -1
    ? `[${hostAlias}]`
    : `${hostAlias.slice(0, at + 1)}[${hostAlias.slice(at + 1)}]`;
}

/** "test@ssh-test" -> "ssh-test" */
function stripUserPrefix(hostAlias: string): string {
  const at = hostAlias.lastIndexOf('@');
  return at === -1 ? hostAlias : hostAlias.slice(at + 1);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function fileTransferFailure(error: unknown): TransferFailure {
  const failure = error as { stderr?: string; killed?: boolean; code?: string | number; message?: string };
  const stderr = failure.stderr || '';
  let code = 'transfer_failed';
  let message = 'File transfer failed. Check SSH connectivity and server file-transfer support.';
  if (failure.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
    code = 'output_limit';
    message = 'File transfer exceeded the subprocess output limit.';
  } else if (failure.killed || failure.code === 'ETIMEDOUT') {
    code = 'timeout';
    message = 'File transfer exceeded the 60-second deadline.';
  } else if (failure.code === 'ENOENT') {
    code = 'not_found';
    message = 'The scp executable or a local path was not found.';
  } else if (/Permission denied \(/i.test(stderr)) {
    code = 'authentication_failed';
    message = 'SSH authentication was rejected. Check the remote user and authentication method.';
  } else if (failure.code === 'EACCES' || /permission denied|access is denied/i.test(stderr)) {
    code = 'permission_denied';
    message = 'File access was denied. Check the remote user, parent-directory access and file permissions.';
  } else if (/no such file|not a directory/i.test(stderr)) {
    code = 'not_found';
    message = 'A transfer file or parent directory was not found.';
  } else if (/subsystem request failed|sftp.*not found/i.test(stderr)) {
    code = 'sftp_unavailable';
    message = 'The SSH server rejected the SFTP subsystem.';
  } else if (/host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(stderr)) {
    code = 'host_key_failed';
    message = 'SSH host-key verification failed.';
  } else if (/^Invalid |^localPath must |^Unknown hostAlias:|^hostAlias must /.test(failure.message || '')) {
    code = 'invalid_arguments';
    message = 'Transfer arguments were rejected. Check the target and local path. Downloads into the SSH directory are refused.';
  }
  return { code, message, ...(typeof failure.code === 'number' ? { exitCode: failure.code } : {}) };
}
