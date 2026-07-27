#!/usr/bin/env node

/**
 * MCP SSH Agent - A Model Context Protocol server for managing SSH connections
 * 
 * This is a simplified implementation that directly imports from specific files
 * to avoid module resolution issues.
 */

// Import required Node.js modules
import { homedir } from 'os';
import { readFile, stat, writeFile, chmod, unlink, mkdir } from 'fs/promises';
import { join } from 'path';
import { createRequire } from 'module';
import { randomBytes } from 'crypto';

// Use createRequire to work around ESM import issues
const require = createRequire(import.meta.url);

// Required libraries
const { spawn, exec, execFile } = require('child_process');
const { promisify } = require('util');
const { statSync } = require('fs');
const sshConfig = require('ssh-config');

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

const isWindows = process.platform === 'win32';

// Resolve an executable's absolute path on Windows by walking PATH and PATHEXT.
// This lets us call spawn() with shell:false on Windows — without it we would
// need shell:true to find ssh.exe/scp.exe via PATH, which would route every
// argument through cmd.exe and make characters like &, |, ^, >, " usable for
// local command injection. Returns the bare name on non-Windows (POSIX spawn
// already searches PATH safely).
function resolveExecutable(name) {
  if (!isWindows) return name;
  const pathDirs = (process.env.PATH || process.env.Path || '').split(';');
  const exts = (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';');
  for (const dir of pathDirs) {
    if (!dir) continue;
    for (const ext of exts) {
      const candidate = join(dir, name + ext);
      try {
        if (statSync(candidate).isFile()) return candidate;
      } catch {}
    }
  }
  return name + '.exe';
}

const SSH_BIN = resolveExecutable('ssh');
const SCP_BIN = resolveExecutable('scp');

// Silent mode for MCP clients - disable debug output when used as MCP server
const SILENT_MODE = process.env.MCP_SILENT === 'true' || process.argv.includes('--silent');

// Debug logging function - only outputs in non-silent mode
function debugLog(message) {
  if (!SILENT_MODE) {
    process.stderr.write(message);
  }
}

// Import MCP components using proper export paths
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { CallToolRequestSchema, ListToolsRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

// ---------------------------------------------------------------------------
// ssh-config@5 value normalization.
//
// The parser returns a plain string for a single-token value, but an array of
// token objects ({ val, separator, quoted }) as soon as a multi-value directive
// carries more than one token. Affected directives (ssh-config/lib/ssh-config.js):
//   Host, Match, ProxyCommand, SendEnv, IPQoS, CanonicalDomains,
//   GlobalKnownHostsFile, UserKnownHostsFile
// Everything downstream must go through these helpers, otherwise a multi-alias
// `Host a b` block is stored with an array where a string is expected and no
// strict comparison against it can ever match.
// ---------------------------------------------------------------------------
function configValueTokens(value) {
  if (value == null) return [];
  if (Array.isArray(value)) {
    return value
      .map(v => (v && typeof v === 'object' && 'val' in v ? v.val : String(v)))
      .filter(v => v !== '');
  }
  return [String(value)];
}

function configValueToString(value) {
  return configValueTokens(value).join(' ');
}

// True if `alias` names this host — via any of its aliases or its hostname.
function hostMatchesAlias(host, alias) {
  if (!host || !alias) return false;
  if (host.hostname === alias) return true;
  if (Array.isArray(host.aliases)) return host.aliases.includes(alias);
  return host.alias === alias;
}

// ---------------------------------------------------------------------------
// Background tasks
//
// A detached task lives entirely on the remote host: `setsid` gives it its own
// session (so it survives the ssh connection closing), stdout/stderr go to a log
// file, the exit code lands in an exit file, and the child records its own
// process group id. Locally we only keep a registry pointing at those paths —
// which is why a task survives an MCP server restart or a dropped link.
//
// The remote shell protocol is adapted from HaHas8468/mcp-ssh (MIT), with one
// change: there, the parent slept a fixed 50ms and then read a pid file written
// by the child, which races under load and can yield an empty process group.
// Here the child writes its own pgid, and liveness is derived from the exit file
// rather than from a pid the parent had to guess at.
// ---------------------------------------------------------------------------

// POSIX single-quote escaping: wrap in single quotes, and close/escape/reopen
// around any embedded single quote. Inside single quotes the shell expands
// nothing, so $(...), backticks, |, && and newlines are all inert.
function shQuote(value) {
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
function taskStartedAt(task) {
  return Date.parse(task?.startedAt) || 0;
}

function taskPaths(taskId, root = TASK_ROOT) {
  return {
    logPath: `${root}/${taskId}.log`,
    exitPath: `${root}/${taskId}.exit`,
    pgidPath: `${root}/${taskId}.pgid`
  };
}

function buildTaskStartScript({ taskId, command, root = TASK_ROOT }) {
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

function parseTaskHandshake(stdout, taskId) {
  return String(stdout || '').includes(`__MCP_TASK_STARTED=${taskId}`);
}

function buildTaskStatusScript({ exitPath, pgidPath }) {
  return [
    'set +e',
    // The exit file is the source of truth: if it exists the task finished,
    // regardless of what any process table says.
    `if [ -r "${exitPath}" ]; then printf '__MCP_TASK_EXIT=%s\\n' "$(cat "${exitPath}" | tr -d ' \\n')"`,
    `elif [ -r "${pgidPath}" ] && kill -0 -- -"$(cat "${pgidPath}" | tr -d ' \\n')" 2>/dev/null; then printf '%s\\n' '__MCP_TASK_RUNNING=true'`,
    `else printf '%s\\n' '__MCP_TASK_RUNNING=false'; fi`
  ].join('\n');
}

function parseTaskStatus(stdout) {
  const text = String(stdout || '');
  // A stop writes its marker where the wrapper would have written an exit code,
  // so a task we killed stays distinguishable from one that chose to exit.
  const stopped = text.match(/__MCP_TASK_EXIT=stopped:(\d+)/);
  if (stopped) return { state: 'stopped', exitCode: Number(stopped[1]) };
  const exit = text.match(/__MCP_TASK_EXIT=(-?\d+)/);
  if (exit) return { state: 'exited', exitCode: Number(exit[1]) };
  if (/__MCP_TASK_RUNNING=true/.test(text)) return { state: 'running' };
  return { state: 'unknown' };
}

function buildTaskStopScript({ pgidPath, exitPath }) {
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

function buildTaskLogsScript(logPath, offset = 0, limit = 128 * 1024) {
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
function buildTaskPurgeScript(taskIds, root = TASK_ROOT) {
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

function parseTaskPurge(stdout) {
  const text = String(stdout || '');
  const collect = re => [...text.matchAll(re)].map(m => m[1]);
  return {
    purged: collect(/__MCP_TASK_PURGED=(\S+)/g),
    busy: collect(/__MCP_TASK_BUSY=(\S+)/g)
  };
}

function parseTaskLogs(stdout) {
  const text = String(stdout || '');
  const size = Number((text.match(/__MCP_TASK_SIZE=(\d+)/) || [])[1] || 0);
  const encoded = (text.match(/__MCP_TASK_LOG=([A-Za-z0-9+/=]*)/) || [])[1] || '';
  return { size, content: encoded ? Buffer.from(encoded, 'base64').toString('utf8') : '' };
}

// Local registry of remote tasks. Holds only pointers (host + remote paths);
// the authoritative state always lives on the remote host.
class TaskStore {
  constructor(path = join(homedir(), '.mcp-ssh', 'tasks.json')) {
    this.path = path;
  }

  async _load() {
    try {
      return JSON.parse(await readFile(this.path, 'utf-8')) || {};
    } catch {
      // Missing or half-written registry must not brick every later call.
      return {};
    }
  }

  async _save(all) {
    try { await mkdir(join(this.path, '..'), { recursive: true }); } catch { /* already there */ }
    await writeFile(this.path, JSON.stringify(all, null, 2), 'utf-8');
  }

  async list() {
    return Object.values(await this._load());
  }

  async get(taskId) {
    return (await this._load())[taskId] || null;
  }

  // Drops finished tasks nobody pruned: those past the retention window, and
  // the oldest beyond the cap. A task that still claims to be running is never
  // dropped on age alone — its entry is the only handle left on it.
  _gc(all) {
    const finished = Object.values(all)
      .filter(task => task.state && task.state !== 'running')
      .sort((a, b) => taskStartedAt(b) - taskStartedAt(a));

    const cutoff = Date.now() - TASK_RETENTION_MS;
    const doomed = finished.filter(
      (task, index) => index >= TASK_MAX_FINISHED || taskStartedAt(task) < cutoff
    );
    for (const task of doomed) delete all[task.taskId];
    return all;
  }

  async add(task) {
    const all = this._gc(await this._load());
    all[task.taskId] = task;
    await this._save(all);
    return task;
  }

  async update(taskId, patch) {
    const all = await this._load();
    const merged = { ...(all[taskId] || { taskId }), ...patch };
    all[taskId] = merged;
    await this._save(all);
    return merged;
  }

  // Returns the ids that were present, so callers can tell the difference
  // between "deleted" and "was never here".
  async remove(taskIds) {
    const ids = Array.isArray(taskIds) ? taskIds : [taskIds];
    const all = await this._load();
    const removed = ids.filter(id => Object.hasOwn(all, id));
    if (!removed.length) return [];
    for (const id of removed) delete all[id];
    await this._save(all);
    return removed;
  }
}

// SSH Configuration Parser
class SSHConfigParser {
  constructor() {
    const homeDir = homedir();
    this.configPath = join(homeDir, '.ssh', 'config');
    this.knownHostsPath = join(homeDir, '.ssh', 'known_hosts');
  }

  async parseConfig() {
    try {
      const content = await readFile(this.configPath, 'utf-8');
      const config = sshConfig.parse(content);
      return this.extractHostsFromConfig(config, this.configPath);
    } catch (error) {
      debugLog(`Error reading SSH config: ${error.message}\n`);
      return [];
    }
  }

  async processIncludeDirectives(configPath) {
    try {
      const content = await readFile(configPath, 'utf-8');
      const config = sshConfig.parse(content);
      const hosts = [];
      
      for (const section of config) {
        if (section.param === 'Include' && section.value) {
          const includePaths = this.expandIncludePath(section.value, configPath);
          
          for (const includePath of includePaths) {
            const includeHosts = await this.processIncludeDirectives(includePath);
            hosts.push(...includeHosts);
          }
        }
      }
      
      // Add hosts from the current config file
      const currentHosts = this.extractHostsFromConfig(config, configPath);
      hosts.push(...currentHosts);
      
      return hosts;
    } catch (error) {
      debugLog(`Error processing config file ${configPath}: ${error.message}\n`);
      return [];
    }
  }

  expandIncludePath(includePath, baseConfigPath) {
    const { dirname, resolve, isAbsolute, win32 } = require('path');
    const { glob } = require('glob');
    const { existsSync } = require('fs');
    
    // Handle tilde expansion
    if (/^~(?=[\\/])/.test(includePath)) {
      includePath = includePath.replace(/^~/, homedir());
    }
    
    // Handle relative paths
    if (!isAbsolute(includePath) && !win32.isAbsolute(includePath)) {
      const baseDir = dirname(baseConfigPath);
      includePath = resolve(baseDir, includePath);
    }
    
    try {
      // Handle glob patterns
      if (includePath.includes('*') || includePath.includes('?')) {
        return glob.sync(includePath).filter(path => existsSync(path));
      } else {
        return existsSync(includePath) ? [includePath] : [];
      }
    } catch (error) {
      debugLog(`Error expanding include path ${includePath}: ${error.message}\n`);
      return [];
    }
  }

  async checkFilePermissions(filePath) {
    // Windows doesn't support Unix file permissions - skip check
    if (isWindows) return;
    try {
      const fileStat = await stat(filePath);
      const mode = fileStat.mode & 0o777;
      if (mode !== 0o600) {
        throw new Error(
          `SSH config file ${filePath} contains @password annotations but has insecure permissions (${mode.toString(8)}). ` +
          `Required: 600. Fix with: chmod 600 ${filePath}`
        );
      }
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
  }

  extractHostsFromConfig(config, configPath) {
    const hosts = [];
    let hasPasswords = false;

    for (const section of config) {
      // Skip Include directives as they are processed separately
      if (section.param === 'Include') {
        continue;
      }

      if (section.param === 'Host') {
        const aliases = configValueTokens(section.value);

        // Skip blocks that only carry defaults (`Host *`, `Host * !bastion`):
        // they are not connectable hosts. The old `section.value !== '*'` check
        // missed these because a multi-token Host value is an array, never '*'.
        if (aliases.length === 0 || aliases.every(a => a === '*' || a.startsWith('!'))) {
          continue;
        }

        const hostInfo = {
          hostname: '',
          alias: aliases[0],   // first alias — keeps the existing output shape
          aliases,             // full list — used for matching
          configFile: configPath
        };

        // Search all entries for this host
        for (const param of section.config) {
          // Parse @password annotation from comments
          if (param.type === 2 && param.content) {
            const match = param.content.match(/^#\s*@password:\s*(.+)$/);
            if (match) {
              hostInfo._password = match[1];
              hasPasswords = true;
              continue;
            }
          }

          // Safety check for undefined param
          if (!param || !param.param) {
            continue;
          }

          // Multi-token directives (ProxyCommand, SendEnv, IPQoS, …) arrive as
          // arrays of token objects; flatten so the JSON we hand back is readable.
          const value = configValueToString(param.value);

          switch (param.param.toLowerCase()) {
            case 'hostname':
              hostInfo.hostname = value;
              break;
            case 'user':
              hostInfo.user = value;
              break;
            case 'port':
              hostInfo.port = parseInt(value, 10);
              break;
            case 'identityfile':
              hostInfo.identityFile = value;
              break;
            default:
              // Store other parameters
              hostInfo[param.param.toLowerCase()] = value;
          }
        }

        // Only add hosts with complete information
        if (hostInfo.hostname) {
          hosts.push(hostInfo);
        }
      }
    }

    // Store whether this config has passwords (for permission check)
    if (hasPasswords) {
      this._configsWithPasswords = this._configsWithPasswords || new Set();
      this._configsWithPasswords.add(configPath);
    }

    return hosts;
  }

  async parseKnownHosts() {
    try {
      const content = await readFile(this.knownHostsPath, 'utf-8');
      const knownHosts = content
        .split('\n')
        .filter(line => line.trim() !== '')
        .map(line => {
          // Format: hostname[,hostname2...] key-type public-key
          const parts = line.split(' ')[0];
          return parts.split(',')[0];
        });

      return knownHosts;
    } catch (error) {
      debugLog(`Error reading known_hosts file: ${error.message}\n`);
      return [];
    }
  }

  async getAllKnownHosts() {
    // First: Get all hosts from ~/.ssh/config including Include directives (these are prioritized)
    const configHosts = await this.processIncludeDirectives(this.configPath);

    // Check file permissions for configs that contain @password annotations
    if (this._configsWithPasswords) {
      for (const configPath of this._configsWithPasswords) {
        await this.checkFilePermissions(configPath);
      }
    }

    // Second: Get hostnames from ~/.ssh/known_hosts
    const knownHostnames = await this.parseKnownHosts();

    // Create a comprehensive list starting with config hosts
    const allHosts = [...configHosts];

    // Add hosts from known_hosts that aren't already in the config
    // These will appear after the config hosts
    for (const hostname of knownHostnames) {
      if (!configHosts.some(host => hostMatchesAlias(host, hostname))) {
        allHosts.push({
          hostname: hostname,
          source: 'known_hosts'
        });
      }
    }

    // Mark config hosts for clarity
    configHosts.forEach(host => {
      host.source = 'ssh_config';
    });

    return allHosts;
  }
}

// SSH Client Implementation
class SSHClient {
  constructor() {
    this.configParser = new SSHConfigParser();
    this._askpassScript = null;
    this._spawn = spawn;
    this._execFileAsync = execFileAsync;
    this.taskStore = new TaskStore();
  }

  async listKnownHosts() {
    return await this.configParser.getAllKnownHosts();
  }

  _assertSafeHostAlias(hostAlias) {
    if (typeof hostAlias !== 'string' || hostAlias.length === 0) {
      throw new Error('hostAlias must be a non-empty string');
    }
    // Strict whitelist. Two threats this defends against:
    //   1. ssh/scp option injection via leading '-' (e.g. -oProxyCommand=…),
    //      which would execute arbitrary commands LOCALLY on this machine.
    //   2. cmd.exe metacharacter injection on Windows, where spawnOptions.shell
    //      is true and characters like &, |, ^, >, " would otherwise be
    //      interpreted by the shell before ssh.exe ever sees them.
    // Allowed: alphanumerics, '.', '_', '-', ':', '@'. Must not start with '-'.
    if (!/^[A-Za-z0-9_.@:][A-Za-z0-9._@:-]*$/.test(hostAlias)) {
      throw new Error(
        `Invalid hostAlias: must match [A-Za-z0-9._@:-] and not start with '-'`
      );
    }
  }

  async _assertKnownHostAlias(hostAlias) {
    const cleanAlias = hostAlias.includes('@') ? hostAlias.split('@').pop() : hostAlias;
    const knownHosts = await this.configParser.getAllKnownHosts();
    const isKnown = knownHosts.some((host) =>
      hostMatchesAlias(host, hostAlias) ||
      hostMatchesAlias(host, cleanAlias)
    );
    if (!isKnown) {
      throw new Error(`Unknown hostAlias: ${hostAlias} is not defined in ~/.ssh/config or ~/.ssh/known_hosts`);
    }
  }

  async getPasswordForHost(hostAlias) {
    // Strip user@ prefix if present (e.g. "test@ssh-test" -> "ssh-test")
    const cleanAlias = hostAlias.includes('@') ? hostAlias.split('@').pop() : hostAlias;
    const hosts = await this.configParser.processIncludeDirectives(this.configParser.configPath);
    const host = hosts.find(h => hostMatchesAlias(h, cleanAlias));
    return host?._password || null;
  }

  async getAskpassScript() {
    if (this._askpassScript) return this._askpassScript;

    const { tmpdir } = require('os');
    let scriptPath;
    if (isWindows) {
      scriptPath = join(tmpdir(), `mcp-ssh-askpass-${process.pid}.cmd`);
      await writeFile(scriptPath, '@echo off\r\necho %MCP_SSH_PASS%\r\n');
    } else {
      scriptPath = join(tmpdir(), `mcp-ssh-askpass-${process.pid}.sh`);
      await writeFile(scriptPath, '#!/bin/sh\necho "$MCP_SSH_PASS"\n');
      await chmod(scriptPath, 0o700);
    }
    this._askpassScript = scriptPath;

    // Clean up on exit
    const cleanup = () => { try { require('fs').unlinkSync(scriptPath); } catch {} };
    process.on('exit', cleanup);
    process.on('SIGINT', () => { cleanup(); process.exit(130); });
    process.on('SIGTERM', () => { cleanup(); process.exit(143); });

    return scriptPath;
  }

  // Build the SSH_ASKPASS env for a plaintext password. Shared by config-based
  // passwords (buildSpawnEnv) and ad-hoc passwords passed as a tool argument.
  // The password only ever reaches OpenSSH through the askpass helper's env var,
  // never on a command line and never in any string returned to the LLM.
  async _askpassEnvForPassword(password) {
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

  async buildSpawnEnv(hostAlias) {
    const password = await this.getPasswordForHost(hostAlias);
    if (!password) return null;

    // Check file permissions before using password
    if (this.configParser._configsWithPasswords) {
      for (const configPath of this.configParser._configsWithPasswords) {
        await this.configParser.checkFilePermissions(configPath);
      }
    }

    return this._askpassEnvForPassword(password);
  }

  // Validate and translate an ad-hoc connection spec (a host not in
  // ~/.ssh/config) into ssh/scp option args. Returns null when `spec` carries no
  // ad-hoc host, so callers fall back to the alias path. Every value that could
  // reach a local shell is either a fixed flag, a validated token, or a bare
  // argv value consumed as an option-argument by ssh (shell:false everywhere),
  // so no ad-hoc field can inject a local command.
  _resolveAdhoc(spec) {
    if (!spec || spec.host == null || spec.host === '') return null;
    const { host, user, port, identityFile, proxyJump, password } = spec;

    // Reuse the strict alias whitelist: it also fits IPv4/IPv6 literals and
    // hostnames, blocks a leading '-' (ssh option injection) and cmd.exe
    // metacharacters. This is the one field spliced next to the '--' target.
    this._assertSafeHostAlias(host);

    let target = host;
    if (user != null && user !== '') {
      const u = String(user);
      if (!/^[A-Za-z0-9_.@-]+$/.test(u) || u.startsWith('-')) {
        throw new Error(`Invalid ad-hoc user: must match [A-Za-z0-9_.@-] and not start with '-'`);
      }
      target = `${u}@${host}`;
    }

    const sshArgs = [];
    const scpArgs = [];
    if (port != null && port !== '') {
      const p = Number(port);
      if (!Number.isInteger(p) || p < 1 || p > 65535) {
        throw new Error(`Invalid ad-hoc port: ${port} (expected an integer 1-65535)`);
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

    return {
      target,
      sshArgs,
      scpArgs,
      password: password != null && password !== '' ? String(password) : null
    };
  }

  // Resolve a target for ssh/scp. Ad-hoc hosts (options.adhoc.host set) skip the
  // known-host gate by design — the caller supplied explicit connection details.
  // The alias path keeps both the safety whitelist and the known-host gate.
  async _prepareConnection(hostAlias, options = {}) {
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
  _taskConnOptions(task) {
    return { adhoc: task.connection };
  }

  async runRemoteCommand(hostAlias, command, options = {}) {
    const conn = await this._prepareConnection(hostAlias, options);
    const timeout = options.timeout || 30000;
    const MAX_OUTPUT_SIZE = 10 * 1024 * 1024; // 10MB limit

    debugLog(`Executing: ssh ${conn.target} ${command}\n`);

    const passwordEnv = conn.env;

    return new Promise((resolve) => {
      const spawnOptions = {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        // shell:false is critical on Windows: with shell:true the args would
        // be re-parsed by cmd.exe and metacharacters in `command` could lead
        // to local command injection. We rely on resolveExecutable() to find
        // ssh.exe on Windows so PATH lookup is not needed.
        shell: false
      };
      if (passwordEnv) {
        spawnOptions.env = passwordEnv;
        if (!isWindows) {
          // setsid needed on some systems so SSH uses SSH_ASKPASS instead of tty
          spawnOptions.detached = true;
        }
      }

      const child = this._spawn(SSH_BIN, ['-o', 'StrictHostKeyChecking=accept-new', ...conn.sshArgs, '--', conn.target, command], spawnOptions);

      let stdout = '';
      let stderr = '';
      let killed = false;
      let stdoutTruncated = false;
      let stderrTruncated = false;

      const timer = setTimeout(() => {
        killed = true;
        child.kill('SIGTERM');
      }, timeout);

      child.stdout.on('data', (data) => {
        if (stdout.length < MAX_OUTPUT_SIZE) {
          stdout += data.toString();
        } else if (!stdoutTruncated) {
          stdoutTruncated = true;
          stdout += '\n[Output truncated - exceeded 10MB limit]';
        }
      });

      child.stderr.on('data', (data) => {
        if (stderr.length < MAX_OUTPUT_SIZE) {
          stderr += data.toString();
        } else if (!stderrTruncated) {
          stderrTruncated = true;
          stderr += '\n[Stderr truncated - exceeded 10MB limit]';
        }
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({
          stdout,
          stderr: killed ? stderr + '\n[Command timed out]' : stderr,
          code: killed ? 124 : (code || 0)
        });
      });

      child.on('error', (error) => {
        clearTimeout(timer);
        debugLog(`Error executing command on ${conn.target}: ${error.message}\n`);
        resolve({
          stdout,
          stderr: error.message,
          code: 1
        });
      });
    });
  }

  // Start a command that outlives this ssh connection. Returns immediately with
  // a task id; the command keeps running on the remote host.
  async startBackgroundTask(hostAlias, command, options = {}) {
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

    const task = {
      taskId,
      // Alias tasks reconnect by alias; ad-hoc tasks replay `connection`. The
      // stored connection carries no password (ad-hoc password + detach is
      // refused above), so it is safe to expose via `backgroundTask list`.
      hostAlias: adhoc ? null : hostAlias,
      connection: adhoc
        ? {
            host: options.adhoc.host,
            user: options.adhoc.user ?? undefined,
            port: options.adhoc.port ?? undefined,
            identityFile: options.adhoc.identityFile ?? undefined,
            proxyJump: options.adhoc.proxyJump ?? undefined
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
  _assertSafeTaskId(taskId) {
    if (!/^[A-Za-z0-9_-]+$/.test(String(taskId || ''))) {
      throw new Error(`Refusing to use unsafe task id '${taskId}'.`);
    }
  }

  // Deletes remote files and registry entries for tasks the host confirms are
  // no longer running. The host is the source of truth: an entry may say
  // 'running' long after the command finished, and only the host can tell.
  async _purgeTasks(tasks, { keepRemote = false } = {}) {
    const removed = [];
    const kept = [];

    const valid = [];
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
    const byHost = new Map();
    for (const task of valid) {
      const key = task.connection ? JSON.stringify(task.connection) : `alias:${task.hostAlias}`;
      if (!byHost.has(key)) byHost.set(key, []);
      byHost.get(key).push(task);
    }

    for (const [, hostTasks] of byHost) {
      const ids = hostTasks.map(t => t.taskId);
      const result = await this.runRemoteCommand(hostTasks[0].hostAlias, buildTaskPurgeScript(ids), this._taskConnOptions(hostTasks[0]));
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
  } = {}) {
    if (action === 'list') return { tasks: await this.taskStore.list() };

    if (action === 'prune') {
      let tasks = await this.taskStore.list();
      if (olderThanHours > 0) {
        const cutoff = Date.now() - olderThanHours * 3600 * 1000;
        tasks = tasks.filter(t => taskStartedAt(t) < cutoff);
      }
      if (!tasks.length) return { removed: [], kept: [] };
      return this._purgeTasks(tasks, { keepRemote });
    }

    if (!['status', 'logs', 'stop', 'remove'].includes(action)) {
      throw new Error(`Unsupported task action '${action}'. Use list, status, logs, stop, remove or prune.`);
    }

    const task = await this.taskStore.get(taskId);
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
      return { task: await this.taskStore.update(taskId, status) };
    }

    if (action === 'logs') {
      const result = await this.runRemoteCommand(task.hostAlias, buildTaskLogsScript(task.logPath, offset, limit), this._taskConnOptions(task));
      const { size, content } = parseTaskLogs(result.stdout);
      return { taskId, offset, size, content, truncated: offset + Buffer.byteLength(content) < size };
    }

    const result = await this.runRemoteCommand(task.hostAlias, buildTaskStopScript(task), this._taskConnOptions(task));
    const stopped = /__MCP_TASK_STOPPED=(true|unknown)/.test(result.stdout);
    return { task: await this.taskStore.update(taskId, { state: stopped ? 'stopped' : 'running' }) };
  }

  async getHostInfo(hostAlias, options = {}) {
    // For an ad-hoc host there is no config entry to read; echo back the
    // supplied connection shape (never the password — only passwordAuth: true).
    const adhoc = this._resolveAdhoc(options.adhoc);
    if (adhoc) {
      const a = options.adhoc;
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
    const host = hosts.find(host => hostMatchesAlias(host, hostAlias)) || null;
    if (host) {
      // Never expose password to the LLM
      const { _password, ...safeHost } = host;
      if (_password) safeHost.passwordAuth = true;
      return safeHost;
    }
    return null;
  }

  async checkConnectivity(hostAlias, options = {}) {
    try {
      // Simple connectivity test using ssh
      const result = await this.runRemoteCommand(hostAlias, 'echo connected', options);
      const connected = result.code === 0 && result.stdout.trim() === 'connected';
      
      return {
        connected,
        message: connected ? 'Connection successful' : 'Connection failed'
      };
    } catch (error) {
      debugLog(`Connectivity error with ${hostAlias}: ${error.message}\n`);
      return {
        connected: false,
        message: error instanceof Error ? error.message : String(error)
      };
    }
  }

  async uploadFile(hostAlias, localPath, remotePath, options = {}) {
    try {
      const conn = await this._prepareConnection(hostAlias, options);
      debugLog(`Executing: scp ${localPath} ${conn.target}:${remotePath}\n`);

      const spawnOptions = { timeout: 60000, windowsHide: true, shell: false };
      if (conn.env) spawnOptions.env = conn.env;

      await this._execFileAsync(SCP_BIN, ['-o', 'StrictHostKeyChecking=accept-new', ...conn.scpArgs, '--', localPath, `${conn.target}:${remotePath}`], spawnOptions);
      return true;
    } catch (error) {
      debugLog(`Error uploading file to ${hostAlias}: ${error.message}\n`);
      return false;
    }
  }

  async downloadFile(hostAlias, remotePath, localPath, options = {}) {
    try {
      const conn = await this._prepareConnection(hostAlias, options);
      debugLog(`Executing: scp ${conn.target}:${remotePath} ${localPath}\n`);

      const spawnOptions = { timeout: 60000, windowsHide: true, shell: false };
      if (conn.env) spawnOptions.env = conn.env;

      await this._execFileAsync(SCP_BIN, ['-o', 'StrictHostKeyChecking=accept-new', ...conn.scpArgs, '--', `${conn.target}:${remotePath}`, localPath], spawnOptions);
      return true;
    } catch (error) {
      debugLog(`Error downloading file from ${hostAlias}: ${error.message}\n`);
      return false;
    }
  }

  async runCommandBatch(hostAlias, commands, options = {}) {
    try {
      const results = [];
      let success = true;

      for (const command of commands) {
        const result = await this.runRemoteCommand(hostAlias, command, options);
        results.push(result);
        
        if (result.code !== 0) {
          success = false;
          // Continue executing remaining commands
        }
      }
      
      return {
        results,
        success
      };
    } catch (error) {
      debugLog(`Error during batch execution on ${hostAlias}: ${error.message}\n`);
      return {
        results: [{
          stdout: '',
          stderr: error instanceof Error ? error.message : String(error),
          code: 1
        }],
        success: false
      };
    }
  }
}

// Shared input-schema properties for connecting to an ad-hoc host that is not
// in ~/.ssh/config / known_hosts. When `host` is set, the known-host gate is
// skipped and ssh is driven by these explicit parameters instead of an alias.
const ADHOC_PROPS = {
  host: {
    type: "string",
    description: "Ad-hoc target host/IP not in ~/.ssh/config. When set, the known-host gate is skipped and connection is driven by these params. Provide this OR hostAlias, not both.",
  },
  user: {
    type: "string",
    description: "Ad-hoc: remote username (used with host).",
  },
  port: {
    type: "number",
    description: "Ad-hoc: SSH port (used with host, default 22).",
  },
  identityFile: {
    type: "string",
    description: "Ad-hoc: path to a private key file for host.",
  },
  password: {
    type: "string",
    description: "Ad-hoc: password for host. Passed to ssh via SSH_ASKPASS and never echoed back. Not usable with detach:true.",
  },
  proxyJump: {
    type: "string",
    description: "Ad-hoc: ProxyJump/-J spec for host (e.g. user@jumphost:port).",
  },
};

// Extract the ad-hoc connection spec from tool arguments, or undefined when the
// call targets a configured hostAlias.
function adhocFromArgs(a) {
  if (a.host == null || a.host === '') return undefined;
  return {
    host: a.host,
    user: a.user,
    port: a.port,
    identityFile: a.identityFile,
    password: a.password,
    proxyJump: a.proxyJump,
  };
}

// Every ssh/scp tool takes exactly one target: a configured hostAlias or an
// ad-hoc host. Reject ambiguous or empty calls up front with a clear message.
function assertOneTarget(a) {
  const hasAlias = a.hostAlias != null && a.hostAlias !== '';
  const hasHost = a.host != null && a.host !== '';
  if (hasAlias && hasHost) {
    throw new Error("Provide either hostAlias or host, not both.");
  }
  if (!hasAlias && !hasHost) {
    throw new Error("Provide hostAlias (a configured host) or host (an ad-hoc IP/hostname).");
  }
  // Ad-hoc auth params only take effect together with `host`. If they arrive
  // alongside a hostAlias they would otherwise be silently ignored (the alias
  // path reads none of them), so reject the ambiguous combination instead.
  if (hasAlias) {
    const stray = ['user', 'port', 'identityFile', 'password', 'proxyJump'].filter(
      k => a[k] != null && a[k] !== ''
    );
    if (stray.length) {
      throw new Error(
        `Ad-hoc parameters (${stray.join(', ')}) require 'host', not 'hostAlias'. ` +
        `Configure these in ~/.ssh/config for an alias, or pass 'host' instead of 'hostAlias'.`
      );
    }
  }
}

// Main function to start the MCP server
async function main() {
  try {
    // Create an instance of the SSH client
    debugLog("Initializing SSH client...\n");
    const sshClient = new SSHClient();

    debugLog("Creating MCP server...\n");
    // Create an MCP server
    const server = new Server(
      { name: "mcp-ssh", version: "1.0.0" },
      { capabilities: { tools: {} } }
    );

    debugLog("Setting up request handlers...\n");
    // Handler for listing available tools
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      debugLog("Received listTools request\n");
      return {
        tools: [
          {
            name: "listKnownHosts",
            description: "Returns a consolidated list of all known SSH hosts, prioritizing ~/.ssh/config entries first, then additional hosts from ~/.ssh/known_hosts",
            inputSchema: {
              type: "object",
              properties: {},
              required: [],
            },
          },
          {
            name: "runRemoteCommand",
            description: "Executes a shell command on an SSH host and waits for it to finish. For work that outlives the call (deploys, backups, builds), set detach:true instead of raising the timeout: the command keeps running on the host and you poll it with backgroundTask. Target either a configured host (hostAlias) or an ad-hoc host not in ~/.ssh/config (host + auth params).",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of a host defined in ~/.ssh/config or known_hosts. Provide this OR the ad-hoc `host`, not both.",
                },
                command: {
                  type: "string",
                  description: "The shell command to execute",
                },
                timeout: {
                  type: "number",
                  description: "Command timeout in milliseconds (default: 120000, max: 300000)",
                },
                detach: {
                  type: "boolean",
                  description: "Run in the background and return a taskId immediately. The command survives this connection closing; follow it with backgroundTask.",
                },
                ...ADHOC_PROPS,
              },
              required: ["command"],
            },
          },
          {
            name: "getHostInfo",
            description: "Returns configuration details for an SSH host. For an ad-hoc host, echoes back the supplied connection shape (never the password).",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of a configured SSH host. Provide this OR the ad-hoc `host`.",
                },
                ...ADHOC_PROPS,
              },
              required: [],
            },
          },
          {
            name: "checkConnectivity",
            description: "Checks if an SSH connection to the host is possible. Target a configured hostAlias or an ad-hoc host.",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of a configured SSH host. Provide this OR the ad-hoc `host`.",
                },
                ...ADHOC_PROPS,
              },
              required: [],
            },
          },
          {
            name: "uploadFile",
            description: "Uploads a local file to an SSH host (configured hostAlias or ad-hoc host).",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of a configured SSH host. Provide this OR the ad-hoc `host`.",
                },
                localPath: {
                  type: "string",
                  description: "Path to the local file",
                },
                remotePath: {
                  type: "string",
                  description: "Path on the remote host",
                },
                ...ADHOC_PROPS,
              },
              required: ["localPath", "remotePath"],
            },
          },
          {
            name: "downloadFile",
            description: "Downloads a file from an SSH host (configured hostAlias or ad-hoc host).",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of a configured SSH host. Provide this OR the ad-hoc `host`.",
                },
                remotePath: {
                  type: "string",
                  description: "Path on the remote host",
                },
                localPath: {
                  type: "string",
                  description: "Path to the local destination",
                },
                ...ADHOC_PROPS,
              },
              required: ["remotePath", "localPath"],
            },
          },
          {
            name: "runCommandBatch",
            description: "Executes multiple shell commands sequentially on an SSH host (configured hostAlias or ad-hoc host).",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of a configured SSH host. Provide this OR the ad-hoc `host`.",
                },
                commands: {
                  type: "array",
                  items: { type: "string" },
                  description: "List of shell commands to execute",
                },
                ...ADHOC_PROPS,
              },
              required: ["commands"],
            },
          },
          {
            name: "backgroundTask",
            description: "Inspects and cleans up commands started with runRemoteCommand detach:true. list: all known tasks. status: whether a task is still running and its exit code. logs: captured output, readable while the task is still running. stop: terminate the task and its children. remove: forget one finished task and delete its files on the host. prune: the same for every finished task — use it once you are done with a batch of tasks, otherwise the registry and the host's log files keep growing. A task that is still running is never removed.",
            inputSchema: {
              type: "object",
              properties: {
                action: {
                  type: "string",
                  enum: ["list", "status", "logs", "stop", "remove", "prune"],
                  description: "What to do with the task",
                },
                taskId: {
                  type: "string",
                  description: "Task id returned by a detached runRemoteCommand (required for status, logs, stop)",
                },
                offset: {
                  type: "number",
                  description: "logs: byte offset to read from, for following a growing log (default: 0)",
                },
                limit: {
                  type: "number",
                  description: "logs: maximum bytes to return (default: 131072)",
                },
                keepRemote: {
                  type: "boolean",
                  description: "remove/prune: drop the registry entry but leave the files on the host — for a host that is gone or logs you still want (default: false)",
                },
                olderThanHours: {
                  type: "number",
                  description: "prune: only consider tasks started at least this many hours ago (default: no age limit)",
                },
              },
              required: ["action"],
            },
          },
        ],
      };
    });

    // Handler for tool calls
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      debugLog(`Received callTool request for tool: ${name}\n`);

      if (!args && name !== "listKnownHosts") {
        throw new Error(`No arguments provided for tool: ${name}`);
      }

      try {
        switch (name) {
          case "listKnownHosts": {
            const hosts = await sshClient.listKnownHosts();
            // Strip passwords before sending to LLM
            const safeHosts = hosts.map(({ _password, ...host }) => {
              if (_password) host.passwordAuth = true;
              return host;
            });
            return {
              content: [{ type: "text", text: JSON.stringify(safeHosts, null, 2) }],
            };
          }

          case "runRemoteCommand": {
            assertOneTarget(args);
            const adhoc = adhocFromArgs(args);
            const timeout = Math.min(args.timeout || 120000, 300000); // Default 2 min, cap at 5 min
            if (args.detach) {
              const task = await sshClient.startBackgroundTask(args.hostAlias, args.command, { timeout, adhoc });
              return {
                content: [{ type: "text", text: JSON.stringify(task, null, 2) }],
              };
            }
            const result = await sshClient.runRemoteCommand(
              args.hostAlias,
              args.command,
              { timeout, adhoc }
            );
            return {
              content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
          }

          case "backgroundTask": {
            const result = await sshClient.backgroundTask(args);
            return {
              content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
          }

          case "getHostInfo": {
            assertOneTarget(args);
            const hostInfo = await sshClient.getHostInfo(args.hostAlias, { adhoc: adhocFromArgs(args) });
            return {
              content: [{ type: "text", text: JSON.stringify(hostInfo, null, 2) }],
            };
          }

          case "checkConnectivity": {
            assertOneTarget(args);
            const status = await sshClient.checkConnectivity(args.hostAlias, { adhoc: adhocFromArgs(args) });
            return {
              content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
            };
          }

          case "uploadFile": {
            assertOneTarget(args);
            const success = await sshClient.uploadFile(
              args.hostAlias,
              args.localPath,
              args.remotePath,
              { adhoc: adhocFromArgs(args) }
            );
            return {
              content: [{ type: "text", text: JSON.stringify({ success }, null, 2) }],
            };
          }

          case "downloadFile": {
            assertOneTarget(args);
            const success = await sshClient.downloadFile(
              args.hostAlias,
              args.remotePath,
              args.localPath,
              { adhoc: adhocFromArgs(args) }
            );
            return {
              content: [{ type: "text", text: JSON.stringify({ success }, null, 2) }],
            };
          }

          case "runCommandBatch": {
            assertOneTarget(args);
            const result = await sshClient.runCommandBatch(
              args.hostAlias,
              args.commands,
              { adhoc: adhocFromArgs(args) }
            );
            return {
              content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
          }

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        debugLog(`Error executing tool ${name}: ${error.message}\n`);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : String(error),
              }),
            },
          ],
        };
      }
    });

    debugLog("Starting MCP SSH Agent on STDIO...\n");
    const transport = new StdioServerTransport();
    await server.connect(transport);
    debugLog("MCP SSH Agent connected and ready!\n");
    
  } catch (error) {
    debugLog(`Error starting MCP SSH Agent: ${error.message}\n`);
    process.exit(1);
  }
}

// Export classes and main() for the bin wrapper and tests.
// We do NOT auto-start main() based on a process.argv[1] heuristic — that
// check was unreliable on Windows (backslashes vs forward slashes) and
// caused the server to silently exit when launched via bin/mcp-ssh.js on
// Windows MCP clients (issue #8). The bin wrapper now imports and calls
// main() explicitly.
export {
  SSHConfigParser,
  SSHClient,
  debugLog,
  main,
  shQuote,
  taskPaths,
  TaskStore,
  parseTaskLogs,
  buildTaskStartScript,
  parseTaskHandshake,
  buildTaskStatusScript,
  parseTaskStatus,
  buildTaskStopScript,
  buildTaskLogsScript,
  buildTaskPurgeScript,
  parseTaskPurge
};
