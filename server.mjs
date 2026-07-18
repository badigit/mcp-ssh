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
    // The command travels as a positional argument, never spliced into this
    // script's text, so it cannot break out of the wrapper that records the
    // exit code. `eval` is what makes it a shell command rather than an argv.
    `__mcp_cmd=${shQuote(command)}`,
    `setsid "\${SHELL:-/bin/sh}" -c 'ps -o pgid= -p $$ | tr -d " " > "$2"; eval "$1"; printf "%s\\n" "$?" > "$3"' _ "$__mcp_cmd" "${pgidPath}" "${exitPath}" > "${logPath}" 2>&1 < /dev/null &`,
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
  const exit = text.match(/__MCP_TASK_EXIT=(-?\d+)/);
  if (exit) return { state: 'exited', exitCode: Number(exit[1]) };
  if (/__MCP_TASK_RUNNING=true/.test(text)) return { state: 'running' };
  return { state: 'unknown' };
}

function buildTaskStopScript(pgidPath) {
  return [
    'set +e',
    `__mcp_pgid=$(cat "${pgidPath}" 2>/dev/null | tr -d ' \\n')`,
    // Never signal an empty group: `kill -- -` would hit an unintended target.
    `if [ -z "$__mcp_pgid" ]; then printf '%s\\n' '__MCP_TASK_STOPPED=unknown'; exit 0; fi`,
    'kill -TERM -- -"$__mcp_pgid" 2>/dev/null',
    'sleep 1',
    'if kill -0 -- -"$__mcp_pgid" 2>/dev/null; then kill -KILL -- -"$__mcp_pgid" 2>/dev/null; sleep 1; fi',
    `if kill -0 -- -"$__mcp_pgid" 2>/dev/null; then printf '%s\\n' '__MCP_TASK_STOPPED=false'; else printf '%s\\n' '__MCP_TASK_STOPPED=true'; fi`
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

  async add(task) {
    const all = await this._load();
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

  async buildSpawnEnv(hostAlias) {
    const password = await this.getPasswordForHost(hostAlias);
    if (!password) return null;

    // Check file permissions before using password
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
      SSH_ASKPASS_REQUIRE: 'force'
    };
  }

  async runRemoteCommand(hostAlias, command, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);
    const timeout = options.timeout || 30000;
    const MAX_OUTPUT_SIZE = 10 * 1024 * 1024; // 10MB limit

    debugLog(`Executing: ssh ${hostAlias} ${command}\n`);

    const passwordEnv = await this.buildSpawnEnv(hostAlias);

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

      const child = this._spawn(SSH_BIN, ['-o', 'StrictHostKeyChecking=accept-new', '--', hostAlias, command], spawnOptions);

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
        debugLog(`Error executing command on ${hostAlias}: ${error.message}\n`);
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
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);

    const taskId = randomBytes(6).toString('hex');
    const paths = taskPaths(taskId);
    const script = buildTaskStartScript({ taskId, command });

    const result = await this.runRemoteCommand(hostAlias, script, { timeout: options.timeout || 30000 });
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
      hostAlias,
      command,
      ...paths,
      state: 'running',
      startedAt: new Date().toISOString()
    };
    await this.taskStore.add(task);
    return task;
  }

  async backgroundTask({ action = 'list', taskId, offset = 0, limit = 128 * 1024 } = {}) {
    if (action === 'list') return { tasks: await this.taskStore.list() };
    if (!['status', 'logs', 'stop'].includes(action)) {
      throw new Error(`Unsupported task action '${action}'. Use list, status, logs or stop.`);
    }

    const task = await this.taskStore.get(taskId);
    if (!task) throw new Error(`Task '${taskId}' not found in the local registry.`);

    if (action === 'status') {
      const result = await this.runRemoteCommand(task.hostAlias, buildTaskStatusScript(task));
      const status = parseTaskStatus(result.stdout);
      return { task: await this.taskStore.update(taskId, status) };
    }

    if (action === 'logs') {
      const result = await this.runRemoteCommand(task.hostAlias, buildTaskLogsScript(task.logPath, offset, limit));
      const { size, content } = parseTaskLogs(result.stdout);
      return { taskId, offset, size, content, truncated: offset + Buffer.byteLength(content) < size };
    }

    const result = await this.runRemoteCommand(task.hostAlias, buildTaskStopScript(task.pgidPath));
    const stopped = /__MCP_TASK_STOPPED=(true|unknown)/.test(result.stdout);
    return { task: await this.taskStore.update(taskId, { state: stopped ? 'stopped' : 'running' }) };
  }

  async getHostInfo(hostAlias) {
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

  async checkConnectivity(hostAlias) {
    try {
      // Simple connectivity test using ssh
      const result = await this.runRemoteCommand(hostAlias, 'echo connected');
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

  async uploadFile(hostAlias, localPath, remotePath) {
    try {
      this._assertSafeHostAlias(hostAlias);
      await this._assertKnownHostAlias(hostAlias);
      debugLog(`Executing: scp ${localPath} ${hostAlias}:${remotePath}\n`);

      const passwordEnv = await this.buildSpawnEnv(hostAlias);
      const options = { timeout: 60000, windowsHide: true, shell: false };
      if (passwordEnv) options.env = passwordEnv;

      await this._execFileAsync(SCP_BIN, ['-o', 'StrictHostKeyChecking=accept-new', '--', localPath, `${hostAlias}:${remotePath}`], options);
      return true;
    } catch (error) {
      debugLog(`Error uploading file to ${hostAlias}: ${error.message}\n`);
      return false;
    }
  }

  async downloadFile(hostAlias, remotePath, localPath) {
    try {
      this._assertSafeHostAlias(hostAlias);
      await this._assertKnownHostAlias(hostAlias);
      debugLog(`Executing: scp ${hostAlias}:${remotePath} ${localPath}\n`);

      const passwordEnv = await this.buildSpawnEnv(hostAlias);
      const options = { timeout: 60000, windowsHide: true, shell: false };
      if (passwordEnv) options.env = passwordEnv;

      await this._execFileAsync(SCP_BIN, ['-o', 'StrictHostKeyChecking=accept-new', '--', `${hostAlias}:${remotePath}`, localPath], options);
      return true;
    } catch (error) {
      debugLog(`Error downloading file from ${hostAlias}: ${error.message}\n`);
      return false;
    }
  }

  async runCommandBatch(hostAlias, commands) {
    try {
      const results = [];
      let success = true;
      
      for (const command of commands) {
        const result = await this.runRemoteCommand(hostAlias, command);
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
            description: "Executes a shell command on an SSH host. For long-running commands, increase the timeout parameter.",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of the SSH host",
                },
                command: {
                  type: "string",
                  description: "The shell command to execute",
                },
                timeout: {
                  type: "number",
                  description: "Command timeout in milliseconds (default: 120000, max: 300000)",
                },
              },
              required: ["hostAlias", "command"],
            },
          },
          {
            name: "getHostInfo",
            description: "Returns all configuration details for an SSH host",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of the SSH host",
                },
              },
              required: ["hostAlias"],
            },
          },
          {
            name: "checkConnectivity",
            description: "Checks if an SSH connection to the host is possible",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of the SSH host",
                },
              },
              required: ["hostAlias"],
            },
          },
          {
            name: "uploadFile",
            description: "Uploads a local file to an SSH host",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of the SSH host",
                },
                localPath: {
                  type: "string",
                  description: "Path to the local file",
                },
                remotePath: {
                  type: "string",
                  description: "Path on the remote host",
                },
              },
              required: ["hostAlias", "localPath", "remotePath"],
            },
          },
          {
            name: "downloadFile",
            description: "Downloads a file from an SSH host",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of the SSH host",
                },
                remotePath: {
                  type: "string",
                  description: "Path on the remote host",
                },
                localPath: {
                  type: "string",
                  description: "Path to the local destination",
                },
              },
              required: ["hostAlias", "remotePath", "localPath"],
            },
          },
          {
            name: "runCommandBatch",
            description: "Executes multiple shell commands sequentially on an SSH host",
            inputSchema: {
              type: "object",
              properties: {
                hostAlias: {
                  type: "string",
                  description: "Alias or hostname of the SSH host",
                },
                commands: {
                  type: "array",
                  items: { type: "string" },
                  description: "List of shell commands to execute",
                },
              },
              required: ["hostAlias", "commands"],
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
            const timeout = Math.min(args.timeout || 120000, 300000); // Default 2 min, cap at 5 min
            const result = await sshClient.runRemoteCommand(
              args.hostAlias,
              args.command,
              { timeout }
            );
            return {
              content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
          }

          case "getHostInfo": {
            const hostInfo = await sshClient.getHostInfo(args.hostAlias);
            return {
              content: [{ type: "text", text: JSON.stringify(hostInfo, null, 2) }],
            };
          }

          case "checkConnectivity": {
            const status = await sshClient.checkConnectivity(args.hostAlias);
            return {
              content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
            };
          }

          case "uploadFile": {
            const success = await sshClient.uploadFile(
              args.hostAlias,
              args.localPath,
              args.remotePath
            );
            return {
              content: [{ type: "text", text: JSON.stringify({ success }, null, 2) }],
            };
          }

          case "downloadFile": {
            const success = await sshClient.downloadFile(
              args.hostAlias,
              args.remotePath,
              args.localPath
            );
            return {
              content: [{ type: "text", text: JSON.stringify({ success }, null, 2) }],
            };
          }

          case "runCommandBatch": {
            const result = await sshClient.runCommandBatch(
              args.hostAlias,
              args.commands
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
  buildTaskLogsScript
};
