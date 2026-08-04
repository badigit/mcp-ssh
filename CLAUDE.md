# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is MCP SSH Agent (@aiondadotcom/mcp-ssh) - a Model Context Protocol (MCP) server that provides SSH operations for AI assistants like Claude Desktop. The project uses native SSH commands (`ssh`, `scp`) rather than JavaScript SSH libraries for maximum reliability and compatibility.

## Development Commands

### Basic Operations
- `npm start` - Start the MCP server (same as `npm run dev`)
- `npm run dev` - Start the MCP server with debug output
- `npm run build` - Currently a no-op (echo "Build skipped")
- `npm test` - Run the vitest suite (`server.test.mjs`) with coverage
- `npm run test:watch` - Vitest in watch mode

### Development Scripts
- `./start.sh` - Start the server with debug output
- `./start-silent.sh` - Start the server in silent mode (no debug output)
- `node server.mjs` - Direct server execution

### Publishing
- `npm version patch|minor|major` - Bump version and create git tag
- `npm publish` - Publish to npm (see PUBLISHING.md for details)
- `npm pack` - Create tarball for testing

### DXT Package Building
- `npm run build:dxt` - Build Desktop Extension (.dxt) package
- `./scripts/build-dxt.sh` - Direct build script execution

## Architecture

### Main Entry Point
- `server.mjs` - Self-contained MCP server implementation that includes all functionality inline to avoid module resolution issues

### Other Files
- `bin/mcp-ssh.js` - Binary wrapper for npx compatibility

### Key Design Decisions
1. **Native SSH Tools**: Uses system `ssh` and `scp` commands rather than JavaScript SSH libraries for reliability
2. **Self-contained**: `server.mjs` includes all code inline to avoid ESM import issues
3. **Silent Mode**: Controlled by `MCP_SILENT` environment variable to disable debug output when used as MCP server
4. **No shell on spawn**: All `spawn`/`execFile` calls use `shell: false`. On Windows, `ssh.exe`/`scp.exe` are resolved to absolute paths once at startup via `resolveExecutable()` (PATH + PATHEXT walk), so PATH lookup does not require `shell: true`. This is required to prevent local command injection through shell metacharacters in tool arguments.
5. **Strict `hostAlias` whitelist**: `_assertSafeHostAlias()` (`SSHClient`) rejects any `hostAlias` that does not match `^[A-Za-z0-9_.@:][A-Za-z0-9._@:-]*$`. Combined with the `--` argument terminator on every `ssh`/`scp` invocation, this blocks SSH option injection (e.g. `-oProxyCommand=…`) and shell-metacharacter injection. Validation is applied at the public entry points (`runRemoteCommand`, `uploadFile`, `downloadFile`) and transitively covers `checkConnectivity` and `runCommandBatch`. **Do not weaken or bypass this validator** without understanding the security implications — see CHANGELOG entry for 1.3.5.
6. **Ad-hoc hosts vs. two separate gates**: There are two independent checks — `_assertSafeHostAlias()` (the safety whitelist above) and `_assertKnownHostAlias()` (the "is this host in ssh_config/known_hosts?" gate). Ad-hoc connections (a tool call carrying `host` + explicit `user`/`port`/`identityFile`/`password`/`proxyJump`, resolved by `_resolveAdhoc()` / `_prepareConnection()`) **skip only the known-host gate** — the user supplied explicit connection details on purpose. They **still pass the safety whitelist** (`_resolveAdhoc` runs `_assertSafeHostAlias(host)`), and every ad-hoc field goes into `ssh`/`scp` structurally as argv (`-p`/`-P`, `-i`, `-J`, `user@host`, password via `SSH_ASKPASS`) with `shell:false`. `host` and `user` are charset-whitelisted; `port` is an integer 1–65535. **`proxyJump` is whitelisted per hop, and that is load-bearing, not cosmetic**: `-J` is the one option ssh does not merely pass through — it expands it into an internally generated `ProxyCommand` that runs via `/bin/sh -c`, interpolating each hop into that shell string, so shell metacharacters in an unvalidated `proxyJump` are local command execution on the machine running ssh (cf. CVE-2023-51385). `identityFile` is a bare option-argument after `-i`, so a leading `-` there is a value, not an option. `host` and `hostAlias` are mutually exclusive, and ad-hoc auth params alongside a `hostAlias` are rejected rather than silently ignored (`assertOneTarget`). **Do not route ad-hoc fields around `_resolveAdhoc` / the safety whitelist, and do not relax the `proxyJump` validation.** Detached background tasks over ad-hoc *password* auth are refused on purpose — persisting the password to the task registry (which `backgroundTask list` returns to the LLM) would leak it.

## SSH Configuration Integration

The agent automatically discovers SSH hosts from:
- `~/.ssh/config` - Primary source for host configurations
- `~/.ssh/known_hosts` - Additional hosts not in config

Host discovery prioritizes SSH config entries first, then adds additional hosts from known_hosts.

### Password Authentication

Passwords can be stored as comment annotations in `~/.ssh/config`:
```
Host myrouter
    HostName 192.168.1.1
    User admin
    # @password:secretPassword
```

- The `# @password:` annotation is read locally — the password **never** reaches the LLM or cloud provider
- Works for login passwords and SSH key passphrases
- Passwords are stripped from all tool outputs (only `passwordAuth: true` is exposed)
- The server enforces `chmod 600` on config files containing `@password` annotations
- Uses `SSH_ASKPASS` mechanism internally (temp script + env variable, no external dependencies)
- The `user@host` format is supported for password lookup (strips user prefix to find the config entry)
- Unknown host fingerprints are auto-accepted via `StrictHostKeyChecking=accept-new` (changed keys are still rejected)

## MCP Tools Provided

1. **listKnownHosts()** - Lists all discovered SSH hosts
2. **runRemoteCommand(hostAlias, command)** - Execute commands via SSH
3. **getHostInfo(hostAlias)** - Get host configuration details
4. **checkConnectivity(hostAlias)** - Test SSH connectivity
5. **uploadFile(hostAlias, localPath, remotePath)** - Upload files via SCP
6. **downloadFile(hostAlias, remotePath, localPath)** - Download files via SCP
7. **runCommandBatch(hostAlias, commands)** - Execute multiple commands sequentially
8. **backgroundTask(action, taskId)** - Inspect and clean up detached tasks (`list`, `status`, `logs`, `stop`, `remove`, `prune`)

Every transport tool (all but `listKnownHosts`/`backgroundTask`) also accepts optional **ad-hoc** params — `host`, `user`, `port`, `identityFile`, `password`, `proxyJump` — to reach a host not in ssh_config. When `host` is set it replaces `hostAlias` (they are mutually exclusive) and the known-host gate is skipped; see Design Decision 6.

### Background task cleanup invariants

- **A running task is never removed.** The liveness check and the `rm` live in one
  remote script (`buildTaskPurgeScript`), so nothing can start between them. Do not
  split them into a `status` call followed by a separate delete.
- **Only what the host confirms is dropped locally.** An unreachable host means the
  files are still there, and the registry entry is the only remaining handle on them —
  hence `reason: 'host-unreachable'` rather than a silent local delete.
- **Both sides expire finished tasks after the same `TASK_RETENTION_DAYS`.** If you
  change one, change the other, or the host sweep and the local GC will orphan each
  other's leftovers. The host sweep is keyed on the `.exit` file, which is what keeps
  a long-running task safe from it.

## Testing and Debugging

### Manual Testing
```bash
# Test as MCP server
npx @aiondadotcom/mcp-ssh

# Test with debug output
MCP_SILENT=false npx @aiondadotcom/mcp-ssh

# Test installation
npm pack
npm install -g ./aiondadotcom-mcp-ssh-*.tgz
mcp-ssh
```

### Integration Testing
Configure in Claude Desktop's `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "mcp-ssh": {
      "command": "npx",
      "args": ["@aiondadotcom/mcp-ssh"]
    }
  }
}
```

## Dependencies

- `@modelcontextprotocol/sdk` - MCP protocol implementation
- `ssh-config` - SSH configuration file parsing
- Node.js built-ins: `child_process`, `fs/promises`, `os`, `path`

## Desktop Extension Support

The project supports Desktop Extensions (.dxt) for easy installation in Claude Desktop:

- `manifest.json` - DXT package manifest with server configuration
- `scripts/build-dxt.sh` - Build script that creates .dxt packages in `build/` directory
- `.dxt` files are ZIP archives containing the manifest and server files
- Built packages are excluded from git via `.gitignore` but can be uploaded to GitHub releases

## Threat Model

The LLM driving this MCP server is **not trusted** — its tool arguments can be steered by prompt injection from any untrusted text in the conversation context (web pages, e-mails, repo files, output of other MCP servers). When changing this codebase, keep these invariants:

- **Local RCE must stay impossible.** `hostAlias`, `command`, `localPath` and `remotePath` must never reach a shell on the local machine. Use `spawn`/`execFile` with `shell: false` and an argv array. Never re-introduce `shell: true`.
- **`runRemoteCommand` is by-design RCE on the configured remote.** That is the tool's contract; do not try to "sanitize" the `command` argument.
- **`uploadFile`/`downloadFile` give the LLM the local filesystem with the server process's privileges.** The README documents this; users are expected to run mcp-ssh under an unprivileged user or in a sandbox. Path arguments are not sandboxed.
- **`# @password:` values must never appear in MCP responses** or in any string the LLM can see. Only `passwordAuth: true` is exposed.
- See README → "Threat Model and Trust Boundaries" for the user-facing version of this.

## Important Notes

- The project is ESM-only (`"type": "module"` in package.json). The `.mjs` extension on `server.mjs` is historical and redundant given `"type": "module"`; keep it for now to avoid touching `bin/`, `manifest.json`, `package.json` `main`, and the start scripts.
- Production code is in `server.mjs`, not compiled from TypeScript
- SSH operations require properly configured SSH keys or `@password` annotations
- The agent runs over STDIO as an MCP server, not as a standalone application
- DXT packages provide one-click installation alternative to manual JSON configuration

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:6cd5cc61 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->
