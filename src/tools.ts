import type { SSHClient } from './ssh-client.js';
import type { AdhocSpec, TransferFailure } from './types.js';
import { debugLog } from './platform.js';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
type ToolArgs = Record<string, unknown>;
export interface ToolResponse { content: { type: 'text'; text: string }[]; [key: string]: unknown }

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
function adhocFromArgs(a: ToolArgs): AdhocSpec | undefined {
  if (a['host'] == null || a['host'] === '') return undefined;
  return {
    host: a['host'],
    user: a['user'],
    port: a['port'],
    identityFile: a['identityFile'],
    password: a['password'],
    proxyJump: a['proxyJump'],
  } as AdhocSpec;
}

// Every ssh/scp tool takes exactly one target: a configured hostAlias or an
// ad-hoc host. Reject ambiguous or empty calls up front with a clear message.
function assertOneTarget(a: ToolArgs) {
  const hasAlias = a['hostAlias'] != null && a['hostAlias'] !== '';
  const hasHost = a['host'] != null && a['host'] !== '';
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


export const TOOL_DEFINITIONS: Tool[] = [
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
            description: "Uploads a local file via scp, overwriting the remote destination. Uses the selected SSH user's permissions. Returns success or a safe error code and message within a 60-second transfer deadline.",
            annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
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
            description: "Downloads a file via scp, overwriting the local destination. Uses the selected SSH user's permissions, without sudo. Downloads into the local SSH directory are refused. Returns success or a safe error code and message within a 60-second transfer deadline.",
            annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
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
        ];

export async function callTool(sshClient: SSHClient, name: string, args: ToolArgs | undefined): Promise<ToolResponse> {
      if (!args && name !== "listKnownHosts") {
        throw new Error(`No arguments provided for tool: ${name}`);
      }

      const a = args ?? {};
      try {
        switch (name) {
          case "listKnownHosts": {
            const hosts = await sshClient.listKnownHosts();
            // Strip passwords before sending to LLM
            const safeHosts = hosts.map(({ _password, ...host }) => {
              if (_password) host['passwordAuth'] = true;
              return host;
            });
            return {
              content: [{ type: "text", text: JSON.stringify(safeHosts, null, 2) }],
            };
          }

          case "runRemoteCommand": {
            assertOneTarget(a);
            const adhoc = adhocFromArgs(a);
            const timeout = Math.min((a['timeout'] as number | undefined) || 120000, 300000); // Default 2 min, cap at 5 min
            if (a['detach']) {
              const task = await sshClient.startBackgroundTask(a['hostAlias'] as string | undefined, a['command'] as string, { timeout, adhoc });
              return {
                content: [{ type: "text", text: JSON.stringify(task, null, 2) }],
              };
            }
            const result = await sshClient.runRemoteCommand(
              a['hostAlias'] as string | undefined,
              a['command'] as string,
              { timeout, adhoc }
            );
            return {
              content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
          }

          case "backgroundTask": {
            const result = await sshClient.backgroundTask(a);
            return {
              content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
          }

          case "getHostInfo": {
            assertOneTarget(a);
            const hostInfo = await sshClient.getHostInfo(a['hostAlias'] as string | undefined, { adhoc: adhocFromArgs(a) });
            return {
              content: [{ type: "text", text: JSON.stringify(hostInfo, null, 2) }],
            };
          }

          case "checkConnectivity": {
            assertOneTarget(a);
            const status = await sshClient.checkConnectivity(a['hostAlias'] as string | undefined, { adhoc: adhocFromArgs(a) });
            return {
              content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
            };
          }

          case "uploadFile": {
            assertOneTarget(a);
            let failure: TransferFailure | undefined;
            const success = await sshClient.uploadFile(
              a['hostAlias'] as string | undefined,
              a['localPath'] as string,
              a['remotePath'] as string,
              { adhoc: adhocFromArgs(a), onError: (error) => { failure = error; } }
            );
            return {
              ...(success ? {} : { isError: true }),
              content: [{ type: "text", text: JSON.stringify({ success, ...(failure ? { error: failure } : {}) }, null, 2) }],
            };
          }

          case "downloadFile": {
            assertOneTarget(a);
            let failure: TransferFailure | undefined;
            const success = await sshClient.downloadFile(
              a['hostAlias'] as string | undefined,
              a['remotePath'] as string,
              a['localPath'] as string,
              { adhoc: adhocFromArgs(a), onError: (error) => { failure = error; } }
            );
            return {
              ...(success ? {} : { isError: true }),
              content: [{ type: "text", text: JSON.stringify({ success, ...(failure ? { error: failure } : {}) }, null, 2) }],
            };
          }

          case "runCommandBatch": {
            assertOneTarget(a);
            const result = await sshClient.runCommandBatch(
              a['hostAlias'] as string | undefined,
              a['commands'] as string[],
              { adhoc: adhocFromArgs(a) }
            );
            return {
              content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            };
          }

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        debugLog(`Error executing tool ${name}: ${error instanceof Error ? error.message : String(error)}\n`);
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

}
