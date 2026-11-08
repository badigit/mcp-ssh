/**
 * Shared types for the MCP SSH agent.
 */

/** Where a host was discovered. */
export type HostSource = 'ssh_config' | 'known_hosts';

/**
 * A host discovered in ~/.ssh/config or ~/.ssh/known_hosts.
 *
 * `alias` holds the first alias of the block and `aliases` the full list — a
 * `Host` directive takes a list of patterns, not a single name. Keeping `alias`
 * a plain string preserves the response shape for single-alias hosts.
 *
 * Directives that are not specifically modelled land in the index signature,
 * lowercased (`proxycommand`, `identitiesonly`, …).
 */
export interface HostInfo {
  hostname: string;
  alias?: string;
  aliases?: string[];
  user?: string;
  port?: number;
  identityFile?: string;
  configFile?: string;
  source?: HostSource;
  /**
   * Password read from a `# @password:` annotation. Never leaves the process:
   * it is stripped before anything is handed to the LLM, which is what the
   * leading underscore marks.
   */
  _password?: string;
  [directive: string]: unknown;
}

/** A host as exposed to the LLM: no password, only the fact that one exists. */
export type SafeHostInfo = Omit<HostInfo, '_password'> & { passwordAuth?: true };

/** Result of a single remote command. */
export interface CommandResult {
  stdout: string;
  stderr: string;
  code: number;
}

/** Result of runCommandBatch. */
export interface BatchResult {
  results: CommandResult[];
  success: boolean;
}

/** Result of checkConnectivity. */
export interface ConnectivityResult {
  connected: boolean;
  message: string;
}

/** Environment handed to a spawned ssh/scp process when a password is in play. */
export interface SpawnEnv extends NodeJS.ProcessEnv {
  MCP_SSH_PASS: string;
  SSH_ASKPASS: string;
  SSH_ASKPASS_REQUIRE: string;
}

export interface AdhocSpec {
  host: string;
  user?: string | undefined;
  port?: number | undefined;
  identityFile?: string | undefined;
  proxyJump?: string | undefined;
  password?: string | undefined;
}

export interface TransferFailure {
  code: string;
  message: string;
  exitCode?: number;
}

export interface ConnectionOptions {
  adhoc?: AdhocSpec | undefined;
  timeout?: number | undefined;
  onError?: (error: TransferFailure) => void;
}

export interface TaskStatus {
  state: 'running' | 'exited' | 'stopped' | 'unknown';
  exitCode?: number;
}

export interface BackgroundTask extends Partial<TaskStatus> {
  taskId: string;
  hostAlias: string | null | undefined;
  connection?: AdhocSpec | undefined;
  command: string;
  logPath: string;
  exitPath: string;
  pgidPath: string;
  startedAt: string;
}

export interface BackgroundTaskOptions {
  action?: string | undefined;
  taskId?: string | undefined;
  offset?: number | undefined;
  limit?: number | undefined;
  keepRemote?: boolean | undefined;
  olderThanHours?: number | undefined;
}

export interface PurgeResult {
  removed: string[];
  kept: { taskId: string; reason: string }[];
}

export interface AdhocHostInfo {
  host: string;
  user: string | null;
  port: number | null;
  identityFile: string | null;
  proxyJump: string | null;
  passwordAuth?: boolean;
  source: 'ad-hoc';
  [key: string]: unknown;
}
