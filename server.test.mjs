import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createRequire } from 'module';
import { EventEmitter } from 'events';

const require = createRequire(import.meta.url);
const sshConfigLib = require('ssh-config');

// Mock fs/promises (used via ESM import in server.mjs)
vi.mock('fs/promises', async () => {
  const actual = await vi.importActual('fs/promises');
  return {
    ...actual,
    readFile: vi.fn(),
    stat: vi.fn(),
    writeFile: vi.fn(),
    chmod: vi.fn(),
    unlink: vi.fn(),
  };
});

import { readFile, stat, writeFile, chmod } from 'fs/promises';
import {
  SSHConfigParser,
  SSHClient,
  main,
  shQuote,
  buildTaskStartScript,
  parseTaskHandshake,
  buildTaskStatusScript,
  parseTaskStatus,
  buildTaskStopScript,
  buildTaskLogsScript,
  parseTaskLogs,
  TaskStore,
  taskPaths,
} from './server.mjs';

// Helper: create a fake spawn that returns a mock child process
function createMockSpawn({ stdout = '', stderr = '', code = 0, error = null } = {}) {
  return vi.fn(() => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = vi.fn(() => {
      setTimeout(() => child.emit('close', null), 2);
    });

    setTimeout(() => {
      if (error) {
        child.emit('error', error);
        return;
      }
      if (stdout) child.stdout.emit('data', Buffer.from(stdout));
      if (stderr) child.stderr.emit('data', Buffer.from(stderr));
      child.emit('close', code);
    }, 5);

    return child;
  });
}

// Helper: create a fake execFileAsync
function createMockExecFileAsync({ error = null } = {}) {
  return vi.fn(async () => {
    if (error) throw error;
    return { stdout: '', stderr: '' };
  });
}

const SAMPLE_SSH_CONFIG = `
Host prod
    HostName 157.90.89.149
    Port 42077
    User trashmail

Host mail
    HostName 88.198.170.88
    Port 42078
    User saf
    # @password: killer99

Host nohost
    User nobody
`;

const SAMPLE_SSH_CONFIG_WITH_INCLUDE = `
Include ~/.ssh/configs/*.conf

Host prod
    HostName 157.90.89.149
    User trashmail
`;

const SAMPLE_KNOWN_HOSTS = `157.90.89.149 ssh-ed25519 AAAAC3Nz...
88.198.170.88 ssh-ed25519 AAAAC3Nz...
10.0.0.1 ssh-rsa AAAAB3Nz...
`;

// =============================================================================
// SSHConfigParser Tests
// =============================================================================

describe('SSHConfigParser', () => {
  let parser;

  beforeEach(() => {
    parser = new SSHConfigParser();
    vi.clearAllMocks();
  });

  describe('extractHostsFromConfig', () => {
    it('should parse hosts with hostname, user, port', () => {
      const config = sshConfigLib.parse(SAMPLE_SSH_CONFIG);
      const hosts = parser.extractHostsFromConfig(config, '/home/test/.ssh/config');

      expect(hosts).toHaveLength(2); // nohost has no hostname
      expect(hosts[0]).toMatchObject({
        alias: 'prod',
        hostname: '157.90.89.149',
        port: 42077,
        user: 'trashmail',
      });
    });

    it('should parse @password annotation from comments', () => {
      const config = sshConfigLib.parse(SAMPLE_SSH_CONFIG);
      const hosts = parser.extractHostsFromConfig(config, '/test');
      const mail = hosts.find(h => h.alias === 'mail');
      expect(mail._password).toBe('killer99');
    });

    it('should handle password with colons', () => {
      const config = sshConfigLib.parse(`
Host test
    HostName 1.2.3.4
    # @password:pass:with:colons
`);
      const hosts = parser.extractHostsFromConfig(config, '/test');
      expect(hosts[0]._password).toBe('pass:with:colons');
    });

    it('should handle password with spaces after colon', () => {
      const config = sshConfigLib.parse(`
Host test
    HostName 1.2.3.4
    # @password: spaced
`);
      const hosts = parser.extractHostsFromConfig(config, '/test');
      expect(hosts[0]._password).toBe('spaced');
    });

    it('should skip hosts without hostname', () => {
      const config = sshConfigLib.parse(SAMPLE_SSH_CONFIG);
      const hosts = parser.extractHostsFromConfig(config, '/test');
      expect(hosts.find(h => h.alias === 'nohost')).toBeUndefined();
    });

    it('should skip wildcard host', () => {
      const config = sshConfigLib.parse(`
Host *
    ServerAliveInterval 55

Host myhost
    HostName 1.2.3.4
`);
      const hosts = parser.extractHostsFromConfig(config, '/test');
      expect(hosts).toHaveLength(1);
      expect(hosts[0].alias).toBe('myhost');
    });

    // Regression: ssh-config@5 returns a plain string for a single-token value
    // but an array of token objects for `Host a b`. Storing that array in
    // `alias` made every strict comparison fail, so a multi-alias host was
    // unreachable under *any* of its names.
    it('should expose every alias of a multi-alias Host block', () => {
      const config = sshConfigLib.parse(`
Host docker-lxc hlab
    HostName 10.9.0.105
    User root
`);
      const hosts = parser.extractHostsFromConfig(config, '/test');

      expect(hosts).toHaveLength(1);
      expect(hosts[0].aliases).toEqual(['docker-lxc', 'hlab']);
      expect(hosts[0].alias).toBe('docker-lxc');
      expect(hosts[0].hostname).toBe('10.9.0.105');
    });

    it('should keep alias a string for single-alias hosts', () => {
      const config = sshConfigLib.parse(`
Host solo
    HostName 1.2.3.4
`);
      const hosts = parser.extractHostsFromConfig(config, '/test');

      expect(hosts[0].alias).toBe('solo');
      expect(hosts[0].aliases).toEqual(['solo']);
    });

    it('should skip a wildcard block carrying negations', () => {
      const config = sshConfigLib.parse(`
Host * !bastion
    HostName 7.7.7.7

Host myhost
    HostName 1.2.3.4
`);
      const hosts = parser.extractHostsFromConfig(config, '/test');

      expect(hosts).toHaveLength(1);
      expect(hosts[0].alias).toBe('myhost');
    });

    it('should flatten multi-token directives into a string', () => {
      const config = sshConfigLib.parse(`
Host jump
    HostName localhost
    ProxyCommand ssh bastion -W %h:%p
`);
      const hosts = parser.extractHostsFromConfig(config, '/test');

      expect(hosts[0].proxycommand).toBe('ssh bastion -W %h:%p');
    });

    it('should skip Include directives', () => {
      const config = sshConfigLib.parse(SAMPLE_SSH_CONFIG_WITH_INCLUDE);
      const hosts = parser.extractHostsFromConfig(config, '/test');
      expect(hosts).toHaveLength(1);
      expect(hosts[0].alias).toBe('prod');
    });

    it('should parse identityFile', () => {
      const config = sshConfigLib.parse(`
Host test
    HostName 1.2.3.4
    IdentityFile ~/.ssh/id_rsa
`);
      const hosts = parser.extractHostsFromConfig(config, '/test');
      expect(hosts[0].identityFile).toBe('~/.ssh/id_rsa');
    });

    it('should store other parameters in lowercase', () => {
      const config = sshConfigLib.parse(`
Host test
    HostName 1.2.3.4
    ProxyJump bastion
`);
      const hosts = parser.extractHostsFromConfig(config, '/test');
      expect(hosts.proxyjump || hosts[0].proxyjump).toBe('bastion');
    });

    it('should track configs with passwords', () => {
      const config = sshConfigLib.parse(`
Host test
    HostName 1.2.3.4
    # @password:secret
`);
      parser.extractHostsFromConfig(config, '/my/config');
      expect(parser._configsWithPasswords.has('/my/config')).toBe(true);
    });

    it('should not track configs without passwords', () => {
      const config = sshConfigLib.parse(`
Host test
    HostName 1.2.3.4
`);
      parser.extractHostsFromConfig(config, '/my/config');
      expect(parser._configsWithPasswords).toBeUndefined();
    });

    it('should ignore comment lines that are not @password', () => {
      const config = sshConfigLib.parse(`
Host test
    HostName 1.2.3.4
    # This is a regular comment
    # Another comment
`);
      const hosts = parser.extractHostsFromConfig(config, '/test');
      expect(hosts[0]._password).toBeUndefined();
    });
  });

  describe('parseConfig', () => {
    it('should parse SSH config file', async () => {
      readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
      const hosts = await parser.parseConfig();
      expect(hosts).toHaveLength(2);
    });

    it('should return empty array on read error', async () => {
      readFile.mockRejectedValue(new Error('ENOENT'));
      const hosts = await parser.parseConfig();
      expect(hosts).toEqual([]);
    });
  });

  describe('parseKnownHosts', () => {
    it('should parse known_hosts file', async () => {
      readFile.mockResolvedValue(SAMPLE_KNOWN_HOSTS);
      const hosts = await parser.parseKnownHosts();
      expect(hosts).toEqual(['157.90.89.149', '88.198.170.88', '10.0.0.1']);
    });

    it('should return empty array on read error', async () => {
      readFile.mockRejectedValue(new Error('ENOENT'));
      const hosts = await parser.parseKnownHosts();
      expect(hosts).toEqual([]);
    });

    it('should skip empty lines', async () => {
      readFile.mockResolvedValue('host1 ssh-rsa key\n\n\nhost2 ssh-rsa key\n');
      const hosts = await parser.parseKnownHosts();
      expect(hosts).toEqual(['host1', 'host2']);
    });

    it('should handle comma-separated hostnames', async () => {
      readFile.mockResolvedValue('host1,host2 ssh-rsa key\n');
      const hosts = await parser.parseKnownHosts();
      expect(hosts).toEqual(['host1']);
    });
  });

  describe('checkFilePermissions', () => {
    it('should pass with 600 permissions', async () => {
      stat.mockResolvedValue({ mode: 0o100600 });
      await expect(parser.checkFilePermissions('/test')).resolves.not.toThrow();
    });

    it('should throw on insecure permissions (644)', async () => {
      stat.mockResolvedValue({ mode: 0o100644 });
      await expect(parser.checkFilePermissions('/test')).rejects.toThrow('insecure permissions');
    });

    it('should throw on insecure permissions (755)', async () => {
      stat.mockResolvedValue({ mode: 0o100755 });
      await expect(parser.checkFilePermissions('/test')).rejects.toThrow('insecure permissions');
    });

    it('should include chmod hint in error message', async () => {
      stat.mockResolvedValue({ mode: 0o100644 });
      await expect(parser.checkFilePermissions('/test')).rejects.toThrow('chmod 600');
    });

    it('should ignore ENOENT errors', async () => {
      const err = new Error('not found');
      err.code = 'ENOENT';
      stat.mockRejectedValue(err);
      await expect(parser.checkFilePermissions('/test')).resolves.not.toThrow();
    });

    it('should rethrow other errors', async () => {
      stat.mockRejectedValue(new Error('disk failure'));
      await expect(parser.checkFilePermissions('/test')).rejects.toThrow('disk failure');
    });
  });

  describe('getAllKnownHosts', () => {
    it('should merge config hosts and known_hosts, deduplicating', async () => {
      readFile
        .mockResolvedValueOnce(SAMPLE_SSH_CONFIG)
        .mockResolvedValueOnce(SAMPLE_KNOWN_HOSTS);
      stat.mockResolvedValue({ mode: 0o100600 });

      const hosts = await parser.getAllKnownHosts();

      const configHosts = hosts.filter(h => h.source === 'ssh_config');
      const knownHosts = hosts.filter(h => h.source === 'known_hosts');

      expect(configHosts).toHaveLength(2);
      expect(knownHosts).toHaveLength(1);
      expect(knownHosts[0].hostname).toBe('10.0.0.1');
    });

    it('should check permissions for configs with passwords', async () => {
      readFile
        .mockResolvedValueOnce(SAMPLE_SSH_CONFIG)
        .mockResolvedValueOnce(SAMPLE_KNOWN_HOSTS);
      stat.mockResolvedValue({ mode: 0o100600 });

      await parser.getAllKnownHosts();
      expect(stat).toHaveBeenCalled();
    });

    it('should work with empty known_hosts', async () => {
      readFile
        .mockResolvedValueOnce(SAMPLE_SSH_CONFIG)
        .mockRejectedValueOnce(new Error('ENOENT'));
      stat.mockResolvedValue({ mode: 0o100600 });

      const hosts = await parser.getAllKnownHosts();
      expect(hosts).toHaveLength(2);
    });
  });

  describe('processIncludeDirectives', () => {
    it('should return empty array on read error', async () => {
      readFile.mockRejectedValue(new Error('ENOENT'));
      const hosts = await parser.processIncludeDirectives('/nonexistent');
      expect(hosts).toEqual([]);
    });

    it('should parse config without includes', async () => {
      readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
      const hosts = await parser.processIncludeDirectives('/test/.ssh/config');
      expect(hosts).toHaveLength(2);
    });

    it('should process Include directives and merge hosts', async () => {
      const mainConfig = `
Include /tmp/included.conf

Host main
    HostName 1.2.3.4
`;
      const includedConfig = `
Host included
    HostName 5.6.7.8
`;
      readFile
        .mockResolvedValueOnce(mainConfig)
        .mockResolvedValueOnce(includedConfig);

      // Mock expandIncludePath to return the include path
      parser.expandIncludePath = vi.fn().mockReturnValue(['/tmp/included.conf']);

      const hosts = await parser.processIncludeDirectives('/test/.ssh/config');
      expect(hosts).toHaveLength(2);
      expect(hosts.map(h => h.alias)).toContain('included');
      expect(hosts.map(h => h.alias)).toContain('main');
    });

    it('should handle errors in included files gracefully', async () => {
      const mainConfig = `
Include /tmp/broken.conf

Host main
    HostName 1.2.3.4
`;
      // First call reads main config, second call for included file rejects
      // processIncludeDirectives catches this internally and returns []
      readFile
        .mockResolvedValueOnce(mainConfig)
        .mockRejectedValueOnce(new Error('permission denied'));

      parser.expandIncludePath = vi.fn().mockReturnValue(['/tmp/broken.conf']);

      const hosts = await parser.processIncludeDirectives('/test/.ssh/config');
      // Should still return hosts from main config (included returns [] on error)
      expect(hosts).toHaveLength(1);
      expect(hosts[0].alias).toBe('main');
    });
  });

  describe('expandIncludePath', () => {
    it('should expand tilde paths', () => {
      const result = parser.expandIncludePath('~/nonexistent-path-xyz', '/base');
      expect(result).toEqual([]);
    });

    it('should handle relative paths', () => {
      const result = parser.expandIncludePath('relative/path', '/base/config');
      expect(result).toEqual([]);
    });

    it('should return empty for non-existent absolute paths', () => {
      const result = parser.expandIncludePath('/nonexistent-absolute-path-xyz', '/base');
      expect(result).toEqual([]);
    });

    it('should treat Windows drive-letter paths as absolute', () => {
      const result = parser.expandIncludePath('C:\\nonexistent-absolute-path-xyz', '/base/config');
      expect(result).toEqual([]);
    });

    it('should treat UNC paths as absolute', () => {
      const result = parser.expandIncludePath('\\\\server\\share\\nonexistent-path-xyz', '/base/config');
      expect(result).toEqual([]);
    });

    it('should expand tilde paths with backslashes', () => {
      const result = parser.expandIncludePath('~\\nonexistent-path-xyz', '/base');
      expect(result).toEqual([]);
    });

    it('should return empty for non-existent glob patterns', () => {
      const result = parser.expandIncludePath('/nonexistent-path-xyz/*.conf', '/base');
      expect(result).toEqual([]);
    });

    it('should handle errors in glob/existsSync gracefully', () => {
      // Temporarily break require('fs').existsSync to trigger catch
      const fs = require('fs');
      const origExistsSync = fs.existsSync;
      fs.existsSync = () => { throw new Error('fs broken'); };

      const result = parser.expandIncludePath('/some/path/file', '/base');
      expect(result).toEqual([]);

      fs.existsSync = origExistsSync;
    });
  });
});

// =============================================================================
// SSHClient Tests
// =============================================================================

describe('SSHClient', () => {
  let client;

  beforeEach(() => {
    client = new SSHClient();
    vi.clearAllMocks();
  });

  describe('getPasswordForHost', () => {
    beforeEach(() => {
      readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
    });

    it('should find password by alias', async () => {
      const pw = await client.getPasswordForHost('mail');
      expect(pw).toBe('killer99');
    });

    it('should return null for host without password', async () => {
      const pw = await client.getPasswordForHost('prod');
      expect(pw).toBeNull();
    });

    it('should return null for unknown host', async () => {
      const pw = await client.getPasswordForHost('unknown');
      expect(pw).toBeNull();
    });

    it('should strip user@ prefix', async () => {
      const pw = await client.getPasswordForHost('saf@mail');
      expect(pw).toBe('killer99');
    });

    it('should find password by hostname', async () => {
      const pw = await client.getPasswordForHost('88.198.170.88');
      expect(pw).toBe('killer99');
    });
  });

  describe('getAskpassScript', () => {
    it('should create askpass script and cache it', async () => {
      writeFile.mockResolvedValue();
      chmod.mockResolvedValue();

      const path1 = await client.getAskpassScript();
      const path2 = await client.getAskpassScript();

      expect(path1).toBe(path2);
      expect(writeFile).toHaveBeenCalledTimes(1);
      expect(chmod).toHaveBeenCalledWith(path1, 0o700);
    });

    it('should write correct script content', async () => {
      writeFile.mockResolvedValue();
      chmod.mockResolvedValue();

      await client.getAskpassScript();

      expect(writeFile).toHaveBeenCalledWith(
        expect.stringContaining('mcp-ssh-askpass'),
        '#!/bin/sh\necho "$MCP_SSH_PASS"\n'
      );
    });
  });

  describe('buildSpawnEnv', () => {
    it('should return null for host without password', async () => {
      readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
      const env = await client.buildSpawnEnv('prod');
      expect(env).toBeNull();
    });

    it('should return env with SSH_ASKPASS for host with password', async () => {
      readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
      stat.mockResolvedValue({ mode: 0o100600 });
      writeFile.mockResolvedValue();
      chmod.mockResolvedValue();

      const env = await client.buildSpawnEnv('mail');
      expect(env.MCP_SSH_PASS).toBe('killer99');
      expect(env.SSH_ASKPASS).toContain('mcp-ssh-askpass');
      expect(env.SSH_ASKPASS_REQUIRE).toBe('force');
      expect(env.DISPLAY).toBe(process.env.DISPLAY);
    });

    it('should throw if config has insecure permissions', async () => {
      readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
      stat.mockResolvedValue({ mode: 0o100644 });

      // Trigger password parsing first
      await client.getPasswordForHost('mail');

      await expect(client.buildSpawnEnv('mail')).rejects.toThrow('insecure permissions');
    });
  });

  describe('runRemoteCommand', () => {
    beforeEach(() => {
      readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
    });

    it('should execute ssh command and return output', async () => {
      client._spawn = createMockSpawn({ stdout: 'hello\n', code: 0 });

      const result = await client.runRemoteCommand('test', 'echo hello');

      expect(client._spawn).toHaveBeenCalledWith(
        'ssh',
        ['-o', 'StrictHostKeyChecking=accept-new', '--', 'test', 'echo hello'],
        expect.any(Object)
      );
      expect(result).toEqual({ stdout: 'hello\n', stderr: '', code: 0 });
    });

    it('should handle command failure with exit code', async () => {
      client._spawn = createMockSpawn({ stderr: 'not found', code: 127 });

      const result = await client.runRemoteCommand('test', 'badcmd');
      expect(result.code).toBe(127);
      expect(result.stderr).toBe('not found');
    });

    it('should handle spawn error', async () => {
      client._spawn = createMockSpawn({ error: new Error('spawn failed') });

      const result = await client.runRemoteCommand('test', 'cmd');
      expect(result.code).toBe(1);
      expect(result.stderr).toBe('spawn failed');
    });

    it('should handle timeout', async () => {
      client._spawn = vi.fn(() => {
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn(() => {
          setTimeout(() => child.emit('close', null), 2);
        });
        return child;
      });

      const result = await client.runRemoteCommand('test', 'sleep 999', { timeout: 10 });
      expect(result.code).toBe(124);
      expect(result.stderr).toContain('Command timed out');
    });

    it('should set detached and env when password is available', async () => {
      readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
      stat.mockResolvedValue({ mode: 0o100600 });
      writeFile.mockResolvedValue();
      chmod.mockResolvedValue();
      client._spawn = createMockSpawn({ stdout: 'ok', code: 0 });

      await client.runRemoteCommand('mail', 'ls');

      expect(client._spawn).toHaveBeenCalledWith(
        'ssh',
        expect.any(Array),
        expect.objectContaining({
          detached: true,
          env: expect.objectContaining({
            MCP_SSH_PASS: 'killer99',
            SSH_ASKPASS_REQUIRE: 'force',
          }),
        })
      );
    });

    it('should not set detached without password', async () => {
      client._spawn = createMockSpawn({ stdout: 'ok', code: 0 });

      await client.runRemoteCommand('test', 'ls');

      expect(client._spawn).toHaveBeenCalledWith(
        'ssh',
        expect.any(Array),
        expect.objectContaining({
          stdio: ['ignore', 'pipe', 'pipe'],
        })
      );
      const opts = client._spawn.mock.calls[0][2];
      expect(opts.detached).toBeUndefined();
      expect(opts.env).toBeUndefined();
    });

    it('should truncate stdout exceeding 10MB', async () => {
      client._spawn = vi.fn(() => {
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();

        setTimeout(() => {
          // Send in two chunks so the second one triggers truncation
          child.stdout.emit('data', Buffer.from('x'.repeat(10 * 1024 * 1024)));
          child.stdout.emit('data', Buffer.from('x'.repeat(1024)));
          child.emit('close', 0);
        }, 5);

        return child;
      });

      const result = await client.runRemoteCommand('test', 'bigcmd');
      expect(result.stdout).toContain('[Output truncated');
    });

    it('should reject hostAlias starting with - to block ProxyCommand injection', async () => {
      client._spawn = createMockSpawn({ stdout: 'pwned', code: 0 });

      await expect(
        client.runRemoteCommand('-oProxyCommand=touch /tmp/pwned', 'echo')
      ).rejects.toThrow(/Invalid hostAlias/);
      expect(client._spawn).not.toHaveBeenCalled();
    });

    it('should reject hostAlias containing shell metacharacters (Windows cmd.exe vector)', async () => {
      client._spawn = createMockSpawn({ stdout: '', code: 0 });

      for (const evil of ['foo & calc.exe', 'foo|calc', 'foo;ls', 'foo`id`', 'foo$(id)', 'foo"bar', "foo'bar"]) {
        await expect(client.runRemoteCommand(evil, 'ls')).rejects.toThrow(/Invalid hostAlias/);
      }
      expect(client._spawn).not.toHaveBeenCalled();
    });

    it('should reject unknown hostAlias that is not in ssh config or known_hosts', async () => {
      readFile
        .mockResolvedValueOnce(`Host test\n    HostName 1.2.3.4\n`)
        .mockResolvedValueOnce('');
      client._spawn = createMockSpawn({ stdout: '', code: 0 });

      await expect(client.runRemoteCommand('unknown.example.com', 'ls')).rejects.toThrow(/Unknown hostAlias/);
      expect(client._spawn).not.toHaveBeenCalled();
    });

    it('should allow user@alias when alias exists in ssh config', async () => {
      client._spawn = createMockSpawn({ stdout: 'ok\n', code: 0 });

      const result = await client.runRemoteCommand('root@test', 'whoami');

      expect(client._spawn).toHaveBeenCalledWith(
        'ssh',
        ['-o', 'StrictHostKeyChecking=accept-new', '--', 'root@test', 'whoami'],
        expect.any(Object)
      );
      expect(result.code).toBe(0);
    });

    it('should allow hosts discovered through Include directives', async () => {
      readFile.mockImplementation(async (filePath) => {
        if (String(filePath).endsWith('/config')) return SAMPLE_SSH_CONFIG_WITH_INCLUDE;
        if (String(filePath).endsWith('.conf')) return `Host included\n    HostName 10.10.10.10\n`;
        if (String(filePath).endsWith('known_hosts')) return '';
        return '';
      });
      client.configParser.expandIncludePath = vi.fn(() => ['/tmp/included.conf']);
      client._spawn = createMockSpawn({ stdout: 'ok\n', code: 0 });

      const result = await client.runRemoteCommand('included', 'hostname');

      expect(client._spawn).toHaveBeenCalled();
      expect(result.code).toBe(0);
    });

    it('should truncate stderr exceeding 10MB', async () => {
      client._spawn = vi.fn(() => {
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();

        setTimeout(() => {
          child.stderr.emit('data', Buffer.from('x'.repeat(10 * 1024 * 1024)));
          child.stderr.emit('data', Buffer.from('x'.repeat(1024)));
          child.emit('close', 0);
        }, 5);

        return child;
      });

      const result = await client.runRemoteCommand('test', 'bigcmd');
      expect(result.stderr).toContain('[Stderr truncated');
    });
  });

  describe('getHostInfo', () => {
    beforeEach(() => {
      readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
    });

    it('should return host info without password exposed', async () => {
      const info = await client.getHostInfo('mail');
      expect(info.alias).toBe('mail');
      expect(info.hostname).toBe('88.198.170.88');
      expect(info._password).toBeUndefined();
      expect(info.passwordAuth).toBe(true);
    });

    it('should not set passwordAuth flag when no password', async () => {
      const info = await client.getHostInfo('prod');
      expect(info.passwordAuth).toBeUndefined();
    });

    it('should return null for unknown host', async () => {
      const info = await client.getHostInfo('nonexistent');
      expect(info).toBeNull();
    });

    it('should return correct port and user', async () => {
      const info = await client.getHostInfo('prod');
      expect(info.port).toBe(42077);
      expect(info.user).toBe('trashmail');
    });
  });

  describe('checkConnectivity', () => {
    beforeEach(() => {
      readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
    });

    it('should return connected on success', async () => {
      client._spawn = createMockSpawn({ stdout: 'connected\n', code: 0 });

      const status = await client.checkConnectivity('test');
      expect(status).toEqual({ connected: true, message: 'Connection successful' });
    });

    it('should return not connected on failure', async () => {
      client._spawn = createMockSpawn({ stderr: 'refused', code: 255 });

      const status = await client.checkConnectivity('test');
      expect(status).toEqual({ connected: false, message: 'Connection failed' });
    });

    it('should return not connected when output is unexpected', async () => {
      client._spawn = createMockSpawn({ stdout: 'something else', code: 0 });

      const status = await client.checkConnectivity('test');
      expect(status.connected).toBe(false);
    });
  });

  describe('uploadFile', () => {
    beforeEach(() => {
      readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
    });

    it('should return true on success', async () => {
      client._execFileAsync = createMockExecFileAsync();

      const result = await client.uploadFile('test', '/local/file', '/remote/file');
      expect(result).toBe(true);
      expect(client._execFileAsync).toHaveBeenCalledWith(
        'scp',
        ['-o', 'StrictHostKeyChecking=accept-new', '--', '/local/file', 'test:/remote/file'],
        expect.any(Object)
      );
    });

    it('should return false on error', async () => {
      client._execFileAsync = createMockExecFileAsync({ error: new Error('scp failed') });

      const result = await client.uploadFile('test', '/local/file', '/remote/file');
      expect(result).toBe(false);
    });

    it('should pass password env when available', async () => {
      readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
      stat.mockResolvedValue({ mode: 0o100600 });
      writeFile.mockResolvedValue();
      chmod.mockResolvedValue();
      client._execFileAsync = createMockExecFileAsync();

      await client.uploadFile('mail', '/local/file', '/remote/file');

      const opts = client._execFileAsync.mock.calls[0][2];
      expect(opts.env.MCP_SSH_PASS).toBe('killer99');
    });

    it('should reject hostAlias starting with - to block ProxyCommand injection', async () => {
      client._execFileAsync = createMockExecFileAsync();

      const result = await client.uploadFile('-oProxyCommand=touch /tmp/pwned', '/local/file', '/remote/file');
      expect(result).toBe(false);
      expect(client._execFileAsync).not.toHaveBeenCalled();
    });

    it('should reject unknown hostAlias for uploads', async () => {
      readFile
        .mockResolvedValueOnce(`Host test\n    HostName 1.2.3.4\n`)
        .mockResolvedValueOnce('');
      client._execFileAsync = createMockExecFileAsync();

      const result = await client.uploadFile('unknown.example.com', '/local/file', '/remote/file');
      expect(result).toBe(false);
      expect(client._execFileAsync).not.toHaveBeenCalled();
    });
  });

  describe('downloadFile', () => {
    beforeEach(() => {
      readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
    });

    it('should return true on success', async () => {
      client._execFileAsync = createMockExecFileAsync();

      const result = await client.downloadFile('test', '/remote/file', '/local/file');
      expect(result).toBe(true);
      expect(client._execFileAsync).toHaveBeenCalledWith(
        'scp',
        ['-o', 'StrictHostKeyChecking=accept-new', '--', 'test:/remote/file', '/local/file'],
        expect.any(Object)
      );
    });

    it('should return false on error', async () => {
      client._execFileAsync = createMockExecFileAsync({ error: new Error('scp failed') });

      const result = await client.downloadFile('test', '/remote/file', '/local/file');
      expect(result).toBe(false);
    });

    it('should reject hostAlias starting with - to block ProxyCommand injection', async () => {
      client._execFileAsync = createMockExecFileAsync();

      const result = await client.downloadFile('-oProxyCommand=touch /tmp/pwned', '/remote/file', '/local/file');
      expect(result).toBe(false);
      expect(client._execFileAsync).not.toHaveBeenCalled();
    });

    it('should allow hostnames learned from known_hosts for downloads', async () => {
      readFile
        .mockResolvedValueOnce(`Host test\n    HostName 1.2.3.4\n`)
        .mockResolvedValueOnce('10.0.0.1 ssh-rsa AAAAB3Nz...\n');
      client._execFileAsync = createMockExecFileAsync();

      const result = await client.downloadFile('10.0.0.1', '/remote/file', '/local/file');
      expect(result).toBe(true);
      expect(client._execFileAsync).toHaveBeenCalled();
    });
  });

  describe('runCommandBatch', () => {
    beforeEach(() => {
      readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
    });

    it('should execute multiple commands and return results', async () => {
      let callCount = 0;
      client._spawn = vi.fn(() => {
        callCount++;
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();
        const n = callCount;
        setTimeout(() => {
          child.stdout.emit('data', Buffer.from(`output${n}\n`));
          child.emit('close', 0);
        }, 5);
        return child;
      });

      const result = await client.runCommandBatch('test', ['cmd1', 'cmd2']);
      expect(result.success).toBe(true);
      expect(result.results).toHaveLength(2);
      expect(result.results[0].stdout).toBe('output1\n');
      expect(result.results[1].stdout).toBe('output2\n');
    });

    it('should mark as failed if any command fails but continue', async () => {
      let callCount = 0;
      client._spawn = vi.fn(() => {
        callCount++;
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();
        const exitCode = callCount === 1 ? 1 : 0;
        setTimeout(() => {
          child.emit('close', exitCode);
        }, 5);
        return child;
      });

      const result = await client.runCommandBatch('test', ['fail', 'pass']);
      expect(result.success).toBe(false);
      expect(result.results).toHaveLength(2);
    });

    it('should handle empty command list', async () => {
      const result = await client.runCommandBatch('test', []);
      expect(result.success).toBe(true);
      expect(result.results).toHaveLength(0);
    });
  });

  describe('listKnownHosts', () => {
    it('should delegate to configParser.getAllKnownHosts', async () => {
      readFile
        .mockResolvedValueOnce(SAMPLE_SSH_CONFIG)
        .mockResolvedValueOnce(SAMPLE_KNOWN_HOSTS);
      stat.mockResolvedValue({ mode: 0o100600 });

      const hosts = await client.listKnownHosts();
      expect(hosts.length).toBeGreaterThan(0);
    });
  });

  describe('checkConnectivity error handling', () => {
    it('should handle thrown errors gracefully', async () => {
      readFile.mockRejectedValue(new Error('config read failed'));
      client._spawn = createMockSpawn({ stderr: 'error', code: 1 });

      const status = await client.checkConnectivity('test');
      expect(status.connected).toBe(false);
    });

    it('should catch exceptions from runRemoteCommand', async () => {
      client.runRemoteCommand = vi.fn().mockRejectedValue(new Error('ssh crash'));

      const status = await client.checkConnectivity('test');
      expect(status.connected).toBe(false);
      expect(status.message).toBe('ssh crash');
    });

    it('should handle non-Error thrown values in catch', async () => {
      client.runRemoteCommand = vi.fn().mockRejectedValue('string error');

      const status = await client.checkConnectivity('test');
      expect(status.connected).toBe(false);
      expect(status.message).toBe('string error');
    });
  });

  describe('runCommandBatch error handling', () => {
    it('should handle thrown errors gracefully', async () => {
      // Make runRemoteCommand throw by overriding it
      client.runRemoteCommand = vi.fn().mockRejectedValue(new Error('connection lost'));

      const result = await client.runCommandBatch('test', ['cmd1']);
      expect(result.success).toBe(false);
      expect(result.results[0].stderr).toBe('connection lost');
      expect(result.results[0].code).toBe(1);
    });

    it('should handle non-Error thrown values', async () => {
      client.runRemoteCommand = vi.fn().mockRejectedValue('string error');

      const result = await client.runCommandBatch('test', ['cmd1']);
      expect(result.success).toBe(false);
      expect(result.results[0].stderr).toBe('string error');
    });
  });
});

// =============================================================================
// MCP Server Handler Tests (via main())
// =============================================================================

describe('MCP Server Handlers', () => {
  let server;
  let handlers;

  beforeEach(async () => {
    vi.clearAllMocks();

    // Capture the request handlers that main() registers
    handlers = {};

    // Mock the MCP SDK Server and Transport
    const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
    const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');

    // Save original and mock
    const origSetRequestHandler = Server.prototype.setRequestHandler;
    const origConnect = Server.prototype.connect;

    Server.prototype.setRequestHandler = function(schema, handler) {
      // Store by schema name
      if (schema === require('@modelcontextprotocol/sdk/types.js').ListToolsRequestSchema) {
        handlers.listTools = handler;
      } else if (schema === require('@modelcontextprotocol/sdk/types.js').CallToolRequestSchema) {
        handlers.callTool = handler;
      }
    };
    Server.prototype.connect = vi.fn().mockResolvedValue();

    readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
    stat.mockResolvedValue({ mode: 0o100600 });

    await main();

    // Restore
    Server.prototype.setRequestHandler = origSetRequestHandler;
    Server.prototype.connect = origConnect;
  });

  it('should register listTools handler that returns all tools', async () => {
    const result = await handlers.listTools();
    expect(result.tools).toHaveLength(8);
    const names = result.tools.map(t => t.name);
    expect(names).toContain('listKnownHosts');
    expect(names).toContain('runRemoteCommand');
    expect(names).toContain('getHostInfo');
    expect(names).toContain('checkConnectivity');
    expect(names).toContain('uploadFile');
    expect(names).toContain('downloadFile');
    expect(names).toContain('runCommandBatch');
  });

  it('should handle listKnownHosts tool call', async () => {
    readFile
      .mockResolvedValueOnce(SAMPLE_SSH_CONFIG)
      .mockResolvedValueOnce(SAMPLE_KNOWN_HOSTS);

    const result = await handlers.callTool({
      params: { name: 'listKnownHosts', arguments: {} }
    });

    const hosts = JSON.parse(result.content[0].text);
    expect(Array.isArray(hosts)).toBe(true);
    // Passwords should be stripped
    for (const host of hosts) {
      expect(host._password).toBeUndefined();
    }
  });

  it('should handle getHostInfo tool call', async () => {
    readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);

    const result = await handlers.callTool({
      params: { name: 'getHostInfo', arguments: { hostAlias: 'mail' } }
    });

    const info = JSON.parse(result.content[0].text);
    expect(info.alias).toBe('mail');
    expect(info._password).toBeUndefined();
    expect(info.passwordAuth).toBe(true);
  });

  it('should throw on missing arguments', async () => {
    await expect(
      handlers.callTool({ params: { name: 'runRemoteCommand', arguments: undefined } })
    ).rejects.toThrow('No arguments provided');
  });

  it('should handle unknown tool name', async () => {
    const result = await handlers.callTool({
      params: { name: 'unknownTool', arguments: {} }
    });

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toContain('Unknown tool');
  });

  it('should cap runRemoteCommand timeout at 300000ms', async () => {
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);

    const result = await handlers.callTool({
      params: {
        name: 'runRemoteCommand',
        arguments: { hostAlias: 'test', command: 'echo hi', timeout: 999999 }
      }
    });

    expect(result.content[0].type).toBe('text');
  });

  it('should handle checkConnectivity tool call', async () => {
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);

    const result = await handlers.callTool({
      params: { name: 'checkConnectivity', arguments: { hostAlias: 'test' } }
    });

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('connected');
    expect(parsed).toHaveProperty('message');
  });

  it('should handle uploadFile tool call', async () => {
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);

    const result = await handlers.callTool({
      params: {
        name: 'uploadFile',
        arguments: { hostAlias: 'test', localPath: '/tmp/test', remotePath: '/tmp/dest' }
      }
    });

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('success');
  });

  it('should handle downloadFile tool call', async () => {
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);

    const result = await handlers.callTool({
      params: {
        name: 'downloadFile',
        arguments: { hostAlias: 'test', remotePath: '/tmp/src', localPath: '/tmp/dest' }
      }
    });

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('success');
  });

  it('should handle runCommandBatch tool call', async () => {
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);

    const result = await handlers.callTool({
      params: {
        name: 'runCommandBatch',
        arguments: { hostAlias: 'test', commands: ['echo a', 'echo b'] }
      }
    });

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('results');
    expect(parsed).toHaveProperty('success');
  });

  it('should allow listKnownHosts without arguments', async () => {
    readFile
      .mockResolvedValueOnce(SAMPLE_SSH_CONFIG)
      .mockResolvedValueOnce(SAMPLE_KNOWN_HOSTS);

    const result = await handlers.callTool({
      params: { name: 'listKnownHosts' }
    });

    const hosts = JSON.parse(result.content[0].text);
    expect(Array.isArray(hosts)).toBe(true);
  });
});

// =============================================================================
// main() error handling
// =============================================================================

describe('main() error handling', () => {
  it('should handle startup errors gracefully', async () => {
    const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
    const origConnect = Server.prototype.connect;

    Server.prototype.connect = vi.fn().mockRejectedValue(new Error('transport failed'));

    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => {});

    await main();

    expect(exitSpy).toHaveBeenCalledWith(1);

    Server.prototype.connect = origConnect;
    exitSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// Background tasks
//
// A detached task lives on the *remote* side: setsid puts it in its own process
// group, stdout/stderr go to a log file, and the exit code lands in a file when
// it finishes. Locally we only keep a registry. That survives an MCP restart and
// a dropped connection, which a locally-detached child process would not.
// ---------------------------------------------------------------------------
describe('background tasks', () => {
  describe('shQuote', () => {
    it('wraps a plain value in single quotes', () => {
      expect(shQuote('hello')).toBe("'hello'");
    });

    it('neutralizes embedded single quotes', () => {
      // The classic break-out attempt: '; touch /tmp/pwned ; echo '
      const quoted = shQuote("'; touch /tmp/pwned ; echo '");
      expect(quoted).toBe(`''"'"'; touch /tmp/pwned ; echo '"'"''`);
    });

    it('leaves shell metacharacters inert', () => {
      for (const raw of ['$(whoami)', '`id`', 'a && b', 'x | y', '$HOME', 'a\nb']) {
        const quoted = shQuote(raw);
        expect(quoted.startsWith("'")).toBe(true);
        expect(quoted.endsWith("'")).toBe(true);
      }
    });
  });

  describe('buildTaskStartScript', () => {
    const opts = { taskId: 'abc123', command: 'sleep 60', root: '$HOME/.mcp-ssh/tasks' };

    it('detaches via setsid so the task outlives the ssh session', () => {
      expect(buildTaskStartScript(opts)).toContain('setsid');
    });

    it('redirects output to the log and detaches stdin', () => {
      const script = buildTaskStartScript(opts);
      expect(script).toContain('abc123.log');
      expect(script).toContain('< /dev/null');
    });

    it('records the exit code in the exit file when the command finishes', () => {
      expect(buildTaskStartScript(opts)).toContain('abc123.exit');
    });

    it('has the child record its own process group, avoiding a startup race', () => {
      const script = buildTaskStartScript(opts);
      expect(script).toContain('abc123.pgid');
      // No fixed sleep: the parent must not guess how long the child needs.
      expect(script).not.toMatch(/sleep\s+0\.\d+/);
    });

    it('quotes the command so metacharacters cannot escape', () => {
      const payload = "echo 'hi'; touch /tmp/pwned";
      const script = buildTaskStartScript({ ...opts, command: payload });
      expect(script).toContain(shQuote(payload));
    });

    it('emits a handshake carrying the task id', () => {
      expect(buildTaskStartScript(opts)).toContain('__MCP_TASK_STARTED=abc123');
    });

    // Regression: `eval "$1"` runs in the current shell, so a command ending in
    // `exit 3` killed the wrapper before it could record the exit code — the
    // task then looked 'unknown' forever despite having finished. Running the
    // command in a subshell keeps the bookkeeping alive.
    it('runs the command in a subshell so `exit N` cannot skip the bookkeeping', () => {
      const script = buildTaskStartScript(opts);
      expect(script).toMatch(/\(\s*eval "\$1"\s*\)/);
    });
  });

  describe('parseTaskHandshake', () => {
    it('accepts the handshake for the expected task', () => {
      expect(parseTaskHandshake('noise\n__MCP_TASK_STARTED=abc123\n', 'abc123')).toBe(true);
    });

    it('rejects a handshake for a different task', () => {
      expect(parseTaskHandshake('__MCP_TASK_STARTED=other\n', 'abc123')).toBe(false);
    });

    it('rejects missing output', () => {
      expect(parseTaskHandshake('', 'abc123')).toBe(false);
    });
  });

  describe('parseTaskStatus', () => {
    it('reports a finished task with its exit code', () => {
      expect(parseTaskStatus('__MCP_TASK_EXIT=0\n')).toEqual({ state: 'exited', exitCode: 0 });
    });

    it('preserves a non-zero exit code', () => {
      expect(parseTaskStatus('__MCP_TASK_EXIT=137\n')).toEqual({ state: 'exited', exitCode: 137 });
    });

    it('reports a running task when the exit file is absent', () => {
      expect(parseTaskStatus('__MCP_TASK_RUNNING=true\n')).toEqual({ state: 'running' });
    });

    it('falls back to unknown when the host says nothing useful', () => {
      expect(parseTaskStatus('')).toEqual({ state: 'unknown' });
    });
  });

  describe('buildTaskStatusScript', () => {
    it('treats the exit file as the source of truth', () => {
      const script = buildTaskStatusScript({ exitPath: '/t/a.exit', pgidPath: '/t/a.pgid' });
      expect(script).toContain('/t/a.exit');
      expect(script).toContain('__MCP_TASK_EXIT=');
    });
  });

  describe('buildTaskStopScript', () => {
    it('signals the whole process group, not just the leader', () => {
      const script = buildTaskStopScript('/t/a.pgid');
      expect(script).toMatch(/kill\s+-TERM\s+--\s+-/);
    });

    it('escalates to KILL if the group survives', () => {
      expect(buildTaskStopScript('/t/a.pgid')).toMatch(/kill\s+-KILL\s+--\s+-/);
    });

    it('refuses to signal when the pgid file is empty', () => {
      // Guards against signalling an unintended process group.
      expect(buildTaskStopScript('/t/a.pgid')).toContain('__MCP_TASK_STOPPED=unknown');
    });
  });

  describe('buildTaskLogsScript', () => {
    it('reads from the requested offset', () => {
      expect(buildTaskLogsScript('/t/a.log', 100, 4096)).toContain('skip=100');
    });

    it('base64-encodes so binary output survives the round trip', () => {
      expect(buildTaskLogsScript('/t/a.log', 0, 4096)).toContain('base64');
    });
  });
});

describe('parseTaskLogs', () => {
  it('decodes the base64 payload', () => {
    expect(parseTaskLogs('__MCP_TASK_SIZE=5\n__MCP_TASK_LOG=aGVsbG8=')).toEqual({
      size: 5,
      content: 'hello',
    });
  });

  it('reports an empty log rather than throwing', () => {
    expect(parseTaskLogs('')).toEqual({ size: 0, content: '' });
  });

  it('survives bytes that are not valid text', () => {
    const raw = Buffer.from([0x00, 0xff, 0x41]).toString('base64');
    const parsed = parseTaskLogs(`__MCP_TASK_SIZE=3\n__MCP_TASK_LOG=${raw}`);
    expect(parsed.size).toBe(3);
    expect(parsed.content).toContain('A');
  });
});

describe('TaskStore', () => {
  let store;

  beforeEach(() => {
    vi.clearAllMocks();
    store = new TaskStore('/tmp/tasks.json');
  });

  it('starts empty when the registry file does not exist', async () => {
    readFile.mockRejectedValue(Object.assign(new Error('nope'), { code: 'ENOENT' }));
    expect(await store.list()).toEqual([]);
  });

  it('starts empty when the registry file is corrupt', async () => {
    // A half-written file must not brick every future task call.
    readFile.mockResolvedValue('{not json');
    expect(await store.list()).toEqual([]);
  });

  it('persists an added task', async () => {
    readFile.mockRejectedValue(Object.assign(new Error('nope'), { code: 'ENOENT' }));
    writeFile.mockResolvedValue();

    await store.add({ taskId: 't1', hostAlias: 'web', state: 'running' });

    expect(writeFile).toHaveBeenCalled();
    const written = JSON.parse(writeFile.mock.calls[0][1]);
    expect(written.t1).toMatchObject({ taskId: 't1', hostAlias: 'web' });
  });

  it('merges a patch into an existing task', async () => {
    readFile.mockResolvedValue(JSON.stringify({ t1: { taskId: 't1', state: 'running' } }));
    writeFile.mockResolvedValue();

    const updated = await store.update('t1', { state: 'exited', exitCode: 0 });

    expect(updated).toMatchObject({ taskId: 't1', state: 'exited', exitCode: 0 });
  });

  it('returns null for an unknown task', async () => {
    readFile.mockResolvedValue('{}');
    expect(await store.get('missing')).toBeNull();
  });
});

describe('SSHClient background tasks', () => {
  let client;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new SSHClient();
    client._execFileAsync = createMockExecFileAsync();
    // A host must exist, otherwise the whitelist gate rejects before we start.
    readFile.mockResolvedValue('Host web\n    HostName 1.2.3.4\n');
  });

  it('starts a task and hands back its id', async () => {
    client._spawn = createMockSpawn({ stdout: '__MCP_TASK_STARTED=' });
    // The handshake must carry the generated id, so echo it back verbatim.
    client._spawn = vi.fn((bin, args) => {
      const command = args[args.length - 1];
      const id = (command.match(/__MCP_TASK_STARTED=([a-f0-9]+)/) || [])[1] || '';
      return createMockSpawn({ stdout: `__MCP_TASK_STARTED=${id}\n` })();
    });

    const result = await client.startBackgroundTask('web', 'sleep 60');

    expect(result.taskId).toMatch(/^[a-f0-9]{8,}$/);
    expect(result.state).toBe('running');
    expect(writeFile).toHaveBeenCalled();
  });

  it('fails loudly when the host never confirms the start', async () => {
    client._spawn = createMockSpawn({ stdout: 'bash: setsid: command not found', code: 127 });

    await expect(client.startBackgroundTask('web', 'sleep 60')).rejects.toThrow(/did not confirm|handshake/i);
  });

  it('does not register a task that failed to start', async () => {
    client._spawn = createMockSpawn({ stdout: '', code: 1 });

    await expect(client.startBackgroundTask('web', 'sleep 60')).rejects.toThrow();
    expect(writeFile).not.toHaveBeenCalled();
  });

  it('refuses an unknown host before touching the network', async () => {
    client._spawn = vi.fn();

    await expect(client.startBackgroundTask('ghost', 'sleep 60')).rejects.toThrow(/Unknown hostAlias/);
    expect(client._spawn).not.toHaveBeenCalled();
  });

  it('reports a finished task with its exit code', async () => {
    const task = { taskId: 'aa11', hostAlias: 'web', ...taskPaths('aa11') };
    client.taskStore.get = vi.fn().mockResolvedValue(task);
    client.taskStore.update = vi.fn(async (id, patch) => ({ ...task, ...patch }));
    client._spawn = createMockSpawn({ stdout: '__MCP_TASK_EXIT=0\n' });

    const status = await client.backgroundTask({ action: 'status', taskId: 'aa11' });

    expect(status.task).toMatchObject({ state: 'exited', exitCode: 0 });
  });

  it('returns decoded logs', async () => {
    const task = { taskId: 'aa11', hostAlias: 'web', ...taskPaths('aa11') };
    client.taskStore.get = vi.fn().mockResolvedValue(task);
    client._spawn = createMockSpawn({ stdout: '__MCP_TASK_SIZE=5\n__MCP_TASK_LOG=aGVsbG8=' });

    const logs = await client.backgroundTask({ action: 'logs', taskId: 'aa11' });

    expect(logs).toMatchObject({ content: 'hello', size: 5 });
  });

  it('stops a task', async () => {
    const task = { taskId: 'aa11', hostAlias: 'web', ...taskPaths('aa11') };
    client.taskStore.get = vi.fn().mockResolvedValue(task);
    client.taskStore.update = vi.fn(async (id, patch) => ({ ...task, ...patch }));
    client._spawn = createMockSpawn({ stdout: '__MCP_TASK_STOPPED=true\n' });

    const result = await client.backgroundTask({ action: 'stop', taskId: 'aa11' });

    expect(result.task.state).toBe('stopped');
  });

  it('explains itself when the task id is unknown', async () => {
    client.taskStore.get = vi.fn().mockResolvedValue(null);

    await expect(client.backgroundTask({ action: 'status', taskId: 'nope' }))
      .rejects.toThrow(/not found/i);
  });

  it('rejects an unsupported action', async () => {
    await expect(client.backgroundTask({ action: 'explode', taskId: 'aa11' }))
      .rejects.toThrow(/action/i);
  });
});

// The MCP surface is tested as a contract (what the model is offered);
// the behaviour behind it is covered by the SSHClient tests above.
describe('MCP surface for background tasks', () => {
  let handlers;

  beforeEach(async () => {
    vi.clearAllMocks();
    handlers = {};

    const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
    const types = require('@modelcontextprotocol/sdk/types.js');
    const origSetRequestHandler = Server.prototype.setRequestHandler;
    const origConnect = Server.prototype.connect;

    Server.prototype.setRequestHandler = function (schema, handler) {
      if (schema === types.ListToolsRequestSchema) handlers.listTools = handler;
      else if (schema === types.CallToolRequestSchema) handlers.callTool = handler;
    };
    Server.prototype.connect = vi.fn().mockResolvedValue();

    readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
    stat.mockResolvedValue({ mode: 0o100600 });

    await main();

    Server.prototype.setRequestHandler = origSetRequestHandler;
    Server.prototype.connect = origConnect;
  });

  it('offers a backgroundTask tool', async () => {
    const { tools } = await handlers.listTools();
    expect(tools.map(t => t.name)).toContain('backgroundTask');
  });

  it('lets runRemoteCommand detach', async () => {
    const { tools } = await handlers.listTools();
    const run = tools.find(t => t.name === 'runRemoteCommand');

    expect(run.inputSchema.properties.detach).toBeDefined();
    expect(run.inputSchema.properties.detach.type).toBe('boolean');
  });

  it('documents detaching in the runRemoteCommand description', async () => {
    const { tools } = await handlers.listTools();
    const run = tools.find(t => t.name === 'runRemoteCommand');

    // The model only learns that long jobs have a better path if we say so here.
    expect(run.description).toMatch(/detach|background/i);
  });

  it('constrains backgroundTask to the supported actions', async () => {
    const { tools } = await handlers.listTools();
    const task = tools.find(t => t.name === 'backgroundTask');

    expect(task.inputSchema.properties.action.enum).toEqual(['list', 'status', 'logs', 'stop']);
    expect(task.inputSchema.required).toEqual(['action']);
  });

  it('lists tasks through the tool', async () => {
    readFile.mockResolvedValue('{}');

    const result = await handlers.callTool({
      params: { name: 'backgroundTask', arguments: { action: 'list' } },
    });

    expect(JSON.parse(result.content[0].text)).toEqual({ tasks: [] });
  });
});
