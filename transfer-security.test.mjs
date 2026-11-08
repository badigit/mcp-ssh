import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, realpathSync, writeFileSync } from 'fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'path';

const testHome = vi.hoisted(() => ({ path: '' }));
vi.mock('node:os', async () => ({
  ...await vi.importActual('node:os'),
  homedir: () => testHome.path,
}));
vi.mock('node:fs/promises', async () => ({
  ...await vi.importActual('node:fs/promises'),
  readFile: vi.fn(),
}));

import { readFile } from 'node:fs/promises';
import { SSHClient, SSHConfigParser } from './src/server.ts';

describe('file transfer security and diagnostics', () => {
  let fixture;
  let client;
  let localPath;

  beforeEach(() => {
    fixture = mkdtempSync(join(tmpdir(), 'mcp-ssh-security-'));
    testHome.path = join(fixture, 'home');
    mkdirSync(join(testHome.path, '.ssh'), { recursive: true });
    localPath = join(fixture, 'archive.tar');
    client = new SSHClient();
    client._execFileAsync = vi.fn().mockResolvedValue({ stdout: '', stderr: '' });
    readFile.mockReset();
  });

  afterEach(() => {
    // The fixture root is ours, is a real directory, and is directly under temp.
    expect(dirname(realpathSync(fixture))).toBe(realpathSync(tmpdir()));
    rmSync(fixture, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it.each(['uploadFile', 'downloadFile'])('rejects remote localPath before %s starts scp', async (method) => {
    for (const path of ['evil.example:/out', 'scp://evil.example/out']) {
      const paths = method === 'uploadFile' ? [path, '/backup'] : ['/backup', path];
      expect(await client[method](undefined, ...paths, { adhoc: { host: '203.0.113.7' } })).toBe(false);
    }
    expect(client._execFileAsync).not.toHaveBeenCalled();
  });

  it.each(['config', '../.ssh/config'])('rejects downloads into SSH directory through %s', async (suffix) => {
    const onError = vi.fn();
    const result = await client.downloadFile(undefined, '/backup', join(testHome.path, '.ssh', suffix), {
      adhoc: { host: '203.0.113.7' }, onError,
    });
    expect(result).toBe(false);
    expect(onError.mock.calls[0][0].code).toBe('invalid_arguments');
    expect(client._execFileAsync).not.toHaveBeenCalled();
  });

  it('rejects a tilde SSH destination', () => {
    expect(() => client._assertNotSshDirectory('~/.ssh/config')).toThrow(/SSH directory/);
  });

  it('resolves a directory link into the SSH directory', () => {
    const link = join(fixture, 'innocent');
    symlinkSync(join(testHome.path, '.ssh'), link, process.platform === 'win32' ? 'junction' : 'dir');
    expect(() => client._assertNotSshDirectory(join(link, 'config'))).toThrow(/SSH directory/);
  });

  it('resolves a dangling directory link into a missing SSH destination', () => {
    const link = join(fixture, 'innocent');
    symlinkSync(join(testHome.path, '.ssh', 'missing'), link, process.platform === 'win32' ? 'junction' : 'dir');
    expect(() => client._assertNotSshDirectory(join(link, 'config'))).toThrow(/SSH directory/);
  });

  it('keeps uploads from the SSH directory available', async () => {
    expect(await client.uploadFile(undefined, join(testHome.path, '.ssh', 'config'), '/backup', {
      adhoc: { host: '203.0.113.7' },
    })).toBe(true);
  });

  it.each(['203.0.113.7', '2001:db8::1', 'a:b'])('brackets the scp host %s and keeps user outside', async (host) => {
    expect(await client.downloadFile(undefined, '/backup', localPath, { adhoc: { host, user: 'root' } })).toBe(true);
    const [, argv, options] = client._execFileAsync.mock.calls[0];
    expect(argv.slice(-2)).toEqual([`root@[${host}]:/backup`, localPath]);
    expect(options).toMatchObject({ shell: false, windowsHide: true, timeout: 60000 });
  });

  it.each([
    [{ killed: true, signal: 'SIGTERM' }, 'timeout'],
    [{ code: 'ETIMEDOUT' }, 'timeout'],
    [{ code: 1, stderr: 'scp: /backup: Permission denied' }, 'permission_denied'],
    [{ code: 255, stderr: 'Permission denied (publickey).' }, 'authentication_failed'],
    [{ code: 1, stderr: 'No such file or directory' }, 'not_found'],
    [{ code: 255, stderr: 'subsystem request failed on channel 0' }, 'sftp_unavailable'],
    [{ code: 255, stderr: 'Host key verification failed.' }, 'host_key_failed'],
    [{ code: 'ENOENT' }, 'not_found'],
    [{ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }, 'output_limit'],
    [{ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', killed: true }, 'output_limit'],
    [{ code: 1, stderr: 'unexpected failure' }, 'transfer_failed'],
  ])('reports %j as %s without leaking subprocess text', async (fields, code) => {
    const secret = 'synthetic-credential-do-not-print';
    client._execFileAsync.mockRejectedValue(Object.assign(new Error(`scp ${secret}`), {
      ...fields, stderr: `${fields.stderr || ''}\n${secret}`, stdout: secret,
    }));
    const onError = vi.fn();
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    expect(await client.downloadFile(undefined, '/backup', localPath, {
      adhoc: { host: '203.0.113.7' }, onError,
    })).toBe(false);
    const failure = onError.mock.calls[0][0];
    expect(failure.code).toBe(code);
    expect(JSON.stringify(failure).includes(secret)).toBe(false);
    expect(JSON.stringify(stderrSpy.mock.calls).includes(secret)).toBe(false);
  });

  it('keeps concurrent transfer errors isolated to each call', async () => {
    client._execFileAsync.mockRejectedValueOnce(Object.assign(new Error('failed'), { stderr: 'Permission denied' }));
    const onError = vi.fn();
    const results = await Promise.all([
      client.downloadFile(undefined, '/backup', localPath, { adhoc: { host: '203.0.113.7' }, onError }),
      client.downloadFile(undefined, '/backup', localPath, { adhoc: { host: '203.0.113.8' } }),
    ]);
    expect(results).toEqual([false, true]);
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it('bounds cyclic Includes', async () => {
    readFile.mockResolvedValue('Include same.conf\nHost test\n HostName 203.0.113.7\n');
    const parser = new SSHConfigParser();
    parser.expandIncludePath = () => [join(fixture, 'same.conf')];
    const hosts = await parser.processIncludeDirectives(join(fixture, 'same.conf'));
    expect(hosts).toHaveLength(1);
    expect(readFile).toHaveBeenCalledTimes(1);
  });

  it('expands Include globs using native path separators', () => {
    const config = join(fixture, 'host.conf');
    writeFileSync(config, 'Host test\n');
    const parser = new SSHConfigParser();
    const paths = parser.expandIncludePath(join(fixture, '*.conf'), join(fixture, 'config'));
    expect(paths.map((path) => realpathSync(path))).toEqual([realpathSync(config)]);
  });
});
