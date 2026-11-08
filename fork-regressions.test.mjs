import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
vi.mock('node:fs', async () => {
  const actual = await vi.importActual('node:fs');
  return { ...actual, realpathSync: vi.fn(actual.realpathSync), readlinkSync: vi.fn(actual.readlinkSync) };
});
vi.mock('node:fs/promises', async () => ({
  ...await vi.importActual('node:fs/promises'),
  readFile: vi.fn(), writeFile: vi.fn().mockResolvedValue(), mkdir: vi.fn().mockResolvedValue(),
}));
import { realpathSync, readlinkSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { parse } from 'node:path';
import { SSHClient, TaskStore, taskPaths, buildTaskLogsScript, callTool } from './src/server.ts';

describe('typed fork contracts', () => {
  let client;
  beforeEach(() => {
    vi.clearAllMocks();
    client = new SSHClient();
    readFile.mockResolvedValue('Host test\n HostName 203.0.113.7\n');
  });
  afterEach(() => vi.restoreAllMocks());

  it.each([
    { user: 1 }, { identityFile: 1 }, { proxyJump: 1 }, { password: 1 },
  ])('validates untrusted ad-hoc fields %j', (fields) => {
    expect(() => client._resolveAdhoc({ host: '203.0.113.7', ...fields })).toThrow();
  });

  it('handles empty credentials without creating an askpass helper', async () => {
    expect(await client._askpassEnvForPassword('')).toBeNull();
    expect(client._resolveAdhoc({ host: '203.0.113.7', password: '' }).password).toBeNull();
    expect(await client.getHostInfo(undefined, { adhoc: { host: '203.0.113.7' } })).toMatchObject({
      source: 'ad-hoc', user: null, port: null,
    });
  });

  it('cleans up an askpass helper that could not be written', async () => {
    writeFile.mockRejectedValueOnce(new Error('synthetic write failure'));
    await expect(client.getAskpassScript()).rejects.toThrow('synthetic write failure');
  });

  it.each([
    { host: '203.0.113.7' },
    { host: '203.0.113.7', user: 'root', port: 2222, identityFile: '/key', proxyJump: 'jump' },
  ])('retains an ad-hoc task connection for polling %j', async (adhoc) => {
    client.runRemoteCommand = vi.fn(async (_host, script) => ({
      code: 0, stderr: '', stdout: `__MCP_TASK_STARTED=${/__MCP_TASK_STARTED=([a-f0-9]+)/.exec(script)[1]}`,
    }));
    client.taskStore.add = vi.fn();
    const task = await client.startBackgroundTask(undefined, 'echo test', { adhoc });
    expect(task.hostAlias).toBeNull();
    expect(task.connection).toMatchObject(adhoc);
    expect(task.connection.password).toBeUndefined();
  });

  it('groups ad-hoc purge calls and preserves running local tasks', async () => {
    const task = { taskId: 'aa11', hostAlias: null, connection: { host: '203.0.113.7' }, ...taskPaths('aa11') };
    client.runRemoteCommand = vi.fn().mockResolvedValue({ code: 0, stderr: '', stdout: '__MCP_TASK_PURGED=aa11' });
    client.taskStore.remove = vi.fn().mockResolvedValue(['aa11']);
    expect((await client._purgeTasks([task])).removed).toEqual(['aa11']);
    expect((await client._purgeTasks([{ ...task, state: 'running' }], { keepRemote: true })).kept).toEqual([
      { taskId: 'aa11', reason: 'running' },
    ]);
    expect(() => client._assertSafeTaskId('')).toThrow(/unsafe task id/);
  });

  it('handles a missing task ID and a failed stop', async () => {
    await expect(client.backgroundTask({ action: 'status' })).rejects.toThrow(/not found/);
    client.taskStore.get = vi.fn().mockResolvedValue({ taskId: 'aa11', hostAlias: 'test', ...taskPaths('aa11') });
    client.taskStore.update = vi.fn(async (_id, patch) => patch);
    client.runRemoteCommand = vi.fn().mockResolvedValue({ code: 0, stderr: '', stdout: '__MCP_TASK_STOPPED=false' });
    expect((await client.backgroundTask({ action: 'stop', taskId: 'aa11' })).task.state).toBe('running');
  });

  it('reads older empty task registries and scalar remove calls', async () => {
    const store = new TaskStore('/synthetic/tasks.json');
    readFile.mockResolvedValue('null');
    expect(await store.list()).toEqual([]);
    expect(await store.update('aa11', { state: 'exited' })).toEqual({ taskId: 'aa11', state: 'exited' });
    readFile.mockResolvedValue('{"aa11":{"taskId":"aa11"}}');
    expect(await store.remove('aa11')).toEqual(['aa11']);
    expect(buildTaskLogsScript('/log', 0, 0)).toContain('count=1');
  });

  it('dispatches detach and rejects missing tool targets', async () => {
    client.startBackgroundTask = vi.fn().mockResolvedValue({ taskId: 'aa11' });
    const detached = await callTool(client, 'runRemoteCommand', { hostAlias: 'test', host: '', command: 'echo test', detach: true });
    expect(JSON.parse(detached.content[0].text).taskId).toBe('aa11');
    const missing = await callTool(client, 'downloadFile', {});
    expect(JSON.parse(missing.content[0].text).error).toContain('Provide hostAlias');
    const adhoc = await callTool(client, 'getHostInfo', { host: '203.0.113.7' });
    expect(JSON.parse(adhoc.content[0].text).source).toBe('ad-hoc');
  });

  it('returns a safe error even without a subprocess message', async () => {
    client._execFileAsync = vi.fn().mockRejectedValue({ code: 1, stderr: 'unexpected' });
    const onError = vi.fn();
    expect(await client.uploadFile(undefined, '/local', '/remote', { adhoc: { host: '203.0.113.7' }, onError })).toBe(false);
    expect(onError.mock.calls[0][0].code).toBe('transfer_failed');
  });

  it('fails closed on unreadable destination ancestors', () => {
    realpathSync.mockImplementationOnce(() => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); });
    expect(() => client._assertNotSshDirectory('/unreadable')).toThrow('denied');
  });

  it('bounds dangling link cycles and fails closed on unreadable links', () => {
    realpathSync.mockImplementation(() => { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); });
    readlinkSync.mockReturnValue('/another-link');
    expect(() => client._assertNotSshDirectory('/link')).toThrow(/too many symbolic links/);
    readlinkSync.mockImplementation(() => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); });
    expect(() => client._assertNotSshDirectory('/link')).toThrow('denied');
  });

  it('handles missing filesystem roots without recursive looping', () => {
    realpathSync.mockImplementation(() => { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); });
    readlinkSync.mockImplementation(() => { throw Object.assign(new Error('not a link'), { code: 'EINVAL' }); });
    expect(() => client._assertNotSshDirectory(parse(process.cwd()).root)).not.toThrow();
  });
});
