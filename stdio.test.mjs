import { expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { mkdtempSync, realpathSync, rmSync } from 'fs';
import { tmpdir } from 'os';

it('serves the file-tool contract through the real STDIO entry point', async () => {
  const fixture = mkdtempSync(join(tmpdir(), 'mcp-ssh-stdio-'));
  const originalEnv = process.env;
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('./bin/mcp-ssh.js', import.meta.url))],
    stderr: 'pipe',
  });
  const client = new Client({ name: 'transfer-smoke', version: '1.0.0' });
  try {
    // The SDK merges a default allowlist even when env is supplied. Isolate it
    // during spawn so a future allowlist change cannot inherit test secrets.
    process.env = {
      PATH: dirname(process.execPath),
      SystemRoot: originalEnv.SystemRoot || '',
      USERPROFILE: fixture,
      HOME: fixture,
      MCP_SILENT: 'true',
    };
    await client.connect(transport, { timeout: 5000 });
    process.env = originalEnv;
    const { tools } = await client.listTools({}, { timeout: 5000 });
    expect(tools.map((tool) => tool.name)).toEqual(expect.arrayContaining(['backgroundTask', 'downloadFile', 'uploadFile']));
    for (const name of ['uploadFile', 'downloadFile']) {
      expect(tools.find((tool) => tool.name === name).annotations).toEqual({
        readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true,
      });
      // Rejected before any SSH connection or real config access.
      const result = await client.callTool({ name, arguments: {
        host: '203.0.113.7', remotePath: '/backup', localPath: 'evil.example:/out',
      } }, undefined, { timeout: 5000 });
      expect(result.isError).toBe(true);
      expect(JSON.parse(result.content[0].text)).toMatchObject({
        success: false, error: { code: 'invalid_arguments' },
      });
    }
  } finally {
    process.env = originalEnv;
    await client.close();
    expect(dirname(realpathSync(fixture))).toBe(realpathSync(tmpdir()));
    rmSync(fixture, { recursive: true, force: true });
  }
});
