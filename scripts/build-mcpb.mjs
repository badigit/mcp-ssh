import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { verifyBuild } from './verify-build.mjs';
import { unpackExtension } from '@anthropic-ai/mcpb';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error('Run this builder through npm run build:mcpb');
const run = (args, cwd = root) => execFileSync(process.execPath, args, {
  cwd, stdio: 'inherit', windowsHide: true, timeout: 180000,
});
run([npmCli, 'run', 'build']);
verifyBuild();
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
if (pkg.version !== manifest.version) throw new Error('Package and manifest versions disagree');
const cli = join(root, 'node_modules', '@anthropic-ai', 'mcpb', 'dist', 'cli', 'cli.js');
run([cli, 'validate', join(root, 'manifest.json')]);
const output = join(root, 'build', `mcp-ssh-${pkg.version}.mcpb`);
mkdirSync(dirname(output), { recursive: true });
const stage = mkdtempSync(join(tmpdir(), 'mcp-ssh-bundle-'));
try {
  for (const path of ['manifest.json', 'package.json', 'package-lock.json', 'LICENSE', 'README.md', 'bin', 'dist']) {
    cpSync(join(root, path), join(stage, path), { recursive: true });
  }
  mkdirSync(join(stage, 'doc'));
  cpSync(join(root, 'doc', 'Claude.png'), join(stage, 'doc', 'Claude.png'));
  run([npmCli, 'ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'], stage);
  verifyBuild(pathToFileURL(stage + '/'));
  run([cli, 'pack', stage, output]);
  if (statSync(output).size < 1000) throw new Error('MCP Bundle is incomplete');
  const unpacked = join(stage, 'verification');
  if (!await unpackExtension({ mcpbPath: output, outputDir: unpacked, silent: true })) {
    throw new Error('MCP Bundle could not be unpacked');
  }
  verifyBuild(pathToFileURL(unpacked + '/'));
  for (const packageName of ['typescript', 'vitest', 'eslint', '@anthropic-ai/mcpb']) {
    if (existsSync(join(unpacked, 'node_modules', packageName))) throw new Error('Development dependency bundled');
  }
  const client = new Client({ name: 'bundle-verifier', version: '1.0.0' });
  try {
    await client.connect(new StdioClientTransport({
      command: process.execPath,
      args: [join(unpacked, 'bin', 'mcp-ssh.js')],
      env: { MCP_SILENT: 'true' },
      stderr: 'pipe',
    }), { timeout: 10000 });
    const { tools } = await client.listTools({}, { timeout: 10000 });
    for (const name of ['runRemoteCommand', 'backgroundTask', 'uploadFile', 'downloadFile']) {
      if (!tools.some((tool) => tool.name === name)) throw new Error(`Bundle is missing tool ${name}`);
    }
  } finally {
    await client.close();
  }
  console.log(`Bundle ready: ${output}`);
} finally {
  // Only the real directory created for this build may be removed.
  if (dirname(realpathSync(stage)) !== realpathSync(tmpdir())) throw new Error('Unexpected staging directory');
  rmSync(stage, { recursive: true, force: true });
}
