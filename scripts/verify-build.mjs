import { statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const required = {
  'dist/server.js': 500,
  'dist/ssh-client.js': 1000,
  'dist/ssh-config-parser.js': 500,
  'dist/platform.js': 200,
  'dist/tools.js': 1000,
  'dist/tasks.js': 1000,
  'dist/config-values.js': 200,
  'bin/mcp-ssh.js': 100,
};

export function verifyBuild(root = new URL('../', import.meta.url)) {
  for (const [path, minimumSize] of Object.entries(required)) {
    const file = statSync(new URL(path, root));
    if (!file.isFile() || file.size < minimumSize) {
      throw new Error(`Missing or incomplete runtime file: ${path}`);
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) verifyBuild();
