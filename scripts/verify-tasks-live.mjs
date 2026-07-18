#!/usr/bin/env node
//
// Live check of background tasks against a real host. The unit tests mock
// spawn, so they cannot tell whether the remote shell protocol actually works:
// whether setsid exists, whether the exit code survives `exit N`, whether
// stopping really kills the process tree. This does.
//
//   node scripts/verify-tasks-live.mjs <hostAlias>
//
// Runs only sleeps and echoes, and removes its own task files afterwards.
import { rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { SSHClient, TaskStore } from '../server.mjs';

const HOST = process.argv[2];
if (!HOST) {
  console.error('usage: node scripts/verify-tasks-live.mjs <hostAlias>');
  process.exit(2);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;

function check(label, ok, detail = '') {
  console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
}

const client = new SSHClient();
// Separate registry, wiped first: a leftover from a previous run would make
// the task count assertion drift.
const registryPath = join(tmpdir(), 'mcp-ssh-verify-tasks.json');
await rm(registryPath, { force: true });
client.taskStore = new TaskStore(registryPath);

console.log(`Host: ${HOST}\n`);

console.log('1) Lifecycle');
// `exit 3` is the interesting part: it must end the command, not the wrapper
// that records the exit code.
const task = await client.startBackgroundTask(HOST, 'echo start; sleep 8; echo finished; exit 3');
check('start returned a task id', /^[a-f0-9]{12}$/.test(task.taskId), task.taskId);

const early = await client.backgroundTask({ action: 'status', taskId: task.taskId });
check('running right after start', early.task.state === 'running', early.task.state);

const earlyLogs = await client.backgroundTask({ action: 'logs', taskId: task.taskId });
check('log readable while running', earlyLogs.content.includes('start'));
check('output still incomplete', !earlyLogs.content.includes('finished'));

await sleep(11000);

const done = await client.backgroundTask({ action: 'status', taskId: task.taskId });
check('exited once finished', done.task.state === 'exited', done.task.state);
check('exit code preserved through `exit N`', done.task.exitCode === 3, String(done.task.exitCode));

const finalLogs = await client.backgroundTask({ action: 'logs', taskId: task.taskId });
check('full output captured', finalLogs.content.includes('finished'));

const tail = await client.backgroundTask({ action: 'logs', taskId: task.taskId, offset: 6 });
check('offset read', !tail.content.startsWith('start'), JSON.stringify(tail.content));

console.log('\n2) Task outlives our connection');
const survivor = await client.startBackgroundTask(HOST, 'sleep 6; echo survived');
await sleep(9000);
const survived = await client.backgroundTask({ action: 'status', taskId: survivor.taskId });
const survivedLogs = await client.backgroundTask({ action: 'logs', taskId: survivor.taskId });
check('finished unattended', survived.task.state === 'exited', survived.task.state);
check('output kept', survivedLogs.content.includes('survived'));

console.log('\n3) Stop');
const victim = await client.startBackgroundTask(HOST, 'sleep 300 & sleep 300; echo never');
await sleep(1500);
const stopped = await client.backgroundTask({ action: 'stop', taskId: victim.taskId });
check('stop reported', stopped.task.state === 'stopped', stopped.task.state);

await sleep(1000);
// Character class so pgrep does not match its own command line.
const afterStop = await client.runRemoteCommand(HOST, `pgrep -f 'sleep[ ]300' | wc -l`);
check('process tree killed', afterStop.stdout.trim() === '0', `left: ${afterStop.stdout.trim()}`);

console.log('\n4) Registry');
const list = await client.backgroundTask({ action: 'list' });
check('all three tasks registered', list.tasks.length === 3, String(list.tasks.length));

const ids = [task.taskId, survivor.taskId, victim.taskId];
await client.runRemoteCommand(HOST, ids.map(id => `rm -f "$HOME/.mcp-ssh/tasks/${id}."*`).join('; '));
console.log('\nCleaned up on host:', ids.join(', '));

console.log(failures === 0 ? '\nALL GREEN' : `\nFAILURES: ${failures}`);
process.exit(failures === 0 ? 0 : 1);
