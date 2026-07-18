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

// A killed task never reaches the wrapper that records an exit code, so without
// a marker of our own it would read as `unknown` on every later status call.
const restatus = await client.backgroundTask({ action: 'status', taskId: victim.taskId });
check('still stopped when asked again', restatus.task.state === 'stopped', restatus.task.state);
check('kept the signal that ended it', [143, 137].includes(restatus.task.exitCode), String(restatus.task.exitCode));

console.log('\n4) Registry');
const list = await client.backgroundTask({ action: 'list' });
check('all three tasks registered', list.tasks.length === 3, String(list.tasks.length));

console.log('\n5) Cleanup');
const countFiles = async id =>
  (await client.runRemoteCommand(HOST, `ls "$HOME/.mcp-ssh/tasks/${id}."* 2>/dev/null | wc -l`)).stdout.trim();
// A running task has two files (.log, .pgid); the .exit file only appears when
// the command finishes — that asymmetry is what the sweep keys on.
const RUNNING_FILES = '2';

// A task that is still working must survive a prune, files and entry alike.
const busy = await client.startBackgroundTask(HOST, 'sleep 120');
await sleep(1500);

const removed = await client.backgroundTask({ action: 'remove', taskId: task.taskId });
check('remove reports the task', removed.removed.includes(task.taskId), JSON.stringify(removed));
check('files gone from the host', (await countFiles(task.taskId)) === '0', await countFiles(task.taskId));
check('entry gone from the registry',
  !(await client.backgroundTask({ action: 'list' })).tasks.some(t => t.taskId === task.taskId));

const pruned = await client.backgroundTask({ action: 'prune' });
check('prune took the finished ones', pruned.removed.length === 2, JSON.stringify(pruned.removed));
check('prune spared the running one',
  pruned.kept.some(k => k.taskId === busy.taskId && k.reason === 'running'), JSON.stringify(pruned.kept));
check('running task kept its files', (await countFiles(busy.taskId)) === RUNNING_FILES, await countFiles(busy.taskId));

const afterPrune = await client.backgroundTask({ action: 'list' });
check('only the running task is left', afterPrune.tasks.length === 1 && afterPrune.tasks[0].taskId === busy.taskId,
  afterPrune.tasks.map(t => t.taskId).join(','));

console.log('\n6) Retention sweep');
// Files of a task that finished long ago must be swept on the next start.
// Backdated by hand, since we cannot wait out the retention window.
const ancient = 'aaaaaaaaaaaa';
await client.runRemoteCommand(HOST, [
  'mkdir -p "$HOME/.mcp-ssh/tasks"',
  `touch "$HOME/.mcp-ssh/tasks/${ancient}.log" "$HOME/.mcp-ssh/tasks/${ancient}.exit" "$HOME/.mcp-ssh/tasks/${ancient}.pgid"`,
  `touch -d '30 days ago' "$HOME/.mcp-ssh/tasks/${ancient}."* 2>/dev/null || touch -t 202001010000 "$HOME/.mcp-ssh/tasks/${ancient}."*`
].join('; '));
check('backdated files exist', (await countFiles(ancient)) === '3', await countFiles(ancient));

const sweeper = await client.startBackgroundTask(HOST, 'true');
check('sweep removed the ancient files', (await countFiles(ancient)) === '0', await countFiles(ancient));
check('sweep spared the running task', (await countFiles(busy.taskId)) === RUNNING_FILES, await countFiles(busy.taskId));

await client.backgroundTask({ action: 'stop', taskId: busy.taskId });
await sleep(500);
const finalPrune = await client.backgroundTask({ action: 'prune' });
check('stopped task prunes cleanly', finalPrune.removed.includes(busy.taskId), JSON.stringify(finalPrune));

const leftovers = await client.backgroundTask({ action: 'prune' });
check('nothing left to prune', leftovers.removed.length === 0 && leftovers.kept.length === 0, JSON.stringify(leftovers));

await client.runRemoteCommand(HOST, `rm -f "$HOME/.mcp-ssh/tasks/${sweeper.taskId}."* "$HOME/.mcp-ssh/tasks/${ancient}."*`);
console.log('\nCleaned up on host.');

console.log(failures === 0 ? '\nALL GREEN' : `\nFAILURES: ${failures}`);
process.exit(failures === 0 ? 0 : 1);
