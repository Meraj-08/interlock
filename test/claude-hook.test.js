import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { InterlockServer, RiskPolicy, runClaudeHook } from '../src/index.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'interlock.js');

async function fixture(name) {
  return JSON.parse(await readFile(join(ROOT, 'test', 'fixtures', name), 'utf8'));
}

function bashInput(command) {
  return {
    session_id: 's1', cwd: '/tmp/app', hook_event_name: 'PreToolUse',
    tool_name: 'Bash', tool_input: { command, description: 'test' },
  };
}

/** A real Interlock server with the example policy on an ephemeral port. */
async function withServer(fn) {
  const policy = await RiskPolicy.fromFile(join(ROOT, 'examples', 'interlock.policy.json'));
  const server = await InterlockServer.create({ policy });
  const port = await server.listen(0);
  try {
    await fn({ server, url: `http://localhost:${port}` });
  } finally {
    await server.close();
  }
}

/** Wait until the server holds a pending proposal, then return it. */
async function nextPending(server) {
  for (let i = 0; i < 200; i++) {
    const pending = (await server.authority.list()).find((p) => p.state === 'pending');
    if (pending) return pending;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('no pending proposal appeared');
}

const decision = (out) => out?.hookSpecificOutput?.permissionDecision;
const reason = (out) => out?.hookSpecificOutput?.permissionDecisionReason ?? '';

test('an auto-allowed call defers to Claude Code (no output)', async () => {
  await withServer(async ({ server, url }) => {
    const out = await runClaudeHook(bashInput('git status'), { server: url, openUrl: () => {} });
    assert.equal(out, null);
    // The call was recorded and its receipt consumed.
    const [p] = await server.authority.list();
    assert.equal(p.action, 'Bash');
    const replay = await server.guard.execute(p.id, () => {});
    assert.equal(replay.executed, false);
  });
});

test('a denied call is blocked with the rule reason', async () => {
  await withServer(async ({ url }) => {
    const out = await runClaudeHook(bashInput('rm -rf /'), { server: url, openUrl: () => {} });
    assert.equal(out.hookSpecificOutput.hookEventName, 'PreToolUse');
    assert.equal(decision(out), 'deny');
    assert.match(reason(out), /deleting the filesystem root is never allowed/);
    assert.match(reason(out), /no-rm-rf-root/);
  });
});

test('a risky call waits for a passkey approval, then is allowed', async () => {
  await withServer(async ({ server, url }) => {
    const input = await fixture('claude-pretooluse-bash.json');
    const opened = [];
    const hook = runClaudeHook(input, { server: url, pollMs: 10, openUrl: (u) => opened.push(u) });

    const pending = await nextPending(server);
    // What the human reviews is exactly what Claude Code is about to run.
    assert.equal(pending.action, 'Bash');
    assert.deepEqual(pending.params, input.tool_input);
    assert.equal(pending.agent, 'claude-code');
    assert.match(pending.consequence, /git push --force origin main/);

    await server.authority.approve(pending.id, { approver: 'ops_alice', method: 'passkey' });
    const out = await hook;

    assert.equal(decision(out), 'allow');
    assert.match(reason(out), /approved by ops_alice/);
    assert.deepEqual(opened, [`${url}/console`]);
    // The receipt was consumed: it cannot be used a second time.
    assert.equal((await server.guard.execute(pending.id, () => {})).executed, false);
  });
});

test('a call the human denies is blocked', async () => {
  await withServer(async ({ server, url }) => {
    const hook = runClaudeHook(bashInput('git push -f origin main'), { server: url, pollMs: 10, openUrl: () => {} });
    const pending = await nextPending(server);
    await server.authority.deny(pending.id, { approver: 'ops_alice', reason: 'not today' });
    const out = await hook;
    assert.equal(decision(out), 'deny');
    assert.match(reason(out), /denied by ops_alice/);
    assert.match(reason(out), /not today/);
  });
});

test('no answer before the timeout blocks the call and closes the request', async () => {
  await withServer(async ({ server, url }) => {
    const out = await runClaudeHook(bashInput('git push --force origin main'), {
      server: url, pollMs: 10, timeoutMs: 80, openUrl: () => {},
    });
    assert.equal(decision(out), 'deny');
    assert.match(reason(out), /no approval within/);
    // A late approval can no longer produce a usable receipt.
    const [p] = await server.authority.list();
    assert.equal(p.state, 'denied');
  });
});

test('Write calls are guarded with the file path in the review', async () => {
  await withServer(async ({ server, url }) => {
    const input = await fixture('claude-pretooluse-write.json');
    const hook = runClaudeHook(input, { server: url, pollMs: 10, openUrl: () => {} });
    const pending = await nextPending(server);
    assert.equal(pending.action, 'Write');
    assert.match(pending.consequence, /\/Users\/dev\/app\/\.env/);
    await server.authority.deny(pending.id, { approver: 'ops_alice', reason: '' });
    assert.equal(decision(await hook), 'deny');
  });
});

test('an unreachable Interlock service blocks the call (fails closed)', async () => {
  const out = await runClaudeHook(bashInput('git status'), { server: 'http://127.0.0.1:1', openUrl: () => {} });
  assert.equal(decision(out), 'deny');
  assert.match(reason(out), /cannot reach Interlock at http:\/\/127\.0\.0\.1:1/);
});

test('a server error blocks the call', async () => {
  const fetchImpl = async () => new Response(JSON.stringify({ error: 'boom' }), { status: 500 });
  const out = await runClaudeHook(bashInput('git status'), { server: 'http://x', fetchImpl, openUrl: () => {} });
  assert.equal(decision(out), 'deny');
  assert.match(reason(out), /HTTP 500/);
});

test('malformed hook input is blocked', async () => {
  for (const input of [null, {}, { hook_event_name: 'PreToolUse', tool_input: {} }, { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: 'x' }]) {
    const out = await runClaudeHook(input, { server: 'http://unused', openUrl: () => {} });
    assert.equal(decision(out), 'deny', JSON.stringify(input));
    assert.match(reason(out), /invalid hook input/);
  }
});

test('events other than PreToolUse are ignored', async () => {
  const out = await runClaudeHook({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: {} }, { server: 'http://unused' });
  assert.equal(out, null);
});

test('the server refuses approval without a passkey by default', async () => {
  const server = await InterlockServer.create();
  const port = await server.listen(0);
  try {
    const { approvalId } = await (await fetch(`http://localhost:${port}/api/propose`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ agent: 'a', onBehalfOf: 'u', action: 'refund.issue', params: { amount: 5000 }, riskClass: 'high' }),
    })).json();
    const res = await fetch(`http://localhost:${port}/api/proposals/${approvalId}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, 'passkey_required');
    assert.equal((await server.authority.get(approvalId)).state, 'pending');
  } finally {
    await server.close();
  }
});

/** Run `interlock hook claude` as Claude Code would: JSON on stdin, JSON on stdout. */
function runBin(args, stdin) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('exit', (code) => resolve({ code, out, err }));
    child.stdin.end(stdin);
  });
}

test('interlock hook claude: stdin JSON in, decision JSON out, exit 0', async () => {
  await withServer(async ({ url }) => {
    const r = await runBin(['hook', 'claude', '--server', url, '--no-open'], JSON.stringify(bashInput('rm -rf /')));
    assert.equal(r.code, 0, r.err);
    const out = JSON.parse(r.out);
    assert.equal(decision(out), 'deny');

    const allowed = await runBin(['hook', 'claude', '--server', url, '--no-open'], JSON.stringify(bashInput('git status')));
    assert.equal(allowed.code, 0, allowed.err);
    assert.equal(allowed.out, '');
  });
});

test('interlock hook claude: unparseable stdin is blocked', async () => {
  const r = await runBin(['hook', 'claude', '--server', 'http://unused', '--no-open'], '{not json');
  assert.equal(r.code, 0);
  assert.equal(decision(JSON.parse(r.out)), 'deny');
});

test('interlock hook claude: --timeout must be a positive number', async () => {
  const r = await runBin(['hook', 'claude', '--timeout', '0'], '{}');
  assert.equal(r.code, 2);
  assert.match(r.err, /--timeout must be a positive number of seconds/);
});
