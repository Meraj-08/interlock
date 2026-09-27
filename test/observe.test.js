import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApprovalAuthority, Guard, RiskPolicy, PolicyError, InterlockServer, runClaudeHook } from '../src/index.js';

const bash = (command) => ({ agent: 'claude-code', onBehalfOf: 'dev', action: 'Bash', params: { command } });

const POLICY = {
  defaultMode: 'enforce',
  rules: [
    { id: 'no-rm-root', match: { action: 'Bash', params: { command: 'rm -rf /$' } }, outcome: 'deny', locked: true },
    { id: 'no-curl', match: { action: 'Bash', params: { command: '^curl' } }, outcome: 'deny', mode: 'observe' },
    { id: 'force-push', match: { action: 'Bash', params: { command: 'push --force' } }, outcome: 'require_approval', mode: 'observe' },
    { id: 'drop-table', match: { action: 'Bash', params: { command: 'DROP TABLE' } }, outcome: 'require_approval' },
    { id: 'status', match: { action: 'Bash', params: { command: '^git status' } }, outcome: 'auto_allow' },
  ],
};

async function setup(doc = POLICY) {
  const authority = await ApprovalAuthority.create({ policy: RiskPolicy.fromJSON(doc) });
  return { authority, guard: new Guard({ authority }) };
}

// --- policy -----------------------------------------------------------------

test('evaluate reports each rule\'s mode, enforce by default', () => {
  const policy = RiskPolicy.fromJSON(POLICY);
  assert.equal(policy.evaluate(bash('curl x.io')).mode, 'observe');
  assert.equal(policy.evaluate(bash('DROP TABLE users')).mode, 'enforce');
  assert.equal(policy.evaluate(bash('ls')).mode, 'enforce'); // fallback default
  assert.equal(RiskPolicy.default().evaluate({ action: 'x', params: {} }).mode, 'enforce');
});

test('defaultMode covers rules without a mode and the fallback', () => {
  const policy = RiskPolicy.fromJSON({ ...POLICY, defaultMode: 'observe' });
  assert.equal(policy.evaluate(bash('DROP TABLE users')).mode, 'observe');
  assert.equal(policy.evaluate(bash('ls')).mode, 'observe');
  // An explicit enforce is kept.
  const explicit = RiskPolicy.fromJSON({
    defaultMode: 'observe',
    rules: [{ id: 'e', match: {}, outcome: 'deny', mode: 'enforce' }],
  });
  assert.equal(explicit.evaluate(bash('ls')).mode, 'enforce');
});

test('locked rules always enforce, even under defaultMode observe', () => {
  const policy = RiskPolicy.fromJSON({ ...POLICY, defaultMode: 'observe' });
  const d = policy.evaluate(bash('rm -rf /'));
  assert.equal(d.outcome, 'deny');
  assert.equal(d.mode, 'enforce');
});

test('invalid modes are rejected at load time', () => {
  const bad = (doc, pattern) => assert.throws(() => RiskPolicy.fromJSON(doc), (err) => {
    assert.ok(err instanceof PolicyError);
    assert.match(err.message, pattern);
    return true;
  });
  bad({ defaultMode: 'watch', rules: [] }, /"defaultMode" must be one of observe, enforce/);
  bad({ rules: [{ id: 'a', match: {}, outcome: 'deny', mode: 'watch' }] }, /rule "a": "mode" must be one of observe, enforce/);
  bad({ rules: [{ id: 'a', match: {}, outcome: 'deny', locked: 'yes' }] }, /rule "a": "locked" must be true or false/);
  bad({ rules: [{ id: 'a', match: {}, outcome: 'deny', locked: true, mode: 'observe' }] }, /rule "a": a locked rule cannot be in observe mode/);
});

// --- authority ----------------------------------------------------------------

test('an observed deny is recorded but not blocked', async () => {
  const { authority, guard } = await setup();
  const d = await authority.propose(bash('curl https://example.com'));
  assert.equal(d.outcome, 'auto_allow');
  assert.equal(d.mode, 'observe');
  assert.equal(d.observed, true);
  assert.equal(d.wouldHave, 'deny');
  assert.equal(d.rule, 'no-curl');

  const p = await authority.get(d.approvalId);
  assert.equal(p.state, 'approved');
  assert.equal(p.method, 'observe');
  assert.equal(p.wouldHave, 'deny');
  assert.equal(p.mode, 'observe');
  assert.equal(p.rule, 'no-curl');
  assert.equal((await guard.execute(d.approvalId, () => 'ran')).executed, true);
});

test('an observed approval requirement never creates a pending request', async () => {
  const { authority } = await setup();
  const d = await authority.propose(bash('git push --force origin main'));
  assert.equal(d.outcome, 'auto_allow');
  assert.equal(d.wouldHave, 'require_approval');
  assert.equal(d.review, undefined);
  assert.equal((await authority.list()).filter((p) => p.state === 'pending').length, 0);
});

test('enforced rules behave as before and record mode and wouldHave', async () => {
  const { authority } = await setup();
  const held = await authority.propose(bash('DROP TABLE users'));
  assert.equal(held.outcome, 'needs_approval');
  assert.equal(held.mode, 'enforce');
  assert.equal(held.observed, false);
  assert.equal(held.wouldHave, 'require_approval');
  assert.equal((await authority.get(held.approvalId)).state, 'pending');

  const allowed = await authority.propose(bash('git status'));
  assert.equal(allowed.outcome, 'auto_allow');
  assert.equal(allowed.observed, false);
  assert.equal(allowed.wouldHave, 'auto_allow');
});

test('a locked deny blocks under defaultMode observe', async () => {
  const { authority } = await setup({ ...POLICY, defaultMode: 'observe' });
  const d = await authority.propose(bash('rm -rf /'));
  assert.equal(d.outcome, 'deny');
  assert.equal(d.mode, 'enforce');
});

test('analyzer escalation follows the matched rule\'s mode', async () => {
  const doc = (mode) => ({ rules: [{ id: 'refunds', match: { action: 'refund.issue' }, outcome: 'auto_allow', mode }] });
  const big = { agent: 'a', onBehalfOf: 'u', action: 'refund.issue', params: { amount: 50000 } };

  const enforced = await (await setup(doc('enforce'))).authority.propose(big);
  assert.equal(enforced.outcome, 'needs_approval');
  assert.equal(enforced.rule, 'analyzer');

  const observed = await (await setup(doc('observe'))).authority.propose(big);
  assert.equal(observed.outcome, 'auto_allow');
  assert.equal(observed.observed, true);
  assert.equal(observed.wouldHave, 'require_approval');
  assert.equal(observed.rule, 'analyzer');
});

// --- API and hook --------------------------------------------------------------

async function withServer(fn) {
  const server = await InterlockServer.create({ policy: RiskPolicy.fromJSON(POLICY) });
  const port = await server.listen(0);
  try {
    await fn({ server, url: `http://localhost:${port}` });
  } finally {
    await server.close();
  }
}

test('the proposals API exposes mode, observed, wouldHave, rule, and reason', async () => {
  await withServer(async ({ url }) => {
    await fetch(`${url}/api/propose`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(bash('curl https://example.com')),
    });
    const [p] = await (await fetch(`${url}/api/proposals`)).json();
    assert.equal(p.mode, 'observe');
    assert.equal(p.observed, true);
    assert.equal(p.wouldHave, 'deny');
    assert.equal(p.rule, 'no-curl');
    assert.ok(p.reason);
  });
});

test('the Claude Code hook lets observed calls through', async () => {
  await withServer(async ({ server, url }) => {
    const input = { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'curl https://example.com' } };
    const out = await runClaudeHook(input, { server: url, openUrl: () => {} });
    assert.equal(out, null);
    const [p] = await server.authority.list();
    assert.equal(p.wouldHave, 'deny');
  });
});
