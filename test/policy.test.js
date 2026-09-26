import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RiskPolicy, PolicyError } from '../src/index.js';

const bash = (command) => ({ action: 'Bash', params: { command } });
const transfer = (amount) => ({ action: 'payments.transfer', params: { amount, to: 'acct_a' } });

test('first matching rule wins, in file order', () => {
  const policy = RiskPolicy.fromJSON({
    rules: [
      { id: 'force-push', match: { action: 'Bash', params: { command: 'git push.*--force' } }, outcome: 'require_approval' },
      { id: 'any-bash', match: { action: 'Bash' }, outcome: 'auto_allow' },
    ],
  });
  assert.deepEqual(policy.evaluate(bash('git push --force origin main')), {
    outcome: 'require_approval', rule: 'force-push', reason: 'force-push',
  });
  assert.equal(policy.evaluate(bash('ls -la')).rule, 'any-bash');
});

test('falls through to the default outcome, which is require_approval unless set', () => {
  const rules = [{ id: 'only-ls', match: { params: { command: '^ls' } }, outcome: 'auto_allow' }];
  assert.equal(RiskPolicy.fromJSON({ rules }).evaluate(bash('rm x')).outcome, 'require_approval');
  assert.equal(RiskPolicy.fromJSON({ default: 'deny', rules }).evaluate(bash('rm x')).outcome, 'deny');
  assert.equal(RiskPolicy.fromJSON({ default: 'deny', rules }).evaluate(bash('rm x')).rule, 'default');
});

test('uses the rule reason when one is given', () => {
  const policy = RiskPolicy.fromJSON({
    rules: [{ id: 'no-delete', match: { action: 'account.delete' }, outcome: 'deny', reason: 'accounts are never deleted by agents' }],
  });
  assert.equal(policy.evaluate({ action: 'account.delete', params: {} }).reason, 'accounts are never deleted by agents');
});

test('action matches exactly, by * wildcard, or by any of a list', () => {
  const policy = RiskPolicy.fromJSON({
    default: 'deny',
    rules: [
      { id: 'exact', match: { action: 'refund.issue' }, outcome: 'require_approval' },
      { id: 'wildcard', match: { action: 'read.*' }, outcome: 'auto_allow' },
      { id: 'list', match: { action: ['Write', 'Edit'] }, outcome: 'require_approval' },
    ],
  });
  assert.equal(policy.evaluate({ action: 'refund.issue' }).rule, 'exact');
  assert.equal(policy.evaluate({ action: 'refund.issued' }).rule, 'default');
  assert.equal(policy.evaluate({ action: 'read.invoice' }).rule, 'wildcard');
  assert.equal(policy.evaluate({ action: 'reader' }).rule, 'default');
  assert.equal(policy.evaluate({ action: 'Edit' }).rule, 'list');
});

test('wildcards do not treat other regex characters as special', () => {
  const policy = RiskPolicy.fromJSON({
    default: 'deny',
    rules: [{ id: 'dot', match: { action: 'a.b' }, outcome: 'auto_allow' }],
  });
  assert.equal(policy.evaluate({ action: 'axb' }).rule, 'default');
});

test('riskClass matches a value or any of a list', () => {
  const policy = RiskPolicy.fromJSON({
    default: 'auto_allow',
    rules: [{ id: 'risky', match: { riskClass: ['high', 'critical'] }, outcome: 'require_approval' }],
  });
  assert.equal(policy.evaluate({ action: 'x', riskClass: 'critical' }).rule, 'risky');
  assert.equal(policy.evaluate({ action: 'x', riskClass: 'low' }).rule, 'default');
  assert.equal(policy.evaluate({ action: 'x' }).rule, 'default');
});

test('string param conditions are regular expressions searched in the value', () => {
  const policy = RiskPolicy.fromJSON({
    default: 'auto_allow',
    rules: [{ id: 'rm-rf', match: { params: { command: 'rm\\s+-rf\\s+/' } }, outcome: 'deny' }],
  });
  assert.equal(policy.evaluate(bash('sudo rm  -rf /')).outcome, 'deny');
  assert.equal(policy.evaluate(bash('rm -rf ./build')).outcome, 'auto_allow');
});

test('numeric comparisons: lt, lte, gt, gte', () => {
  const policy = RiskPolicy.fromJSON({
    default: 'deny',
    rules: [
      { id: 'small', match: { params: { amount: { lt: 100 } } }, outcome: 'auto_allow' },
      { id: 'medium', match: { params: { amount: { gte: 100, lte: 10000 } } }, outcome: 'require_approval' },
      { id: 'huge', match: { params: { amount: { gt: 10000 } } }, outcome: 'deny' },
    ],
  });
  assert.equal(policy.evaluate(transfer(99)).rule, 'small');
  assert.equal(policy.evaluate(transfer(100)).rule, 'medium');
  assert.equal(policy.evaluate(transfer(10000)).rule, 'medium');
  assert.equal(policy.evaluate(transfer(10001)).rule, 'huge');
});

test('comparisons never match a missing or non-numeric value', () => {
  const policy = RiskPolicy.fromJSON({
    default: 'require_approval',
    rules: [{ id: 'small', match: { params: { amount: { lt: 100 } } }, outcome: 'auto_allow' }],
  });
  assert.equal(policy.evaluate({ action: 'payments.transfer', params: {} }).rule, 'default');
  assert.equal(policy.evaluate(transfer('5')).rule, 'default');
  assert.equal(policy.evaluate({ action: 'payments.transfer' }).rule, 'default');
});

test('eq and in match exact values', () => {
  const policy = RiskPolicy.fromJSON({
    default: 'auto_allow',
    rules: [
      { id: 'usd-only', match: { params: { currency: { in: ['EUR', 'GBP'] } } }, outcome: 'require_approval' },
      { id: 'exact', match: { params: { amount: 5000 } }, outcome: 'deny' },
      { id: 'eq-string', match: { params: { branch: { eq: 'main' } } }, outcome: 'require_approval' },
    ],
  });
  assert.equal(policy.evaluate({ action: 'x', params: { currency: 'EUR' } }).rule, 'usd-only');
  assert.equal(policy.evaluate({ action: 'x', params: { amount: 5000 } }).rule, 'exact');
  assert.equal(policy.evaluate({ action: 'x', params: { amount: 50000 } }).rule, 'default');
  assert.equal(policy.evaluate({ action: 'x', params: { branch: 'main-old' } }).rule, 'default');
  assert.equal(policy.evaluate({ action: 'x', params: { branch: 'main' } }).rule, 'eq-string');
});

test('every condition in a rule must hold', () => {
  const policy = RiskPolicy.fromJSON({
    default: 'deny',
    rules: [{
      id: 'small-transfer',
      match: { action: 'payments.transfer', params: { amount: { lt: 100 }, to: '^acct_' } },
      outcome: 'auto_allow',
    }],
  });
  assert.equal(policy.evaluate(transfer(10)).rule, 'small-transfer');
  assert.equal(policy.evaluate({ action: 'payments.transfer', params: { amount: 10, to: 'ext_1' } }).rule, 'default');
  assert.equal(policy.evaluate({ action: 'refund.issue', params: { amount: 10, to: 'acct_a' } }).rule, 'default');
});

test('an empty match is a catch-all', () => {
  const policy = RiskPolicy.fromJSON({ rules: [{ id: 'all', match: {}, outcome: 'auto_allow' }] });
  assert.equal(policy.evaluate({ action: 'anything' }).rule, 'all');
});

test('invalid policies fail at load time and name the rule and field', () => {
  const bad = (doc, pattern) => assert.throws(() => RiskPolicy.fromJSON(doc), (err) => {
    assert.ok(err instanceof PolicyError, `expected PolicyError, got ${err}`);
    assert.match(err.message, pattern);
    return true;
  });

  bad(null, /policy must be an object/);
  bad({ rules: 'nope' }, /"rules" must be an array/);
  bad({ rules: [], extra: 1 }, /unknown field "extra"/);
  bad({ default: 'maybe', rules: [] }, /"default" must be one of/);
  bad({ rules: [{ match: {}, outcome: 'deny' }] }, /rule #1: "id" must be a non-empty string/);
  bad({ rules: [{ id: 'a', match: {}, outcome: 'deny' }, { id: 'a', match: {}, outcome: 'deny' }] }, /rule "a": duplicate id/);
  bad({ rules: [{ id: 'a', match: {}, outcome: 'block' }] }, /rule "a": "outcome" must be one of/);
  bad({ rules: [{ id: 'a', outcome: 'deny' }] }, /rule "a": "match" must be an object/);
  bad({ rules: [{ id: 'a', match: { tool: 'Bash' }, outcome: 'deny' }] }, /rule "a": unknown match field "tool"/);
  bad({ rules: [{ id: 'a', match: {}, outcome: 'deny', mode: 'observe' }] }, /rule "a": unknown field "mode"/);
  bad({ rules: [{ id: 'a', match: { params: { command: '(' } }, outcome: 'deny' }] }, /rule "a": params.command: invalid regular expression/);
  bad({ rules: [{ id: 'a', match: { params: { amount: { lt: '5' } } }, outcome: 'deny' }] }, /rule "a": params.amount.lt must be a number/);
  bad({ rules: [{ id: 'a', match: { params: { amount: { between: [1, 2] } } }, outcome: 'deny' }] }, /rule "a": params.amount: unknown operator "between"/);
  bad({ rules: [{ id: 'a', match: { params: { amount: {} } }, outcome: 'deny' }] }, /rule "a": params.amount: needs at least one operator/);
  bad({ rules: [{ id: 'a', match: { action: 7 }, outcome: 'deny' }] }, /rule "a": "action" must be a string or an array of strings/);
  bad({ rules: [{ id: 'a', match: { riskClass: 'severe' }, outcome: 'deny' }] }, /rule "a": "riskClass" must be one of/);
  bad({ rules: [{ id: 'a', match: { params: { currency: { in: 'EUR' } } }, outcome: 'deny' }] }, /rule "a": params.currency.in must be an array/);
});

test('fromFile loads JSON and reports errors with the file path', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'interlock-policy-'));
  const good = join(dir, 'good.json');
  await writeFile(good, JSON.stringify({ rules: [{ id: 'all', match: {}, outcome: 'deny' }] }));
  assert.equal((await RiskPolicy.fromFile(good)).evaluate({ action: 'x' }).outcome, 'deny');

  const broken = join(dir, 'broken.json');
  await writeFile(broken, '{ "rules": [');
  await assert.rejects(RiskPolicy.fromFile(broken), (err) => {
    assert.ok(err instanceof PolicyError);
    assert.ok(err.message.includes(broken));
    assert.match(err.message, /not valid JSON/);
    return true;
  });

  const invalid = join(dir, 'invalid.json');
  await writeFile(invalid, JSON.stringify({ rules: [{ id: 'a', match: {}, outcome: 'nope' }] }));
  await assert.rejects(RiskPolicy.fromFile(invalid), (err) => {
    assert.ok(err.message.includes(invalid));
    assert.match(err.message, /rule "a": "outcome" must be one of/);
    return true;
  });

  await assert.rejects(RiskPolicy.fromFile(join(dir, 'missing.json')), PolicyError);
});

test('the example policy loads and behaves as documented', async () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const policy = await RiskPolicy.fromFile(join(root, 'examples', 'interlock.policy.json'));

  assert.equal(policy.evaluate({ action: 'account.delete', params: {} }).outcome, 'deny');
  assert.equal(policy.evaluate(bash('rm -rf /')).outcome, 'deny');
  assert.equal(policy.evaluate(bash('git push --force origin main')).outcome, 'require_approval');
  assert.equal(policy.evaluate(bash('git status')).outcome, 'auto_allow');
  assert.equal(policy.evaluate({ action: 'refund.issue', params: { amount: 40 } }).outcome, 'auto_allow');
  assert.equal(policy.evaluate({ action: 'refund.issue', params: { amount: 5000 }, riskClass: 'high' }).outcome, 'require_approval');
  assert.equal(policy.evaluate({ action: 'something.new' }).outcome, 'require_approval');
});

test('RiskPolicy.default() is unchanged', () => {
  const policy = RiskPolicy.default({ autoApproveUnder: 100, denyActions: ['account.delete'] });
  assert.equal(policy.evaluate({ action: 'account.delete', params: {} }).outcome, 'deny');
  assert.equal(policy.evaluate({ action: 'refund.issue', params: { amount: 5 } }).outcome, 'auto_allow');
  assert.equal(policy.evaluate({ action: 'refund.issue', params: { amount: 5000 } }).outcome, 'require_approval');
});
