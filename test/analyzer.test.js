import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ActionAnalyzer, ApprovalAuthority, Guard, RiskPolicy } from '../src/index.js';

test('flags large money movement as critical', async () => {
  const a = new ActionAnalyzer();
  const r = await a.analyze({ action: 'refund.issue', params: { amount: 48200 } });
  assert.equal(r.severity, 'critical');
  assert.ok(r.findings.some((f) => f.category === 'money'));
  assert.equal(r.escalate, true);
});

test('flags irreversible deletion', async () => {
  const a = new ActionAnalyzer();
  const r = await a.analyze({ action: 'workspace.delete', params: { id: 'ws_1' } });
  assert.ok(r.findings.some((f) => f.category === 'irreversible' && f.severity === 'critical'));
});

test('flags an unseen destination but trusts a known one', async () => {
  const a = new ActionAnalyzer({ knownDestinations: ['acct_known'] });
  const unseen = await a.analyze({ action: 'payout.send', params: { amount: 5, account: 'acct_new' } });
  assert.ok(unseen.findings.some((f) => f.category === 'anomaly'));
  const known = await a.analyze({ action: 'payout.send', params: { amount: 5, account: 'acct_known' } });
  assert.ok(!known.findings.some((f) => f.category === 'anomaly'));
});

test('a clean, low-risk action produces no escalating findings', async () => {
  const a = new ActionAnalyzer();
  const r = await a.analyze({ action: 'note.add', params: { text: 'called customer' } });
  assert.equal(r.severity, 'info');
  assert.equal(r.escalate, false);
});

test('an LLM-style reviewer can add findings', async () => {
  const a = new ActionAnalyzer({
    reviewer: async () => [{ severity: 'warning', category: 'llm', message: 'Unusual for this agent.' }],
  });
  const r = await a.analyze({ action: 'note.add', params: {} });
  assert.ok(r.findings.some((f) => f.category === 'llm'));
});

test('analyzer escalates an auto-allow to human review', async () => {
  // Policy alone would auto-allow a low-risk action; the analyzer flags the
  // irreversible "purge" and forces a human approval.
  const authority = await ApprovalAuthority.create({ policy: RiskPolicy.default() });
  const guard = new Guard({ authority });
  const decision = await guard.propose({
    agent: 'agent_x', onBehalfOf: 'user_1', action: 'workspace.purge',
    params: {}, riskClass: 'low',
  });
  assert.equal(decision.outcome, 'needs_approval');
  assert.equal(decision.rule, 'analyzer');
  assert.ok(decision.review.findings.some((f) => f.category === 'irreversible'));
});
