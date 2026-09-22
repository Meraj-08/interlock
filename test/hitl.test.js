import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApprovalAuthority, Guard, RiskPolicy } from '../src/index.js';

const AGENT = 'agent_support_bot';
const USER = 'user_42';

async function setup(policy) {
  const authority = await ApprovalAuthority.create({ policy });
  const guard = new Guard({ authority });
  return { authority, guard };
}

const refund = (amount) => ({
  agent: AGENT,
  onBehalfOf: USER,
  action: 'refund.issue',
  params: { amount, currency: 'USD', order: 'ord_9' },
  riskClass: 'high',
  consequence: `Refund $${amount} to the customer.`,
});

test('high-risk action needs approval, then executes exactly once', async () => {
  const { authority, guard } = await setup();
  let ran = 0;

  const decision = await guard.propose(refund(5000));
  assert.equal(decision.outcome, 'needs_approval');
  assert.ok(decision.review.action_hash);

  // Cannot execute while pending.
  const early = await guard.execute(decision.approvalId, () => ++ran);
  assert.equal(early.executed, false);
  assert.equal(early.reason, 'awaiting_approval');
  assert.equal(ran, 0);

  // Human approves the exact action.
  await authority.approve(decision.approvalId, { approver: 'ops_alice', method: 'passkey' });

  const first = await guard.execute(decision.approvalId, () => ++ran);
  assert.equal(first.executed, true);
  assert.equal(ran, 1);

  // Replay -> proof already consumed -> blocked, action not re-run.
  const second = await guard.execute(decision.approvalId, () => ++ran);
  assert.equal(second.executed, false);
  assert.equal(ran, 1, 'business action must not run twice');
});

test('low-risk action auto-allows and runs without a human', async () => {
  const { guard } = await setup();
  const decision = await guard.propose({
    agent: AGENT, onBehalfOf: USER, action: 'note.add',
    params: { text: 'hi' }, riskClass: 'low',
  });
  assert.equal(decision.outcome, 'auto_allow');
  const r = await guard.execute(decision.approvalId, () => 'done');
  assert.equal(r.executed, true);
  assert.equal(r.result, 'done');
});

test('denied by policy -> never executable', async () => {
  const policy = RiskPolicy.default({ denyActions: ['account.delete'] });
  const { guard } = await setup(policy);
  const decision = await guard.propose({
    agent: AGENT, onBehalfOf: USER, action: 'account.delete', params: {}, riskClass: 'critical',
  });
  assert.equal(decision.outcome, 'deny');
  const r = await guard.execute(decision.approvalId ?? 'apr_none', () => 'boom');
  assert.equal(r.executed, false);
});

test('human deny stops execution', async () => {
  const { authority, guard } = await setup();
  const decision = await guard.propose(refund(9000));
  await authority.deny(decision.approvalId, { approver: 'ops_bob', reason: 'suspicious' });
  const r = await guard.execute(decision.approvalId, () => 'boom');
  assert.equal(r.executed, false);
  assert.equal(r.reason, 'denied');
});

test('tampered params after approval are rejected (approve $10, execute $10000)', async () => {
  const { authority, guard } = await setup();
  const decision = await guard.propose({
    agent: AGENT, onBehalfOf: USER, action: 'payout.send',
    params: { amount: 10, to: 'acct_self' }, riskClass: 'high',
  });
  await authority.approve(decision.approvalId, { approver: 'ops_alice', method: 'passkey' });

  // Agent got approval for $10 but tries to execute $10,000.
  let ran = 0;
  const r = await guard.execute(decision.approvalId, () => ++ran, {
    params: { amount: 10000, to: 'acct_self' },
  });
  assert.equal(r.executed, false);
  assert.equal(r.reason, 'action_hash_mismatch');
  assert.equal(ran, 0);
});

test('fails closed when the authority is unreachable', async () => {
  const { authority, guard } = await setup();
  const decision = await guard.propose(refund(2500));
  await authority.approve(decision.approvalId, { approver: 'ops_alice', method: 'passkey' });

  // Break the online verify/consume path only.
  const realFetch = authority.fetchImpl;
  guard.verifier.cfg.fetchImpl = async (u, init) =>
    u.toString().includes('/.well-known/') ? realFetch(u, init) : Promise.reject(new Error('down'));

  const r = await guard.execute(decision.approvalId, () => 'boom');
  assert.equal(r.executed, false);
  assert.equal(r.reason, 'unavailable');
});

test('approve is idempotent', async () => {
  const { authority, guard } = await setup();
  const decision = await guard.propose(refund(3000));
  const a = await authority.approve(decision.approvalId, { approver: 'ops_alice' });
  const b = await authority.approve(decision.approvalId, { approver: 'ops_alice' });
  assert.equal(a.jti, b.jti, 'second approve must not mint a new proof');
});
