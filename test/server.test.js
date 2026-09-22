import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InterlockServer } from '../src/index.js';

// End-to-end over real HTTP: an agent proposes, the console lists it, a human
// approves, the agent executes once, and a replay is refused.
test('HTTP: propose -> approve -> execute once -> replay blocked', async () => {
  const server = await InterlockServer.create();
  const port = await server.listen(0); // ephemeral port
  const base = `http://localhost:${port}`;

  try {
    // Agent proposes a high-risk action.
    const decision = await post(`${base}/api/propose`, {
      agent: 'agent_x', onBehalfOf: 'user_1', action: 'refund.issue',
      params: { amount: 5000 }, riskClass: 'high', consequence: 'Refund $5,000.',
    });
    assert.equal(decision.outcome, 'needs_approval');
    const id = decision.approvalId;

    // Console lists it as pending.
    const list = await get(`${base}/api/proposals`);
    assert.ok(list.find((p) => p.id === id && p.state === 'pending'));

    // Cannot execute before approval.
    const early = await post(`${base}/api/proposals/${id}/execute`, {});
    assert.equal(early.executed, false);

    // Human approves.
    const receipt = await post(`${base}/api/proposals/${id}/approve`, { approver: 'ops' });
    assert.equal(receipt.state, 'approved');

    // Agent executes once.
    const first = await post(`${base}/api/proposals/${id}/execute`, {});
    assert.equal(first.executed, true, first.reason);

    // Replay refused.
    const second = await post(`${base}/api/proposals/${id}/execute`, {});
    assert.equal(second.executed, false);
  } finally {
    await server.close();
  }
});

test('HTTP: tampered execute params are rejected', async () => {
  const server = await InterlockServer.create();
  const port = await server.listen(0);
  const base = `http://localhost:${port}`;
  try {
    const decision = await post(`${base}/api/propose`, {
      agent: 'agent_x', onBehalfOf: 'user_1', action: 'payout.send',
      params: { amount: 10, to: 'acct_a' }, riskClass: 'high',
    });
    await post(`${base}/api/proposals/${decision.approvalId}/approve`, { approver: 'ops' });
    const r = await post(`${base}/api/proposals/${decision.approvalId}/execute`, {
      params: { amount: 10000, to: 'acct_a' },
    });
    assert.equal(r.executed, false);
    assert.equal(r.reason, 'action_hash_mismatch');
  } finally {
    await server.close();
  }
});

async function post(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}
async function get(url) {
  return (await fetch(url)).json();
}
