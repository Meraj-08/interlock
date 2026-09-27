import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  InterlockServer, createReceiptVerifier, requireReceipt, verifyRequest, RECEIPT_HEADER,
} from '../src/index.js';

const TRANSFER = 'payments.transfer';

/** Interlock + a separate "payments" service that only trusts receipts. */
async function withServices(fn) {
  const interlock = await InterlockServer.create();
  const iport = await interlock.listen(0);
  const interlockUrl = `http://localhost:${iport}`;

  const transfers = [];
  const guard = requireReceipt({
    interlock: interlockUrl,
    action: TRANSFER,
    params: (req) => ({ to: req.body.to, amount: req.body.amount }),
  });
  const target = createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    req.body = raw ? JSON.parse(raw) : {};
    guard(req, res, () => {
      transfers.push({ ...req.body, approvedFor: req.interlock.subject });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise((r) => target.listen(0, r));
  const targetUrl = `http://localhost:${target.address().port}`;

  try {
    await fn({ interlock, interlockUrl, targetUrl, transfers });
  } finally {
    await interlock.close();
    await new Promise((r) => target.close(r));
  }
}

async function proposeAndApprove(interlock, params, action = TRANSFER) {
  const d = await interlock.authority.propose({
    agent: 'agent_pay', onBehalfOf: 'user_7', action, params, riskClass: 'high',
  });
  assert.equal(d.outcome, 'needs_approval');
  await interlock.authority.approve(d.approvalId, { approver: 'ops_alice', method: 'passkey' });
  return d.approvalId;
}

async function getReceipt(interlockUrl, id) {
  const res = await fetch(`${interlockUrl}/api/proposals/${id}/receipt`);
  return { status: res.status, body: await res.json() };
}

async function callTarget(targetUrl, body, receipt) {
  const res = await fetch(`${targetUrl}/transfers`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(receipt ? { [RECEIPT_HEADER]: receipt } : {}) },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

test('an approved receipt lets the target run the exact action once', async () => {
  await withServices(async ({ interlock, interlockUrl, targetUrl, transfers }) => {
    const id = await proposeAndApprove(interlock, { to: 'acct_9', amount: 250 });
    const { status, body } = await getReceipt(interlockUrl, id);
    assert.equal(status, 200);
    assert.equal(typeof body.receipt, 'string');

    const first = await callTarget(targetUrl, { to: 'acct_9', amount: 250 }, body.receipt);
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.deepEqual(transfers, [{ to: 'acct_9', amount: 250, approvedFor: 'user_7' }]);

    const replay = await callTarget(targetUrl, { to: 'acct_9', amount: 250 }, body.receipt);
    assert.equal(replay.status, 403);
    assert.equal(replay.body.error, 'receipt_refused');
    assert.equal(replay.body.reason, 'consumed');
    assert.equal(transfers.length, 1);
  });
});

test('changed params are refused: approve 250, send 250000', async () => {
  await withServices(async ({ interlock, interlockUrl, targetUrl, transfers }) => {
    const id = await proposeAndApprove(interlock, { to: 'acct_9', amount: 250 });
    const { body } = await getReceipt(interlockUrl, id);
    const r = await callTarget(targetUrl, { to: 'acct_9', amount: 250000 }, body.receipt);
    assert.equal(r.status, 403);
    assert.equal(r.body.reason, 'action_hash_mismatch');
    assert.equal(transfers.length, 0);
  });
});

test('a receipt for a different action is refused', async () => {
  await withServices(async ({ interlock, interlockUrl, targetUrl, transfers }) => {
    const id = await proposeAndApprove(interlock, { to: 'acct_9', amount: 250 }, 'refund.issue');
    const { body } = await getReceipt(interlockUrl, id);
    const r = await callTarget(targetUrl, { to: 'acct_9', amount: 250 }, body.receipt);
    assert.equal(r.status, 403);
    assert.equal(r.body.reason, 'action_mismatch');
    assert.equal(transfers.length, 0);
  });
});

test('lying about the binding context breaks the hash', async () => {
  await withServices(async ({ interlock, interlockUrl, targetUrl, transfers }) => {
    const id = await proposeAndApprove(interlock, { to: 'acct_9', amount: 250 });
    const { body } = await getReceipt(interlockUrl, id);
    const decoded = JSON.parse(Buffer.from(body.receipt, 'base64url').toString('utf8'));
    decoded.binding.subject = 'user_admin';
    const forged = Buffer.from(JSON.stringify(decoded)).toString('base64url');
    const r = await callTarget(targetUrl, { to: 'acct_9', amount: 250 }, forged);
    assert.equal(r.status, 403);
    assert.equal(r.body.reason, 'action_hash_mismatch');
    assert.equal(transfers.length, 0);
  });
});

test('a missing receipt is 401, a malformed one is refused', async () => {
  await withServices(async ({ targetUrl, transfers }) => {
    const none = await callTarget(targetUrl, { to: 'acct_9', amount: 250 });
    assert.equal(none.status, 401);
    assert.equal(none.body.error, 'receipt_required');

    const junk = await callTarget(targetUrl, { to: 'acct_9', amount: 250 }, 'not-a-receipt');
    assert.equal(junk.status, 403);
    assert.equal(junk.body.reason, 'malformed_receipt');
    assert.equal(transfers.length, 0);
  });
});

test('a revoked proof is refused by the online check', async () => {
  await withServices(async ({ interlock, interlockUrl, targetUrl }) => {
    const id = await proposeAndApprove(interlock, { to: 'acct_9', amount: 250 });
    const { body } = await getReceipt(interlockUrl, id);
    const p = await interlock.authority.get(id);
    await interlock.authority.signer.setProofState(p.jti, 'revoked');
    const r = await callTarget(targetUrl, { to: 'acct_9', amount: 250 }, body.receipt);
    assert.equal(r.status, 403);
    assert.equal(r.body.reason, 'revoked');
  });
});

test('the receipt endpoint only hands out usable receipts', async () => {
  await withServices(async ({ interlock, interlockUrl }) => {
    const pending = await interlock.authority.propose({
      agent: 'a', onBehalfOf: 'u', action: TRANSFER, params: { amount: 5000 }, riskClass: 'high',
    });
    assert.equal((await getReceipt(interlockUrl, pending.approvalId)).status, 409);

    await interlock.authority.deny(pending.approvalId, { approver: 'ops' });
    const denied = await getReceipt(interlockUrl, pending.approvalId);
    assert.equal(denied.status, 409);
    assert.equal(denied.body.error, 'not_approved');

    // Used through the agent-side guard: the receipt is gone.
    const id = await proposeAndApprove(interlock, { to: 'acct_9', amount: 250 });
    assert.equal((await interlock.guard.execute(id, () => {})).executed, true);
    const used = await getReceipt(interlockUrl, id);
    assert.equal(used.status, 410);
    assert.equal(used.body.error, 'receipt_used');

    assert.equal((await getReceipt(interlockUrl, 'apr_nope')).status, 404);
  });
});

test('a receipt used at the target cannot also be executed through the guard', async () => {
  await withServices(async ({ interlock, interlockUrl, targetUrl }) => {
    const id = await proposeAndApprove(interlock, { to: 'acct_9', amount: 250 });
    const { body } = await getReceipt(interlockUrl, id);
    assert.equal((await callTarget(targetUrl, { to: 'acct_9', amount: 250 }, body.receipt)).status, 200);
    assert.equal((await interlock.guard.execute(id, () => {})).executed, false);
  });
});

test('verification fails closed when Interlock is unreachable', async () => {
  const verifier = createReceiptVerifier({ interlock: 'http://127.0.0.1:1' });
  const token = Buffer.from(JSON.stringify({
    v: 1, proof: 'a.b.c', binding: { nonce: 'n', subject: 's', actor: 'a', actorType: 'agent', resource: { type: 't', id: 'i' } },
  })).toString('base64url');
  const r = await verifier.verify(token, { action: TRANSFER, params: {} });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unavailable');
});

test('verifyRequest works without any framework', async () => {
  await withServices(async ({ interlock, interlockUrl }) => {
    const id = await proposeAndApprove(interlock, { to: 'acct_9', amount: 250 });
    const { body } = await getReceipt(interlockUrl, id);
    const req = { headers: { [RECEIPT_HEADER.toLowerCase()]: body.receipt } };
    const r = await verifyRequest(req, { interlock: interlockUrl, action: TRANSFER, params: { to: 'acct_9', amount: 250 } });
    assert.equal(r.ok, true);
    assert.equal(r.subject, 'user_7');
    assert.equal(r.actor, 'agent_pay');
  });
});

test('the discovery document describes how to verify', async () => {
  await withServices(async ({ interlock, interlockUrl }) => {
    const cfg = await (await fetch(`${interlockUrl}/.well-known/interlock.json`)).json();
    assert.equal(cfg.issuer, interlock.authority.issuer);
    assert.equal(cfg.audience, interlock.authority.audience);
    assert.equal(cfg.environment, interlock.authority.environment);
    assert.equal(cfg.tenant, interlock.authority.tenant);
    const jwks = await (await fetch(`${interlockUrl}/.well-known/graypass-proof-keys.json`)).json();
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0].d, undefined, 'no private key material');
  });
});
