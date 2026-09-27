/**
 * Receipts: the service that moves the money checks the approval itself.
 * Offline narrated demo: `node examples/receipt-demo.js`
 *
 * Two separate HTTP services: Interlock, and a small payments API guarded by
 * requireReceipt(). An agent gets a transfer approved, fetches its receipt,
 * and calls the payments API. The API runs the exact approved transfer once;
 * a replay, a bigger amount, or no receipt at all is refused. The payments
 * API never talks to the agent's machine and does not trust it.
 */
import { createServer } from 'node:http';
import { InterlockServer, requireReceipt, RECEIPT_HEADER } from '../src/index.js';

const line = (s = '') => console.log(s);
const h = (s) => line(`\n\x1b[1m${s}\x1b[0m`);
const ok = (s) => line(`   \x1b[32m${s}\x1b[0m`);
const no = (s) => line(`   \x1b[31m${s}\x1b[0m`);

// --- Interlock -------------------------------------------------------------
const interlock = await InterlockServer.create();
const interlockUrl = `http://localhost:${await interlock.listen(0)}`;

// --- The payments API: it only trusts receipts -------------------------------
const guard = requireReceipt({
  interlock: interlockUrl,
  action: 'payments.transfer',
  params: (req) => ({ to: req.body.to, amount: req.body.amount }),
});
const payments = createServer(async (req, res) => {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  req.body = JSON.parse(raw || '{}');
  guard(req, res, () => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ sent: req.body.amount, to: req.body.to, for: req.interlock.subject }));
  });
});
await new Promise((r) => payments.listen(0, r));
const paymentsUrl = `http://localhost:${payments.address().port}`;

async function transfer(body, receipt) {
  const res = await fetch(`${paymentsUrl}/transfers`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(receipt ? { [RECEIPT_HEADER]: receipt } : {}) },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}
const show = ({ status, body }) => (status === 200 ? ok : no)(`${status} ${JSON.stringify(body)}`);

// --- 1. approval -------------------------------------------------------------
h('1. Agent asks to send $2,500 to acct_9');
const d = await interlock.authority.propose({
  agent: 'agent_payouts', onBehalfOf: 'user_42', action: 'payments.transfer',
  params: { to: 'acct_9', amount: 2500 }, riskClass: 'high',
});
line(`   policy: ${d.outcome}  (${d.reason})`);
line('   ...a person approves it with a passkey in the console...');
await interlock.authority.approve(d.approvalId, { approver: 'ops_alice', method: 'passkey' });

const { receipt } = await (await fetch(`${interlockUrl}/api/proposals/${d.approvalId}/receipt`)).json();
line(`   agent fetched its receipt (${receipt.length} chars) from Interlock`);

// --- 2. the payments API checks it ------------------------------------------------
h('2. Agent calls the payments API with the receipt');
show(await transfer({ to: 'acct_9', amount: 2500 }, receipt));

h('3. Agent sends the same receipt again');
show(await transfer({ to: 'acct_9', amount: 2500 }, receipt));

h('4. A fresh approval for $2,500, but the agent sends $250,000');
const d2 = await interlock.authority.propose({
  agent: 'agent_payouts', onBehalfOf: 'user_42', action: 'payments.transfer',
  params: { to: 'acct_9', amount: 2500 }, riskClass: 'high',
});
await interlock.authority.approve(d2.approvalId, { approver: 'ops_alice', method: 'passkey' });
const r2 = (await (await fetch(`${interlockUrl}/api/proposals/${d2.approvalId}/receipt`)).json()).receipt;
show(await transfer({ to: 'acct_9', amount: 250000 }, r2));

h('5. Agent skips Interlock and calls the API directly');
show(await transfer({ to: 'acct_9', amount: 2500 }));

line();
await interlock.close();
payments.close();
