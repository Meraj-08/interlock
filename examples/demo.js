/**
 * Interlock — human circuit-breaker for risky agent actions.
 * Fully offline narrated demo: `node examples/demo.js`
 *
 * A support agent tries to issue refunds and payouts. Low-risk runs itself;
 * high-risk waits for a human; a human approves the EXACT action; the agent
 * executes exactly once; replays and param-tampering are blocked; the authority
 * going down fails closed.
 */
import { ApprovalAuthority, Guard, RiskPolicy } from '../src/index.js';

const line = (s = '') => console.log(s);
const h = (s) => line(`\n\x1b[1m${s}\x1b[0m`);
const ok = (s) => line(`   \x1b[32m${s}\x1b[0m`);
const no = (s) => line(`   \x1b[31m${s}\x1b[0m`);

const authority = await ApprovalAuthority.create({
  policy: RiskPolicy.default({ autoApproveUnder: 100, denyActions: ['account.delete'] }),
});
const guard = new Guard({ authority });

const AGENT = 'agent_support_bot';
const USER = 'user_42';

// --- 1. low-risk: runs itself -------------------------------------------
h('1. Agent adds an internal note  (low risk)');
let d = await guard.propose({ agent: AGENT, onBehalfOf: USER, action: 'note.add', params: { text: 'called customer' }, riskClass: 'low' });
line(`   policy: ${d.outcome}  (${d.reason})`);
let r = await guard.execute(d.approvalId, () => 'note saved');
ok(`executed automatically -> ${r.result}`);

// --- 2. small refund under threshold: auto ------------------------------
h('2. Agent issues a $12 refund  (under auto-approve threshold)');
d = await guard.propose({ agent: AGENT, onBehalfOf: USER, action: 'refund.issue', params: { amount: 12, order: 'ord_1' }, riskClass: 'high' });
line(`   policy: ${d.outcome}  (${d.reason})`);
r = await guard.execute(d.approvalId, () => 'refunded $12');
ok(`executed -> ${r.result}`);

// --- 3. big refund: needs a human ---------------------------------------
h('3. Agent issues a $5,000 refund  (HIGH risk -> human circuit-breaker)');
d = await guard.propose({
  agent: AGENT, onBehalfOf: USER, action: 'refund.issue',
  params: { amount: 5000, currency: 'USD', order: 'ord_9' }, riskClass: 'high',
  consequence: 'Refund $5,000 to the customer card.',
});
line(`   policy: ${d.outcome}  (${d.reason})`);
line('   -- review card shown to the human --');
line(`      agent:       ${d.review.agent}`);
line(`      on behalf of ${d.review.onBehalfOf}`);
line(`      action:      ${d.review.action}  ${JSON.stringify(d.review.params)}`);
line(`      consequence: ${d.review.consequence}`);
line(`      hash:        ${d.review.action_hash.slice(0, 24)}...`);

const tooEarly = await guard.execute(d.approvalId, () => 'SHOULD NOT RUN');
no(`agent tries to run before approval -> refused (${tooEarly.reason})`);

line('   ...human reviews in the console and approves with a passkey...');
await authority.approve(d.approvalId, { approver: 'ops_alice', method: 'passkey' });
let ran = 0;
const done = await guard.execute(d.approvalId, () => { ran++; return 'refunded $5,000'; });
ok(`executed once -> ${done.result}`);

const replay = await guard.execute(d.approvalId, () => { ran++; return 'refunded AGAIN'; });
no(`agent replays the same approval -> blocked (${replay.reason}); ran ${ran} time(s)`);

// --- 4. tampering: approve $10, try to execute $10,000 ------------------
h('4. Agent approves a $10 payout, then tries to execute $10,000');
d = await guard.propose({ agent: AGENT, onBehalfOf: USER, action: 'payout.send', params: { amount: 10, to: 'acct_x' }, riskClass: 'high' });
await authority.approve(d.approvalId, { approver: 'ops_alice', method: 'passkey' });
const tamper = await guard.execute(d.approvalId, () => 'PAID $10,000', { params: { amount: 10000, to: 'acct_x' } });
no(`swapped params after approval -> blocked (${tamper.reason})`);

// --- 5. explicit deny ---------------------------------------------------
h('5. Agent tries to delete the account  (on the deny list)');
d = await guard.propose({ agent: AGENT, onBehalfOf: USER, action: 'account.delete', params: {}, riskClass: 'critical' });
no(`policy: ${d.outcome}  (${d.reason}) -- no approval offered`);

// --- 6. fail closed when the authority is down --------------------------
h('6. Authority unreachable at execution time  (fail closed)');
d = await guard.propose({ agent: AGENT, onBehalfOf: USER, action: 'refund.issue', params: { amount: 2500, order: 'ord_x' }, riskClass: 'high' });
await authority.approve(d.approvalId, { approver: 'ops_alice', method: 'passkey' });
const realFetch = authority.fetchImpl;
guard.verifier.cfg.fetchImpl = async (u, init) =>
  u.toString().includes('/.well-known/') ? realFetch(u, init) : Promise.reject(new Error('down'));
const down = await guard.execute(d.approvalId, () => 'SHOULD NOT RUN');
no(`verify/consume unreachable -> refused (${down.reason}), nothing executed`);

line('\nInterlock: agents move fast, humans hold the keys to the irreversible.\n');
