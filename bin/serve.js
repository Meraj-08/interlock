#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { InterlockServer, FileStore, RiskPolicy } from '../src/index.js';

// Durable, restart-safe state on disk.
const __dirname = dirname(fileURLToPath(import.meta.url));
const store = new FileStore(join(__dirname, '..', 'data', 'interlock.json'));

// INTERLOCK_POLICY=path/to/policy.json swaps the built-in rules for a policy file.
const policyPath = process.env.INTERLOCK_POLICY;
let policy;
try {
  policy = policyPath
    ? await RiskPolicy.fromFile(policyPath)
    : RiskPolicy.default({ autoApproveUnder: 100, denyActions: ['account.delete'] });
} catch (err) {
  console.error(`Interlock: ${err.message}`);
  process.exit(1);
}

const server = await InterlockServer.create({ store, policy });

// Seed one pending high-risk proposal so the console isn't empty on first run.
const pending = (await server.authority.list()).some((p) => p.state === 'pending');
if (!pending) {
  await server.authority.propose({
    agent: 'agent_support_bot',
    onBehalfOf: 'user_42',
    action: 'refund.issue',
    params: { amount: 5000, currency: 'USD', order: 'ord_9' },
    riskClass: 'high',
    consequence: 'Refund $5,000 to the customer card.',
  });
}

const port = await server.listen(process.env.PORT || 4000);
console.log(`\n🔒 Interlock server running`);
console.log(`   Console:  http://localhost:${port}/console`);
console.log(`   API:      http://localhost:${port}/api/proposals`);
console.log(`   State:    ${store.path}`);
console.log(`   Policy:   ${policyPath ?? 'built-in default'}\n`);
