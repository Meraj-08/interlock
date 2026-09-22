#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { InterlockServer, FileStore, RiskPolicy } from '../src/index.js';

// Durable, restart-safe state on disk.
const __dirname = dirname(fileURLToPath(import.meta.url));
const store = new FileStore(join(__dirname, '..', 'data', 'interlock.json'));

const server = await InterlockServer.create({
  store,
  policy: RiskPolicy.default({ autoApproveUnder: 100, denyActions: ['account.delete'] }),
});

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
console.log(`   State:    ${store.path}\n`);
