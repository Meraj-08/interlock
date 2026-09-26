import { resolve } from 'node:path';
import { InterlockServer } from './server.js';
import { FileStore } from './store.js';
import { RiskPolicy } from './policy.js';

/**
 * Start the approval service + console with durable state on disk.
 *
 * @param {Object} [opts]
 * @param {number} [opts.port]        Default 4000; 0 picks a free port.
 * @param {string} [opts.policyPath]  JSON policy file; the built-in default when omitted.
 * @param {string} [opts.dataPath]    State file. Default ./data/interlock.json.
 * @param {boolean} [opts.demo]       Seed one pending proposal so the console isn't empty.
 * @param {string} [opts.cwd]         Base for relative paths. Default process.cwd().
 * @returns {Promise<{server: InterlockServer, port: number, dataPath: string, policyPath: string|null}>}
 *   Throws PolicyError before listening if the policy file is invalid.
 */
export async function startServer(opts = {}) {
  const cwd = opts.cwd ?? process.cwd();
  const policyPath = opts.policyPath ? resolve(cwd, opts.policyPath) : null;
  const dataPath = resolve(cwd, opts.dataPath ?? 'data/interlock.json');

  const policy = policyPath
    ? await RiskPolicy.fromFile(policyPath)
    : RiskPolicy.default({ autoApproveUnder: 100, denyActions: ['account.delete'] });

  const server = await InterlockServer.create({ store: new FileStore(dataPath), policy });

  if (opts.demo) {
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
  }

  const port = await server.listen(opts.port ?? 4000);
  return { server, port, dataPath, policyPath };
}
