import { Verifier } from './verifier.js';
import { actionHash } from './action-hash.js';

/**
 * Guard — the execution boundary an agent must pass through to actually run a
 * high-risk action. It ties the whole loop together:
 *
 *   1. propose()  -> asks the ApprovalAuthority for a policy decision.
 *   2. (a human approves out-of-band when required.)
 *   3. execute()  -> verifies the single-use proof with the Signet core,
 *                    consumes it once, and runs your action EXACTLY once.
 *
 * The Guard recomputes the action hash from the parameters the agent is ACTUALLY
 * about to execute. If the agent got approval for one thing and tries to execute
 * another (amount, recipient, …), the hash won't match the proof and execution
 * is refused. It fails closed on every error path: not approved, denied, expired,
 * replayed, tampered, or authority unavailable.
 */
export class Guard {
  /**
   * @param {Object} cfg
   * @param {import('./authority.js').ApprovalAuthority} cfg.authority
   */
  constructor(cfg) {
    this.authority = cfg.authority;
    this.verifier = new Verifier({
      issuer: cfg.authority.issuer,
      baseUrl: cfg.authority.issuer,
      credential: 'interlock',
      tenant: cfg.authority.tenant,
      environment: cfg.authority.environment,
      environmentKind: cfg.authority.environmentKind,
      fetchImpl: cfg.authority.fetchImpl,
    });
  }

  /** Convenience pass-through to the authority. */
  propose(proposal) {
    return this.authority.propose(proposal);
  }

  /**
   * Execute an approved action exactly once behind the proof check.
   *
   * @param {string} approvalId
   * @param {() => Promise<any>|any} fn  Your business action. Runs at most once.
   * @param {Object} [opts]
   * @param {Object} [opts.params]  The params the agent will actually use.
   *   Defaults to the approved params. Pass different params to see tampering
   *   rejected (action_hash_mismatch).
   * @returns {Promise<{executed: boolean, reason?: string, phase?: string, result?: any}>}
   */
  async execute(approvalId, fn, opts = {}) {
    const proposal = this.authority.get(approvalId);
    if (!proposal) return { executed: false, reason: 'unknown_approval' };
    if (proposal.state === 'pending') return { executed: false, reason: 'awaiting_approval' };
    if (proposal.state === 'denied') return { executed: false, reason: 'denied' };
    if (proposal.state !== 'approved' || !proposal.proof) {
      return { executed: false, reason: `not_executable_${proposal.state}` };
    }

    // Recompute the binding from what the agent is ACTUALLY about to do.
    const effectiveParams = opts.params ?? proposal.params;
    const request = {
      ...proposal.request,
      context: { ...proposal.request.context, params: effectiveParams },
    };
    const expectedActionHash = actionHash(request);

    const verdict = await this.verifier.authorizeExecution(proposal.proof, {
      audience: this.authority.audience,
      expectedAction: proposal.action,
      expectedActionHash,
      actor: { id: proposal.agent, type: 'agent' },
    });

    if (!verdict.execute) {
      return { executed: false, reason: verdict.reason, phase: verdict.phase };
    }

    // Proof verified and consumed exactly once. Run the business action.
    const result = await fn();
    return { executed: true, result };
  }
}
