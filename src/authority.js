import { MockGrayPass } from './mock/server.js';
import { actionHash } from './action-hash.js';
import { RiskPolicy } from './policy.js';
import { ActionAnalyzer } from './analyzer.js';
import { MemoryStore, namespaced } from './store.js';
import { randomUUID } from 'node:crypto';

/**
 * ApprovalAuthority — the human-in-the-loop authority.
 *
 * It receives an agent's proposed action, runs it through a {@link RiskPolicy},
 * and manages the approval lifecycle:
 *
 *   pending ──approve──▶ approved ──consumed (by the Guard, once)
 *      │
 *      ├──deny────────▶ denied
 *      └──(ttl)────────▶ expired
 *
 * On `auto_allow` or a human `approve`, it mints a single-use Proof of Agency
 * (ES256 JWS) bound to the FROZEN proposal — the exact agent, principal, action,
 * and params. It reuses the Signet verification core (via an internal signer +
 * a fetch-compatible /verify + JWKS surface) so the Guard's checks are real
 * cryptography, and it fails safe: nothing executes without a consumable proof.
 *
 * In production this authority is a service; the human approves in a console or
 * mobile prompt with a passkey. Here it runs in-memory for offline demos/tests.
 */
export class ApprovalAuthority {
  /**
   * @param {Object} [opts]
   * @param {RiskPolicy} [opts.policy]  Default RiskPolicy.default().
   * @param {number} [opts.approvalTtlSeconds]  How long an approval's proof lives. Default 300.
   * @param {string} [opts.environment] @param {string} [opts.audience]
   */
  static async create(opts = {}) {
    const a = new ApprovalAuthority();
    a.policy = opts.policy ?? RiskPolicy.default();
    a.analyzer = opts.analyzer ?? new ActionAnalyzer();
    a.store = opts.store ?? new MemoryStore();
    a.signer = await MockGrayPass.create({
      proofTtlSeconds: opts.approvalTtlSeconds ?? 300,
      store: namespaced(a.store, 'signer:'),
    });
    a.environment = a.signer.environment;
    a.environmentKind = a.signer.environmentKind;
    a.tenant = a.signer.tenant;
    a.issuer = a.signer.issuer;
    a.audience = opts.audience ?? 'agent-actions';
    a.proposalStore = namespaced(a.store, 'proposal:');
    a.fetchImpl = a.signer.fetchImpl; // Guard verifies/consumes against the signer.
    return a;
  }

  /**
   * An agent proposes an action. Returns the policy outcome and, when the action
   * may proceed (auto or after approval), an approval id the Guard will execute
   * against.
   *
   * @param {Object} p
   * @param {string} p.agent        Agent identity making the request.
   * @param {string} p.onBehalfOf   Human principal the agent acts for.
   * @param {string} p.action       Dotted action key, e.g. 'refund.issue'.
   * @param {Object} p.params       Concrete parameters (bound into the proof).
   * @param {'low'|'elevated'|'high'|'critical'} [p.riskClass]
   * @param {{type: string, id: string}} [p.resource]
   * @param {string} [p.consequence] Human-readable consequence for the reviewer.
   * @returns {Promise<{outcome: string, rule: string, reason: string, approvalId?: string, review?: Object}>}
   */
  async propose(p) {
    const decision = this.policy.evaluate({ action: p.action, riskClass: p.riskClass, params: p.params });

    // AI/heuristic review of the action itself — findings inform the decision
    // and give the human context.
    const analysis = await this.analyzer.analyze({
      agent: p.agent, onBehalfOf: p.onBehalfOf, action: p.action,
      params: p.params, riskClass: p.riskClass, resource: p.resource,
    });
    let { outcome, rule, reason } = decision;
    // A flagged action must not slip through on an auto-allow.
    if (outcome === 'auto_allow' && analysis.escalate) {
      outcome = 'require_approval';
      rule = 'analyzer';
      reason = `escalated by risk analysis (${analysis.severity})`;
    }

    const id = 'apr_' + randomUUID().slice(0, 12);
    const request = this._request(p);
    const hash = actionHash(request);

    /** @type {Proposal} */
    const proposal = {
      id,
      state: 'pending',
      request,
      hash,
      agent: p.agent,
      onBehalfOf: p.onBehalfOf,
      action: p.action,
      params: p.params,
      riskClass: p.riskClass ?? null,
      consequence: p.consequence ?? '',
      findings: analysis.findings,
      analysisSeverity: analysis.severity,
      proof: null,
      jti: null,
      approver: null,
      createdAt: Date.now(),
    };

    if (outcome === 'deny') {
      proposal.state = 'denied';
      await this.proposalStore.set(id, proposal);
      return { outcome: 'deny', rule, reason, findings: analysis.findings };
    }

    if (outcome === 'auto_allow') {
      await this._mint(proposal, { approver: 'policy:auto', method: 'auto' });
      return { outcome: 'auto_allow', rule, reason, approvalId: id, findings: analysis.findings };
    }

    // require_approval: hold for a human. Expose an immutable review card.
    await this.proposalStore.set(id, proposal);
    return {
      outcome: 'needs_approval',
      rule,
      reason,
      approvalId: id,
      review: this._card(proposal),
      findings: analysis.findings,
    };
  }

  /**
   * A human approves a pending proposal (passkey/click in the real world). Mints
   * the single-use proof bound to the frozen request. Idempotent per approval.
   * @param {string} id
   * @param {{approver: string, method?: 'passkey'|'click'}} by
   */
  async approve(id, by) {
    const proposal = await this.get(id);
    if (!proposal) throw new Error('unknown approval');
    if (proposal.state === 'approved') return this.receipt(proposal); // idempotent
    if (proposal.state !== 'pending') throw new Error(`cannot approve a ${proposal.state} proposal`);
    await this._mint(proposal, { approver: by.approver, method: by.method ?? 'click' });
    return this.receipt(proposal);
  }

  /** A human denies a pending proposal. */
  async deny(id, by = {}) {
    const proposal = await this.get(id);
    if (!proposal) throw new Error('unknown approval');
    if (proposal.state !== 'pending') throw new Error(`cannot deny a ${proposal.state} proposal`);
    proposal.state = 'denied';
    proposal.approver = by.approver ?? 'human';
    proposal.denyReason = by.reason ?? '';
    await this.proposalStore.set(id, proposal);
    return { id, state: 'denied' };
  }

  /** @param {string} id @returns {Promise<Proposal|null>} */
  async get(id) {
    return this.proposalStore.get(id);
  }

  /** All proposals, newest first — used by the console/service. */
  async list() {
    const all = await this.proposalStore.values();
    return all.sort((x, y) => y.createdAt - x.createdAt);
  }

  /**
   * The immutable details a human must see before approving. The reviewer
   * approves THIS exact card; the proof binds to its hash, so an agent cannot
   * approve one thing and execute another.
   */
  async reviewCard(id) {
    const p = await this.get(id);
    return p ? this._card(p) : null;
  }

  /** Build a review card from a proposal object. */
  _card(p) {
    return {
      approvalId: p.id,
      agent: p.agent,
      onBehalfOf: p.onBehalfOf,
      action: p.action,
      params: p.params,
      consequence: p.consequence,
      findings: p.findings ?? [],
      action_hash: p.hash,
    };
  }

  receipt(p) {
    return { id: p.id, state: p.state, approver: p.approver, jti: p.jti, action_hash: p.hash };
  }

  // --- internals ---------------------------------------------------------

  async _mint(proposal, by) {
    const { proof, jti } = await this.signer.issueProof({
      subject: proposal.onBehalfOf,
      action: proposal.action,
      audience: this.audience,
      actionHash: proposal.hash,
      actor: { id: proposal.agent, type: 'agent' },
    });
    proposal.proof = proof;
    proposal.jti = jti;
    proposal.state = 'approved';
    proposal.approver = by.approver;
    proposal.method = by.method;
    await this.proposalStore.set(proposal.id, proposal);
  }

  _request(p) {
    return {
      environment: this.environment,
      action: p.action,
      resource: p.resource ?? { type: 'agent_action', id: p.action },
      context: { params: p.params, on_behalf_of: p.onBehalfOf },
      subject: p.onBehalfOf,
      actor: p.agent,
      actorType: 'agent',
      audience: this.audience,
      nonce: 'nonce_' + randomUUID().slice(0, 12),
    };
  }
}

/**
 * @typedef {Object} Proposal
 * @property {string} id
 * @property {'pending'|'approved'|'denied'|'expired'} state
 * @property {Object} request
 * @property {string} hash
 * @property {string} agent
 * @property {string} onBehalfOf
 * @property {string} action
 * @property {Object} params
 * @property {string} consequence
 * @property {string|null} proof
 * @property {string|null} jti
 * @property {string|null} approver
 * @property {number} createdAt
 */
