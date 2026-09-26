/**
 * RiskPolicy — decides whether a proposed agent action can run automatically,
 * needs a human's approval, or must be denied outright.
 *
 * This is the "circuit breaker" logic: agents run at machine speed, so the
 * dangerous case is an irreversible action (move money, delete data, email all
 * customers). The policy classifies each proposal into one of three outcomes.
 *
 * Rules are evaluated in order; the first match wins. A rule may inspect the
 * action key, the declared risk class, and the concrete params (e.g. amount).
 * Anything not matched falls through to `defaultOutcome`.
 *
 * Rules can be written in code (rule()) or loaded from a JSON policy file
 * (RiskPolicy.fromFile / fromJSON).
 */

import { readFile } from 'node:fs/promises';
import { compilePolicy, PolicyError } from './policy-file.js';

/** @typedef {'auto_allow'|'require_approval'|'deny'} Outcome */

export class RiskPolicy {
  /**
   * @param {Object} [cfg]
   * @param {Array<Rule>} [cfg.rules]  Ordered rules; first match wins.
   * @param {Outcome} [cfg.defaultOutcome]  Default 'require_approval' (fail safe).
   */
  constructor(cfg = {}) {
    this.rules = cfg.rules ?? [];
    this.defaultOutcome = cfg.defaultOutcome ?? 'require_approval';
  }

  /**
   * @param {Object} proposal
   * @param {string} proposal.action
   * @param {'low'|'elevated'|'high'|'critical'} [proposal.riskClass]
   * @param {Object} [proposal.params]
   * @returns {{outcome: Outcome, rule: string, reason: string}}
   */
  evaluate(proposal) {
    for (const rule of this.rules) {
      if (rule.match(proposal)) {
        return { outcome: rule.outcome, rule: rule.name, reason: rule.reason ?? rule.name };
      }
    }
    return { outcome: this.defaultOutcome, rule: 'default', reason: 'no rule matched; default applied' };
  }

  /**
   * Build a policy from a parsed policy document (see policy-file.js for the
   * format). Throws PolicyError naming the rule and field if it is invalid.
   * @param {unknown} doc
   */
  static fromJSON(doc) {
    return new RiskPolicy(compilePolicy(doc));
  }

  /**
   * Load a policy file (JSON). Errors include the file path.
   * @param {string} path
   */
  static async fromFile(path) {
    let text;
    try {
      text = await readFile(path, 'utf8');
    } catch (err) {
      throw new PolicyError(`${path}: cannot read policy file (${err.code ?? err.message})`);
    }
    let doc;
    try {
      doc = JSON.parse(text);
    } catch (err) {
      throw new PolicyError(`${path}: not valid JSON (${err.message})`);
    }
    try {
      return RiskPolicy.fromJSON(doc);
    } catch (err) {
      if (err instanceof PolicyError) throw new PolicyError(`${path}: ${err.message}`);
      throw err;
    }
  }

  /**
   * A sensible starting policy for financial/agent actions:
   *  - explicit deny list is refused,
   *  - low risk runs automatically,
   *  - money movement over a threshold or high/critical risk needs a human,
   *  - everything else needs a human (fail safe).
   * @param {Object} [opts]
   * @param {number} [opts.autoApproveUnder]  Amount below which money moves auto-run. Default 100.
   * @param {string[]} [opts.denyActions]     Action keys always denied.
   */
  static default(opts = {}) {
    const cap = opts.autoApproveUnder ?? 100;
    const denyList = new Set(opts.denyActions ?? []);
    return new RiskPolicy({
      rules: [
        rule('deny-list', (p) => denyList.has(p.action), 'deny', 'action is on the deny list'),
        rule('low-risk-auto', (p) => p.riskClass === 'low', 'auto_allow', 'declared low risk'),
        rule('small-amount-auto', (p) => amount(p) !== null && amount(p) < cap, 'auto_allow', `amount under ${cap}`),
        rule('high-risk-human', (p) => p.riskClass === 'high' || p.riskClass === 'critical', 'require_approval', 'high/critical risk'),
        rule('money-movement-human', (p) => amount(p) !== null, 'require_approval', 'money movement needs a human'),
      ],
      defaultOutcome: 'require_approval',
    });
  }
}

/**
 * @typedef {Object} Rule
 * @property {string} name
 * @property {(p: Object) => boolean} match
 * @property {Outcome} outcome
 * @property {string} [reason]
 */

/** @returns {Rule} */
export function rule(name, match, outcome, reason) {
  return { name, match, outcome, reason };
}

/** Extract a numeric amount from common param shapes, or null. */
function amount(p) {
  const a = p.params?.amount ?? p.params?.amount_cents ?? p.params?.value;
  return typeof a === 'number' ? a : null;
}
