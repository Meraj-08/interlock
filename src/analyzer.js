/**
 * ActionAnalyzer — an AI/heuristic risk reviewer for a proposed agent action.
 *
 * Where a RiskPolicy makes a coarse allow/approve/deny call, the analyzer looks
 * *into* the action and surfaces specific risk signals — large money movement,
 * a never-before-seen destination, privilege escalation, irreversible deletion,
 * sensitive data in the payload. Those findings do two things:
 *
 *   1. they can ESCALATE the decision (a critical finding forces human review,
 *      even if the base policy would have auto-allowed);
 *   2. they are shown to the human on the approval card, so a person approves
 *      with context instead of a raw JSON blob.
 *
 * Rules are heuristic and run offline by default. Pass `reviewer` (an async
 * function) to plug in an LLM-backed review — model-agnostic, same as the rest.
 */

/** @typedef {'info'|'warning'|'critical'} Severity */
/** @typedef {{severity: Severity, category: string, message: string}} Finding */

export class ActionAnalyzer {
  /**
   * @param {Object} [cfg]
   * @param {Array<(ctx: object) => Finding|Finding[]|null>} [cfg.rules] Extra rules.
   * @param {(ctx: object) => Promise<Finding[]>} [cfg.reviewer] Optional async LLM reviewer.
   * @param {string[]} [cfg.knownDestinations] Destinations considered trusted.
   */
  constructor(cfg = {}) {
    this.rules = [...DEFAULT_RULES, ...(cfg.rules ?? [])];
    this.reviewer = cfg.reviewer ?? null;
    this.known = new Set(cfg.knownDestinations ?? []);
  }

  /**
   * @param {Object} p { agent, onBehalfOf, action, params, riskClass, resource }
   * @returns {Promise<{findings: Finding[], severity: Severity, escalate: boolean}>}
   */
  async analyze(p) {
    const ctx = { ...p, known: this.known };
    /** @type {Finding[]} */
    let findings = [];
    for (const rule of this.rules) {
      try {
        const r = rule(ctx);
        if (Array.isArray(r)) findings.push(...r);
        else if (r) findings.push(r);
      } catch {
        /* a rule must never break a proposal */
      }
    }
    if (this.reviewer) {
      try { findings.push(...(await this.reviewer(ctx) ?? [])); } catch { /* best-effort */ }
    }
    const severity = topSeverity(findings);
    // Any critical or warning signal means a human should look.
    const escalate = severity === 'critical' || severity === 'warning';
    return { findings, severity, escalate };
  }
}

/** Highest severity present, else 'info'. */
function topSeverity(findings) {
  if (findings.some((f) => f.severity === 'critical')) return 'critical';
  if (findings.some((f) => f.severity === 'warning')) return 'warning';
  return 'info';
}

function amountOf(params) {
  const a = params?.amount ?? params?.amount_cents ?? params?.value;
  return typeof a === 'number' ? a : null;
}

/** The default offline heuristic rules. */
const DEFAULT_RULES = [
  // Large money movement.
  (c) => {
    const amt = amountOf(c.params);
    if (amt == null) return null;
    if (amt >= 10000) return { severity: 'critical', category: 'money', message: `Large transfer: ${amt.toLocaleString()} — well above typical.` };
    if (amt >= 1000) return { severity: 'warning', category: 'money', message: `Sizable amount: ${amt.toLocaleString()}.` };
    return null;
  },
  // Never-before-seen destination / account.
  (c) => {
    const dest = c.params?.destination ?? c.params?.account ?? c.params?.to;
    if (!dest) return null;
    if (!c.known.has(String(dest))) return { severity: 'warning', category: 'anomaly', message: `Destination "${dest}" has not been seen before.` };
    return null;
  },
  // Irreversible deletion / purge.
  (c) => {
    if (/\b(delete|remove|purge|drop|wipe)\b/i.test(c.action)) {
      return { severity: 'critical', category: 'irreversible', message: 'Irreversible deletion — cannot be undone once run.' };
    }
    return null;
  },
  // Privilege escalation / access change.
  (c) => {
    if (/\b(grant|role|admin|permission|access|privilege)\b/i.test(c.action) || /\badmin\b/i.test(JSON.stringify(c.params || {}))) {
      return { severity: 'warning', category: 'escalation', message: 'Changes permissions or grants access.' };
    }
    return null;
  },
  // Sensitive data in the payload.
  (c) => {
    const keys = Object.keys(c.params || {}).join(' ').toLowerCase();
    if (/\b(ssn|card|cvv|password|secret|token|api[_-]?key|private[_-]?key)\b/.test(keys)) {
      return { severity: 'critical', category: 'sensitive', message: 'Payload appears to contain sensitive data.' };
    }
    return null;
  },
  // Payout / banking destination change is inherently high-blast-radius.
  (c) => {
    if (/payout|bank|destination|withdraw/i.test(c.action)) {
      return { severity: 'warning', category: 'blast_radius', message: 'Redirects where future money is sent — high blast radius.' };
    }
    return null;
  },
];
