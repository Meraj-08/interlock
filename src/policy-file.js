/**
 * Declarative policy files.
 *
 * Compiles a JSON policy document into the ordered rules a RiskPolicy runs, so
 * what needs a human can be changed without writing code:
 *
 *   {
 *     "default": "require_approval",
 *     "rules": [
 *       { "id": "force-push", "match": { "action": "Bash", "params": { "command": "git push.*--force" } },
 *         "outcome": "require_approval" },
 *       { "id": "small-refund", "match": { "action": "refund.issue", "params": { "amount": { "lt": 100 } } },
 *         "outcome": "auto_allow" }
 *     ]
 *   }
 *
 * Match conditions (all present conditions must hold):
 *   action     "refund.issue", "read.*" (wildcard), or a list of either
 *   riskClass  "high" or a list
 *   params     per param: a string is a regex searched in the value, a number
 *              or boolean must be equal, or an object of operators
 *              { lt, lte, gt, gte, eq, in, regex }
 *
 * Everything is validated at load time: a bad policy fails loudly with the
 * rule id and field, never silently at runtime.
 */

export const OUTCOMES = ['auto_allow', 'require_approval', 'deny'];
const RISK_CLASSES = ['low', 'elevated', 'high', 'critical'];
const POLICY_FIELDS = ['default', 'rules'];
const RULE_FIELDS = ['id', 'match', 'outcome', 'reason'];
const MATCH_FIELDS = ['action', 'riskClass', 'params'];
const NUMERIC_OPS = ['lt', 'lte', 'gt', 'gte'];
const OPERATORS = [...NUMERIC_OPS, 'eq', 'in', 'regex'];

export class PolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyError';
  }
}

/**
 * Validate a policy document and compile it.
 * @param {unknown} doc
 * @returns {{ rules: Array<{name: string, match: Function, outcome: string, reason?: string}>, defaultOutcome: string }}
 */
export function compilePolicy(doc) {
  if (!isPlainObject(doc)) throw new PolicyError('policy must be an object');
  rejectUnknown(doc, POLICY_FIELDS, 'unknown field');

  const defaultOutcome = doc.default ?? 'require_approval';
  if (!OUTCOMES.includes(defaultOutcome)) {
    throw new PolicyError(`"default" must be one of ${OUTCOMES.join(', ')}`);
  }
  if (!Array.isArray(doc.rules)) throw new PolicyError('"rules" must be an array');

  const seen = new Set();
  const rules = doc.rules.map((r, i) => {
    if (!isPlainObject(r)) throw new PolicyError(`rule #${i + 1}: must be an object`);
    if (typeof r.id !== 'string' || r.id.trim() === '') {
      throw new PolicyError(`rule #${i + 1}: "id" must be a non-empty string`);
    }
    const fail = (msg) => new PolicyError(`rule "${r.id}": ${msg}`);
    if (seen.has(r.id)) throw fail('duplicate id');
    seen.add(r.id);
    rejectUnknown(r, RULE_FIELDS, 'unknown field', fail);
    if (!OUTCOMES.includes(r.outcome)) throw fail(`"outcome" must be one of ${OUTCOMES.join(', ')}`);
    if (r.reason !== undefined && typeof r.reason !== 'string') throw fail('"reason" must be a string');
    if (!isPlainObject(r.match)) throw fail('"match" must be an object');

    return { name: r.id, match: compileMatch(r.match, fail), outcome: r.outcome, reason: r.reason };
  });

  return { rules, defaultOutcome };
}

function compileMatch(match, fail) {
  rejectUnknown(match, MATCH_FIELDS, 'unknown match field', fail);
  const checks = [];

  if (match.action !== undefined) {
    const patterns = toStringList(match.action, fail, '"action" must be a string or an array of strings');
    const res = patterns.map(wildcard);
    checks.push((p) => typeof p.action === 'string' && res.some((re) => re.test(p.action)));
  }

  if (match.riskClass !== undefined) {
    const classes = toStringList(match.riskClass, fail, `"riskClass" must be one of ${RISK_CLASSES.join(', ')}`);
    for (const c of classes) {
      if (!RISK_CLASSES.includes(c)) throw fail(`"riskClass" must be one of ${RISK_CLASSES.join(', ')}`);
    }
    checks.push((p) => classes.includes(p.riskClass));
  }

  if (match.params !== undefined) {
    if (!isPlainObject(match.params)) throw fail('"params" must be an object');
    for (const [name, cond] of Object.entries(match.params)) {
      const test = compileCondition(cond, `params.${name}`, fail);
      checks.push((p) => isPlainObject(p.params) && Object.hasOwn(p.params, name) && test(p.params[name]));
    }
  }

  return (proposal) => checks.every((check) => check(proposal ?? {}));
}

function compileCondition(cond, where, fail) {
  if (typeof cond === 'string') return regexTest(cond, where, fail);
  if (typeof cond === 'number' || typeof cond === 'boolean') return (v) => v === cond;
  if (!isPlainObject(cond)) throw fail(`${where}: must be a string, number, boolean, or an object of operators`);

  const ops = Object.keys(cond);
  if (ops.length === 0) throw fail(`${where}: needs at least one operator (${OPERATORS.join(', ')})`);
  const tests = ops.map((op) => {
    const arg = cond[op];
    if (!OPERATORS.includes(op)) throw fail(`${where}: unknown operator "${op}"`);
    if (NUMERIC_OPS.includes(op)) {
      if (typeof arg !== 'number' || !Number.isFinite(arg)) throw fail(`${where}.${op} must be a number`);
      const cmp = { lt: (v) => v < arg, lte: (v) => v <= arg, gt: (v) => v > arg, gte: (v) => v >= arg }[op];
      return (v) => typeof v === 'number' && cmp(v);
    }
    if (op === 'eq') return (v) => v === arg;
    if (op === 'in') {
      if (!Array.isArray(arg)) throw fail(`${where}.in must be an array`);
      return (v) => arg.includes(v);
    }
    if (typeof arg !== 'string') throw fail(`${where}.regex must be a string`);
    return regexTest(arg, where, fail);
  });
  return (v) => tests.every((t) => t(v));
}

function regexTest(source, where, fail) {
  let re;
  try {
    re = new RegExp(source);
  } catch (err) {
    throw fail(`${where}: invalid regular expression (${err.message})`);
  }
  return (v) => (typeof v === 'string' || typeof v === 'number') && re.test(String(v));
}

/** "read.*" -> /^read\..*$/ : only * is special. */
function wildcard(pattern) {
  const escaped = pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${escaped}$`);
}

function toStringList(value, fail, message) {
  const list = Array.isArray(value) ? value : [value];
  if (list.length === 0 || !list.every((s) => typeof s === 'string')) throw fail(message);
  return list;
}

function rejectUnknown(obj, allowed, label, fail = (m) => new PolicyError(m)) {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) throw fail(`${label} "${key}"`);
  }
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}
