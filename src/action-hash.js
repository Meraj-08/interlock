import { createHash } from 'node:crypto';

/**
 * Canonical request hashing for a GrayPass protected-action request.
 *
 * GrayPass binds every decision (and proof) to the exact business request via a
 * SHA-256 "action hash". The relying party MUST recompute this hash locally from
 * its own frozen pending request and configuration -- never read it out of the
 * proof it is checking (docs: "Compute the binding").
 *
 * The documented inputs (https://app.graypass.org/docs/proofs) are:
 *   environment, action, resource {type, id}, context, subject, actor,
 *   actorType, audience, nonce.
 *
 * NOTE ON CANONICALIZATION: GrayPass's exact byte-level canonicalization ships
 * inside `@graypass/node`'s `actionHash`. It is not published, so this module
 * implements a deterministic, documented canonical form (RFC 8785-style: object
 * keys sorted, no insignificant whitespace) and uses the SAME function on both
 * sides -- the bundled mock signer and this verifier. For LIVE traffic, pass the
 * `actionHash` you get back from the official SDK's `authorize()` /
 * `verification.actionHash` as `expectedActionHash` instead of recomputing here.
 * The verifier is agnostic to how the hash was produced; it only compares.
 *
 * @param {Object} input
 * @param {string} input.environment
 * @param {string} input.action
 * @param {{type: string, id: string}} input.resource
 * @param {Object} [input.context]
 * @param {string} input.subject
 * @param {string} input.actor
 * @param {string} [input.actorType]
 * @param {string} input.audience
 * @param {string} input.nonce
 * @returns {string} 64-character lowercase hex SHA-256 digest.
 */
export function actionHash(input) {
  const canonical = {
    action: input.action,
    actor: input.actor,
    actor_type: input.actorType ?? 'human',
    audience: input.audience,
    context: input.context ?? {},
    environment: input.environment,
    nonce: input.nonce,
    resource: { id: input.resource.id, type: input.resource.type },
    subject: input.subject,
  };
  return createHash('sha256').update(canonicalJson(canonical), 'utf8').digest('hex');
}

/**
 * Deterministic JSON serialization: object keys sorted recursively, arrays kept
 * in order, no insignificant whitespace. Stable across runs and platforms.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`);
  return `{${parts.join(',')}}`;
}
