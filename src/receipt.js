/**
 * Receipt checks for the service that performs an action.
 *
 * Guarding only on the agent's machine is not enough: if the hook or agent host
 * is bypassed, the API that moves the money has no idea. With a receipt, that
 * API checks the approval itself:
 *
 *   agent  -> GET  /api/proposals/:id/receipt      (Interlock; approved only)
 *   agent  -> POST /transfers  Interlock-Receipt: <receipt>   (your service)
 *   target -> recompute the action hash from ITS OWN request params,
 *             verify the proof offline (signature + bindings),
 *             then consume it once at Interlock (POST /api/v1/verify)
 *
 * A receipt is the signed proof plus the binding context Interlock froze when
 * the action was proposed (nonce, subject, actor, resource). That context is
 * not trusted: it only feeds the hash, and any lie makes the hash differ from
 * the signed one. The action and params always come from the target's request,
 * so what runs is exactly what the person approved, once.
 */

import { decodeProtectedHeader } from 'jose';
import { actionHash } from './action-hash.js';
import { verifyProof } from './verify-offline.js';
import { verifyOnline } from './online.js';
import { createJwksCache } from './jwks.js';

export const RECEIPT_HEADER = 'Interlock-Receipt';

/** Pack a proof and its binding context into one header-safe token. */
export function encodeReceipt({ proof, binding }) {
  return Buffer.from(JSON.stringify({ v: 1, proof, binding }), 'utf8').toString('base64url');
}

function decodeReceipt(token) {
  try {
    const r = JSON.parse(Buffer.from(String(token), 'base64url').toString('utf8'));
    const b = r?.binding;
    const ok = r?.v === 1 && typeof r.proof === 'string' && b
      && ['nonce', 'subject', 'actor'].every((k) => typeof b[k] === 'string')
      && typeof b.resource?.type === 'string' && typeof b.resource?.id === 'string';
    return ok ? r : null;
  } catch {
    return null;
  }
}

/**
 * @param {Object} opts
 * @param {string} opts.interlock  Interlock server URL, e.g. http://localhost:4000
 * @param {typeof fetch} [opts.fetchImpl]
 */
export function createReceiptVerifier(opts) {
  const base = opts.interlock.replace(/\/+$/, '');
  const doFetch = opts.fetchImpl ?? fetch;
  const jwks = createJwksCache({ issuer: base, fetchImpl: doFetch });
  let config = null;

  async function loadConfig() {
    if (config) return config;
    const res = await doFetch(`${base}/.well-known/interlock.json`, { headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`config fetch failed: ${res.status}`);
    config = await res.json();
    return config;
  }

  /**
   * @param {string} token   The Interlock-Receipt header value.
   * @param {{action: string, params: Object}} expected  From the target's own request.
   * @returns {Promise<{ok: true, subject: string, actor: string, claims: Object}
   *   | {ok: false, reason: string}>}
   */
  async function verify(token, expected) {
    const receipt = decodeReceipt(token);
    if (!receipt) return { ok: false, reason: 'malformed_receipt' };
    const { proof, binding } = receipt;

    // Anything we cannot fetch fails closed.
    let cfg;
    try {
      cfg = await loadConfig();
    } catch {
      return { ok: false, reason: 'unavailable' };
    }
    let kid;
    try {
      kid = decodeProtectedHeader(proof).kid;
    } catch {
      return { ok: false, reason: 'malformed' };
    }
    let keys;
    try {
      keys = await jwks.getForKid(kid);
    } catch {
      return { ok: false, reason: 'unavailable' };
    }

    const expectedActionHash = actionHash({
      environment: cfg.environment,
      action: expected.action,
      resource: binding.resource,
      context: { params: expected.params, on_behalf_of: binding.subject },
      subject: binding.subject,
      actor: binding.actor,
      actorType: binding.actorType ?? 'agent',
      audience: cfg.audience,
      nonce: binding.nonce,
    });

    const offline = await verifyProof(proof, keys, {
      issuer: cfg.issuer,
      tenant: cfg.tenant,
      environment: cfg.environment,
      environmentKind: cfg.environmentKind,
      audience: cfg.audience,
      expectedAction: expected.action,
      expectedActionHash,
      actor: { id: binding.actor, type: binding.actorType ?? 'agent' },
    });
    if (!offline.valid) return { ok: false, reason: offline.reason };

    // The single-use boundary: consume at Interlock, shared with the guard.
    let online;
    try {
      online = await verifyOnline(
        proof,
        { audience: cfg.audience, expectedAction: expected.action, expectedActionHash, consume: true },
        { baseUrl: base, credential: '', fetchImpl: doFetch },
      );
    } catch {
      return { ok: false, reason: 'unavailable' };
    }
    if (!online.valid) return { ok: false, reason: online.reason ?? 'refused' };

    return { ok: true, subject: binding.subject, actor: binding.actor, claims: offline.claims };
  }

  return { verify };
}

const verifiers = new Map();
function verifierFor(interlock) {
  if (!verifiers.has(interlock)) verifiers.set(interlock, createReceiptVerifier({ interlock }));
  return verifiers.get(interlock);
}

function headerValue(req) {
  const h = req.headers?.[RECEIPT_HEADER.toLowerCase()];
  return Array.isArray(h) ? h[0] : h;
}

/**
 * Framework-free check of an incoming request.
 * @param {{headers: Object}} req
 * @param {{interlock?: string, verifier?: ReturnType<typeof createReceiptVerifier>, action: string, params: Object}} opts
 */
export async function verifyRequest(req, opts) {
  const token = headerValue(req);
  if (!token) return { ok: false, reason: 'receipt_required' };
  const verifier = opts.verifier ?? verifierFor(opts.interlock);
  return verifier.verify(token, { action: opts.action, params: opts.params });
}

/**
 * Express-style middleware `(req, res, next)`; also works with plain
 * node:http when the body is parsed first. Refuses with 401 when there is no
 * receipt and 403 when it does not check out. On success sets
 * `req.interlock = { subject, actor, claims }` and calls next().
 *
 * @param {Object} opts
 * @param {string} opts.interlock   Interlock server URL.
 * @param {string} opts.action      The action this route performs.
 * @param {(req) => Object} opts.params  The params the route will actually use.
 * @param {typeof fetch} [opts.fetchImpl]
 */
export function requireReceipt(opts) {
  const verifier = createReceiptVerifier({ interlock: opts.interlock, fetchImpl: opts.fetchImpl });
  return async function interlockReceipt(req, res, next) {
    let result;
    try {
      result = await verifyRequest(req, { verifier, action: opts.action, params: opts.params(req) });
    } catch {
      result = { ok: false, reason: 'unavailable' };
    }
    if (result.ok) {
      req.interlock = { subject: result.subject, actor: result.actor, claims: result.claims };
      return next();
    }
    const status = result.reason === 'receipt_required' ? 401 : 403;
    const error = status === 401 ? 'receipt_required' : 'receipt_refused';
    res.statusCode = status;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(status === 401 ? { error } : { error, reason: result.reason }));
  };
}
