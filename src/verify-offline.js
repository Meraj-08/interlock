import { compactVerify, importJWK, decodeProtectedHeader, decodeJwt } from 'jose';
import { Reason, fail, ok } from './reasons.js';

const HOSTED_ISSUER = 'https://app.graypass.org';

/**
 * @typedef {Object} Expected
 * @property {string} [issuer]              Configured GrayPass issuer. Default hosted issuer.
 * @property {string} tenant                Tenant id from your credential identity.
 * @property {string} environment           Environment id (sandbox/live boundary).
 * @property {'sandbox'|'live'} [environmentKind]
 * @property {string} audience              Relying-party audience for this route.
 * @property {string} expectedAction        Action key this route implements.
 * @property {string} expectedActionHash    64-hex hash of the frozen pending request.
 * @property {number} [maxTtlSeconds]       Max accepted proof lifetime. Default 300.
 * @property {number} [clockToleranceSeconds] Default 5.
 * @property {boolean} [requireEnforceable] Default true.
 * @property {{id?: string, type?: string}} [actor] Optional actor constraint.
 */

/**
 * Purely local (no network) cryptographic + claims verification of a compact
 * Proof-of-Agency JWS against an already-obtained JWKS.
 *
 * This mirrors the checks GrayPass documents for its Node verifier's
 * `verifyProof()`: signature, algorithm, key id, issuer, time bounds and maximum
 * lifetime, audience, tenant, environment, enforceability, actor constraints,
 * action, and request hash -- plus optional single-process replay tracking.
 *
 * IMPORTANT: an offline-valid proof is NOT necessarily active, unrevoked, or
 * unconsumed. You MUST follow this with the online status + consume step
 * (see {@link module:online}) before executing. This function never executes
 * anything; it returns a decision only.
 *
 * @param {string} compactJws
 * @param {{keys: Array<Object>}} jwks  Trusted key set (fetched from the configured origin).
 * @param {Expected} expected
 * @param {Object} [opts]
 * @param {number} [opts.now]  Unix seconds; injectable for testing.
 * @param {{seen(jti: string): boolean, remember(jti: string, exp: number): void}} [opts.replayStore]
 * @returns {Promise<import('./reasons.js').VerifyResult>}
 */
export async function verifyProof(compactJws, jwks, expected, opts = {}) {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const tolerance = expected.clockToleranceSeconds ?? 5;
  const maxTtl = expected.maxTtlSeconds ?? 300;
  const issuer = expected.issuer ?? HOSTED_ISSUER;
  const requireEnforceable = expected.requireEnforceable ?? true;

  // --- malformed: must parse as a compact JWS with a decodable header/payload
  let header;
  let unsafeClaims;
  try {
    header = decodeProtectedHeader(compactJws);
    unsafeClaims = decodeJwt(compactJws);
  } catch {
    return fail(Reason.MALFORMED);
  }
  if (!header || typeof unsafeClaims !== 'object') return fail(Reason.MALFORMED);

  // --- unsupported_alg: GrayPass proofs are ES256
  if (header.alg !== 'ES256') return fail(Reason.UNSUPPORTED_ALG);

  // --- unknown_kid: signing key must be in the trusted JWKS
  if (!header.kid) return fail(Reason.UNKNOWN_KID);
  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) return fail(Reason.UNKNOWN_KID);

  // --- invalid_signature: verify ES256 over the resolved key
  let claims;
  try {
    const key = await importJWK(jwk, 'ES256');
    const { payload } = await compactVerify(compactJws, key);
    claims = JSON.parse(new TextDecoder().decode(payload));
  } catch {
    return fail(Reason.INVALID_SIGNATURE);
  }

  const gp = claims.gp ?? {};

  // --- issuer_mismatch
  if (claims.iss !== issuer) return fail(Reason.ISSUER_MISMATCH);

  // --- audience_mismatch (aud may be a string or array per JWT spec)
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(expected.audience)) return fail(Reason.AUDIENCE_MISMATCH);

  // --- not_yet_valid
  const nbf = claims.nbf ?? claims.iat;
  if (typeof nbf === 'number' && nbf > now + tolerance) return fail(Reason.NOT_YET_VALID);

  // --- expired
  if (typeof claims.exp !== 'number') return fail(Reason.MALFORMED);
  if (claims.exp < now - tolerance) return fail(Reason.EXPIRED);

  // --- ttl_too_long: lifetime the issuer stamped must not exceed our max
  if (typeof claims.iat === 'number' && claims.exp - claims.iat > maxTtl) {
    return fail(Reason.TTL_TOO_LONG);
  }

  // --- not_enforceable: only an enforce-mode allow can authorize execution
  if (requireEnforceable && gp.enforceable !== true) return fail(Reason.NOT_ENFORCEABLE);

  // --- environment_mismatch (id and, if configured, kind)
  if (gp.env !== expected.environment) return fail(Reason.ENVIRONMENT_MISMATCH);
  if (expected.environmentKind && gp.env_kind !== expected.environmentKind) {
    return fail(Reason.ENVIRONMENT_MISMATCH);
  }

  // --- tenant_mismatch
  if (gp.tenant !== expected.tenant) return fail(Reason.TENANT_MISMATCH);

  // --- actor_mismatch (optional constraint)
  if (expected.actor) {
    const actor = gp.actor ?? {};
    if (expected.actor.id && actor.id !== expected.actor.id) return fail(Reason.ACTOR_MISMATCH);
    if (expected.actor.type && actor.type !== expected.actor.type) return fail(Reason.ACTOR_MISMATCH);
  }

  // --- action_mismatch
  if (gp.action !== expected.expectedAction) return fail(Reason.ACTION_MISMATCH);

  // --- action_hash_mismatch (constant-time-ish compare of equal-length hex)
  if (!hexEqual(gp.action_hash, expected.expectedActionHash)) {
    return fail(Reason.ACTION_HASH_MISMATCH);
  }

  // --- replayed: single-process reuse guard (cross-process needs a shared store)
  if (opts.replayStore) {
    if (opts.replayStore.seen(claims.jti)) return fail(Reason.REPLAYED);
    opts.replayStore.remember(claims.jti, claims.exp);
  }

  return ok(claims);
}

/** Length-checked, non-short-circuiting hex compare. */
function hexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
