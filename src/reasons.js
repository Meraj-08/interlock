/**
 * The complete set of Proof-of-Agency verification refusal reasons documented
 * by GrayPass (https://app.graypass.org/docs/proofs, "Reading failures").
 *
 * These are stable identifiers. Log the reason and a trace id rather than the
 * raw proof. Never "fix" a mismatch by dropping a verifier expectation --
 * correct the request, configuration, or pending-request association instead.
 *
 * @readonly
 * @enum {string}
 */
export const Reason = Object.freeze({
  MALFORMED: 'malformed',
  UNSUPPORTED_ALG: 'unsupported_alg',
  UNKNOWN_KID: 'unknown_kid',
  INVALID_SIGNATURE: 'invalid_signature',
  ISSUER_MISMATCH: 'issuer_mismatch',
  AUDIENCE_MISMATCH: 'audience_mismatch',
  NOT_YET_VALID: 'not_yet_valid',
  EXPIRED: 'expired',
  TTL_TOO_LONG: 'ttl_too_long',
  NOT_ENFORCEABLE: 'not_enforceable',
  ENVIRONMENT_MISMATCH: 'environment_mismatch',
  TENANT_MISMATCH: 'tenant_mismatch',
  ACTOR_MISMATCH: 'actor_mismatch',
  ACTION_MISMATCH: 'action_mismatch',
  ACTION_HASH_MISMATCH: 'action_hash_mismatch',
  REPLAYED: 'replayed',
});

/** Human-readable descriptions, useful for demos and operator diagnostics. */
export const REASON_DESCRIPTIONS = Object.freeze({
  malformed: 'The token is not a well-formed compact JWS.',
  unsupported_alg: 'Header alg is not the expected ES256.',
  unknown_kid: 'The signing key id is not present in the trusted JWKS.',
  invalid_signature: 'The ES256 signature did not verify against the key.',
  issuer_mismatch: 'iss is not the configured GrayPass issuer.',
  audience_mismatch: 'aud is not the relying-party audience for this route.',
  not_yet_valid: 'nbf/iat is in the future beyond clock tolerance.',
  expired: 'exp is in the past beyond clock tolerance.',
  ttl_too_long: 'exp - iat exceeds the maximum accepted proof lifetime.',
  not_enforceable: 'Proof is not an enforce-mode allow; not usable to execute.',
  environment_mismatch: 'Environment id or kind does not match configuration.',
  tenant_mismatch: 'Tenant id does not match configuration.',
  actor_mismatch: 'Actor id/type does not match the expected actor.',
  action_mismatch: 'Bound action key is not the action this route implements.',
  action_hash_mismatch: 'Bound action hash != hash of the frozen pending request.',
  replayed: 'This proof id (jti) was already seen; possible reuse.',
});

/**
 * @typedef {Object} VerifyResult
 * @property {boolean} valid
 * @property {string=} reason  One of {@link Reason} when invalid.
 * @property {Object=} claims  Verified proof claims when valid.
 */

/** @returns {VerifyResult} */
export function fail(reason) {
  return { valid: false, reason };
}

/** @returns {VerifyResult} */
export function ok(claims) {
  return { valid: true, claims };
}
