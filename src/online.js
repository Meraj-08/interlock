/**
 * Online proof verification + one-time consumption against the GrayPass API.
 *
 * Wraps `POST /api/v1/verify`. A valid offline signature does NOT reveal current
 * revocation/consumption state, so the execution flow requires this step. With
 * `consume: true` the server accepts the proof only once via a scoped
 * conditional state change -- this is the real single-use boundary.
 *
 * Transport note (from the docs): a 200 response can still carry `valid: false`
 * (malformed, expired, mismatched, revoked, unknown, consumed). Always inspect
 * `valid`; a successful HTTP response alone is not permission to execute. If the
 * request fails or is ambiguous, keep the operation unexecuted and reconcile
 * against your own durable request ledger -- never blind-replay the business
 * mutation.
 *
 * @param {string} proof  Compact JWS.
 * @param {Object} expected
 * @param {string} expected.audience
 * @param {string} expected.expectedAction
 * @param {string} expected.expectedActionHash  64-hex, from your frozen request.
 * @param {boolean} [expected.consume]  Default false (status check only).
 * @param {Object} opts
 * @param {string} opts.baseUrl  e.g. https://app.graypass.org
 * @param {string} opts.credential  Server credential (Authorization: Bearer ...).
 * @param {typeof fetch} [opts.fetchImpl]
 * @returns {Promise<{valid: boolean, reason?: string|null, claims?: Object|null}>}
 */
export async function verifyOnline(proof, expected, opts) {
  const doFetch = opts.fetchImpl ?? fetch;
  const res = await doFetch(new URL('/api/v1/verify', opts.baseUrl).toString(), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      authorization: `Bearer ${opts.credential}`,
    },
    body: JSON.stringify({
      proof,
      audience: expected.audience,
      expected_action: expected.expectedAction,
      expected_action_hash: expected.expectedActionHash,
      consume: expected.consume ?? false,
    }),
  });

  // Only 200 carries a decision body; anything else is a transport/input problem
  // and must be treated as "do not execute".
  if (res.status !== 200) {
    return { valid: false, reason: `transport_${res.status}`, claims: null };
  }
  const body = await res.json();
  return { valid: body.valid === true, reason: body.reason ?? null, claims: body.claims ?? null };
}

/**
 * Read-only proof state lookup: `GET /api/v1/proofs/{jti}/status`.
 * Does not reserve the proof; state may change before a later consumption.
 * @returns {Promise<{jti: string, status: 'active'|'consumed'|'revoked'|'expired'|'unknown', expires_at?: string|null, revoked_at?: string|null}>}
 */
export async function proofStatus(jti, opts) {
  const doFetch = opts.fetchImpl ?? fetch;
  const res = await doFetch(
    new URL(`/api/v1/proofs/${encodeURIComponent(jti)}/status`, opts.baseUrl).toString(),
    { headers: { accept: 'application/json', authorization: `Bearer ${opts.credential}` } },
  );
  if (res.status !== 200) return { jti, status: 'unknown' };
  return res.json();
}
