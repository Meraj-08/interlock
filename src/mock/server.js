import { generateKeyPair, exportJWK, importJWK, SignJWT, base64url } from 'jose';
import { randomUUID, createHash } from 'node:crypto';
import { MemoryStore, namespaced } from '../store.js';

/**
 * In-memory mock of the GrayPass proof surface, for offline development, demos,
 * and tests. It mints REAL ES256 proofs (so the verifier does genuine crypto)
 * and serves a fetch-compatible router for:
 *   - GET  /.well-known/graypass-proof-keys.json
 *   - POST /api/v1/verify           (state check + one-time consume)
 *   - GET  /api/v1/proofs/{jti}/status
 *
 * Wire it into the Verifier by passing `mock.fetchImpl` as `fetchImpl`. Nothing
 * here talks to the network. The response shapes mirror the published OpenAPI.
 */
export class MockGrayPass {
  /**
   * @param {Object} [opts]
   * @param {string} [opts.issuer]       Default https://app.graypass.org
   * @param {string} [opts.tenant]       Default 'tnt_mock'
   * @param {string} [opts.environment]  Default 'env_sandbox'
   * @param {'sandbox'|'live'} [opts.environmentKind] Default 'sandbox'
   * @param {number} [opts.proofTtlSeconds] Default 300 (their action default).
   * @param {MemoryStore} [opts.store] Durable store. Default in-memory. When a
   *   persistent store is supplied, the signing key and proof state survive
   *   restarts (so previously issued proofs still verify and stay consumed).
   */
  static async create(opts = {}) {
    const m = new MockGrayPass();
    m.issuer = opts.issuer ?? 'https://app.graypass.org';
    m.origin = new URL(m.issuer).origin;
    m.tenant = opts.tenant ?? 'tnt_mock';
    m.environment = opts.environment ?? 'env_sandbox';
    m.environmentKind = opts.environmentKind ?? 'sandbox';
    m.proofTtl = opts.proofTtlSeconds ?? 300;

    m.store = opts.store ?? new MemoryStore();
    m.proofs = namespaced(m.store, 'proof:');

    const saved = await m.store.get('signer_key');
    if (saved) {
      // Restore the persisted signing key so old proofs remain verifiable.
      m.kid = saved.kid;
      m._priv = await importJWK(saved.privateJwk, 'ES256');
      m._pubJwk = saved.pubJwk;
    } else {
      const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
      m.kid = 'gpk_' + base64url.encode(randomUUID()).slice(0, 12);
      m._priv = privateKey;
      m._pubJwk = { ...(await exportJWK(publicKey)), kid: m.kid, alg: 'ES256', use: 'sig' };
      await m.store.set('signer_key', { kid: m.kid, privateJwk: await exportJWK(privateKey), pubJwk: m._pubJwk });
    }
    m.fetchImpl = m.fetchImpl.bind(m);
    return m;
  }

  /** The JWKS as served at the well-known path. */
  jwks() {
    return { keys: [this._pubJwk] };
  }

  /**
   * Mint a proof. Defaults produce a valid enforce-mode allow. Pass `overrides`
   * to deliberately produce a bad proof for demoing a specific reason code.
   *
   * @param {Object} p
   * @param {string} p.subject
   * @param {string} p.action
   * @param {string} p.audience
   * @param {string} p.actionHash  64-hex, computed from the same request.
   * @param {{id: string, type?: string}} [p.actor]
   * @param {Object} [overrides]
   * @param {number} [overrides.iat] @param {number} [overrides.exp]
   * @param {string} [overrides.alg]   Force a non-ES256 header alg.
   * @param {string} [overrides.kid]   Force an unknown kid.
   * @param {boolean} [overrides.enforceable]
   * @param {Partial<{iss:string,aud:string,tenant:string,env:string,env_kind:string,action:string,action_hash:string}>} [overrides.claims]
   * @param {boolean} [overrides.tamper] Flip a signature byte after signing.
   * @returns {Promise<{proof: string, jti: string}>}
   */
  async issueProof(p, overrides = {}) {
    const now = Math.floor(Date.now() / 1000);
    const iat = overrides.iat ?? now;
    const exp = overrides.exp ?? iat + this.proofTtl;
    const jti = 'proof_' + base64url.encode(randomUUID()).slice(0, 16);

    const c = overrides.claims ?? {};
    const gp = {
      tenant: c.tenant ?? this.tenant,
      env: c.env ?? this.environment,
      env_kind: c.env_kind ?? this.environmentKind,
      enforceable: overrides.enforceable ?? true,
      action: c.action ?? p.action,
      action_hash: c.action_hash ?? p.actionHash,
      actor: { id: p.actor?.id ?? p.subject, type: p.actor?.type ?? 'human' },
    };

    let proof = await new SignJWT({ gp })
      .setProtectedHeader({ alg: overrides.alg ?? 'ES256', kid: overrides.kid ?? this.kid, typ: 'JWS' })
      .setIssuer(c.iss ?? this.issuer)
      .setSubject(p.subject)
      .setAudience(c.aud ?? p.audience)
      .setJti(jti)
      .setIssuedAt(iat)
      .setNotBefore(iat)
      .setExpirationTime(exp)
      .sign(this._priv);

    if (overrides.tamper) proof = tamperSignature(proof);

    // Track state as the authoritative server would (only clean proofs stored).
    if (!overrides.tamper && !overrides.alg && !overrides.kid) {
      await this.proofs.set(jti, { status: 'active', exp });
    }
    return { proof, jti };
  }

  /** Force a proof into a given state (revoked/expired/consumed) for demos. */
  async setProofState(jti, status) {
    const rec = await this.proofs.get(jti);
    if (rec) { rec.status = status; await this.proofs.set(jti, rec); }
  }

  // --- fetch-compatible router -------------------------------------------
  /** @param {string|URL} input @param {RequestInit} [init] */
  async fetchImpl(input, init = {}) {
    const url = new URL(input.toString());
    const path = url.pathname;

    if (path === '/.well-known/graypass-proof-keys.json') {
      return json(200, this.jwks());
    }
    if (path === '/api/v1/verify' && (init.method || 'GET').toUpperCase() === 'POST') {
      return this._verify(JSON.parse(init.body));
    }
    const statusMatch = path.match(/^\/api\/v1\/proofs\/([^/]+)\/status$/);
    if (statusMatch) {
      return json(200, await this._status(decodeURIComponent(statusMatch[1])));
    }
    return json(404, { type: 'about:blank', title: 'Not Found', status: 404 });
  }

  async _status(jti) {
    const rec = await this.proofs.get(jti);
    if (!rec) return { jti, status: 'unknown', expires_at: null, revoked_at: null };
    let status = rec.status;
    if (status === 'active' && rec.exp < Math.floor(Date.now() / 1000)) status = 'expired';
    return {
      jti,
      status,
      expires_at: new Date(rec.exp * 1000).toISOString(),
      revoked_at: status === 'revoked' ? new Date().toISOString() : null,
    };
  }

  /** Mirror of POST /api/v1/verify: bindings + current state + optional consume. */
  async _verify(body) {
    const jti = readJti(body.proof);
    if (!jti) return json(200, { valid: false, reason: 'malformed', claims: null });

    const rec = await this.proofs.get(jti);
    if (!rec) return json(200, { valid: false, reason: 'unknown', claims: null });

    const now = Math.floor(Date.now() / 1000);
    if (rec.status === 'revoked') return json(200, { valid: false, reason: 'revoked', claims: null });
    if (rec.status === 'consumed') return json(200, { valid: false, reason: 'consumed', claims: null });
    if (rec.exp < now) return json(200, { valid: false, reason: 'expired', claims: null });

    // Online binding checks (audience + action + hash) against caller expectations.
    const claims = decodeClaims(body.proof);
    if (claims?.aud !== body.audience) return json(200, { valid: false, reason: 'audience_mismatch', claims: null });
    if (claims?.gp?.action !== body.expected_action) return json(200, { valid: false, reason: 'action_mismatch', claims: null });
    if (claims?.gp?.action_hash !== body.expected_action_hash) {
      return json(200, { valid: false, reason: 'action_hash_mismatch', claims: null });
    }

    // Conditional one-time consumption -- the real single-use boundary.
    if (body.consume === true) { rec.status = 'consumed'; await this.proofs.set(jti, rec); }
    return json(200, { valid: true, reason: null, claims });
  }
}

// --- helpers -------------------------------------------------------------

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': status === 404 ? 'application/problem+json' : 'application/json' },
  });
}

function decodeClaims(jws) {
  try {
    const [, payload] = jws.split('.');
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

function readJti(jws) {
  return decodeClaims(jws)?.jti ?? null;
}

function tamperSignature(jws) {
  const parts = jws.split('.');
  const sig = Buffer.from(parts[2], 'base64url');
  sig[0] ^= 0xff;
  parts[2] = base64url.encode(sig);
  return parts.join('.');
}

/** Convenience: SHA-256 hex, matching the canonical hash width. */
export function sha256hex(s) {
  return createHash('sha256').update(s).digest('hex');
}
