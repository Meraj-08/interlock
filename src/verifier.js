import { verifyProof } from './verify-offline.js';
import { verifyOnline } from './online.js';
import { createJwksCache } from './jwks.js';
import { MemoryReplayStore } from './replay.js';
import { decodeProtectedHeader } from 'jose';
import { Reason } from './reasons.js';

/**
 * High-level composer that enforces GrayPass's documented two-phase rule:
 *
 *   1. Offline: verify signature + all claim bindings against trusted JWKS.
 *   2. Online:  check current state and CONSUME the proof exactly once.
 *
 * `authorizeExecution()` returns `execute: true` ONLY when both phases pass with
 * `consume: true`. It fails closed: any offline failure, online failure, or
 * ambiguous/unavailable result yields `execute: false`. The caller still owns
 * the business transaction (idempotency, locking, its own request ledger); this
 * class does not execute anything.
 *
 * The same instance works against the local mock or the live API -- only
 * `issuer`, `baseUrl`, and `credential` differ.
 */
export class Verifier {
  /**
   * @param {Object} cfg
   * @param {string} cfg.issuer      Configured GrayPass issuer/origin.
   * @param {string} cfg.baseUrl     API base url (usually same origin as issuer).
   * @param {string} cfg.credential  Server credential (bearer).
   * @param {string} cfg.tenant
   * @param {string} cfg.environment
   * @param {'sandbox'|'live'} [cfg.environmentKind]
   * @param {number} [cfg.maxTtlSeconds]
   * @param {number} [cfg.clockToleranceSeconds]
   * @param {typeof fetch} [cfg.fetchImpl]  Injectable fetch (mock or live).
   * @param {object} [cfg.replayStore]      Defaults to a MemoryReplayStore.
   */
  constructor(cfg) {
    this.cfg = cfg;
    this.jwks = createJwksCache({ issuer: cfg.issuer, fetchImpl: cfg.fetchImpl });
    this.replayStore = cfg.replayStore ?? new MemoryReplayStore();
  }

  /**
   * Full offline + online + consume flow for one pending business request.
   *
   * @param {string} proof  Compact JWS from your trusted authorization workflow.
   * @param {Object} expected
   * @param {string} expected.audience
   * @param {string} expected.expectedAction
   * @param {string} expected.expectedActionHash  Locally computed from the frozen request.
   * @param {{id?: string, type?: string}} [expected.actor]
   * @param {boolean} [expected.requireEnforceable]
   * @returns {Promise<{execute: boolean, phase: 'offline'|'online', reason?: string, claims?: Object}>}
   */
  async authorizeExecution(proof, expected) {
    // Resolve the right key set (refresh once on unknown kid).
    let kid;
    try {
      kid = decodeProtectedHeader(proof).kid;
    } catch {
      return { execute: false, phase: 'offline', reason: Reason.MALFORMED };
    }
    const keys = await this.jwks.getForKid(kid);

    // Phase 1: offline crypto + bindings + single-process replay.
    const offline = await verifyProof(proof, keys, { ...this.cfg, ...expected }, {
      replayStore: this.replayStore,
    });
    if (!offline.valid) return { execute: false, phase: 'offline', reason: offline.reason };

    // Phase 2: authoritative online state check + one-time consume.
    let online;
    try {
      online = await verifyOnline(
        proof,
        { ...expected, consume: true },
        { baseUrl: this.cfg.baseUrl, credential: this.cfg.credential, fetchImpl: this.cfg.fetchImpl },
      );
    } catch {
      // Unavailable dependency must never become permission to execute.
      return { execute: false, phase: 'online', reason: 'unavailable' };
    }
    if (!online.valid) return { execute: false, phase: 'online', reason: online.reason ?? 'refused' };

    return { execute: true, phase: 'online', claims: online.claims ?? offline.claims };
  }
}
