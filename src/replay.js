/**
 * In-process replay guard, mirroring GrayPass's documented `MemoryReplayStore`.
 *
 * Tracks proof ids (jti) seen within one process so a proof is not offline-
 * accepted twice locally. This does NOT span processes -- for multi-worker
 * deployments back it with a shared store (Redis, a DB unique constraint, etc.),
 * and remember that local replay tracking never substitutes for the online
 * one-time `consume` step, which is the real single-use boundary.
 */
export class MemoryReplayStore {
  constructor() {
    /** @type {Map<string, number>} jti -> exp (unix seconds) */
    this._seen = new Map();
  }

  /** @param {string} jti @returns {boolean} */
  seen(jti) {
    this._sweep();
    return this._seen.has(jti);
  }

  /** @param {string} jti @param {number} exp */
  remember(jti, exp) {
    this._seen.set(jti, exp);
  }

  /** Drop entries whose proofs have already expired. */
  _sweep() {
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, exp] of this._seen) {
      if (typeof exp === 'number' && exp < now) this._seen.delete(jti);
    }
  }
}
