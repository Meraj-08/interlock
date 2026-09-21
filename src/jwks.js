const WELL_KNOWN_PATH = '/.well-known/graypass-proof-keys.json';

/**
 * JWKS provider for GrayPass proof keys.
 *
 * Follows the key-handling rules from the docs:
 *   - Fetch ONLY from the configured service origin. Never follow a key url
 *     taken from an untrusted proof header.
 *   - Cache the key set, and refresh at most once when an unknown key id is
 *     encountered (key rotation), rather than fetching on every verification.
 *
 * @param {Object} opts
 * @param {string} opts.issuer  Configured origin, e.g. https://app.graypass.org.
 * @param {typeof fetch} [opts.fetchImpl]  Injectable fetch (mock or live).
 * @param {number} [opts.minRefreshIntervalMs]  Rate-limit refreshes. Default 10s.
 */
export function createJwksCache(opts) {
  const origin = new URL(opts.issuer).origin;
  const url = origin + WELL_KNOWN_PATH;
  const doFetch = opts.fetchImpl ?? fetch;
  const minRefresh = opts.minRefreshIntervalMs ?? 10_000;

  /** @type {{keys: Array<Object>}|null} */
  let cache = null;
  let lastFetch = 0;
  /** @type {Promise<{keys: Array<Object>}>|null} */
  let inflight = null;

  async function load() {
    const res = await doFetch(url, { headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
    const body = await res.json();
    if (!body || !Array.isArray(body.keys)) throw new Error('JWKS malformed');
    cache = body;
    lastFetch = Date.now();
    return cache;
  }

  return {
    origin,
    url,
    /** Return the cached key set, fetching once if empty. */
    async get() {
      if (cache) return cache;
      if (!inflight) inflight = load().finally(() => (inflight = null));
      return inflight;
    },
    /**
     * Return the key set, refreshing once if `kid` is absent (rotation), while
     * respecting the minimum refresh interval so a barrage of unknown kids
     * cannot hammer the origin.
     * @param {string} kid
     */
    async getForKid(kid) {
      let keys = await this.get();
      const has = (k) => (k.keys || []).some((j) => j.kid === kid);
      if (!has(keys) && Date.now() - lastFetch > minRefresh) {
        if (!inflight) inflight = load().finally(() => (inflight = null));
        keys = await inflight;
      }
      return keys;
    },
  };
}
