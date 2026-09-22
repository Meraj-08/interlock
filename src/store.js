import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Pluggable key/value store used for Interlock's durable state: proposals,
 * the signing key, and proof consumption records. The interface is intentionally
 * tiny (get / set / delete / keys / values) so it can be backed by memory, a
 * JSON file, or — in a real deployment — Redis or a database.
 *
 * All methods are async so the same code works against a network-backed store.
 */

/** In-memory store. State is lost on restart; good for tests and demos. */
export class MemoryStore {
  constructor() {
    /** @type {Map<string, any>} */
    this.m = new Map();
  }
  async get(k) { return this.m.has(k) ? this.m.get(k) : null; }
  async set(k, v) { this.m.set(k, v); }
  async delete(k) { this.m.delete(k); }
  async keys() { return [...this.m.keys()]; }
  async values() { return [...this.m.values()]; }
}

/**
 * JSON-file store. Durable across process restarts: every write is flushed to
 * disk as a `[[key, value], ...]` array. Suitable for single-process
 * deployments; swap for Redis/Postgres to span processes.
 */
export class FileStore {
  /** @param {string} path Absolute or relative path to the JSON file. */
  constructor(path) {
    this.path = path;
    /** @type {Map<string, any>} */
    this.m = new Map();
    this._load();
  }
  _load() {
    try {
      const raw = JSON.parse(readFileSync(this.path, 'utf8'));
      if (Array.isArray(raw)) for (const [k, v] of raw) this.m.set(k, v);
    } catch {
      // Missing or unreadable file → start empty.
    }
  }
  _save() {
    try {
      mkdirSync(dirname(this.path), { recursive: true });
      writeFileSync(this.path, JSON.stringify([...this.m.entries()]));
    } catch {
      // Best-effort; a real store would surface this.
    }
  }
  async get(k) { return this.m.has(k) ? this.m.get(k) : null; }
  async set(k, v) { this.m.set(k, v); this._save(); }
  async delete(k) { this.m.delete(k); this._save(); }
  async keys() { return [...this.m.keys()]; }
  async values() { return [...this.m.values()]; }
}

/**
 * Wrap a store so all keys are transparently prefixed, letting several
 * components share one underlying store without colliding.
 * @param {MemoryStore|FileStore} store
 * @param {string} prefix
 */
export function namespaced(store, prefix) {
  return {
    async get(k) { return store.get(prefix + k); },
    async set(k, v) { return store.set(prefix + k, v); },
    async delete(k) { return store.delete(prefix + k); },
    async keys() {
      return (await store.keys()).filter((k) => k.startsWith(prefix)).map((k) => k.slice(prefix.length));
    },
    async values() {
      const keys = (await store.keys()).filter((k) => k.startsWith(prefix));
      return Promise.all(keys.map((k) => store.get(k)));
    },
  };
}
