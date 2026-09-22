import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { ApprovalAuthority } from './authority.js';
import { Guard } from './guard.js';
import { RiskPolicy } from './policy.js';
import { WebAuthnApprover } from './webauthn.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, '..', 'public');
const CONTENT_TYPES = {
  html: 'text/html; charset=utf-8', css: 'text/css', js: 'text/javascript',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', svg: 'image/svg+xml',
  ico: 'image/x-icon', webp: 'image/webp',
};

/**
 * InterlockServer — turns the Interlock library into a runnable HTTP service:
 * a JSON API plus a human approval console.
 *
 *   Agent side:
 *     POST /api/propose                 -> policy decision (+ approvalId)
 *     POST /api/proposals/:id/execute   -> verify + consume once (go / no-go)
 *   Human side (console):
 *     GET  /api/proposals               -> list (newest first)
 *     GET  /api/proposals/:id           -> one proposal
 *     POST /api/proposals/:id/approve   -> approve (mints the single-use proof)
 *     POST /api/proposals/:id/deny      -> deny
 *   UI:
 *     GET  /  and  /console             -> the approval console page
 *
 * The Guard runs in-process against the authority, so a proof never leaves the
 * server unverified. Back the authority with a FileStore (or Redis) for
 * durability; the API and console are stateless over it.
 */
export class InterlockServer {
  /**
   * @param {Object} [opts]
   * @param {ApprovalAuthority} [opts.authority] Existing authority, else one is built.
   * @param {RiskPolicy} [opts.policy] Policy for a freshly built authority.
   * @param {import('./store.js').MemoryStore} [opts.store] Store for a fresh authority.
   */
  static async create(opts = {}) {
    const s = new InterlockServer();
    s.authority = opts.authority ?? (await ApprovalAuthority.create({
      policy: opts.policy ?? RiskPolicy.default(),
      store: opts.store,
    }));
    s.guard = new Guard({ authority: s.authority });
    s.webauthn = new WebAuthnApprover({ store: s.authority.store });
    s.server = createServer((req, res) => s._route(req, res));
    return s;
  }

  /** Start listening. @returns {Promise<number>} the bound port. */
  listen(port = 4000) {
    return new Promise((resolve) => {
      this.server.listen(port, () => resolve(this.server.address().port));
    });
  }

  close() {
    return new Promise((resolve) => this.server.close(resolve));
  }

  async _route(req, res) {
    try {
      const url = new URL(req.url, 'http://localhost');
      const path = url.pathname;
      const method = req.method || 'GET';

      if (method === 'GET' && path === '/') {
        return this._serveFile(res, 'index.html');
      }
      if (method === 'GET' && path === '/console') {
        return this._serveFile(res, 'console.html');
      }
      // Static assets (images/css/js) from public/, basename-only (no traversal).
      if (method === 'GET' && /^\/[\w.-]+\.(png|jpe?g|svg|ico|css|js|webp)$/.test(path)) {
        return this._serveFile(res, path.slice(1));
      }
      if (method === 'POST' && path === '/api/propose') {
        const body = await readBody(req);
        return json(res, 200, await this.authority.propose(body));
      }
      if (method === 'GET' && path === '/api/proposals') {
        const list = await this.authority.list();
        return json(res, 200, list.map(publicView));
      }

      // --- WebAuthn: passkey registration ---
      if (method === 'GET' && path === '/api/webauthn/registered') {
        const approver = url.searchParams.get('approver') || '';
        return json(res, 200, { registered: await this.webauthn.isRegistered(approver) });
      }
      if (method === 'POST' && path === '/api/webauthn/register/options') {
        const { approver } = await readBody(req);
        return json(res, 200, await this.webauthn.registrationOptions(approver, rpID(req)));
      }
      if (method === 'POST' && path === '/api/webauthn/register/verify') {
        const { approver, response } = await readBody(req);
        return json(res, 200, await this.webauthn.verifyRegistration(approver, response, rp(req)));
      }

      // --- WebAuthn: passkey approval of a specific proposal ---
      const wa = path.match(/^\/api\/proposals\/([^/]+)\/approve\/(options|verify)$/);
      if (method === 'POST' && wa) {
        const [, id, step] = wa;
        const body = await readBody(req);
        const approver = body.approver || 'console-user';
        if (step === 'options') {
          return json(res, 200, await this.webauthn.approvalOptions(approver, id, rpID(req)));
        }
        const { verified } = await this.webauthn.verifyApproval(approver, id, body.response, rp(req));
        if (!verified) return json(res, 401, { error: 'passkey_verification_failed' });
        return json(res, 200, await this.authority.approve(id, { approver, method: 'passkey' }));
      }

      const m = path.match(/^\/api\/proposals\/([^/]+)(?:\/(approve|deny|execute))?$/);
      if (m) {
        const [, id, verb] = m;
        if (method === 'GET' && !verb) {
          const p = await this.authority.get(id);
          return p ? json(res, 200, publicView(p)) : json(res, 404, { error: 'unknown_approval' });
        }
        if (method === 'POST' && verb === 'approve') {
          const body = await readBody(req);
          return json(res, 200, await this.authority.approve(id, {
            approver: body.approver || 'console-user',
            method: body.method || 'click',
          }));
        }
        if (method === 'POST' && verb === 'deny') {
          const body = await readBody(req);
          return json(res, 200, await this.authority.deny(id, {
            approver: body.approver || 'console-user',
            reason: body.reason || '',
          }));
        }
        if (method === 'POST' && verb === 'execute') {
          const body = await readBody(req);
          const result = await this.guard.execute(id, () => ({ ran: true }), {
            params: body.params, // optional: pass different params to prove tamper-blocking
          });
          return json(res, 200, result);
        }
      }
      return json(res, 404, { error: 'not_found' });
    } catch (err) {
      return json(res, 400, { error: 'bad_request', detail: String(err && err.message) });
    }
  }

  /** Serve a file from the public directory by basename. */
  async _serveFile(res, name) {
    const base = name.split('/').pop(); // defensive: strip any path
    const ext = base.includes('.') ? base.split('.').pop().toLowerCase() : '';
    try {
      const buf = await readFile(join(PUBLIC_DIR, base));
      res.writeHead(200, { 'content-type': CONTENT_TYPES[ext] || 'application/octet-stream' });
      res.end(buf);
    } catch {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
    }
  }
}

/** A safe, proof-free view of a proposal for the API/console. */
function publicView(p) {
  return {
    id: p.id,
    state: p.state,
    agent: p.agent,
    onBehalfOf: p.onBehalfOf,
    action: p.action,
    params: p.params,
    riskClass: p.riskClass ?? null,
    consequence: p.consequence,
    action_hash: p.hash,
    approver: p.approver ?? null,
    method: p.method ?? null,
    createdAt: p.createdAt,
  };
}

/** Relying-party origin + id derived from the request's Origin header. */
function rp(req) {
  const origin = req.headers.origin || 'http://localhost';
  let id = 'localhost';
  try { id = new URL(origin).hostname; } catch { /* keep default */ }
  return { origin, rpID: id };
}
function rpID(req) {
  return rp(req).rpID;
}

function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 1_000_000) reject(new Error('body too large'));
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}
