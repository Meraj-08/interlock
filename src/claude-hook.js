/**
 * Claude Code PreToolUse hook.
 *
 * Claude Code runs `interlock hook claude` before a tool call, with the call as
 * JSON on stdin. The call becomes an Interlock proposal (action = tool name,
 * params = the exact tool input) and the server's policy decides:
 *
 *   auto_allow        -> consume the receipt, then print nothing so Claude
 *                        Code's own permission flow carries on unchanged
 *   deny              -> block, with the rule's reason
 *   require_approval  -> open the console and wait for a passkey approval;
 *                        approved -> consume the receipt and allow;
 *                        denied or timed out -> block
 *
 * Interlock only ever adds restrictions. Anything unexpected (service down,
 * bad input, server error, receipt refused) blocks the call.
 */

import { spawn } from 'node:child_process';
import { userInfo } from 'node:os';

export const DEFAULT_SERVER = 'http://localhost:4000';
// Under Claude Code's default 60s hook timeout: if Claude Code killed the hook
// first, the call would not be blocked.
export const DEFAULT_TIMEOUT_MS = 50_000;

/**
 * @param {unknown} input  Parsed hook input from Claude Code.
 * @param {Object} [opts]
 * @param {string} [opts.server]      Interlock base URL.
 * @param {number} [opts.timeoutMs]   How long to wait for a human.
 * @param {number} [opts.pollMs]      Poll interval while waiting.
 * @param {string} [opts.user]        Human the agent acts for.
 * @param {(url: string) => void} [opts.openUrl]  Opens the console; default the OS browser.
 * @param {typeof fetch} [opts.fetchImpl]
 * @returns {Promise<Object|null>} Hook output JSON, or null for "no objection".
 */
export async function runClaudeHook(input, opts = {}) {
  const server = (opts.server ?? DEFAULT_SERVER).replace(/\/+$/, '');
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollMs = opts.pollMs ?? 1000;
  const openUrl = opts.openUrl ?? openInBrowser;
  const api = client(server, opts.fetchImpl ?? fetch);

  if (isObject(input) && input.hook_event_name && input.hook_event_name !== 'PreToolUse') return null;
  if (!isObject(input) || typeof input.tool_name !== 'string' || !input.tool_name || !isObject(input.tool_input)) {
    return block('invalid hook input from Claude Code');
  }

  const tool = input.tool_name;
  const params = input.tool_input;

  try {
    const decision = await api.post('/api/propose', {
      agent: 'claude-code',
      onBehalfOf: opts.user ?? defaultUser(),
      action: tool,
      params,
      resource: input.cwd ? { type: 'workspace', id: String(input.cwd) } : undefined,
      consequence: describe(tool, params),
    });
    const why = `${decision.reason} (rule ${decision.rule})`;

    if (decision.outcome === 'deny') return block(`Interlock policy: ${why}`);

    if (decision.outcome === 'auto_allow') {
      const run = await api.post(`/api/proposals/${decision.approvalId}/execute`, { params });
      if (!run.executed) return block(`Interlock refused the receipt: ${run.reason}`);
      return null;
    }

    if (decision.outcome !== 'needs_approval') {
      return block(`Interlock returned an unexpected decision: ${decision.outcome}`);
    }

    const id = decision.approvalId;
    openUrl(`${server}/console`);
    const final = await waitForHuman(api, id, { timeoutMs, pollMs });

    if (final.state === 'pending') {
      return block(`Interlock: no approval within ${Math.round(timeoutMs / 1000)}s for ${tool} (${why}). Approve it in the console and try again.`);
    }
    if (final.state === 'denied') {
      const note = final.denyReason ? `: ${final.denyReason}` : '';
      return block(`Interlock: denied by ${final.approver ?? 'a human'}${note}`);
    }
    if (final.state !== 'approved') return block(`Interlock: request ended in state ${final.state}`);

    const run = await api.post(`/api/proposals/${id}/execute`, { params });
    if (!run.executed) return block(`Interlock refused the receipt: ${run.reason}`);
    return decide('allow', `Interlock: approved by ${final.approver} with ${final.method ?? 'passkey'}`);
  } catch (err) {
    return block(`Interlock: ${err.message}`);
  }
}

/**
 * Poll until the proposal leaves `pending` or the time runs out. On timeout the
 * request is denied on the server so a late approval cannot mint a usable
 * receipt; if the human approved in that last moment, the approval stands.
 */
async function waitForHuman(api, id, { timeoutMs, pollMs }) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const p = await api.get(`/api/proposals/${id}`);
    if (p.state !== 'pending') return p;
    if (Date.now() >= deadline) break;
    await sleep(Math.min(pollMs, Math.max(0, deadline - Date.now())));
  }
  try {
    await api.post(`/api/proposals/${id}/deny`, { approver: 'interlock:timeout', reason: 'no approval in time' });
    return { state: 'pending' };
  } catch {
    const p = await api.get(`/api/proposals/${id}`);
    return p.state === 'approved' ? p : { state: 'pending' };
  }
}

/** One-line description for the reviewer. */
function describe(tool, params) {
  if (typeof params.command === 'string') return `Run: ${params.command}`;
  if (typeof params.file_path === 'string') return `${tool} file ${params.file_path}`;
  if (typeof params.url === 'string') return `${tool} ${params.url}`;
  return `Use the ${tool} tool`;
}

function decide(permissionDecision, reason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason: reason,
    },
  };
}

function block(reason) {
  return decide('deny', reason);
}

function client(server, fetchImpl) {
  async function call(method, path, body) {
    let res;
    try {
      res = await fetchImpl(server + path, {
        method,
        headers: body ? { 'content-type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw new Error(`cannot reach Interlock at ${server}; blocking the call`);
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`${method} ${path} failed with HTTP ${res.status}${data.detail ? `: ${data.detail}` : ''}`);
    return data;
  }
  return { get: (p) => call('GET', p), post: (p, b) => call('POST', p, b ?? {}) };
}

function openInBrowser(url) {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [url]]
    : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]]
    : ['xdg-open', [url]];
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => {});
    child.unref();
  } catch { /* the reason text still points at the console */ }
}

function defaultUser() {
  try {
    return userInfo().username;
  } catch {
    return 'unknown';
  }
}

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
