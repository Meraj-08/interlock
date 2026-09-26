# Interlock

A human-in-the-loop circuit breaker for high-risk AI-agent actions.

An agent proposes an action. A risk policy decides whether it can run on its own,
needs a human, or must be refused. For the actions that need a human, a person
approves the exact action with a passkey, and only then does the agent get a
single-use, action-bound proof that lets it run the action exactly once. Every
other path fails closed.

It is built on a small verification core called Signet: ES256-signed proofs that
are verified and consumed exactly once, so "approved" is backed by cryptography
rather than a flag an agent could flip.

This is an independent project. The proof model follows the GrayPass
"Proof of Agency" contract (https://app.graypass.org/docs); the human-approval
layer on top is Interlock's own.

## The idea

The scary case for AI agents is not reading a row — it is the irreversible
action: wiring money, deleting a tenant, emailing every customer. For those you
want a deliberate human decision, plus a guarantee that what the human approved
is exactly what runs.

Interlock provides that:

- the human approves a specific, frozen action (agent, user, action, params);
- approval mints a proof bound to that exact request;
- the guard recomputes the binding from what the agent is actually about to do,
  so "approve $10, execute $10,000" cannot happen;
- the proof is consumed once, so there are no replays or double-spends;
- if anything is wrong or the authority is unreachable, execution is refused.

## The flow

```
agent.propose(action) -> RiskPolicy -> auto_allow      (proof minted now)
                                    -> needs_approval   (human approves w/ passkey,
                                                         then proof is minted)
                                    -> deny             (no proof, ever)

guard.execute(id, fn) -> verify proof (signature + bindings)
                       -> recompute hash from the actual params
                       -> consume once -> run fn() exactly once
                       -> replay / tamper / expired / denied / outage -> refuse
```

## Requirements

- Node.js 18 or newer.
- No API keys or environment variables. It runs fully offline.

## Install and test

```bash
npm install
npm test        # 53 tests
npm run demo    # narrated offline walkthrough (approval, tamper, deny, fail-closed)
```

## Run as a service

```bash
npm run serve   # http://localhost:4000
```

- `http://localhost:4000/` — landing page.
- `http://localhost:4000/console` — the approval console. Register a passkey once,
  then approve pending actions with a WebAuthn ceremony (Touch ID or a security
  key). The proof is minted only after the passkey assertion verifies.

State is written to `data/interlock.json`, so registrations, approvals, and
one-time consumption survive a restart. Delete that file to reset.

## HTTP API

| Method and path | Who | What it does |
|---|---|---|
| `POST /api/propose` | agent | returns a policy decision and an `approvalId` |
| `GET /api/proposals` | console | lists proposals, newest first |
| `POST /api/webauthn/register/options` and `/verify` | human | register a passkey |
| `POST /api/proposals/:id/approve/options` and `/verify` | human | approve via passkey; mints the proof |
| `POST /api/proposals/:id/deny` | human | deny |
| `POST /api/proposals/:id/execute` | agent | verify and consume once (go / no-go) |

## Use as a library

```js
import { ApprovalAuthority, Guard, RiskPolicy } from 'interlock';

const authority = await ApprovalAuthority.create({
  policy: RiskPolicy.default({ autoApproveUnder: 100, denyActions: ['account.delete'] }),
});
const guard = new Guard({ authority });

// 1. The agent proposes an action.
const decision = await guard.propose({
  agent: 'agent_support_bot',
  onBehalfOf: 'user_42',
  action: 'refund.issue',
  params: { amount: 5000, currency: 'USD', order: 'ord_9' },
  riskClass: 'high',
  consequence: 'Refund $5,000 to the customer card.',
});

// 2. If it needs a human, collect an approval (a passkey ceremony in the console).
if (decision.outcome === 'needs_approval') {
  await authority.approve(decision.approvalId, { approver: 'ops_alice', method: 'passkey' });
}

// 3. The agent executes through the guard: verified, consumed once, run once.
const result = await guard.execute(decision.approvalId, async () => {
  return issueRefund(5000); // your business action
});
if (!result.executed) return handleRefusal(result.reason);
```

## Writing a policy

Rules can live in a JSON file instead of code. The first rule that matches
decides the outcome (`auto_allow`, `require_approval`, or `deny`); if none
matches, `default` applies (`require_approval` when omitted).

```json
{
  "default": "require_approval",
  "rules": [
    { "id": "never-delete-accounts", "match": { "action": "account.delete" }, "outcome": "deny" },
    { "id": "force-push-needs-human",
      "match": { "action": "Bash", "params": { "command": "git\\s+push\\b.*(--force|-f\\b)" } },
      "outcome": "require_approval", "reason": "force-pushing rewrites shared history" },
    { "id": "small-refunds",
      "match": { "action": "refund.issue", "params": { "amount": { "lt": 100 } } },
      "outcome": "auto_allow" }
  ]
}
```

Everything in `match` must hold for the rule to apply:

| Field | Matches |
|---|---|
| `action` | exact name, `*` wildcard (`"read.*"`), or a list of either |
| `riskClass` | `low`, `elevated`, `high`, `critical`, or a list |
| `params.<name>` | a string is a regular expression searched in the value; a number or boolean must be equal; or an object of operators: `lt`, `lte`, `gt`, `gte`, `eq`, `in`, `regex` |

An empty `match` matches everything. Numeric operators never match a missing or
non-numeric value. The file is checked when it loads: an unknown field, a bad
regex, or a wrong type is an error naming the rule and field.

```js
const policy = await RiskPolicy.fromFile('interlock.policy.json');
```

```bash
INTERLOCK_POLICY=examples/interlock.policy.json npm run serve
```

See [`examples/interlock.policy.json`](examples/interlock.policy.json) for a
complete example.

## Behavior (each row has a test)

| Scenario | Result |
|---|---|
| Low risk / small amount | `auto_allow` — runs without a human |
| High risk / large amount | `needs_approval` — held for a human |
| Execute before approval | refused (`awaiting_approval`) |
| Approved, then executed | runs exactly once |
| Same approval replayed | refused (`replayed`) |
| Approve $10, execute $10,000 | refused (`action_hash_mismatch`) |
| Human denies | refused (`denied`) |
| Deny-listed action | `deny` — no approval offered |
| Authority unreachable | refused (`unavailable`) — fails closed |
| Approve twice | idempotent — no second proof |

## Project layout

```
src/
  policy.js          RiskPolicy: auto_allow / require_approval / deny
  policy-file.js     JSON policy files: validation + rule compilation
  authority.js       ApprovalAuthority: proposal lifecycle + proof minting
  guard.js           Guard: execution boundary, exactly-once, fail-closed
  store.js           MemoryStore / FileStore: durable state
  server.js          InterlockServer: HTTP API + serves the site
  webauthn.js        WebAuthnApprover: passkey register + approval
  verifier.js        Signet: two-phase verify composer
  verify-offline.js  Signet: offline signature + claim checks
  online.js          Signet: online verify + one-time consume
  jwks.js  replay.js  reasons.js  action-hash.js
  mock/server.js     signer + fetch-compatible API (persists key + proofs)
bin/serve.js         `npm run serve` entry point
public/
  index.html         landing page
  console.html       approval console
  logo.svg           logo mark
test/                one file per area (loop, HTTP, WebAuthn, persistence, Signet)
examples/demo.js     narrated offline walkthrough
examples/interlock.policy.json  example policy file
docs/                screenshots
```

## Limitations

- The canonical action hash uses a documented, deterministic form applied
  identically on both sides. Swap in a provider's official hasher for live use.
- `FileStore` is single-process durable. For multiple workers, back the store
  with Redis or Postgres. The online one-time consume is still the real
  single-use boundary.
- WebAuthn `rpID` and origin are derived from the request Origin, which works on
  localhost. Set them explicitly behind a proxy or custom domain.

## Status

Done: risk policy, approval lifecycle, single-use proofs, the fail-closed guard,
durable storage, HTTP service, web console, landing page, and real WebAuthn
passkey approval.

Next: a Redis/Postgres store adapter for multi-process deployments, and a
deployment setup.
