import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MockGrayPass,
  Verifier,
  verifyProof,
  actionHash,
  MemoryReplayStore,
  Reason,
} from '../src/index.js';

const SUBJECT = 'sub_merchant_42';
const ACTION = 'payout.destination.change';
const AUDIENCE = 'payments-app';

/** Build a mock, a matching request/hash, and a base "expected" config. */
async function fixture(mockOpts = {}) {
  const mock = await MockGrayPass.create(mockOpts);
  const request = {
    environment: mock.environment,
    action: ACTION,
    resource: { type: 'merchant_account', id: 'merch_001' },
    context: { destination_fingerprint: 'fp_' + '0'.repeat(61) },
    subject: SUBJECT,
    actor: SUBJECT,
    actorType: 'human',
    audience: AUDIENCE,
    nonce: 'nonce_abc123',
  };
  const hash = actionHash(request);
  const expected = {
    issuer: mock.issuer,
    tenant: mock.tenant,
    environment: mock.environment,
    environmentKind: mock.environmentKind,
    audience: AUDIENCE,
    expectedAction: ACTION,
    expectedActionHash: hash,
    maxTtlSeconds: 300,
  };
  return { mock, request, hash, expected };
}

/** Offline-verify a freshly minted proof against the mock's JWKS. */
async function offline(mock, issue, expected, opts) {
  const { proof } = await mock.issueProof(
    { subject: SUBJECT, action: ACTION, audience: AUDIENCE, actionHash: expected.expectedActionHash, actor: { id: SUBJECT } },
    issue,
  );
  return verifyProof(proof, mock.jwks(), expected, opts);
}

test('happy path: valid enforce-mode allow verifies offline', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, {}, expected);
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.claims.sub, SUBJECT);
});

test('full two-phase: authorizeExecution executes once, then blocks double-spend', async () => {
  const { mock, expected } = await fixture();
  const { proof } = await mock.issueProof({
    subject: SUBJECT, action: ACTION, audience: AUDIENCE, actionHash: expected.expectedActionHash, actor: { id: SUBJECT },
  });
  const verifier = new Verifier({
    issuer: mock.issuer,
    baseUrl: mock.issuer,
    credential: 'sk_mock',
    tenant: mock.tenant,
    environment: mock.environment,
    environmentKind: mock.environmentKind,
    fetchImpl: mock.fetchImpl,
  });
  const expect = { audience: AUDIENCE, expectedAction: ACTION, expectedActionHash: expected.expectedActionHash };

  const first = await verifier.authorizeExecution(proof, expect);
  assert.equal(first.execute, true, first.reason);

  // Second worker replays the same proof -> online consume refuses it.
  const second = await verifier.authorizeExecution(proof, expect);
  assert.equal(second.execute, false);
});

test('fail-closed when the online dependency is unavailable', async () => {
  const { mock, expected } = await fixture();
  const { proof } = await mock.issueProof({
    subject: SUBJECT, action: ACTION, audience: AUDIENCE, actionHash: expected.expectedActionHash, actor: { id: SUBJECT },
  });
  const verifier = new Verifier({
    issuer: mock.issuer, baseUrl: mock.issuer, credential: 'sk_mock',
    tenant: mock.tenant, environment: mock.environment, environmentKind: mock.environmentKind,
    fetchImpl: async (u) => {
      if (u.toString().includes('/.well-known/')) return mock.fetchImpl(u);
      throw new Error('network down'); // /verify unreachable
    },
  });
  const r = await verifier.authorizeExecution(proof, { audience: AUDIENCE, expectedAction: ACTION, expectedActionHash: expected.expectedActionHash });
  assert.equal(r.execute, false);
  assert.equal(r.reason, 'unavailable');
});

// --- one test per documented refusal reason ------------------------------

test('malformed', async () => {
  const { mock, expected } = await fixture();
  const r = await verifyProof('not-a-jws', mock.jwks(), expected);
  assert.equal(r.reason, Reason.MALFORMED);
});

test('unsupported_alg', async () => {
  const { mock, expected } = await fixture();
  // Take a valid proof and rewrite only its header alg to a non-ES256 value.
  // The verifier must reject on algorithm before doing any signature work.
  const { proof } = await mock.issueProof({
    subject: SUBJECT, action: ACTION, audience: AUDIENCE, expectedActionHash: expected.expectedActionHash,
    actionHash: expected.expectedActionHash, actor: { id: SUBJECT },
  });
  const parts = proof.split('.');
  parts[0] = Buffer.from(JSON.stringify({ alg: 'RS256', kid: mock.kid, typ: 'JWS' })).toString('base64url');
  const r = await verifyProof(parts.join('.'), mock.jwks(), expected);
  assert.equal(r.reason, Reason.UNSUPPORTED_ALG);
});

test('unknown_kid', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, { kid: 'gpk_not_in_jwks' }, expected);
  assert.equal(r.reason, Reason.UNKNOWN_KID);
});

test('invalid_signature', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, { tamper: true }, expected);
  assert.equal(r.reason, Reason.INVALID_SIGNATURE);
});

test('issuer_mismatch', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, { claims: { iss: 'https://evil.example' } }, expected);
  assert.equal(r.reason, Reason.ISSUER_MISMATCH);
});

test('audience_mismatch', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, { claims: { aud: 'some-other-app' } }, expected);
  assert.equal(r.reason, Reason.AUDIENCE_MISMATCH);
});

test('not_yet_valid', async () => {
  const { mock, expected } = await fixture();
  const future = Math.floor(Date.now() / 1000) + 3600;
  const r = await offline(mock, { iat: future, exp: future + 300 }, expected);
  assert.equal(r.reason, Reason.NOT_YET_VALID);
});

test('expired', async () => {
  const { mock, expected } = await fixture();
  const past = Math.floor(Date.now() / 1000) - 3600;
  const r = await offline(mock, { iat: past, exp: past + 300 }, expected);
  assert.equal(r.reason, Reason.EXPIRED);
});

test('ttl_too_long', async () => {
  const { mock, expected } = await fixture();
  const now = Math.floor(Date.now() / 1000);
  const r = await offline(mock, { iat: now, exp: now + 4000 }, expected); // > 300s
  assert.equal(r.reason, Reason.TTL_TOO_LONG);
});

test('not_enforceable', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, { enforceable: false }, expected);
  assert.equal(r.reason, Reason.NOT_ENFORCEABLE);
});

test('environment_mismatch', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, { claims: { env: 'env_other' } }, expected);
  assert.equal(r.reason, Reason.ENVIRONMENT_MISMATCH);
});

test('tenant_mismatch', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, { claims: { tenant: 'tnt_other' } }, expected);
  assert.equal(r.reason, Reason.TENANT_MISMATCH);
});

test('actor_mismatch', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, {}, { ...expected, actor: { id: 'sub_someone_else', type: 'human' } });
  assert.equal(r.reason, Reason.ACTOR_MISMATCH);
});

test('action_mismatch', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, { claims: { action: 'password.change' } }, expected);
  assert.equal(r.reason, Reason.ACTION_MISMATCH);
});

test('action_hash_mismatch', async () => {
  const { mock, expected } = await fixture();
  const r = await offline(mock, { claims: { action_hash: 'f'.repeat(64) } }, expected);
  assert.equal(r.reason, Reason.ACTION_HASH_MISMATCH);
});

test('replayed (single-process guard)', async () => {
  const { mock, expected } = await fixture();
  const store = new MemoryReplayStore();
  const { proof } = await mock.issueProof({
    subject: SUBJECT, action: ACTION, audience: AUDIENCE, actionHash: expected.expectedActionHash, actor: { id: SUBJECT },
  });
  const first = await verifyProof(proof, mock.jwks(), expected, { replayStore: store });
  assert.equal(first.valid, true);
  const second = await verifyProof(proof, mock.jwks(), expected, { replayStore: store });
  assert.equal(second.reason, Reason.REPLAYED);
});
