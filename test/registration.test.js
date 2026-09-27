import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryStore, InterlockServer } from '../src/index.js';
import { WebAuthnApprover } from '../src/webauthn.js';
import { startServer } from '../src/serve.js';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CODE = 'TEST-SETUP-CODE';

async function withServer(fn, opts = {}) {
  const server = await InterlockServer.create({ setupCode: CODE, ...opts });
  const port = await server.listen(0);
  try {
    await fn({ server, base: `http://localhost:${port}` });
  } finally {
    await server.close();
  }
}

async function post(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

const storedCred = { id: 'cred_real', publicKey: 'AAAA', counter: 0, transports: [] };

test('registration options need the setup code', async () => {
  await withServer(async ({ server, base }) => {
    const missing = await post(`${base}/api/webauthn/register/options`, { approver: 'alice' });
    assert.equal(missing.status, 403);
    assert.equal(missing.body.error, 'setup_code_required');

    const wrong = await post(`${base}/api/webauthn/register/options`, { approver: 'alice', setupCode: 'nope' });
    assert.equal(wrong.status, 403);

    // Nothing was started for a refused request.
    assert.equal(await server.authority.store.get('wa:chal:reg:alice'), null);

    const ok = await post(`${base}/api/webauthn/register/options`, { approver: 'alice', setupCode: CODE });
    assert.equal(ok.status, 200);
    assert.ok(ok.body.challenge);
  });
});

test('registration verify needs the setup code and stores nothing without it', async () => {
  await withServer(async ({ server, base }) => {
    await post(`${base}/api/webauthn/register/options`, { approver: 'alice', setupCode: CODE });
    const r = await post(`${base}/api/webauthn/register/verify`, { approver: 'alice', response: {} });
    assert.equal(r.status, 403);
    assert.equal(r.body.error, 'setup_code_required');
    assert.equal(await server.webauthn.isRegistered('alice'), false);
  });
});

test('an existing passkey is never replaced over the API', async () => {
  await withServer(async ({ server, base }) => {
    await server.authority.store.set('wa:cred:ops', storedCred);

    const options = await post(`${base}/api/webauthn/register/options`, { approver: 'ops', setupCode: CODE });
    assert.equal(options.status, 409);
    assert.equal(options.body.error, 'already_registered');

    const verify = await post(`${base}/api/webauthn/register/verify`, { approver: 'ops', setupCode: CODE, response: {} });
    assert.equal(verify.status, 409);

    assert.deepEqual(await server.authority.store.get('wa:cred:ops'), storedCred);
  });
});

test('WebAuthnApprover refuses to overwrite a registered approver', async () => {
  const store = new MemoryStore();
  const wa = new WebAuthnApprover({ store });
  await store.set('wa:cred:ops', storedCred);
  await assert.rejects(() => wa.registrationOptions('ops', 'localhost'), /already has a passkey/);
  await store.set('wa:chal:reg:ops', 'challenge');
  await assert.rejects(
    () => wa.verifyRegistration('ops', {}, { origin: 'http://localhost', rpID: 'localhost' }),
    /already has a passkey/,
  );
  assert.deepEqual(await store.get('wa:cred:ops'), storedCred);
});

test('a server without an explicit setup code generates a random one', async () => {
  const a = await InterlockServer.create();
  const b = await InterlockServer.create();
  assert.match(a.setupCode, /^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
  assert.notEqual(a.setupCode, b.setupCode);
});

test('an empty setup code is not accepted as configuration', async () => {
  await assert.rejects(() => InterlockServer.create({ setupCode: '' }), /setup code/);
  await assert.rejects(() => InterlockServer.create({ setupCode: 'short' }), /at least 8 characters/);
});

test('startServer passes the setup code through', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'interlock-reg-'));
  const { server } = await startServer({ port: 0, dataPath: join(dir, 's.json'), setupCode: 'FIXED-CODE-1' });
  try {
    assert.equal(server.setupCode, 'FIXED-CODE-1');
  } finally {
    await server.close();
  }
});
