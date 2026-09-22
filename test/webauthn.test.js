import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryStore } from '../src/index.js';
import { WebAuthnApprover } from '../src/webauthn.js';

test('registration options are generated and challenge is stored', async () => {
  const wa = new WebAuthnApprover({ store: new MemoryStore() });
  assert.equal(await wa.isRegistered('alice'), false);

  const options = await wa.registrationOptions('alice', 'localhost');
  assert.ok(options.challenge, 'has a challenge');
  assert.equal(options.rp.id, 'localhost');
  assert.ok(options.user, 'has a user');
});

test('approval options require a registered passkey', async () => {
  const store = new MemoryStore();
  const wa = new WebAuthnApprover({ store });
  await assert.rejects(() => wa.approvalOptions('bob', 'apr_1', 'localhost'), /no registered passkey/);

  // Inject a stored credential (as verifyRegistration would) and retry.
  await store.set('wa:cred:bob', { id: 'cred_1', publicKey: 'AAAA', counter: 0, transports: [] });
  const options = await wa.approvalOptions('bob', 'apr_1', 'localhost');
  assert.ok(options.challenge);
  assert.equal(options.allowCredentials[0].id, 'cred_1');
});
