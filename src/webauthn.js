import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { namespaced } from './store.js';

/**
 * WebAuthnApprover — real passkey ceremonies for the human approval step.
 *
 * An approver registers a passkey once, then each high-risk approval requires a
 * fresh WebAuthn assertion (Touch ID / security key / platform authenticator).
 * Only after the assertion verifies does the authority mint the single-use
 * Proof of Agency. This upgrades the "click to approve" step to a real
 * possession + user-presence proof.
 *
 * Credentials and one-time challenges are kept in the durable store, so
 * registrations survive restarts alongside proposals and proof state.
 */
export class WebAuthnApprover {
  /**
   * @param {Object} cfg
   * @param {import('./store.js').MemoryStore} cfg.store
   * @param {string} [cfg.rpName] Relying-party display name.
   */
  constructor(cfg) {
    this.rpName = cfg.rpName ?? 'Interlock';
    this.creds = namespaced(cfg.store, 'wa:cred:');
    this.chal = namespaced(cfg.store, 'wa:chal:');
  }

  /** Does this approver already have a registered passkey? */
  async isRegistered(approver) {
    return (await this.creds.get(approver)) != null;
  }

  // --- registration ------------------------------------------------------

  /** Step 1 of registration: options the browser feeds to navigator.credentials.create. */
  async registrationOptions(approver, rpID) {
    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID,
      userID: new TextEncoder().encode(approver),
      userName: approver,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    });
    await this.chal.set(`reg:${approver}`, options.challenge);
    return options;
  }

  /** Step 2: verify the attestation and store the credential. */
  async verifyRegistration(approver, response, { origin, rpID }) {
    const expectedChallenge = await this.chal.get(`reg:${approver}`);
    if (!expectedChallenge) throw new Error('no pending registration');
    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
    if (!verified || !registrationInfo) return { verified: false };

    const c = registrationInfo.credential;
    await this.creds.set(approver, {
      id: c.id,
      publicKey: Buffer.from(c.publicKey).toString('base64url'),
      counter: c.counter ?? 0,
      transports: c.transports ?? [],
    });
    await this.chal.delete(`reg:${approver}`);
    return { verified: true };
  }

  // --- approval (authentication) ----------------------------------------

  /**
   * Step 1 of an approval: an authentication challenge scoped to one proposal,
   * limited to this approver's registered credential.
   */
  async approvalOptions(approver, proposalId, rpID) {
    const cred = await this.creds.get(approver);
    if (!cred) throw new Error('approver has no registered passkey');
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: [{ id: cred.id, transports: cred.transports }],
      userVerification: 'preferred',
    });
    await this.chal.set(`auth:${approver}:${proposalId}`, options.challenge);
    return options;
  }

  /**
   * Step 2: verify the assertion for this proposal. Returns { verified }.
   * The caller mints the proof / approves only when verified is true.
   */
  async verifyApproval(approver, proposalId, response, { origin, rpID }) {
    const key = `auth:${approver}:${proposalId}`;
    const expectedChallenge = await this.chal.get(key);
    if (!expectedChallenge) throw new Error('no pending approval challenge');
    const cred = await this.creds.get(approver);
    if (!cred) throw new Error('approver has no registered passkey');

    const { verified, authenticationInfo } = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: cred.id,
        publicKey: new Uint8Array(Buffer.from(cred.publicKey, 'base64url')),
        counter: cred.counter,
        transports: cred.transports,
      },
    });

    await this.chal.delete(key);
    if (!verified) return { verified: false };

    // Persist the updated signature counter (clone-detection).
    cred.counter = authenticationInfo.newCounter;
    await this.creds.set(approver, cred);
    return { verified: true };
  }
}
