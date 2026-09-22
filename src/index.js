/**
 * Interlock — a human circuit-breaker for risky AI-agent actions.
 *
 * An agent proposes an action; a RiskPolicy decides auto-allow / needs-approval
 * / deny; a human approves the EXACT action (passkey/click); the authority mints
 * a single-use, action-bound Proof of Agency; and the Guard verifies + consumes
 * it before running the action exactly once. Fails closed everywhere.
 *
 * Built on the Signet verification core (below): the same two-phase, ES256,
 * consume-once, fail-closed proof checks.
 *
 * Mock-first: runs fully offline. Live-ready: the Signet core points at a real
 * issuer/API with no code changes.
 */

// --- Interlock: human-in-the-loop guard ---
export { RiskPolicy, rule } from './policy.js';
export { ApprovalAuthority } from './authority.js';
export { Guard } from './guard.js';
export { MemoryStore, FileStore, namespaced } from './store.js';
export { InterlockServer } from './server.js';
export { WebAuthnApprover } from './webauthn.js';

// --- Signet: the verification core it is built on ---
export { Reason, REASON_DESCRIPTIONS } from './reasons.js';
export { actionHash, canonicalJson } from './action-hash.js';
export { verifyProof } from './verify-offline.js';
export { verifyOnline, proofStatus } from './online.js';
export { createJwksCache } from './jwks.js';
export { MemoryReplayStore } from './replay.js';
export { Verifier } from './verifier.js';
export { MockGrayPass } from './mock/server.js';
