import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ApprovalAuthority, Guard, FileStore } from '../src/index.js';

// A FileStore-backed authority must survive a process restart: proposals, the
// signing key, and proof consumption state all persist, so an approval granted
// before the restart still executes exactly once afterward.
test('approval + proof state survive a restart (FileStore)', async () => {
  const path = join(mkdtempSync(join(tmpdir(), 'interlock-')), 'state.json');

  // --- process 1: propose a high-risk action and approve it ---
  let approvalId;
  {
    const authority = await ApprovalAuthority.create({ store: new FileStore(path) });
    const guard = new Guard({ authority });
    const decision = await guard.propose({
      agent: 'agent_x', onBehalfOf: 'user_1', action: 'refund.issue',
      params: { amount: 5000 }, riskClass: 'high',
    });
    assert.equal(decision.outcome, 'needs_approval');
    await authority.approve(decision.approvalId, { approver: 'ops', method: 'passkey' });
    approvalId = decision.approvalId;
  }

  // --- process 2: a brand-new authority reading the SAME file ---
  {
    const authority = await ApprovalAuthority.create({ store: new FileStore(path) });
    const guard = new Guard({ authority });

    const restored = await authority.get(approvalId);
    assert.ok(restored, 'proposal restored from disk');
    assert.equal(restored.state, 'approved');

    let ran = 0;
    const first = await guard.execute(approvalId, () => ++ran);
    assert.equal(first.executed, true, first.reason); // restored key still verifies the proof
    assert.equal(ran, 1);

    const second = await guard.execute(approvalId, () => ++ran);
    assert.equal(second.executed, false); // consumed state persisted across restart
    assert.equal(ran, 1);
  }
});
