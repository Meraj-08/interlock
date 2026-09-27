import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { run } from '../src/cli.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'interlock.js');
const EXAMPLE = join(ROOT, 'examples', 'interlock.policy.json');

/** Run the CLI in-process and capture its output. */
async function cli(args, { cwd = ROOT, env = {}, stdin = '' } = {}) {
  let out = '';
  let err = '';
  const io = {
    stdout: { write: (s) => { out += s; } },
    stderr: { write: (s) => { err += s; } },
    cwd,
    env,
    readStdin: async () => stdin,
  };
  const code = await run(args, io);
  return { code, out, err };
}

async function tempDir() {
  return mkdtemp(join(tmpdir(), 'interlock-cli-'));
}

test('no arguments prints usage and exits 2', async () => {
  const r = await cli([]);
  assert.equal(r.code, 2);
  assert.match(r.err, /Usage: interlock <command>/);
});

test('--help and help print usage and exit 0', async () => {
  for (const args of [['--help'], ['-h'], ['help']]) {
    const r = await cli(args);
    assert.equal(r.code, 0, args.join(' '));
    assert.match(r.out, /Usage: interlock <command>/);
    for (const cmd of ['serve', 'policy check', 'hook claude', 'trail verify']) assert.ok(r.out.includes(cmd), cmd);
  }
});

test('--version prints the package version', async () => {
  const r = await cli(['--version']);
  assert.equal(r.code, 0);
  assert.match(r.out, /^\d+\.\d+\.\d+\n$/);
});

test('an unknown command is a usage error', async () => {
  const r = await cli(['launch']);
  assert.equal(r.code, 2);
  assert.match(r.err, /unknown command "launch"/);
});

test('every command has its own --help', async () => {
  for (const cmd of [['serve'], ['policy', 'check'], ['hook', 'claude'], ['trail', 'verify']]) {
    const r = await cli([...cmd, '--help']);
    assert.equal(r.code, 0, cmd.join(' '));
    assert.match(r.out, new RegExp(`Usage: interlock ${cmd.join(' ')}`));
  }
});

test('policy check accepts a valid file and summarises it', async () => {
  const r = await cli(['policy', 'check', EXAMPLE]);
  assert.equal(r.code, 0);
  assert.match(r.out, /valid: 6 rules, default require_approval/);
  assert.equal(r.err, '');
});

test('policy check defaults to ./interlock.policy.json', async () => {
  const dir = await tempDir();
  await writeFile(join(dir, 'interlock.policy.json'), JSON.stringify({ default: 'deny', rules: [] }));
  const r = await cli(['policy', 'check'], { cwd: dir });
  assert.equal(r.code, 0);
  assert.match(r.out, /valid: 0 rules, default deny/);
});

test('policy check uses INTERLOCK_POLICY when no file is given', async () => {
  const r = await cli(['policy', 'check'], { cwd: await tempDir(), env: { INTERLOCK_POLICY: EXAMPLE } });
  assert.equal(r.code, 0);
  assert.ok(r.out.includes(EXAMPLE));
});

test('policy check says which rules are only observed', async () => {
  const dir = await tempDir();
  const file = join(dir, 'observe.json');
  await writeFile(file, JSON.stringify({
    defaultMode: 'observe',
    rules: [
      { id: 'a', match: {}, outcome: 'deny', locked: true },
      { id: 'b', match: {}, outcome: 'deny' },
      { id: 'c', match: {}, outcome: 'deny' },
    ],
  }));
  const r = await cli(['policy', 'check', file]);
  assert.equal(r.code, 0);
  assert.match(r.out, /valid: 3 rules, default require_approval, default mode observe, 2 in observe mode/);
});

test('policy check reports an invalid file and exits 1', async () => {
  const dir = await tempDir();
  const file = join(dir, 'bad.json');
  await writeFile(file, JSON.stringify({ rules: [{ id: 'a', match: {}, outcome: 'nope' }] }));
  const r = await cli(['policy', 'check', file]);
  assert.equal(r.code, 1);
  assert.match(r.err, /rule "a": "outcome" must be one of/);
  assert.equal(r.out, '');
});

test('policy check reports a missing file and exits 1', async () => {
  const r = await cli(['policy', 'check'], { cwd: await tempDir() });
  assert.equal(r.code, 1);
  assert.match(r.err, /interlock\.policy\.json: cannot read policy file/);
});

test('policy without a subcommand, or with an unknown one, is a usage error', async () => {
  assert.equal((await cli(['policy'])).code, 2);
  const r = await cli(['policy', 'lint']);
  assert.equal(r.code, 2);
  assert.match(r.err, /unknown policy command "lint"/);
});

test('unknown flags and extra arguments are usage errors', async () => {
  const flag = await cli(['policy', 'check', EXAMPLE, '--strict']);
  assert.equal(flag.code, 2);
  assert.match(flag.err, /unknown option --strict/);

  const extra = await cli(['policy', 'check', EXAMPLE, 'other.json']);
  assert.equal(extra.code, 2);
  assert.match(extra.err, /unexpected argument "other.json"/);

  const missing = await cli(['serve', '--port']);
  assert.equal(missing.code, 2);
  assert.match(missing.err, /--port needs a value/);

  const badPort = await cli(['serve', '--port', 'abc']);
  assert.equal(badPort.code, 2);
  assert.match(badPort.err, /--port must be a number/);
});

test('commands that are not built yet say so and exit 1', async () => {
  const trail = await cli(['trail', 'verify']);
  assert.equal(trail.code, 1);
  assert.match(trail.err, /not available yet.*#5/);
});

test('serve refuses a setup code shorter than 8 characters', async () => {
  const r = await cli(['serve', '--setup-code', 'abc']);
  assert.equal(r.code, 2);
  assert.match(r.err, /setup code must be at least 8 characters/);
  const env = await cli(['serve'], { env: { INTERLOCK_SETUP_CODE: 'abc' } });
  assert.equal(env.code, 2);
});

test('serve refuses an invalid policy before starting', async () => {
  const dir = await tempDir();
  const file = join(dir, 'bad.json');
  await writeFile(file, '{');
  const r = await cli(['serve', '--policy', file, '--data', join(dir, 'state.json')]);
  assert.equal(r.code, 1);
  assert.match(r.err, /not valid JSON/);
});

test('the bin script starts the server with a policy file and serves the API', async () => {
  const dir = await tempDir();
  const child = spawn(process.execPath, [
    BIN, 'serve', '--port', '0', '--policy', EXAMPLE, '--data', join(dir, 'state.json'),
    '--setup-code', 'CLI-TEST-CODE',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  let printed = '';
  child.stdout.on('data', (d) => { printed += d; });

  try {
    const port = await new Promise((resolve, reject) => {
      let buf = '';
      const timer = setTimeout(() => reject(new Error(`server did not start:\n${buf}`)), 10000);
      child.stdout.on('data', (d) => {
        buf += d;
        const m = buf.match(/localhost:(\d+)\/console/);
        if (m && buf.includes('Setup code')) { clearTimeout(timer); resolve(Number(m[1])); }
      });
      child.stderr.on('data', (d) => { buf += d; });
      child.on('exit', (code) => reject(new Error(`server exited early (${code}):\n${buf}`)));
    });

    const res = await fetch(`http://localhost:${port}/api/propose`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ agent: 'a', onBehalfOf: 'u', action: 'Bash', params: { command: 'git status' } }),
    });
    const body = await res.json();
    assert.equal(body.outcome, 'auto_allow');
    assert.equal(body.rule, 'read-only-git');
    assert.match(printed, /Setup code \(to register a passkey\): CLI-TEST-CODE/);
  } finally {
    child.kill();
  }
});

test('the bin script exits with the command status', async () => {
  const code = await new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, 'policy', 'check', join(ROOT, 'missing.json')], { stdio: 'ignore' });
    child.on('exit', resolve);
  });
  assert.equal(code, 1);
});
