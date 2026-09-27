/**
 * The `interlock` command line.
 *
 * run() is the whole CLI: it takes argv and an io object (stdout, stderr, cwd,
 * env) and resolves to an exit code, so it can be tested in-process. It
 * resolves to null for commands that keep running (serve).
 *
 * Exit codes: 0 success, 1 the command failed, 2 usage error.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { RiskPolicy } from './policy.js';
import { PolicyError } from './policy-file.js';
import { startServer } from './serve.js';
import { runClaudeHook, DEFAULT_SERVER, DEFAULT_TIMEOUT_MS } from './claude-hook.js';

const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const DEFAULT_POLICY = 'interlock.policy.json';

const USAGE = `Usage: interlock <command> [options]

Commands:
  serve                  Start the approval service and web console
  policy check [file]    Validate a policy file (default ./${DEFAULT_POLICY})
  hook claude            Claude Code PreToolUse hook (passkey approval for risky tool calls)
  trail verify           Verify the audit trail (coming in #5)

Options:
  -h, --help             Show help (also: interlock <command> --help)
  -v, --version          Show the version
`;

const COMMANDS = {
  serve: {
    usage: `Usage: interlock serve [options]

Start the approval service and web console. State is kept on disk so
approvals and one-time consumption survive a restart.

Options:
  --port <n>        Port to listen on (default: $PORT or 4000; 0 picks a free port)
  --policy <file>   JSON policy file (default: $INTERLOCK_POLICY or the built-in rules)
  --data <file>     State file (default: ./data/interlock.json)
  --setup-code <c>  Code needed to register a passkey in the console
                    (default: $INTERLOCK_SETUP_CODE or a random code, printed at start)
  --demo            Seed a pending proposal so the console isn't empty
`,
    options: { port: 'value', policy: 'value', data: 'value', 'setup-code': 'value', demo: 'flag' },
    maxArgs: 0,
    run: serve,
  },
  'policy check': {
    usage: `Usage: interlock policy check [file]

Validate a policy file and print a summary. Uses [file], else
$INTERLOCK_POLICY, else ./${DEFAULT_POLICY}. Exits 1 if it is invalid.
`,
    options: {},
    maxArgs: 1,
    run: policyCheck,
  },
  'hook claude': {
    usage: `Usage: interlock hook claude [options]

Claude Code PreToolUse hook. Reads the tool call as JSON on stdin, sends it
through the Interlock policy, and prints Claude Code's decision JSON:
blocked calls are denied with a reason, calls that need a human wait for a
passkey approval in the console. Fails closed if Interlock is unreachable.

Options:
  --server <url>    Interlock service (default: $INTERLOCK_URL or ${DEFAULT_SERVER})
  --timeout <sec>   How long to wait for an approval (default: ${DEFAULT_TIMEOUT_MS / 1000}).
                    Keep it below the hook's "timeout" in Claude Code settings.
  --user <name>     Who the agent acts for (default: $INTERLOCK_USER or your login)
  --no-open         Don't open the console in the browser
`,
    options: { server: 'value', timeout: 'value', user: 'value', 'no-open': 'flag' },
    maxArgs: 0,
    run: hookClaude,
  },
  'trail verify': {
    usage: `Usage: interlock trail verify

Verify that the audit trail has not been edited, deleted, or reordered.
Not available yet (#5).
`,
    options: {},
    maxArgs: 0,
    run: notYet('#5'),
  },
};

/**
 * @param {string[]} argv  Arguments after the program name.
 * @param {{stdout: {write: Function}, stderr: {write: Function}, cwd?: string, env?: Object}} [io]
 * @returns {Promise<number|null>}
 */
export async function run(argv, io = defaultIo()) {
  io = { cwd: process.cwd(), env: process.env, ...io };
  const [first, second] = argv;

  if (first === undefined) {
    io.stderr.write(USAGE);
    return 2;
  }
  if (first === '-h' || first === '--help' || first === 'help') {
    io.stdout.write(USAGE);
    return 0;
  }
  if (first === '-v' || first === '--version') {
    io.stdout.write(`${VERSION}\n`);
    return 0;
  }

  let name;
  let rest;
  if (COMMANDS[first]) {
    name = first;
    rest = argv.slice(1);
  } else if (['policy', 'hook', 'trail'].includes(first)) {
    if (second === undefined || second.startsWith('-')) {
      return usageError(io, `"${first}" needs a subcommand`);
    }
    name = `${first} ${second}`;
    rest = argv.slice(2);
    if (!COMMANDS[name]) return usageError(io, `unknown ${first} command "${second}"`);
  } else {
    return usageError(io, `unknown command "${first}"`);
  }

  const cmd = COMMANDS[name];
  let parsed;
  try {
    parsed = parseArgs(rest, cmd.options);
  } catch (err) {
    return usageError(io, err.message, cmd.usage);
  }
  if (parsed.help) {
    io.stdout.write(cmd.usage);
    return 0;
  }
  if (parsed.args.length > cmd.maxArgs) {
    return usageError(io, `unexpected argument "${parsed.args[cmd.maxArgs]}"`, cmd.usage);
  }
  return cmd.run(parsed, io);
}

async function serve({ opts }, io) {
  const rawPort = opts.port ?? io.env.PORT ?? '4000';
  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    return usageError(io, `--port must be a number from 0 to 65535, got "${rawPort}"`, COMMANDS.serve.usage);
  }

  const setupCode = opts['setup-code'] ?? io.env.INTERLOCK_SETUP_CODE;
  if (setupCode !== undefined && setupCode.length < 8) {
    return usageError(io, 'the passkey setup code must be at least 8 characters', COMMANDS.serve.usage);
  }

  let started;
  try {
    started = await startServer({
      port,
      policyPath: opts.policy ?? io.env.INTERLOCK_POLICY,
      dataPath: opts.data,
      setupCode,
      demo: Boolean(opts.demo),
      cwd: io.cwd,
    });
  } catch (err) {
    if (!(err instanceof PolicyError)) throw err;
    io.stderr.write(`interlock: ${err.message}\n`);
    return 1;
  }

  io.stdout.write(`\n🔒 Interlock server running\n`);
  io.stdout.write(`   Console:  http://localhost:${started.port}/console\n`);
  io.stdout.write(`   API:      http://localhost:${started.port}/api/proposals\n`);
  io.stdout.write(`   State:    ${started.dataPath}\n`);
  io.stdout.write(`   Policy:   ${started.policyPath ?? 'built-in default'}\n`);
  io.stdout.write(`   Setup code (to register a passkey): ${started.server.setupCode}\n\n`);
  return null;
}

async function policyCheck({ args }, io) {
  const path = resolve(io.cwd, args[0] ?? io.env.INTERLOCK_POLICY ?? DEFAULT_POLICY);
  let policy;
  try {
    policy = await RiskPolicy.fromFile(path);
  } catch (err) {
    if (!(err instanceof PolicyError)) throw err;
    io.stderr.write(`interlock: ${err.message}\n`);
    return 1;
  }
  const n = policy.rules.length;
  const observed = policy.rules.filter((r) => (r.mode ?? policy.defaultMode) === 'observe').length;
  let summary = `${n} rule${n === 1 ? '' : 's'}, default ${policy.defaultOutcome}`;
  if (policy.defaultMode === 'observe') summary += ', default mode observe';
  if (observed > 0) summary += `, ${observed} in observe mode (recorded, never blocked)`;
  io.stdout.write(`${path}: valid: ${summary}\n`);
  return 0;
}

async function hookClaude({ opts }, io) {
  let timeoutMs;
  if (opts.timeout !== undefined) {
    const sec = Number(opts.timeout);
    if (!Number.isFinite(sec) || sec <= 0) {
      return usageError(io, `--timeout must be a positive number of seconds, got "${opts.timeout}"`, COMMANDS['hook claude'].usage);
    }
    timeoutMs = sec * 1000;
  }

  const text = await (io.readStdin ?? readStdin)();
  let input;
  try {
    input = JSON.parse(text);
  } catch {
    input = null;
  }

  const out = await runClaudeHook(input, {
    server: opts.server ?? io.env.INTERLOCK_URL,
    timeoutMs,
    user: opts.user ?? io.env.INTERLOCK_USER,
    openUrl: opts['no-open'] ? () => {} : undefined,
  });
  // Always exit 0 and let the JSON carry the decision; no output = no objection.
  if (out) io.stdout.write(`${JSON.stringify(out)}\n`);
  return 0;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function notYet(issue) {
  return async (_parsed, io) => {
    io.stderr.write(`interlock: this command is not available yet (tracked in ${issue})\n`);
    return 1;
  };
}

/**
 * Parse `--name value`, `--name=value`, boolean `--flag`, and -h/--help.
 * @param {string[]} argv
 * @param {Record<string, 'value'|'flag'>} spec
 */
function parseArgs(argv, spec) {
  const opts = {};
  const args = [];
  let help = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') {
      help = true;
      continue;
    }
    if (a === '--') {
      args.push(...argv.slice(i + 1));
      break;
    }
    if (!a.startsWith('-') || a === '-') {
      args.push(a);
      continue;
    }
    const eq = a.indexOf('=');
    const key = a.slice(2, eq === -1 ? undefined : eq);
    if (!a.startsWith('--') || !spec[key]) throw new Error(`unknown option ${eq === -1 ? a : a.slice(0, eq)}`);
    if (spec[key] === 'flag') {
      if (eq !== -1) throw new Error(`--${key} does not take a value`);
      opts[key] = true;
    } else if (eq !== -1) {
      opts[key] = a.slice(eq + 1);
    } else {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) throw new Error(`--${key} needs a value`);
      opts[key] = value;
      i++;
    }
  }
  return { opts, args, help };
}

function usageError(io, message, usage = USAGE) {
  io.stderr.write(`interlock: ${message}\n\n${usage}`);
  return 2;
}

function defaultIo() {
  return { stdout: process.stdout, stderr: process.stderr };
}
