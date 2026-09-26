#!/usr/bin/env node
// `npm run serve`: the service with a seeded demo proposal.
// Same as `interlock serve --demo`; extra flags are passed through.
import { run } from '../src/cli.js';

const code = await run(['serve', '--demo', ...process.argv.slice(2)]);
if (code !== null) process.exitCode = code;
