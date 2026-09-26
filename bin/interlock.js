#!/usr/bin/env node
import { run } from '../src/cli.js';

const code = await run(process.argv.slice(2));
// null means the command keeps running (serve).
if (code !== null) process.exitCode = code;
