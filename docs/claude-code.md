# Guarding Claude Code

Interlock can sit in front of Claude Code's tool calls. Before Claude Code runs
a command or writes a file, the call goes through your Interlock policy:

- **deny**: the call is blocked and Claude Code is told why;
- **needs approval**: the console opens, and the call waits until a person
  approves that exact call with a passkey (or denies it);
- **auto allow**: Interlock steps aside and Claude Code's normal permission
  prompts apply.

If the Interlock service is not running, calls are blocked (fail closed).

## Setup

1. Write a policy. Tool calls are matched as `action` = tool name and `params`
   = the tool input, for example `params.command` for `Bash` or
   `params.file_path` for `Write`. Start from
   [`examples/interlock.policy.json`](../examples/interlock.policy.json).

   ```bash
   npx interlock policy check interlock.policy.json
   ```

2. Start Interlock and register a passkey in the console
   (`http://localhost:4000/console`). Registering asks for the setup code that
   `serve` prints when it starts:

   ```bash
   npx interlock serve --policy interlock.policy.json
   ```

3. Add the hook to `.claude/settings.json` in your project (or
   `~/.claude/settings.json` for every project):

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash|Write|Edit",
           "hooks": [
             { "type": "command", "command": "npx interlock hook claude --timeout 280", "timeout": 300 }
           ]
         }
       ]
     }
   }
   ```

   Keep `--timeout` (how long Interlock waits for a person) **below** the
   hook's `timeout` (when Claude Code gives up on the hook). If Claude Code
   stops the hook first, the call is not blocked. Without `--timeout`,
   Interlock waits 50 seconds, which fits Claude Code's default of 60.

## What happens on a risky call

```
Claude Code: Bash "git push --force origin main"
  -> interlock hook claude
  -> POST /api/propose            policy: force-push-needs-human
  -> console opens                a person approves with a passkey
  -> POST /api/proposals/:id/execute   receipt verified and consumed once
  -> {"permissionDecision": "allow"}   Claude Code runs the command
```

The person approves the exact tool input. The receipt is bound to it and can
be used once. If nobody answers in time, the call is blocked and the request
is closed, so a late approval cannot be used.

## Options

| Option | Default | |
|---|---|---|
| `--server <url>` | `$INTERLOCK_URL` or `http://localhost:4000` | Interlock service |
| `--timeout <sec>` | `50` | how long to wait for a person |
| `--user <name>` | `$INTERLOCK_USER` or your login | who the agent acts for |
| `--no-open` | off | don't open the console in the browser |

## Notes

- Every guarded call is recorded as a proposal, including auto-allowed ones,
  so the console shows them too. Narrow the `matcher` to the tools you care
  about.
- Approval without a passkey (`POST /api/proposals/:id/approve`) is disabled on
  the server, so an agent cannot approve its own request with `curl`.
